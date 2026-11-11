"""bastion-core: run the triage loop, the incident page, checks and evaluations."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from bastion.core.corestore import CoreStore
from bastion.core.edge import EdgeClient, EdgeError
from bastion.core.settings import Settings


def _model():
    from bastion.core.models import AnthropicClient

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set (add it to deploy/.env).")
    return AnthropicClient()


def cmd_run(args, s: Settings) -> int:
    from bastion.core.tracing import setup_tracing
    from bastion.core.worker import Worker

    setup_tracing()
    if len(s.edge_token) < 32:
        sys.exit("BASTION_EDGE_TOKEN is missing (run scripts/setup-phase2.sh).")
    store = CoreStore(s.db_path, s.timezone)
    Worker(s, store, EdgeClient(s.edge_url, s.edge_token), _model()).run_forever()
    return 0


def cmd_web(args, s: Settings) -> int:
    import uvicorn

    from bastion.core.web import create_app

    uvicorn.run(create_app(s), host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_check(args, s: Settings) -> int:
    """Verify each dependency and say exactly what is wrong."""
    from bastion.core.models import ModelError
    from bastion.core.push import Pusher

    ok = True

    def line(good: bool, name: str, detail: str) -> None:
        nonlocal ok
        ok = ok and good
        print(f"[{'OK  ' if good else 'FAIL'}] {name:<10} {detail}")

    try:
        status = EdgeClient(s.edge_url, s.edge_token).query("status")
        hb = status.get("heartbeat_age_s")
        line(hb is not None and hb < 300, "edge api",
             f"bastiond reachable, heartbeat {hb} s ago, "
             f"{sum((status.get('events_24h') or {}).values()):,} events in 24 h")
    except EdgeError as exc:
        line(False, "edge api", f"{exc}. Is bastiond running with [edge_api] enabled, and "
             "does BASTION_EDGE_TOKEN match?")
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            from bastion.core.models import AnthropicClient, cost_usd

            reply = AnthropicClient().complete(
                model=s.agent_model, system="Reply with the single word OK.",
                messages=[{"role": "user", "content": "ping"}], tools=[], max_tokens=5)
            line(True, "model", f"{s.agent_model} answered "
                 f"(${cost_usd(s, s.agent_model, reply.usage):.6f})")
        except ModelError as exc:
            line(False, "model", str(exc)[:200])
    else:
        line(False, "model", "ANTHROPIC_API_KEY is not set in deploy/.env")
    pusher = Pusher(s)
    if not pusher.enabled:
        line(False, "push", "BASTION_NTFY_URL / BASTION_NTFY_TOPIC not set")
    elif args.push:
        line(pusher.send("Bastion test", "Phase 2 push works.", tags="white_check_mark"),
             "push", f"test push sent via {s.ntfy_url}")
    else:
        line(True, "push", f"configured for {s.ntfy_url} (add --push to send a test)")
    store = CoreStore(s.db_path, s.timezone)
    line(True, "budget", f"${store.spend_today():.2f} today (cap ${s.daily_cap_usd:.2f}), "
         f"${store.spend_month():.2f} this month (cap ${s.monthly_cap_usd:.0f})")
    return 0 if ok else 1


def cmd_eval(args, s: Settings) -> int:
    from bastion.core.evaluate import load_labels, report, run_eval

    labels = load_labels(Path(args.labels))
    cases, uncovered = run_eval(settings=s, model=_model(),
                                edge=EdgeClient(s.edge_url, s.edge_token), labels=labels,
                                days=args.days, per_label=args.per_label)
    text = report(cases, uncovered, s)
    out = s.data_dir / f"eval-{time.strftime('%Y%m%d-%H%M')}.md"
    out.write_text(text)
    print(text)
    print(f"Saved to {out}")
    return 0 if cases and all(c.grade == "PASS" for c in cases) else 1


def cmd_digest(args, s: Settings) -> int:
    from bastion.core.push import Pusher, digest_text

    try:
        status = EdgeClient(s.edge_url, s.edge_token).query("status")
    except EdgeError:
        status = None
    title, body = digest_text(CoreStore(s.db_path, s.timezone), status, s)
    print(title, body, sep="\n")
    if args.send:
        Pusher(s).send(title, body, priority="low", tags="shield", click=s.console_url)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bastion-core", description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="run the triage loop")
    p = sub.add_parser("web", help="serve the read-only incident page")
    p.add_argument("--host", default="0.0.0.0")  # inside the container; published to localhost
    p.add_argument("--port", type=int, default=8787)
    p = sub.add_parser("check", help="verify edge API, model key, push and budget")
    p.add_argument("--push", action="store_true", help="also send a test notification")
    p = sub.add_parser("eval", help="grade the agents against the labeled set")
    p.add_argument("--labels", default="tests/labeled_events/phase1-labels.yml")
    p.add_argument("--days", type=int, default=21)
    p.add_argument("--per-label", type=int, default=2)
    p = sub.add_parser("digest", help="print the daily digest")
    p.add_argument("--send", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    handler = {"run": cmd_run, "web": cmd_web, "check": cmd_check, "eval": cmd_eval,
               "digest": cmd_digest}[args.cmd]
    return handler(args, Settings.from_env())


if __name__ == "__main__":
    raise SystemExit(main())
