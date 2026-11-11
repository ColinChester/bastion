"""`bastion` command-line tool."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from bastion import __version__
from bastion.config import Config, ConfigPermissionError, load_config

# Commands that read bastiond's root-only data folder or config.
NEEDS_ROOT = {"status", "doctor", "report", "test-push", "detections", "enable-edge-api",
              "backfill-index", "enable-executor", "autonomy", "passkey", "actions",
              "approvals", "approve", "deny", "undo", "audit"}


def _need_sudo(cmd: str) -> str:
    return (f"`bastion {cmd}` reads Bastion's data, which is root-only. "
            f"Run it with sudo:  sudo bastion {cmd} ...")


def _store(cfg, cmd: str = "status"):
    from bastion.store import Store

    if os.geteuid() != 0:
        sys.exit(_need_sudo(cmd))
    if not cfg.db_path.exists():
        sys.exit(f"No database at {cfg.db_path} yet. Is bastiond running? "
                 "Check with: sudo bastion doctor")
    return Store(cfg.db_path)


def _write_user_file(path: Path, text: str) -> None:
    """Write a report and, under sudo, hand it back to the user who ran sudo."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        with contextlib.suppress(OSError):
            os.chown(path, int(uid), int(gid))


def cmd_status(args, cfg) -> int:
    from bastion.daemon import HEARTBEAT_KEY, learning_day, sensor_health

    store = _store(cfg, "status")
    hb = store.get_state(HEARTBEAT_KEY)
    age = (time.time() * 1000 - int(hb)) / 1000 if hb else None
    print(f"bastiond heartbeat: {f'{age:.0f} s ago' if age is not None else 'never'}")
    print(f"learning day: {learning_day(store)} of {cfg.baseline.learning_days}")
    for k, v in sensor_health(cfg, store).items():
        print(f"sensor {k}: {v}")
    day = int(time.time() * 1000) - 86_400_000
    counts = store.count_events_by_source(day)
    print("events (24 h): " + (", ".join(f"{k} {v:,}" for k, v in counts.items()) or "none"))
    dets = list(store.iter_detections(day))
    print(f"detections (24 h): {len(dets)} ({sum(d['hits'] for d in dets)} hits)")
    return 0


def cmd_doctor(args, cfg) -> int:
    from bastion.doctor import check_all, to_text

    items = check_all(cfg)
    print(to_text(items))
    return 1 if any(h.status == "fail" for h in items) else 0


def cmd_posture(args, cfg) -> int:
    from bastion.posture import Posture, to_json, to_markdown

    checks = Posture().all_checks(skip_slow=args.quick)
    md = to_markdown(checks)
    print(md)
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    out_dir = Path(args.out) if args.out else Path.cwd()
    _write_user_file(out_dir / f"posture-{stamp}.md", md)
    _write_user_file(out_dir / f"posture-{stamp}.json", to_json(checks))
    print(f"\nSaved posture-{stamp}.md and .json in {out_dir}", file=sys.stderr)
    return 0


def cmd_whoowns(args, cfg) -> int:
    from bastion.triage import who_owns

    print(who_owns(Path(args.path)))
    return 0


def cmd_test_push(args, cfg) -> int:
    from bastion.notify import Notifier

    n = Notifier(cfg)
    if not cfg.notify.ntfy_topic:
        print("No ntfy topic configured (notify.ntfy_topic in config.toml).")
        return 1
    ok = n.send("Bastion test push",
                "If you can read this on your phone, Phase 0's push spike works.",
                tags="white_check_mark")
    print("sent" if ok else "failed (see message above)")
    print(f"Subscribe in the ntfy app to: {cfg.notify.ntfy_server.rstrip('/')}/"
          f"{cfg.notify.ntfy_topic}")
    return 0 if ok else 1


def cmd_report(args, cfg) -> int:
    from bastion.report import build_report

    md = build_report(_store(cfg, "report"), days=args.days)
    if args.out:
        _write_user_file(Path(args.out), md)
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


def cmd_detections(args, cfg) -> int:
    """Detections whose latest hit is at or after --since (epoch seconds)."""
    store = _store(cfg, "detections")
    rows = [{"title": d["title"], "rule_id": d["rule_id"], "severity": d["severity"],
             "hits": d["hits"], "last_ms": d["last_ms"]}
            for d in store.iter_detections(int(args.since * 1000))]
    if args.json:
        print(json.dumps(rows))
    else:
        for r in rows:
            print(f"[{r['severity']}] {r['title']} x{r['hits']}")
        print(f"{len(rows)} detection(s)")
    return 0


def cmd_enable_edge_api(args, cfg) -> int:
    """Turn on the edge API for the Phase 2 orchestrator and write its token to a file.

    Idempotent: an existing token is kept. The token is never printed; it is written to
    --token-file (owned by the user who ran sudo, mode 600) for deploy/.env.
    """
    import secrets

    from bastion.config import DEFAULT_CONFIG_PATH, ENV_CONFIG, set_toml_value

    if os.geteuid() != 0:
        sys.exit(_need_sudo("enable-edge-api"))
    path = Path(args.config or os.environ.get(ENV_CONFIG, DEFAULT_CONFIG_PATH))
    text = path.read_text() if path.exists() else ""
    token = cfg.edge_api.token if len(cfg.edge_api.token) >= 32 else secrets.token_hex(32)
    text = set_toml_value(text, "edge_api", "enabled", "true")
    text = set_toml_value(text, "edge_api", "token", f'"{token}"')
    if args.quiet_bastiond_pushes:
        # The orchestrator's digest replaces bastiond's own daily summary.
        text = set_toml_value(text, "notify", "mode", '"off"')
    path.write_text(text)
    path.chmod(0o600)
    if args.token_file:
        out = Path(args.token_file)
        out.write_text(token + "\n")
        out.chmod(0o600)
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if uid and gid:
            os.chown(out, int(uid), int(gid))
    print(f"Edge API enabled on {cfg.edge_api.bind}:{cfg.edge_api.port}. "
          "Restart bastiond to apply.")
    return 0


def _executor(cfg, cmd: str):
    from bastion.executor.service import Executor

    if os.geteuid() != 0:
        sys.exit(_need_sudo(cmd))
    return Executor(cfg)


def _when(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000).strftime("%b %d %H:%M")


def cmd_enable_executor(args, cfg) -> int:
    """Turn on the executor and record the gateway's public key and the console address."""
    from bastion.config import DEFAULT_CONFIG_PATH, ENV_CONFIG, set_toml_value

    if os.geteuid() != 0:
        sys.exit(_need_sudo("enable-executor"))
    path = Path(args.config or os.environ.get(ENV_CONFIG, DEFAULT_CONFIG_PATH))
    text = path.read_text() if path.exists() else ""
    text = set_toml_value(text, "executor", "enabled", "true")
    text = set_toml_value(text, "executor", "command_public_key", json.dumps(args.public_key))
    text = set_toml_value(text, "executor", "rp_id", json.dumps(args.rp_id))
    text = set_toml_value(text, "executor", "origin", json.dumps(args.origin))
    path.write_text(text)
    path.chmod(0o600)
    print("Executor enabled in shadow mode (it logs what it would do and changes nothing). "
          "Restart bastiond to apply.")
    return 0


def cmd_autonomy(args, cfg) -> int:
    ex = _executor(cfg, "autonomy")
    st = ex.status()
    if args.state == "status":
        print(f"automatic containment: {'ON' if st['mode'] == 'on' else 'shadow (log only)'}")
        print(f"shadow period: day {st['shadow_day']} of {st['shadow_days']}")
        print(f"automatic actions in the last hour: {st['auto_actions_last_hour']} "
              f"(limit {st['max_auto_actions_per_hour']})")
        print(f"passkeys: {st['passkeys']}   pending approvals: {st['pending_approvals']}")
        if not cfg.executor.enabled:
            print("note: the executor is disabled in config.toml")
        return 0
    if args.state == "on":
        if st["shadow_day"] <= st["shadow_days"] and not args.force:
            print(f"Still in the shadow period (day {st['shadow_day']} of "
                  f"{st['shadow_days']}). Review `sudo bastion actions` first; "
                  "add --force to turn it on anyway.")
            return 1
        ex.set_mode("on")
        print("Automatic containment is ON. Turn it off with: sudo bastion autonomy off")
    else:
        ex.set_mode("shadow")
        print("Automatic containment is off (shadow mode). Existing containment stays in "
              "place; undo items with: sudo bastion undo ID")
    return 0


def cmd_passkey(args, cfg) -> int:
    ex = _executor(cfg, "passkey")
    if args.op == "enroll":
        code = ex.new_enroll_code()
        where = (cfg.executor.origin or "the console") + "/enroll"
        print(f"Open {where} and enter this code within 10 minutes:\n\n    {code}\n")
    elif args.op == "list":
        keys = ex.store.list_passkeys()
        for k in keys:
            print(f"{k['credential_id'][:16]}…  {k['name']}  added {_when(k['created_ms'])}")
        print(f"{len(keys)} passkey(s)")
    else:
        match = [k for k in ex.store.list_passkeys()
                 if args.credential_id and k["credential_id"].startswith(args.credential_id)]
        if len(match) != 1:
            print("Give the start of exactly one credential id (see: sudo bastion passkey list)")
            return 1
        ex.store.remove_passkey(match[0]["credential_id"])
        ex.store.audit("passkey_removed", {"credential_id": match[0]["credential_id"]})
        print("Removed.")
    return 0


def cmd_actions(args, cfg) -> int:
    ex = _executor(cfg, "actions")
    rows = ex.list_actions(args.limit)
    for a in rows:
        target = a["args"].get("path") or a["args"].get("action_id") or ""
        print(f"{a['id']}  {_when(a['ts_ms'])}  {a['status']:<8} {a['action']}  {target}")
        print(f"    {'auto' if a['auto'] else 'approved'} · {a['agent'] or '-'} · {a['detail']}")
    print(f"{len(rows)} action(s). Undo an executed one with: sudo bastion undo ID")
    return 0


def cmd_approvals(args, cfg) -> int:
    ex = _executor(cfg, "approvals")
    rows = ex.list_approvals(None if args.all else "pending")
    for a in rows:
        c = a["command"]
        target = c["args"].get("path") or c["args"].get("action_id") or ""
        print(f"{a['id']}  {_when(a['created_ms'])}  {a['status']:<8} tier {c['tier']}  "
              f"{c['action']}  {target}")
        print(f"    {c.get('reason', '')}")
    print(f"{len(rows)} request(s). Decide with: sudo bastion approve ID  /  deny ID")
    return 0


def cmd_decide(args, cfg) -> int:
    from bastion.executor.service import Rejected

    ex = _executor(cfg, args.cmd)
    try:
        if args.cmd == "approve":
            result = ex.approve_local(args.id)
        elif args.cmd == "deny":
            result = ex.deny(args.id, by="cli")
        else:
            result = ex.undo_local(args.id)
    except Rejected as exc:
        print(f"Not done: {exc}")
        return 1
    print(f"{result['status']}: {result.get('detail', '')}")
    return 0 if result["status"] in ("executed", "denied", "undone") else 1


def cmd_audit(args, cfg) -> int:
    ex = _executor(cfg, "audit")
    ok, n, detail = ex.store.verify_audit()
    if not args.verify:
        for e in reversed(ex.store.audit_tail(args.limit)):
            print(f"{e['seq']:>5}  {_when(e['ts_ms'])}  {e['kind']:<22} "
                  f"{json.dumps(e['body'])[:160]}")
    print(f"audit log: {n} entries, chain {'intact' if ok else 'BROKEN: ' + detail}")
    return 0 if ok else 2


def cmd_backfill_index(args, cfg) -> int:
    """Index older events so agents can look up process trees and binary history."""
    store = _store(cfg, "backfill-index")
    total = 0
    while True:
        n = store.backfill_lookup_columns(max_rows=20_000)
        total += n
        if not n:
            break
        print(f"  indexed {total:,} events...", flush=True)
    print(f"Done: {total:,} events indexed.")
    return 0


def cmd_rules(args, cfg) -> int:
    from bastion.detect.sigma import load_rules

    rules, errors = load_rules(Path(args.dir) if args.dir else cfg.resolved_rules_dir())
    for r in rules:
        print(f"{r.level:<8} {r.category:<18} {r.title}")
    for e in errors:
        print(f"ERROR {e}")
    print(f"{len(rules)} rules loaded, {len(errors)} errors")
    return 1 if errors else 0


def cmd_replay(args, cfg) -> int:
    """Run a log file through the full pipeline into a scratch database."""
    from bastion.collectors import RawRecord
    from bastion.daemon import Pipeline
    from bastion.store import Store

    db = args.db or ":memory:"
    store = Store(db)
    if args.learned:
        store.set_state("install_ms", "0")  # pretend the learning window is over
    pipe = Pipeline(cfg, store)
    for line in Path(args.file).read_text().splitlines():
        if not line.strip():
            continue
        payload = json.loads(line) if args.source in ("osquery", "unified_log") else line
        pipe.handle(RawRecord(args.source, payload))
    for d in store.iter_detections():
        print(f"[{d['severity']}] {d['title']} x{d['hits']}")
    print(json.dumps(pipe.stats))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bastion", description="Bastion endpoint security")
    ap.add_argument("--config", help="path to config.toml")
    ap.add_argument("--version", action="version", version=f"bastion {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="daemon heartbeat, sensors, 24 h counts")
    sub.add_parser("doctor", help="check every sensor is installed and producing data")
    p = sub.add_parser("posture", help="run the read-only posture checks")
    p.add_argument("--quick", action="store_true", help="skip the slow software update check")
    p.add_argument("--out", help="folder for the .md/.json report (default: current folder)")
    p = sub.add_parser("whoowns", help="find which app owns a file or folder")
    p.add_argument("path")
    sub.add_parser("test-push", help="send a test notification to your phone")
    p = sub.add_parser("report", help="false-positive review report")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--out")
    p = sub.add_parser("detections", help="list detections since a time")
    p.add_argument("--since", type=float, default=0, help="epoch seconds (default: all)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("enable-edge-api", help="turn on the local API for the orchestrator")
    p.add_argument("--token-file", help="write the API token to this file (mode 600)")
    p.add_argument("--quiet-bastiond-pushes", action="store_true",
                   help="turn off bastiond's own daily summary (the orchestrator sends one)")
    sub.add_parser("backfill-index", help="index older events for agent lookups")
    p = sub.add_parser("enable-executor", help="turn on the Phase 3 executor (shadow mode)")
    p.add_argument("--public-key", required=True, help="gateway's Ed25519 public key (base64)")
    p.add_argument("--rp-id", required=True, help="console host name, e.g. mac.tail1234.ts.net")
    p.add_argument("--origin", required=True, help="console origin, e.g. https://mac.tail…")
    p = sub.add_parser("autonomy", help="show or switch automatic containment")
    p.add_argument("state", nargs="?", default="status", choices=["status", "on", "off"])
    p.add_argument("--force", action="store_true", help="turn on before the shadow period ends")
    p = sub.add_parser("passkey", help="manage the passkeys that approve actions")
    p.add_argument("op", choices=["enroll", "list", "remove"])
    p.add_argument("credential_id", nargs="?")
    p = sub.add_parser("actions", help="what the executor did or would have done")
    p.add_argument("--limit", type=int, default=30)
    p = sub.add_parser("approvals", help="requests waiting for your approval")
    p.add_argument("--all", action="store_true")
    for name, text in (("approve", "approve a request from this terminal"),
                       ("deny", "deny a request"), ("undo", "undo a containment action")):
        p = sub.add_parser(name, help=text)
        p.add_argument("id")
    p = sub.add_parser("audit", help="show or verify the executor's audit log")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--limit", type=int, default=30)
    p = sub.add_parser("rules", help="list and validate detection rules")
    p.add_argument("--dir")
    p = sub.add_parser("replay", help="replay a log file through the pipeline")
    p.add_argument("source", choices=["osquery", "santa", "unified_log"])
    p.add_argument("file")
    p.add_argument("--db", help="sqlite path (default: in-memory)")
    p.add_argument("--learned", action="store_true",
                   help="treat the learning window as finished (first-seen findings fire)")

    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigPermissionError:
        if args.cmd in NEEDS_ROOT:
            print(_need_sudo(args.cmd), file=sys.stderr)
            return 1
        cfg = Config()  # posture, whoowns, rules and replay work fine with defaults
    handler = {
        "status": cmd_status, "doctor": cmd_doctor, "posture": cmd_posture,
        "whoowns": cmd_whoowns, "test-push": cmd_test_push, "report": cmd_report,
        "rules": cmd_rules, "replay": cmd_replay, "detections": cmd_detections,
        "enable-edge-api": cmd_enable_edge_api, "backfill-index": cmd_backfill_index,
        "enable-executor": cmd_enable_executor, "autonomy": cmd_autonomy,
        "passkey": cmd_passkey, "actions": cmd_actions, "approvals": cmd_approvals,
        "approve": cmd_decide, "deny": cmd_decide, "undo": cmd_decide, "audit": cmd_audit,
    }[args.cmd]
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
