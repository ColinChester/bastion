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
NEEDS_ROOT = {"status", "doctor", "report", "test-push"}


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
        "rules": cmd_rules, "replay": cmd_replay,
    }[args.cmd]
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
