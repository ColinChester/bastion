"""`bastion doctor`: is every sensor installed, running and actually producing data?

This is the Phase 1 version of the registry/health-check pattern: each component gets
ok / warn / fail plus the exact fix. The most common silent failure is osquery running
without Full Disk Access, which leaves the Endpoint Security tables empty.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from bastion.config import Config
from bastion.macos import Runner


@dataclass
class Health:
    component: str
    status: str  # ok | warn | fail
    detail: str
    fix: str = ""


def _recent_query_names(log_path: Path, max_bytes: int = 2_000_000) -> dict[str, int]:
    """Latest unixTime per query name in the tail of osquery's results log."""
    out: dict[str, int] = {}
    try:
        with log_path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return out
    for line in data.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        name, t = rec.get("name"), int(rec.get("unixTime", 0) or 0)
        if name:
            out[name] = max(out.get(name, 0), t)
    return out


def check_all(cfg: Config, runner: Runner | None = None, now: float | None = None) -> list[Health]:
    r = runner or Runner()
    now = now or time.time()
    res: list[Health] = []

    # osquery
    if r.run(["pgrep", "-x", "osqueryd"]).ok:
        names = _recent_query_names(Path(cfg.osquery.results_log))
        proc_age = now - names.get("process_events", 0)
        if not names:
            res.append(Health("osquery", "warn", "running, but no results logged yet",
                              "Wait a minute, then check /var/log/osquery/osqueryd.results.log"))
        elif proc_age > 600:
            res.append(Health(
                "osquery", "fail",
                "running, but no process events in the last 10 minutes",
                "Grant Full Disk Access to /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd "
                "(System Settings > Privacy & Security > Full Disk Access), then "
                "`sudo launchctl kickstart -k system/io.osquery.agent`"))
        else:
            res.append(Health("osquery", "ok", f"process events {int(proc_age)} s ago"))
    else:
        res.append(Health("osquery", "fail", "osqueryd not running",
                          "sudo launchctl bootstrap system "
                          "/Library/LaunchDaemons/io.osquery.agent.plist"))

    # Santa
    st = r.run(["santactl", "status"])
    if st.ok:
        mode = next((ln.split("|")[-1].strip() for ln in st.out.splitlines()
                     if "Mode" in ln), "?")
        status = "ok" if "monitor" in mode.lower() else "warn"
        res.append(Health("santa", status, f"mode: {mode}",
                          "" if status == "ok" else "Phase 1 expects Monitor mode"))
    else:
        res.append(Health("santa", "fail", "santactl unavailable or Santa not running",
                          "Approve Santa's system extension and Full Disk Access in System "
                          "Settings, or reinstall the Santa package"))

    # Objective-See tools
    for name, pattern in (("lulu", "LuLu"), ("blockblock", "BlockBlock")):
        ok = r.run(["pgrep", "-f", pattern]).ok
        res.append(Health(name, "ok" if ok else "warn", "running" if ok else "not running",
                          "" if ok else f"Open /Applications/{pattern}.app and approve its "
                          "extension prompts"))

    # bastiond
    if r.run(["pgrep", "-f", "bastiond"]).ok:
        res.append(Health("bastiond", "ok", "running"))
    else:
        res.append(Health("bastiond", "fail", "not running",
                          "sudo launchctl bootstrap system "
                          "/Library/LaunchDaemons/com.bastion.bastiond.plist; "
                          "logs: /Library/Logs/Bastion/bastiond.log"))

    # notifications
    if cfg.notify.ntfy_topic and cfg.notify.mode != "off":
        res.append(Health("notify", "ok", f"ntfy topic set, mode {cfg.notify.mode}"))
    else:
        res.append(Health("notify", "warn", "no ntfy topic configured",
                          "Set notify.ntfy_topic in config.toml and run `bastion test-push`"))
    return res


def to_text(items: list[Health]) -> str:
    lines = []
    for h in items:
        lines.append(f"[{h.status.upper():4}] {h.component:<10} {h.detail}")
        if h.fix:
            lines.append(f"       fix: {h.fix}")
    return "\n".join(lines)
