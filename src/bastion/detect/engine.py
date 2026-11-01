"""Detection engine: Sigma rules plus first-seen baseline analytics.

Sigma handles stateless patterns. "First time this happened on this Mac" needs state,
so three analytics live here instead, backed by the store's baseline table:

    first-seen non-Apple binary executed          (low)
    first-seen outbound connection by a binary    (medium)
    first-seen listening port for a binary        (medium)

plus one short-window correlation, because an interactive `curl URL | sh` runs as two
sibling processes and neither command line contains the pipe:

    curl/wget and a stdin-reading shell started by the same parent within 3 s  (high)

During the learning window (default 14 days from install, which is also the shadow
period) sightings are recorded silently. After it, a new key produces a finding.
Binaries under "built locally" paths (config baseline.dev_path_markers) never do.
"""

from __future__ import annotations

import logging
import shlex
import time
from collections import deque
from dataclasses import dataclass

from bastion import ocsf
from bastion.config import Config
from bastion.detect.sigma import SigmaRule, load_rules
from bastion.store import Store

log = logging.getLogger(__name__)

INSTALL_KEY = "install_ms"

FETCH_PIPE_RULE = "bastion-fetch-piped-to-shell"
FETCH_PIPE_WINDOW_MS = 3_000
_FETCHERS = {"curl", "wget"}
_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby"}


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _reads_stdin(cmdline: str) -> bool:
    """True if an interpreter's command line names no script or -c code (so it runs stdin)."""
    try:
        argv = shlex.split(cmdline)
    except ValueError:
        argv = cmdline.split()
    args = argv[1:]
    if "-s" in args or "-" in args:
        return True
    return not any(not a.startswith("-") for a in args) and "-c" not in args


@dataclass
class Hit:
    finding: dict
    dedupe_key: str


def _subject(event: dict) -> str:
    """What a detection is about, for de-duplication (not pid: re-runs should merge)."""
    if event.get("class_uid") == 1001 and ocsf.get(event, "file.path"):
        # File events: the file is the subject. The same write is often seen twice (ES
        # with the writing process, FSEvents without one) and should merge into one hit.
        return f"file|{ocsf.get(event, 'file.path')}"
    parts = [
        ocsf.get(event, "process.file.path") or ocsf.get(event, "actor.process.file.path") or "",
        ocsf.get(event, "file.path") or "",
        str(ocsf.get(event, "dst_endpoint.ip") or ""),
        str(ocsf.get(event, "src_endpoint.port") or ""),
    ]
    return "|".join(parts)


class DetectionEngine:
    def __init__(self, cfg: Config, store: Store, rules: list[SigmaRule] | None = None):
        self.cfg = cfg
        self.store = store
        if rules is None:
            rules, errors = load_rules(cfg.resolved_rules_dir())
            for err in errors:
                log.error("rule failed to load: %s", err)
        self.rules = rules
        if store.get_state(INSTALL_KEY) is None:
            store.set_state(INSTALL_KEY, str(int(time.time() * 1000)))
        self._markers = [m.lower() for m in cfg.baseline.dev_path_markers]
        # (time_ms, parent_pid, kind, path, cmdline) of recent fetcher/interpreter execs
        self._recent_execs: deque[tuple[int, int, str, str, str]] = deque(maxlen=512)

    # ---- public -------------------------------------------------------------------
    def learning(self, now_ms: int | None = None) -> bool:
        now_ms = now_ms or int(time.time() * 1000)
        install = int(self.store.get_state(INSTALL_KEY) or now_ms)
        return now_ms < install + self.cfg.baseline.learning_days * 86_400_000

    def evaluate(self, event: dict, event_id: int | None = None) -> list[Hit]:
        hits: list[Hit] = []
        initial = bool(ocsf.get(event, "unmapped.initial_snapshot"))
        self._mark_known_persistence(event)
        if not initial:
            for rule in self.rules:
                try:
                    matched = rule.matches(event)
                except Exception:
                    log.exception("rule %s raised", rule.id)
                    continue
                if matched:
                    finding = ocsf.detection_finding(
                        rule_id=rule.id, title=rule.title, severity=rule.level,
                        tags=rule.tags, event=event, event_id=event_id,
                        description=rule.description, analytic_type="Rule",
                    )
                    hits.append(Hit(finding, f"{rule.id}|{_subject(event)}"))
        hits.extend(self._first_seen(event, event_id, initial))
        if not initial:
            hits.extend(self._fetch_piped_to_shell(event, event_id))
        return hits

    # ---- persistence --------------------------------------------------------------
    def _mark_known_persistence(self, event: dict) -> None:
        """Remember every launch item ever seen and flag re-appearances.

        osquery reports an existing item as "added" again when it can suddenly see more
        (Full Disk Access granted after the first run) or when the item flickers. The
        Sigma rule ignores items marked seen_before, so only genuinely new ones alert.
        """
        p = ocsf.get(event, "unmapped.persistence")
        if not isinstance(p, dict) or event.get("activity_id") != ocsf.FILE_CREATE:
            return
        key = "|".join([p.get("type", ""), ocsf.get(event, "file.path") or "",
                        p.get("label", "")])
        now = int(event.get("time") or time.time() * 1000)
        p["seen_before"] = not self.store.baseline_touch("persistence", key, now)

    # ---- correlation --------------------------------------------------------------
    def _fetch_piped_to_shell(self, event: dict, event_id: int | None) -> list[Hit]:
        if event.get("class_uid") != 1007 or event.get("activity_id") != ocsf.PROC_LAUNCH:
            return []
        if ocsf.get(event, "metadata.log_name") != "osquery":
            return []  # Santa sees the same execs; one source is enough
        path = ocsf.get(event, "process.file.path") or ""
        cmd = ocsf.get(event, "process.cmd_line") or ""
        ppid = ocsf.get(event, "actor.process.pid")
        name = _basename(path)
        if name in _FETCHERS:
            kind = "fetch"
        elif name in _INTERPRETERS and _reads_stdin(cmd):
            kind = "shell"
        else:
            return []
        if not ppid or ppid <= 1:
            return []
        now = int(event.get("time") or time.time() * 1000)
        while self._recent_execs and abs(now - self._recent_execs[0][0]) > 10_000:
            self._recent_execs.popleft()
        partner = next(
            (r for r in reversed(self._recent_execs)
             if r[1] == ppid and r[2] != kind and abs(now - r[0]) <= FETCH_PIPE_WINDOW_MS),
            None,
        )
        self._recent_execs.append((now, ppid, kind, path, cmd))
        if partner is None:
            return []
        fetch_cmd = cmd if kind == "fetch" else partner[4]
        shell_path = partner[3] if kind == "fetch" else path
        finding = ocsf.detection_finding(
            rule_id=FETCH_PIPE_RULE, title="Download piped into a shell (interactive)",
            severity="high", tags=["attack.execution", "attack.t1059.004", "attack.t1105"],
            event=event, event_id=event_id, analytic_type="Behavioral",
            description=f"{fetch_cmd!r} and {_basename(shell_path)} reading stdin were "
                        f"started together by the same parent (pid {ppid}).",
        )
        return [Hit(finding, f"{FETCH_PIPE_RULE}|{fetch_cmd}")]

    # ---- first-seen ---------------------------------------------------------------
    def _is_dev_path(self, path: str) -> bool:
        p = path.lower()
        return any(m in p for m in self._markers)

    def _first_seen(self, event: dict, event_id: int | None, initial: bool) -> list[Hit]:
        cls, act = event.get("class_uid"), event.get("activity_id")
        source = ocsf.get(event, "metadata.log_name")
        now = int(event.get("time") or time.time() * 1000)
        checks: list[tuple[str, str, str, str, list[str]]] = []
        if cls == 1007 and act == ocsf.PROC_LAUNCH and source == "osquery":
            path = ocsf.get(event, "process.file.path") or ""
            if path and not ocsf.get(event, "unmapped.platform_binary") \
                    and not self._is_dev_path(path):
                team = ocsf.get(event, "unmapped.team_id") or "unsigned"
                checks.append(("binary", f"{team}:{path}", "bastion-fs-binary",
                               "First-seen non-Apple binary executed", ["attack.t1204"]))
        elif cls == 4001 and act == ocsf.NET_OPEN:
            path = ocsf.get(event, "process.file.path") or ""
            if path:
                checks.append(("egress", path, "bastion-fs-egress",
                               "First outbound connection by this binary",
                               ["attack.t1071"]))
        elif cls == 4001 and act == ocsf.NET_LISTEN:
            path = ocsf.get(event, "process.file.path") or ""
            port = ocsf.get(event, "src_endpoint.port")
            ip = str(ocsf.get(event, "src_endpoint.ip") or "")
            if path and port and ip not in ("127.0.0.1", "::1"):
                # Ports in the ephemeral range change on every launch (rapportd, AltServer);
                # treat them as one "random port" per binary so they don't alert forever.
                port_key = port if port < 49152 else "ephemeral"
                checks.append(("listener", f"{path}:{port_key}", "bastion-fs-listener",
                               "First-seen listening port for this binary",
                               ["attack.t1571"]))
        hits = []
        learning = self.learning(now)
        for kind, key, rule_id, title, tags in checks:
            new = self.store.baseline_touch(kind, key, now)
            if new and not learning and not initial:
                severity = "low" if kind == "binary" else "medium"
                finding = ocsf.detection_finding(
                    rule_id=rule_id, title=title, severity=severity, tags=tags,
                    event=event, event_id=event_id, analytic_type="Behavioral",
                    description=f"No {kind} sighting matching {key!r} in the learned baseline.",
                )
                hits.append(Hit(finding, f"{rule_id}|{key}"))
        return hits
