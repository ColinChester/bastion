"""Minimal OCSF (Open Cybersecurity Schema Framework) event builders.

Bastion normalizes every record to a small subset of OCSF 1.x so that detections,
storage and (later) the orchestrator all see one shape. Fields OCSF has no slot for
go under `unmapped`, as the spec recommends.

Classes used:
    1001 File System Activity   1007 Process Activity   4001 Network Activity
    2004 Detection Finding      0    Base Event (unified log lines)
"""

from __future__ import annotations

import time
from typing import Any

OCSF_VERSION = "1.3.0"
PRODUCT = {"name": "Bastion", "vendor_name": "Bastion"}

# class_uid -> (category_uid, class_name)
CLASSES = {
    0: (0, "Base Event"),
    1001: (1, "File System Activity"),
    1007: (1, "Process Activity"),
    2004: (2, "Detection Finding"),
    4001: (4, "Network Activity"),
}

# Process Activity
PROC_LAUNCH = 1
PROC_TERMINATE = 2
# File System Activity
FILE_CREATE = 1
FILE_READ = 2
FILE_UPDATE = 3
FILE_DELETE = 4
FILE_RENAME = 5
FILE_OTHER = 99
# Network Activity
NET_OPEN = 1
NET_LISTEN = 7

SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAMES = {v: k for k, v in SEVERITY.items()}


def now_ms() -> int:
    return int(time.time() * 1000)


def base(class_uid: int, activity_id: int, source: str, time_ms: int | None = None) -> dict:
    category_uid, class_name = CLASSES[class_uid]
    return {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "time": time_ms if time_ms is not None else now_ms(),
        "severity_id": 1,
        "metadata": {"version": OCSF_VERSION, "product": PRODUCT, "log_name": source},
    }


def file_obj(path: str | None) -> dict | None:
    if not path:
        return None
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return {"path": path, "name": name}


def process_obj(
    *,
    pid: int | None = None,
    path: str | None = None,
    cmd_line: str | None = None,
    uid: int | None = None,
    user: str | None = None,
    cwd: str | None = None,
    team_id: str | None = None,
) -> dict:
    proc: dict[str, Any] = {}
    if pid is not None:
        proc["pid"] = pid
    if cmd_line is not None:
        proc["cmd_line"] = cmd_line
    if cwd:
        proc["working_directory"] = cwd
    f = file_obj(path)
    if f:
        if team_id is not None:
            f["signature"] = {"developer_uid": team_id}
        proc["file"] = f
        proc["name"] = f["name"]
    if user is not None or uid is not None:
        proc["user"] = {k: v for k, v in (("name", user), ("uid", uid)) if v is not None}
    return proc


def get(event: dict, dotted: str, default: Any = None) -> Any:
    """Read a dotted path (e.g. 'process.file.path') from an event dict."""
    cur: Any = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def set_path(event: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = event
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def detection_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    tags: list[str],
    event: dict,
    event_id: int | None,
    description: str = "",
    analytic_type: str = "Rule",
) -> dict:
    finding = base(2004, 1, "bastion.detect")
    sev = SEVERITY.get(severity.lower(), 1)
    finding["severity_id"] = sev
    finding["severity"] = SEVERITY_NAMES[sev]
    attacks = []
    for tag in tags:
        t = tag.lower()
        if t.startswith("attack.t"):
            attacks.append({"technique": {"uid": tag.split(".", 1)[1].upper()}})
    finding["finding_info"] = {
        "uid": rule_id,
        "title": title,
        "desc": description,
        "analytic": {"uid": rule_id, "name": title, "type": analytic_type},
        "attacks": attacks,
        "tags": tags,
    }
    finding["evidences"] = [{"event_id": event_id, "class_uid": event.get("class_uid")}]
    # Copy the subjects so the finding is readable without a join.
    for key in ("process", "actor", "file", "dst_endpoint", "src_endpoint", "message"):
        if key in event:
            finding[key] = event[key]
    return finding
