"""Which object an action applies to, derived from telemetry in code.

A model can propose *that* something be suspended or quarantined. It never says *what*:
the target always comes from the detection that bastiond recorded. So a fooled model
can at worst cause an allowed action on the object the detection was already about.
"""

from __future__ import annotations

CONTAIN_ACTIONS = ("suspend_process", "quarantine_file", "disable_launch_item")
# After an automatic containment, the permanent step that is offered for approval.
FOLLOW_UP = {"quarantine_file": "delete_quarantined",
             "disable_launch_item": "delete_disabled_item"}
OWNER = {"suspend_process": "sentry", "quarantine_file": "sentry",
         "disable_launch_item": "anchor"}


def derive_args(action: str, detection: dict) -> dict | None:
    """Typed executor arguments for `action`, or None if the detection has no such target."""
    subject = detection.get("subject") or {}
    proc = subject.get("process") or {}
    file_path = (subject.get("file") or {}).get("path") or ""
    if action == "suspend_process":
        if isinstance(proc.get("pid"), int) and proc.get("path"):
            return {"pid": proc["pid"], "path": proc["path"]}
    elif action == "quarantine_file":
        # Always the program that ran, never a file it touched (which may be the victim's).
        if proc.get("path"):
            return {"path": proc["path"]}
    elif (action == "disable_launch_item" and file_path.endswith(".plist")
          and ("/LaunchAgents/" in file_path or "/LaunchDaemons/" in file_path)):
        return {"path": file_path}
    return None
