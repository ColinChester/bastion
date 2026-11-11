"""Agent tools. Each is a typed, read-only function backed by one edge API query.

Agents never get a shell. The set of things an agent can do is this table, and each
agent sees only its own row of it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    query: str                      # edge API query name
    params: dict[str, tuple[str, str]]  # name -> (json type, description)
    required: tuple[str, ...]

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": {k: {"type": t, "description": d}
                               for k, (t, d) in self.params.items()},
                "required": list(self.required),
                "additionalProperties": False,
            },
        }

    def clean(self, args: dict) -> dict:
        """Keep only declared parameters, coerced to their declared types."""
        out = {}
        for key, (typ, _) in self.params.items():
            if key in args and args[key] is not None:
                out[key] = int(args[key]) if typ == "integer" else str(args[key])
        missing = [r for r in self.required if r not in out]
        if missing:
            raise ValueError(f"missing required argument(s): {', '.join(missing)}")
        return out


_AT = ("integer", "Time of interest in epoch milliseconds (use the detection's time_ms).")
_WIN = ("integer", "Minutes before and after to include (default 30).")

GET_EVENT = Tool("get_event", "Fetch one recorded event by id.", "event",
                 {"event_id": ("integer", "Event id from the detection or another tool.")},
                 ("event_id",))
PROCESS_TREE = Tool(
    "get_process_tree",
    "Parents of a process (child first, up to the login shell or launchd) and the "
    "processes it started. Use it to learn what launched something.",
    "process-tree", {"pid": ("integer", "Process id."), "at_ms": _AT}, ("pid", "at_ms"))
BINARY_HISTORY = Tool(
    "get_binary_history",
    "How often a binary at this exact path has run on this Mac, with which command lines "
    "and parents, its code signature, and when Bastion first saw it.",
    "binary-history", {"path": ("string", "Absolute path of the binary."),
                       "days": ("integer", "How far back to look (default 14, max 30).")},
    ("path",))
PROCESS_ACTIVITY = Tool(
    "get_process_activity",
    "Everything recorded for one pid within an hour: executions, file events, sockets.",
    "process-activity", {"pid": ("integer", "Process id."), "at_ms": _AT}, ("pid", "at_ms"))
FILE_ACTIVITY = Tool(
    "get_file_activity",
    "File events (create, open, write, rename) on one exact path around a time, with the "
    "process responsible when known.",
    "file-activity", {"path": ("string", "Absolute file path."), "at_ms": _AT,
                      "window_minutes": _WIN}, ("path", "at_ms"))
RELATED = Tool(
    "get_related_detections",
    "Other detections that fired around the same time. Several different detections "
    "close together are stronger evidence than one alone.",
    "related-detections", {"at_ms": _AT, "window_minutes": _WIN}, ("at_ms",))
PERSISTENCE = Tool(
    "lookup_persistence",
    "Launch agents, daemons and login items Bastion has seen whose path or label contains "
    "the text, with first and last seen times, and any recently removed.",
    "persistence-lookup",
    {"contains": ("string", "Part of a label or path, at least 3 characters.")},
    ("contains",))
NETWORK_HISTORY = Tool(
    "get_network_history",
    "Listening ports and outbound connections recorded for a binary, and whether they "
    "are in the first-seen baseline.",
    "network-history", {"path": ("string", "Absolute path of the binary."),
                        "days": ("integer", "How far back to look (default 14, max 30).")},
    ("path",))

AGENT_TOOLS: dict[str, tuple[Tool, ...]] = {
    "sentry": (GET_EVENT, PROCESS_TREE, BINARY_HISTORY, PROCESS_ACTIVITY, FILE_ACTIVITY,
               RELATED),
    "anchor": (GET_EVENT, PERSISTENCE, FILE_ACTIVITY, PROCESS_TREE, BINARY_HISTORY, RELATED),
    "tide": (GET_EVENT, NETWORK_HISTORY, BINARY_HISTORY, PROCESS_TREE, RELATED),
}
