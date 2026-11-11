"""Map raw collector records to OCSF events.

Every normalizer returns a list (possibly empty) of OCSF dicts. Records Bastion doesn't
use are dropped here rather than stored.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import OrderedDict
from datetime import datetime

from bastion import ocsf
from bastion.collectors import RawRecord

log = logging.getLogger(__name__)


_EVENT_QUERIES = {"process_events", "file_events", "fs_events"}


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class ProcessCache:
    """pid -> (path, cmdline) from recent exec events, to fill in parent details.

    osquery joins the parent from the live process table, but short-lived parents can
    exit before the scheduled query runs; this cache covers most of those.
    """

    def __init__(self, size: int = 4096):
        self._d: OrderedDict[int, tuple[str, str]] = OrderedDict()
        self.size = size

    def put(self, pid: int | None, path: str | None, cmdline: str | None) -> None:
        if pid is None or not path:
            return
        self._d[pid] = (path, cmdline or "")
        self._d.move_to_end(pid)
        while len(self._d) > self.size:
            self._d.popitem(last=False)

    def get(self, pid: int | None) -> tuple[str, str] | None:
        return self._d.get(pid) if pid is not None else None


class Normalizer:
    def __init__(self):
        self.procs = ProcessCache()

    def normalize(self, rec: RawRecord) -> list[dict]:
        try:
            if rec.source == "osquery":
                return self._osquery(rec.payload)
            if rec.source == "santa":
                return self._santa(rec.payload)
            if rec.source == "unified_log":
                return self._unified(rec.payload)
        except Exception:  # never let one malformed record kill the pipeline
            log.exception("normalize failed for %s record", rec.source)
        return []

    # ---- osquery ------------------------------------------------------------------
    def _osquery(self, rec: dict) -> list[dict]:
        name = rec.get("name", "")
        action = rec.get("action", "snapshot")
        cols = rec.get("columns") or {}
        t_ms = _int(cols.get("time"), None)
        t_ms = t_ms * 1000 if t_ms else _int(rec.get("unixTime"), int(time.time())) * 1000
        # osquery's first differential result for a state query (counter 0) lists
        # everything that already exists. Mark it so detections treat it as baseline, not
        # "new". Event tables (execs, file events) have no such backlog: their first batch
        # is real activity and must be evaluated.
        initial = (rec.get("counter") in (0, "0") and action == "added"
                   and name not in _EVENT_QUERIES)
        handler = {
            "process_events": self._oq_exec,
            "file_events": self._oq_es_file,
            "fs_events": self._oq_fsevents,
            "listening_ports": self._oq_listen,
            "open_sockets": self._oq_socket,
            "launchd": self._oq_persistence,
            "startup_items": self._oq_persistence,
        }.get(name)
        if handler is None:
            if action in ("added", "removed"):
                ev = ocsf.base(0, 0, "osquery", t_ms)
                ev["message"] = f"{name} {action}"
                ev["unmapped"] = {"inventory": {"kind": name, "action": action, "row": cols},
                                  "initial_snapshot": initial}
                return [ev]
            return []
        out = handler(cols, action, t_ms)
        for ev in out:
            ev.setdefault("unmapped", {})["initial_snapshot"] = initial
            ev["unmapped"]["osquery_query"] = name
        return out

    def _oq_exec(self, c: dict, action: str, t_ms: int) -> list[dict]:
        if action == "removed" or c.get("event_type", "exec") != "exec":
            return []
        pid = _int(c.get("pid"))
        ppid = _int(c.get("parent"))
        path = c.get("path") or ""
        if not path:
            return []
        cmdline = c.get("cmdline") or ""
        ev = ocsf.base(1007, ocsf.PROC_LAUNCH, "osquery", t_ms)
        ev["process"] = ocsf.process_obj(
            pid=pid, path=path, cmd_line=cmdline, uid=_int(c.get("uid")),
            user=c.get("username") or None, cwd=c.get("cwd"), team_id=c.get("team_id") or "",
        )
        parent_path, parent_cmd = c.get("parent_path"), c.get("parent_cmdline")
        if not parent_path:
            cached = self.procs.get(ppid)
            if cached:
                parent_path, parent_cmd = cached
        ev["actor"] = {"process": ocsf.process_obj(pid=ppid, path=parent_path,
                                                   cmd_line=parent_cmd)}
        ev["unmapped"] = {
            "signing_id": c.get("signing_id") or "",
            "team_id": c.get("team_id") or "",
            "cdhash": c.get("cdhash") or "",
            "platform_binary": _int(c.get("platform_binary"), 0),
            "codesigning_flags": c.get("codesigning_flags") or "",
            "env": c.get("env") or "",
        }
        self.procs.put(pid, path, cmdline)
        return [ev]

    _ES_FILE_ACTIVITY = {
        "create": ocsf.FILE_CREATE,
        "write": ocsf.FILE_UPDATE,
        "truncate": ocsf.FILE_UPDATE,
        "rename": ocsf.FILE_RENAME,
        "open": ocsf.FILE_READ,
    }

    def _oq_es_file(self, c: dict, action: str, t_ms: int) -> list[dict]:
        if action == "removed":
            return []
        etype = (c.get("event_type") or "").lower()
        activity = next((v for k, v in self._ES_FILE_ACTIVITY.items() if k in etype),
                        ocsf.FILE_OTHER)
        target = c.get("dest_filename") if activity == ocsf.FILE_RENAME else c.get("filename")
        ev = ocsf.base(1001, activity, "osquery", t_ms)
        ev["file"] = ocsf.file_obj(target or c.get("filename"))
        if activity == ocsf.FILE_RENAME and c.get("filename"):
            ev["file"]["unmapped_source_path"] = c["filename"]
        pid = _int(c.get("pid"))
        cached = self.procs.get(pid)
        ev["actor"] = {"process": ocsf.process_obj(
            pid=pid, path=c.get("path"), cmd_line=cached[1] if cached else None)}
        ev["activity_name"] = etype or "other"
        return [ev] if ev["file"] else []

    _FSEVENT_ACTIVITY = {
        "CREATED": ocsf.FILE_CREATE,
        "UPDATED": ocsf.FILE_UPDATE,
        "DELETED": ocsf.FILE_DELETE,
        "MOVED_TO": ocsf.FILE_RENAME,
        "ATTRIBUTES_MODIFIED": ocsf.FILE_UPDATE,
    }

    def _oq_fsevents(self, c: dict, action: str, t_ms: int) -> list[dict]:
        if action == "removed":
            return []
        acts = (c.get("action") or "").split("|")
        activity = next((self._FSEVENT_ACTIVITY[a] for a in acts if a in self._FSEVENT_ACTIVITY),
                        ocsf.FILE_OTHER)
        ev = ocsf.base(1001, activity, "osquery", t_ms)
        ev["file"] = ocsf.file_obj(c.get("target_path"))
        if ev["file"] and c.get("sha256"):
            ev["file"]["hashes"] = [{"algorithm": "SHA-256", "value": c["sha256"]}]
        ev["activity_name"] = c.get("action", "")
        return [ev] if ev["file"] else []

    def _oq_listen(self, c: dict, action: str, t_ms: int) -> list[dict]:
        if action != "added":
            return []
        ev = ocsf.base(4001, ocsf.NET_LISTEN, "osquery", t_ms)
        ev["src_endpoint"] = {"ip": c.get("address"), "port": _int(c.get("port"))}
        ev["connection_info"] = {"protocol_num": _int(c.get("protocol"))}
        ev["process"] = ocsf.process_obj(pid=_int(c.get("pid")), path=c.get("path"))
        return [ev]

    def _oq_socket(self, c: dict, action: str, t_ms: int) -> list[dict]:
        if action != "added":
            return []
        ev = ocsf.base(4001, ocsf.NET_OPEN, "osquery", t_ms)
        ev["dst_endpoint"] = {"ip": c.get("remote_address"), "port": _int(c.get("remote_port"))}
        ev["connection_info"] = {"protocol_num": _int(c.get("protocol"))}
        ev["process"] = ocsf.process_obj(path=c.get("path"))
        return [ev]

    def _oq_persistence(self, c: dict, action: str, t_ms: int) -> list[dict]:
        activity = ocsf.FILE_CREATE if action == "added" else ocsf.FILE_DELETE
        ev = ocsf.base(1001, activity, "osquery", t_ms)
        ev["file"] = ocsf.file_obj(c.get("path")) or {"path": "", "name": c.get("name", "")}
        program = c.get("program") or c.get("program_arguments") or c.get("args") or ""
        ev["unmapped"] = {
            "persistence": {
                "type": "launchd" if "label" in c else (c.get("type") or "startup_item"),
                "label": c.get("label") or c.get("name") or "",
                "program": program,
                "run_at_load": c.get("run_at_load", ""),
                "username": c.get("username", ""),
            }
        }
        return [ev]

    # ---- santa --------------------------------------------------------------------
    _SANTA_PREFIX = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+\w\s+santad:\s*(?P<body>.*)$")
    _SANTA_SPLIT = re.compile(r"\|(?=[a-z_]+=)")

    def _santa(self, line: str) -> list[dict]:
        line = line.strip()
        if line.startswith("{"):
            return self._santa_json(json.loads(line))
        m = self._SANTA_PREFIX.match(line)
        if not m:
            return []
        fields = {}
        for part in self._SANTA_SPLIT.split(m.group("body")):
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k] = v
        t_ms = _parse_iso_ms(m.group("ts"))
        if fields.get("action") != "EXEC":
            return []
        return [self._santa_exec(fields, t_ms)]

    def _santa_exec(self, f: dict, t_ms: int) -> dict:
        ev = ocsf.base(1007, ocsf.PROC_LAUNCH, "santa", t_ms)
        pid, ppid = _int(f.get("pid")), _int(f.get("ppid"))
        ev["process"] = ocsf.process_obj(
            pid=pid, path=f.get("path"), cmd_line=f.get("args"), uid=_int(f.get("uid")),
            user=f.get("user"), team_id=f.get("teamid", ""),
        )
        if f.get("sha256") and "file" in ev["process"]:
            ev["process"]["file"]["hashes"] = [{"algorithm": "SHA-256", "value": f["sha256"]}]
        cached = self.procs.get(ppid)
        ev["actor"] = {"process": ocsf.process_obj(
            pid=ppid, path=cached[0] if cached else None, cmd_line=cached[1] if cached else None)}
        ev["unmapped"] = {
            "team_id": f.get("teamid", ""),
            "signing_id": f.get("signingid", ""),
            "santa": {
                "decision": f.get("decision", ""),
                "reason": f.get("reason", ""),
                "mode": f.get("mode", ""),
                "cert_cn": f.get("cert_cn", ""),
            },
        }
        # Santa logs each exec within a second, osquery only every 10 s. Caching Santa's
        # execs lets osquery's later copy of a child resolve a parent that already exited.
        self.procs.put(pid, f.get("path"), f.get("args"))
        return ev

    def _santa_json(self, d: dict) -> list[dict]:
        # Santa's JSON logging (beta) mirrors its protobuf schema; read defensively.
        ex = d.get("execution")
        if not ex:
            return []
        target = ex.get("target", {})
        exe = target.get("executable", {})
        inst = d.get("instigator") or ex.get("instigator") or {}
        f = {
            "path": exe.get("path"),
            "args": " ".join(ex.get("args", [])) if isinstance(ex.get("args"), list)
            else ex.get("args"),
            "pid": target.get("id", {}).get("pid"),
            "ppid": target.get("parent_id", {}).get("pid") or inst.get("id", {}).get("pid"),
            "uid": target.get("effective_user", {}).get("uid"),
            "user": target.get("effective_user", {}).get("name"),
            "teamid": target.get("team_id", ""),
            "signingid": target.get("signing_id", ""),
            "sha256": exe.get("hash", {}).get("hash"),
            "decision": str(ex.get("decision", "")).replace("DECISION_", ""),
            "reason": str(ex.get("reason", "")).replace("REASON_", ""),
            "mode": str(ex.get("mode", "")).replace("MODE_", ""),
        }
        t_ms = _parse_iso_ms(d.get("event_time", "")) if d.get("event_time") else None
        return [self._santa_exec(f, t_ms or int(time.time() * 1000))]

    # ---- unified log --------------------------------------------------------------
    def _unified(self, d: dict) -> list[dict]:
        t_ms = _parse_unified_ts(d.get("timestamp", "")) or int(time.time() * 1000)
        ev = ocsf.base(0, 0, "unified_log", t_ms)
        ev["message"] = d.get("eventMessage", "")
        ev["actor"] = {"process": ocsf.process_obj(pid=_int(d.get("processID")),
                                                   path=d.get("processImagePath"))}
        ev["unmapped"] = {"subsystem": d.get("subsystem", ""), "category": d.get("category", "")}
        return [ev]


def _parse_iso_ms(ts: str) -> int:
    try:
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return int(time.time() * 1000)


def _parse_unified_ts(ts: str) -> int | None:
    # e.g. "2026-10-31 16:02:03.123456-0400"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return int(datetime.strptime(ts, fmt).timestamp() * 1000)
        except ValueError:
            continue
    return None
