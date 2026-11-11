"""Edge API: the only door between the orchestrator and this Mac (Phase 2).

bastiond serves a small HTTP API on localhost so the orchestrator, which runs in a
container, can pull detections and ask fixed, read-only questions about the telemetry.
It is the Phase 2 form of the plan's domain gateways:

- Every endpoint is a typed query with bounded output. There is no free-form SQL, no
  shell, and nothing that changes the system. The single write is "mark this detection
  as triaged".
- Everything returned was already redacted before it was stored.
- A bearer token (root-only in config.toml) is required on every request, and the server
  binds to 127.0.0.1 unless configured otherwise.

`EdgeQueries` holds the logic so it can be tested without HTTP.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from bastion import ocsf
from bastion.config import Config
from bastion.store import Store

log = logging.getLogger(__name__)

HOUR_MS = 3_600_000
DAY_MS = 86_400_000
MAX_TEXT = 600


def _clip(text, limit: int = MAX_TEXT):
    if isinstance(text, str) and len(text) > limit:
        return text[:limit] + f"… [{len(text) - limit} more chars]"
    return text


def brief(event: dict) -> dict:
    """A compact view of an OCSF event: what an analyst needs, in few tokens."""
    g = lambda path: ocsf.get(event, path)  # noqa: E731
    out: dict = {
        "event_id": event.get("_id"),
        "time_ms": event.get("time"),
        "source": g("metadata.log_name"),
        "class": {1001: "file", 1007: "process", 4001: "network", 2004: "detection"}.get(
            event.get("class_uid"), "other"),
        "activity_id": event.get("activity_id"),
    }
    if g("process.file.path") or g("process.pid"):
        out["process"] = {"pid": g("process.pid"), "path": g("process.file.path"),
                          "cmd_line": _clip(g("process.cmd_line")),
                          "user": g("process.user.name"), "cwd": g("process.cwd")}
    if g("actor.process.pid") or g("actor.process.file.path"):
        out["parent"] = {"pid": g("actor.process.pid"), "path": g("actor.process.file.path"),
                         "cmd_line": _clip(g("actor.process.cmd_line"))}
    if g("file.path"):
        out["file"] = {"path": g("file.path")}
    signing = {k: g(f"unmapped.{k}") for k in
               ("team_id", "signing_id", "platform_binary", "codesigning_flags")}
    if any(v not in (None, "") for v in signing.values()):
        out["signing"] = signing
    if g("unmapped.santa"):
        out["santa"] = g("unmapped.santa")
    if g("unmapped.persistence"):
        out["persistence"] = g("unmapped.persistence")
    for side in ("src_endpoint", "dst_endpoint"):
        if g(side):
            out[side] = g(side)
    if event.get("message"):
        out["message"] = _clip(event["message"])
    return {k: v for k, v in out.items() if v is not None}


def brief_detection(d: dict) -> dict:
    f = d["finding"]
    return {
        "detection_id": d["id"], "time_ms": d["time_ms"], "last_ms": d["last_ms"],
        "hits": d["hits"], "rule_id": d["rule_id"], "title": d["title"],
        "severity": d["severity"], "event_id": d["event_id"],
        "description": _clip(ocsf.get(f, "finding_info.desc"), 900),
        "attack_techniques": [a.get("technique", {}).get("uid") for a in
                              ocsf.get(f, "finding_info.attacks") or [] if a.get("technique")],
        "analytic_type": ocsf.get(f, "finding_info.analytic.type"),
        "subject": brief(f),
    }


class EdgeQueries:
    """Typed, bounded, read-only queries (plus the outbox acknowledgement)."""

    def __init__(self, store: Store):
        self.store = store

    # ---- outbox -------------------------------------------------------------------
    def pending(self, since_ms: int = 0, limit: int = 20) -> list[dict]:
        return [brief_detection(d) for d in self.store.detections_pending(since_ms, limit)]

    def detection(self, det_id: int) -> dict | None:
        d = self.store.get_detection(det_id)
        return brief_detection(d) if d else None

    def ack(self, det_id: int) -> bool:
        return self.store.ack_detection(det_id)

    def detections_window(self, start_ms: int, end_ms: int, limit: int = 50) -> list[dict]:
        end_ms = min(end_ms, start_ms + 31 * DAY_MS)
        return [brief_detection(d)
                for d in self.store.detections_between(start_ms, end_ms, limit)]

    # ---- investigation queries ----------------------------------------------------
    def event(self, event_id: int) -> dict | None:
        ev = self.store.get_event(event_id)
        if ev is None:
            return None
        ev["_id"] = event_id
        return brief(ev)

    def process_tree(self, pid: int, at_ms: int, max_depth: int = 8) -> dict:
        """Ancestors of a process (nearest exec at or before `at_ms`) and its children."""
        chain: list[dict] = []
        cur_pid, cur_t = pid, at_ms + 2_000
        seen: set[int] = set()
        for _ in range(max_depth):
            if cur_pid in seen or cur_pid is None or cur_pid <= 1:
                break
            seen.add(cur_pid)
            rows = self.store.events_where("pid", cur_pid, since_ms=cur_t - DAY_MS,
                                           until_ms=cur_t, limit=4, class_uid=1007)
            if not rows:
                chain.append({"pid": cur_pid, "note": "no exec event recorded for this pid"})
                break
            ev = rows[0]
            chain.append(brief(ev))
            cur_pid = ocsf.get(ev, "actor.process.pid")
            cur_t = int(ev.get("time", cur_t))
        kids = self.store.events_where("ppid", pid, since_ms=at_ms - 5_000,
                                       until_ms=at_ms + HOUR_MS, limit=40, class_uid=1007,
                                       newest_first=False)
        children, seen_kids = [], set()
        for ev in kids:  # osquery and Santa both report each exec; keep one per pid+path
            key = (ocsf.get(ev, "process.pid"), ocsf.get(ev, "process.file.path"))
            if key not in seen_kids:
                seen_kids.add(key)
                children.append(brief(ev))
        return {"lineage_child_first": chain, "children": children[:20]}

    def binary_history(self, path: str, days: int = 14) -> dict:
        """How often and how a binary has run here, and whether it is in the baseline."""
        since = int(time.time() * 1000) - min(max(days, 1), 30) * DAY_MS
        stats = self.store.proc_path_stats(path, since)
        recent = self.store.events_where("proc_path", path, since_ms=since, limit=40,
                                         class_uid=1007)
        cmds, parents, signing = [], [], None
        for ev in recent:
            c = _clip(ocsf.get(ev, "process.cmd_line"), 300)
            if c and c not in cmds and len(cmds) < 8:
                cmds.append(c)
            pp = ocsf.get(ev, "actor.process.file.path")
            if pp and pp not in parents and len(parents) < 8:
                parents.append(pp)
            signing = signing or brief(ev).get("signing")
        team = (signing or {}).get("team_id") or ""
        return {
            "path": path, **stats, "distinct_cmd_lines": cmds, "parent_binaries": parents,
            "signing": signing,
            "first_seen_baseline": self.store.baseline_entry("binary", f"{team}:{path}"),
            "egress_baseline": self.store.baseline_entry("egress", path),
        }

    def file_activity(self, path: str, at_ms: int, window_minutes: int = 30,
                      limit: int = 40) -> list[dict]:
        """File events on one exact path around a time."""
        w = min(max(window_minutes, 1), 24 * 60) * 60_000
        rows = self.store.events_where("file_path", path, since_ms=at_ms - w,
                                       until_ms=at_ms + w, limit=limit, class_uid=1001,
                                       newest_first=False)
        return [brief(ev) for ev in rows]

    def process_activity(self, pid: int, at_ms: int, limit: int = 40) -> list[dict]:
        """Everything recorded for one pid within an hour of a time (execs, files, sockets)."""
        rows = self.store.events_where("pid", pid, since_ms=at_ms - HOUR_MS,
                                       until_ms=at_ms + HOUR_MS, limit=limit,
                                       newest_first=False)
        return [brief(ev) for ev in rows]

    def persistence_lookup(self, contains: str) -> dict:
        """Launch items Bastion has seen whose type, path or label contains the text."""
        if len(contains) < 3:
            return {"error": "search text must be at least 3 characters"}
        return {"known_items": self.store.baseline_search("persistence", contains),
                "recently_removed": self.store.baseline_search("persistence_removed",
                                                               contains)}

    def network_history(self, path: str, days: int = 14, limit: int = 40) -> dict:
        """Listeners and outbound connections recorded for a binary."""
        since = int(time.time() * 1000) - min(max(days, 1), 30) * DAY_MS
        rows = self.store.events_where("proc_path", path, since_ms=since, limit=limit,
                                       class_uid=4001)
        return {"path": path, "events": [brief(ev) for ev in rows],
                "egress_baseline": self.store.baseline_entry("egress", path),
                "listener_baselines": self.store.baseline_search("listener", path)}

    def status(self) -> dict:
        """Sensor freshness and 24 h counts, for the daily digest."""
        from bastion.daemon import HEARTBEAT_KEY

        now = int(time.time() * 1000)
        seen = {n: self.store.get_state(f"last_seen.{n}") for n in ("osquery", "santa")}
        hb = self.store.get_state(HEARTBEAT_KEY)
        return {
            "heartbeat_age_s": (now - int(hb)) // 1000 if hb else None,
            "sensor_age_s": {n: (now - int(v)) // 1000 if v else None
                             for n, v in seen.items()},
            "events_24h": self.store.count_events_by_source(now - DAY_MS),
            "detections_24h": len(self.store.detections_between(now - DAY_MS, now, 500)),
            "baseline": self.store.baseline_size(),
        }

    def related_detections(self, at_ms: int, window_minutes: int = 30) -> list[dict]:
        w = min(max(window_minutes, 1), 24 * 60) * 60_000
        return self.detections_window(at_ms - w, at_ms + w, limit=30)


# name -> (method, {param: type}); the HTTP layer accepts exactly these.
ROUTES: dict[str, tuple[str, dict[str, type]]] = {
    "pending": ("pending", {"since_ms": int, "limit": int}),
    "detection": ("detection", {"det_id": int}),
    "detections-window": ("detections_window", {"start_ms": int, "end_ms": int, "limit": int}),
    "event": ("event", {"event_id": int}),
    "process-tree": ("process_tree", {"pid": int, "at_ms": int}),
    "binary-history": ("binary_history", {"path": str, "days": int}),
    "file-activity": ("file_activity", {"path": str, "at_ms": int, "window_minutes": int}),
    "process-activity": ("process_activity", {"pid": int, "at_ms": int}),
    "persistence-lookup": ("persistence_lookup", {"contains": str}),
    "network-history": ("network_history", {"path": str, "days": int}),
    "status": ("status", {}),
    "related-detections": ("related_detections", {"at_ms": int, "window_minutes": int}),
}


def dispatch(queries: EdgeQueries, name: str, raw: dict[str, str]):
    """Run one named query with string parameters. Raises KeyError/ValueError on bad input."""
    method, spec = ROUTES[name]
    unknown = set(raw) - set(spec)
    if unknown:
        raise ValueError(f"unknown parameter(s): {', '.join(sorted(unknown))}")
    kwargs = {k: spec[k](v) for k, v in raw.items()}
    return getattr(queries, method)(**kwargs)


def _handler(db_path, token: str):
    local = threading.local()

    def queries() -> EdgeQueries:  # one SQLite connection per server thread
        if not hasattr(local, "q"):
            local.q = EdgeQueries(Store(db_path))
        return local.q

    class Handler(BaseHTTPRequestHandler):
        server_version = "bastion-edge/1"

        def log_message(self, fmt, *args):  # quiet; bastiond has its own log
            log.debug("edge api: " + fmt, *args)

        def _send(self, code: int, payload) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            given = self.headers.get("Authorization", "")
            return hmac.compare_digest(given.encode(), f"Bearer {token}".encode())

        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            if url.path == "/v1/health":
                return self._send(200, {"ok": True})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            name = url.path.removeprefix("/v1/")
            if name not in ROUTES:
                return self._send(404, {"error": "unknown query"})
            raw = {k: v[-1] for k, v in parse_qs(url.query).items()}
            try:
                result = dispatch(queries(), name, raw)
            except (ValueError, TypeError) as exc:
                return self._send(400, {"error": str(exc)})
            except Exception:
                log.exception("edge api query %s failed", name)
                return self._send(500, {"error": "query failed"})
            if result is None:
                return self._send(404, {"error": "not found"})
            self._send(200, {"result": result})

        def do_POST(self):  # noqa: N802
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            parts = urlparse(self.path).path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["v1", "detections"] and parts[3] == "ack":
                try:
                    ok = queries().ack(int(parts[2]))
                except ValueError:
                    return self._send(400, {"error": "bad detection id"})
                return self._send(200 if ok else 404, {"acked": ok})
            self._send(404, {"error": "unknown action"})

    return Handler


def start_edge_api(cfg: Config) -> ThreadingHTTPServer | None:
    """Start the API in a background thread. Returns the server, or None if disabled."""
    api = cfg.edge_api
    if not api.enabled:
        return None
    if len(api.token) < 32:
        log.error("edge API not started: edge_api.token must be at least 32 characters")
        return None
    server = ThreadingHTTPServer((api.bind, api.port), _handler(cfg.db_path, api.token))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="edge-api", daemon=True).start()
    log.info("edge API listening on %s:%d", api.bind, server.server_address[1])
    return server
