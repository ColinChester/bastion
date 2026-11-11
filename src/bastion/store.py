"""Local SQLite store.

Holds normalized (already redacted) events for `retention_days`, detections, the
first-seen baseline, collector checkpoints and small state values. Event bodies are
zlib-compressed JSON to keep a month of process telemetry small.

The `outbox` column on detections is for Phase 2: findings with published = 0 are
what bastiond will forward to the orchestrator.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
import zlib
from collections.abc import Iterator
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    time_ms    INTEGER NOT NULL,
    class_uid  INTEGER NOT NULL,
    source     TEXT NOT NULL,
    body       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events(time_ms);

CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY,
    time_ms     INTEGER NOT NULL,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    dedupe_key  TEXT NOT NULL,
    event_id    INTEGER,
    hits        INTEGER NOT NULL DEFAULT 1,
    last_ms     INTEGER NOT NULL,
    body        BLOB NOT NULL,
    published   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS detections_time ON detections(time_ms);
CREATE INDEX IF NOT EXISTS detections_dedupe ON detections(dedupe_key, last_ms);

CREATE TABLE IF NOT EXISTS baseline (
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    first_ms    INTEGER NOT NULL,
    last_ms     INTEGER NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (kind, key)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    source  TEXT PRIMARY KEY,
    inode   INTEGER,
    offset  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS state (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""


def _pack(obj: dict) -> bytes:
    return zlib.compress(json.dumps(obj, separators=(",", ":")).encode(), 6)


def _unpack(blob: bytes) -> dict:
    return json.loads(zlib.decompress(blob))


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.executescript(SCHEMA)
        if str(path) != ":memory:":
            with contextlib.suppress(OSError):
                self.path.chmod(0o600)

    def close(self) -> None:
        self.db.close()

    # ---- events -------------------------------------------------------------------
    def add_event(self, event: dict) -> int:
        cur = self.db.execute(
            "INSERT INTO events (time_ms, class_uid, source, body) VALUES (?, ?, ?, ?)",
            (
                int(event.get("time", time.time() * 1000)),
                int(event.get("class_uid", 0)),
                event.get("metadata", {}).get("log_name", "unknown"),
                _pack(event),
            ),
        )
        return int(cur.lastrowid)

    def get_event(self, event_id: int) -> dict | None:
        row = self.db.execute("SELECT body FROM events WHERE id = ?", (event_id,)).fetchone()
        return _unpack(row[0]) if row else None

    def iter_events(self, since_ms: int = 0, class_uid: int | None = None) -> Iterator[dict]:
        q = "SELECT id, body FROM events WHERE time_ms >= ?"
        args: list = [since_ms]
        if class_uid is not None:
            q += " AND class_uid = ?"
            args.append(class_uid)
        for event_id, body in self.db.execute(q + " ORDER BY time_ms", args):
            ev = _unpack(body)
            ev["_id"] = event_id
            yield ev

    def count_events_by_source(self, since_ms: int) -> dict[str, int]:
        rows = self.db.execute(
            "SELECT source, COUNT(*) FROM events WHERE time_ms >= ? GROUP BY source", (since_ms,)
        )
        return dict(rows.fetchall())

    # ---- detections ---------------------------------------------------------------
    def add_or_merge_detection(
        self, finding: dict, dedupe_key: str, window_ms: int, event_id: int | None
    ) -> tuple[int, bool]:
        """Insert a detection, or bump `hits` on a recent one with the same dedupe key.

        Returns (detection_id, is_new).
        """
        now = int(finding.get("time", time.time() * 1000))
        row = self.db.execute(
            "SELECT id FROM detections WHERE dedupe_key = ? AND last_ms >= ? "
            "ORDER BY id DESC LIMIT 1",
            (dedupe_key, now - window_ms),
        ).fetchone()
        if row:
            self.db.execute(
                "UPDATE detections SET hits = hits + 1, last_ms = ? WHERE id = ?", (now, row[0])
            )
            return int(row[0]), False
        info = finding["finding_info"]
        cur = self.db.execute(
            "INSERT INTO detections (time_ms, rule_id, title, severity, dedupe_key, event_id, "
            "last_ms, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                now,
                info["uid"],
                info["title"],
                finding.get("severity", "informational"),
                dedupe_key,
                event_id,
                now,
                _pack(finding),
            ),
        )
        return int(cur.lastrowid), True

    def iter_detections(self, since_ms: int = 0) -> Iterator[dict]:
        for row in self.db.execute(
            "SELECT id, time_ms, rule_id, title, severity, hits, last_ms, event_id, body "
            "FROM detections WHERE last_ms >= ? ORDER BY time_ms",
            (since_ms,),
        ):
            det_id, t, rule_id, title, sev, hits, last_ms, event_id, body = row
            yield {
                "id": det_id,
                "time_ms": t,
                "rule_id": rule_id,
                "title": title,
                "severity": sev,
                "hits": hits,
                "last_ms": last_ms,
                "event_id": event_id,
                "finding": _unpack(body),
            }

    # ---- baseline -----------------------------------------------------------------
    def baseline_touch(self, kind: str, key: str, now_ms: int) -> bool:
        """Record a sighting. Returns True if (kind, key) was never seen before."""
        cur = self.db.execute(
            "UPDATE baseline SET last_ms = ?, count = count + 1 WHERE kind = ? AND key = ?",
            (now_ms, kind, key),
        )
        if cur.rowcount:
            return False
        self.db.execute(
            "INSERT INTO baseline (kind, key, first_ms, last_ms) VALUES (?, ?, ?, ?)",
            (kind, key, now_ms, now_ms),
        )
        return True

    def baseline_size(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT kind, COUNT(*) FROM baseline GROUP BY kind"))

    # ---- checkpoints & state ------------------------------------------------------
    def get_checkpoint(self, source: str) -> tuple[int | None, int]:
        row = self.db.execute(
            "SELECT inode, offset FROM checkpoints WHERE source = ?", (source,)
        ).fetchone()
        return (row[0], row[1]) if row else (None, 0)

    def set_checkpoint(self, source: str, inode: int | None, offset: int) -> None:
        self.db.execute(
            "INSERT INTO checkpoints (source, inode, offset) VALUES (?, ?, ?) "
            "ON CONFLICT(source) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
            (source, inode, offset),
        )

    def get_state(self, key: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set_state(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO state (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # ---- maintenance --------------------------------------------------------------
    def purge(self, retention_days: int, now_ms: int | None = None,
              detection_retention_days: int | None = None) -> int:
        """Drop events older than retention_days and detections older than
        detection_retention_days (default: the same). Freed pages are reused, so the file
        stops growing at steady state rather than shrinking."""
        now_ms = now_ms or int(time.time() * 1000)
        cutoff = now_ms - retention_days * 86_400_000
        det_days = detection_retention_days or retention_days
        n = self.db.execute("DELETE FROM events WHERE time_ms < ?", (cutoff,)).rowcount
        self.db.execute("DELETE FROM detections WHERE last_ms < ?",
                        (now_ms - det_days * 86_400_000,))
        return n
