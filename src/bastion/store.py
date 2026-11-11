"""Local SQLite store.

Holds normalized (already redacted) events for `retention_days`, detections, the
first-seen baseline, collector checkpoints and small state values. Event bodies are
zlib-compressed JSON to keep a month of process telemetry small.

Detections double as the outbox for the orchestrator: rows with published = 0 haven't
been triaged yet (`detections_pending`, `ack_detection`).

Events carry a few indexed lookup columns (pid, ppid, proc_path, file_path) so the edge
API can answer agent questions (process tree, binary history, file activity) without
scanning compressed bodies. Events stored before those columns existed have NULLs there.
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


_EVENT_COLUMNS = {"pid": "INTEGER", "ppid": "INTEGER", "proc_path": "TEXT", "file_path": "TEXT"}

INDEXES = """
CREATE INDEX IF NOT EXISTS events_pid ON events(pid, time_ms);
CREATE INDEX IF NOT EXISTS events_ppid ON events(ppid, time_ms);
CREATE INDEX IF NOT EXISTS events_proc_path ON events(proc_path, time_ms);
CREATE INDEX IF NOT EXISTS events_file_path ON events(file_path, time_ms);
CREATE INDEX IF NOT EXISTS detections_published ON detections(published, id);
"""


def _dig(obj: dict, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


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
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.executescript(SCHEMA)
        self._migrate()
        if str(path) != ":memory:":
            with contextlib.suppress(OSError):
                self.path.chmod(0o600)

    def close(self) -> None:
        self.db.close()

    def _migrate(self) -> None:
        have = {row[1] for row in self.db.execute("PRAGMA table_info(events)")}
        for col, typ in _EVENT_COLUMNS.items():
            if col not in have:
                self.db.execute(f"ALTER TABLE events ADD COLUMN {col} {typ}")
        self.db.executescript(INDEXES)

    # ---- events -------------------------------------------------------------------
    def add_event(self, event: dict) -> int:
        cur = self.db.execute(
            "INSERT INTO events (time_ms, class_uid, source, body, pid, ppid, proc_path, "
            "file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                int(event.get("time", time.time() * 1000)),
                int(event.get("class_uid", 0)),
                event.get("metadata", {}).get("log_name", "unknown"),
                _pack(event),
                _dig(event, "process.pid"),
                _dig(event, "actor.process.pid"),
                _dig(event, "process.file.path"),
                _dig(event, "file.path"),
            ),
        )
        return int(cur.lastrowid)

    def events_where(self, column: str, value, since_ms: int = 0,
                     until_ms: int | None = None, limit: int = 50,
                     class_uid: int | None = None, newest_first: bool = True) -> list[dict]:
        """Events whose indexed lookup column equals `value`, within a time window."""
        if column not in _EVENT_COLUMNS:
            raise ValueError(f"not a lookup column: {column}")
        q = f"SELECT id, body FROM events WHERE {column} = ? AND time_ms >= ?"
        args: list = [value, since_ms]
        if until_ms is not None:
            q += " AND time_ms <= ?"
            args.append(until_ms)
        if class_uid is not None:
            q += " AND class_uid = ?"
            args.append(class_uid)
        q += f" ORDER BY time_ms {'DESC' if newest_first else 'ASC'} LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        out = []
        for event_id, body in self.db.execute(q, args):
            ev = _unpack(body)
            ev["_id"] = event_id
            out.append(ev)
        return out

    def backfill_lookup_columns(self, batch: int = 2000, max_rows: int | None = None) -> int:
        """Fill the lookup columns for events stored before they existed. Resumable."""
        done = 0
        last = int(self.get_state("backfill_last_id") or 0)
        while max_rows is None or done < max_rows:
            rows = self.db.execute(
                "SELECT id, body FROM events WHERE id > ? AND pid IS NULL AND ppid IS NULL "
                "AND proc_path IS NULL AND file_path IS NULL ORDER BY id LIMIT ?",
                (last, batch)).fetchall()
            if not rows:
                break
            updates = []
            for event_id, body in rows:
                ev = _unpack(body)
                updates.append((_dig(ev, "process.pid"), _dig(ev, "actor.process.pid"),
                                _dig(ev, "process.file.path"), _dig(ev, "file.path"),
                                event_id))
            self.db.execute("BEGIN")
            self.db.executemany("UPDATE events SET pid = ?, ppid = ?, proc_path = ?, "
                                "file_path = ? WHERE id = ?", updates)
            self.db.execute("COMMIT")
            last = rows[-1][0]
            self.set_state("backfill_last_id", str(last))
            done += len(rows)
        return done

    def proc_path_stats(self, path: str, since_ms: int = 0) -> dict:
        row = self.db.execute(
            "SELECT COUNT(*), MIN(time_ms), MAX(time_ms) FROM events "
            "WHERE proc_path = ? AND class_uid = 1007 AND time_ms >= ?", (path, since_ms),
        ).fetchone()
        return {"executions": row[0], "first_ms": row[1], "last_ms": row[2]}

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
            "SELECT id, body FROM detections WHERE dedupe_key = ? AND last_ms >= ? "
            "ORDER BY id DESC LIMIT 1",
            (dedupe_key, now - window_ms),
        ).fetchone()
        if row:
            self.db.execute(
                "UPDATE detections SET hits = hits + 1, last_ms = ? WHERE id = ?", (now, row[0])
            )
            # The same file write arrives from FSEvents (no process) and Endpoint Security
            # (with the writing process). Keep whichever copy says who did it.
            stored = _unpack(row[1])
            if not _dig(stored, "actor.process.file.path") and \
                    _dig(finding, "actor.process.file.path"):
                self.db.execute("UPDATE detections SET body = ?, event_id = ? WHERE id = ?",
                                (_pack(finding), event_id, row[0]))
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

    def _detection_row(self, row) -> dict:
        det_id, t, rule_id, title, sev, hits, last_ms, event_id, body, published = row
        return {"id": det_id, "time_ms": t, "rule_id": rule_id, "title": title,
                "severity": sev, "hits": hits, "last_ms": last_ms, "event_id": event_id,
                "published": bool(published), "finding": _unpack(body)}

    _DET_COLS = ("id, time_ms, rule_id, title, severity, hits, last_ms, event_id, body, "
                 "published")

    def get_detection(self, det_id: int) -> dict | None:
        row = self.db.execute(
            f"SELECT {self._DET_COLS} FROM detections WHERE id = ?", (det_id,)).fetchone()
        return self._detection_row(row) if row else None

    def detections_pending(self, since_ms: int = 0, limit: int = 20) -> list[dict]:
        """Untriaged detections (the orchestrator's outbox), oldest first."""
        rows = self.db.execute(
            f"SELECT {self._DET_COLS} FROM detections WHERE published = 0 AND time_ms >= ? "
            "ORDER BY id LIMIT ?", (since_ms, max(1, min(int(limit), 100))))
        return [self._detection_row(r) for r in rows]

    def detections_between(self, start_ms: int, end_ms: int, limit: int = 50) -> list[dict]:
        rows = self.db.execute(
            f"SELECT {self._DET_COLS} FROM detections WHERE last_ms >= ? AND time_ms <= ? "
            "ORDER BY time_ms LIMIT ?", (start_ms, end_ms, max(1, min(int(limit), 500))))
        return [self._detection_row(r) for r in rows]

    def ack_detection(self, det_id: int) -> bool:
        cur = self.db.execute("UPDATE detections SET published = 1 WHERE id = ?", (det_id,))
        return cur.rowcount > 0

    def baseline_entry(self, kind: str, key: str) -> dict | None:
        row = self.db.execute(
            "SELECT first_ms, last_ms, count FROM baseline WHERE kind = ? AND key = ?",
            (kind, key)).fetchone()
        return {"first_ms": row[0], "last_ms": row[1], "count": row[2]} if row else None

    def baseline_search(self, kind: str, contains: str, limit: int = 20) -> list[dict]:
        rows = self.db.execute(
            "SELECT key, first_ms, last_ms, count FROM baseline WHERE kind = ? "
            "AND instr(key, ?) > 0 ORDER BY last_ms DESC LIMIT ?",
            (kind, contains, max(1, min(int(limit), 100))))
        return [{"key": k, "first_ms": f, "last_ms": la, "count": c} for k, f, la, c in rows]

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

    def baseline_last(self, kind: str, key: str) -> int | None:
        row = self.db.execute("SELECT last_ms FROM baseline WHERE kind = ? AND key = ?",
                              (kind, key)).fetchone()
        return row[0] if row else None

    def baseline_forget(self, kind: str, key: str) -> None:
        self.db.execute("DELETE FROM baseline WHERE kind = ? AND key = ?", (kind, key))

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
