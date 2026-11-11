"""The core's own SQLite: incidents, the spend ledger and small state values."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from bastion.core.schemas import Incident

SCHEMA = """
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS incidents (
    id            TEXT PRIMARY KEY,
    detection_id  INTEGER NOT NULL,
    created_ms    INTEGER NOT NULL,
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    domain        TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    notify        INTEGER NOT NULL,
    cost_usd      REAL NOT NULL,
    body          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_time ON incidents(created_ms);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_detection ON incidents(detection_id);
CREATE TABLE IF NOT EXISTS spend (
    ts_ms        INTEGER NOT NULL,
    incident_id  TEXT NOT NULL,
    model        TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    usd          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS spend_time ON spend(ts_ms);
CREATE INDEX IF NOT EXISTS spend_incident ON spend(incident_id);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class CoreStore:
    def __init__(self, path: Path | str, timezone: str = "UTC"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.executescript(SCHEMA)
        try:
            self.tz = ZoneInfo(timezone)
        except Exception:
            self.tz = ZoneInfo("UTC")

    def close(self) -> None:
        self.db.close()

    # ---- incidents ----------------------------------------------------------------
    def save_incident(self, inc: Incident) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO incidents (id, detection_id, created_ms, rule_id, title, "
            "domain, verdict, severity, confidence, notify, cost_usd, body) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (inc.id, inc.detection_id, inc.created_ms, inc.rule_id, inc.title, inc.domain,
             inc.decision.verdict.value, inc.decision.severity, inc.decision.confidence,
             int(inc.decision.notify), inc.cost_usd, inc.model_dump_json()))

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self.db.execute("SELECT body FROM incidents WHERE id = ?",
                              (incident_id,)).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def has_detection(self, detection_id: int) -> bool:
        return self.db.execute("SELECT 1 FROM incidents WHERE detection_id = ?",
                               (detection_id,)).fetchone() is not None

    def list_incidents(self, since_ms: int = 0, verdict: str | None = None,
                       limit: int = 200) -> list[dict]:
        q = ("SELECT id, created_ms, title, domain, verdict, severity, confidence, notify, "
             "cost_usd, body FROM incidents WHERE created_ms >= ?")
        args: list = [since_ms]
        if verdict:
            q += " AND verdict = ?"
            args.append(verdict)
        q += " ORDER BY created_ms DESC LIMIT ?"
        args.append(limit)
        keys = ("id", "created_ms", "title", "domain", "verdict", "severity", "confidence",
                "notify", "cost_usd")
        out = []
        for row in self.db.execute(q, args):
            item = dict(zip(keys, row[:-1], strict=True))
            item["headline"] = json.loads(row[-1])["decision"]["headline"]
            out.append(item)
        return out

    def verdict_counts(self, since_ms: int) -> dict[str, int]:
        return dict(self.db.execute(
            "SELECT verdict, COUNT(*) FROM incidents WHERE created_ms >= ? GROUP BY verdict",
            (since_ms,)))

    # ---- spend ledger -------------------------------------------------------------
    def add_spend(self, incident_id: str, model: str, input_tokens: int,
                  output_tokens: int, usd: float, ts_ms: int | None = None) -> None:
        self.db.execute("INSERT INTO spend VALUES (?, ?, ?, ?, ?, ?)",
                        (ts_ms or int(time.time() * 1000), incident_id, model,
                         input_tokens, output_tokens, usd))

    def spend_since(self, since_ms: int) -> float:
        return self.db.execute("SELECT COALESCE(SUM(usd), 0) FROM spend WHERE ts_ms >= ?",
                               (since_ms,)).fetchone()[0]

    def spend_incident(self, incident_id: str) -> float:
        return self.db.execute(
            "SELECT COALESCE(SUM(usd), 0) FROM spend WHERE incident_id = ?",
            (incident_id,)).fetchone()[0]

    def _local_start(self, now_ms: int | None, month: bool) -> int:
        now = datetime.fromtimestamp((now_ms or time.time() * 1000) / 1000, self.tz)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if month:
            start = start.replace(day=1)
        return int(start.timestamp() * 1000)

    def spend_today(self, now_ms: int | None = None) -> float:
        return self.spend_since(self._local_start(now_ms, month=False))

    def spend_month(self, now_ms: int | None = None) -> float:
        return self.spend_since(self._local_start(now_ms, month=True))

    # ---- state --------------------------------------------------------------------
    def get_state(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_state(self, key: str, value: str) -> None:
        with contextlib.suppress(sqlite3.Error):
            self.db.execute("INSERT INTO state VALUES (?, ?) ON CONFLICT(key) DO UPDATE "
                            "SET value = excluded.value", (key, value))
