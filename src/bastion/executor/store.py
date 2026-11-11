"""Executor state: audit log, action records, approvals, passkeys, nonces."""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms      INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    body       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
    id           TEXT PRIMARY KEY,
    ts_ms        INTEGER NOT NULL,
    action       TEXT NOT NULL,
    args         TEXT NOT NULL,
    tier         INTEGER NOT NULL,
    auto         INTEGER NOT NULL,
    status       TEXT NOT NULL,   -- executed | shadow | undone | deleted | failed
    incident_id  TEXT NOT NULL DEFAULT '',
    agent        TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    undo         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS actions_time ON actions(ts_ms);
CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,
    created_ms   INTEGER NOT NULL,
    expires_ms   INTEGER NOT NULL,
    command      TEXT NOT NULL,   -- the exact request that will run if approved
    action_hash  TEXT NOT NULL,
    status       TEXT NOT NULL,   -- pending | approved | denied | expired | failed
    decided_ms   INTEGER,
    result       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS challenges (
    id          TEXT PRIMARY KEY,
    purpose     TEXT NOT NULL,
    subject     TEXT NOT NULL,
    challenge   BLOB NOT NULL,
    expires_ms  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS passkeys (
    credential_id  TEXT PRIMARY KEY,
    public_key     BLOB NOT NULL,
    sign_count     INTEGER NOT NULL,
    name           TEXT NOT NULL,
    created_ms     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, expires_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(prev: str, ts_ms: int, kind: str, body: str) -> str:
    return hashlib.sha256(f"{prev}|{ts_ms}|{kind}|{body}".encode()).hexdigest()


class ExecStore:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.executescript(SCHEMA)
        if str(path) != ":memory:":
            with contextlib.suppress(OSError):
                Path(path).chmod(0o600)

    def close(self) -> None:
        self.db.close()

    # ---- audit log (append-only, hash-chained) ------------------------------------
    def audit(self, kind: str, body: dict, ts_ms: int | None = None) -> str:
        ts_ms = ts_ms or int(time.time() * 1000)
        text = canonical(body)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = _entry_hash(prev, ts_ms, kind, text)
            self.db.execute("INSERT INTO audit (ts_ms, kind, body, prev_hash, hash) "
                            "VALUES (?, ?, ?, ?, ?)", (ts_ms, kind, text, prev, h))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return h

    def verify_audit(self) -> tuple[bool, int, str]:
        """(intact, entries checked, detail). Recomputes every hash from the start."""
        prev, n = GENESIS, 0
        for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            n += 1
            if row["prev_hash"] != prev:
                return False, n, f"entry {row['seq']}: chain broken"
            if _entry_hash(prev, row["ts_ms"], row["kind"], row["body"]) != row["hash"]:
                return False, n, f"entry {row['seq']}: contents changed"
            prev = row["hash"]
        return True, n, "intact"

    def audit_tail(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT seq, ts_ms, kind, body FROM audit ORDER BY seq DESC "
                               "LIMIT ?", (limit,)).fetchall()
        return [{"seq": r["seq"], "ts_ms": r["ts_ms"], "kind": r["kind"],
                 "body": json.loads(r["body"])} for r in rows]

    # ---- actions ------------------------------------------------------------------
    def add_action(self, rec: dict) -> None:
        self.db.execute(
            "INSERT INTO actions (id, ts_ms, action, args, tier, auto, status, incident_id, "
            "agent, reason, detail, undo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (rec["id"], rec["ts_ms"], rec["action"], canonical(rec["args"]), rec["tier"],
             int(rec["auto"]), rec["status"], rec.get("incident_id", ""),
             rec.get("agent", ""), rec.get("reason", ""), rec.get("detail", ""),
             canonical(rec.get("undo", {}))))

    @staticmethod
    def _action(row) -> dict:
        d = dict(row)
        d["args"], d["undo"], d["auto"] = json.loads(d["args"]), json.loads(d["undo"]), \
            bool(d["auto"])
        return d

    def get_action(self, action_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
        return self._action(row) if row else None

    def set_action_status(self, action_id: str, status: str, detail: str | None = None) -> None:
        if detail is None:
            self.db.execute("UPDATE actions SET status = ? WHERE id = ?", (status, action_id))
        else:
            self.db.execute("UPDATE actions SET status = ?, detail = ? WHERE id = ?",
                            (status, detail, action_id))

    def list_actions(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT * FROM actions ORDER BY ts_ms DESC LIMIT ?",
                               (max(1, min(limit, 200)),)).fetchall()
        return [self._action(r) for r in rows]

    def recent_same_action(self, action: str, args: dict, statuses: tuple[str, ...],
                           since_ms: int) -> dict | None:
        marks = ",".join("?" * len(statuses))
        row = self.db.execute(
            f"SELECT * FROM actions WHERE action = ? AND args = ? AND status IN ({marks}) "
            "AND ts_ms >= ? ORDER BY ts_ms DESC LIMIT 1",
            (action, canonical(args), *statuses, since_ms)).fetchone()
        return self._action(row) if row else None

    def pending_same_approval(self, action_hash: str, now_ms: int) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM approvals WHERE action_hash = ? AND status = 'pending' "
            "AND expires_ms > ? LIMIT 1", (action_hash, now_ms)).fetchone()
        return self._approval(row) if row else None

    def count_auto_executed_since(self, since_ms: int) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM actions WHERE auto = 1 AND status IN "
            "('executed', 'undone', 'deleted') AND ts_ms >= ?", (since_ms,)).fetchone()[0]

    # ---- approvals ----------------------------------------------------------------
    def add_approval(self, rec: dict) -> None:
        self.db.execute(
            "INSERT INTO approvals (id, created_ms, expires_ms, command, action_hash, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            (rec["id"], rec["created_ms"], rec["expires_ms"], canonical(rec["command"]),
             rec["action_hash"]))

    @staticmethod
    def _approval(row) -> dict:
        d = dict(row)
        d["command"] = json.loads(d["command"])
        return d

    def get_approval(self, approval_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM approvals WHERE id = ?",
                              (approval_id,)).fetchone()
        return self._approval(row) if row else None

    def list_approvals(self, status: str | None = "pending", limit: int = 50) -> list[dict]:
        q, args = "SELECT * FROM approvals", []
        if status:
            q += " WHERE status = ?"
            args.append(status)
        rows = self.db.execute(q + " ORDER BY created_ms DESC LIMIT ?",
                               (*args, max(1, min(limit, 200)))).fetchall()
        return [self._approval(r) for r in rows]

    def claim_approval(self, approval_id: str, now_ms: int) -> bool:
        """Atomically move pending -> approved. False if someone else got there first."""
        cur = self.db.execute(
            "UPDATE approvals SET status = 'approved', decided_ms = ? WHERE id = ? "
            "AND status = 'pending' AND expires_ms > ?", (now_ms, approval_id, now_ms))
        return cur.rowcount == 1

    def finish_approval(self, approval_id: str, status: str, result: str, now_ms: int) -> bool:
        cur = self.db.execute(
            "UPDATE approvals SET status = ?, result = ?, decided_ms = ? WHERE id = ? "
            "AND status IN ('pending', 'approved')", (status, result, now_ms, approval_id))
        return cur.rowcount == 1

    def expire_approvals(self, now_ms: int) -> int:
        return self.db.execute(
            "UPDATE approvals SET status = 'expired', decided_ms = ? WHERE status = 'pending' "
            "AND expires_ms <= ?", (now_ms, now_ms)).rowcount

    # ---- challenges, nonces, passkeys, state --------------------------------------
    def add_challenge(self, cid: str, purpose: str, subject: str, challenge: bytes,
                      expires_ms: int) -> None:
        self.db.execute("DELETE FROM challenges WHERE expires_ms < ?",
                        (int(time.time() * 1000) - 3_600_000,))
        self.db.execute("INSERT INTO challenges VALUES (?, ?, ?, ?, ?, 0)",
                        (cid, purpose, subject, challenge, expires_ms))

    def use_challenge(self, cid: str, purpose: str, subject: str, now_ms: int) -> bytes | None:
        """Consume a challenge exactly once. None if unknown, expired, used or mismatched."""
        cur = self.db.execute(
            "UPDATE challenges SET used = 1 WHERE id = ? AND purpose = ? AND subject = ? "
            "AND used = 0 AND expires_ms > ?", (cid, purpose, subject, now_ms))
        if cur.rowcount != 1:
            return None
        return self.db.execute("SELECT challenge FROM challenges WHERE id = ?",
                               (cid,)).fetchone()["challenge"]

    def use_nonce(self, nonce: str, expires_ms: int, now_ms: int) -> bool:
        self.db.execute("DELETE FROM nonces WHERE expires_ms < ?", (now_ms,))
        try:
            self.db.execute("INSERT INTO nonces VALUES (?, ?)", (nonce, expires_ms))
            return True
        except sqlite3.IntegrityError:
            return False

    def add_passkey(self, credential_id: str, public_key: bytes, sign_count: int,
                    name: str, now_ms: int) -> None:
        self.db.execute("INSERT OR REPLACE INTO passkeys VALUES (?, ?, ?, ?, ?)",
                        (credential_id, public_key, sign_count, name, now_ms))

    def list_passkeys(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT credential_id, public_key, sign_count, name, created_ms FROM passkeys "
            "ORDER BY created_ms")]

    def update_sign_count(self, credential_id: str, count: int) -> None:
        self.db.execute("UPDATE passkeys SET sign_count = ? WHERE credential_id = ?",
                        (count, credential_id))

    def remove_passkey(self, credential_id: str) -> bool:
        return self.db.execute("DELETE FROM passkeys WHERE credential_id = ?",
                               (credential_id,)).rowcount == 1

    def get_state(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO state VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
                        "value = excluded.value", (key, value))

    def del_state(self, key: str) -> None:
        self.db.execute("DELETE FROM state WHERE key = ?", (key,))
