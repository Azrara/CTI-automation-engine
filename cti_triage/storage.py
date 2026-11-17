"""État local (SQLite) : curseur d'ingestion, événements vus, décisions,
retours analystes (labels) et tickets JIRA créés. Tout reste en local."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoint (
    name TEXT PRIMARY KEY,
    cursor TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
    uid TEXT PRIMARY KEY,
    category TEXT,
    source_type TEXT,
    severity TEXT,
    fingerprint TEXT,
    simhash INTEGER,
    created_at TEXT,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_fp ON events(fingerprint);
CREATE TABLE IF NOT EXISTS decisions (
    uid TEXT PRIMARY KEY,
    decision TEXT,
    score REAL,
    reasons TEXT,
    components TEXT,
    duplicate_of TEXT,
    decided_at TEXT
);
-- Retour analyste : 1 = vrai positif (à notifier), 0 = bruit.
CREATE TABLE IF NOT EXISTS feedback (
    uid TEXT PRIMARY KEY,
    label INTEGER NOT NULL,
    source TEXT,
    labelled_at TEXT
);
CREATE TABLE IF NOT EXISTS jira_issues (
    uid TEXT PRIMARY KEY,
    issue_key TEXT,
    created_at TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    def __init__(self, path: str | Path = ":memory:"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # -- curseur ----------------------------------------------------------
    def get_cursor(self, name: str = "tenant_feed") -> str | None:
        row = self.conn.execute("SELECT cursor FROM checkpoint WHERE name=?", (name,)).fetchone()
        return row["cursor"] if row else None

    def set_cursor(self, cursor: str | None, name: str = "tenant_feed") -> None:
        self.conn.execute(
            "INSERT INTO checkpoint(name, cursor, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at",
            (name, cursor, _now()),
        )
        self.conn.commit()

    # -- événements -------------------------------------------------------
    def has_event(self, uid: str) -> bool:
        return self.conn.execute("SELECT 1 FROM events WHERE uid=?", (uid,)).fetchone() is not None

    def save_event(self, uid: str, category: str, source_type: str, severity: str,
                   fingerprint: str, simhash: int, created_at: str | None, payload: dict[str, Any]) -> None:
        # SQLite stocke des entiers signés 64 bits : on replie le simhash.
        signed = simhash - (1 << 64) if simhash >= (1 << 63) else simhash
        self.conn.execute(
            "INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?,?,?)",
            (uid, category, source_type, severity, fingerprint, signed, created_at,
             json.dumps(payload, default=str)),
        )
        self.conn.commit()

    def find_by_fingerprint(self, fingerprint: str, exclude_uid: str) -> str | None:
        row = self.conn.execute(
            "SELECT uid FROM events WHERE fingerprint=? AND uid<>? LIMIT 1", (fingerprint, exclude_uid)
        ).fetchone()
        return row["uid"] if row else None

    def recent_simhashes(self, category: str, limit: int = 5000) -> list[tuple[str, int]]:
        rows = self.conn.execute(
            "SELECT uid, simhash FROM events WHERE category=? ORDER BY rowid DESC LIMIT ?", (category, limit)
        ).fetchall()
        return [(r["uid"], r["simhash"] & ((1 << 64) - 1)) for r in rows]

    def load_events(self) -> list[dict[str, Any]]:
        return [json.loads(r["payload"]) for r in self.conn.execute("SELECT payload FROM events")]

    # -- décisions / feedback --------------------------------------------
    def save_decision(self, uid: str, decision: str, score: float, reasons: list[str],
                      components: dict[str, float], duplicate_of: str | None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO decisions VALUES(?,?,?,?,?,?,?)",
            (uid, decision, score, json.dumps(reasons), json.dumps(components), duplicate_of, _now()),
        )
        self.conn.commit()

    def add_feedback(self, uid: str, label: int, source: str = "analyst") -> None:
        self.conn.execute("INSERT OR REPLACE INTO feedback VALUES(?,?,?,?)", (uid, int(bool(label)), source, _now()))
        self.conn.commit()

    def labelled_events(self) -> Iterable[tuple[dict[str, Any], int]]:
        rows = self.conn.execute(
            "SELECT e.payload, f.label FROM feedback f JOIN events e ON e.uid=f.uid"
        ).fetchall()
        return [(json.loads(r["payload"]), r["label"]) for r in rows]

    # -- JIRA -------------------------------------------------------------
    def jira_issue_for(self, uid: str) -> str | None:
        row = self.conn.execute("SELECT issue_key FROM jira_issues WHERE uid=?", (uid,)).fetchone()
        return row["issue_key"] if row else None

    def save_jira_issue(self, uid: str, issue_key: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO jira_issues VALUES(?,?,?)", (uid, issue_key, _now()))
        self.conn.commit()
