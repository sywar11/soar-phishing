"""Persistance SQLite : dossiers (= campagnes), signalements, clés de regroupement, renseignement interne, journal d'actions."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import config

_lock = threading.RLock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL, updated REAL,
    status TEXT,              -- awaiting_validation | confirmed | false_positive | closed_benign
    verdict TEXT,             -- benign | suspicious | malicious
    max_score INTEGER,
    title TEXT, sender TEXT, subject TEXT,
    iocs TEXT,                -- JSON
    purged TEXT DEFAULT '[]', -- JSON : messages supprimés
    blocked TEXT DEFAULT '[]',-- JSON : domaines bloqués
    thehive_id TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id),
    created REAL,
    reporter TEXT, mailpit_id TEXT UNIQUE, message_id TEXT,
    subject TEXT, sender TEXT, score INTEGER, decision TEXT,
    duplicate INTEGER DEFAULT 0,
    analysis TEXT
);
CREATE TABLE IF NOT EXISTS case_keys (case_id INTEGER, key TEXT, created REAL);
CREATE INDEX IF NOT EXISTS idx_case_keys ON case_keys(key);
CREATE TABLE IF NOT EXISTS intel (indicator TEXT PRIMARY KEY, type TEXT, case_id INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, created REAL, action TEXT, detail TEXT);
"""


def _conn() -> sqlite3.Connection:
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


_db = None


@contextmanager
def db():
    global _db
    with _lock:
        if _db is None:
            _db = _conn()
            _db.executescript(SCHEMA)
        try:
            yield _db
            _db.commit()
        except Exception:
            _db.rollback()
            raise


def _row(r) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for k in ("iocs", "purged", "blocked", "analysis"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except json.JSONDecodeError:
                pass
    return d


# --------------------------------------------------------------------------- dossiers
def create_case(verdict: str, score: int, sender: str, subject: str, iocs: dict) -> int:
    now = time.time()
    status = "closed_benign" if verdict == "benign" else "awaiting_validation"
    with db() as c:
        cur = c.execute(
            "INSERT INTO cases(created, updated, status, verdict, max_score, title, sender, subject, iocs)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (now, now, status, verdict, score, f"[{verdict}] {subject[:120]}", sender, subject, json.dumps(iocs)),
        )
        return cur.lastrowid


def update_case(case_id: int, **fields) -> None:
    if not fields:
        return
    fields["updated"] = time.time()
    for k in ("iocs", "purged", "blocked"):
        if k in fields and not isinstance(fields[k], str):
            fields[k] = json.dumps(fields[k])
    sets = ", ".join(f"{k}=?" for k in fields)
    with db() as c:
        c.execute(f"UPDATE cases SET {sets} WHERE id=?", (*fields.values(), case_id))  # noqa: S608 - clés internes


def get_case(case_id: int) -> dict | None:
    with db() as c:
        return _row(c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())


def list_cases(limit: int = 200) -> list[dict]:
    with db() as c:
        rows = c.execute(
            "SELECT cases.*, (SELECT COUNT(*) FROM reports r WHERE r.case_id=cases.id) AS report_count,"
            " (SELECT COUNT(DISTINCT reporter) FROM reports r WHERE r.case_id=cases.id) AS reporter_count"
            " FROM cases ORDER BY updated DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row(r) for r in rows]


# --------------------------------------------------------------------------- signalements
def add_report(case_id: int, reporter: str, mailpit_id: str | None, message_id: str, subject: str, sender: str,
               score: int, decision: str, duplicate: bool, analysis: dict) -> int:
    with db() as c:
        cur = c.execute(
            "INSERT INTO reports(case_id, created, reporter, mailpit_id, message_id, subject, sender, score, decision,"
            " duplicate, analysis) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, time.time(), reporter, mailpit_id, message_id, subject, sender, score, decision,
             int(duplicate), json.dumps(analysis, default=str)),
        )
        return cur.lastrowid


def get_report(report_id: int) -> dict | None:
    with db() as c:
        return _row(c.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone())


def report_by_mailpit_id(mailpit_id: str) -> dict | None:
    with db() as c:
        return _row(c.execute("SELECT * FROM reports WHERE mailpit_id=?", (mailpit_id,)).fetchone())


def reports_for_case(case_id: int) -> list[dict]:
    with db() as c:
        return [_row(r) for r in c.execute("SELECT * FROM reports WHERE case_id=? ORDER BY created", (case_id,))]


def same_message_reported(message_id: str, reporter: str) -> dict | None:
    if not message_id:
        return None
    with db() as c:
        return _row(c.execute("SELECT * FROM reports WHERE message_id=? AND reporter=? LIMIT 1",
                              (message_id, reporter)).fetchone())


# --------------------------------------------------------------------------- clés de regroupement
def add_keys(case_id: int, keys: list[str]) -> None:
    now = time.time()
    with db() as c:
        existing = {r["key"] for r in c.execute("SELECT key FROM case_keys WHERE case_id=?", (case_id,))}
        c.executemany("INSERT INTO case_keys(case_id, key, created) VALUES (?,?,?)",
                      [(case_id, k, now) for k in set(keys) - existing])


def find_case_by_keys(keys: list[str], since: float) -> tuple[int, list[str]] | None:
    if not keys:
        return None
    q = ",".join("?" * len(keys))
    with db() as c:
        rows = c.execute(
            f"SELECT k.case_id, k.key FROM case_keys k JOIN cases ON cases.id=k.case_id"  # noqa: S608
            f" WHERE k.key IN ({q}) AND cases.created >= ? ORDER BY cases.updated DESC", (*keys, since)
        ).fetchall()
    if not rows:
        return None
    best = rows[0]["case_id"]
    return best, sorted({r["key"] for r in rows if r["case_id"] == best})


# --------------------------------------------------------------------------- renseignement interne
def add_intel(items: list[tuple[str, str]], case_id: int) -> None:
    with db() as c:
        c.executemany("INSERT OR REPLACE INTO intel(indicator, type, case_id, created) VALUES (?,?,?,?)",
                      [(i, t, case_id, time.time()) for i, t in items])


def remove_intel(case_id: int) -> None:
    with db() as c:
        c.execute("DELETE FROM intel WHERE case_id=?", (case_id,))


def lookup_intel(indicator: str) -> dict | None:
    with db() as c:
        return _row(c.execute("SELECT * FROM intel WHERE indicator=?", (indicator,)).fetchone())


# --------------------------------------------------------------------------- journal
def log_action(case_id: int, action: str, detail) -> None:
    with db() as c:
        c.execute("INSERT INTO actions(case_id, created, action, detail) VALUES (?,?,?,?)",
                  (case_id, time.time(), action, json.dumps(detail, default=str)))


def actions_for_case(case_id: int) -> list[dict]:
    with db() as c:
        out = []
        for r in c.execute("SELECT * FROM actions WHERE case_id=? ORDER BY created", (case_id,)):
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except json.JSONDecodeError:
                pass
            out.append(d)
        return out


def stats() -> dict:
    with db() as c:
        cases = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM cases GROUP BY status")}
        reports = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        intel = c.execute("SELECT COUNT(*) FROM intel").fetchone()[0]
    return {"cases_by_status": cases, "reports": reports, "intel_indicators": intel}
