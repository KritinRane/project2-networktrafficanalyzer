"""SQLite persistence for customer accounts and stored reports.

The app was stateless until now; this module introduces the only durable
state. Everything goes through a single SQLite file whose path is
``DB_PATH`` (default ``./data/ntg.db``). On Railway the working-dir
filesystem is ephemeral, so point ``DB_PATH`` at a mounted volume to make
accounts/reports survive redeploys.

No ORM by design — a handful of typed helper functions keep the dependency
surface at zero (stdlib ``sqlite3`` only). WAL mode is enabled so a customer
reading a report never blocks the admin writing one.
"""
import os
import time
import json
import sqlite3
import secrets
from typing import Optional, List, Dict, Any

DB_PATH = os.getenv("DB_PATH", os.path.join(os.getcwd(), "data", "ntg.db"))

# Invite links are valid for this many seconds (7 days).
INVITE_TTL = 7 * 24 * 3600


def _connect() -> sqlite3.Connection:
    """New connection per call. SQLite handles cross-thread use fine as long
    as each thread uses its own connection, which per-call guarantees."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if absent. Safe to call on every startup."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                email          TEXT    NOT NULL UNIQUE,
                name           TEXT,
                company        TEXT,
                password_hash  TEXT,
                invite_token   TEXT,
                invite_expires REAL,
                active         INTEGER NOT NULL DEFAULT 0,
                created_at     REAL    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id   INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                created_by    TEXT,
                filename      TEXT,
                analysis_json TEXT    NOT NULL,
                threat_score  INTEGER,
                risk_level    TEXT,
                pdf           BLOB,
                created_at    REAL    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_reports_customer
                ON reports(customer_id, created_at DESC);
            """
        )


# ── Customers ────────────────────────────────────────────────────────────────

def _row_to_customer(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(row) if row else None


def get_customer_by_email(email: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM customers WHERE email = ? COLLATE NOCASE", (email.strip(),)
        ).fetchone()
    return _row_to_customer(row)


def get_customer_by_id(customer_id: int) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    return _row_to_customer(row)


def get_customer_by_invite(token: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM customers WHERE invite_token = ?", (token,)
        ).fetchone()
    return _row_to_customer(row)


def upsert_customer(email: str, name: str = "", company: str = "") -> Dict[str, Any]:
    """Find an existing customer by email, or create a new (inactive, invited)
    one. Returns the customer row. A freshly created customer gets an invite
    token; an existing one is returned untouched so we never clobber a set
    password or re-issue an invite on every report."""
    existing = get_customer_by_email(email)
    if existing:
        return existing
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO customers (email, name, company, invite_token, invite_expires, "
            "active, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (email.strip(), name.strip(), company.strip(), token, now + INVITE_TTL, now),
        )
        cid = cur.lastrowid
    return get_customer_by_id(cid)


def refresh_invite(customer_id: int) -> str:
    """Issue a fresh invite token (e.g. the old one expired). Returns it."""
    token = secrets.token_urlsafe(32)
    with _connect() as conn:
        conn.execute(
            "UPDATE customers SET invite_token = ?, invite_expires = ? WHERE id = ?",
            (token, time.time() + INVITE_TTL, customer_id),
        )
    return token


def set_password(customer_id: int, password_hash: str) -> None:
    """Set the password and activate the account; consume the invite token."""
    with _connect() as conn:
        conn.execute(
            "UPDATE customers SET password_hash = ?, active = 1, invite_token = NULL, "
            "invite_expires = NULL WHERE id = ?",
            (password_hash, customer_id),
        )


# ── Reports ──────────────────────────────────────────────────────────────────

def save_report(customer_id: int, analysis: Dict[str, Any], created_by: str = "admin",
                filename: str = "", pdf: Optional[bytes] = None) -> int:
    """Persist a full analysis dict for a customer. Returns the new report id."""
    summary = analysis.get("summary", {}) or {}
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO reports (customer_id, created_by, filename, analysis_json, "
            "threat_score, risk_level, pdf, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                customer_id,
                created_by,
                filename,
                json.dumps(analysis),
                summary.get("threat_score"),
                summary.get("risk_level"),
                pdf,
                time.time(),
            ),
        )
        return cur.lastrowid


def attach_pdf(report_id: int, pdf: bytes) -> None:
    with _connect() as conn:
        conn.execute("UPDATE reports SET pdf = ? WHERE id = ?", (pdf, report_id))


def list_reports_for_customer(customer_id: int) -> List[Dict[str, Any]]:
    """Report metadata (no heavy analysis_json / pdf) for the list view."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, filename, threat_score, risk_level, created_at, "
            "(pdf IS NOT NULL) AS has_pdf FROM reports WHERE customer_id = ? "
            "ORDER BY created_at DESC",
            (customer_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_report(report_id: int) -> Optional[Dict[str, Any]]:
    """Full report row incl. parsed analysis. ``pdf`` bytes are included."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["analysis"] = json.loads(d.pop("analysis_json"))
    return d
