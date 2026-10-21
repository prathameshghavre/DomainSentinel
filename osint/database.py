"""database.py - Store scan history in a local SQLite database.

All queries use parameter placeholders (?) and never string formatting,
so user input cannot change the SQL (protection against SQL injection).
"""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "osint_scans.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the scans table if it does not exist yet."""
    with closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                domain TEXT NOT NULL,
                score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                data_complete INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )


def save_scan(report):
    """Save one scan report and return its new id."""
    risk = report["risk"]
    with closing(_connect()) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO scans (scanned_at, domain, score, severity, "
            "data_complete, report_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                report["scanned_at"],
                report["domain"],
                risk["score"],
                risk["severity"],
                int(risk["data_complete"]),
                json.dumps(report),
            ),
        )
        return cursor.lastrowid


def get_history(limit=50):
    """Return the most recent scans (newest first) as a list of dicts."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, scanned_at, domain, score, severity, data_complete "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id):
    """Return the full saved report for one scan id, or None if not found."""
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT report_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    return json.loads(row["report_json"]) if row else None