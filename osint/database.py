"""database.py - Store scan history in a local SQLite database.

Every value that comes from a user goes into a query through a ? placeholder.
The only parts of a query built as text are fixed fragments written in this file.
"""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "osint_scans.db"
SEVERITIES = ("Low", "Medium", "High", "Critical")


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


def get_history(limit=50, severity=None, query=None):
    """Return recent scans (newest first), optionally filtered."""
    sql = ("SELECT id, scanned_at, domain, score, severity, data_complete "
           "FROM scans")
    conditions, params = [], []
    if severity in SEVERITIES:
        conditions.append("severity = ?")
        params.append(severity)
    if query:
        conditions.append("domain LIKE ?")
        params.append(f"%{query}%")
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with closing(_connect()) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id):
    """Return the full saved report for one scan id, or None if not found."""
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT report_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    return json.loads(row["report_json"]) if row else None


def get_stats():
    """Numbers for the dashboard cards and charts."""
    with closing(_connect()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        average = conn.execute("SELECT AVG(score) FROM scans").fetchone()[0]
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM scans GROUP BY severity"
        ).fetchall()
        alerts = conn.execute(
            "SELECT id, scanned_at, domain, score, severity FROM scans "
            "WHERE severity IN ('High', 'Critical') ORDER BY id DESC LIMIT 5"
        ).fetchall()

    counts = {level: 0 for level in SEVERITIES}
    for row in rows:
        if row["severity"] in counts:
            counts[row["severity"]] = row["n"]

    return {
        "total": total,
        "average": round(average or 0),
        "counts": counts,
        "high_risk": counts["High"] + counts["Critical"],
        "alerts": [dict(alert) for alert in alerts],
    }