"""
history.py — ThreatLens permanent investigation history (SQLite).

Purpose: unlike cache.py (temporary, 30-min TTL, avoids redundant API calls),
this keeps a permanent record of every scan ever run, so past investigations
can be reviewed later.

Rules:
  1. No Streamlit imports — plain data-persistence utility.
  2. Never imports app.py, sources.py, scoring.py, or cache.py.
     One-way dependency: app.py -> history.py.
  3. Uses only the standard library (sqlite3, json) — no new dependency.
"""

import sqlite3
import json
import time
from pathlib import Path

DB_FILE = Path(__file__).parent / "threatlens_history.db"


def _get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Creates the scans table if it doesn't already exist. Safe to call every run."""
    conn = _get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                confidence TEXT NOT NULL,
                knowledge_level TEXT NOT NULL,
                results_json TEXT NOT NULL,
                assessment_json TEXT NOT NULL,
                insight_json TEXT NOT NULL,
                scanned_at REAL NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def log_scan(target: str, target_type: str, knowledge_level: str,
             results: dict, assessment: dict, insight: dict) -> None:
    """Records a completed scan permanently. Never raises — a logging failure
    should never crash the app or block the user from seeing their result."""
    try:
        conn = _get_connection()
        conn.execute(
            """
            INSERT INTO scans
                (target, target_type, verdict, score, risk_level, confidence,
                 knowledge_level, results_json, assessment_json, insight_json, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target, target_type,
                assessment["verdict"], assessment["score"], assessment["risk_level"],
                assessment["confidence"], knowledge_level,
                json.dumps(results, default=str),
                json.dumps(assessment, default=str),
                json.dumps(insight, default=str),
                time.time(),
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # Logging failures must never break the scan flow


def get_recent_scans(limit: int = 20) -> list:
    """Returns the most recent scans, newest first, as a list of dicts."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_scan_by_id(scan_id: int):
    """Returns a single scan's full detail, or None if not found."""
    conn = _get_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_history_count() -> int:
    conn = _get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        conn.close()