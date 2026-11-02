import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent / "threat_intel.db"

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            sources TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            threat TEXT,
            date_added TEXT,
            source TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            UNIQUE(indicator, source)
        )""")

def save_investigation(indicator, indicator_type, score, severity, sources, results):
    with connect() as conn:
        conn.execute(
            "INSERT INTO investigations(created_at,indicator,indicator_type,risk_score,severity,sources,result_json) VALUES(?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), indicator, indicator_type, score, severity, sources, json.dumps(results))
        )

def get_history():
    with connect() as conn:
        rows = conn.execute("SELECT id,created_at,indicator,indicator_type,risk_score,severity,sources FROM investigations ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

def save_feed(indicator, threat, date_added, source):
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO feeds(indicator,threat,date_added,source,collected_at) VALUES(?,?,?,?,?)",
            (indicator, threat, date_added, source, datetime.now(timezone.utc).isoformat())
        )

def get_feeds():
    with connect() as conn:
        rows = conn.execute("SELECT indicator,threat,date_added,source,collected_at FROM feeds ORDER BY id DESC LIMIT 500").fetchall()
        return [dict(r) for r in rows]
