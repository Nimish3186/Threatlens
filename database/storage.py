import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "events.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type  TEXT,
            timestamp TEXT,
            hostname  TEXT,
            source_ip TEXT,
            process   TEXT,
            message   TEXT,
            raw       TEXT,
            extra     TEXT
        )
    """)


    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT,
            alert_type   TEXT,
            severity     TEXT,
            source_ip    TEXT,
            description  TEXT,
            event_count  INTEGER,
            window_secs  INTEGER,
            attack_id    TEXT,
            attack_name  TEXT,
            raw_events   TEXT
        )
    """)

    conn.commit()
    conn.close()

def insert_events(events: list[dict]):
    conn = sqlite3.connect(DB_PATH)
    for e in events:
        conn.execute("""
            INSERT INTO events (log_type, timestamp, hostname, source_ip, process, message, raw, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            e.get("log_type"),
            e.get("timestamp"),
            e.get("hostname"),
            e.get("source_ip"),
            e.get("process"),
            e.get("message"),
            e.get("raw"),
            json.dumps({k: v for k, v in e.items()
                        if k not in ("log_type","timestamp","hostname","source_ip","process","message","raw")})
        ))
    conn.commit()
    conn.close()
    print(f"[db] Inserted {len(events)} events.")


def insert_alert(alert: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO alerts
        (created_at, alert_type, severity, source_ip, description,
         event_count, window_secs, attack_id, attack_name, raw_events)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("created_at"),
        alert.get("alert_type"),
        alert.get("severity"),
        alert.get("source_ip"),
        alert.get("description"),
        alert.get("event_count"),
        alert.get("window_secs"),
        alert.get("attack_id"),
        alert.get("attack_name"),
        json.dumps(alert.get("raw_events", [])),
    ))
    conn.commit()
    conn.close()

def get_alerts() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]