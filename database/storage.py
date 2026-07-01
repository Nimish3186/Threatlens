import sqlite3
import json
from pathlib import Path

# Resolves correctly regardless of where you run from
DB_PATH = Path(__file__).resolve().parent / "events.db"


# ─────────────────────────────────────────────
#  INITIALISATION
# ─────────────────────────────────────────────

def init_db():
    """Create all tables if they don't already exist."""
    conn = sqlite3.connect(DB_PATH)

    # EVENTS TABLE — every parsed log line from any source
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type    TEXT,     -- 'syslog', 'apache', 'firewall', etc.
            timestamp   TEXT,     -- ISO 8601 format
            hostname    TEXT,     -- machine that generated the log
            source_ip   TEXT,     -- attacker/client IP if present
            process     TEXT,     -- e.g. 'sshd', 'sudo', 'kernel'
            pid         TEXT,     -- process ID if present
            message     TEXT,     -- the actual log message
            raw         TEXT,     -- original unmodified log line
            extra       TEXT      -- JSON blob for any extra parsed fields
        )
    """)

    # ALERTS TABLE — every detection fired by any detector
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,

            -- When & what
            created_at      TEXT,    -- when your detector fired
            alert_type      TEXT,    -- 'brute_force', 'priv_escalation', etc.

            -- Severity
            severity        TEXT,    -- LOW / MEDIUM / HIGH / CRITICAL
            confidence      TEXT,    -- LOW / MEDIUM / HIGH

            -- Who
            source_ip       TEXT,    -- attacker IP
            target_host     TEXT,    -- machine being attacked
            target_user     TEXT,    -- account being targeted

            -- What happened
            description     TEXT,    -- human-readable summary
            event_count     INTEGER, -- how many log lines triggered this
            window_secs     INTEGER, -- detection time window used

            -- Timeline
            first_seen      TEXT,    -- timestamp of first event in window
            last_seen       TEXT,    -- timestamp of last event in window

            -- ATT&CK mapping
            attack_id       TEXT,    -- e.g. 'T1110.001'
            attack_name     TEXT,    -- e.g. 'Brute Force: Password Guessing'
            attack_tactic   TEXT,    -- e.g. 'Credential Access'

            -- Evidence & response
            raw_events      TEXT,    -- JSON list of raw log lines that triggered this
            remediation     TEXT,    -- step-by-step fix instructions
            status          TEXT DEFAULT 'open'  -- open / investigating / resolved / false_positive
        )
    """)
    # IOC CACHE TABLE — stores enrichment results to avoid repeat API calls
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS ioc_cache
                 (
                     ip             TEXT PRIMARY KEY,
                     queried_at     TEXT,
                     abuse_score    INTEGER,
                     total_reports  INTEGER,
                     country_code   TEXT,
                     isp            TEXT,
                     usage_type     TEXT,
                     last_reported  TEXT,
                     is_whitelisted INTEGER,
                     raw_response   TEXT
                 )
                 """)

    conn.commit()
    conn.close()
    print("[db] Database initialized successfully.")


# ─────────────────────────────────────────────
#  EVENTS
# ─────────────────────────────────────────────

def insert_events(events: list[dict]):
    """Insert a list of parsed log event dicts into the events table."""
    if not events:
        print("[db] No events to insert.")
        return

    conn = sqlite3.connect(DB_PATH)
    for e in events:
        conn.execute("""
            INSERT INTO events
            (log_type, timestamp, hostname, source_ip, process, pid, message, raw, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            e.get("log_type"),
            e.get("timestamp"),
            e.get("hostname"),
            e.get("source_ip"),
            e.get("process"),
            e.get("pid"),
            e.get("message"),
            e.get("raw"),
            json.dumps({
                k: v for k, v in e.items()
                if k not in ("log_type", "timestamp", "hostname",
                             "source_ip", "process", "pid", "message", "raw")
            })
        ))
    conn.commit()
    conn.close()
    print(f"[db] Inserted {len(events)} events.")


def get_events(limit: int = 100) -> list[dict]:
    """Return the most recent parsed events, newest first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_events_by_ip(ip: str) -> list[dict]:
    """Return all events from a specific source IP."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM events WHERE source_ip = ? ORDER BY timestamp ASC", (ip,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_failed_logins() -> list[dict]:
    """Return all failed SSH / login events."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        WHERE (
            message LIKE '%Failed password%'
            OR message LIKE '%authentication failure%'
            OR message LIKE '%Invalid user%'
            OR message LIKE '%Connection closed by invalid user%'
        )
        AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_events() -> int:
    """Return total number of events in the table."""
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return count


# ─────────────────────────────────────────────
#  ALERTS
# ─────────────────────────────────────────────

def insert_alert(alert: dict):
    """Insert a single alert dict into the alerts table."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO alerts
        (created_at, alert_type, severity, confidence,
         source_ip, target_host, target_user,
         description, event_count, window_secs,
         first_seen, last_seen,
         attack_id, attack_name, attack_tactic,
         raw_events, remediation, status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        alert.get("created_at"),
        alert.get("alert_type"),
        alert.get("severity"),
        alert.get("confidence"),
        alert.get("source_ip"),
        alert.get("target_host"),
        alert.get("target_user"),
        alert.get("description"),
        alert.get("event_count"),
        alert.get("window_secs"),
        alert.get("first_seen"),
        alert.get("last_seen"),
        alert.get("attack_id"),
        alert.get("attack_name"),
        alert.get("attack_tactic"),
        json.dumps(alert.get("raw_events", [])),
        alert.get("remediation"),
        alert.get("status", "open"),
    ))
    conn.commit()
    conn.close()


def get_alerts() -> list[dict]:
    """Return all alerts, newest first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts_by_severity(severity: str) -> list[dict]:
    """Return alerts filtered by severity: LOW / MEDIUM / HIGH / CRITICAL."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts WHERE severity = ? ORDER BY created_at DESC",
        (severity.upper(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts_by_type(alert_type: str) -> list[dict]:
    """Return alerts filtered by type: e.g. 'brute_force'."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts WHERE alert_type = ? ORDER BY created_at DESC",
        (alert_type,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_alert_status(alert_id: int, new_status: str):
    """Update the status of an alert by ID.
    Valid values: 'open', 'investigating', 'resolved', 'false_positive'
    """
    valid = {"open", "investigating", "resolved", "false_positive"}
    if new_status not in valid:
        raise ValueError(f"Invalid status '{new_status}'. Must be one of: {valid}")

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id)
    )
    conn.commit()
    conn.close()
    print(f"[db] Alert {alert_id} status updated to '{new_status}'.")


def count_alerts() -> dict:
    """Return alert counts grouped by severity."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    """).fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}


# ─────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────

def clear_all():
    """Wipe both tables — useful during development and testing."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    print("[db] All tables cleared.")


def get_summary() -> dict:
    """Return a quick summary of what's in the database."""
    conn = sqlite3.connect(DB_PATH)

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    open_alerts  = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
    ).fetchone()[0]

    severity_breakdown = {
        row[0]: row[1] for row in conn.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ).fetchall()
    }

    type_breakdown = {
        row[0]: row[1] for row in conn.execute(
            "SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"
        ).fetchall()
    }

    conn.close()

    return {
        "total_events":       total_events,
        "total_alerts":       total_alerts,
        "open_alerts":        open_alerts,
        "severity_breakdown": severity_breakdown,
        "type_breakdown":     type_breakdown,
    }
def get_cached_ioc(ip: str, max_age_hours: int = 24) -> dict | None:
    """Return cached enrichment if it exists and isn't stale."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM ioc_cache WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()

    if not row:
        return None

    # Check if cache is still fresh
    queried_at = datetime.fromisoformat(row["queried_at"])
    age_hours = (datetime.now() - queried_at).total_seconds() / 3600
    if age_hours > max_age_hours:
        return None  # stale — re-query

    return dict(row)


def save_ioc_cache(ioc: dict):
    """Save or update an enrichment result in the cache."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ioc_cache
        (ip, queried_at, abuse_score, total_reports, country_code,
         isp, usage_type, last_reported, is_whitelisted, raw_response)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            queried_at     = excluded.queried_at,
            abuse_score    = excluded.abuse_score,
            total_reports  = excluded.total_reports,
            country_code   = excluded.country_code,
            isp            = excluded.isp,
            usage_type     = excluded.usage_type,
            last_reported  = excluded.last_reported,
            is_whitelisted = excluded.is_whitelisted,
            raw_response   = excluded.raw_response
    """, (
        ioc["ip"],
        ioc["queried_at"],
        ioc["abuse_score"],
        ioc["total_reports"],
        ioc["country_code"],
        ioc["isp"],
        ioc["usage_type"],
        ioc.get("last_reported"),
        ioc.get("is_whitelisted", 0),
        ioc.get("raw_response"),
    ))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
#  QUICK TEST — run this file directly to verify
#  python database/storage.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[db] Using database at: {DB_PATH}")
    init_db()

    summary = get_summary()
    print(f"[db] Events : {summary['total_events']}")
    print(f"[db] Alerts : {summary['total_alerts']} total, {summary['open_alerts']} open")
    print(f"[db] Severity breakdown : {summary['severity_breakdown']}")
    print(f"[db] Alert types        : {summary['type_breakdown']}")