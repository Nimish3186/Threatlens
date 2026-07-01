import sqlite3
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "events.db"

# Tunable config
THRESHOLD   = 3     # failed attempts to trigger
WINDOW_SECS = 60     # within this many seconds


def fetch_failed_logins() -> list[dict]:
    """Pull all failed SSH/login events from the events table."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        WHERE (
            message LIKE '%Failed password%'
            OR message LIKE '%authentication failure%'
            OR message LIKE '%Invalid user%'
        )
        AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def extract_ip_from_message(message: str) -> str | None:
    """Pull the attacker IP from a syslog message string."""
    import re
    # Matches: "from 192.168.1.5" or "rhost=10.0.0.1"
    match = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
    if match:
        return match.group(1)
    match = re.search(r'rhost=(\d{1,3}(?:\.\d{1,3}){3})', message)
    if match:
        return match.group(1)
    return None


def sliding_window_check(timestamps: list[datetime]) -> list[datetime]:
    """
    Given a sorted list of timestamps for one IP,
    return the earliest window of THRESHOLD hits within WINDOW_SECS.
    Returns the matching timestamps if found, else empty list.
    """
    if len(timestamps) < THRESHOLD:
        return []

    for i in range(len(timestamps) - THRESHOLD + 1):
        window_start = timestamps[i]
        window_end   = timestamps[i + THRESHOLD - 1]
        delta = (window_end - window_start).total_seconds()
        if delta <= WINDOW_SECS:
            return timestamps[i: i + THRESHOLD]

    return []



def extract_target_user(message: str) -> str:
    match = re.search(r'Failed password for (?:invalid user )?(\S+) from', message)
    return match.group(1) if match else "unknown"

def calculate_severity(event_count: int) -> str:
    if event_count >= 20:
        return "CRITICAL"
    elif event_count >= 10:
        return "HIGH"
    elif event_count >= 5:
        return "MEDIUM"
    return "LOW"

def build_alert(ip: str, matching_events: list[dict], window_hits: list) -> dict:
    first_seen = window_hits[0].isoformat()
    last_seen  = window_hits[-1].isoformat()
    count      = len(window_hits)
    severity   = calculate_severity(count)

    # Get target user from the first matching event
    sample_message  = matching_events[0].get("message", "")
    target_user     = extract_target_user(sample_message)
    target_host     = matching_events[0].get("hostname", "unknown")

    return {
        "created_at":     datetime.now().isoformat(),
        "alert_type":     "brute_force",
        "severity":       severity,
        "confidence":     "HIGH",
        "source_ip":      ip,
        "target_host":    target_host,
        "target_user":    target_user,
        "description": (
            f"Brute force: {ip} made {count} failed login attempts "
            f"targeting '{target_user}' on {target_host} within {WINDOW_SECS}s"
        ),
        "event_count":    count,
        "window_secs":    WINDOW_SECS,
        "first_seen":     first_seen,
        "last_seen":      last_seen,
        "attack_id":      "T1110.001",
        "attack_name":    "Brute Force: Password Guessing",
        "attack_tactic":  "Credential Access",
        "raw_events":     [e["raw"] for e in matching_events[:10]],
        "remediation":    (
            f"1. Block {ip} at firewall: `iptables -A INPUT -s {ip} -j DROP`\n"
            f"2. Check if '{target_user}' account was compromised\n"
            f"3. Review full auth.log around {first_seen}\n"
            f"4. Consider installing fail2ban"
        ),
        "status":         "open",
    }


def get_timestamp(pair):
    return pair[0]


def detect_brute_force() -> list[dict]:
    """Main entry point. Returns a list of alert dicts."""
    events = fetch_failed_logins()

    if not events:
        print("[brute_force] No failed login events found.")
        return []

    # Group events by attacker IP
    ip_events: dict[str, list] = defaultdict(list)

    for e in events:
        ip = e.get("source_ip") or extract_ip_from_message(e.get("message", ""))
        if not ip:
            continue
        try:
            ts = datetime.fromisoformat(e["timestamp"])
        except (ValueError, TypeError):
            continue
        ip_events[ip].append((ts, e))

    alerts = []

    for ip, ts_event_pairs in ip_events.items():
        ts_event_pairs.sort(key=get_timestamp)
        timestamps = [ts for ts, _ in ts_event_pairs]
        matched_events = [ev for _, ev in ts_event_pairs]

        window_hits = sliding_window_check(timestamps)

        if window_hits:
            alert = build_alert(ip, matched_events, window_hits)
            alerts.append(alert)
            print(f"[ALERT] Brute force from {ip} — {len(window_hits)} hits in {WINDOW_SECS}s")

    print(f"[brute_force] Scan complete. {len(alerts)} alert(s) generated.")
    return alerts


