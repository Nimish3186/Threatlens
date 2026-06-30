import re
import sys
import sqlite3
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.storage import DB_PATH

# ─────────────────────────────────────────────
#  TUNABLE CONFIG
# ─────────────────────────────────────────────

SCORE_THRESHOLD   = 50    # minimum risk score to fire an alert
OFF_HOURS_START   = 0     # midnight
OFF_HOURS_END     = 5     # 5 am
FAIL_WINDOW_SECS  = 300   # look back 5 min for failures before a success

# Risk points per signal
POINTS = {
    "off_hours":        30,
    "root_login":       50,
    "new_ip":           25,
    "fail_then_success":40,
    "multi_account":    35,
}

# ─────────────────────────────────────────────
#  REGEX PATTERNS
# ─────────────────────────────────────────────

# Accepted password for nimish from 192.168.1.25 port 52134 ssh2
SUCCESS_PATTERN = re.compile(
    r'Accepted (?:password|publickey|keyboard-interactive) for (?P<user>\S+)'
    r' from (?P<ip>[\d.]+) port (?P<port>\d+)'
)

# Failed password for root from 203.0.113.45 port 51422 ssh2
FAILURE_PATTERN = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+)'
    r' from (?P<ip>[\d.]+) port (?P<port>\d+)'
)

# session opened for user root
ROOT_SESSION_PATTERN = re.compile(
    r'session opened for user (?P<user>root)'
)


# ─────────────────────────────────────────────
#  FETCH EVENTS FROM DB
# ─────────────────────────────────────────────

def fetch_login_events() -> list[dict]:
    """Pull all successful and failed login events."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        WHERE (
            message LIKE '%Accepted password%'
            OR message LIKE '%Accepted publickey%'
            OR message LIKE '%Accepted keyboard-interactive%'
            OR message LIKE '%Failed password%'
            OR message LIKE '%session opened for user%'
        )
        AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
#  EXTRACT KNOWN IPs FROM HISTORY
# ─────────────────────────────────────────────

def build_known_ips(events: list[dict]) -> set[str]:
    """
    Build a set of IPs that have successfully logged in before.
    Used to detect first-time IPs.
    In production you'd persist this — for now we build it from
    the earliest 50% of events as our 'history'.
    """
    known = set()
    cutoff = len(events) // 2
    for event in events[:cutoff]:
        msg = event.get("message", "")
        m = SUCCESS_PATTERN.search(msg)
        if m:
            known.add(m.group("ip"))
    return known


# ─────────────────────────────────────────────
#  CLASSIFY ONE SUCCESSFUL LOGIN
# ─────────────────────────────────────────────

def score_login(
    event: dict,
    all_events: list[dict],
    known_ips: set[str],
    failure_index: dict,     # ip -> list of failure timestamps
    spray_index: dict,       # ip -> set of usernames attempted
) -> dict | None:
    """
    Score a single successful login event.
    Returns a signal dict if score >= threshold, else None.
    """
    msg  = event.get("message", "")
    ts   = event.get("timestamp", "")
    host = event.get("hostname", "unknown")

    # Try to parse as a successful login
    m = SUCCESS_PATTERN.search(msg)

    # Also catch root session opened (PAM)
    is_root_session = bool(ROOT_SESSION_PATTERN.search(msg))

    if not m and not is_root_session:
        return None

    if m:
        user = m.group("user")
        ip   = m.group("ip")
    else:
        user = "root"
        ip   = event.get("source_ip") or host

    try:
        login_time = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None

    signals = []
    score   = 0

    # ── Signal 1: off-hours login ──────────────────────────────────
    hour = login_time.hour
    if OFF_HOURS_START <= hour < OFF_HOURS_END:
        score += POINTS["off_hours"]
        signals.append(f"off-hours login ({hour:02d}:xx)")

    # ── Signal 2: direct root login ────────────────────────────────
    if user == "root" or is_root_session:
        score += POINTS["root_login"]
        signals.append("direct root login")

    # ── Signal 3: never-seen-before IP ────────────────────────────
    if ip and ip not in known_ips:
        score += POINTS["new_ip"]
        signals.append(f"new source IP ({ip})")

    # ── Signal 4: failures immediately before success ──────────────
    if ip and ip in failure_index:
        window_start = login_time - timedelta(seconds=FAIL_WINDOW_SECS)
        recent_fails = [
            t for t in failure_index[ip]
            if window_start <= t <= login_time
        ]
        if recent_fails:
            score += POINTS["fail_then_success"]
            signals.append(
                f"{len(recent_fails)} failure(s) before success within {FAIL_WINDOW_SECS}s"
            )

    # ── Signal 5: multi-account spray from same IP ─────────────────
    if ip and ip in spray_index:
        accounts = spray_index[ip]
        if len(accounts) >= 3:
            score += POINTS["multi_account"]
            signals.append(
                f"password spray: {len(accounts)} accounts tried from {ip}"
            )

    if score < SCORE_THRESHOLD:
        return None

    return {
        "user":    user,
        "ip":      ip,
        "ts":      ts,
        "host":    host,
        "score":   score,
        "signals": signals,
    }


# ─────────────────────────────────────────────
#  SEVERITY FROM SCORE
# ─────────────────────────────────────────────

def severity_from_score(score: int) -> str:
    if score >= 100: return "CRITICAL"
    if score >= 75:  return "HIGH"
    return "MEDIUM"


def confidence_from_signals(signals: list[str]) -> str:
    if len(signals) >= 3: return "HIGH"
    if len(signals) == 2: return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────
#  BUILD ALERT
# ─────────────────────────────────────────────

def build_suspicious_login_alert(result: dict, raw_event: dict) -> dict:
    user    = result["user"]
    ip      = result["ip"]
    host    = result["host"]
    score   = result["score"]
    signals = result["signals"]
    ts      = result["ts"]
    sev     = severity_from_score(score)
    conf    = confidence_from_signals(signals)

    signals_text = "; ".join(signals)
    description  = (
        f"Suspicious login: '{user}' from {ip} on {host} "
        f"(risk score {score}) — {signals_text}"
    )

    attack_id, attack_name, tactic = pick_attack(signals)

    return {
        "created_at":    datetime.now().isoformat(),
        "alert_type":    "suspicious_login",
        "severity":      sev,
        "confidence":    conf,
        "source_ip":     ip,
        "target_host":   host,
        "target_user":   user,
        "description":   description,
        "event_count":   1,
        "window_secs":   FAIL_WINDOW_SECS,
        "first_seen":    ts,
        "last_seen":     ts,
        "attack_id":     attack_id,
        "attack_name":   attack_name,
        "attack_tactic": tactic,
        "raw_events":    [raw_event.get("raw", "")],
        "remediation":   build_remediation(user, ip, host, signals, sev),
        "status":        "open",
    }


def pick_attack(signals: list[str]) -> tuple[str, str, str]:
    """Pick the most relevant ATT&CK technique based on active signals."""
    if any("spray" in s for s in signals):
        return "T1110.003", "Brute Force: Password Spraying", "Credential Access"
    if any("root" in s for s in signals):
        return "T1078.003", "Valid Accounts: Local Accounts", "Privilege Escalation"
    if any("failure" in s for s in signals):
        return "T1110.001", "Brute Force: Password Guessing", "Credential Access"
    return "T1078", "Valid Accounts", "Defense Evasion"


def build_remediation(
    user: str, ip: str, host: str, signals: list[str], severity: str
) -> str:
    steps = [f"1. Verify if '{user}' login from {ip} on {host} was authorized"]

    if any("root" in s for s in signals):
        steps.append("2. Disable direct root SSH: set PermitRootLogin no in /etc/ssh/sshd_config")
        steps.append("3. Check /root/.ssh/authorized_keys for unauthorized keys")

    if any("failure" in s for s in signals):
        steps.append(f"4. Investigate failures from {ip} — possible credential theft")
        steps.append(f"5. Block {ip}: iptables -A INPUT -s {ip} -j DROP")

    if any("spray" in s for s in signals):
        steps.append("6. Audit all accounts for unauthorized access")
        steps.append("7. Force password reset for all targeted accounts")

    if any("off-hours" in s for s in signals):
        steps.append("8. Confirm with user whether login was expected at this hour")

    if any("new" in s and "IP" in s for s in signals):
        steps.append(f"9. Geolocate {ip} and verify it matches user's expected location")

    if severity == "CRITICAL":
        steps.append("10. CRITICAL: Consider isolating host and initiating incident response")

    return "\n".join(steps)


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def detect_suspicious_logins() -> list[dict]:
    """
    Main detector. Fetches events, builds indexes,
    scores each successful login, returns alert dicts.
    """
    events = fetch_login_events()

    if not events:
        print("[suspicious_login] No login events found in DB.")
        return []

    print(f"[suspicious_login] Scanning {len(events)} login events...")

    # Build lookup indexes in one pass
    known_ips     = build_known_ips(events)
    failure_index = defaultdict(list)   # ip -> [datetime, ...]
    spray_index   = defaultdict(set)    # ip -> {username, ...}

    for e in events:
        msg = e.get("message", "")
        ts  = e.get("timestamp")

        fail_m = FAILURE_PATTERN.search(msg)
        if fail_m and ts:
            try:
                failure_index[fail_m.group("ip")].append(
                    datetime.fromisoformat(ts)
                )
                spray_index[fail_m.group("ip")].add(fail_m.group("user"))
            except ValueError:
                pass

    # Score every successful login
    alerts = []
    seen   = set()  # deduplicate same user+ip within same minute

    for event in events:
        result = score_login(
            event, events, known_ips, failure_index, spray_index
        )
        if not result:
            continue

        dedup_key = (result["user"], result["ip"], result["ts"][:16])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        alert = build_suspicious_login_alert(result, event)
        alerts.append(alert)
        print(
            f"  [ALERT] {alert['severity']} (score {result['score']}) — "
            f"{result['user']}@{result['ip']} — {'; '.join(result['signals'])}"
        )

    print(f"[suspicious_login] Scan complete. {len(alerts)} alert(s) generated.")
    return alerts


# ─────────────────────────────────────────────
#  QUICK TEST — python detectors/suspicious_login.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all

    init_db()
    clear_all()

    base = datetime(2025, 6, 27)

    fake_events = [
        # ── Normal daytime login (should NOT alert) ──────────────────
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=9, minute=0)).isoformat(),
            "hostname": "kali-system", "source_ip": "192.168.1.25",
            "process": "sshd", "pid": "1301", "message":
            "Accepted password for nimish from 192.168.1.25 port 52134 ssh2",
            "raw": "Jun 27 09:00:00 kali-system sshd[1301]: Accepted password for nimish from 192.168.1.25 port 52134 ssh2",
        },
        # ── Off-hours login from same known IP (MEDIUM — off hours only) ─
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=2, minute=15)).isoformat(),
            "hostname": "kali-system", "source_ip": "192.168.1.25",
            "process": "sshd", "pid": "1310", "message":
            "Accepted password for nimish from 192.168.1.25 port 52200 ssh2",
            "raw": "Jun 27 02:15:00 kali-system sshd[1310]: Accepted password for nimish from 192.168.1.25 port 52200 ssh2",
        },
        # ── 3 failures then success from attacker IP (HIGH) ──────────
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=0)).isoformat(),
            "hostname": "kali-system", "source_ip": "203.0.113.45",
            "process": "sshd", "pid": "1400", "message":
            "Failed password for nimish from 203.0.113.45 port 51000 ssh2",
            "raw": "Jun 27 03:00:00 kali-system sshd[1400]: Failed password for nimish from 203.0.113.45 port 51000 ssh2",
        },
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=1)).isoformat(),
            "hostname": "kali-system", "source_ip": "203.0.113.45",
            "process": "sshd", "pid": "1401", "message":
            "Failed password for nimish from 203.0.113.45 port 51001 ssh2",
            "raw": "Jun 27 03:01:00 kali-system sshd[1401]: Failed password for nimish from 203.0.113.45 port 51001 ssh2",
        },
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=2)).isoformat(),
            "hostname": "kali-system", "source_ip": "203.0.113.45",
            "process": "sshd", "pid": "1402", "message":
            "Failed password for nimish from 203.0.113.45 port 51002 ssh2",
            "raw": "Jun 27 03:02:00 kali-system sshd[1402]: Failed password for nimish from 203.0.113.45 port 51002 ssh2",
        },
        {   # success after failures — HIGH (off-hours + new IP + fail-then-success)
            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=3)).isoformat(),
            "hostname": "kali-system", "source_ip": "203.0.113.45",
            "process": "sshd", "pid": "1403", "message":
            "Accepted password for nimish from 203.0.113.45 port 51003 ssh2",
            "raw": "Jun 27 03:03:00 kali-system sshd[1403]: Accepted password for nimish from 203.0.113.45 port 51003 ssh2",
        },
        # ── Password spray then success (CRITICAL) ───────────────────
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=0)).isoformat(),
            "hostname": "kali-system", "source_ip": "10.0.0.99",
            "process": "sshd", "pid": "1500", "message":
            "Failed password for admin from 10.0.0.99 port 60000 ssh2",
            "raw": "Jun 27 01:00:00 kali-system sshd[1500]: Failed password for admin from 10.0.0.99 port 60000 ssh2",
        },
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=1)).isoformat(),
            "hostname": "kali-system", "source_ip": "10.0.0.99",
            "process": "sshd", "pid": "1501", "message":
            "Failed password for ubuntu from 10.0.0.99 port 60001 ssh2",
            "raw": "Jun 27 01:01:00 kali-system sshd[1501]: Failed password for ubuntu from 10.0.0.99 port 60001 ssh2",
        },
        {
            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=2)).isoformat(),
            "hostname": "kali-system", "source_ip": "10.0.0.99",
            "process": "sshd", "pid": "1502", "message":
            "Failed password for guest from 10.0.0.99 port 60002 ssh2",
            "raw": "Jun 27 01:02:00 kali-system sshd[1502]: Failed password for guest from 10.0.0.99 port 60002 ssh2",
        },
        {   # root login after spray at 1am — CRITICAL
            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=3)).isoformat(),
            "hostname": "kali-system", "source_ip": "10.0.0.99",
            "process": "sshd", "pid": "1503", "message":
            "Accepted password for root from 10.0.0.99 port 60003 ssh2",
            "raw": "Jun 27 01:03:00 kali-system sshd[1503]: Accepted password for root from 10.0.0.99 port 60003 ssh2",
        },
    ]

    insert_events(fake_events)
    alerts = detect_suspicious_logins()

    for a in alerts:
        insert_alert(a)

    print(f"\n=== {len(alerts)} ALERT(S) STORED ===")
    for a in get_alerts():
        if a["alert_type"] == "suspicious_login":
            print(f"\n  [{a['severity']}] score — {a['description'][:80]}")
            print(f"  ATT&CK : {a['attack_id']} — {a['attack_name']}")
            print(f"  Fix    : {a['remediation'].splitlines()[0]}")