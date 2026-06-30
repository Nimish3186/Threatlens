import re
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.storage import DB_PATH, get_failed_logins
import sqlite3
import json

# ─────────────────────────────────────────────
#  TUNABLE CONFIG
# ─────────────────────────────────────────────

WINDOW_SECS = 300   # 5-minute window for correlating related events


# ─────────────────────────────────────────────
#  DANGEROUS COMMANDS — any sudo use of these is an escalation signal
# ─────────────────────────────────────────────

DANGEROUS_COMMANDS = [
    "/bin/bash", "/bin/sh", "/bin/zsh",          # shell spawn as root
    "/bin/su",                                    # su inside sudo
    "/usr/bin/passwd",                            # changing passwords
    "/bin/chmod",  "/usr/bin/chmod",             # permission changes
    "/bin/chown",  "/usr/bin/chown",
    "/etc/sudoers", "/etc/passwd", "/etc/shadow", # sensitive file edits
    "/usr/sbin/useradd", "/usr/sbin/usermod",    # account manipulation
    "/usr/sbin/visudo",
    "python", "python3", "perl", "ruby",          # script interpreters (GTFOBins)
    "awk", "vim", "vi", "nano", "less", "more",  # editors that can spawn shells
    "find", "curl", "wget",                       # common GTFOBins
]

CRITICAL_FILES = [
    "/etc/sudoers", "/etc/passwd", "/etc/shadow",
    "/etc/crontab", "/etc/cron.d", "/root/.ssh",
]


# ─────────────────────────────────────────────
#  REGEX PATTERNS
# ─────────────────────────────────────────────

# sudo: nimish : TTY=pts/0 ; PWD=/home/nimish ; USER=root ; COMMAND=/bin/bash
SUDO_PATTERN = re.compile(
    r'(?P<user>\S+)\s*:\s*TTY=\S+\s*;.*?USER=(?P<target_user>\S+)\s*;'
    r'\s*COMMAND=(?P<command>.+)$'
)

# su: Successful su for root by nimish
SU_PATTERN = re.compile(
    r'(?:Successful su for|session opened for user)\s+(?P<target_user>\S+)'
    r'(?:\s+by\s+(?P<user>\S+))?'
)

# pam session opened for root
PAM_ROOT_PATTERN = re.compile(
    r'session opened for user\s+(?P<target_user>\S+)'
)

# chmod with wide permissions
CHMOD_PATTERN = re.compile(
    r'COMMAND=.*?chmod\s+(?P<perms>[0-9]+|[ugoa][+\-=][rwxst]+)\s+(?P<path>\S+)'
)

# new user / group added
USERADD_PATTERN = re.compile(
    r'new (?:user|group):\s+name=(?P<newuser>\S+)'
)


# ─────────────────────────────────────────────
#  FETCH EVENTS FROM DB
# ─────────────────────────────────────────────

def fetch_priv_events() -> list[dict]:
    """Pull all potentially relevant events from the events table."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        WHERE (
            message LIKE '%sudo%'
            OR message LIKE '%su for%'
            OR message LIKE '%session opened for user root%'
            OR message LIKE '%COMMAND=%'
            OR message LIKE '%new user%'
            OR message LIKE '%new group%'
            OR message LIKE '%useradd%'
            OR message LIKE '%usermod%'
            OR message LIKE '%passwd%'
            OR message LIKE '%sudoers%'
            OR message LIKE '%chmod%'
            OR message LIKE '%chown%'
        )
        AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
#  CLASSIFY EACH EVENT
# ─────────────────────────────────────────────

def classify_event(event: dict) -> dict | None:
    """
    Inspect one event and return a classification dict if it looks
    like a privilege escalation signal. Returns None if not relevant.
    """
    msg = event.get("message", "")

    # ── sudo execution ──────────────────────────────────────────────
    sudo_match = SUDO_PATTERN.search(msg)
    if sudo_match:
        user        = sudo_match.group("user")
        target_user = sudo_match.group("target_user")
        command     = sudo_match.group("command").strip()

        # Only care about sudo to root
        if target_user != "root":
            return None

        # Check if command is dangerous
        is_dangerous = any(danger in command for danger in DANGEROUS_COMMANDS)
        touches_critical = any(f in command for f in CRITICAL_FILES)

        severity   = "CRITICAL" if touches_critical else ("HIGH" if is_dangerous else "MEDIUM")
        confidence = "HIGH"     if is_dangerous     else "MEDIUM"

        return {
            "subtype":      "sudo_to_root",
            "user":         user,
            "target_user":  target_user,
            "command":      command,
            "severity":     severity,
            "confidence":   confidence,
            "attack_id":    "T1548.003",
            "attack_name":  "Abuse Elevation Control: Sudo and Sudo Caching",
            "attack_tactic":"Privilege Escalation",
            "description":  f"User '{user}' ran sudo as root: {command}",
        }

    # ── su to root ──────────────────────────────────────────────────
    su_match = SU_PATTERN.search(msg)
    if su_match and "su" in event.get("process", "").lower():
        target_user = su_match.group("target_user")
        user        = su_match.group("user") or "unknown"
        if target_user == "root":
            return {
                "subtype":      "su_to_root",
                "user":         user,
                "target_user":  "root",
                "command":      "su root",
                "severity":     "HIGH",
                "confidence":   "HIGH",
                "attack_id":    "T1548.003",
                "attack_name":  "Abuse Elevation Control: Sudo and Sudo Caching",
                "attack_tactic":"Privilege Escalation",
                "description":  f"User '{user}' switched to root via su",
            }

    # ── root SSH/PAM session opened ─────────────────────────────────
    if "session opened for user root" in msg:
        return {
            "subtype":      "root_session_opened",
            "user":         "root",
            "target_user":  "root",
            "command":      "login",
            "severity":     "HIGH",
            "confidence":   "MEDIUM",
            "attack_id":    "T1078.003",
            "attack_name":  "Valid Accounts: Local Accounts",
            "attack_tactic":"Privilege Escalation",
            "description":  "Root session opened — direct root login detected",
        }

    # ── chmod with dangerous permissions ────────────────────────────
    chmod_match = CHMOD_PATTERN.search(msg)
    if chmod_match:
        perms = chmod_match.group("perms")
        path  = chmod_match.group("path")
        # Flag world-writable (777, 666, o+w) or SUID (4xxx, u+s)
        is_dangerous_perm = (
            "777" in perms or "666" in perms or
            "+w" in perms  or "4755" in perms or
            "u+s" in perms or "g+s" in perms
        )
        if is_dangerous_perm:
            return {
                "subtype":      "dangerous_chmod",
                "user":         event.get("process", "unknown"),
                "target_user":  "root",
                "command":      f"chmod {perms} {path}",
                "severity":     "HIGH",
                "confidence":   "HIGH",
                "attack_id":    "T1222.002",
                "attack_name":  "File and Directory Permissions Modification: Linux",
                "attack_tactic":"Defense Evasion",
                "description":  f"Dangerous permission change: chmod {perms} {path}",
            }

    # ── new user/group created ───────────────────────────────────────
    useradd_match = USERADD_PATTERN.search(msg)
    if useradd_match:
        newuser = useradd_match.group("newuser")
        return {
            "subtype":      "new_account_created",
            "user":         event.get("process", "unknown"),
            "target_user":  newuser,
            "command":      f"useradd {newuser}",
            "severity":     "MEDIUM",
            "confidence":   "HIGH",
            "attack_id":    "T1136.001",
            "attack_name":  "Create Account: Local Account",
            "attack_tactic":"Persistence",
            "description":  f"New local account created: '{newuser}'",
        }

    return None


# ─────────────────────────────────────────────
#  BUILD ALERT
# ─────────────────────────────────────────────

def build_priv_alert(event: dict, classification: dict) -> dict:
    """Combine a raw event with its classification into a full alert dict."""
    hostname = event.get("hostname", "unknown")
    ip       = event.get("source_ip", "")
    ts       = event.get("timestamp", datetime.now().isoformat())
    user     = classification["user"]
    command  = classification["command"]

    return {
        "created_at":     datetime.now().isoformat(),
        "alert_type":     "priv_escalation",
        "severity":       classification["severity"],
        "confidence":     classification["confidence"],
        "source_ip":      ip or hostname,
        "target_host":    hostname,
        "target_user":    classification["target_user"],
        "description":    classification["description"],
        "event_count":    1,
        "window_secs":    0,
        "first_seen":     ts,
        "last_seen":      ts,
        "attack_id":      classification["attack_id"],
        "attack_name":    classification["attack_name"],
        "attack_tactic":  classification["attack_tactic"],
        "raw_events":     [event.get("raw", "")],
        "remediation":    build_remediation(classification, hostname, user, command),
        "status":         "open",
    }


def build_remediation(cls: dict, host: str, user: str, command: str) -> str:
    subtype = cls["subtype"]

    if subtype == "sudo_to_root":
        return (
            f"1. Review sudo usage by '{user}' on {host}\n"
            f"2. Check if command was authorized: {command}\n"
            f"3. Audit /etc/sudoers: sudo visudo\n"
            f"4. Review full session: ausearch -ua {user}\n"
            f"5. Consider restricting sudo with NOEXEC or specific command allowlist"
        )
    elif subtype == "su_to_root":
        return (
            f"1. Check who ran 'su root' on {host}\n"
            f"2. Verify root password has not been changed\n"
            f"3. Consider disabling direct root login: passwd -l root\n"
            f"4. Review PAM config: /etc/pam.d/su"
        )
    elif subtype == "root_session_opened":
        return (
            f"1. Check /var/log/auth.log for root login source IP\n"
            f"2. Disable root SSH login: PermitRootLogin no in /etc/ssh/sshd_config\n"
            f"3. Verify no unauthorized SSH keys in /root/.ssh/authorized_keys\n"
            f"4. Restart SSH: systemctl restart sshd"
        )
    elif subtype == "dangerous_chmod":
        return (
            f"1. Review the permission change: {command}\n"
            f"2. Revert if unauthorized: chmod 644 <file>\n"
            f"3. Check for SUID binaries: find / -perm -4000 -type f 2>/dev/null\n"
            f"4. Audit who ran this command via auth.log"
        )
    elif subtype == "new_account_created":
        return (
            f"1. Verify account creation was authorized\n"
            f"2. Check new account's groups: id {cls['target_user']}\n"
            f"3. If unauthorized: userdel -r {cls['target_user']}\n"
            f"4. Review /etc/passwd for unexpected accounts"
        )
    return "Review the event manually and check system audit logs."


# ─────────────────────────────────────────────
#  DEDUPLICATION
# ─────────────────────────────────────────────

def deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    """
    If the same user ran the same command within WINDOW_SECS,
    collapse into one alert rather than firing 10 times for one session.
    """
    seen    = {}
    unique  = []

    for alert in alerts:
        key = (
            alert["target_host"],
            alert["target_user"],
            alert.get("description", "")[:60],   # first 60 chars of description
        )
        ts = alert["first_seen"]

        if key in seen:
            last_ts = datetime.fromisoformat(seen[key])
            curr_ts = datetime.fromisoformat(ts)
            if (curr_ts - last_ts).total_seconds() < WINDOW_SECS:
                continue   # duplicate within window — skip

        seen[key] = ts
        unique.append(alert)

    return unique


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def detect_priv_escalation() -> list[dict]:
    """
    Main detector function.
    Fetches events, classifies each one, builds and deduplicates alerts.
    Returns list of alert dicts ready to insert into DB.
    """
    events = fetch_priv_events()

    if not events:
        print("[priv_escalation] No relevant events found in DB.")
        return []

    print(f"[priv_escalation] Scanning {len(events)} candidate events...")

    raw_alerts = []

    for event in events:
        classification = classify_event(event)
        if classification:
            alert = build_priv_alert(event, classification)
            raw_alerts.append(alert)
            print(f"  [ALERT] {classification['severity']} — {classification['description']}")

    alerts = deduplicate_alerts(raw_alerts)

    removed = len(raw_alerts) - len(alerts)
    if removed:
        print(f"[priv_escalation] Deduplicated {removed} duplicate alert(s)")

    print(f"[priv_escalation] Scan complete. {len(alerts)} alert(s) generated.")
    return alerts


# ─────────────────────────────────────────────
#  QUICK TEST — python detectors/priv_escalation.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from database.storage import init_db, insert_events, insert_alert, get_alerts

    init_db()

    # Inject fake events that cover every detection subtype
    fake_events = [
        {   # sudo shell spawn — HIGH
            "log_type": "syslog", "timestamp": "2025-06-27T10:17:45",
            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1350",
            "message": "nimish : TTY=pts/0 ; PWD=/home/nimish ; USER=root ; COMMAND=/bin/bash",
            "raw": "Jun 27 10:17:45 kali-system sudo[1350]: nimish : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
        },
        {   # sudoers edit — CRITICAL
            "log_type": "syslog", "timestamp": "2025-06-27T10:21:05",
            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1410",
            "message": "nimish : TTY=pts/0 ; PWD=/home/nimish ; USER=root ; COMMAND=/bin/nano /etc/sudoers",
            "raw": "Jun 27 10:21:05 kali-system sudo[1410]: nimish : USER=root ; COMMAND=/bin/nano /etc/sudoers",
        },
        {   # su to root — HIGH
            "log_type": "syslog", "timestamp": "2025-06-27T10:18:01",
            "hostname": "kali-system", "source_ip": "", "process": "su", "pid": "1401",
            "message": "Successful su for root by nimish",
            "raw": "Jun 27 10:18:01 kali-system su[1401]: Successful su for root by nimish",
        },
        {   # root session opened — HIGH
            "log_type": "syslog", "timestamp": "2025-06-27T10:16:11",
            "hostname": "kali-system", "source_ip": "203.0.113.45", "process": "sshd", "pid": "1301",
            "message": "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
            "raw": "Jun 27 10:16:11 kali-system sshd[1301]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
        },
        {   # dangerous chmod — HIGH
            "log_type": "syslog", "timestamp": "2025-06-27T10:19:22",
            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1402",
            "message": "nimish : USER=root ; COMMAND=/bin/chmod 777 /etc/passwd",
            "raw": "Jun 27 10:19:22 kali-system sudo[1402]: nimish : USER=root ; COMMAND=/bin/chmod 777 /etc/passwd",
        },
        {   # new user created — MEDIUM
            "log_type": "syslog", "timestamp": "2025-06-27T10:22:30",
            "hostname": "kali-system", "source_ip": "", "process": "useradd", "pid": "1450",
            "message": "new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor",
            "raw": "Jun 27 10:22:30 kali-system useradd[1450]: new user: name=backdoor, UID=1337",
        },
        {   # safe sudo (apt update) — should NOT trigger
            "log_type": "syslog", "timestamp": "2025-06-27T10:17:46",
            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1350",
            "message": "nimish : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update",
            "raw": "Jun 27 10:17:46 kali-system sudo[1350]: nimish : USER=root ; COMMAND=/usr/bin/apt update",
        },
    ]

    insert_events(fake_events)
    alerts = detect_priv_escalation()

    for a in alerts:
        insert_alert(a)

    print(f"\n=== {len(alerts)} ALERTS STORED ===")
    for a in get_alerts():
        if a["alert_type"] == "priv_escalation":
            print(f"\n  [{a['severity']}] {a['attack_id']} — {a['description']}")
            print(f"  Remediation preview: {a['remediation'].splitlines()[0]}")