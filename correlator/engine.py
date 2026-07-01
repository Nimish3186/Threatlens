import sys
import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.storage import DB_PATH

# ─────────────────────────────────────────────
#  TUNABLE CONFIG
# ─────────────────────────────────────────────

CORRELATION_WINDOW_MIN = 30   # alerts within this many minutes get grouped
MIN_ALERTS_TO_CORRELATE = 2   # need at least this many alerts to form an incident
MIN_SOURCES_FOR_BOOST   = 2   # alerts from this many distinct log_types = severity boost

# Attack chain stages — used to detect a recognizable kill-chain pattern
KILL_CHAIN_STAGES = {
    "port_scan":             1,   # Reconnaissance
    "sensitive_port_probe":  1,   # Reconnaissance
    "scanner_detected":      1,   # Reconnaissance (apache)
    "sensitive_path_probe":  1,   # Reconnaissance (apache)
    "brute_force":           2,   # Credential Access
    "web_brute_force":       2,   # Credential Access
    "suspicious_login":      3,   # Initial Access
    "sql_injection":         3,   # Initial Access
    "web_attack":            3,   # Initial Access (covers sqli/xss/etc subtypes)
    "priv_escalation":       4,   # Privilege Escalation
    "mobile_root_jailbreak": 4,   # Privilege Escalation
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ─────────────────────────────────────────────
#  FETCH ALL ALERTS
# ─────────────────────────────────────────────

def fetch_all_alerts() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM alerts
        WHERE source_ip IS NOT NULL AND source_ip != ''
        ORDER BY first_seen ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_log_type_for_alert(alert: dict) -> str:
    """Infer which log source an alert came from based on its alert_type."""
    mapping = {
        "brute_force":            "syslog",
        "priv_escalation":        "syslog",
        "suspicious_login":       "syslog",
        "port_scan":              "firewall",
        "sensitive_port_probe":   "firewall",
        "web_attack":             "apache",
        "web_brute_force":        "apache",
        "mobile_root_jailbreak":  "mobile",
        "mobile_suspicious_install": "mobile",
        "mobile_sandbox_violation": "mobile",
    }
    return mapping.get(alert.get("alert_type", ""), "unknown")


# ─────────────────────────────────────────────
#  GROUP ALERTS BY IP + TIME WINDOW
# ─────────────────────────────────────────────

def group_alerts_by_ip_window(alerts: list[dict]) -> list[list[dict]]:
    """
    Group alerts that share a source_ip and fall within
    CORRELATION_WINDOW_MIN of each other.
    Returns a list of alert groups (each group = one potential incident).
    """
    by_ip = defaultdict(list)
    for a in alerts:
        ip = a.get("source_ip")
        if ip:
            by_ip[ip].append(a)

    groups = []

    for ip, ip_alerts in by_ip.items():
        # Sort by first_seen, fall back to created_at if missing
        def get_ts(a):
            ts = a.get("first_seen") or a.get("created_at")
            try:
                return datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                return datetime.min

        ip_alerts.sort(key=get_ts)

        current_group = [ip_alerts[0]]
        last_ts = get_ts(ip_alerts[0])

        for alert in ip_alerts[1:]:
            ts = get_ts(alert)
            if (ts - last_ts).total_seconds() <= CORRELATION_WINDOW_MIN * 60:
                current_group.append(alert)
            else:
                if len(current_group) >= MIN_ALERTS_TO_CORRELATE:
                    groups.append(current_group)
                current_group = [alert]
            last_ts = ts

        if len(current_group) >= MIN_ALERTS_TO_CORRELATE:
            groups.append(current_group)

    return groups


# ─────────────────────────────────────────────
#  ANALYZE A GROUP — BUILD INCIDENT
# ─────────────────────────────────────────────

def analyze_kill_chain(group: list[dict]) -> dict:
    """
    Look at the stages represented in a group of alerts.
    Returns info about whether this looks like a real attack progression.
    """
    stages_seen = set()
    for alert in group:
        stage = KILL_CHAIN_STAGES.get(alert.get("alert_type", ""))
        if stage:
            stages_seen.add(stage)

    is_progression = len(stages_seen) >= 2
    is_full_chain  = stages_seen == {1, 2, 3, 4} or (
        len(stages_seen) >= 3 and max(stages_seen) >= 3
    )

    stage_names = {
        1: "Reconnaissance",
        2: "Credential Access",
        3: "Initial Access",
        4: "Privilege Escalation",
    }
    stage_labels = [stage_names[s] for s in sorted(stages_seen)]

    return {
        "stages_seen":    stages_seen,
        "is_progression": is_progression,
        "is_full_chain":  is_full_chain,
        "stage_labels":   stage_labels,
    }


def calculate_incident_severity(group: list[dict], kill_chain: dict) -> str:
    """
    Determine incident severity based on:
    - highest individual alert severity
    - number of distinct log sources involved
    - whether it forms a recognizable kill chain
    """
    max_severity_rank = max(
        SEVERITY_RANK.get(a.get("severity", "LOW"), 1) for a in group
    )

    distinct_sources = len(set(get_log_type_for_alert(a) for a in group))

    # Base severity from worst individual alert
    severity = max_severity_rank

    # Boost for multi-source correlation
    if distinct_sources >= MIN_SOURCES_FOR_BOOST:
        severity += 1

    # Boost for recognizable kill chain progression
    if kill_chain["is_full_chain"]:
        severity += 1
    elif kill_chain["is_progression"]:
        severity += 0  # already counted via distinct_sources typically

    severity = min(severity, 4)  # cap at CRITICAL

    rank_to_name = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    return rank_to_name[severity]


def build_incident(group: list[dict]) -> dict:
    """Combine a group of correlated alerts into one incident dict."""
    ip = group[0]["source_ip"]
    kill_chain = analyze_kill_chain(group)
    severity   = calculate_incident_severity(group, kill_chain)

    def get_ts(a):
        ts = a.get("first_seen") or a.get("created_at")
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return datetime.now()

    timestamps = [get_ts(a) for a in group]
    first_seen = min(timestamps).isoformat()
    last_seen  = max(timestamps).isoformat()

    distinct_sources = sorted(set(get_log_type_for_alert(a) for a in group))
    alert_types       = [a.get("alert_type", "") for a in group]
    attack_ids        = sorted(set(a.get("attack_id", "") for a in group if a.get("attack_id")))
    attack_names      = sorted(set(a.get("attack_name", "") for a in group if a.get("attack_name")))

    if kill_chain["is_full_chain"]:
        narrative = (
            f"Full attack chain detected from {ip}: "
            f"{' → '.join(kill_chain['stage_labels'])}. "
            f"{len(group)} alerts across {len(distinct_sources)} log sources "
            f"({', '.join(distinct_sources)})."
        )
    elif kill_chain["is_progression"]:
        narrative = (
            f"Multi-stage activity from {ip}: "
            f"{' + '.join(kill_chain['stage_labels'])}. "
            f"{len(group)} correlated alerts across {len(distinct_sources)} sources."
        )
    else:
        narrative = (
            f"{len(group)} related alerts from {ip} within {CORRELATION_WINDOW_MIN} min "
            f"across {len(distinct_sources)} source(s): {', '.join(distinct_sources)}."
        )

    timeline = []
    for a in sorted(group, key=get_ts):
        timeline.append({
            "timestamp":  a.get("first_seen") or a.get("created_at"),
            "alert_type": a.get("alert_type"),
            "severity":   a.get("severity"),
            "log_source": get_log_type_for_alert(a),
            "description": a.get("description"),
            "alert_id":   a.get("id"),
        })

    return {
        "created_at":       datetime.now().isoformat(),
        "incident_type":    "correlated_attack",
        "severity":         severity,
        "confidence":       "HIGH" if kill_chain["is_progression"] else "MEDIUM",
        "source_ip":        ip,
        "first_seen":       first_seen,
        "last_seen":        last_seen,
        "alert_count":      len(group),
        "alert_ids":        [a.get("id") for a in group],
        "distinct_sources": distinct_sources,
        "alert_types":      alert_types,
        "attack_ids":       attack_ids,
        "attack_names":     attack_names,
        "kill_chain_stages":kill_chain["stage_labels"],
        "is_full_chain":    kill_chain["is_full_chain"],
        "narrative":        narrative,
        "timeline":         timeline,
        "remediation":      build_incident_remediation(ip, kill_chain, distinct_sources),
        "status":           "open",
    }


def build_incident_remediation(ip: str, kill_chain: dict, sources: list[str]) -> str:
    steps = [f"1. IMMEDIATE: Block {ip} at perimeter firewall and WAF"]

    if kill_chain["is_full_chain"]:
        steps.append("2. CRITICAL: Full attack chain observed — assume compromise")
        steps.append("3. Isolate affected hosts from network immediately")
        steps.append("4. Begin incident response procedure")
        steps.append("5. Preserve logs and memory dumps for forensics")
    else:
        steps.append("2. Investigate all correlated alerts for this IP")
        steps.append("3. Check if any stage succeeded (not just attempted)")

    if "syslog" in sources:
        steps.append(f"{len(steps)+1}. Audit all auth.log activity from {ip}")
    if "firewall" in sources:
        steps.append(f"{len(steps)+1}. Review firewall rules — was traffic actually blocked?")
    if "apache" in sources:
        steps.append(f"{len(steps)+1}. Check web server access logs for successful exploitation")
    if "mobile" in sources:
        steps.append(f"{len(steps)+1}. Audit affected mobile devices for compromise indicators")

    steps.append(f"{len(steps)+1}. Add {ip} to threat intelligence blocklist")
    return "\n".join(steps)


# ─────────────────────────────────────────────
#  STORE INCIDENTS — needs a new table
# ─────────────────────────────────────────────

def init_incidents_table():
    """Create the incidents table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at         TEXT,
            incident_type      TEXT,
            severity           TEXT,
            confidence         TEXT,
            source_ip          TEXT,
            first_seen         TEXT,
            last_seen          TEXT,
            alert_count        INTEGER,
            alert_ids          TEXT,
            distinct_sources   TEXT,
            alert_types        TEXT,
            attack_ids         TEXT,
            attack_names       TEXT,
            kill_chain_stages  TEXT,
            is_full_chain      INTEGER,
            narrative          TEXT,
            timeline           TEXT,
            remediation        TEXT,
            status             TEXT DEFAULT 'open'
        )
    """)
    conn.commit()
    conn.close()


def insert_incident(incident: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO incidents
        (created_at, incident_type, severity, confidence, source_ip,
         first_seen, last_seen, alert_count, alert_ids, distinct_sources,
         alert_types, attack_ids, attack_names, kill_chain_stages,
         is_full_chain, narrative, timeline, remediation, status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        incident["created_at"], incident["incident_type"], incident["severity"],
        incident["confidence"], incident["source_ip"], incident["first_seen"],
        incident["last_seen"], incident["alert_count"],
        json.dumps(incident["alert_ids"]), json.dumps(incident["distinct_sources"]),
        json.dumps(incident["alert_types"]), json.dumps(incident["attack_ids"]),
        json.dumps(incident["attack_names"]), json.dumps(incident["kill_chain_stages"]),
        int(incident["is_full_chain"]), incident["narrative"],
        json.dumps(incident["timeline"]), incident["remediation"], incident["status"],
    ))
    conn.commit()
    conn.close()


def get_incidents() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

    incidents = []
    for r in rows:
        d = dict(r)
        for field in ("alert_ids", "distinct_sources", "alert_types",
                      "attack_ids", "attack_names", "kill_chain_stages", "timeline"):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                d[field] = []
        incidents.append(d)
    return incidents


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def correlate_alerts() -> list[dict]:
    """
    Main correlation function. Fetches all alerts, groups by IP + time,
    builds incidents for qualifying groups, stores and returns them.
    """
    init_incidents_table()

    alerts = fetch_all_alerts()

    if len(alerts) < MIN_ALERTS_TO_CORRELATE:
        print(f"[correlator] Not enough alerts to correlate ({len(alerts)} found).")
        return []

    print(f"[correlator] Analyzing {len(alerts)} alerts for correlation...")

    groups = group_alerts_by_ip_window(alerts)

    if not groups:
        print("[correlator] No correlated groups found.")
        return []

    incidents = []
    for group in groups:
        incident = build_incident(group)
        incidents.append(incident)
        insert_incident(incident)

        chain_tag = " [FULL KILL CHAIN]" if incident["is_full_chain"] else ""
        print(
            f"  [INCIDENT] {incident['severity']}{chain_tag} — {incident['source_ip']} — "
            f"{incident['alert_count']} alerts across {len(incident['distinct_sources'])} sources"
        )

    print(f"[correlator] {len(incidents)} incident(s) created.")
    return incidents


# ─────────────────────────────────────────────
#  SELF TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from database.storage import init_db, insert_alert, clear_all

    init_db()
    clear_all()
    init_incidents_table()

    # Wipe incidents table too for clean test
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()

    attacker_ip = "203.0.113.45"
    base = datetime(2025, 6, 27, 10, 0, 0)

    # Simulate a full kill chain: recon -> brute force -> web exploit -> priv esc
    fake_alerts = [
        {  # Stage 1: Reconnaissance (firewall)
            "created_at": base.isoformat(), "alert_type": "port_scan",
            "severity": "HIGH", "confidence": "HIGH", "source_ip": attacker_ip,
            "target_host": "firewall", "target_user": "", "event_count": 18,
            "window_secs": 60, "first_seen": base.isoformat(),
            "last_seen": (base + timedelta(seconds=30)).isoformat(),
            "description": f"Port scan: {attacker_ip} probed 18 ports",
            "attack_id": "T1046", "attack_name": "Network Service Discovery",
            "attack_tactic": "Discovery", "raw_events": [], "remediation": "Block IP",
            "status": "open",
        },
        {  # Stage 2: Credential Access (syslog) - 5 min later
            "created_at": (base + timedelta(minutes=5)).isoformat(), "alert_type": "brute_force",
            "severity": "HIGH", "confidence": "HIGH", "source_ip": attacker_ip,
            "target_host": "kali-system", "target_user": "root", "event_count": 7,
            "window_secs": 60, "first_seen": (base + timedelta(minutes=5)).isoformat(),
            "last_seen": (base + timedelta(minutes=5, seconds=45)).isoformat(),
            "description": f"Brute force: {attacker_ip} made 7 attempts",
            "attack_id": "T1110.001", "attack_name": "Brute Force: Password Guessing",
            "attack_tactic": "Credential Access", "raw_events": [], "remediation": "Block IP",
            "status": "open",
        },
        {  # Stage 3: Initial Access (apache) - 12 min later
            "created_at": (base + timedelta(minutes=12)).isoformat(), "alert_type": "web_attack",
            "severity": "CRITICAL", "confidence": "HIGH", "source_ip": attacker_ip,
            "target_host": "webserver", "target_user": "", "event_count": 1,
            "window_secs": 0, "first_seen": (base + timedelta(minutes=12)).isoformat(),
            "last_seen": (base + timedelta(minutes=12)).isoformat(),
            "description": f"SQL injection attempt from {attacker_ip}",
            "attack_id": "T1190", "attack_name": "Exploit Public-Facing Application",
            "attack_tactic": "Initial Access", "raw_events": [], "remediation": "Block IP",
            "status": "open",
        },
        {  # Stage 4: Privilege Escalation (syslog) - 18 min later
            "created_at": (base + timedelta(minutes=18)).isoformat(), "alert_type": "priv_escalation",
            "severity": "CRITICAL", "confidence": "HIGH", "source_ip": attacker_ip,
            "target_host": "kali-system", "target_user": "root", "event_count": 1,
            "window_secs": 0, "first_seen": (base + timedelta(minutes=18)).isoformat(),
            "last_seen": (base + timedelta(minutes=18)).isoformat(),
            "description": f"Privilege escalation via sudo from session linked to {attacker_ip}",
            "attack_id": "T1548.003", "attack_name": "Abuse Elevation Control",
            "attack_tactic": "Privilege Escalation", "raw_events": [], "remediation": "Investigate",
            "status": "open",
        },
        # Unrelated alert from a different IP — should NOT correlate
        {
            "created_at": base.isoformat(), "alert_type": "suspicious_login",
            "severity": "MEDIUM", "confidence": "LOW", "source_ip": "192.168.1.50",
            "target_host": "kali-system", "target_user": "bob", "event_count": 1,
            "window_secs": 0, "first_seen": base.isoformat(), "last_seen": base.isoformat(),
            "description": "Off-hours login from known IP",
            "attack_id": "T1078", "attack_name": "Valid Accounts",
            "attack_tactic": "Defense Evasion", "raw_events": [], "remediation": "Verify",
            "status": "open",
        },
    ]

    for a in fake_alerts:
        insert_alert(a)

    print("=" * 60)
    print("CORRELATION TEST")
    print("=" * 60)

    incidents = correlate_alerts()

    print(f"\n=== {len(incidents)} INCIDENT(S) ===")
    for inc in get_incidents():
        print(f"""
  ┌─ INCIDENT #{inc['id']} ──────────────────────────────
  │  Severity     : {inc['severity']}
  │  Source IP    : {inc['source_ip']}
  │  Alert count  : {inc['alert_count']}
  │  Sources      : {', '.join(inc['distinct_sources'])}
  │  Kill chain   : {' -> '.join(inc['kill_chain_stages'])}
  │  Full chain   : {bool(inc['is_full_chain'])}
  │  Narrative    : {inc['narrative']}
  └────────────────────────────────────────────""")
        print("  Timeline:")
        for event in inc["timeline"]:
            print(f"    {event['timestamp']} [{event['log_source']:8s}] {event['description'][:60]}")