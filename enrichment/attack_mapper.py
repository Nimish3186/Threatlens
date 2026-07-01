"""
ATT&CK mapper for ThreatLens.

Provides a curated local lookup table covering every technique ThreatLens
detectors map to, plus helper functions to enrich alert dicts with full
tactic/technique metadata. No internet access required at runtime.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ─────────────────────────────────────────────
#  ATT&CK TECHNIQUE LOOKUP TABLE
#  Covers every technique used across all ThreatLens detectors.
#  Source: https://attack.mitre.org  (Enterprise ATT&CK, accurate as of v15)
# ─────────────────────────────────────────────

ATTACK_TECHNIQUES = {

    "T1110": {
        "name":        "Brute Force",
        "tactic":      "Credential Access",
        "tactic_id":   "TA0006",
        "description": "Adversaries use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "url":         "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.001": {
        "name":        "Brute Force: Password Guessing",
        "tactic":      "Credential Access",
        "tactic_id":   "TA0006",
        "description": "Adversaries use a single or small list of commonly used passwords against many different accounts.",
        "url":         "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1110.003": {
        "name":        "Brute Force: Password Spraying",
        "tactic":      "Credential Access",
        "tactic_id":   "TA0006",
        "description": "Adversaries use a single or small list of passwords against many different accounts to avoid account lockouts.",
        "url":         "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1548": {
        "name":        "Abuse Elevation Control Mechanism",
        "tactic":      "Privilege Escalation",
        "tactic_id":   "TA0004",
        "description": "Adversaries circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.",
        "url":         "https://attack.mitre.org/techniques/T1548/",
    },
    "T1548.003": {
        "name":        "Abuse Elevation Control: Sudo and Sudo Caching",
        "tactic":      "Privilege Escalation",
        "tactic_id":   "TA0004",
        "description": "Adversaries may perform sudo caching and/or use the suoders file to elevate privileges.",
        "url":         "https://attack.mitre.org/techniques/T1548/003/",
    },
    "T1078": {
        "name":        "Valid Accounts",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Adversaries obtain and abuse credentials of existing accounts as a means of gaining access.",
        "url":         "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.003": {
        "name":        "Valid Accounts: Local Accounts",
        "tactic":      "Privilege Escalation",
        "tactic_id":   "TA0004",
        "description": "Adversaries obtain and abuse credentials of a local account, such as direct root login.",
        "url":         "https://attack.mitre.org/techniques/T1078/003/",
    },
    "T1222": {
        "name":        "File and Directory Permissions Modification",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Adversaries modify file or directory permissions/attributes to evade access control lists.",
        "url":         "https://attack.mitre.org/techniques/T1222/",
    },
    "T1222.002": {
        "name":        "File and Directory Permissions Modification: Linux and Mac",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Adversaries modify file/directory permissions on Linux/macOS, e.g. chmod 777 on sensitive files.",
        "url":         "https://attack.mitre.org/techniques/T1222/002/",
    },
    "T1136": {
        "name":        "Create Account",
        "tactic":      "Persistence",
        "tactic_id":   "TA0003",
        "description": "Adversaries create an account to maintain access to victim systems.",
        "url":         "https://attack.mitre.org/techniques/T1136/",
    },
    "T1136.001": {
        "name":        "Create Account: Local Account",
        "tactic":      "Persistence",
        "tactic_id":   "TA0003",
        "description": "Adversaries create a local account to maintain access using built-in tools like useradd.",
        "url":         "https://attack.mitre.org/techniques/T1136/001/",
    },
    "T1190": {
        "name":        "Exploit Public-Facing Application",
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "description": "Adversaries exploit weaknesses in internet-facing applications such as SQL injection or command injection.",
        "url":         "https://attack.mitre.org/techniques/T1190/",
    },
    "T1083": {
        "name":        "File and Directory Discovery",
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "description": "Adversaries enumerate files and directories, e.g. via path traversal attacks against web servers.",
        "url":         "https://attack.mitre.org/techniques/T1083/",
    },
    "T1046": {
        "name":        "Network Service Discovery",
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "description": "Adversaries attempt to get a listing of services running on remote hosts, including port scans.",
        "url":         "https://attack.mitre.org/techniques/T1046/",
    },
    "T1595": {
        "name":        "Active Scanning",
        "tactic":      "Reconnaissance",
        "tactic_id":   "TA0043",
        "description": "Adversaries execute active reconnaissance scans to gather information for targeting purposes.",
        "url":         "https://attack.mitre.org/techniques/T1595/",
    },
    "T1595.002": {
        "name":        "Active Scanning: Vulnerability Scanning",
        "tactic":      "Reconnaissance",
        "tactic_id":   "TA0043",
        "description": "Adversaries scan victim infrastructure for vulnerabilities by probing exposed services and paths.",
        "url":         "https://attack.mitre.org/techniques/T1595/002/",
    },
    "T1068": {
        "name":        "Exploitation for Privilege Escalation",
        "tactic":      "Privilege Escalation",
        "tactic_id":   "TA0004",
        "description": "Adversaries exploit software vulnerabilities to elevate privileges, e.g. rooting/jailbreaking a mobile device.",
        "url":         "https://attack.mitre.org/techniques/T1068/",
    },
    "T1476": {
        "name":        "Deliver Malicious App via Other Means",
        "tactic":      "Initial Access",
        "tactic_id":   "TA0027",
        "description": "Adversaries install malicious applications on mobile devices outside of official app stores.",
        "url":         "https://attack.mitre.org/techniques/T1476/",
    },
    "T1562": {
        "name":        "Impair Defenses",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Adversaries disable or modify security tools to avoid detection.",
        "url":         "https://attack.mitre.org/techniques/T1562/",
    },
    "T1562.001": {
        "name":        "Impair Defenses: Disable or Modify Tools",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Adversaries disable security tools, such as bypassing SELinux/sandbox restrictions.",
        "url":         "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1430": {
        "name":        "Location Tracking",
        "tactic":      "Collection",
        "tactic_id":   "TA0035",
        "description": "Adversaries gather information about a mobile device's location without authorization.",
        "url":         "https://attack.mitre.org/techniques/T1430/",
    },
    "T1557": {
        "name":        "Adversary-in-the-Middle",
        "tactic":      "Collection",
        "tactic_id":   "TA0035",
        "description": "Adversaries position themselves between two devices to collect or manipulate traffic, e.g. SSL/TLS interception.",
        "url":         "https://attack.mitre.org/techniques/T1557/",
    },
    "T1429": {
        "name":        "Capture Audio",
        "tactic":      "Collection",
        "tactic_id":   "TA0035",
        "description": "Adversaries capture audio via a device's microphone without authorization.",
        "url":         "https://attack.mitre.org/techniques/T1429/",
    },
    "T1499": {
        "name":        "Endpoint Denial of Service",
        "tactic":      "Impact",
        "tactic_id":   "TA0034",
        "description": "Adversaries perform actions that degrade availability of a service or system, e.g. crash loops.",
        "url":         "https://attack.mitre.org/techniques/T1499/",
    },
}


# ─────────────────────────────────────────────
#  TACTIC ORDERING — for kill chain display
#  Matches the standard ATT&CK Enterprise kill chain order
# ─────────────────────────────────────────────

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


# ─────────────────────────────────────────────
#  CORE LOOKUP FUNCTIONS
# ─────────────────────────────────────────────

def get_technique(attack_id: str) -> dict | None:
    """
    Look up full metadata for a technique ID.
    Returns None if not in our local table.
    """
    return ATTACK_TECHNIQUES.get(attack_id)


def get_tactic_order(tactic_name: str) -> int:
    """Return the kill-chain position of a tactic (0 = earliest)."""
    try:
        return TACTIC_ORDER.index(tactic_name)
    except ValueError:
        return 999   # unknown tactics sort last


def enrich_alert_with_attack(alert: dict) -> dict:
    """
    Take an alert dict that already has an attack_id set by a detector,
    and fill in / correct attack_name, attack_tactic, and add attack_url
    and attack_description from the canonical lookup table.

    This guarantees consistency even if a detector's hardcoded name
    drifts from the official MITRE wording.
    """
    attack_id = alert.get("attack_id")
    if not attack_id:
        return alert

    technique = get_technique(attack_id)
    if not technique:
        # Unknown technique ID — leave alert as-is but flag it
        alert.setdefault("attack_url", "")
        alert.setdefault("attack_description", "Technique not in local ATT&CK database.")
        return alert

    alert["attack_name"]        = technique["name"]
    alert["attack_tactic"]      = technique["tactic"]
    alert["attack_tactic_id"]   = technique["tactic_id"]
    alert["attack_url"]         = technique["url"]
    alert["attack_description"] = technique["description"]

    return alert


def enrich_alerts_batch(alerts: list[dict]) -> list[dict]:
    """Enrich a list of alerts in place. Convenience wrapper."""
    return [enrich_alert_with_attack(a) for a in alerts]


# ─────────────────────────────────────────────
#  TACTIC / TECHNIQUE SUMMARY — for dashboard widgets
# ─────────────────────────────────────────────

def summarize_attack_coverage(alerts: list[dict]) -> dict:
    """
    Given a list of alerts, return a summary of which tactics and
    techniques are represented — useful for an ATT&CK matrix view
    on the dashboard.
    """
    tactics_seen    = {}
    techniques_seen = {}

    for alert in alerts:
        attack_id = alert.get("attack_id")
        if not attack_id:
            continue

        technique = get_technique(attack_id) or {
            "name": alert.get("attack_name", attack_id),
            "tactic": alert.get("attack_tactic", "Unknown"),
        }

        tactic = technique["tactic"]
        tactics_seen[tactic] = tactics_seen.get(tactic, 0) + 1

        key = attack_id
        if key not in techniques_seen:
            techniques_seen[key] = {
                "id":    attack_id,
                "name":  technique["name"],
                "tactic":tactic,
                "count": 0,
            }
        techniques_seen[key]["count"] += 1

    # Sort tactics by kill-chain order for display
    sorted_tactics = sorted(
        tactics_seen.items(),
        key=lambda kv: get_tactic_order(kv[0])
    )

    return {
        "tactics":             dict(sorted_tactics),
        "techniques":          list(techniques_seen.values()),
        "total_techniques":    len(techniques_seen),
        "total_tactics":       len(tactics_seen),
    }


def build_kill_chain_sequence(alerts: list[dict]) -> list[dict]:
    """
    Given alerts (ideally for one IP/incident), return them ordered
    by ATT&CK kill-chain position rather than just timestamp —
    useful for visualizing the attacker's progression logically.
    """
    enriched = []
    for alert in alerts:
        tactic = alert.get("attack_tactic", "Unknown")
        enriched.append({
            "tactic":       tactic,
            "tactic_order": get_tactic_order(tactic),
            "attack_id":    alert.get("attack_id"),
            "attack_name":  alert.get("attack_name"),
            "timestamp":    alert.get("first_seen") or alert.get("created_at"),
            "description":  alert.get("description"),
        })

    return sorted(enriched, key=lambda x: x["tactic_order"])


# ─────────────────────────────────────────────
#  VALIDATION — run this to check all detector IDs are covered
# ─────────────────────────────────────────────

def validate_detector_coverage():
    """
    Sanity check: every attack_id your detectors hardcode should
    exist in this lookup table. Run this after adding a new detector.
    """
    detector_ids = {
        "T1110", "T1110.001", "T1110.003",
        "T1548.003", "T1078.003", "T1078",
        "T1222.002", "T1136.001",
        "T1190", "T1083", "T1046",
        "T1595", "T1595.002",
        "T1068", "T1476", "T1562.001",
        "T1430", "T1557", "T1429", "T1499",
    }

    missing = detector_ids - set(ATTACK_TECHNIQUES.keys())
    if missing:
        print(f"[attack_mapper] WARNING: {len(missing)} technique IDs used by detectors "
              f"are missing from the lookup table: {missing}")
    else:
        print(f"[attack_mapper] OK — all {len(detector_ids)} detector technique IDs are covered.")

    return missing


# ─────────────────────────────────────────────
#  SELF TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("ATT&CK MAPPER SELF TEST")
    print("=" * 60)

    validate_detector_coverage()

    print("\n--- Single lookup ---")
    t = get_technique("T1110.001")
    print(f"  T1110.001 -> {t['name']} ({t['tactic']})")
    print(f"  {t['description']}")

    print("\n--- Enrichment test ---")
    fake_alert = {
        "alert_type": "brute_force",
        "attack_id":  "T1110.001",
        "attack_name": "wrong name placeholder",   # will be corrected
        "attack_tactic": "",                         # will be filled in
    }
    enriched = enrich_alert_with_attack(fake_alert)
    print(f"  Before: wrong name placeholder")
    print(f"  After : {enriched['attack_name']} | {enriched['attack_tactic']}")
    print(f"  URL   : {enriched['attack_url']}")

    print("\n--- Coverage summary test ---")
    fake_alerts = [
        {"attack_id": "T1046",     "attack_name": "Network Service Discovery"},
        {"attack_id": "T1110.001","attack_name": "Brute Force"},
        {"attack_id": "T1110.001","attack_name": "Brute Force"},
        {"attack_id": "T1190",    "attack_name": "Exploit Public-Facing App"},
        {"attack_id": "T1548.003","attack_name": "Sudo Abuse"},
    ]
    summary = summarize_attack_coverage(fake_alerts)
    print(f"  Tactics represented   : {list(summary['tactics'].keys())}")
    print(f"  Total techniques      : {summary['total_techniques']}")
    for tech in summary["techniques"]:
        print(f"    {tech['id']:12s} {tech['name']:35s} x{tech['count']}")

    print("\n--- Kill chain ordering test ---")
    full_alerts = [
        {"attack_tactic": "Privilege Escalation", "attack_id": "T1548.003",
         "attack_name": "Sudo Abuse", "first_seen": "2025-06-27T10:18:00", "description": "sudo to root"},
        {"attack_tactic": "Reconnaissance", "attack_id": "T1046",
         "attack_name": "Network Service Discovery", "first_seen": "2025-06-27T10:00:00", "description": "port scan"},
        {"attack_tactic": "Initial Access", "attack_id": "T1190",
         "attack_name": "Exploit Public-Facing App", "first_seen": "2025-06-27T10:12:00", "description": "sql injection"},
        {"attack_tactic": "Credential Access", "attack_id": "T1110.001",
         "attack_name": "Brute Force", "first_seen": "2025-06-27T10:05:00", "description": "ssh brute force"},
    ]
    ordered = build_kill_chain_sequence(full_alerts)
    print("  Kill chain order (by tactic, not timestamp):")
    for step in ordered:
        print(f"    [{step['tactic_order']}] {step['tactic']:22s} — {step['description']}")