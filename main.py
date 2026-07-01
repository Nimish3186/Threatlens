import sys
import os

# Always resolve imports from project root
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from database.storage import init_db, insert_events, insert_alert, get_alerts, get_summary, clear_all
from parsers.linux_parser import parse_log_file
from detectors.brute_force import detect_brute_force
from detectors.priv_escalation import detect_priv_escalation
from detectors.suspicious_login import detect_suspicious_logins
from parsers.mobile_parser import parse_mobile_log_file, detect_mobile_threats
from parsers.firewall_parser import parse_firewall_log_file, detect_firewall_threats
from enrichment.ioc_enricher import enrich_alert_ips
from correlator.engine import correlate_alerts, get_incidents
from enrichment.attack_mapper import enrich_alerts_batch, validate_detector_coverage

def safe_str(s):
    if not isinstance(s, str):
        return str(s)
    # Replace common unicode characters with ASCII equivalents
    replacements = {
        "\u2192": " -> ",
        "\u2014": " - ",
        "\u2013": " - ",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2713": "[OK]",
        "\u274c": "[FAIL]",
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    return s.encode("ascii", "replace").decode("ascii")


# =============================================================
#  STEP 1 — Initialize the database
# =============================================================

def step1_init(wipe_db=False):
    print("\n" + "="*50)
    print("STEP 1 — Initializing database")
    print("="*50)
    init_db()
    if wipe_db:
        clear_all()
        print("[db] Database wiped for clean run")
    print("[OK] Database ready")


# =============================================================
#  STEP 2 — Parse log files (Linux, Mobile, Firewall)
# =============================================================

def step2_parse():
    print("\n" + "="*50)
    print("STEP 2 — Parsing log files")
    print("="*50)

    total = 0

    # 1. Linux/syslog log files
    linux_files = [
        ("samples/auth.log",   "syslog"),
        ("samples/linux.log",  "syslog"),
        ("samples/auth.txt",   "syslog"),
        ("samples/sudo.log",   "syslog"),
    ]
    for filepath, log_type in linux_files:
        if not os.path.exists(filepath):
            print(f"  [skip] {filepath} not found")
            continue
        try:
            events = parse_log_file(filepath, log_type=log_type)
            if events:
                insert_events(events)
                total += len(events)
                print(f"  [OK] {filepath} -> {len(events)} events parsed & stored")
        except Exception as e:
            print(f"  [error] {filepath} -> {e}")

    # 2. Mobile log files
    mobile_files = [
        ("samples/android.log", "android"),
        ("samples/ios.log", "ios")
    ]
    for filepath, log_type in mobile_files:
        if not os.path.exists(filepath):
            print(f"  [skip] {filepath} not found")
            continue
        try:
            events = parse_mobile_log_file(filepath, log_type)
            if events:
                insert_events(events)
                total += len(events)
                print(f"  [OK] {filepath} -> {len(events)} events parsed & stored")
        except Exception as e:
            print(f"  [error] {filepath} -> {e}")

    # 3. Firewall log files
    fw_files = [
        ("samples/firewall.log", "auto")
    ]
    for filepath, vendor in fw_files:
        if not os.path.exists(filepath):
            print(f"  [skip] {filepath} not found")
            continue
        try:
            events = parse_firewall_log_file(filepath, vendor=vendor)
            if events:
                insert_events(events)
                total += len(events)
                print(f"  [OK] {filepath} -> {len(events)} events parsed & stored")
        except Exception as e:
            print(f"  [error] {filepath} -> {e}")

    print(f"\n  Total events inserted: {total}")
    return total


# =============================================================
#  STEP 3 — Run detectors and collect alerts
# =============================================================

def step3_detect():
    print("\n" + "="*50)
    print("STEP 3 — Running detectors")
    print("="*50)

    all_alerts = []

    # 1. Syslog Brute Force
    try:
        print("[*] Running brute force detector...")
        bf_alerts = detect_brute_force()
        all_alerts.extend(bf_alerts)
    except Exception as e:
        print(f"  [error] Brute force detector failed -> {e}")

    # 2. Syslog Privilege Escalation
    try:
        print("[*] Running privilege escalation detector...")
        priv_alerts = detect_priv_escalation()
        all_alerts.extend(priv_alerts)
    except Exception as e:
        print(f"  [error] Privilege escalation detector failed -> {e}")

    # 3. Syslog Suspicious Login
    try:
        print("[*] Running suspicious login detector...")
        susp_alerts = detect_suspicious_logins()
        all_alerts.extend(susp_alerts)
    except Exception as e:
        print(f"  [error] Suspicious login detector failed -> {e}")

    # 4. Mobile Threat Detection (requires parsed mobile events from DB)
    try:
        print("[*] Running mobile threat detector...")
        # Get android & ios events
        from database.storage import get_events
        events = get_events(limit=1000)
        mobile_events = [e for e in events if e.get("log_type") in ("android", "ios")]
        if mobile_events:
            mob_alerts = detect_mobile_threats(mobile_events)
            all_alerts.extend(mob_alerts)
        else:
            print("  [skip] No mobile events found in DB to analyze.")
    except Exception as e:
        print(f"  [error] Mobile threat detector failed -> {e}")

    # 5. Firewall Threat Detection (requires parsed firewall events from DB)
    try:
        print("[*] Running firewall threat detector...")
        from database.storage import get_events
        events = get_events(limit=1000)
        fw_events = [e for e in events if e.get("log_type") == "firewall"]
        if fw_events:
            fw_alerts = detect_firewall_threats(fw_events)
            all_alerts.extend(fw_alerts)
        else:
            print("  [skip] No firewall events found in DB to analyze.")
    except Exception as e:
        print(f"  [error] Firewall threat detector failed -> {e}")

    print(f"\n  Total raw alerts generated: {len(all_alerts)}")
    return all_alerts


# =============================================================
#  STEP 4 — Enrich and Map ATT&CK Tactics
# =============================================================

def step4_enrich_and_map(alerts):
    print("\n" + "="*50)
    print("STEP 4 — Enrichment & MITRE ATT&CK Mapping")
    print("="*50)

    if not alerts:
        print("  No alerts to enrich.")
        return []

    # 1. IP Reputation Enrichment
    try:
        print("[*] Enriching alert IPs via AbuseIPDB reputation...")
        alerts = enrich_alert_ips(alerts)
    except Exception as e:
        print(f"  [error] IP enrichment failed -> {e}")

    # 2. ATT&CK Tactic/Technique Mapping
    try:
        print("[*] Mapping alerts to MITRE ATT&CK database...")
        validate_detector_coverage()
        alerts = enrich_alerts_batch(alerts)
    except Exception as e:
        print(f"  [error] ATT&CK mapping failed -> {e}")

    # Store all enriched alerts in the database
    for alert in alerts:
        insert_alert(alert)

    print(f"  [OK] Enriched and stored {len(alerts)} alerts in database.")
    return alerts


# =============================================================
#  STEP 5 — Correlate Alerts into Incidents
# =============================================================

def step5_correlate():
    print("\n" + "="*50)
    print("STEP 5 — Correlation Engine")
    print("="*50)

    try:
        print("[*] Running cross-log correlator...")
        incidents = correlate_alerts()
        return incidents
    except Exception as e:
        print(f"  [error] Correlation engine failed -> {e}")
        return []


# =============================================================
#  STEP 6 — Summary Report
# =============================================================

def step6_summary():
    print("\n" + "="*50)
    print("STEP 6 — Database Summary Report")
    print("="*50)

    summary = get_summary()
    print(f"  Total events  : {summary['total_events']}")
    print(f"  Total alerts  : {summary['total_alerts']}")
    print(f"  Open alerts   : {summary['open_alerts']}")
    print(f"  By severity   : {summary['severity_breakdown']}")
    print(f"  By type       : {summary['type_breakdown']}")


# =============================================================
#  STEP 7 — Print Detailed Alerts and Incidents
# =============================================================

def step7_print_details():
    print("\n" + "="*50)
    print("STEP 7 — Detailed Alert and Incident Log")
    print("="*50)

    alerts = get_alerts()
    if not alerts:
        print("  No alerts found in database.")
    else:
        print(f"\n--- Stored Alerts ({len(alerts)}) ---")
        for a in alerts:
            print(f"""
  +-- ALERT #{a['id']} ----------------------------------------
  |  Type        : {safe_str(a['alert_type'])}
  |  Severity    : {safe_str(a['severity'])}  |  Confidence: {safe_str(a['confidence'])}
  |  Attacker IP : {safe_str(a['source_ip'])}
  |  Target      : {safe_str(a['target_user'])}@{safe_str(a['target_host'])}
  |  Hits        : {a['event_count']} attempts in {a['window_secs']}s
  |  First seen  : {safe_str(a['first_seen'])}
  |  Last seen   : {safe_str(a['last_seen'])}
  |  ATT&CK      : {safe_str(a['attack_id'])} - {safe_str(a['attack_name'])}
  |  Tactic      : {safe_str(a['attack_tactic'])}
  |  Status      : {safe_str(a['status'])}
  |  Description : {safe_str(a['description'])}
  +------------------------------------------------------------""")

            print("  Remediation steps:")
            if a.get("remediation"):
                for line in a["remediation"].split("\n"):
                    print(f"    {safe_str(line)}")

    incidents = get_incidents()
    if not incidents:
        print("\n  No correlated incidents found in database.")
    else:
        print(f"\n--- Correlated Incidents ({len(incidents)}) ---")
        for inc in incidents:
            print(f"""
  +-- INCIDENT #{inc['id']} ------------------------------------
  |  Severity     : {safe_str(inc['severity'])}
  |  Source IP    : {safe_str(inc['source_ip'])}
  |  Alert count  : {inc['alert_count']}
  |  Sources      : {', '.join(inc['distinct_sources'])}
  |  Kill chain   : {safe_str(' -> '.join(inc['kill_chain_stages']))}
  |  Full chain   : {bool(inc['is_full_chain'])}
  |  Narrative    : {safe_str(inc['narrative'])}
  +------------------------------------------------------------""")
            print("  Timeline:")
            for event in inc["timeline"]:
                print(f"    {safe_str(event['timestamp'])} [{safe_str(event['log_source']):8s}] {safe_str(event['description'][:60])}")
            print("  Response Remediation:")
            if inc.get("remediation"):
                for line in inc["remediation"].split("\n"):
                    print(f"    {safe_str(line)}")


# =============================================================
#  MAIN PIPELINE RUNNER
# =============================================================

if __name__ == "__main__":
    print("\n==============================================")
    print("         ThreatLens — Pipeline Test           ")
    print("==============================================")

    # Initialize and clean DB for a fresh run
    step1_init(wipe_db=True)

    # 1. Parse all available logs
    total_events = step2_parse()

    # 2. Run detection engines on logs
    raw_alerts = step3_detect()

    # 3. Enrich alerts (AbuseIPDB reputation + MITRE ATT&CK mapping) & save to DB
    enriched_alerts = step4_enrich_and_map(raw_alerts)

    # 4. Correlate alerts into multi-stage incidents & save to DB
    incidents = step5_correlate()

    # 5. Output pipeline summary and details
    step6_summary()
    step7_print_details()

    print("\n" + "="*50)
    # Pipeline pass/fail diagnostics
    if total_events > 0:
        print("[OK] Parser     - WORKING (events in DB)")
    else:
        print("[WARN] Parser   - No events found (check sample files)")

    if enriched_alerts:
        print("[OK] Detector   - WORKING (alerts generated)")
    else:
        print("[WARN] Detector - No alerts (need more threat signals in sample logs)")

    if incidents:
        print("[OK] Correlator - WORKING (cross-log attacks identified)")
    else:
        print("[INFO] Correlator - No multi-stage incidents identified")

    print("[OK] Database   - WORKING")
    print("\nPipeline execution complete.")
    print("="*50 + "\n")