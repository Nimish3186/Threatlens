import sys
import os

# Always resolve imports from project root
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from database.storage import init_db, insert_events, insert_alert, get_alerts, get_summary, clear_all
from parsers.linux_parser import parse_log_file
from detectors.brute_force import detect_brute_force


# ─────────────────────────────────────────────
#  STEP 1 — Initialize the database
# ─────────────────────────────────────────────

def step1_init():
    print("\n" + "="*50)
    print("STEP 1 — Initializing database")
    print("="*50)
    init_db()
    print("✓ Database ready")


# ─────────────────────────────────────────────
#  STEP 2 — Parse sample log files
# ─────────────────────────────────────────────

def step2_parse():
    print("\n" + "="*50)
    print("STEP 2 — Parsing log files")
    print("="*50)

    total = 0

    # Try each sample file — skips gracefully if not found
    sample_files = [
        ("samples/auth.log",   "syslog"),
        ("samples/linux.log",  "syslog"),
        ("samples/auth.txt",   "syslog"),
    ]

    for filepath, log_type in sample_files:
        if not os.path.exists(filepath):
            print(f"  [skip] {filepath} not found")
            continue

        try:
            events = parse_log_file(filepath, log_type=log_type)
            if events:
                insert_events(events)
                total += len(events)
                print(f"  ✓ {filepath} → {len(events)} events parsed and stored")
            else:
                print(f"  [warn] {filepath} → 0 events parsed (check file content)")
        except Exception as e:
            print(f"  [error] {filepath} → {e}")

    print(f"\n  Total events inserted: {total}")
    return total


# ─────────────────────────────────────────────
#  STEP 3 — Run brute force detector
# ─────────────────────────────────────────────

def step3_detect():
    print("\n" + "="*50)
    print("STEP 3 — Running brute force detector")
    print("="*50)

    try:
        alerts = detect_brute_force()

        if not alerts:
            print("  [info] No brute force detected in current events.")
            print("  [info] This is OK if your sample logs don't have enough failed logins.")
        else:
            for alert in alerts:
                insert_alert(alert)
            print(f"  ✓ {len(alerts)} brute force alert(s) detected and stored")

        return alerts

    except Exception as e:
        print(f"  [error] Detector failed → {e}")
        return []


# ─────────────────────────────────────────────
#  STEP 4 — Print summary
# ─────────────────────────────────────────────

def step4_summary():
    print("\n" + "="*50)
    print("STEP 4 — Database summary")
    print("="*50)

    summary = get_summary()
    print(f"  Total events  : {summary['total_events']}")
    print(f"  Total alerts  : {summary['total_alerts']}")
    print(f"  Open alerts   : {summary['open_alerts']}")
    print(f"  By severity   : {summary['severity_breakdown']}")
    print(f"  By type       : {summary['type_breakdown']}")


# ─────────────────────────────────────────────
#  STEP 5 — Print alerts in detail
# ─────────────────────────────────────────────

def step5_print_alerts():
    print("\n" + "="*50)
    print("STEP 5 — Alert details")
    print("="*50)

    alerts = get_alerts()

    if not alerts:
        print("  No alerts in database yet.")
        return

    for a in alerts:
        print(f"""
  ┌─ ALERT #{a['id']} ──────────────────────────────
  │  Type        : {a['alert_type']}
  │  Severity    : {a['severity']}  |  Confidence: {a['confidence']}
  │  Attacker IP : {a['source_ip']}
  │  Target      : {a['target_user']}@{a['target_host']}
  │  Hits        : {a['event_count']} attempts in {a['window_secs']}s
  │  First seen  : {a['first_seen']}
  │  Last seen   : {a['last_seen']}
  │  ATT&CK      : {a['attack_id']} — {a['attack_name']}
  │  Tactic      : {a['attack_tactic']}
  │  Status      : {a['status']}
  │  Description : {a['description']}
  └────────────────────────────────────────────""")

        print("  Remediation steps:")
        if a.get("remediation"):
            for line in a["remediation"].split("\n"):
                print(f"    {line}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════╗")
    print("║         ThreatLens — Pipeline Test           ║")
    print("╚══════════════════════════════════════════════╝")

    # Uncomment the line below to wipe the DB before each test run
    # clear_all()

    step1_init()
    total_events = step2_parse()
    alerts       = step3_detect()
    step4_summary()
    step5_print_alerts()

    print("\n" + "="*50)

    # Final pass/fail verdict
    if total_events > 0:
        print("✓ Parser     — WORKING (events in DB)")
    else:
        print("✗ Parser     — No events found (check sample files)")

    if alerts:
        print("✓ Detector   — WORKING (alerts generated)")
    else:
        print("~ Detector   — No alerts (need more failed logins in samples)")

    print("✓ Database   — WORKING (no crash = tables exist)")
    print("\nPipeline check complete.")
    print("="*50 + "\n")