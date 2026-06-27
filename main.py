from parsers.linux_parser import parse_log_file
from database.storage import init_db, insert_events, insert_alert, get_alerts
from detectors.brute_force import detect_brute_force

if __name__ == "__main__":
    init_db()

    # 1. Parse logs into DB
    events = parse_log_file("/var/log/auth.log", log_type="syslog")
    insert_events(events)

    # 2. Run brute force detector
    alerts = detect_brute_force()

    # 3. Store alerts
    for alert in alerts:
        insert_alert(alert)

    # 4. Print all stored alerts
    print("\n--- ALERTS ---")
    for a in get_alerts():
        print(f"[{a['severity']}] {a['alert_type']} | {a['source_ip']} | {a['description'][:80]}")