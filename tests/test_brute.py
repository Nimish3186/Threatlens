import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all
from detectors.brute_force import detect_brute_force

def test_brute_force_detector():
    init_db()
    clear_all()

    # Simulate 7 failed SSH attempts from one IP within 45 seconds
    base_time = datetime(2025, 6, 27, 10, 0, 0)
    fake_events = []

    for i in range(7):
        ts = base_time + timedelta(seconds=i * 6)  # every 6s → 7 hits in 42s
        fake_events.append({
            "log_type":  "syslog",
            "timestamp": ts.isoformat(),
            "hostname":  "myserver",
            "source_ip": "192.168.1.99",
            "process":   "sshd",
            "message":   f"Failed password for root from 192.168.1.99 port 22 ssh2",
            "raw":       f"Jun 27 10:00:{i*6:02d} myserver sshd[999]: Failed password for root from 192.168.1.99 port 22 ssh2",
        })

    # One innocent user with only 2 failures — should NOT trigger
    for i in range(2):
        fake_events.append({
            "log_type":  "syslog",
            "timestamp": (base_time + timedelta(minutes=5, seconds=i*10)).isoformat(),
            "hostname":  "myserver",
            "source_ip": "10.0.0.5",
            "process":   "sshd",
            "message":   "Failed password for alice from 10.0.0.5 port 22 ssh2",
            "raw":       f"Jun 27 10:05:{i*10:02d} myserver sshd[888]: Failed password for alice from 10.0.0.5 port 22 ssh2",
        })

    insert_events(fake_events)

    alerts = detect_brute_force()

    for a in alerts:
        insert_alert(a)

    stored_alerts = get_alerts()
    
    # Assertions
    assert len(stored_alerts) == 1, f"Expected 1 alert, got {len(stored_alerts)}"
    assert stored_alerts[0]["source_ip"] == "192.168.1.99", f"Expected alert from 192.168.1.99, got {stored_alerts[0]['source_ip']}"
    assert stored_alerts[0]["alert_type"] == "brute_force"
    print("[OK] Brute Force Detector Test Passed Successfully!")

if __name__ == "__main__":
    test_brute_force_detector()