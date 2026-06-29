from database.storage import init_db, insert_events, insert_alert, get_alerts
from detectors.brute_force import detect_brute_force
from datetime import datetime, timedelta

init_db()

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

print("\n=== STORED ALERTS ===")
for a in get_alerts():
    print(f"  [{a['severity']}] {a['source_ip']} — {a['description']}")