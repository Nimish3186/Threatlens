import sys
import os
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all
from detectors.suspicious_login import detect_suspicious_logins

def test_suspicious_login_detector():
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

    print(f"Generated {len(alerts)} alerts.")
    for a in alerts:
        insert_alert(a)

    # Assertions
    assert len(alerts) == 2, f"Expected 2 alerts, got {len(alerts)}"
    
    severities = sorted([a["severity"] for a in alerts])
    assert severities == ["CRITICAL", "HIGH"], f"Unexpected severities: {severities}"
    
    print("[OK] Suspicious Login Detector Test Passed Successfully!")

if __name__ == "__main__":
    test_suspicious_login_detector()
