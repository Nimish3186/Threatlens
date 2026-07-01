import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all
from detectors.priv_escalation import detect_priv_escalation

def test_priv_escalation_detector():
    init_db()
    clear_all()

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

    print(f"Generated {len(alerts)} alerts.")
    for a in alerts:
        insert_alert(a)

    # Assertions
    assert len(alerts) == 7, f"Expected 7 alerts, got {len(alerts)}"
    
    subtypes = [a["alert_type"] for a in alerts]
    assert all(st.startswith("priv_escalation") for st in subtypes)
    print("[OK] Privilege Escalation Detector Test Passed Successfully!")

if __name__ == "__main__":
    test_priv_escalation_detector()
