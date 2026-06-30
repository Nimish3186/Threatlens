import re
import os
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ─────────────────────────────────────────────
#  IPTABLES PATTERN
#  Jun 27 10:15:32 firewall kernel: [12345.678] IPTABLES-DROP: IN=eth0 OUT=
#  MAC=.. SRC=203.0.113.45 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=44312 DPT=22 SYN
# ─────────────────────────────────────────────

IPTABLES_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+kernel:\s+\[\s*[\d.]+\]\s+'
    r'IPTABLES-(?P<action>\w+):\s+(?P<fields>.+)$'
)

# Extracts key=value pairs from the iptables fields string
IPTABLES_KV_PATTERN = re.compile(r'(\w+)=(\S+)')


# ─────────────────────────────────────────────
#  PFSENSE / PF FILTERLOG PATTERN (CSV-style)
#  Jun 27 10:15:32 firewall filterlog: 5,...,em0,match,block,in,4,...,tcp,60,
#  203.0.113.45,10.0.0.5,44312,22,...
# ─────────────────────────────────────────────

PFSENSE_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+filterlog\[?\d*\]?:\s+(?P<fields>.+)$'
)


# ─────────────────────────────────────────────
#  CISCO ASA PATTERN
#  Jun 27 10:15:32 firewall %ASA-4-106023: Deny tcp src outside:203.0.113.45/44312
#  dst inside:10.0.0.5/22 by access-group "OUTSIDE_IN"
# ─────────────────────────────────────────────

ASA_DENY_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+%ASA-(?P<severity>\d)-(?P<msgid>\d+):\s+'
    r'Deny\s+(?P<proto>\w+)\s+src\s+(?P<src_zone>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+'
    r'dst\s+(?P<dst_zone>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)'
)

ASA_BUILT_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+%ASA-(?P<severity>\d)-(?P<msgid>\d+):\s+'
    r'Built\s+(?P<direction>\w+)\s+(?P<proto>\w+)\s+connection.*?for\s+'
    r'(?P<src_zone>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+to\s+'
    r'(?P<dst_zone>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)'
)


# ─────────────────────────────────────────────
#  PARSE IPTABLES LINE
# ─────────────────────────────────────────────

def parse_iptables_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None

    match = IPTABLES_PATTERN.match(line)
    if not match:
        return None

    f = match.groupdict()
    year = datetime.now().year
    try:
        ts_str    = f"{f['month']} {f['day']} {f['time']} {year}"
        timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        timestamp = None

    # Parse the key=value fields blob
    kv = dict(IPTABLES_KV_PATTERN.findall(f["fields"]))

    action = "BLOCK" if f["action"].upper() in ("DROP", "REJECT", "DENY") else "ALLOW"

    return {
        "log_type":   "firewall",
        "timestamp":  timestamp.isoformat() if timestamp else None,
        "hostname":   f["hostname"],
        "source_ip":  kv.get("SRC"),
        "process":    "iptables",
        "pid":        None,
        "message":    f"{action} {kv.get('PROTO','?')} {kv.get('SRC','?')}:{kv.get('SPT','?')} -> {kv.get('DST','?')}:{kv.get('DPT','?')}",
        "raw":        line,
        # Firewall-specific extras
        "fw_action":   action,
        "dest_ip":     kv.get("DST"),
        "src_port":    kv.get("SPT"),
        "dest_port":   kv.get("DPT"),
        "protocol":    kv.get("PROTO"),
        "interface":   kv.get("IN") or kv.get("OUT"),
        "fw_vendor":   "iptables",
    }


# ─────────────────────────────────────────────
#  PARSE PFSENSE LINE
# ─────────────────────────────────────────────

def parse_pfsense_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None

    match = PFSENSE_PATTERN.match(line)
    if not match:
        return None

    f = match.groupdict()
    year = datetime.now().year
    try:
        ts_str    = f"{f['month']} {f['day']} {f['time']} {year}"
        timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        timestamp = None

    # CSV fields: rule,sub,anchor,tracker,iface,reason,action,dir,ipver,...
    parts = f["fields"].split(",")
    if len(parts) < 20:
        return None   # malformed / unexpected pf log line

    try:
        iface     = parts[4]
        action    = parts[6]      # 'block' or 'pass'
        direction = parts[7]      # 'in' or 'out'
        proto     = parts[16] if len(parts) > 16 else "?"
        src_ip    = parts[18] if len(parts) > 18 else "?"
        dst_ip    = parts[19] if len(parts) > 19 else "?"
        src_port  = parts[20] if len(parts) > 20 else ""
        dst_port  = parts[21] if len(parts) > 21 else ""
    except IndexError:
        return None

    fw_action = "BLOCK" if action.lower() == "block" else "ALLOW"

    return {
        "log_type":   "firewall",
        "timestamp":  timestamp.isoformat() if timestamp else None,
        "hostname":   f["hostname"],
        "source_ip":  src_ip,
        "process":    "pf",
        "pid":        None,
        "message":    f"{fw_action} {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({direction})",
        "raw":        line,
        "fw_action":   fw_action,
        "dest_ip":     dst_ip,
        "src_port":    src_port,
        "dest_port":   dst_port,
        "protocol":    proto,
        "interface":   iface,
        "fw_vendor":   "pfsense",
    }


# ─────────────────────────────────────────────
#  PARSE CISCO ASA LINE
# ─────────────────────────────────────────────

def parse_asa_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None

    year = datetime.now().year

    # Try DENY pattern first (more security-relevant)
    match = ASA_DENY_PATTERN.match(line)
    if match:
        f = match.groupdict()
        try:
            ts_str    = f"{f['month']} {f['day']} {f['time']} {year}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            timestamp = None

        return {
            "log_type":   "firewall",
            "timestamp":  timestamp.isoformat() if timestamp else None,
            "hostname":   f["hostname"],
            "source_ip":  f["src_ip"],
            "process":    "asa",
            "pid":        None,
            "message":    f"BLOCK {f['proto']} {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']}",
            "raw":        line,
            "fw_action":   "BLOCK",
            "dest_ip":     f["dst_ip"],
            "src_port":    f["src_port"],
            "dest_port":   f["dst_port"],
            "protocol":    f["proto"],
            "interface":   f["src_zone"],
            "fw_vendor":   "cisco_asa",
            "asa_msgid":   f["msgid"],
        }

    # Try BUILT (allowed connection) pattern
    match = ASA_BUILT_PATTERN.match(line)
    if match:
        f = match.groupdict()
        try:
            ts_str    = f"{f['month']} {f['day']} {f['time']} {year}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            timestamp = None

        return {
            "log_type":   "firewall",
            "timestamp":  timestamp.isoformat() if timestamp else None,
            "hostname":   f["hostname"],
            "source_ip":  f["src_ip"],
            "process":    "asa",
            "pid":        None,
            "message":    f"ALLOW {f['proto']} {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']}",
            "raw":        line,
            "fw_action":   "ALLOW",
            "dest_ip":     f["dst_ip"],
            "src_port":    f["src_port"],
            "dest_port":   f["dst_port"],
            "protocol":    f["proto"],
            "interface":   f["src_zone"],
            "fw_vendor":   "cisco_asa",
            "asa_msgid":   f["msgid"],
        }

    return None


# ─────────────────────────────────────────────
#  AUTO-DETECT VENDOR FROM FIRST FEW LINES
# ─────────────────────────────────────────────

def detect_firewall_vendor(filepath: str, sample_lines: int = 10) -> str:
    """Peek at a file and guess which firewall vendor format it uses."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= sample_lines:
                break
            if "IPTABLES-" in line:
                return "iptables"
            if "filterlog" in line:
                return "pfsense"
            if "%ASA-" in line:
                return "cisco_asa"
    return "unknown"


def parse_firewall_line(line: str, vendor: str) -> Optional[dict]:
    """Route to the correct parser based on vendor."""
    if vendor == "iptables":
        return parse_iptables_line(line)
    elif vendor == "pfsense":
        return parse_pfsense_line(line)
    elif vendor == "cisco_asa":
        return parse_asa_line(line)
    return None


# ─────────────────────────────────────────────
#  PARSE AN ENTIRE FILE
# ─────────────────────────────────────────────

def parse_firewall_log_file(filepath: str, vendor: str = "auto") -> list[dict]:
    """
    Read a firewall log file and return normalized event dicts.
    vendor: 'iptables', 'pfsense', 'cisco_asa', or 'auto' to detect.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    if vendor == "auto":
        vendor = detect_firewall_vendor(filepath)
        print(f"[fw_parser] Auto-detected vendor: {vendor}")

    if vendor == "unknown":
        print(f"[fw_parser] Could not detect firewall vendor for {filepath}")
        return []

    results = []
    skipped = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_firewall_line(line, vendor)
            if parsed:
                results.append(parsed)
            else:
                stripped = line.strip()
                if stripped:
                    skipped.append(stripped)

    print(f"[fw_parser] {filepath} ({vendor}): {len(results)} parsed, {len(skipped)} skipped")

    if skipped:
        print("[fw_parser] First 3 skipped lines:")
        for l in skipped[:3]:
            print(f"  >> {l}")

    return results


# ─────────────────────────────────────────────
#  FIREWALL THREAT DETECTOR
# ─────────────────────────────────────────────

PORT_SCAN_THRESHOLD   = 10   # distinct ports from one IP
PORT_SCAN_WINDOW_SECS = 60

SENSITIVE_PORTS = {
    22:   "SSH",
    23:   "Telnet",
    3389: "RDP",
    445:  "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017:"MongoDB",
}


def detect_firewall_threats(events: list[dict]) -> list[dict]:
    """
    Scan parsed firewall events for:
      1. Port scanning (one IP hitting many distinct ports fast)
      2. Repeated blocks against sensitive ports (SSH/RDP/DB probing)
    """
    alerts = []

    blocked_events = [e for e in events if e.get("fw_action") == "BLOCK"]

    # ── Detection 1: Port scan ────────────────────────────────────────
    ip_ports = defaultdict(set)
    ip_first_event = {}

    for e in blocked_events:
        ip = e.get("source_ip")
        port = e.get("dest_port")
        if not ip or not port:
            continue
        ip_ports[ip].add(port)
        if ip not in ip_first_event:
            ip_first_event[ip] = e

    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            event = ip_first_event[ip]
            alerts.append({
                "created_at":    datetime.now().isoformat(),
                "alert_type":    "port_scan",
                "severity":      "HIGH",
                "confidence":    "HIGH",
                "source_ip":     ip,
                "target_host":   event.get("hostname", "firewall"),
                "target_user":   "",
                "description":   f"Port scan detected: {ip} probed {len(ports)} distinct ports",
                "event_count":   len(ports),
                "window_secs":   PORT_SCAN_WINDOW_SECS,
                "first_seen":    event.get("timestamp", ""),
                "last_seen":     event.get("timestamp", ""),
                "attack_id":     "T1046",
                "attack_name":   "Network Service Discovery",
                "attack_tactic": "Discovery",
                "raw_events":    [event.get("raw", "")],
                "remediation": (
                    f"1. Block {ip} at perimeter firewall\n"
                    f"2. Review which ports were targeted: {sorted(ports)[:10]}\n"
                    f"3. Check if any scanned ports are actually open\n"
                    f"4. Enable rate limiting / fail2ban on firewall"
                ),
                "status":        "open",
            })

    # ── Detection 2: Sensitive port probing ──────────────────────────
    ip_sensitive_hits = defaultdict(list)

    for e in blocked_events:
        ip   = e.get("source_ip")
        port = e.get("dest_port")
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue

        if port_int in SENSITIVE_PORTS:
            ip_sensitive_hits[ip].append((port_int, e))

    for ip, hits in ip_sensitive_hits.items():
        if len(hits) >= 3:   # 3+ blocked attempts on sensitive ports
            services = sorted(set(SENSITIVE_PORTS[p] for p, _ in hits))
            event = hits[0][1]
            alerts.append({
                "created_at":    datetime.now().isoformat(),
                "alert_type":    "sensitive_port_probe",
                "severity":      "CRITICAL" if "RDP" in services or "SSH" in services else "HIGH",
                "confidence":    "HIGH",
                "source_ip":     ip,
                "target_host":   event.get("hostname", "firewall"),
                "target_user":   "",
                "description":   f"{ip} attempted to access sensitive services: {', '.join(services)}",
                "event_count":   len(hits),
                "window_secs":   PORT_SCAN_WINDOW_SECS,
                "first_seen":    event.get("timestamp", ""),
                "last_seen":     hits[-1][1].get("timestamp", ""),
                "attack_id":     "T1190",
                "attack_name":   "Exploit Public-Facing Application",
                "attack_tactic": "Initial Access",
                "raw_events":    [h[1].get("raw", "") for h in hits[:5]],
                "remediation": (
                    f"1. Block {ip} immediately at firewall\n"
                    f"2. Verify {', '.join(services)} are not exposed to internet unnecessarily\n"
                    f"3. Add geo-blocking if attacks originate from unexpected regions\n"
                    f"4. Review firewall rules for these services"
                ),
                "status":        "open",
            })

    print(f"[fw_detector] {len(alerts)} firewall threat(s) detected.")
    return alerts


# ─────────────────────────────────────────────
#  SELF TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all

    init_db()
    clear_all()

    print("=" * 50)
    print("IPTABLES PARSING TEST")
    print("=" * 50)

    iptables_lines = [
        "Jun 27 10:15:32 firewall kernel: [12345.678] IPTABLES-DROP: IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=203.0.113.45 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=44312 DPT=22 SYN",
        "Jun 27 10:15:33 firewall kernel: [12345.700] IPTABLES-DROP: IN=eth0 OUT= SRC=203.0.113.45 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=44313 DPT=23 SYN",
        "Jun 27 10:15:34 firewall kernel: [12345.720] IPTABLES-DROP: IN=eth0 OUT= SRC=203.0.113.45 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=44314 DPT=3389 SYN",
        "Jun 27 10:16:01 firewall kernel: [12346.100] IPTABLES-ACCEPT: IN=eth0 OUT=eth1 SRC=192.168.1.10 DST=8.8.8.8 LEN=84 PROTO=UDP SPT=53124 DPT=53",
        "not a valid firewall line",
    ]

    fw_events = []
    for line in iptables_lines:
        result = parse_iptables_line(line)
        if result:
            fw_events.append(result)
            print(f"  ✓ {result['fw_action']:6s} {result['protocol']:4s} {result['source_ip']:16s} -> {result['dest_ip']}:{result['dest_port']}")
        else:
            print(f"  ✗ skipped: {line[:50]}")

    # Add more port scan events to trigger detection
    for port in range(1000, 1015):
        fw_events.append({
            "log_type": "firewall", "timestamp": "2025-06-27T10:15:40",
            "hostname": "firewall", "source_ip": "203.0.113.45",
            "process": "iptables", "pid": None,
            "message": f"BLOCK TCP 203.0.113.45 -> 10.0.0.5:{port}",
            "raw": f"Jun 27 10:15:40 firewall kernel: IPTABLES-DROP: SRC=203.0.113.45 DST=10.0.0.5 PROTO=TCP DPT={port}",
            "fw_action": "BLOCK", "dest_ip": "10.0.0.5", "src_port": "9999",
            "dest_port": str(port), "protocol": "TCP", "interface": "eth0", "fw_vendor": "iptables",
        })

    print("\n" + "=" * 50)
    print("THREAT DETECTION TEST")
    print("=" * 50)
    insert_events(fw_events)
    alerts = detect_firewall_threats(fw_events)

    for a in alerts:
        insert_alert(a)
        print(f"  [{a['severity']:8s}] {a['attack_id']} — {a['description']}")

    print(f"\n  {len(alerts)} alert(s) stored in DB")