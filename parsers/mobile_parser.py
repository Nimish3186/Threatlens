import re
import os
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ─────────────────────────────────────────────
#  ANDROID LOGCAT PATTERN
#  Format: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message
# ─────────────────────────────────────────────

ANDROID_PATTERN = re.compile(
    r'^(?P<month>\d{2})-(?P<day>\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<pid>\d+)\s+(?P<tid>\d+)\s+'
    r'(?P<level>[VDIWEF])\s+'
    r'(?P<tag>[^:]+?):\s+'
    r'(?P<message>.+)$'
)

# Android logcat with brief format (no PID/TID columns)
# Format: MM-DD HH:MM:SS.mmm LEVEL/TAG: message
ANDROID_BRIEF_PATTERN = re.compile(
    r'^(?P<month>\d{2})-(?P<day>\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<level>[VDIWEF])/(?P<tag>[^:]+?):\s+'
    r'(?P<message>.+)$'
)

# ─────────────────────────────────────────────
#  iOS UNIFIED LOG PATTERN
#  Format: YYYY-MM-DD HH:MM:SS.mmm+TZ Process[PID] <Level>: message
# ─────────────────────────────────────────────

IOS_PATTERN = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)'
    r'(?P<tz>[+-]\d{4})?\s+'
    r'(?P<process>[^\[]+)\[(?P<pid>\d+)\]\s+'
    r'<(?P<level>\w+)>:\s+'
    r'(?P<message>.+)$'
)

# iOS syslog export (older format from idevicesyslog)
# Format: DayOfWeek Mon DD HH:MM:SS hostname process[pid]: message
IOS_SYSLOG_PATTERN = re.compile(
    r'^(?P<weekday>\w{3})\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+'
    r'(?P<message>.+)$'
)

# ─────────────────────────────────────────────
#  LEVEL NORMALISATION
# ─────────────────────────────────────────────

ANDROID_LEVEL_MAP = {
    'V': 'VERBOSE',
    'D': 'DEBUG',
    'I': 'INFO',
    'W': 'WARNING',
    'E': 'ERROR',
    'F': 'FATAL',
}

IOS_LEVEL_MAP = {
    'Default': 'INFO',
    'Info':    'INFO',
    'Debug':   'DEBUG',
    'Notice':  'INFO',
    'Warning': 'WARNING',
    'Error':   'ERROR',
    'Fault':   'FATAL',
}


# ─────────────────────────────────────────────
#  PARSE A SINGLE LINE
# ─────────────────────────────────────────────

def parse_android_line(line: str) -> Optional[dict]:
    """Parse one Android logcat line into a normalized dict."""
    line = line.strip()
    if not line:
        return None

    # Try full format first, then brief format
    match = ANDROID_PATTERN.match(line) or ANDROID_BRIEF_PATTERN.match(line)
    if not match:
        return None

    fields = match.groupdict()
    year   = datetime.now().year

    try:
        ts_str    = f"{year}-{fields['month']}-{fields['day']} {fields['time']}"
        timestamp = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        timestamp = None

    level = ANDROID_LEVEL_MAP.get(fields.get("level", ""), fields.get("level", ""))

    return {
        "log_type":   "android",
        "timestamp":  timestamp.isoformat() if timestamp else None,
        "hostname":   "android-device",
        "source_ip":  None,
        "process":    fields.get("tag", "").strip(),
        "pid":        fields.get("pid"),
        "message":    fields.get("message", "").strip(),
        "level":      level,
        "raw":        line,
        # Android-specific extras
        "tid":        fields.get("tid"),
    }


def parse_ios_line(line: str) -> Optional[dict]:
    """Parse one iOS unified log or syslog line into a normalized dict."""
    line = line.strip()
    if not line:
        return None

    # Try unified log format
    match = IOS_PATTERN.match(line)
    if match:
        fields = match.groupdict()
        try:
            ts_str    = f"{fields['date']} {fields['time'][:8]}"
            timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = None

        level = IOS_LEVEL_MAP.get(fields.get("level", ""), fields.get("level", ""))

        return {
            "log_type":  "ios",
            "timestamp": timestamp.isoformat() if timestamp else None,
            "hostname":  "ios-device",
            "source_ip": None,
            "process":   fields.get("process", "").strip(),
            "pid":       fields.get("pid"),
            "message":   fields.get("message", "").strip(),
            "level":     level,
            "raw":       line,
        }

    # Try older idevicesyslog format
    match = IOS_SYSLOG_PATTERN.match(line)
    if match:
        fields = match.groupdict()
        year   = datetime.now().year
        try:
            ts_str    = f"{fields['month']} {fields['day']} {fields['time']} {year}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            timestamp = None

        return {
            "log_type":  "ios",
            "timestamp": timestamp.isoformat() if timestamp else None,
            "hostname":  fields.get("hostname", "ios-device"),
            "source_ip": None,
            "process":   fields.get("process", "").strip(),
            "pid":       fields.get("pid"),
            "message":   fields.get("message", "").strip(),
            "level":     "INFO",
            "raw":       line,
        }

    return None


def parse_mobile_line(line: str, log_type: str) -> Optional[dict]:
    """Route to the right parser based on log_type."""
    if log_type == "android":
        return parse_android_line(line)
    elif log_type == "ios":
        return parse_ios_line(line)
    return None


# ─────────────────────────────────────────────
#  PARSE AN ENTIRE FILE
# ─────────────────────────────────────────────

def parse_mobile_log_file(filepath: str, log_type: str) -> list[dict]:
    """
    Read an entire mobile log file and return normalized event dicts.
    log_type must be 'android' or 'ios'.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    results      = []
    skipped      = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_mobile_line(line, log_type)
            if parsed:
                results.append(parsed)
            else:
                stripped = line.strip()
                if stripped:
                    skipped.append(stripped)

    print(f"[mobile_parser] {filepath}: {len(results)} parsed, {len(skipped)} skipped")

    if skipped:
        print(f"[mobile_parser] First 3 skipped lines:")
        for l in skipped[:3]:
            print(f"  >> {l}")

    return results


# ─────────────────────────────────────────────
#  MOBILE-SPECIFIC THREAT DETECTOR
# ─────────────────────────────────────────────

# Patterns that indicate malicious or suspicious mobile activity
THREAT_PATTERNS = {

    # ── Rooting / Jailbreaking ──────────────────────────────────────
    "root_jailbreak": {
        "patterns": [
            r'su\s+binary|superuser|SuperSU|Magisk|KingRoot',
            r'com\.topjohnwu\.magisk',
            r'Cydia|substrate|jailbreak|Unc0ver|checkra1n',
            r'rooted device|root access granted',
        ],
        "severity":    "CRITICAL",
        "attack_id":   "T1068",
        "attack_name": "Exploitation for Privilege Escalation",
        "tactic":      "Privilege Escalation",
    },

    # ── Malware / Unknown App Install ───────────────────────────────
    "suspicious_install": {
        "patterns": [
            r'Installed.*?com\.(?!android|google|samsung|oneplus|xiaomi|oppo)\S+',
            r'PackageManager.*?install.*?unknown',
            r'installd.*?Install.*?unsigned',
            r'sideload|APK install|INSTALL_PACKAGES',
        ],
        "severity":    "HIGH",
        "attack_id":   "T1476",
        "attack_name": "Deliver Malicious App via Authorized App Store",
        "tactic":      "Initial Access",
    },

    # ── SELinux / Sandbox Denial ─────────────────────────────────────
    "sandbox_violation": {
        "patterns": [
            r'avc:\s+denied',
            r'SELinux.*?denied',
            r'Sandbox violation',
            r'sandbox.*?blocked',
        ],
        "severity":    "HIGH",
        "attack_id":   "T1562.001",
        "attack_name": "Impair Defenses: Disable or Modify Tools",
        "tactic":      "Defense Evasion",
    },

    # ── Unauthorized Location Access ────────────────────────────────
    "location_access": {
        "patterns": [
            r'Unauthorized location access',
            r'location.*?permission denied',
            r'CLLocationManager.*?error',
            r'ACCESS_FINE_LOCATION.*?denied',
        ],
        "severity":    "MEDIUM",
        "attack_id":   "T1430",
        "attack_name": "Location Tracking",
        "tactic":      "Collection",
    },

    # ── Suspicious Network Activity ──────────────────────────────────
    "suspicious_network": {
        "patterns": [
            r'SSL.*?error|certificate.*?invalid|MITM',
            r'connect.*?(?:1\.1\.1\.1|8\.8\.8\.8|tor)',  # unexpected DNS
            r'NetworkSecurity.*?cleartext',
            r'CFNetwork.*?error.*?SSL',
        ],
        "severity":    "HIGH",
        "attack_id":   "T1557",
        "attack_name": "Adversary-in-the-Middle",
        "tactic":      "Collection",
    },

    # ── Camera / Mic Access ─────────────────────────────────────────
    "sensor_access": {
        "patterns": [
            r'camera.*?access.*?background',
            r'microphone.*?access.*?background',
            r'AVCaptureSession.*?background',
            r'RECORD_AUDIO.*?background',
        ],
        "severity":    "HIGH",
        "attack_id":   "T1429",
        "attack_name": "Capture Audio",
        "tactic":      "Collection",
    },

    # ── Crash Loop (stability / exploit) ────────────────────────────
    "crash_loop": {
        "patterns": [
            r'FATAL EXCEPTION',
            r'Process.*?has died',
            r'<Error>.*?crash',
            r'crash.*?Exception',
        ],
        "severity":    "LOW",
        "attack_id":   "T1499",
        "attack_name": "Endpoint Denial of Service",
        "tactic":      "Impact",
    },
}


def detect_mobile_threats(events: list[dict]) -> list[dict]:
    """
    Scan parsed mobile events for threat patterns.
    Returns a list of alert dicts.
    """
    alerts        = []
    crash_counts  = {}   # process -> crash count (for crash loop detection)

    for event in events:
        msg     = event.get("message", "")
        process = event.get("process", "unknown")
        ts      = event.get("timestamp", datetime.now().isoformat())
        device  = event.get("hostname", "mobile-device")
        ltype   = event.get("log_type", "mobile")

        for threat_name, config in THREAT_PATTERNS.items():

            # Crash loop needs special counting logic
            if threat_name == "crash_loop":
                for pattern in config["patterns"]:
                    if re.search(pattern, msg, re.IGNORECASE):
                        crash_counts[process] = crash_counts.get(process, 0) + 1
                        if crash_counts[process] == 3:  # fire on 3rd crash
                            alerts.append(build_mobile_alert(
                                event, threat_name, config,
                                f"Process '{process}' has crashed {crash_counts[process]} times"
                            ))
                break

            # All other threats fire immediately on pattern match
            for pattern in config["patterns"]:
                if re.search(pattern, msg, re.IGNORECASE):
                    alerts.append(build_mobile_alert(
                        event, threat_name, config,
                        f"[{ltype.upper()}] {config['attack_name']} detected on {device}: {msg[:80]}"
                    ))
                    break   # one alert per threat type per event

    print(f"[mobile_detector] {len(alerts)} mobile threat(s) detected.")
    return alerts


def build_mobile_alert(
    event: dict,
    threat_name: str,
    config: dict,
    description: str,
) -> dict:
    return {
        "created_at":    datetime.now().isoformat(),
        "alert_type":    f"mobile_{threat_name}",
        "severity":      config["severity"],
        "confidence":    "MEDIUM",
        "source_ip":     event.get("source_ip") or event.get("hostname", ""),
        "target_host":   event.get("hostname", "mobile-device"),
        "target_user":   event.get("process", "unknown"),
        "description":   description,
        "event_count":   1,
        "window_secs":   0,
        "first_seen":    event.get("timestamp", ""),
        "last_seen":     event.get("timestamp", ""),
        "attack_id":     config["attack_id"],
        "attack_name":   config["attack_name"],
        "attack_tactic": config["tactic"],
        "raw_events":    [event.get("raw", "")],
        "remediation":   REMEDIATIONS.get(threat_name, "Investigate the flagged event manually."),
        "status":        "open",
    }


REMEDIATIONS = {
    "root_jailbreak": (
        "1. Device is rooted/jailbroken — enforce MDM policy to block access\n"
        "2. Revoke corporate credentials from device immediately\n"
        "3. Wipe device if it holds sensitive data\n"
        "4. Review what apps were installed post-root"
    ),
    "suspicious_install": (
        "1. Identify the installed app and its package name\n"
        "2. Check VirusTotal: https://virustotal.com\n"
        "3. Uninstall immediately if unauthorized: adb uninstall com.package.name\n"
        "4. Enable Play Protect / restrict to verified sources only"
    ),
    "sandbox_violation": (
        "1. Review the process triggering SELinux/sandbox denials\n"
        "2. Check if denial pattern matches known exploit behavior\n"
        "3. Update device OS — many sandbox bypasses are patched\n"
        "4. Consider factory reset if exploitation confirmed"
    ),
    "suspicious_network": (
        "1. Check if device is on a trusted network\n"
        "2. Inspect certificate chain for the failing connection\n"
        "3. Enable certificate pinning in apps if possible\n"
        "4. Check for rogue Wi-Fi / MITM proxy"
    ),
    "location_access": (
        "1. Identify which app triggered the access\n"
        "2. Revoke location permission: Settings > Apps > Permissions\n"
        "3. Check if app has legitimate reason for location access\n"
        "4. Remove app if access is unexplained"
    ),
    "sensor_access": (
        "1. Identify the app accessing camera/mic in background\n"
        "2. Revoke permissions immediately\n"
        "3. Uninstall if app has no legitimate reason for access\n"
        "4. Check for spyware indicators"
    ),
    "crash_loop": (
        "1. Identify the crashing process and check recent installs\n"
        "2. Clear app cache: Settings > Apps > Clear Cache\n"
        "3. Repeated FATAL crashes can indicate exploit attempts\n"
        "4. Update or reinstall the crashing app"
    ),
}


# ─────────────────────────────────────────────
#  SELF TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all

    init_db()

    # ── Test Android parsing ─────────────────────────────────────────
    android_lines = [
        "06-27 10:15:32.841  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main",
        "06-27 10:15:33.100  1234  5678 W ActivityManager: Slow operation: 120ms",
        "06-27 10:16:01.002  9999  9999 I PackageManager: Installed app com.evil.malware",
        "06-27 10:17:45.333  1234  1234 E SELinux: avc: denied { read } for pid=1234",
        "06-27 10:18:00.000  2222  2222 I SuperSU: su binary accessed by com.hacker.app",
        "06-27 10:19:00.000  3333  3333 W NetworkSecurity: cleartext traffic to 10.0.0.5",
        "06-27 10:20:00.000  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main",
        "06-27 10:21:00.000  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main",
        "not a valid log line !!!",
    ]

    # ── Test iOS parsing ──────────────────────────────────────────────
    ios_lines = [
        "2025-06-27 10:15:32.841+0530 SpringBoard[1234] <Error>: Application crashed",
        "2025-06-27 10:16:01.002+0530 installd[5678] <Notice>: Installing com.evil.app unsigned",
        "2025-06-27 10:17:45.100+0530 kernel[0] <Warning>: Sandbox violation by pid 9999",
        "2025-06-27 10:18:00.500+0530 locationd[2222] <Error>: Unauthorized location access",
        "2025-06-27 10:19:30.000+0530 Cydia[3333] <Notice>: Package installed",
        "not a valid ios line !!!",
    ]

    print("=" * 50)
    print("ANDROID PARSING TEST")
    print("=" * 50)
    android_events = []
    for line in android_lines:
        result = parse_android_line(line)
        if result:
            android_events.append(result)
            print(f"  ✓ [{result['level']:7s}] {result['process']:20s} | {result['message'][:50]}")
        else:
            print(f"  ✗ skipped: {line[:50]}")

    print("\n" + "=" * 50)
    print("iOS PARSING TEST")
    print("=" * 50)
    ios_events = []
    for line in ios_lines:
        result = parse_ios_line(line)
        if result:
            ios_events.append(result)
            print(f"  ✓ [{result['level']:7s}] {result['process']:20s} | {result['message'][:50]}")
        else:
            print(f"  ✗ skipped: {line[:50]}")

    print("\n" + "=" * 50)
    print("THREAT DETECTION TEST")
    print("=" * 50)
    all_events = android_events + ios_events
    insert_events(all_events)
    alerts = detect_mobile_threats(all_events)

    for a in alerts:
        insert_alert(a)
        print(f"  [{a['severity']:8s}] {a['attack_id']} — {a['description'][:70]}")

    print(f"\n  {len(alerts)} alert(s) stored in DB")