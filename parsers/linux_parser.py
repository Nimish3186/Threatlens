import re
from datetime import datetime
from typing import Optional
import os

# Covers syslog, auth.log, kern.log
SYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)$'
)

# Apache combined log format
APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

def parse_syslog_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None

    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None

    fields = match.groupdict()

    # Build a normalized timestamp (assume current year)
    year = datetime.now().year
    raw_ts = f"{fields['month']} {fields['day']} {fields['time']} {year}"
    try:
        timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S %Y")
    except ValueError:
        timestamp = None

    return {
        "log_type":  "syslog",
        "timestamp": timestamp.isoformat() if timestamp else None,
        "hostname":  fields["hostname"],
        "process":   fields["process"],
        "pid":       fields.get("pid"),
        "message":   fields["message"],
        "raw":       line,
    }


def parse_apache_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None

    match = APACHE_PATTERN.match(line)
    if not match:
        return None

    fields = match.groupdict()
    try:
        timestamp = datetime.strptime(fields["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        timestamp = None

    return {
        "log_type":    "apache",
        "timestamp":   timestamp.isoformat() if timestamp else None,
        "source_ip":   fields["ip"],
        "http_method": fields["method"],
        "path":        fields["path"],
        "status_code": int(fields["status"]),
        "raw":         line,
    }


def parse_line(line: str, log_type: str = "syslog") -> Optional[dict]:
    """Single entry point. Routes to the right parser."""
    if log_type == "apache":
        return parse_apache_line(line)
    return parse_syslog_line(line)




def parse_log_file(filepath: str, log_type: str = "syslog") -> list[dict]:
    """Read an entire log file, return list of parsed event dicts."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    results = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_line(line, log_type=log_type)
            if parsed:
                results.append(parsed)
            else:
                skipped += 1

    print(f"[parser] {filepath}: {len(results)} parsed, {skipped} skipped")
    return results


