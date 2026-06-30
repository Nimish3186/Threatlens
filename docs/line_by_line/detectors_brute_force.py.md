# Line-by-Line Explanation: detectors/brute_force.py

This file explains every line in `detectors/brute_force.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `import sqlite3` | Imports the sqlite3 module so this file can use its built-in functions or classes later. |
| 2 | `import re` | Imports the re module so this file can use its built-in functions or classes later. |
| 3 | `import json` | Imports the json module so this file can use its built-in functions or classes later. |
| 4 | `from datetime import datetime, timedelta` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 5 | `from collections import defaultdict` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 6 | `from pathlib import Path` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 7 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 8 | `DB_PATH = Path(__file__).resolve().parent.parent / "database" / "events.db"` | Builds the path to the SQLite database file using the current file location, so the program can find the database reliably. |
| 9 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 10 | `# Tunable config` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 11 | `THRESHOLD   = 3     # failed attempts to trigger` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 12 | `WINDOW_SECS = 60     # within this many seconds` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 13 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 14 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 15 | `def fetch_failed_logins() -> list[dict]:` | Starts a function named `fetch_failed_logins`. The indented lines below it are grouped together and run only when this function is called. |
| 16 | `    """Pull all failed SSH/login events from the events table."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 17 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 18 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 19 | `    rows = conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 20 | `        SELECT * FROM events` | Begins an SQL query that reads rows from a database table. |
| 21 | `        WHERE (` | Adds filtering rules to an SQL query so only matching rows are returned. |
| 22 | `            message LIKE '%Failed password%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 23 | `            OR message LIKE '%authentication failure%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 24 | `            OR message LIKE '%Invalid user%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 25 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 26 | `        AND timestamp IS NOT NULL` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 27 | `        ORDER BY timestamp ASC` | Sorts database results by a column, such as timestamp or creation time. |
| 28 | `    """).fetchall()` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 29 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 30 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 31 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 32 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 33 | `def extract_ip_from_message(message: str) -> str &#124; None:` | Starts a function named `extract_ip_from_message`. The indented lines below it are grouped together and run only when this function is called. |
| 34 | `    """Pull the attacker IP from a syslog message string."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 35 | `    import re` | Imports the re module so this file can use its built-in functions or classes later. |
| 36 | `    # Matches: "from 192.168.1.5" or "rhost=10.0.0.1"` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 37 | `    match = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', message)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 38 | `    if match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 39 | `        return match.group(1)` | Sends a value back to the code that called this function, then stops the function. |
| 40 | `    match = re.search(r'rhost=(\d{1,3}(?:\.\d{1,3}){3})', message)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 41 | `    if match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 42 | `        return match.group(1)` | Sends a value back to the code that called this function, then stops the function. |
| 43 | `    return None` | Sends a value back to the code that called this function, then stops the function. |
| 44 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 45 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 46 | `def sliding_window_check(timestamps: list[datetime]) -> list[datetime]:` | Starts a function named `sliding_window_check`. The indented lines below it are grouped together and run only when this function is called. |
| 47 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 48 | `    Given a sorted list of timestamps for one IP,` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 49 | `    return the earliest window of THRESHOLD hits within WINDOW_SECS.` | Sends a value back to the code that called this function, then stops the function. |
| 50 | `    Returns the matching timestamps if found, else empty list.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 51 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 52 | `    if len(timestamps) < THRESHOLD:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 53 | `        return []` | Sends a value back to the code that called this function, then stops the function. |
| 54 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 55 | `    for i in range(len(timestamps) - THRESHOLD + 1):` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 56 | `        window_start = timestamps[i]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 57 | `        window_end   = timestamps[i + THRESHOLD - 1]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 58 | `        delta = (window_end - window_start).total_seconds()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 59 | `        if delta <= WINDOW_SECS:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 60 | `            return timestamps[i: i + THRESHOLD]` | Sends a value back to the code that called this function, then stops the function. |
| 61 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 62 | `    return []` | Sends a value back to the code that called this function, then stops the function. |
| 63 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 64 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 65 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 66 | `def extract_target_user(message: str) -> str:` | Starts a function named `extract_target_user`. The indented lines below it are grouped together and run only when this function is called. |
| 67 | `    match = re.search(r'Failed password for (?:invalid user )?(\S+) from', message)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 68 | `    return match.group(1) if match else "unknown"` | Sends a value back to the code that called this function, then stops the function. |
| 69 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 70 | `def calculate_severity(event_count: int) -> str:` | Starts a function named `calculate_severity`. The indented lines below it are grouped together and run only when this function is called. |
| 71 | `    if event_count >= 20:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 72 | `        return "CRITICAL"` | Sends a value back to the code that called this function, then stops the function. |
| 73 | `    elif event_count >= 10:` | Adds another condition to a previous if statement. Python checks this only if the earlier condition was false. |
| 74 | `        return "HIGH"` | Sends a value back to the code that called this function, then stops the function. |
| 75 | `    elif event_count >= 5:` | Adds another condition to a previous if statement. Python checks this only if the earlier condition was false. |
| 76 | `        return "MEDIUM"` | Sends a value back to the code that called this function, then stops the function. |
| 77 | `    return "LOW"` | Sends a value back to the code that called this function, then stops the function. |
| 78 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 79 | `def build_alert(ip: str, matching_events: list[dict], window_hits: list) -> dict:` | Starts a function named `build_alert`. The indented lines below it are grouped together and run only when this function is called. |
| 80 | `    first_seen = window_hits[0].isoformat()` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 81 | `    last_seen  = window_hits[-1].isoformat()` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 82 | `    count      = len(window_hits)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 83 | `    severity   = calculate_severity(count)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 84 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 85 | `    # Get target user from the first matching event` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 86 | `    sample_message  = matching_events[0].get("message", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 87 | `    target_user     = extract_target_user(sample_message)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 88 | `    target_host     = matching_events[0].get("hostname", "unknown")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 89 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 90 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 91 | `        "created_at":     datetime.now().isoformat(),` | Creates the current time and converts it to a standard text format for storage. |
| 92 | `        "alert_type":     "brute_force",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 93 | `        "severity":       severity,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 94 | `        "confidence":     "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 95 | `        "source_ip":      ip,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 96 | `        "target_host":    target_host,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 97 | `        "target_user":    target_user,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 98 | `        "description": (` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 99 | `            f"Brute force: {ip} made {count} failed login attempts "` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 100 | `            f"targeting '{target_user}' on {target_host} within {WINDOW_SECS}s"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 101 | `        ),` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 102 | `        "event_count":    count,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 103 | `        "window_secs":    WINDOW_SECS,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 104 | `        "first_seen":     first_seen,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 105 | `        "last_seen":      last_seen,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 106 | `        "attack_id":      "T1110.001",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 107 | `        "attack_name":    "Brute Force: Password Guessing",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 108 | `        "attack_tactic":  "Credential Access",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 109 | `        "raw_events":     [e["raw"] for e in matching_events[:10]],` | List comprehension. It builds a new list from another collection in one compact line; this can be rewritten as a normal for loop for easier explanation. |
| 110 | `        "remediation":    (` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 111 | `            f"1. Block {ip} at firewall: \`iptables -A INPUT -s {ip} -j DROP\`\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 112 | `            f"2. Check if '{target_user}' account was compromised\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 113 | `            f"3. Review full auth.log around {first_seen}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 114 | `            f"4. Consider installing fail2ban"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 115 | `        ),` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 116 | `        "status":         "open",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 117 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 118 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 119 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 120 | `def detect_brute_force() -> list[dict]:` | Starts a function named `detect_brute_force`. The indented lines below it are grouped together and run only when this function is called. |
| 121 | `    """Main entry point. Returns a list of alert dicts."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 122 | `    events = fetch_failed_logins()` | Stores a list of events. In this project, an event usually means one parsed log line. |
| 123 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 124 | `    if not events:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 125 | `        print("[brute_force] No failed login events found.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 126 | `        return []` | Sends a value back to the code that called this function, then stops the function. |
| 127 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 128 | `    # Group events by attacker IP` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 129 | `    ip_events: dict[str, list] = defaultdict(list)` | Creates a dictionary where each new key automatically starts with an empty list. |
| 130 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 131 | `    for e in events:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 132 | `        ip = e.get("source_ip") or extract_ip_from_message(e.get("message", ""))` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 133 | `        if not ip:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 134 | `            continue` | Skips the rest of the current loop cycle and moves to the next item. |
| 135 | `        try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 136 | `            ts = datetime.fromisoformat(e["timestamp"])` | Converts an ISO-format timestamp string back into a Python datetime object. |
| 137 | `        except (ValueError, TypeError):` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 138 | `            continue` | Skips the rest of the current loop cycle and moves to the next item. |
| 139 | `        ip_events[ip].append((ts, e))` | Adds one item to the end of a list. |
| 140 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 141 | `    alerts = []` | Creates or stores a list of alerts generated by a detector. |
| 142 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 143 | `    for ip, ts_event_pairs in ip_events.items():` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 144 | `        ts_event_pairs.sort(key=lambda x: x[0])` | Uses a small unnamed function. Here it is likely used to tell sorting code which part of each item should be used as the sort key. |
| 145 | `        timestamps = [ts for ts, _ in ts_event_pairs]` | List comprehension. It builds a new list from another collection in one compact line; this can be rewritten as a normal for loop for easier explanation. |
| 146 | `        matched_events = [ev for _, ev in ts_event_pairs]` | List comprehension. It builds a new list from another collection in one compact line; this can be rewritten as a normal for loop for easier explanation. |
| 147 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 148 | `        window_hits = sliding_window_check(timestamps)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 149 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 150 | `        if window_hits:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 151 | `            alert = build_alert(ip, matched_events, window_hits)` | Creates or stores one alert dictionary. |
| 152 | `            alerts.append(alert)` | Adds one item to the end of a list. |
| 153 | `            print(f"[ALERT] Brute force from {ip} — {len(window_hits)} hits in {WINDOW_SECS}s")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 154 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 155 | `    print(f"[brute_force] Scan complete. {len(alerts)} alert(s) generated.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 156 | `    return alerts` | Sends a value back to the code that called this function, then stops the function. |
| 157 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 158 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 159 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
