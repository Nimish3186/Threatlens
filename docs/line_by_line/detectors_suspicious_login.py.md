# Line-by-Line Explanation: detectors/suspicious_login.py

This file explains every line in `detectors/suspicious_login.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `import re` | Imports the re module so this file can use its built-in functions or classes later. |
| 2 | `import sys` | Imports the sys module so this file can use its built-in functions or classes later. |
| 3 | `import sqlite3` | Imports the sqlite3 module so this file can use its built-in functions or classes later. |
| 4 | `import json` | Imports the json module so this file can use its built-in functions or classes later. |
| 5 | `from datetime import datetime, timedelta` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 6 | `from collections import defaultdict` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 7 | `from pathlib import Path` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 8 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 9 | `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))` | Adds the project folder to Python import search paths. This helps imports work even when the script is run from a different folder, but it is a bit advanced-looking. |
| 10 | `from database.storage import DB_PATH` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 11 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 12 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 13 | `#  TUNABLE CONFIG` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 14 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 15 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 16 | `SCORE_THRESHOLD   = 50    # minimum risk score to fire an alert` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 17 | `OFF_HOURS_START   = 0     # midnight` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 18 | `OFF_HOURS_END     = 5     # 5 am` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 19 | `FAIL_WINDOW_SECS  = 300   # look back 5 min for failures before a success` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 20 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 21 | `# Risk points per signal` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 22 | `POINTS = {` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 23 | `    "off_hours":        30,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 24 | `    "root_login":       50,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 25 | `    "new_ip":           25,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 26 | `    "fail_then_success":40,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 27 | `    "multi_account":    35,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 28 | `}` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 29 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 30 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 31 | `#  REGEX PATTERNS` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 32 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 33 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 34 | `# Accepted password for nimish from 192.168.1.25 port 52134 ssh2` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 35 | `SUCCESS_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 36 | `    r'Accepted (?:password&#124;publickey&#124;keyboard-interactive) for (?P<user>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 37 | `    r' from (?P<ip>[\d.]+) port (?P<port>\d+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 38 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 39 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 40 | `# Failed password for root from 203.0.113.45 port 51422 ssh2` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 41 | `FAILURE_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 42 | `    r'Failed password for (?:invalid user )?(?P<user>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 43 | `    r' from (?P<ip>[\d.]+) port (?P<port>\d+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 44 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 45 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 46 | `# session opened for user root` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 47 | `ROOT_SESSION_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 48 | `    r'session opened for user (?P<user>root)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 49 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 50 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 51 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 52 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 53 | `#  FETCH EVENTS FROM DB` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 54 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 55 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 56 | `def fetch_login_events() -> list[dict]:` | Starts a function named `fetch_login_events`. The indented lines below it are grouped together and run only when this function is called. |
| 57 | `    """Pull all successful and failed login events."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 58 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 59 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 60 | `    rows = conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 61 | `        SELECT * FROM events` | Begins an SQL query that reads rows from a database table. |
| 62 | `        WHERE (` | Adds filtering rules to an SQL query so only matching rows are returned. |
| 63 | `            message LIKE '%Accepted password%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 64 | `            OR message LIKE '%Accepted publickey%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 65 | `            OR message LIKE '%Accepted keyboard-interactive%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 66 | `            OR message LIKE '%Failed password%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 67 | `            OR message LIKE '%session opened for user%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 68 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 69 | `        AND timestamp IS NOT NULL` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 70 | `        ORDER BY timestamp ASC` | Sorts database results by a column, such as timestamp or creation time. |
| 71 | `    """).fetchall()` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 72 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 73 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 74 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 75 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 76 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 77 | `#  EXTRACT KNOWN IPs FROM HISTORY` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 78 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 79 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 80 | `def build_known_ips(events: list[dict]) -> set[str]:` | Starts a function named `build_known_ips`. The indented lines below it are grouped together and run only when this function is called. |
| 81 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 82 | `    Build a set of IPs that have successfully logged in before.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 83 | `    Used to detect first-time IPs.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 84 | `    In production you'd persist this — for now we build it from` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 85 | `    the earliest 50% of events as our 'history'.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 86 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 87 | `    known = set()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 88 | `    cutoff = len(events) // 2` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 89 | `    for event in events[:cutoff]:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 90 | `        msg = event.get("message", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 91 | `        m = SUCCESS_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 92 | `        if m:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 93 | `            known.add(m.group("ip"))` | Reads one captured value from a regex match, such as the username or IP address. |
| 94 | `    return known` | Sends a value back to the code that called this function, then stops the function. |
| 95 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 96 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 97 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 98 | `#  CLASSIFY ONE SUCCESSFUL LOGIN` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 99 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 100 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 101 | `def score_login(` | Starts a function named `score_login`. The indented lines below it are grouped together and run only when this function is called. |
| 102 | `    event: dict,` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 103 | `    all_events: list[dict],` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 104 | `    known_ips: set[str],` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 105 | `    failure_index: dict,     # ip -> list of failure timestamps` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 106 | `    spray_index: dict,       # ip -> set of usernames attempted` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 107 | `) -> dict &#124; None:` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 108 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 109 | `    Score a single successful login event.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 110 | `    Returns a signal dict if score >= threshold, else None.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 111 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 112 | `    msg  = event.get("message", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 113 | `    ts   = event.get("timestamp", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 114 | `    host = event.get("hostname", "unknown")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 115 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 116 | `    # Try to parse as a successful login` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 117 | `    m = SUCCESS_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 118 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 119 | `    # Also catch root session opened (PAM)` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 120 | `    is_root_session = bool(ROOT_SESSION_PATTERN.search(msg))` | Applies a regular expression to text to see whether the expected pattern exists. |
| 121 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 122 | `    if not m and not is_root_session:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 123 | `        return None` | Sends a value back to the code that called this function, then stops the function. |
| 124 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 125 | `    if m:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 126 | `        user = m.group("user")` | Reads one captured value from a regex match, such as the username or IP address. |
| 127 | `        ip   = m.group("ip")` | Reads one captured value from a regex match, such as the username or IP address. |
| 128 | `    else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 129 | `        user = "root"` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 130 | `        ip   = event.get("source_ip") or host` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 131 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 132 | `    try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 133 | `        login_time = datetime.fromisoformat(ts)` | Converts an ISO-format timestamp string back into a Python datetime object. |
| 134 | `    except (ValueError, TypeError):` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 135 | `        return None` | Sends a value back to the code that called this function, then stops the function. |
| 136 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 137 | `    signals = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 138 | `    score   = 0` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 139 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 140 | `    # ── Signal 1: off-hours login ──────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 141 | `    hour = login_time.hour` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 142 | `    if OFF_HOURS_START <= hour < OFF_HOURS_END:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 143 | `        score += POINTS["off_hours"]` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 144 | `        signals.append(f"off-hours login ({hour:02d}:xx)")` | Adds one item to the end of a list. |
| 145 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 146 | `    # ── Signal 2: direct root login ────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 147 | `    if user == "root" or is_root_session:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 148 | `        score += POINTS["root_login"]` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 149 | `        signals.append("direct root login")` | Adds one item to the end of a list. |
| 150 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 151 | `    # ── Signal 3: never-seen-before IP ────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 152 | `    if ip and ip not in known_ips:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 153 | `        score += POINTS["new_ip"]` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 154 | `        signals.append(f"new source IP ({ip})")` | Adds one item to the end of a list. |
| 155 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 156 | `    # ── Signal 4: failures immediately before success ──────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 157 | `    if ip and ip in failure_index:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 158 | `        window_start = login_time - timedelta(seconds=FAIL_WINDOW_SECS)` | Creates or uses a time duration, such as a number of seconds or minutes. |
| 159 | `        recent_fails = [` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 160 | `            t for t in failure_index[ip]` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 161 | `            if window_start <= t <= login_time` | Starts a condition. Python runs the indented block below only if this test is true. |
| 162 | `        ]` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 163 | `        if recent_fails:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 164 | `            score += POINTS["fail_then_success"]` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 165 | `            signals.append(` | Adds one item to the end of a list. |
| 166 | `                f"{len(recent_fails)} failure(s) before success within {FAIL_WINDOW_SECS}s"` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 167 | `            )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 168 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 169 | `    # ── Signal 5: multi-account spray from same IP ─────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 170 | `    if ip and ip in spray_index:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 171 | `        accounts = spray_index[ip]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 172 | `        if len(accounts) >= 3:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 173 | `            score += POINTS["multi_account"]` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 174 | `            signals.append(` | Adds one item to the end of a list. |
| 175 | `                f"password spray: {len(accounts)} accounts tried from {ip}"` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 176 | `            )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 177 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 178 | `    if score < SCORE_THRESHOLD:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 179 | `        return None` | Sends a value back to the code that called this function, then stops the function. |
| 180 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 181 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 182 | `        "user":    user,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 183 | `        "ip":      ip,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 184 | `        "ts":      ts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 185 | `        "host":    host,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 186 | `        "score":   score,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 187 | `        "signals": signals,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 188 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 189 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 190 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 191 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 192 | `#  SEVERITY FROM SCORE` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 193 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 194 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 195 | `def severity_from_score(score: int) -> str:` | Starts a function named `severity_from_score`. The indented lines below it are grouped together and run only when this function is called. |
| 196 | `    if score >= 100: return "CRITICAL"` | Starts a condition. Python runs the indented block below only if this test is true. |
| 197 | `    if score >= 75:  return "HIGH"` | Starts a condition. Python runs the indented block below only if this test is true. |
| 198 | `    return "MEDIUM"` | Sends a value back to the code that called this function, then stops the function. |
| 199 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 200 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 201 | `def confidence_from_signals(signals: list[str]) -> str:` | Starts a function named `confidence_from_signals`. The indented lines below it are grouped together and run only when this function is called. |
| 202 | `    if len(signals) >= 3: return "HIGH"` | Starts a condition. Python runs the indented block below only if this test is true. |
| 203 | `    if len(signals) == 2: return "MEDIUM"` | Starts a condition. Python runs the indented block below only if this test is true. |
| 204 | `    return "LOW"` | Sends a value back to the code that called this function, then stops the function. |
| 205 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 206 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 207 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 208 | `#  BUILD ALERT` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 209 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 210 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 211 | `def build_suspicious_login_alert(result: dict, raw_event: dict) -> dict:` | Starts a function named `build_suspicious_login_alert`. The indented lines below it are grouped together and run only when this function is called. |
| 212 | `    user    = result["user"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 213 | `    ip      = result["ip"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 214 | `    host    = result["host"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 215 | `    score   = result["score"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 216 | `    signals = result["signals"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 217 | `    ts      = result["ts"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 218 | `    sev     = severity_from_score(score)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 219 | `    conf    = confidence_from_signals(signals)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 220 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 221 | `    signals_text = "; ".join(signals)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 222 | `    description  = (` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 223 | `        f"Suspicious login: '{user}' from {ip} on {host} "` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 224 | `        f"(risk score {score}) — {signals_text}"` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 225 | `    )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 226 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 227 | `    attack_id, attack_name, tactic = pick_attack(signals)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 228 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 229 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 230 | `        "created_at":    datetime.now().isoformat(),` | Creates the current time and converts it to a standard text format for storage. |
| 231 | `        "alert_type":    "suspicious_login",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 232 | `        "severity":      sev,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 233 | `        "confidence":    conf,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 234 | `        "source_ip":     ip,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 235 | `        "target_host":   host,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 236 | `        "target_user":   user,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 237 | `        "description":   description,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 238 | `        "event_count":   1,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 239 | `        "window_secs":   FAIL_WINDOW_SECS,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 240 | `        "first_seen":    ts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 241 | `        "last_seen":     ts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 242 | `        "attack_id":     attack_id,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 243 | `        "attack_name":   attack_name,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 244 | `        "attack_tactic": tactic,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 245 | `        "raw_events":    [raw_event.get("raw", "")],` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 246 | `        "remediation":   build_remediation(user, ip, host, signals, sev),` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 247 | `        "status":        "open",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 248 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 249 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 250 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 251 | `def pick_attack(signals: list[str]) -> tuple[str, str, str]:` | Starts a function named `pick_attack`. The indented lines below it are grouped together and run only when this function is called. |
| 252 | `    """Pick the most relevant ATT&CK technique based on active signals."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 253 | `    if any("spray" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 254 | `        return "T1110.003", "Brute Force: Password Spraying", "Credential Access"` | Sends a value back to the code that called this function, then stops the function. |
| 255 | `    if any("root" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 256 | `        return "T1078.003", "Valid Accounts: Local Accounts", "Privilege Escalation"` | Sends a value back to the code that called this function, then stops the function. |
| 257 | `    if any("failure" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 258 | `        return "T1110.001", "Brute Force: Password Guessing", "Credential Access"` | Sends a value back to the code that called this function, then stops the function. |
| 259 | `    return "T1078", "Valid Accounts", "Defense Evasion"` | Sends a value back to the code that called this function, then stops the function. |
| 260 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 261 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 262 | `def build_remediation(` | Starts a function named `build_remediation`. The indented lines below it are grouped together and run only when this function is called. |
| 263 | `    user: str, ip: str, host: str, signals: list[str], severity: str` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 264 | `) -> str:` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 265 | `    steps = [f"1. Verify if '{user}' login from {ip} on {host} was authorized"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 266 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 267 | `    if any("root" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 268 | `        steps.append("2. Disable direct root SSH: set PermitRootLogin no in /etc/ssh/sshd_config")` | Adds one item to the end of a list. |
| 269 | `        steps.append("3. Check /root/.ssh/authorized_keys for unauthorized keys")` | Adds one item to the end of a list. |
| 270 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 271 | `    if any("failure" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 272 | `        steps.append(f"4. Investigate failures from {ip} — possible credential theft")` | Adds one item to the end of a list. |
| 273 | `        steps.append(f"5. Block {ip}: iptables -A INPUT -s {ip} -j DROP")` | Adds one item to the end of a list. |
| 274 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 275 | `    if any("spray" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 276 | `        steps.append("6. Audit all accounts for unauthorized access")` | Adds one item to the end of a list. |
| 277 | `        steps.append("7. Force password reset for all targeted accounts")` | Adds one item to the end of a list. |
| 278 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 279 | `    if any("off-hours" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 280 | `        steps.append("8. Confirm with user whether login was expected at this hour")` | Adds one item to the end of a list. |
| 281 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 282 | `    if any("new" in s and "IP" in s for s in signals):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 283 | `        steps.append(f"9. Geolocate {ip} and verify it matches user's expected location")` | Adds one item to the end of a list. |
| 284 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 285 | `    if severity == "CRITICAL":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 286 | `        steps.append("10. CRITICAL: Consider isolating host and initiating incident response")` | Adds one item to the end of a list. |
| 287 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 288 | `    return "\n".join(steps)` | Sends a value back to the code that called this function, then stops the function. |
| 289 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 290 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 291 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 292 | `#  MAIN ENTRY POINT` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 293 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 294 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 295 | `def detect_suspicious_logins() -> list[dict]:` | Starts a function named `detect_suspicious_logins`. The indented lines below it are grouped together and run only when this function is called. |
| 296 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 297 | `    Main detector. Fetches events, builds indexes,` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 298 | `    scores each successful login, returns alert dicts.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 299 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 300 | `    events = fetch_login_events()` | Stores a list of events. In this project, an event usually means one parsed log line. |
| 301 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 302 | `    if not events:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 303 | `        print("[suspicious_login] No login events found in DB.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 304 | `        return []` | Sends a value back to the code that called this function, then stops the function. |
| 305 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 306 | `    print(f"[suspicious_login] Scanning {len(events)} login events...")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 307 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 308 | `    # Build lookup indexes in one pass` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 309 | `    known_ips     = build_known_ips(events)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 310 | `    failure_index = defaultdict(list)   # ip -> [datetime, ...]` | Creates a dictionary where each new key automatically starts with an empty list. |
| 311 | `    spray_index   = defaultdict(set)    # ip -> {username, ...}` | Creates a dictionary where each new key automatically starts with an empty set of unique values. |
| 312 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 313 | `    for e in events:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 314 | `        msg = e.get("message", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 315 | `        ts  = e.get("timestamp")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 316 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 317 | `        fail_m = FAILURE_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 318 | `        if fail_m and ts:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 319 | `            try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 320 | `                failure_index[fail_m.group("ip")].append(` | Reads one captured value from a regex match, such as the username or IP address. |
| 321 | `                    datetime.fromisoformat(ts)` | Converts an ISO-format timestamp string back into a Python datetime object. |
| 322 | `                )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 323 | `                spray_index[fail_m.group("ip")].add(fail_m.group("user"))` | Reads one captured value from a regex match, such as the username or IP address. |
| 324 | `            except ValueError:` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 325 | `                pass` | Does nothing. It is used as a placeholder where Python requires a statement. |
| 326 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 327 | `    # Score every successful login` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 328 | `    alerts = []` | Creates or stores a list of alerts generated by a detector. |
| 329 | `    seen   = set()  # deduplicate same user+ip within same minute` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 330 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 331 | `    for event in events:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 332 | `        result = score_login(` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 333 | `            event, events, known_ips, failure_index, spray_index` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 334 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 335 | `        if not result:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 336 | `            continue` | Skips the rest of the current loop cycle and moves to the next item. |
| 337 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 338 | `        dedup_key = (result["user"], result["ip"], result["ts"][:16])` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 339 | `        if dedup_key in seen:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 340 | `            continue` | Skips the rest of the current loop cycle and moves to the next item. |
| 341 | `        seen.add(dedup_key)` | Adds one item to a set. Sets keep only unique values. |
| 342 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 343 | `        alert = build_suspicious_login_alert(result, event)` | Creates or stores one alert dictionary. |
| 344 | `        alerts.append(alert)` | Adds one item to the end of a list. |
| 345 | `        print(` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 346 | `            f"  [ALERT] {alert['severity']} (score {result['score']}) — "` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 347 | `            f"{result['user']}@{result['ip']} — {'; '.join(result['signals'])}"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 348 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 349 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 350 | `    print(f"[suspicious_login] Scan complete. {len(alerts)} alert(s) generated.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 351 | `    return alerts` | Sends a value back to the code that called this function, then stops the function. |
| 352 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 353 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 354 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 355 | `#  QUICK TEST — python detectors/suspicious_login.py` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 356 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 357 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 358 | `if __name__ == "__main__":` | Checks whether this file is being run directly. Code inside this block runs only when you execute this file, not when another file imports it. |
| 359 | `    from database.storage import init_db, insert_events, insert_alert, get_alerts, clear_all` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 360 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 361 | `    init_db()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 362 | `    clear_all()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 363 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 364 | `    base = datetime(2025, 6, 27)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 365 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 366 | `    fake_events = [` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 367 | `        # ── Normal daytime login (should NOT alert) ──────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 368 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 369 | `            "log_type": "syslog", "timestamp": (base.replace(hour=9, minute=0)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 370 | `            "hostname": "kali-system", "source_ip": "192.168.1.25",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 371 | `            "process": "sshd", "pid": "1301", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 372 | `            "Accepted password for nimish from 192.168.1.25 port 52134 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 373 | `            "raw": "Jun 27 09:00:00 kali-system sshd[1301]: Accepted password for nimish from 192.168.1.25 port 52134 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 374 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 375 | `        # ── Off-hours login from same known IP (MEDIUM — off hours only) ─` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 376 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 377 | `            "log_type": "syslog", "timestamp": (base.replace(hour=2, minute=15)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 378 | `            "hostname": "kali-system", "source_ip": "192.168.1.25",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 379 | `            "process": "sshd", "pid": "1310", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 380 | `            "Accepted password for nimish from 192.168.1.25 port 52200 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 381 | `            "raw": "Jun 27 02:15:00 kali-system sshd[1310]: Accepted password for nimish from 192.168.1.25 port 52200 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 382 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 383 | `        # ── 3 failures then success from attacker IP (HIGH) ──────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 384 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 385 | `            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=0)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 386 | `            "hostname": "kali-system", "source_ip": "203.0.113.45",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 387 | `            "process": "sshd", "pid": "1400", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 388 | `            "Failed password for nimish from 203.0.113.45 port 51000 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 389 | `            "raw": "Jun 27 03:00:00 kali-system sshd[1400]: Failed password for nimish from 203.0.113.45 port 51000 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 390 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 391 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 392 | `            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=1)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 393 | `            "hostname": "kali-system", "source_ip": "203.0.113.45",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 394 | `            "process": "sshd", "pid": "1401", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 395 | `            "Failed password for nimish from 203.0.113.45 port 51001 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 396 | `            "raw": "Jun 27 03:01:00 kali-system sshd[1401]: Failed password for nimish from 203.0.113.45 port 51001 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 397 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 398 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 399 | `            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=2)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 400 | `            "hostname": "kali-system", "source_ip": "203.0.113.45",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 401 | `            "process": "sshd", "pid": "1402", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 402 | `            "Failed password for nimish from 203.0.113.45 port 51002 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 403 | `            "raw": "Jun 27 03:02:00 kali-system sshd[1402]: Failed password for nimish from 203.0.113.45 port 51002 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 404 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 405 | `        {   # success after failures — HIGH (off-hours + new IP + fail-then-success)` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 406 | `            "log_type": "syslog", "timestamp": (base.replace(hour=3, minute=3)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 407 | `            "hostname": "kali-system", "source_ip": "203.0.113.45",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 408 | `            "process": "sshd", "pid": "1403", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 409 | `            "Accepted password for nimish from 203.0.113.45 port 51003 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 410 | `            "raw": "Jun 27 03:03:00 kali-system sshd[1403]: Accepted password for nimish from 203.0.113.45 port 51003 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 411 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 412 | `        # ── Password spray then success (CRITICAL) ───────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 413 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 414 | `            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=0)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 415 | `            "hostname": "kali-system", "source_ip": "10.0.0.99",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 416 | `            "process": "sshd", "pid": "1500", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 417 | `            "Failed password for admin from 10.0.0.99 port 60000 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 418 | `            "raw": "Jun 27 01:00:00 kali-system sshd[1500]: Failed password for admin from 10.0.0.99 port 60000 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 419 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 420 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 421 | `            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=1)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 422 | `            "hostname": "kali-system", "source_ip": "10.0.0.99",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 423 | `            "process": "sshd", "pid": "1501", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 424 | `            "Failed password for ubuntu from 10.0.0.99 port 60001 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 425 | `            "raw": "Jun 27 01:01:00 kali-system sshd[1501]: Failed password for ubuntu from 10.0.0.99 port 60001 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 426 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 427 | `        {` | Starts returning or creating a dictionary. The following lines define key-value pairs. |
| 428 | `            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=2)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 429 | `            "hostname": "kali-system", "source_ip": "10.0.0.99",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 430 | `            "process": "sshd", "pid": "1502", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 431 | `            "Failed password for guest from 10.0.0.99 port 60002 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 432 | `            "raw": "Jun 27 01:02:00 kali-system sshd[1502]: Failed password for guest from 10.0.0.99 port 60002 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 433 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 434 | `        {   # root login after spray at 1am — CRITICAL` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 435 | `            "log_type": "syslog", "timestamp": (base.replace(hour=1, minute=3)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 436 | `            "hostname": "kali-system", "source_ip": "10.0.0.99",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 437 | `            "process": "sshd", "pid": "1503", "message":` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 438 | `            "Accepted password for root from 10.0.0.99 port 60003 ssh2",` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 439 | `            "raw": "Jun 27 01:03:00 kali-system sshd[1503]: Accepted password for root from 10.0.0.99 port 60003 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 440 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 441 | `    ]` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 442 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 443 | `    insert_events(fake_events)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 444 | `    alerts = detect_suspicious_logins()` | Creates or stores a list of alerts generated by a detector. |
| 445 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 446 | `    for a in alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 447 | `        insert_alert(a)` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 448 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 449 | `    print(f"\n=== {len(alerts)} ALERT(S) STORED ===")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 450 | `    for a in get_alerts():` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 451 | `        if a["alert_type"] == "suspicious_login":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 452 | `            print(f"\n  [{a['severity']}] score — {a['description'][:80]}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 453 | `            print(f"  ATT&CK : {a['attack_id']} — {a['attack_name']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 454 | `            print(f"  Fix    : {a['remediation'].splitlines()[0]}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
