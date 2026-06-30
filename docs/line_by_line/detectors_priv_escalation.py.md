# Line-by-Line Explanation: detectors/priv_escalation.py

This file explains every line in `detectors/priv_escalation.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `import re` | Imports the re module so this file can use its built-in functions or classes later. |
| 2 | `import sys` | Imports the sys module so this file can use its built-in functions or classes later. |
| 3 | `import os` | Imports the os module so this file can use its built-in functions or classes later. |
| 4 | `from datetime import datetime, timedelta` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 5 | `from collections import defaultdict` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 6 | `from pathlib import Path` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 7 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 8 | `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))` | Adds the project folder to Python import search paths. This helps imports work even when the script is run from a different folder, but it is a bit advanced-looking. |
| 9 | `from database.storage import DB_PATH, get_failed_logins` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 10 | `import sqlite3` | Imports the sqlite3 module so this file can use its built-in functions or classes later. |
| 11 | `import json` | Imports the json module so this file can use its built-in functions or classes later. |
| 12 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 13 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 14 | `#  TUNABLE CONFIG` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 15 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 16 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 17 | `WINDOW_SECS = 300   # 5-minute window for correlating related events` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 18 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 19 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 20 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 21 | `#  DANGEROUS COMMANDS — any sudo use of these is an escalation signal` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 22 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 23 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 24 | `DANGEROUS_COMMANDS = [` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 25 | `    "/bin/bash", "/bin/sh", "/bin/zsh",          # shell spawn as root` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 26 | `    "/bin/su",                                    # su inside sudo` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 27 | `    "/usr/bin/passwd",                            # changing passwords` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 28 | `    "/bin/chmod",  "/usr/bin/chmod",             # permission changes` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 29 | `    "/bin/chown",  "/usr/bin/chown",` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 30 | `    "/etc/sudoers", "/etc/passwd", "/etc/shadow", # sensitive file edits` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 31 | `    "/usr/sbin/useradd", "/usr/sbin/usermod",    # account manipulation` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 32 | `    "/usr/sbin/visudo",` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 33 | `    "python", "python3", "perl", "ruby",          # script interpreters (GTFOBins)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 34 | `    "awk", "vim", "vi", "nano", "less", "more",  # editors that can spawn shells` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 35 | `    "find", "curl", "wget",                       # common GTFOBins` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 36 | `]` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 37 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 38 | `CRITICAL_FILES = [` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 39 | `    "/etc/sudoers", "/etc/passwd", "/etc/shadow",` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 40 | `    "/etc/crontab", "/etc/cron.d", "/root/.ssh",` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 41 | `]` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 42 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 43 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 44 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 45 | `#  REGEX PATTERNS` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 46 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 47 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 48 | `# sudo: nimish : TTY=pts/0 ; PWD=/home/nimish ; USER=root ; COMMAND=/bin/bash` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 49 | `SUDO_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 50 | `    r'(?P<user>\S+)\s*:\s*TTY=\S+\s*;.*?USER=(?P<target_user>\S+)\s*;'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 51 | `    r'\s*COMMAND=(?P<command>.+)$'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 52 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 53 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 54 | `# su: Successful su for root by nimish` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 55 | `SU_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 56 | `    r'(?:Successful su for&#124;session opened for user)\s+(?P<target_user>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 57 | `    r'(?:\s+by\s+(?P<user>\S+))?'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 58 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 59 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 60 | `# pam session opened for root` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 61 | `PAM_ROOT_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 62 | `    r'session opened for user\s+(?P<target_user>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 63 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 64 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 65 | `# chmod with wide permissions` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 66 | `CHMOD_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 67 | `    r'COMMAND=.*?chmod\s+(?P<perms>[0-9]+&#124;[ugoa][+\-=][rwxst]+)\s+(?P<path>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 68 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 69 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 70 | `# new user / group added` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 71 | `USERADD_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 72 | `    r'new (?:user&#124;group):\s+name=(?P<newuser>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 73 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 74 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 75 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 76 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 77 | `#  FETCH EVENTS FROM DB` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 78 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 79 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 80 | `def fetch_priv_events() -> list[dict]:` | Starts a function named `fetch_priv_events`. The indented lines below it are grouped together and run only when this function is called. |
| 81 | `    """Pull all potentially relevant events from the events table."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 82 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 83 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 84 | `    rows = conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 85 | `        SELECT * FROM events` | Begins an SQL query that reads rows from a database table. |
| 86 | `        WHERE (` | Adds filtering rules to an SQL query so only matching rows are returned. |
| 87 | `            message LIKE '%sudo%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 88 | `            OR message LIKE '%su for%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 89 | `            OR message LIKE '%session opened for user root%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 90 | `            OR message LIKE '%COMMAND=%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 91 | `            OR message LIKE '%new user%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 92 | `            OR message LIKE '%new group%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 93 | `            OR message LIKE '%useradd%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 94 | `            OR message LIKE '%usermod%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 95 | `            OR message LIKE '%passwd%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 96 | `            OR message LIKE '%sudoers%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 97 | `            OR message LIKE '%chmod%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 98 | `            OR message LIKE '%chown%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 99 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 100 | `        AND timestamp IS NOT NULL` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 101 | `        ORDER BY timestamp ASC` | Sorts database results by a column, such as timestamp or creation time. |
| 102 | `    """).fetchall()` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 103 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 104 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 105 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 106 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 107 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 108 | `#  CLASSIFY EACH EVENT` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 109 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 110 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 111 | `def classify_event(event: dict) -> dict &#124; None:` | Starts a function named `classify_event`. The indented lines below it are grouped together and run only when this function is called. |
| 112 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 113 | `    Inspect one event and return a classification dict if it looks` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 114 | `    like a privilege escalation signal. Returns None if not relevant.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 115 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 116 | `    msg = event.get("message", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 117 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 118 | `    # ── sudo execution ──────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 119 | `    sudo_match = SUDO_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 120 | `    if sudo_match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 121 | `        user        = sudo_match.group("user")` | Reads one captured value from a regex match, such as the username or IP address. |
| 122 | `        target_user = sudo_match.group("target_user")` | Reads one captured value from a regex match, such as the username or IP address. |
| 123 | `        command     = sudo_match.group("command").strip()` | Reads one captured value from a regex match, such as the username or IP address. |
| 124 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 125 | `        # Only care about sudo to root` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 126 | `        if target_user != "root":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 127 | `            return None` | Sends a value back to the code that called this function, then stops the function. |
| 128 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 129 | `        # Check if command is dangerous` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 130 | `        is_dangerous = any(danger in command for danger in DANGEROUS_COMMANDS)` | Checks whether at least one item in a group passes a condition. A beginner-friendly version would use a loop and a boolean flag. |
| 131 | `        touches_critical = any(f in command for f in CRITICAL_FILES)` | Checks whether at least one item in a group passes a condition. A beginner-friendly version would use a loop and a boolean flag. |
| 132 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 133 | `        severity   = "CRITICAL" if touches_critical else ("HIGH" if is_dangerous else "MEDIUM")` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 134 | `        confidence = "HIGH"     if is_dangerous     else "MEDIUM"` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 135 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 136 | `        return {` | Sends a value back to the code that called this function, then stops the function. |
| 137 | `            "subtype":      "sudo_to_root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 138 | `            "user":         user,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 139 | `            "target_user":  target_user,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 140 | `            "command":      command,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 141 | `            "severity":     severity,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 142 | `            "confidence":   confidence,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 143 | `            "attack_id":    "T1548.003",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 144 | `            "attack_name":  "Abuse Elevation Control: Sudo and Sudo Caching",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 145 | `            "attack_tactic":"Privilege Escalation",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 146 | `            "description":  f"User '{user}' ran sudo as root: {command}",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 147 | `        }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 148 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 149 | `    # ── su to root ──────────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 150 | `    su_match = SU_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 151 | `    if su_match and "su" in event.get("process", "").lower():` | Starts a condition. Python runs the indented block below only if this test is true. |
| 152 | `        target_user = su_match.group("target_user")` | Reads one captured value from a regex match, such as the username or IP address. |
| 153 | `        user        = su_match.group("user") or "unknown"` | Reads one captured value from a regex match, such as the username or IP address. |
| 154 | `        if target_user == "root":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 155 | `            return {` | Sends a value back to the code that called this function, then stops the function. |
| 156 | `                "subtype":      "su_to_root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 157 | `                "user":         user,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 158 | `                "target_user":  "root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 159 | `                "command":      "su root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 160 | `                "severity":     "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 161 | `                "confidence":   "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 162 | `                "attack_id":    "T1548.003",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 163 | `                "attack_name":  "Abuse Elevation Control: Sudo and Sudo Caching",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 164 | `                "attack_tactic":"Privilege Escalation",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 165 | `                "description":  f"User '{user}' switched to root via su",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 166 | `            }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 167 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 168 | `    # ── root SSH/PAM session opened ─────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 169 | `    if "session opened for user root" in msg:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 170 | `        return {` | Sends a value back to the code that called this function, then stops the function. |
| 171 | `            "subtype":      "root_session_opened",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 172 | `            "user":         "root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 173 | `            "target_user":  "root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 174 | `            "command":      "login",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 175 | `            "severity":     "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 176 | `            "confidence":   "MEDIUM",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 177 | `            "attack_id":    "T1078.003",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 178 | `            "attack_name":  "Valid Accounts: Local Accounts",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 179 | `            "attack_tactic":"Privilege Escalation",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 180 | `            "description":  "Root session opened — direct root login detected",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 181 | `        }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 182 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 183 | `    # ── chmod with dangerous permissions ────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 184 | `    chmod_match = CHMOD_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 185 | `    if chmod_match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 186 | `        perms = chmod_match.group("perms")` | Reads one captured value from a regex match, such as the username or IP address. |
| 187 | `        path  = chmod_match.group("path")` | Reads one captured value from a regex match, such as the username or IP address. |
| 188 | `        # Flag world-writable (777, 666, o+w) or SUID (4xxx, u+s)` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 189 | `        is_dangerous_perm = (` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 190 | `            "777" in perms or "666" in perms or` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 191 | `            "+w" in perms  or "4755" in perms or` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 192 | `            "u+s" in perms or "g+s" in perms` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 193 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 194 | `        if is_dangerous_perm:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 195 | `            return {` | Sends a value back to the code that called this function, then stops the function. |
| 196 | `                "subtype":      "dangerous_chmod",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 197 | `                "user":         event.get("process", "unknown"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 198 | `                "target_user":  "root",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 199 | `                "command":      f"chmod {perms} {path}",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 200 | `                "severity":     "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 201 | `                "confidence":   "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 202 | `                "attack_id":    "T1222.002",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 203 | `                "attack_name":  "File and Directory Permissions Modification: Linux",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 204 | `                "attack_tactic":"Defense Evasion",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 205 | `                "description":  f"Dangerous permission change: chmod {perms} {path}",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 206 | `            }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 207 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 208 | `    # ── new user/group created ───────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 209 | `    useradd_match = USERADD_PATTERN.search(msg)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 210 | `    if useradd_match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 211 | `        newuser = useradd_match.group("newuser")` | Reads one captured value from a regex match, such as the username or IP address. |
| 212 | `        return {` | Sends a value back to the code that called this function, then stops the function. |
| 213 | `            "subtype":      "new_account_created",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 214 | `            "user":         event.get("process", "unknown"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 215 | `            "target_user":  newuser,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 216 | `            "command":      f"useradd {newuser}",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 217 | `            "severity":     "MEDIUM",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 218 | `            "confidence":   "HIGH",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 219 | `            "attack_id":    "T1136.001",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 220 | `            "attack_name":  "Create Account: Local Account",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 221 | `            "attack_tactic":"Persistence",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 222 | `            "description":  f"New local account created: '{newuser}'",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 223 | `        }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 224 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 225 | `    return None` | Sends a value back to the code that called this function, then stops the function. |
| 226 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 227 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 228 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 229 | `#  BUILD ALERT` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 230 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 231 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 232 | `def build_priv_alert(event: dict, classification: dict) -> dict:` | Starts a function named `build_priv_alert`. The indented lines below it are grouped together and run only when this function is called. |
| 233 | `    """Combine a raw event with its classification into a full alert dict."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 234 | `    hostname = event.get("hostname", "unknown")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 235 | `    ip       = event.get("source_ip", "")` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 236 | `    ts       = event.get("timestamp", datetime.now().isoformat())` | Creates the current time and converts it to a standard text format for storage. |
| 237 | `    user     = classification["user"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 238 | `    command  = classification["command"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 239 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 240 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 241 | `        "created_at":     datetime.now().isoformat(),` | Creates the current time and converts it to a standard text format for storage. |
| 242 | `        "alert_type":     "priv_escalation",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 243 | `        "severity":       classification["severity"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 244 | `        "confidence":     classification["confidence"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 245 | `        "source_ip":      ip or hostname,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 246 | `        "target_host":    hostname,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 247 | `        "target_user":    classification["target_user"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 248 | `        "description":    classification["description"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 249 | `        "event_count":    1,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 250 | `        "window_secs":    0,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 251 | `        "first_seen":     ts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 252 | `        "last_seen":      ts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 253 | `        "attack_id":      classification["attack_id"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 254 | `        "attack_name":    classification["attack_name"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 255 | `        "attack_tactic":  classification["attack_tactic"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 256 | `        "raw_events":     [event.get("raw", "")],` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 257 | `        "remediation":    build_remediation(classification, hostname, user, command),` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 258 | `        "status":         "open",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 259 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 260 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 261 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 262 | `def build_remediation(cls: dict, host: str, user: str, command: str) -> str:` | Starts a function named `build_remediation`. The indented lines below it are grouped together and run only when this function is called. |
| 263 | `    subtype = cls["subtype"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 264 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 265 | `    if subtype == "sudo_to_root":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 266 | `        return (` | Sends a value back to the code that called this function, then stops the function. |
| 267 | `            f"1. Review sudo usage by '{user}' on {host}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 268 | `            f"2. Check if command was authorized: {command}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 269 | `            f"3. Audit /etc/sudoers: sudo visudo\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 270 | `            f"4. Review full session: ausearch -ua {user}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 271 | `            f"5. Consider restricting sudo with NOEXEC or specific command allowlist"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 272 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 273 | `    elif subtype == "su_to_root":` | Adds another condition to a previous if statement. Python checks this only if the earlier condition was false. |
| 274 | `        return (` | Sends a value back to the code that called this function, then stops the function. |
| 275 | `            f"1. Check who ran 'su root' on {host}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 276 | `            f"2. Verify root password has not been changed\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 277 | `            f"3. Consider disabling direct root login: passwd -l root\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 278 | `            f"4. Review PAM config: /etc/pam.d/su"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 279 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 280 | `    elif subtype == "root_session_opened":` | Adds another condition to a previous if statement. Python checks this only if the earlier condition was false. |
| 281 | `        return (` | Sends a value back to the code that called this function, then stops the function. |
| 282 | `            f"1. Check /var/log/auth.log for root login source IP\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 283 | `            f"2. Disable root SSH login: PermitRootLogin no in /etc/ssh/sshd_config\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 284 | `            f"3. Verify no unauthorized SSH keys in /root/.ssh/authorized_keys\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 285 | `            f"4. Restart SSH: systemctl restart sshd"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 286 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 287 | `    elif subtype == "dangerous_chmod":` | Adds another condition to a previous if statement. Python checks this only if the earlier condition was false. |
| 288 | `        return (` | Sends a value back to the code that called this function, then stops the function. |
| 289 | `            f"1. Review the permission change: {command}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 290 | `            f"2. Revert if unauthorized: chmod 644 <file>\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 291 | `            f"3. Check for SUID binaries: find / -perm -4000 -type f 2>/dev/null\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 292 | `            f"4. Audit who ran this command via auth.log"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 293 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 294 | `    elif subtype == "new_account_created":` | Adds another condition to a previous if statement. Python checks this only if the earlier condition was false. |
| 295 | `        return (` | Sends a value back to the code that called this function, then stops the function. |
| 296 | `            f"1. Verify account creation was authorized\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 297 | `            f"2. Check new account's groups: id {cls['target_user']}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 298 | `            f"3. If unauthorized: userdel -r {cls['target_user']}\n"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 299 | `            f"4. Review /etc/passwd for unexpected accounts"` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 300 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 301 | `    return "Review the event manually and check system audit logs."` | Sends a value back to the code that called this function, then stops the function. |
| 302 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 303 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 304 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 305 | `#  DEDUPLICATION` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 306 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 307 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 308 | `def deduplicate_alerts(alerts: list[dict]) -> list[dict]:` | Starts a function named `deduplicate_alerts`. The indented lines below it are grouped together and run only when this function is called. |
| 309 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 310 | `    If the same user ran the same command within WINDOW_SECS,` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 311 | `    collapse into one alert rather than firing 10 times for one session.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 312 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 313 | `    seen    = {}` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 314 | `    unique  = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 315 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 316 | `    for alert in alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 317 | `        key = (` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 318 | `            alert["target_host"],` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 319 | `            alert["target_user"],` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 320 | `            alert.get("description", "")[:60],   # first 60 chars of description` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 321 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 322 | `        ts = alert["first_seen"]` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 323 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 324 | `        if key in seen:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 325 | `            last_ts = datetime.fromisoformat(seen[key])` | Converts an ISO-format timestamp string back into a Python datetime object. |
| 326 | `            curr_ts = datetime.fromisoformat(ts)` | Converts an ISO-format timestamp string back into a Python datetime object. |
| 327 | `            if (curr_ts - last_ts).total_seconds() < WINDOW_SECS:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 328 | `                continue   # duplicate within window — skip` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 329 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 330 | `        seen[key] = ts` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 331 | `        unique.append(alert)` | Adds one item to the end of a list. |
| 332 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 333 | `    return unique` | Sends a value back to the code that called this function, then stops the function. |
| 334 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 335 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 336 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 337 | `#  MAIN ENTRY POINT` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 338 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 339 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 340 | `def detect_priv_escalation() -> list[dict]:` | Starts a function named `detect_priv_escalation`. The indented lines below it are grouped together and run only when this function is called. |
| 341 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 342 | `    Main detector function.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 343 | `    Fetches events, classifies each one, builds and deduplicates alerts.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 344 | `    Returns list of alert dicts ready to insert into DB.` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 345 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 346 | `    events = fetch_priv_events()` | Stores a list of events. In this project, an event usually means one parsed log line. |
| 347 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 348 | `    if not events:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 349 | `        print("[priv_escalation] No relevant events found in DB.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 350 | `        return []` | Sends a value back to the code that called this function, then stops the function. |
| 351 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 352 | `    print(f"[priv_escalation] Scanning {len(events)} candidate events...")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 353 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 354 | `    raw_alerts = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 355 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 356 | `    for event in events:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 357 | `        classification = classify_event(event)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 358 | `        if classification:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 359 | `            alert = build_priv_alert(event, classification)` | Creates or stores one alert dictionary. |
| 360 | `            raw_alerts.append(alert)` | Adds one item to the end of a list. |
| 361 | `            print(f"  [ALERT] {classification['severity']} — {classification['description']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 362 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 363 | `    alerts = deduplicate_alerts(raw_alerts)` | Creates or stores a list of alerts generated by a detector. |
| 364 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 365 | `    removed = len(raw_alerts) - len(alerts)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 366 | `    if removed:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 367 | `        print(f"[priv_escalation] Deduplicated {removed} duplicate alert(s)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 368 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 369 | `    print(f"[priv_escalation] Scan complete. {len(alerts)} alert(s) generated.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 370 | `    return alerts` | Sends a value back to the code that called this function, then stops the function. |
| 371 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 372 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 373 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 374 | `#  QUICK TEST — python detectors/priv_escalation.py` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 375 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 376 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 377 | `if __name__ == "__main__":` | Checks whether this file is being run directly. Code inside this block runs only when you execute this file, not when another file imports it. |
| 378 | `    from database.storage import init_db, insert_events, insert_alert, get_alerts` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 379 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 380 | `    init_db()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 381 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 382 | `    # Inject fake events that cover every detection subtype` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 383 | `    fake_events = [` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 384 | `        {   # sudo shell spawn — HIGH` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 385 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:17:45",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 386 | `            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1350",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 387 | `            "message": "nimish : TTY=pts/0 ; PWD=/home/nimish ; USER=root ; COMMAND=/bin/bash",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 388 | `            "raw": "Jun 27 10:17:45 kali-system sudo[1350]: nimish : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 389 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 390 | `        {   # sudoers edit — CRITICAL` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 391 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:21:05",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 392 | `            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1410",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 393 | `            "message": "nimish : TTY=pts/0 ; PWD=/home/nimish ; USER=root ; COMMAND=/bin/nano /etc/sudoers",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 394 | `            "raw": "Jun 27 10:21:05 kali-system sudo[1410]: nimish : USER=root ; COMMAND=/bin/nano /etc/sudoers",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 395 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 396 | `        {   # su to root — HIGH` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 397 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:18:01",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 398 | `            "hostname": "kali-system", "source_ip": "", "process": "su", "pid": "1401",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 399 | `            "message": "Successful su for root by nimish",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 400 | `            "raw": "Jun 27 10:18:01 kali-system su[1401]: Successful su for root by nimish",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 401 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 402 | `        {   # root session opened — HIGH` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 403 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:16:11",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 404 | `            "hostname": "kali-system", "source_ip": "203.0.113.45", "process": "sshd", "pid": "1301",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 405 | `            "message": "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 406 | `            "raw": "Jun 27 10:16:11 kali-system sshd[1301]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 407 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 408 | `        {   # dangerous chmod — HIGH` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 409 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:19:22",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 410 | `            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1402",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 411 | `            "message": "nimish : USER=root ; COMMAND=/bin/chmod 777 /etc/passwd",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 412 | `            "raw": "Jun 27 10:19:22 kali-system sudo[1402]: nimish : USER=root ; COMMAND=/bin/chmod 777 /etc/passwd",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 413 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 414 | `        {   # new user created — MEDIUM` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 415 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:22:30",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 416 | `            "hostname": "kali-system", "source_ip": "", "process": "useradd", "pid": "1450",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 417 | `            "message": "new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 418 | `            "raw": "Jun 27 10:22:30 kali-system useradd[1450]: new user: name=backdoor, UID=1337",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 419 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 420 | `        {   # safe sudo (apt update) — should NOT trigger` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 421 | `            "log_type": "syslog", "timestamp": "2025-06-27T10:17:46",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 422 | `            "hostname": "kali-system", "source_ip": "", "process": "sudo", "pid": "1350",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 423 | `            "message": "nimish : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 424 | `            "raw": "Jun 27 10:17:46 kali-system sudo[1350]: nimish : USER=root ; COMMAND=/usr/bin/apt update",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 425 | `        },` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 426 | `    ]` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 427 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 428 | `    insert_events(fake_events)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 429 | `    alerts = detect_priv_escalation()` | Creates or stores a list of alerts generated by a detector. |
| 430 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 431 | `    for a in alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 432 | `        insert_alert(a)` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 433 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 434 | `    print(f"\n=== {len(alerts)} ALERTS STORED ===")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 435 | `    for a in get_alerts():` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 436 | `        if a["alert_type"] == "priv_escalation":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 437 | `            print(f"\n  [{a['severity']}] {a['attack_id']} — {a['description']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 438 | `            print(f"  Remediation preview: {a['remediation'].splitlines()[0]}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
