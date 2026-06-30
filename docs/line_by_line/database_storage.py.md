# Line-by-Line Explanation: database/storage.py

This file explains every line in `database/storage.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `import sqlite3` | Imports the sqlite3 module so this file can use its built-in functions or classes later. |
| 2 | `import json` | Imports the json module so this file can use its built-in functions or classes later. |
| 3 | `from pathlib import Path` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 4 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 5 | `# Resolves correctly regardless of where you run from` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 6 | `DB_PATH = Path(__file__).resolve().parent / "events.db"` | Builds the path to the SQLite database file using the current file location, so the program can find the database reliably. |
| 7 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 8 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 9 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 10 | `#  INITIALISATION` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 11 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 12 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 13 | `def init_db():` | Starts a function named `init_db`. The indented lines below it are grouped together and run only when this function is called. |
| 14 | `    """Create all tables if they don't already exist."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 15 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 16 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 17 | `    # EVENTS TABLE — every parsed log line from any source` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 18 | `    conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 19 | `        CREATE TABLE IF NOT EXISTS events (` | Begins an SQL command that creates a database table if it does not already exist. |
| 20 | `            id          INTEGER PRIMARY KEY AUTOINCREMENT,` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 21 | `            log_type    TEXT,     -- 'syslog', 'apache', 'firewall', etc.` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 22 | `            timestamp   TEXT,     -- ISO 8601 format` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 23 | `            hostname    TEXT,     -- machine that generated the log` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 24 | `            source_ip   TEXT,     -- attacker/client IP if present` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 25 | `            process     TEXT,     -- e.g. 'sshd', 'sudo', 'kernel'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 26 | `            pid         TEXT,     -- process ID if present` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 27 | `            message     TEXT,     -- the actual log message` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 28 | `            raw         TEXT,     -- original unmodified log line` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 29 | `            extra       TEXT      -- JSON blob for any extra parsed fields` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 30 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 31 | `    """)` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 32 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 33 | `    # ALERTS TABLE — every detection fired by any detector` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 34 | `    conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 35 | `        CREATE TABLE IF NOT EXISTS alerts (` | Begins an SQL command that creates a database table if it does not already exist. |
| 36 | `            id              INTEGER PRIMARY KEY AUTOINCREMENT,` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 37 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 38 | `            -- When & what` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 39 | `            created_at      TEXT,    -- when your detector fired` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 40 | `            alert_type      TEXT,    -- 'brute_force', 'priv_escalation', etc.` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 41 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 42 | `            -- Severity` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 43 | `            severity        TEXT,    -- LOW / MEDIUM / HIGH / CRITICAL` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 44 | `            confidence      TEXT,    -- LOW / MEDIUM / HIGH` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 45 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 46 | `            -- Who` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 47 | `            source_ip       TEXT,    -- attacker IP` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 48 | `            target_host     TEXT,    -- machine being attacked` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 49 | `            target_user     TEXT,    -- account being targeted` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 50 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 51 | `            -- What happened` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 52 | `            description     TEXT,    -- human-readable summary` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 53 | `            event_count     INTEGER, -- how many log lines triggered this` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 54 | `            window_secs     INTEGER, -- detection time window used` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 55 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 56 | `            -- Timeline` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 57 | `            first_seen      TEXT,    -- timestamp of first event in window` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 58 | `            last_seen       TEXT,    -- timestamp of last event in window` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 59 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 60 | `            -- ATT&CK mapping` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 61 | `            attack_id       TEXT,    -- e.g. 'T1110.001'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 62 | `            attack_name     TEXT,    -- e.g. 'Brute Force: Password Guessing'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 63 | `            attack_tactic   TEXT,    -- e.g. 'Credential Access'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 64 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 65 | `            -- Evidence & response` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 66 | `            raw_events      TEXT,    -- JSON list of raw log lines that triggered this` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 67 | `            remediation     TEXT,    -- step-by-step fix instructions` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 68 | `            status          TEXT DEFAULT 'open'  -- open / investigating / resolved / false_positive` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 69 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 70 | `    """)` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 71 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 72 | `    conn.commit()` | Saves database changes permanently. Without commit, inserts or updates may not be written. |
| 73 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 74 | `    print("[db] Database initialized successfully.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 75 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 76 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 77 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 78 | `#  EVENTS` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 79 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 80 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 81 | `def insert_events(events: list[dict]):` | Starts a function named `insert_events`. The indented lines below it are grouped together and run only when this function is called. |
| 82 | `    """Insert a list of parsed log event dicts into the events table."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 83 | `    if not events:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 84 | `        print("[db] No events to insert.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 85 | `        return` | Stops the function early and returns nothing. |
| 86 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 87 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 88 | `    for e in events:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 89 | `        conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 90 | `            INSERT INTO events` | Begins an SQL command that adds a new row to a database table. |
| 91 | `            (log_type, timestamp, hostname, source_ip, process, pid, message, raw, extra)` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 92 | `            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)` | Lists placeholders for the values that will be inserted into the database safely. |
| 93 | `        """, (` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 94 | `            e.get("log_type"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 95 | `            e.get("timestamp"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 96 | `            e.get("hostname"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 97 | `            e.get("source_ip"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 98 | `            e.get("process"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 99 | `            e.get("pid"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 100 | `            e.get("message"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 101 | `            e.get("raw"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 102 | `            json.dumps({` | Converts a Python object, usually a list or dictionary, into JSON text so it can be stored in SQLite. |
| 103 | `                k: v for k, v in e.items()` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 104 | `                if k not in ("log_type", "timestamp", "hostname",` | Starts a condition. Python runs the indented block below only if this test is true. |
| 105 | `                             "source_ip", "process", "pid", "message", "raw")` | This line continues the current block at indentation level 29. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 106 | `            })` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 107 | `        ))` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 108 | `    conn.commit()` | Saves database changes permanently. Without commit, inserts or updates may not be written. |
| 109 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 110 | `    print(f"[db] Inserted {len(events)} events.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 111 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 112 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 113 | `def get_events(limit: int = 100) -> list[dict]:` | Starts a function named `get_events`. The indented lines below it are grouped together and run only when this function is called. |
| 114 | `    """Return the most recent parsed events, newest first."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 115 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 116 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 117 | `    rows = conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 118 | `        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)` | Begins an SQL query that reads rows from a database table. |
| 119 | `    ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 120 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 121 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 122 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 123 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 124 | `def get_events_by_ip(ip: str) -> list[dict]:` | Starts a function named `get_events_by_ip`. The indented lines below it are grouped together and run only when this function is called. |
| 125 | `    """Return all events from a specific source IP."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 126 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 127 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 128 | `    rows = conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 129 | `        "SELECT * FROM events WHERE source_ip = ? ORDER BY timestamp ASC", (ip,)` | Begins an SQL query that reads rows from a database table. |
| 130 | `    ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 131 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 132 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 133 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 134 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 135 | `def get_failed_logins() -> list[dict]:` | Starts a function named `get_failed_logins`. The indented lines below it are grouped together and run only when this function is called. |
| 136 | `    """Return all failed SSH / login events."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 137 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 138 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 139 | `    rows = conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 140 | `        SELECT * FROM events` | Begins an SQL query that reads rows from a database table. |
| 141 | `        WHERE (` | Adds filtering rules to an SQL query so only matching rows are returned. |
| 142 | `            message LIKE '%Failed password%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 143 | `            OR message LIKE '%authentication failure%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 144 | `            OR message LIKE '%Invalid user%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 145 | `            OR message LIKE '%Connection closed by invalid user%'` | This line continues the current block at indentation level 12. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 146 | `        )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 147 | `        AND timestamp IS NOT NULL` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 148 | `        ORDER BY timestamp ASC` | Sorts database results by a column, such as timestamp or creation time. |
| 149 | `    """).fetchall()` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 150 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 151 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 152 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 153 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 154 | `def count_events() -> int:` | Starts a function named `count_events`. The indented lines below it are grouped together and run only when this function is called. |
| 155 | `    """Return total number of events in the table."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 156 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 157 | `    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 158 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 159 | `    return count` | Sends a value back to the code that called this function, then stops the function. |
| 160 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 161 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 162 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 163 | `#  ALERTS` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 164 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 165 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 166 | `def insert_alert(alert: dict):` | Starts a function named `insert_alert`. The indented lines below it are grouped together and run only when this function is called. |
| 167 | `    """Insert a single alert dict into the alerts table."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 168 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 169 | `    conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 170 | `        INSERT INTO alerts` | Begins an SQL command that adds a new row to a database table. |
| 171 | `        (created_at, alert_type, severity, confidence,` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 172 | `         source_ip, target_host, target_user,` | This line continues the current block at indentation level 9. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 173 | `         description, event_count, window_secs,` | This line continues the current block at indentation level 9. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 174 | `         first_seen, last_seen,` | This line continues the current block at indentation level 9. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 175 | `         attack_id, attack_name, attack_tactic,` | This line continues the current block at indentation level 9. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 176 | `         raw_events, remediation, status)` | This line continues the current block at indentation level 9. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 177 | `        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)` | Lists placeholders for the values that will be inserted into the database safely. |
| 178 | `    """, (` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 179 | `        alert.get("created_at"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 180 | `        alert.get("alert_type"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 181 | `        alert.get("severity"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 182 | `        alert.get("confidence"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 183 | `        alert.get("source_ip"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 184 | `        alert.get("target_host"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 185 | `        alert.get("target_user"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 186 | `        alert.get("description"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 187 | `        alert.get("event_count"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 188 | `        alert.get("window_secs"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 189 | `        alert.get("first_seen"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 190 | `        alert.get("last_seen"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 191 | `        alert.get("attack_id"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 192 | `        alert.get("attack_name"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 193 | `        alert.get("attack_tactic"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 194 | `        json.dumps(alert.get("raw_events", [])),` | Converts a Python object, usually a list or dictionary, into JSON text so it can be stored in SQLite. |
| 195 | `        alert.get("remediation"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 196 | `        alert.get("status", "open"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 197 | `    ))` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 198 | `    conn.commit()` | Saves database changes permanently. Without commit, inserts or updates may not be written. |
| 199 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 200 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 201 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 202 | `def get_alerts() -> list[dict]:` | Starts a function named `get_alerts`. The indented lines below it are grouped together and run only when this function is called. |
| 203 | `    """Return all alerts, newest first."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 204 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 205 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 206 | `    rows = conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 207 | `        "SELECT * FROM alerts ORDER BY created_at DESC"` | Begins an SQL query that reads rows from a database table. |
| 208 | `    ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 209 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 210 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 211 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 212 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 213 | `def get_alerts_by_severity(severity: str) -> list[dict]:` | Starts a function named `get_alerts_by_severity`. The indented lines below it are grouped together and run only when this function is called. |
| 214 | `    """Return alerts filtered by severity: LOW / MEDIUM / HIGH / CRITICAL."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 215 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 216 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 217 | `    rows = conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 218 | `        "SELECT * FROM alerts WHERE severity = ? ORDER BY created_at DESC",` | Begins an SQL query that reads rows from a database table. |
| 219 | `        (severity.upper(),)` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 220 | `    ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 221 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 222 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 223 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 224 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 225 | `def get_alerts_by_type(alert_type: str) -> list[dict]:` | Starts a function named `get_alerts_by_type`. The indented lines below it are grouped together and run only when this function is called. |
| 226 | `    """Return alerts filtered by type: e.g. 'brute_force'."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 227 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 228 | `    conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 229 | `    rows = conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 230 | `        "SELECT * FROM alerts WHERE alert_type = ? ORDER BY created_at DESC",` | Begins an SQL query that reads rows from a database table. |
| 231 | `        (alert_type,)` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 232 | `    ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 233 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 234 | `    return [dict(r) for r in rows]` | Sends a value back to the code that called this function, then stops the function. |
| 235 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 236 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 237 | `def update_alert_status(alert_id: int, new_status: str):` | Starts a function named `update_alert_status`. The indented lines below it are grouped together and run only when this function is called. |
| 238 | `    """Update the status of an alert by ID.` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 239 | `    Valid values: 'open', 'investigating', 'resolved', 'false_positive'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 240 | `    """` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 241 | `    valid = {"open", "investigating", "resolved", "false_positive"}` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 242 | `    if new_status not in valid:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 243 | `        raise ValueError(f"Invalid status '{new_status}'. Must be one of: {valid}")` | Creates an error intentionally because the program cannot continue safely with the current input. |
| 244 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 245 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 246 | `    conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 247 | `        "UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id)` | Adds filtering rules to an SQL query so only matching rows are returned. |
| 248 | `    )` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 249 | `    conn.commit()` | Saves database changes permanently. Without commit, inserts or updates may not be written. |
| 250 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 251 | `    print(f"[db] Alert {alert_id} status updated to '{new_status}'.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 252 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 253 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 254 | `def count_alerts() -> dict:` | Starts a function named `count_alerts`. The indented lines below it are grouped together and run only when this function is called. |
| 255 | `    """Return alert counts grouped by severity."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 256 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 257 | `    rows = conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 258 | `        SELECT severity, COUNT(*) as count` | Begins an SQL query that reads rows from a database table. |
| 259 | `        FROM alerts` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 260 | `        GROUP BY severity` | Groups database rows by a field so the code can count items in each group. |
| 261 | `    """).fetchall()` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 262 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 263 | `    return {row[0]: row[1] for row in rows}` | Sends a value back to the code that called this function, then stops the function. |
| 264 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 265 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 266 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 267 | `#  UTILITIES` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 268 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 269 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 270 | `def clear_all():` | Starts a function named `clear_all`. The indented lines below it are grouped together and run only when this function is called. |
| 271 | `    """Wipe both tables — useful during development and testing."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 272 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 273 | `    conn.execute("DELETE FROM events")` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 274 | `    conn.execute("DELETE FROM alerts")` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 275 | `    conn.commit()` | Saves database changes permanently. Without commit, inserts or updates may not be written. |
| 276 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 277 | `    print("[db] All tables cleared.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 278 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 279 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 280 | `def get_summary() -> dict:` | Starts a function named `get_summary`. The indented lines below it are grouped together and run only when this function is called. |
| 281 | `    """Return a quick summary of what's in the database."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 282 | `    conn = sqlite3.connect(DB_PATH)` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 283 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 284 | `    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 285 | `    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 286 | `    open_alerts  = conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 287 | `        "SELECT COUNT(*) FROM alerts WHERE status = 'open'"` | Begins an SQL query that reads rows from a database table. |
| 288 | `    ).fetchone()[0]` | Gets one row returned by the previous database query. |
| 289 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 290 | `    severity_breakdown = {` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 291 | `        row[0]: row[1] for row in conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 292 | `            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"` | Begins an SQL query that reads rows from a database table. |
| 293 | `        ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 294 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 295 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 296 | `    type_breakdown = {` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 297 | `        row[0]: row[1] for row in conn.execute(` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 298 | `            "SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"` | Begins an SQL query that reads rows from a database table. |
| 299 | `        ).fetchall()` | Collects all rows returned by the previous database query into a Python list. |
| 300 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 301 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 302 | `    conn.close()` | Closes the database or file connection after the program is finished using it. |
| 303 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 304 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 305 | `        "total_events":       total_events,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 306 | `        "total_alerts":       total_alerts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 307 | `        "open_alerts":        open_alerts,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 308 | `        "severity_breakdown": severity_breakdown,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 309 | `        "type_breakdown":     type_breakdown,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 310 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 311 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 312 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 313 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 314 | `#  QUICK TEST — run this file directly to verify` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 315 | `#  python database/storage.py` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 316 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 317 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 318 | `if __name__ == "__main__":` | Checks whether this file is being run directly. Code inside this block runs only when you execute this file, not when another file imports it. |
| 319 | `    print(f"[db] Using database at: {DB_PATH}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 320 | `    init_db()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 321 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 322 | `    summary = get_summary()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 323 | `    print(f"[db] Events : {summary['total_events']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 324 | `    print(f"[db] Alerts : {summary['total_alerts']} total, {summary['open_alerts']} open")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 325 | `    print(f"[db] Severity breakdown : {summary['severity_breakdown']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 326 | `    print(f"[db] Alert types        : {summary['type_breakdown']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
