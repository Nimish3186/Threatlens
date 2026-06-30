# Line-by-Line Explanation: tests/test_brute.py

This file explains every line in `tests/test_brute.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `from database.storage import init_db, insert_events, insert_alert, get_alerts` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 2 | `from detectors.brute_force import detect_brute_force` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 3 | `from datetime import datetime, timedelta` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 4 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 5 | `init_db()` | This line continues the current block at indentation level 0. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 6 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 7 | `# Simulate 7 failed SSH attempts from one IP within 45 seconds` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 8 | `base_time = datetime(2025, 6, 27, 10, 0, 0)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 9 | `fake_events = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 10 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 11 | `for i in range(7):` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 12 | `    ts = base_time + timedelta(seconds=i * 6)  # every 6s → 7 hits in 42s` | Creates or uses a time duration, such as a number of seconds or minutes. |
| 13 | `    fake_events.append({` | Adds one item to the end of a list. |
| 14 | `        "log_type":  "syslog",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 15 | `        "timestamp": ts.isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 16 | `        "hostname":  "myserver",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 17 | `        "source_ip": "192.168.1.99",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 18 | `        "process":   "sshd",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 19 | `        "message":   f"Failed password for root from 192.168.1.99 port 22 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 20 | `        "raw":       f"Jun 27 10:00:{i*6:02d} myserver sshd[999]: Failed password for root from 192.168.1.99 port 22 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 21 | `    })` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 22 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 23 | `# One innocent user with only 2 failures — should NOT trigger` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 24 | `for i in range(2):` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 25 | `    fake_events.append({` | Adds one item to the end of a list. |
| 26 | `        "log_type":  "syslog",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 27 | `        "timestamp": (base_time + timedelta(minutes=5, seconds=i*10)).isoformat(),` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 28 | `        "hostname":  "myserver",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 29 | `        "source_ip": "10.0.0.5",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 30 | `        "process":   "sshd",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 31 | `        "message":   "Failed password for alice from 10.0.0.5 port 22 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 32 | `        "raw":       f"Jun 27 10:05:{i*10:02d} myserver sshd[888]: Failed password for alice from 10.0.0.5 port 22 ssh2",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 33 | `    })` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 34 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 35 | `insert_events(fake_events)` | This line continues the current block at indentation level 0. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 36 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 37 | `alerts = detect_brute_force()` | Creates or stores a list of alerts generated by a detector. |
| 38 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 39 | `for a in alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 40 | `    insert_alert(a)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 41 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 42 | `print("\n=== STORED ALERTS ===")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 43 | `for a in get_alerts():` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 44 | `    print(f"  [{a['severity']}] {a['source_ip']} — {a['description']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
