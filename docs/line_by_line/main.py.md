# Line-by-Line Explanation: main.py

This file explains every line in `main.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `import sys` | Imports the sys module so this file can use its built-in functions or classes later. |
| 2 | `import os` | Imports the os module so this file can use its built-in functions or classes later. |
| 3 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 4 | `# Always resolve imports from project root` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 5 | `sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))` | Adds the project folder to Python import search paths. This helps imports work even when the script is run from a different folder, but it is a bit advanced-looking. |
| 6 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 7 | `from database.storage import init_db, insert_events, insert_alert, get_alerts, get_summary, clear_all` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 8 | `from parsers.linux_parser import parse_log_file` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 9 | `from detectors.brute_force import detect_brute_force` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 10 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 11 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 12 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 13 | `#  STEP 1 — Initialize the database` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 14 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 15 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 16 | `def step1_init():` | Starts a function named `step1_init`. The indented lines below it are grouped together and run only when this function is called. |
| 17 | `    print("\n" + "="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 18 | `    print("STEP 1 — Initializing database")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 19 | `    print("="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 20 | `    init_db()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 21 | `    print("✓ Database ready")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 22 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 23 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 24 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 25 | `#  STEP 2 — Parse sample log files` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 26 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 27 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 28 | `def step2_parse():` | Starts a function named `step2_parse`. The indented lines below it are grouped together and run only when this function is called. |
| 29 | `    print("\n" + "="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 30 | `    print("STEP 2 — Parsing log files")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 31 | `    print("="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 32 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 33 | `    total = 0` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 34 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 35 | `    # Try each sample file — skips gracefully if not found` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 36 | `    sample_files = [` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 37 | `        ("samples/auth.log",   "syslog"),` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 38 | `        ("samples/linux.log",  "syslog"),` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 39 | `        ("samples/auth.txt",   "syslog"),` | This line continues the current block at indentation level 8. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 40 | `    ]` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 41 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 42 | `    for filepath, log_type in sample_files:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 43 | `        if not os.path.exists(filepath):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 44 | `            print(f"  [skip] {filepath} not found")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 45 | `            continue` | Skips the rest of the current loop cycle and moves to the next item. |
| 46 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 47 | `        try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 48 | `            events = parse_log_file(filepath, log_type=log_type)` | Stores a list of events. In this project, an event usually means one parsed log line. |
| 49 | `            if events:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 50 | `                insert_events(events)` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 51 | `                total += len(events)` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 52 | `                print(f"  ✓ {filepath} → {len(events)} events parsed and stored")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 53 | `            else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 54 | `                print(f"  [warn] {filepath} → 0 events parsed (check file content)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 55 | `        except Exception as e:` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 56 | `            print(f"  [error] {filepath} → {e}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 57 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 58 | `    print(f"\n  Total events inserted: {total}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 59 | `    return total` | Sends a value back to the code that called this function, then stops the function. |
| 60 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 61 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 62 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 63 | `#  STEP 3 — Run brute force detector` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 64 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 65 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 66 | `def step3_detect():` | Starts a function named `step3_detect`. The indented lines below it are grouped together and run only when this function is called. |
| 67 | `    print("\n" + "="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 68 | `    print("STEP 3 — Running brute force detector")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 69 | `    print("="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 70 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 71 | `    try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 72 | `        alerts = detect_brute_force()` | Creates or stores a list of alerts generated by a detector. |
| 73 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 74 | `        if not alerts:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 75 | `            print("  [info] No brute force detected in current events.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 76 | `            print("  [info] This is OK if your sample logs don't have enough failed logins.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 77 | `        else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 78 | `            for alert in alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 79 | `                insert_alert(alert)` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 80 | `            print(f"  ✓ {len(alerts)} brute force alert(s) detected and stored")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 81 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 82 | `        return alerts` | Sends a value back to the code that called this function, then stops the function. |
| 83 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 84 | `    except Exception as e:` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 85 | `        print(f"  [error] Detector failed → {e}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 86 | `        return []` | Sends a value back to the code that called this function, then stops the function. |
| 87 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 88 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 89 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 90 | `#  STEP 4 — Print summary` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 91 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 92 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 93 | `def step4_summary():` | Starts a function named `step4_summary`. The indented lines below it are grouped together and run only when this function is called. |
| 94 | `    print("\n" + "="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 95 | `    print("STEP 4 — Database summary")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 96 | `    print("="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 97 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 98 | `    summary = get_summary()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 99 | `    print(f"  Total events  : {summary['total_events']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 100 | `    print(f"  Total alerts  : {summary['total_alerts']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 101 | `    print(f"  Open alerts   : {summary['open_alerts']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 102 | `    print(f"  By severity   : {summary['severity_breakdown']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 103 | `    print(f"  By type       : {summary['type_breakdown']}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 104 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 105 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 106 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 107 | `#  STEP 5 — Print alerts in detail` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 108 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 109 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 110 | `def step5_print_alerts():` | Starts a function named `step5_print_alerts`. The indented lines below it are grouped together and run only when this function is called. |
| 111 | `    print("\n" + "="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 112 | `    print("STEP 5 — Alert details")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 113 | `    print("="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 114 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 115 | `    alerts = get_alerts()` | Creates or stores a list of alerts generated by a detector. |
| 116 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 117 | `    if not alerts:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 118 | `        print("  No alerts in database yet.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 119 | `        return` | Stops the function early and returns nothing. |
| 120 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 121 | `    for a in alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 122 | `        print(f"""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 123 | `  ┌─ ALERT #{a['id']} ──────────────────────────────` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 124 | `  │  Type        : {a['alert_type']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 125 | `  │  Severity    : {a['severity']}  &#124;  Confidence: {a['confidence']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 126 | `  │  Attacker IP : {a['source_ip']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 127 | `  │  Target      : {a['target_user']}@{a['target_host']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 128 | `  │  Hits        : {a['event_count']} attempts in {a['window_secs']}s` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 129 | `  │  First seen  : {a['first_seen']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 130 | `  │  Last seen   : {a['last_seen']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 131 | `  │  ATT&CK      : {a['attack_id']} — {a['attack_name']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 132 | `  │  Tactic      : {a['attack_tactic']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 133 | `  │  Status      : {a['status']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 134 | `  │  Description : {a['description']}` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 135 | `  └────────────────────────────────────────────""")` | This line continues the current block at indentation level 2. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 136 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 137 | `        print("  Remediation steps:")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 138 | `        if a.get("remediation"):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 139 | `            for line in a["remediation"].split("\n"):` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 140 | `                print(f"    {line}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 141 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 142 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 143 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 144 | `#  MAIN` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 145 | `# ─────────────────────────────────────────────` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 146 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 147 | `if __name__ == "__main__":` | Checks whether this file is being run directly. Code inside this block runs only when you execute this file, not when another file imports it. |
| 148 | `    print("\n╔══════════════════════════════════════════════╗")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 149 | `    print("║         ThreatLens — Pipeline Test           ║")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 150 | `    print("╚══════════════════════════════════════════════╝")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 151 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 152 | `    # Uncomment the line below to wipe the DB before each test run` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 153 | `    # clear_all()` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 154 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 155 | `    step1_init()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 156 | `    total_events = step2_parse()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 157 | `    alerts       = step3_detect()` | Creates or stores a list of alerts generated by a detector. |
| 158 | `    step4_summary()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 159 | `    step5_print_alerts()` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 160 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 161 | `    print("\n" + "="*50)` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 162 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 163 | `    # Final pass/fail verdict` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 164 | `    if total_events > 0:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 165 | `        print("✓ Parser     — WORKING (events in DB)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 166 | `    else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 167 | `        print("✗ Parser     — No events found (check sample files)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 168 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 169 | `    if alerts:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 170 | `        print("✓ Detector   — WORKING (alerts generated)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 171 | `    else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 172 | `        print("~ Detector   — No alerts (need more failed logins in samples)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 173 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 174 | `    print("✓ Database   — WORKING (no crash = tables exist)")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 175 | `    print("\nPipeline check complete.")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 176 | `    print("="*50 + "\n")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 177 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 178 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 179 | `from detectors.priv_escalation import detect_priv_escalation` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 180 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 181 | `# In your main block, after brute force:` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 182 | `print("[*] Running privilege escalation detector...")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 183 | `priv_alerts = detect_priv_escalation()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 184 | `for alert in priv_alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 185 | `    insert_alert(alert)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 186 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 187 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 188 | `from detectors.suspicious_login import detect_suspicious_logins` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 189 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 190 | `print("[*] Running suspicious login detector...")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 191 | `susp_alerts = detect_suspicious_logins()` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 192 | `for alert in susp_alerts:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 193 | `    insert_alert(alert)` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
