# ThreatLens Student Code Guide

This guide explains the files you actually need to understand. I am not explaining `.venv`, `.idea`, `__pycache__`, `.db`, or sample log files line by line because those are environment files, IDE settings, compiled cache files, databases, or test data. They are not code you would normally write for a project submission.

## Big Picture

ThreatLens does this:

1. Reads Linux log files from `samples/`.
2. Turns each log line into a Python dictionary.
3. Stores those dictionaries in SQLite.
4. Runs detectors on the stored events.
5. Stores generated alerts.
6. Prints a summary in the terminal.

The important source files are:

- `main.py`: runs the whole pipeline.
- `parsers/linux_parser.py`: reads raw logs and converts them to dictionaries.
- `database/storage.py`: creates tables and saves/loads events and alerts.
- `detectors/brute_force.py`: detects many failed logins from the same IP.
- `detectors/priv_escalation.py`: detects risky `sudo`, `su`, permission, and account changes.
- `detectors/suspicious_login.py`: scores successful logins for suspicious behavior.
- `database/inspect.py`: small script to peek inside the database.
- `tests/test_brute.py`: manual brute-force test data.

## Important Warning

`config.yaml` contains what looks like a real AbuseIPDB API key. Do not submit or push real API keys. Replace it with a placeholder such as `PUT_YOUR_API_KEY_HERE`.

## main.py

Lines 1-2 import `sys` and `os`, which help Python work with file paths and imports.

Lines 4-5 force Python to treat the project folder as the import root. This is common in AI-generated scripts, but it is a little clunky. A student version could avoid this by always running the project from the root folder.

Lines 7-9 import database functions, the parser, and the brute-force detector.

Lines 12-16 are decorative comments. They make the file look polished, but they are not needed.

Lines 17-22 define `step1_init()`. It prints a heading, creates the database tables, then prints that the database is ready.

Lines 29-62 define `step2_parse()`. It starts a counter, lists sample files, skips missing files, parses existing files, inserts parsed events, and returns the total inserted event count.

Lines 42-43 use tuple unpacking: `for filepath, log_type in sample_files:`. Each item has two parts, and Python puts them into `filepath` and `log_type`.

Lines 65-88 define `step3_detect()`. It runs the brute-force detector, inserts any alerts, and returns the alert list. The `try/except` prevents the whole program from crashing if the detector fails.

Lines 95-106 define `step4_summary()`. It asks the database for counts and prints them.

Lines 113-153 define `step5_print_alerts()`. It loads alerts and prints each alert in a formatted block. This section is very presentation-heavy and looks AI-polished.

Lines 160-190 are the main program. `if __name__ == "__main__":` means "only run this part when this file is executed directly."

Lines 166-171 run the pipeline in order: initialize DB, parse logs, detect brute force, print summary, print alerts.

Lines 177-187 print a final pass/fail-style check.

Lines 193 onward are a problem: the privilege-escalation and suspicious-login detectors are imported and run outside the main block. That means they run whenever `main.py` is imported by another file. A cleaner student version should move those lines inside the main block, after `step3_detect()`.

## parsers/linux_parser.py

Lines 1-4 import tools: regex, datetime conversion, optional return typing, and file-existence checks.

Lines 7-13 define `SYSLOG_PATTERN`, a regex for normal Linux syslog lines.

Lines 14-19 define `KERNEL_PATTERN`, which handles kernel logs.

Lines 21-27 define `APACHE_PATTERN`, which parses Apache access logs.

Lines 29-73 define `parse_syslog_line()`. It removes whitespace, ignores blank lines, tries kernel parsing first, tries standard syslog parsing second, converts the timestamp, and returns a dictionary.

Lines 39 and 61 use the current year because syslog lines usually do not include a year.

Lines 44 and 70 use an inline if: `timestamp.isoformat() if timestamp else None`. It means "convert timestamp if it exists, otherwise store None."

Lines 75-99 define `parse_apache_line()`, the Apache version of the same parser idea.

Lines 102-106 define `parse_line()`, a router that chooses the right parser.

Lines 111-132 are an old version of `parse_log_file()` inside a triple-quoted string. This is commented-out code and should be deleted for a cleaner submission.

Lines 134-155 define the real `parse_log_file()`. It checks the file exists, loops over every line, parses each line, stores successful parses in `results`, stores failed lines in `skipped_lines`, prints a summary, and returns all parsed events.

## database/storage.py

Lines 1-3 import SQLite, JSON, and path tools.

Line 6 creates `DB_PATH`, the path to `database/events.db`.

Lines 13-74 define `init_db()`. It opens SQLite, creates the `events` and `alerts` tables if needed, saves the changes, and closes the database.

Lines 18-31 are the SQL for the `events` table. Each parsed log line becomes one row.

Lines 34-70 are the SQL for the `alerts` table. Each detector warning becomes one row.

Lines 81-110 define `insert_events()`. It accepts a list of event dictionaries and inserts each one into SQLite.

Lines 102-106 are a dictionary comprehension that stores extra event fields as JSON. Student version: make an empty dictionary, loop through `e.items()`, and add only keys that are not standard fields.

Lines 113-121 define `get_events()`, which returns recent events.

Lines 124-132 define `get_events_by_ip()`, which returns events from one IP.

Lines 135-151 define `get_failed_logins()`, which finds failed-login messages with SQL `LIKE` filters.

Lines 154-159 define `count_events()`.

Lines 166-199 define `insert_alert()`, which stores one alert dictionary.

Lines 202-210 define `get_alerts()`.

Lines 213-222 define `get_alerts_by_severity()`.

Lines 225-234 define `get_alerts_by_type()`.

Lines 237-251 define `update_alert_status()`. It validates the status and updates one alert row.

Lines 254-263 define `count_alerts()`. Line 263 is a dictionary comprehension that turns SQL rows into a dictionary like `{"HIGH": 2}`.

Lines 270-277 define `clear_all()`. It deletes all events and alerts, so use it carefully.

Lines 280-310 define `get_summary()`. It returns counts and grouped summaries.

Lines 318-326 let you run this file directly to test the database.

## detectors/brute_force.py

Lines 1-6 import database, regex, time, grouping, and path tools.

Line 8 points to the SQLite database.

Lines 11-12 are settings: alert after 3 failed attempts within 60 seconds.

Lines 15-30 define `fetch_failed_logins()`, which reads failed-login rows from the database.

Lines 33-43 define `extract_ip_from_message()`, which uses regex to find an IP address.

Lines 46-62 define `sliding_window_check()`. This is the main brute-force logic: it checks whether any group of 3 attempts happened within 60 seconds.

Lines 66-68 define `extract_target_user()`. Line 68 uses a compact inline if. A student version can use a normal `if/else`.

Lines 70-77 define `calculate_severity()`. More attempts means higher severity.

Lines 79-117 define `build_alert()`. It creates a full alert dictionary.

Line 109 uses a list comprehension: `[e["raw"] for e in matching_events[:10]]`. It means "collect the raw log text from the first 10 matching events."

Lines 120-156 define `detect_brute_force()`. It gets failed logins, groups them by IP, converts timestamps, sorts events, checks each IP's time window, builds alerts, and returns them.

Line 144 uses a lambda: `ts_event_pairs.sort(key=lambda x: x[0])`. It means "sort by the timestamp, which is the first item in each pair." Student version:

```python
def get_timestamp(pair):
    return pair[0]

ts_event_pairs.sort(key=get_timestamp)
```

## detectors/priv_escalation.py

Lines 1-11 import regex, path, date, grouping, SQLite, JSON, and database settings.

Line 8 is another path hack. It helps imports work, but a cleaner project structure would avoid it.

Line 17 sets a 5-minute deduplication window.

Lines 24-36 list dangerous commands. These are commands that can help a user become root or hide activity.

Lines 38-41 list critical files and folders.

Lines 49-73 define regex patterns for `sudo`, `su`, root sessions, dangerous `chmod`, and new-user events.

Lines 80-104 define `fetch_priv_events()`. It queries the database for messages that might involve privilege escalation.

Lines 111-225 define `classify_event()`. This is the heart of the detector. It checks one event at a time and returns a classification dictionary if the event looks risky.

Lines 119-147 handle `sudo` events.

Lines 130-131 use `any(...)`. It means "if at least one dangerous command appears inside the command text." A student version can use a normal loop and a boolean flag.

Lines 133-134 use compact conditional expressions. Replace them with normal `if/elif/else` blocks if you need easier explanation.

Lines 150-166 detect `su root`.

Lines 169-181 detect root sessions.

Lines 184-206 detect dangerous permission changes like `chmod 777`.

Lines 209-223 detect new local accounts.

Lines 232-259 define `build_priv_alert()`, which converts a classification into the same alert format used by the database.

Lines 262-301 define `build_remediation()`, which returns different response steps depending on alert subtype.

Lines 308-333 define `deduplicate_alerts()`, which avoids repeated alerts for the same host, user, and description inside 5 minutes.

Lines 340-370 define `detect_priv_escalation()`. It fetches candidate events, classifies them, builds alerts, deduplicates them, and returns the final list.

Lines 377-438 are direct-run fake test data. Useful for testing, but too large for the detector file. Move it to `tests/` for a cleaner project.

## detectors/suspicious_login.py

This is the most AI-looking file because it uses scoring, indexes, multiple signals, MITRE mappings, and long fake test data.

Lines 1-10 import tools and the database path.

Lines 16-28 define risk-score settings. For example, root login adds 50 points and off-hours login adds 30 points.

Lines 35-49 define regex patterns for successful logins, failed logins, and root sessions.

Lines 56-73 fetch login-related events from the database.

Lines 80-94 define `build_known_ips()`. It treats the first half of historical events as "normal history" and collects IPs that successfully logged in before.

Lines 101-188 define `score_login()`. It scores one successful login using off-hours login, direct root login, new IP, failures before success, and password spraying.

Lines 159-162 use a list comprehension to collect recent failures within the five minutes before a successful login. A student version can use a normal loop and `append`.

Lines 195-204 convert score and signal count into severity and confidence.

Lines 211-248 build the final suspicious-login alert.

Lines 251-259 choose a MITRE ATT&CK technique using `any(...)`.

Lines 262-288 build remediation text.

Lines 295-351 define `detect_suspicious_logins()`. It fetches login events, builds known-IP history, builds indexes of failed attempts and accounts tried, scores every successful login, deduplicates alerts, and returns them.

Lines 310-311 use `defaultdict`, which automatically creates empty lists or sets for new keys. A student version can use normal dictionaries and `if ip not in dictionary` checks.

Lines 358-454 are a large direct-run test. Move this to `tests/test_suspicious_login.py` if you want the detector file to look simpler.

## database/inspect.py

Line 1 is a comment explaining the file.

Line 2 imports SQLite.

Lines 4-5 open the database and tell SQLite to return row-like objects.

Lines 7-9 count all events and print the count.

Lines 11-18 query the 10 newest failed-login rows.

Lines 20-21 print each row with only the first 60 message characters.

Line 23 closes the database.

One issue: the database path may fail depending on where you run the file from. A better path would use `Path(__file__).resolve().parent / "events.db"`.

## tests/test_brute.py

Lines 1-3 import database functions, the brute-force detector, and date tools.

Line 5 initializes the database.

Lines 8-9 create a base test time and an empty fake-event list.

Lines 11-24 create 7 fake failed SSH attempts from one IP. This should trigger an alert.

Lines 27-38 create only 2 failed attempts from another IP. This should not trigger an alert.

Line 40 inserts the fake events.

Line 42 runs detection.

Lines 44-45 insert generated alerts.

Lines 47-49 print stored alerts.

This is not a proper `pytest` test yet because it has no `assert` statements. It is more like a manual test script.

## parsers/test.py

Lines 1-3 import parser functions.

Lines 5-10 define example log lines.

Lines 11-14 parse and print each result.

This is also a manual test script, not a formal unit test.

## config.yaml

Line 1 creates an `abuseipdb` config section.

Line 2 stores the API key. Replace this before sharing.

Line 3 says cached IP lookups should last 24 hours.

Line 4 says IPs with score above 25 should be flagged.

Currently, this config does not appear to be used by the Python code.

## improve.md

This is a project notes file. It suggests future improvements: Windows EVTX parsing, an `event_type` field, dataclasses or Pydantic later, and parser unit tests.

## chatgpt steps .txt

This is not application code. It is a planning note that describes how the project may have been generated step by step. You can keep it for reference, but do not include it as part of the actual program unless your teacher asks for planning notes.

## Complex Python Patterns Explained

### Lambda

`lambda x: x[0]` is a tiny unnamed function. In this project it is used to sort timestamp/event pairs by timestamp.

Student rewrite:

```python
def get_first_item(x):
    return x[0]
```

### List Comprehension

`[ts for ts, _ in ts_event_pairs]` means "make a list containing only the timestamp from each pair."

Student rewrite:

```python
timestamps = []
for pair in ts_event_pairs:
    timestamps.append(pair[0])
```

### Dictionary Comprehension

`{row[0]: row[1] for row in rows}` means "turn rows like `('HIGH', 3)` into `{'HIGH': 3}`."

Student rewrite:

```python
result = {}
for row in rows:
    result[row[0]] = row[1]
return result
```

### any(...)

`any("root" in s for s in signals)` means "if at least one signal contains the word root."

Student rewrite:

```python
has_root_signal = False
for signal in signals:
    if "root" in signal:
        has_root_signal = True
```

### Inline if

`return match.group(1) if match else "unknown"` means "return the matched username if there was a match; otherwise return unknown."

Student rewrite:

```python
if match:
    return match.group(1)
else:
    return "unknown"
```

### defaultdict

`defaultdict(list)` makes a dictionary where every new key automatically starts with an empty list.

Student rewrite:

```python
ip_events = {}
if ip not in ip_events:
    ip_events[ip] = []
ip_events[ip].append((ts, event))
```

### Regex Named Groups

`(?P<user>\S+)` captures part of the text and names it `user`. Later the code can use `match.group("user")`.

## How To Humanize The Code

Do not make it worse. Make it simpler and easier to explain.

1. Remove decorative Unicode banners and box drawings.
2. Move fake test data into `tests/` files.
3. Delete old commented-out code in `parsers/linux_parser.py`.
4. Replace `lambda`, `any(...)`, and comprehensions with normal `for` loops where you need to explain them confidently.
5. Remove unused imports like `json` in files that do not use it.
6. Use simpler comments that explain your thinking, not polished section headers everywhere.
7. Keep MITRE ATT&CK mapping only if you can explain what it means.
8. Make thresholds simple constants at the top of each detector.
9. Add real `assert` statements to tests.
10. Replace the leaked API key with a placeholder.

## Suggested Student-Friendly Refactor Order

1. Fix `main.py` so all detector calls are inside the main block.
2. Remove the old triple-quoted parser function.
3. Replace the lambda in `brute_force.py` with a named function.
4. Replace the clearest `any(...)` calls in `priv_escalation.py` with normal loops.
5. Move fake test data from detector files into separate test files.
6. Add 2-3 simple `assert` tests.

That keeps the same project idea but makes it much easier to defend in a viva or presentation.
