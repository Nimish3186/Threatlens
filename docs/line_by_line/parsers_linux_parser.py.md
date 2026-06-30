# Line-by-Line Explanation: parsers/linux_parser.py

This file explains every line in `parsers/linux_parser.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `import re` | Imports the re module so this file can use its built-in functions or classes later. |
| 2 | `from datetime import datetime` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 3 | `from typing import Optional` | Imports specific functions, classes, or constants from another module so this file can call them directly. |
| 4 | `import os` | Imports the os module so this file can use its built-in functions or classes later. |
| 5 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 6 | `# Covers syslog, auth.log, kern.log` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 7 | `SYSLOG_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 8 | `    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 9 | `    r'(?P<hostname>\S+)\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 10 | `    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'  ` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 11 | `    r'(?P<message>.+)$'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 12 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 13 | `KERNEL_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 14 | `    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 15 | `    r'(?P<hostname>\S+)\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 16 | `    r'kernel:\s+\[\s*\d+\.\d+\]\s+'   # kernel: [1024.567890]` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 17 | `    r'(?P<message>.+)$'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 18 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 19 | `# Apache combined log format` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 20 | `APACHE_PATTERN = re.compile(` | Defines a constant-style setting. The uppercase name signals that this value is meant to be configured but not changed during normal execution. |
| 21 | `    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 22 | `    r'\[(?P<time>[^\]]+)\]\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 23 | `    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 24 | `    r'(?P<status>\d{3})\s+(?P<size>\S+)'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 25 | `)` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 26 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 27 | `def parse_syslog_line(line: str) -> Optional[dict]:` | Starts a function named `parse_syslog_line`. The indented lines below it are grouped together and run only when this function is called. |
| 28 | `    line = line.strip()` | Removes extra spaces or newline characters from the beginning and end of a string. |
| 29 | `    if not line:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 30 | `        return None` | Sends a value back to the code that called this function, then stops the function. |
| 31 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 32 | `    # Try kernel pattern first` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 33 | `    kernel_match = KERNEL_PATTERN.match(line)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 34 | `    if kernel_match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 35 | `        f = kernel_match.groupdict()` | Turns all named regex matches into a dictionary, such as month, day, hostname, process, and message. |
| 36 | `        year = datetime.now().year` | Gets the current date and time from the computer. |
| 37 | `        raw_ts = f"{f['month']} {f['day']} {f['time']} {year}"` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 38 | `        try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 39 | `            timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S %Y")` | Converts a timestamp string from the log into a Python datetime object using the specified date format. |
| 40 | `        except ValueError:` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 41 | `            timestamp = None` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 42 | `        return {` | Sends a value back to the code that called this function, then stops the function. |
| 43 | `            "log_type":  "syslog",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 44 | `            "timestamp": timestamp.isoformat() if timestamp else None,` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 45 | `            "hostname":  f["hostname"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 46 | `            "process":   "kernel",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 47 | `            "pid":       None,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 48 | `            "message":   f["message"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 49 | `            "raw":       line,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 50 | `        }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 51 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 52 | `    # Try standard syslog pattern` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 53 | `    match = SYSLOG_PATTERN.match(line)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 54 | `    if not match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 55 | `        return None                    # genuinely unparseable line` | Sends a value back to the code that called this function, then stops the function. |
| 56 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 57 | `    fields = match.groupdict()` | Turns all named regex matches into a dictionary, such as month, day, hostname, process, and message. |
| 58 | `    year = datetime.now().year` | Gets the current date and time from the computer. |
| 59 | `    raw_ts = f"{fields['month']} {fields['day']} {fields['time']} {year}"` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 60 | `    try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 61 | `        timestamp = datetime.strptime(raw_ts, "%b %d %H:%M:%S %Y")` | Converts a timestamp string from the log into a Python datetime object using the specified date format. |
| 62 | `    except ValueError:` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 63 | `        timestamp = None` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 64 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 65 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 66 | `        "log_type":  "syslog",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 67 | `        "timestamp": timestamp.isoformat() if timestamp else None,` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 68 | `        "hostname":  fields["hostname"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 69 | `        "process":   fields["process"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 70 | `        "pid":       fields.get("pid"),` | Reads a value from a dictionary safely. If the key is missing, it returns a default value instead of crashing. |
| 71 | `        "message":   fields["message"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 72 | `        "raw":       line,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 73 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 74 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 75 | `def parse_apache_line(line: str) -> Optional[dict]:` | Starts a function named `parse_apache_line`. The indented lines below it are grouped together and run only when this function is called. |
| 76 | `    line = line.strip()` | Removes extra spaces or newline characters from the beginning and end of a string. |
| 77 | `    if not line:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 78 | `        return None` | Sends a value back to the code that called this function, then stops the function. |
| 79 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 80 | `    match = APACHE_PATTERN.match(line)` | Applies a regular expression to text to see whether the expected pattern exists. |
| 81 | `    if not match:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 82 | `        return None` | Sends a value back to the code that called this function, then stops the function. |
| 83 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 84 | `    fields = match.groupdict()` | Turns all named regex matches into a dictionary, such as month, day, hostname, process, and message. |
| 85 | `    try:` | Starts a protected block. If an error happens inside it, the matching except block can handle the error instead of crashing immediately. |
| 86 | `        timestamp = datetime.strptime(fields["time"], "%d/%b/%Y:%H:%M:%S %z")` | Converts a timestamp string from the log into a Python datetime object using the specified date format. |
| 87 | `    except ValueError:` | Handles an error raised in the matching try block. This keeps the program running and lets it print or return a safer result. |
| 88 | `        timestamp = None` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 89 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 90 | `    return {` | Sends a value back to the code that called this function, then stops the function. |
| 91 | `        "log_type":    "apache",` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 92 | `        "timestamp":   timestamp.isoformat() if timestamp else None,` | Converts a datetime object into ISO text format, which is easy to store and sort. |
| 93 | `        "source_ip":   fields["ip"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 94 | `        "http_method": fields["method"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 95 | `        "path":        fields["path"],` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 96 | `        "status_code": int(fields["status"]),` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 97 | `        "raw":         line,` | Defines one key-value pair inside a dictionary, usually part of an event or alert structure. |
| 98 | `    }` | Closes a multi-line dictionary, list, function call, SQL string, or expression started on earlier lines. |
| 99 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 100 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 101 | `def parse_line(line: str, log_type: str = "syslog") -> Optional[dict]:` | Starts a function named `parse_line`. The indented lines below it are grouped together and run only when this function is called. |
| 102 | `    """Single entry point. Routes to the right parser."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 103 | `    if log_type == "apache":` | Starts a condition. Python runs the indented block below only if this test is true. |
| 104 | `        return parse_apache_line(line)` | Sends a value back to the code that called this function, then stops the function. |
| 105 | `    return parse_syslog_line(line)` | Sends a value back to the code that called this function, then stops the function. |
| 106 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 107 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 108 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 109 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 110 | `'''def parse_log_file(filepath: str, log_type: str = "syslog") -> list[dict]:` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 111 | `    """Read an entire log file, return list of parsed event dicts."""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 112 | `    if not os.path.exists(filepath):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 113 | `        raise FileNotFoundError(f"Log file not found: {filepath}")` | Creates an error intentionally because the program cannot continue safely with the current input. |
| 114 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 115 | `    results = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 116 | `    skipped = 0` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 117 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 118 | `    with open(filepath, "r", encoding="utf-8", errors="replace") as f:` | Opens a file safely. Python will automatically close it when the indented block is finished. |
| 119 | `        for line in f:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 120 | `            parsed = parse_line(line, log_type=log_type)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 121 | `            if parsed:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 122 | `                results.append(parsed)` | Adds one item to the end of a list. |
| 123 | `            else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 124 | `                skipped += 1` | This line continues the current block at indentation level 16. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 125 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 126 | `    print(f"[parser] {filepath}: {len(results)} parsed, {skipped} skipped")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 127 | `    return results'''` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 128 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 129 | `def parse_log_file(filepath: str, log_type: str = "syslog") -> list[dict]:` | Starts a function named `parse_log_file`. The indented lines below it are grouped together and run only when this function is called. |
| 130 | `    if not os.path.exists(filepath):` | Starts a condition. Python runs the indented block below only if this test is true. |
| 131 | `        raise FileNotFoundError(f"Log file not found: {filepath}")` | Creates an error intentionally because the program cannot continue safely with the current input. |
| 132 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 133 | `    results = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 134 | `    skipped_lines = []` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 135 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 136 | `    with open(filepath, "r", encoding="utf-8", errors="replace") as f:` | Opens a file safely. Python will automatically close it when the indented block is finished. |
| 137 | `        for line in f:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 138 | `            parsed = parse_line(line, log_type=log_type)` | Assigns a value to a variable. The variable name on the left stores the result from the expression on the right. |
| 139 | `            if parsed:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 140 | `                results.append(parsed)` | Adds one item to the end of a list. |
| 141 | `            else:` | Fallback branch. Python runs this block when the earlier if/elif conditions were false. |
| 142 | `                skipped_lines.append(line.strip())` | Adds one item to the end of a list. |
| 143 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 144 | `    print(f"[parser] {filepath}: {len(results)} parsed, {len(skipped_lines)} skipped")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 145 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 146 | `    # Show the skipped lines so we know what format to fix` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 147 | `    if skipped_lines:` | Starts a condition. Python runs the indented block below only if this test is true. |
| 148 | `        print("[parser] Skipped lines sample:")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 149 | `        for l in skipped_lines[:5]:   # show first 5 only` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 150 | `            print(f"  >> {l}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 151 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 152 | `    return results` | Sends a value back to the code that called this function, then stops the function. |
| 153 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 154 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 155 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
