# Line-by-Line Explanation: database/inspect.py

This file explains every line in `database/inspect.py`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `# inspect_db.py  ← save this, run whenever you want to peek at the data` | Comment for the reader. Python ignores this line, but it explains or labels the code section. |
| 2 | `import sqlite3` | Imports the sqlite3 module so this file can use its built-in functions or classes later. |
| 3 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 4 | `conn = sqlite3.connect("threatlens/database/events.db")` | Opens a connection to the SQLite database so the code can read or write stored data. |
| 5 | `conn.row_factory = sqlite3.Row` | Tells SQLite to return rows that can be accessed by column name, which makes later code easier to read. |
| 6 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 7 | `print("=== Total events ===")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 8 | `count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]` | Runs an SQL command against the database, such as creating a table, inserting data, updating rows, or selecting rows. |
| 9 | `print(f"  {count} rows\n")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 10 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 11 | `print("=== Failed logins ===")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 12 | `rows = conn.execute("""` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 13 | `    SELECT timestamp, source_ip, message FROM events` | Begins an SQL query that reads rows from a database table. |
| 14 | `    WHERE message LIKE '%Failed password%'` | Adds filtering rules to an SQL query so only matching rows are returned. |
| 15 | `    OR message LIKE '%Invalid user%'` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 16 | `    ORDER BY timestamp DESC` | Sorts database results by a column, such as timestamp or creation time. |
| 17 | `    LIMIT 10` | This line continues the current block at indentation level 4. Read it together with the surrounding lines because it is part of a multi-line statement, data structure, SQL command, regex, or formatted string. |
| 18 | `""").fetchall()` | Docstring or large quoted text. It is used as documentation when placed inside a function, or as ignored text when used to comment out old code. |
| 19 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 20 | `for r in rows:` | Starts a loop. Python repeats the indented block once for each item in the sequence. |
| 21 | `    print(f"  {r['timestamp']}  {r['source_ip']}  {r['message'][:60]}")` | Prints information to the terminal so the user can see progress, results, or debugging details. |
| 22 | <blank> | Blank line used to visually separate sections of the program. It has no effect when Python runs. |
| 23 | `conn.close()` | Closes the database or file connection after the program is finished using it. |
