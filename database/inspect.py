# inspect_db.py  ← save this, run whenever you want to peek at the data
import sqlite3

conn = sqlite3.connect("threatlens/database/events.db")
conn.row_factory = sqlite3.Row

print("=== Total events ===")
count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
print(f"  {count} rows\n")

print("=== Failed logins ===")
rows = conn.execute("""
    SELECT timestamp, source_ip, message FROM events
    WHERE message LIKE '%Failed password%'
    OR message LIKE '%Invalid user%'
    ORDER BY timestamp DESC
    LIMIT 10
""").fetchall()

for r in rows:
    print(f"  {r['timestamp']}  {r['source_ip']}  {r['message'][:60]}")

conn.close()