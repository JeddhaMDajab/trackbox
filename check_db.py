import sqlite3

db_path = 'trackbox.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(lost_items)")
columns = cursor.fetchall()
for col in columns:
    print(col)
conn.close()
