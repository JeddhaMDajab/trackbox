import sqlite3
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
conn = sqlite3.connect(os.path.join(BASE_DIR, 'trackbox.db'))
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(users)")
cols = cursor.fetchall()
for col in cols:
    print(col)
conn.close()
