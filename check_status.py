import sqlite3

conn = sqlite3.connect('trackbox.db')
cursor = conn.cursor()

print("=== FOUND ITEMS ===")
cursor.execute('SELECT id, item_name, status, is_claimed, is_verified FROM found_items')
for row in cursor.fetchall():
    print(f"ID: {row[0]}, Name: {row[1]}, Status: {row[2]}, Claimed: {row[3]}, Verified: {row[4]}")

conn.close()
