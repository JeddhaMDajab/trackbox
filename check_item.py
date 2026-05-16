import sqlite3

conn = sqlite3.connect('trackbox.db')
cursor = conn.cursor()

print("=== FOUND ITEMS (ID 5) ===")
cursor.execute('SELECT id, item_name, status, is_claimed, is_verified, is_archived FROM found_items WHERE id = 5')
row = cursor.fetchone()
if row:
    print(f"ID: {row[0]}")
    print(f"Name: {row[1]}")
    print(f"Status: {row[2]}")
    print(f"Claimed: {row[3]}")
    print(f"Verified: {row[4]}")
    print(f"Archived: {row[5]}")
else:
    print("Item not found")

print("\n=== ALL FOUND ITEMS ===")
cursor.execute('SELECT id, item_name, status, is_claimed, is_verified FROM found_items ORDER BY id')
for row in cursor.fetchall():
    print(f"ID: {row[0]}, Name: {row[1]}, Status: {row[2]}, Claimed: {row[3]}, Verified: {row[4]}")

conn.close()
