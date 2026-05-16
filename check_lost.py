import sqlite3

conn = sqlite3.connect('trackbox.db')
cursor = conn.cursor()

print("=== LOST ITEMS (ID 5) ===")
cursor.execute('SELECT id, item_name, type, status, is_archived, reporter FROM lost_items WHERE id = 5')
row = cursor.fetchone()
if row:
    print(f"ID: {row[0]}")
    print(f"Name: {row[1]}")
    print(f"Type: {row[2]}")
    print(f"Status: {row[3]}")
    print(f"Archived: {row[4]}")
    print(f"Reporter: {row[5]}")
else:
    print("Item not found in lost_items")

print("\n=== ALL LOST ITEMS ===")
cursor.execute('SELECT id, item_name, type, status, reporter FROM lost_items ORDER BY id')
for row in cursor.fetchall():
    print(f"ID: {row[0]}, Name: {row[1]}, Type: {row[2]}, Status: {row[3]}, Reporter: {row[4]}")

conn.close()
