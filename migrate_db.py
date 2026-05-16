import sqlite3
import os

db_path = r'c:\Users\Andrea\Downloads\finalproject (1)\finalproject\trackbox.db'

def migrate():
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        print("Adding is_owner_verified column...")
        cursor.execute("ALTER TABLE lost_items ADD COLUMN is_owner_verified BOOLEAN DEFAULT 0")
        print("Done.")
    except sqlite3.OperationalError as e:
        print(f"Could not add is_owner_verified: {e}")

    try:
        print("Adding verified_at column...")
        cursor.execute("ALTER TABLE lost_items ADD COLUMN verified_at DATETIME")
        print("Done.")
    except sqlite3.OperationalError as e:
        print(f"Could not add verified_at: {e}")

    conn.commit()
    conn.close()
    print("Migration finished.")

if __name__ == "__main__":
    migrate()
