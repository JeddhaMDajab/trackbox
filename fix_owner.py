
import sqlite3

def fix_ownership():
    conn = sqlite3.connect('trackbox.db')
    cursor = conn.cursor()
    try:
        # Update Item 2 to belong to user1 so they can test it
        cursor.execute("UPDATE found_items SET reporter='user1' WHERE id=2")
        conn.commit()
        print("Successfully transferred Item #2 ownership to user1.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    fix_ownership()
