
import sqlite3

def restore_item():
    conn = sqlite3.connect('trackbox.db')
    cursor = conn.cursor()
    try:
        # Check if item 2 exists
        cursor.execute("SELECT id FROM found_items WHERE id=2")
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO found_items (id, reporter, item_name, category, description, found_in, status, is_claimed, is_verified, is_archived, created_at)
                VALUES (2, 'user2', 'Restored iPhone 7', 'Electronics', 'Black iPhone 7 found in Lobby', 'Lobby', 'Found', 0, 0, 0, datetime('now'))
            """)
            conn.commit()
            print("Successfully restored Found Item #2 for user2")
        else:
            print("Item #2 already exists")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    restore_item()
