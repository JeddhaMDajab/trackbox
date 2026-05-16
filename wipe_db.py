import sqlite3
import os
import glob

def wipe_data():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, 'trackbox.db')
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Added 'users' to the list to clear all account data
    tables_to_clear = ['users', 'found_items', 'lost_items', 'notifications', 'messages']
    
    print(f"Wiping data from {db_path}...")
    for table in tables_to_clear:
        try:
            cursor.execute(f"DELETE FROM {table}")
            print(f"Cleared table: {table}")
        except sqlite3.OperationalError as e:
            print(f"Table {table} error: {e}")

    # Reset auto-increment counters
    try:
        cursor.execute(f"DELETE FROM sqlite_sequence WHERE name IN ({','.join(['?' for _ in tables_to_clear])})", tables_to_clear)
        print("Reset auto-increment sequences.")
    except Exception as e:
        print(f"Error resetting sequences: {e}")

    conn.commit()
    conn.close()

    # Clear uploads (profile images, item images)
    upload_path = os.path.join(BASE_DIR, 'uploads', '*')
    for f in glob.glob(upload_path):
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(f"Deleted {f}")
            except Exception as e:
                print(f"Error deleting {f}: {e}")
    
    # Clear temp uploads
    temp_path = os.path.join(BASE_DIR, 'temp_uploads', '*')
    for f in glob.glob(temp_path):
        if os.path.isfile(f):
             try:
                os.remove(f)
                print(f"Deleted {f}")
             except Exception as e:
                print(f"Error deleting {f}: {e}")
    
    print("Database and files wiped successfully.")

if __name__ == "__main__":
    wipe_data()
