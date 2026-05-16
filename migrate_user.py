import sqlite3

import os

def migrate():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, 'trackbox.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if columns exists in 'users'
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    
    needed_cols = {
        'profile_image': 'TEXT',
        'reset_token': 'TEXT',
        'first_name': 'TEXT',
        'middle_name': 'TEXT',
        'last_name': 'TEXT'
    }

    for col, col_type in needed_cols.items():
        if col not in columns:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
                print(f"Added '{col}' column.")
            except Exception as e:
                print(f"Error adding {col}: {e}")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
