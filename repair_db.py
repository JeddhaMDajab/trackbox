import sqlite3
import os

def hard_migrate():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, 'trackbox.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print(f"Repairing schema in {db_path}...")
    
    # 1. Get existing users
    try:
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        cursor.execute("PRAGMA table_info(users)")
        cols = [col[1] for col in cursor.fetchall()]
        
        # Map old data to new columns
        users_data = []
        for row in rows:
            user_dict = dict(zip(cols, row))
            # Handle missing or renamed fields
            users_data.append({
                "username": user_dict.get("username"),
                "first_name": user_dict.get("first_name", ""),
                "middle_name": user_dict.get("middle_name", ""),
                "last_name": user_dict.get("last_name", ""),
                "email": user_dict.get("email"),
                "hashed_password": user_dict.get("hashed_password"),
                "role": user_dict.get("role", "student"),
                "profile_image": user_dict.get("profile_image"),
                "points": user_dict.get("points", 0),
                "reset_token": user_dict.get("reset_token")
            })
    except Exception as e:
        print(f"Error reading old data: {e}")
        users_data = []

    # 2. Drop and Recreate
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR UNIQUE,
            first_name VARCHAR,
            middle_name VARCHAR,
            last_name VARCHAR,
            email VARCHAR UNIQUE,
            hashed_password VARCHAR,
            role VARCHAR DEFAULT 'student',
            profile_image VARCHAR,
            points INTEGER DEFAULT 0,
            reset_token VARCHAR
        )
    """)
    
    # 3. Insert data back
    for u in users_data:
        try:
            cursor.execute("""
                INSERT INTO users (username, first_name, middle_name, last_name, email, hashed_password, role, profile_image, points, reset_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (u['username'], u['first_name'], u['middle_name'], u['last_name'], u['email'], u['hashed_password'], u['role'], u['profile_image'], u['points'], u['reset_token']))
        except Exception as e:
            print(f"Error restoring user {u['username']}: {e}")

    conn.commit()
    conn.close()
    print("Schema repair complete.")

if __name__ == "__main__":
    hard_migrate()
