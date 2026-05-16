from main import DATABASE_URL, SessionLocal
from sqlalchemy import text
import os

print(f"ABS PATH of trackbox.db expected: {os.path.abspath('trackbox.db')}")
print(f"DATABASE_URL used in app: {DATABASE_URL}")

db = SessionLocal()
try:
    result = db.execute(text("PRAGMA table_info(lost_items)")).fetchall()
    print("Columns in lost_items:")
    for row in result:
        print(f"  {row}")
    
    # Check if we can query it
    from main import LostItem
    print("Attempting to query LostItem...")
    lost = db.query(LostItem).first()
    print("Query successful!")
except Exception as e:
    print(f"ERROR: {e}")
finally:
    db.close()
