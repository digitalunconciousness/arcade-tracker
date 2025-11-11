# add_work_order_type_column.py
from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        # Add the work_order_type column
        with db.engine.connect() as conn:
            conn.execute(text(
                "ALTER TABLE maintenance_record ADD COLUMN work_order_type VARCHAR(50) DEFAULT 'game'"
            ))
            conn.commit()
        print("✅ Successfully added work_order_type column")
        
        # Verify the column was added
        result = db.session.execute(text("PRAGMA table_info(maintenance_record)"))
        columns = [row[1] for row in result]
        print(f"Current columns: {columns}")
        
    except Exception as e:
        print(f"❌ Error: {e}")