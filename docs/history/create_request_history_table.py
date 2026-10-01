"""Create inventory_request_history table if it doesn't exist"""
from app import app, db

with app.app_context():
    # Create table using raw SQL to avoid migration issues
    with db.engine.connect() as conn:
        conn.execute(db.text("""
        CREATE TABLE IF NOT EXISTS inventory_request_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            action VARCHAR(50) NOT NULL,
            field_changed VARCHAR(50),
            old_value VARCHAR(500),
            new_value VARCHAR(500),
            notes TEXT,
            timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES inventory_request(id),
            FOREIGN KEY (user_id) REFERENCES user(id)
        )
        """))
        conn.commit()
    
    print("✅ inventory_request_history table created/verified successfully!")
