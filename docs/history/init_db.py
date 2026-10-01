#!/usr/bin/env python3
"""
Initialize database with all required tables and columns
"""
import os
import sys
import sqlite3
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db

def backup_database():
    """Create a backup of the current database"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = 'backups'
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    source_db = 'arcade.db'
    backup_path = os.path.join(backup_dir, f"arcade_backup_before_init_{timestamp}.db")
    
    if os.path.exists(source_db):
        try:
            source_conn = sqlite3.connect(source_db)
            backup_conn = sqlite3.connect(backup_path)
            source_conn.backup(backup_conn)
            source_conn.close()
            backup_conn.close()
            print(f"✅ Backup created: {backup_path}")
            return backup_path
        except Exception as e:
            print(f"❌ Failed to create backup: {e}")
            return None
    return None

def check_table_exists(db_path, table_name):
    """Check if a table exists in the database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name=?;
    """, (table_name,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def check_column_exists(db_path, table_name, column_name):
    """Check if a column exists in a table"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = [row[1] for row in cursor.fetchall()]
    conn.close()
    return column_name in columns

def init_database():
    """Initialize the database with all required tables"""
    print("🔄 Initializing database...")
    
    # Create backup first
    backup_path = backup_database()
    
    try:
        with app.app_context():
            # Create all tables
            print("Creating all tables...")
            db.create_all()
            
            # Check specific table that was causing the error
            db_path = 'arcade.db'
            
            if check_table_exists(db_path, 'game'):
                print("✅ Game table exists")
                
                # Check for the specific missing column
                if check_column_exists(db_path, 'game', 'counter_status'):
                    print("✅ counter_status column exists")
                else:
                    print("❌ counter_status column missing - adding it")
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute("ALTER TABLE game ADD COLUMN counter_status VARCHAR(20) DEFAULT 'Working';")
                    cursor.execute("ALTER TABLE game ADD COLUMN counter_notes TEXT;")
                    conn.commit()
                    conn.close()
                    print("✅ Added counter_status and counter_notes columns")
            else:
                print("❌ Game table missing - this should have been created by db.create_all()")
                return False
                
            print("✅ Database initialization completed successfully!")
            return True
            
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

if __name__ == '__main__':
    success = init_database()
    if not success:
        print("Database initialization failed!")
        sys.exit(1)