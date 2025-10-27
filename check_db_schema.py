#!/usr/bin/env python3
"""
Check database schema to identify which database file is missing columns.
"""

import sqlite3
import os

def check_database_schema(db_path):
    """Check if the database has the required columns"""
    print(f"\n=== Checking {db_path} ===")
    
    if not os.path.exists(db_path):
        print(f"❌ Database file {db_path} not found!")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if game table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='game'")
        if not cursor.fetchone():
            print("❌ game table does not exist")
            conn.close()
            return False
        
        # Check columns in game table
        cursor.execute("PRAGMA table_info(game)")
        columns = [column[1] for column in cursor.fetchall()]
        
        print(f"Columns in game table: {columns}")
        
        # Check for required columns
        required_columns = ['counter_status', 'counter_notes']
        missing_columns = [col for col in required_columns if col not in columns]
        
        if missing_columns:
            print(f"❌ Missing columns: {missing_columns}")
            result = False
        else:
            print("✅ All required columns present")
            result = True
        
        conn.close()
        return result
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False

if __name__ == "__main__":
    print("Checking database schemas...")
    
    # Check various database files
    databases_to_check = [
        'arcade.db',
        'instance/arcade.db'
    ]
    
    for db_path in databases_to_check:
        check_database_schema(db_path)
    
    print("\nDone checking databases.")