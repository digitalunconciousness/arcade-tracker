#!/usr/bin/env python3
"""
Database migration script to add missing columns to the game table.
This script adds the counter_status and counter_notes columns that are defined
in the Game model but missing from the actual database.
"""

import sqlite3
import sys
import os

def migrate_database():
    """Add missing columns to the game table"""
    
    # Database file path - Flask uses instance folder
    db_path = 'instance/arcade.db'
    
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} not found!")
        return False
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if counter_status column exists
        cursor.execute("PRAGMA table_info(game)")
        columns = [column[1] for column in cursor.fetchall()]
        
        print(f"Current columns in game table: {columns}")
        
        # Add counter_status column if it doesn't exist
        if 'counter_status' not in columns:
            print("Adding counter_status column...")
            cursor.execute("ALTER TABLE game ADD COLUMN counter_status VARCHAR(20) DEFAULT 'Working'")
            print("✓ counter_status column added")
        else:
            print("✓ counter_status column already exists")
        
        # Add counter_notes column if it doesn't exist
        if 'counter_notes' not in columns:
            print("Adding counter_notes column...")
            cursor.execute("ALTER TABLE game ADD COLUMN counter_notes TEXT")
            print("✓ counter_notes column added")
        else:
            print("✓ counter_notes column already exists")
        
        # Commit the changes
        conn.commit()
        
        # Verify the columns were added
        cursor.execute("PRAGMA table_info(game)")
        columns_after = [column[1] for column in cursor.fetchall()]
        print(f"Columns after migration: {columns_after}")
        
        conn.close()
        print("\n✅ Database migration completed successfully!")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("Starting database migration...")
    success = migrate_database()
    sys.exit(0 if success else 1)