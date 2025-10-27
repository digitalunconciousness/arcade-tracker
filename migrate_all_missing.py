#!/usr/bin/env python3
"""
Comprehensive database migration script to add all missing columns.
"""

import sqlite3
import sys
import os

def add_missing_column(cursor, table_name, column_name, column_definition):
    """Add a missing column to a table"""
    try:
        query = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        cursor.execute(query)
        print(f"✓ Added {column_name} to {table_name}")
        return True
    except sqlite3.Error as e:
        print(f"❌ Failed to add {column_name} to {table_name}: {e}")
        return False

def migrate_all_missing_columns():
    """Add all missing columns to the database"""
    
    # Database file path - Flask uses instance folder
    db_path = 'instance/arcade.db'
    
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} not found!")
        return False
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Starting comprehensive database migration...")
        
        # Define missing columns and their definitions
        missing_columns = {
            'maintenance_record': [
                ('photos', 'TEXT')  # JSON array of photo filenames
            ]
        }
        
        success_count = 0
        
        for table_name, columns in missing_columns.items():
            print(f"\n=== Migrating {table_name} table ===")
            
            # Check current columns
            cursor.execute(f"PRAGMA table_info({table_name})")
            existing_columns = [column[1] for column in cursor.fetchall()]
            print(f"Current columns: {existing_columns}")
            
            for column_name, column_def in columns:
                if column_name not in existing_columns:
                    if add_missing_column(cursor, table_name, column_name, column_def):
                        success_count += 1
                else:
                    print(f"✓ {column_name} already exists in {table_name}")
        
        # Commit the changes
        conn.commit()
        
        # Verify the columns were added
        print(f"\n=== Verification ===")
        for table_name in missing_columns.keys():
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns_after = [column[1] for column in cursor.fetchall()]
            print(f"{table_name} columns after migration: {columns_after}")
        
        conn.close()
        
        print(f"\n✅ Database migration completed successfully!")
        print(f"   Added {success_count} missing column(s)")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("Starting comprehensive database migration...")
    success = migrate_all_missing_columns()
    sys.exit(0 if success else 1)