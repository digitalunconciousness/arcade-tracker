#!/usr/bin/env python3
"""
Comprehensive database schema checker to identify all missing columns.
"""

import sqlite3
import os

def check_table_schema(cursor, table_name, expected_columns):
    """Check if a table has the expected columns"""
    print(f"\n=== Checking {table_name} table ===")
    
    # Check if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    if not cursor.fetchone():
        print(f"❌ {table_name} table does not exist")
        return False
    
    # Get actual columns
    cursor.execute(f"PRAGMA table_info({table_name})")
    actual_columns = [column[1] for column in cursor.fetchall()]
    
    print(f"Actual columns: {actual_columns}")
    print(f"Expected columns: {expected_columns}")
    
    missing_columns = [col for col in expected_columns if col not in actual_columns]
    
    if missing_columns:
        print(f"❌ Missing columns: {missing_columns}")
        return missing_columns
    else:
        print("✅ All expected columns present")
        return []

def check_database_comprehensive(db_path):
    """Check all tables in the database for missing columns"""
    print(f"\n{'='*50}")
    print(f"Checking {db_path}")
    print(f"{'='*50}")
    
    if not os.path.exists(db_path):
        print(f"❌ Database file {db_path} not found!")
        return {}
    
    # Define expected columns for each table based on the models
    expected_schemas = {
        'game': [
            'id', 'name', 'manufacturer', 'year', 'genre', 'location', 
            'floor_position', 'warehouse_section', 'status', 'coins_per_play', 
            'total_plays', 'total_revenue', 'counter_status', 'counter_notes',
            'date_added', 'notes', 'image_filename', 'times_in_top_5', 'times_in_top_10'
        ],
        'maintenance_record': [
            'id', 'game_id', 'issue_description', 'fix_description', 'work_notes',
            'parts_used', 'cost', 'date_reported', 'date_fixed', 'status',
            'technician', 'photos'
        ],
        'play_record': [
            'id', 'game_id', 'coin_count', 'plays_count', 'revenue', 
            'date_recorded', 'notes'
        ],
        'user': [
            'id', 'username', 'password_hash', 'role', 'is_active', 'created_at',
            'must_change_password', 'profile_picture', 'last_login'
        ],
        'work_log': [
            'id', 'maintenance_id', 'user_id', 'work_description', 'parts_used',
            'time_spent', 'cost_incurred', 'timestamp'
        ]
    }
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        all_missing = {}
        
        for table_name, expected_columns in expected_schemas.items():
            missing = check_table_schema(cursor, table_name, expected_columns)
            if missing:
                all_missing[table_name] = missing
        
        conn.close()
        return all_missing
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return {}

if __name__ == "__main__":
    print("Comprehensive database schema check...")
    
    # Check instance database (the one Flask uses)
    missing_columns = check_database_comprehensive('instance/arcade.db')
    
    if missing_columns:
        print(f"\n{'='*50}")
        print("SUMMARY OF MISSING COLUMNS:")
        print(f"{'='*50}")
        for table, columns in missing_columns.items():
            print(f"{table}: {columns}")
    else:
        print(f"\n{'='*50}")
        print("✅ All tables have the expected columns!")
        print(f"{'='*50}")