#!/usr/bin/env python3
"""
Database backup script for Arcade Tracker
Creates timestamped backups and manages backup retention
"""

import os
import sys
import shutil
import sqlite3
from datetime import datetime, timedelta
import argparse

# Configuration
DATABASE_PATH = 'arcade.db'
BACKUP_DIR = 'backups'
MAX_BACKUPS = 30  # Keep 30 days of backups
INSTANCE_DB_PATH = 'instance/arcade.db'

def ensure_backup_dir():
    """Create backup directory if it doesn't exist"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        print(f"Created backup directory: {BACKUP_DIR}")

def get_database_path():
    """Determine which database file to backup"""
    # Check if instance database exists and has content
    if os.path.exists(INSTANCE_DB_PATH) and os.path.getsize(INSTANCE_DB_PATH) > 0:
        return INSTANCE_DB_PATH
    elif os.path.exists(DATABASE_PATH) and os.path.getsize(DATABASE_PATH) > 0:
        return DATABASE_PATH
    else:
        raise FileNotFoundError("No valid database file found")

def create_backup():
    """Create a timestamped backup of the database"""
    try:
        ensure_backup_dir()
        db_path = get_database_path()
        
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"arcade_backup_{timestamp}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Perform SQLite backup (safer than file copy for active databases)
        source_conn = sqlite3.connect(db_path)
        backup_conn = sqlite3.connect(backup_path)
        
        # Use SQLite's backup API
        source_conn.backup(backup_conn)
        
        source_conn.close()
        backup_conn.close()
        
        print(f"✅ Database backed up successfully: {backup_path}")
        
        # Verify backup
        if verify_backup(backup_path):
            print(f"✅ Backup verified successfully")
            return backup_path
        else:
            print(f"❌ Backup verification failed")
            os.remove(backup_path)
            return None
            
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return None

def verify_backup(backup_path):
    """Verify that the backup file is valid"""
    try:
        conn = sqlite3.connect(backup_path)
        
        # Check that main tables exist and have some structure
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['user', 'game', 'play_record', 'maintenance_record']
        missing_tables = [table for table in expected_tables if table not in tables]
        
        if missing_tables:
            print(f"❌ Backup missing tables: {missing_tables}")
            conn.close()
            return False
        
        # Check that we can query the tables
        for table in expected_tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table};")
            count = cursor.fetchone()[0]
            print(f"  - {table}: {count} records")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Backup verification failed: {e}")
        return False

def cleanup_old_backups():
    """Remove backups older than MAX_BACKUPS days"""
    global MAX_BACKUPS
    if not os.path.exists(BACKUP_DIR):
        return
    
    cutoff_date = datetime.now() - timedelta(days=MAX_BACKUPS)
    removed_count = 0
    
    for filename in os.listdir(BACKUP_DIR):
        if filename.startswith('arcade_backup_') and filename.endswith('.db'):
            filepath = os.path.join(BACKUP_DIR, filename)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            
            if file_time < cutoff_date:
                try:
                    os.remove(filepath)
                    removed_count += 1
                    print(f"🗑️  Removed old backup: {filename}")
                except Exception as e:
                    print(f"❌ Failed to remove {filename}: {e}")
    
    if removed_count > 0:
        print(f"✅ Cleaned up {removed_count} old backups")
    else:
        print("ℹ️  No old backups to clean up")

def list_backups():
    """List all available backups"""
    if not os.path.exists(BACKUP_DIR):
        print("No backup directory found")
        return
    
    backups = []
    for filename in os.listdir(BACKUP_DIR):
        if filename.startswith('arcade_backup_') and filename.endswith('.db'):
            filepath = os.path.join(BACKUP_DIR, filename)
            file_size = os.path.getsize(filepath)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            backups.append((filename, file_time, file_size))
    
    if not backups:
        print("No backups found")
        return
    
    backups.sort(key=lambda x: x[1], reverse=True)
    
    print("\nAvailable backups:")
    print("-" * 60)
    for filename, file_time, file_size in backups:
        size_mb = file_size / (1024 * 1024)
        print(f"{filename:<30} {file_time.strftime('%Y-%m-%d %H:%M:%S')} ({size_mb:.2f} MB)")

def main():
    parser = argparse.ArgumentParser(description='Database backup management for Arcade Tracker')
    parser.add_argument('action', choices=['backup', 'list', 'cleanup'], 
                       help='Action to perform')
    parser.add_argument('--max-backups', type=int, default=30,
                       help=f'Maximum number of backups to keep (default: 30)')
    
    args = parser.parse_args()
    
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    os.chdir(parent_dir)
    
    # Update configuration
    MAX_BACKUPS = args.max_backups
    
    if args.action == 'backup':
        backup_path = create_backup()
        if backup_path:
            cleanup_old_backups()
    elif args.action == 'list':
        list_backups()
    elif args.action == 'cleanup':
        cleanup_old_backups()

if __name__ == '__main__':
    main()