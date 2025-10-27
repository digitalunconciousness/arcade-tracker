#!/usr/bin/env python3
"""
Database restore script for Arcade Tracker
Restores database from backup files with validation
"""

import os
import sys
import shutil
import sqlite3
from datetime import datetime
import argparse

# Configuration
DATABASE_PATH = 'arcade.db'
BACKUP_DIR = 'backups'
INSTANCE_DB_PATH = 'instance/arcade.db'

def list_available_backups():
    """List all available backup files"""
    if not os.path.exists(BACKUP_DIR):
        print("❌ No backup directory found")
        return []
    
    backups = []
    for filename in os.listdir(BACKUP_DIR):
        if filename.startswith('arcade_backup_') and filename.endswith('.db'):
            filepath = os.path.join(BACKUP_DIR, filename)
            file_size = os.path.getsize(filepath)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            backups.append((filename, filepath, file_time, file_size))
    
    if not backups:
        print("❌ No backup files found")
        return []
    
    # Sort by timestamp (newest first)
    backups.sort(key=lambda x: x[2], reverse=True)
    
    print("\nAvailable backups:")
    print("-" * 70)
    for i, (filename, filepath, file_time, file_size) in enumerate(backups, 1):
        size_mb = file_size / (1024 * 1024)
        print(f"{i:2}. {filename:<35} {file_time.strftime('%Y-%m-%d %H:%M:%S')} ({size_mb:.2f} MB)")
    
    return backups

def verify_backup_integrity(backup_path):
    """Verify that a backup file is valid and intact"""
    try:
        print(f"🔍 Verifying backup integrity: {backup_path}")
        
        conn = sqlite3.connect(backup_path)
        cursor = conn.cursor()
        
        # Check that main tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['user', 'game', 'play_record', 'maintenance_record']
        missing_tables = [table for table in expected_tables if table not in tables]
        
        if missing_tables:
            print(f"❌ Backup missing tables: {missing_tables}")
            conn.close()
            return False
        
        # Check table integrity and record counts
        for table in expected_tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table};")
            count = cursor.fetchone()[0]
            print(f"  ✅ {table}: {count} records")
        
        # Check that we can read from each table
        try:
            cursor.execute("SELECT * FROM user LIMIT 1;")
            cursor.execute("SELECT * FROM game LIMIT 1;")
            cursor.execute("SELECT * FROM play_record LIMIT 1;")
            cursor.execute("SELECT * FROM maintenance_record LIMIT 1;")
        except Exception as e:
            print(f"❌ Error reading from tables: {e}")
            conn.close()
            return False
        
        conn.close()
        print("✅ Backup integrity verified successfully")
        return True
        
    except Exception as e:
        print(f"❌ Backup verification failed: {e}")
        return False

def create_current_backup():
    """Create a backup of the current database before restore"""
    try:
        # Determine current database path
        current_db = None
        if os.path.exists(INSTANCE_DB_PATH) and os.path.getsize(INSTANCE_DB_PATH) > 0:
            current_db = INSTANCE_DB_PATH
        elif os.path.exists(DATABASE_PATH) and os.path.getsize(DATABASE_PATH) > 0:
            current_db = DATABASE_PATH
        
        if not current_db:
            print("ℹ️  No current database to backup")
            return True
        
        # Create backup directory if needed
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
        
        # Create pre-restore backup
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"arcade_backup_pre_restore_{timestamp}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Use SQLite backup API
        source_conn = sqlite3.connect(current_db)
        backup_conn = sqlite3.connect(backup_path)
        source_conn.backup(backup_conn)
        source_conn.close()
        backup_conn.close()
        
        print(f"✅ Current database backed up to: {backup_path}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to backup current database: {e}")
        return False

def restore_database(backup_path, target_path=None):
    """Restore database from backup file"""
    try:
        if target_path is None:
            # Default to main database path
            target_path = DATABASE_PATH
        
        print(f"🔄 Restoring database from: {backup_path}")
        print(f"🔄 Restoring to: {target_path}")
        
        # Ensure target directory exists
        target_dir = os.path.dirname(target_path)
        if target_dir and not os.path.exists(target_dir):
            os.makedirs(target_dir)
        
        # Use SQLite backup to restore (safer than file copy)
        source_conn = sqlite3.connect(backup_path)
        target_conn = sqlite3.connect(target_path)
        
        # Clear target database first
        cursor = target_conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        for table in tables:
            cursor.execute(f"DROP TABLE IF EXISTS {table};")
        target_conn.commit()
        
        # Restore from backup
        source_conn.backup(target_conn)
        
        source_conn.close()
        target_conn.close()
        
        print(f"✅ Database restored successfully to: {target_path}")
        
        # Verify the restored database
        if verify_backup_integrity(target_path):
            print("✅ Restored database verification passed")
            return True
        else:
            print("❌ Restored database verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Database restore failed: {e}")
        return False

def interactive_restore():
    """Interactive restore process"""
    backups = list_available_backups()
    if not backups:
        return False
    
    print(f"\nSelect a backup to restore:")
    while True:
        try:
            choice = input("Enter backup number (or 'q' to quit): ").strip()
            if choice.lower() == 'q':
                print("Restore cancelled")
                return False
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(backups):
                selected_backup = backups[choice_num - 1]
                break
            else:
                print(f"Please enter a number between 1 and {len(backups)}")
        except ValueError:
            print("Please enter a valid number or 'q' to quit")
    
    backup_filename, backup_path, backup_time, backup_size = selected_backup
    
    print(f"\nSelected backup: {backup_filename}")
    print(f"Created: {backup_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Size: {backup_size / (1024 * 1024):.2f} MB")
    
    # Verify backup integrity
    if not verify_backup_integrity(backup_path):
        print("❌ Backup verification failed. Restore cancelled.")
        return False
    
    # Confirm restore
    print("\n⚠️  WARNING: This will replace your current database!")
    print("Current database will be backed up before restore.")
    
    confirm = input("Continue with restore? (yes/no): ").strip().lower()
    if confirm not in ['yes', 'y']:
        print("Restore cancelled")
        return False
    
    # Create backup of current database
    if not create_current_backup():
        print("❌ Failed to backup current database. Restore cancelled for safety.")
        return False
    
    # Perform restore
    success = restore_database(backup_path, DATABASE_PATH)
    
    # Also restore to instance path if it exists
    if os.path.exists('instance'):
        restore_database(backup_path, INSTANCE_DB_PATH)
    
    return success

def main():
    parser = argparse.ArgumentParser(description='Database restore utility for Arcade Tracker')
    parser.add_argument('--backup-file', '-f', help='Specific backup file to restore')
    parser.add_argument('--list', '-l', action='store_true', help='List available backups')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive restore mode')
    parser.add_argument('--verify', '-v', help='Verify integrity of a backup file')
    
    args = parser.parse_args()
    
    # Change to project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    os.chdir(parent_dir)
    
    if args.list:
        list_available_backups()
    elif args.verify:
        if verify_backup_integrity(args.verify):
            print("✅ Backup file is valid")
            sys.exit(0)
        else:
            print("❌ Backup file is invalid")
            sys.exit(1)
    elif args.backup_file:
        if not os.path.exists(args.backup_file):
            print(f"❌ Backup file not found: {args.backup_file}")
            sys.exit(1)
        
        if not verify_backup_integrity(args.backup_file):
            print("❌ Backup verification failed")
            sys.exit(1)
        
        if create_current_backup():
            if restore_database(args.backup_file):
                print("✅ Restore completed successfully")
            else:
                print("❌ Restore failed")
                sys.exit(1)
    else:
        # Default to interactive mode
        if interactive_restore():
            print("\n🎉 Database restore completed successfully!")
            print("You can now restart your Arcade Tracker application.")
        else:
            print("\n❌ Restore process failed or was cancelled")

if __name__ == '__main__':
    main()