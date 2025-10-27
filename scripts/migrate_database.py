#!/usr/bin/env python3
"""
Database migration system for Arcade Tracker
Handles schema changes without data loss using ALTER TABLE statements
"""

import os
import sys
import sqlite3
from datetime import datetime
import argparse
import json

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

# Configuration
MIGRATIONS_DIR = 'migrations'
MIGRATION_TABLE = 'schema_migrations'

class Migration:
    """Represents a single database migration"""
    
    def __init__(self, version, name, up_sql, down_sql=None):
        self.version = version
        self.name = name
        self.up_sql = up_sql
        self.down_sql = down_sql
    
    def apply(self, conn):
        """Apply the migration"""
        cursor = conn.cursor()
        for statement in self.up_sql:
            cursor.execute(statement)
        conn.commit()
    
    def rollback(self, conn):
        """Rollback the migration"""
        if not self.down_sql:
            raise ValueError(f"No rollback SQL defined for migration {self.version}")
        
        cursor = conn.cursor()
        for statement in self.down_sql:
            cursor.execute(statement)
        conn.commit()

# Define migrations
MIGRATIONS = [
    Migration(
        version=1,
        name="Add work_notes column to maintenance_record",
        up_sql=[
            "ALTER TABLE maintenance_record ADD COLUMN work_notes TEXT;"
        ],
        down_sql=[
            "ALTER TABLE maintenance_record DROP COLUMN work_notes;"
        ]
    ),
    Migration(
        version=2,
        name="Add indexes for better performance",
        up_sql=[
            "CREATE INDEX IF NOT EXISTS idx_game_location ON game(location);",
            "CREATE INDEX IF NOT EXISTS idx_game_status ON game(status);",
            "CREATE INDEX IF NOT EXISTS idx_play_record_date ON play_record(date_recorded);",
            "CREATE INDEX IF NOT EXISTS idx_maintenance_status ON maintenance_record(status);",
            "CREATE INDEX IF NOT EXISTS idx_maintenance_date ON maintenance_record(date_reported);"
        ],
        down_sql=[
            "DROP INDEX IF EXISTS idx_game_location;",
            "DROP INDEX IF EXISTS idx_game_status;",
            "DROP INDEX IF EXISTS idx_play_record_date;",
            "DROP INDEX IF EXISTS idx_maintenance_status;",
            "DROP INDEX IF EXISTS idx_maintenance_date;"
        ]
    ),
    # Add future migrations here...
]

def ensure_migrations_table(conn):
    """Create the migrations tracking table if it doesn't exist"""
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

def get_applied_migrations(conn):
    """Get list of applied migration versions"""
    cursor = conn.cursor()
    cursor.execute(f"SELECT version FROM {MIGRATION_TABLE} ORDER BY version;")
    return [row[0] for row in cursor.fetchall()]

def mark_migration_applied(conn, migration):
    """Mark a migration as applied"""
    cursor = conn.cursor()
    cursor.execute(f"""
        INSERT INTO {MIGRATION_TABLE} (version, name, applied_at)
        VALUES (?, ?, ?);
    """, (migration.version, migration.name, datetime.now()))
    conn.commit()

def mark_migration_rollback(conn, migration):
    """Remove migration from applied list"""
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {MIGRATION_TABLE} WHERE version = ?;", (migration.version,))
    conn.commit()

def backup_before_migration(db_path):
    """Create a backup before applying migrations"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = 'backups'
        
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        backup_path = os.path.join(backup_dir, f"arcade_backup_pre_migration_{timestamp}.db")
        
        # Use SQLite backup API
        source_conn = sqlite3.connect(db_path)
        backup_conn = sqlite3.connect(backup_path)
        source_conn.backup(backup_conn)
        source_conn.close()
        backup_conn.close()
        
        print(f"✅ Pre-migration backup created: {backup_path}")
        return backup_path
        
    except Exception as e:
        print(f"❌ Failed to create pre-migration backup: {e}")
        return None

def check_column_exists(conn, table_name, column_name):
    """Check if a column exists in a table"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def safe_add_column(conn, table_name, column_definition):
    """Safely add a column if it doesn't exist"""
    column_name = column_definition.split()[0]
    if not check_column_exists(conn, table_name, column_name):
        cursor = conn.cursor()
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_definition};")
        conn.commit()
        print(f"✅ Added column {column_name} to {table_name}")
        return True
    else:
        print(f"ℹ️  Column {column_name} already exists in {table_name}")
        return False

def get_database_path():
    """Get the correct database path"""
    instance_path = 'instance/arcade.db'
    root_path = 'arcade.db'
    
    if os.path.exists(instance_path) and os.path.getsize(instance_path) > 0:
        return instance_path
    elif os.path.exists(root_path) and os.path.getsize(root_path) > 0:
        return root_path
    else:
        # Default to root path for new databases
        return root_path

def migrate_up(target_version=None):
    """Apply migrations up to target version (or all if None)"""
    db_path = get_database_path()
    print(f"Using database: {db_path}")
    
    # Create backup
    backup_path = backup_before_migration(db_path)
    if not backup_path:
        print("❌ Cannot proceed without backup")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        ensure_migrations_table(conn)
        applied_versions = get_applied_migrations(conn)
        
        print(f"Currently applied migrations: {applied_versions}")
        
        # Find migrations to apply
        migrations_to_apply = []
        for migration in MIGRATIONS:
            if migration.version not in applied_versions:
                if target_version is None or migration.version <= target_version:
                    migrations_to_apply.append(migration)
        
        if not migrations_to_apply:
            print("✅ No migrations to apply")
            conn.close()
            return True
        
        print(f"Migrations to apply: {[m.version for m in migrations_to_apply]}")
        
        # Apply migrations
        for migration in sorted(migrations_to_apply, key=lambda m: m.version):
            print(f"🔄 Applying migration {migration.version}: {migration.name}")
            
            try:
                # Special handling for common migration patterns
                if "work_notes" in migration.name.lower():
                    # Handle work_notes column addition safely
                    if not check_column_exists(conn, 'maintenance_record', 'work_notes'):
                        migration.apply(conn)
                        mark_migration_applied(conn, migration)
                        print(f"✅ Migration {migration.version} applied successfully")
                    else:
                        # Column already exists, just mark as applied
                        mark_migration_applied(conn, migration)
                        print(f"✅ Migration {migration.version} already applied (column exists)")
                else:
                    # Apply normally
                    migration.apply(conn)
                    mark_migration_applied(conn, migration)
                    print(f"✅ Migration {migration.version} applied successfully")
                
            except Exception as e:
                print(f"❌ Failed to apply migration {migration.version}: {e}")
                conn.rollback()
                conn.close()
                return False
        
        conn.close()
        print("🎉 All migrations applied successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

def migrate_down(target_version):
    """Rollback migrations down to target version"""
    db_path = get_database_path()
    print(f"Using database: {db_path}")
    
    # Create backup
    backup_path = backup_before_migration(db_path)
    if not backup_path:
        print("❌ Cannot proceed without backup")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        ensure_migrations_table(conn)
        applied_versions = get_applied_migrations(conn)
        
        print(f"Currently applied migrations: {applied_versions}")
        
        # Find migrations to rollback
        migrations_to_rollback = []
        for migration in MIGRATIONS:
            if migration.version in applied_versions and migration.version > target_version:
                migrations_to_rollback.append(migration)
        
        if not migrations_to_rollback:
            print("✅ No migrations to rollback")
            conn.close()
            return True
        
        print(f"Migrations to rollback: {[m.version for m in migrations_to_rollback]}")
        
        # Rollback migrations in reverse order
        for migration in sorted(migrations_to_rollback, key=lambda m: m.version, reverse=True):
            print(f"🔄 Rolling back migration {migration.version}: {migration.name}")
            
            try:
                migration.rollback(conn)
                mark_migration_rollback(conn, migration)
                print(f"✅ Migration {migration.version} rolled back successfully")
                
            except Exception as e:
                print(f"❌ Failed to rollback migration {migration.version}: {e}")
                conn.rollback()
                conn.close()
                return False
        
        conn.close()
        print("🎉 Rollback completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Rollback failed: {e}")
        return False

def show_migration_status():
    """Show current migration status"""
    try:
        db_path = get_database_path()
        print(f"Database: {db_path}")
        
        conn = sqlite3.connect(db_path)
        ensure_migrations_table(conn)
        applied_versions = get_applied_migrations(conn)
        conn.close()
        
        print("\nMigration Status:")
        print("-" * 50)
        
        for migration in MIGRATIONS:
            status = "✅ Applied" if migration.version in applied_versions else "⭕ Pending"
            print(f"{migration.version:2}: {status:<12} {migration.name}")
        
        if not applied_versions:
            print("No migrations have been applied yet.")
        else:
            print(f"\nLatest applied migration: {max(applied_versions)}")
            
    except Exception as e:
        print(f"❌ Failed to check migration status: {e}")

def main():
    parser = argparse.ArgumentParser(description='Database migration utility for Arcade Tracker')
    parser.add_argument('action', choices=['up', 'down', 'status'], help='Migration action')
    parser.add_argument('--version', '-v', type=int, help='Target migration version')
    
    args = parser.parse_args()
    
    # Change to project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    os.chdir(parent_dir)
    
    if args.action == 'up':
        success = migrate_up(args.version)
        sys.exit(0 if success else 1)
    elif args.action == 'down':
        if args.version is None:
            print("❌ Target version required for rollback")
            sys.exit(1)
        success = migrate_down(args.version)
        sys.exit(0 if success else 1)
    elif args.action == 'status':
        show_migration_status()

if __name__ == '__main__':
    main()