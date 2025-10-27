# Database Backup & Migration System

This document describes the comprehensive backup and migration system for Arcade Tracker.

## Overview

The backup system provides:
- **Automated daily backups** with cron scheduling
- **Manual backup creation** via web interface or command line
- **Database restore** from backup files with verification
- **Database migrations** for safe schema changes
- **Backup management** through the web interface

## Components

### 1. Backup Script (`scripts/backup_database.py`)

Creates timestamped database backups with automatic verification and cleanup.

**Usage:**
```bash
# Create a backup
python scripts/backup_database.py backup

# List available backups
python scripts/backup_database.py list

# Clean up old backups
python scripts/backup_database.py cleanup
```

**Features:**
- SQLite backup API for safe backups of active databases
- Automatic backup verification
- Cleanup of backups older than 30 days
- Support for both instance and root database locations

### 2. Restore Script (`scripts/restore_database.py`)

Restores database from backup files with safety checks.

**Usage:**
```bash
# Interactive restore (recommended)
python scripts/restore_database.py --interactive

# Restore specific backup
python scripts/restore_database.py --backup-file backups/arcade_backup_20231021_123456.db

# List available backups
python scripts/restore_database.py --list

# Verify backup integrity
python scripts/restore_database.py --verify backups/arcade_backup_20231021_123456.db
```

**Safety Features:**
- Automatic backup of current database before restore
- Backup integrity verification
- Interactive confirmation process
- Restores to both root and instance database locations

### 3. Migration Script (`scripts/migrate_database.py`)

Handles database schema changes without data loss.

**Usage:**
```bash
# Apply all pending migrations
python scripts/migrate_database.py up

# Apply migrations up to specific version
python scripts/migrate_database.py up --version 2

# Rollback to specific version
python scripts/migrate_database.py down --version 1

# Check migration status
python scripts/migrate_database.py status
```

**Features:**
- Automatic pre-migration backups
- Migration tracking table
- Safe column addition with existence checks
- Rollback support for reversible migrations

### 4. Automated Backup Setup (`scripts/setup_backup_cron.sh`)

Sets up automated daily backups using cron.

**Usage:**
```bash
# Setup automated daily backups
bash scripts/setup_backup_cron.sh
```

**Configuration:**
- Daily backups at 2:00 AM
- Logs stored in `logs/backup.log`
- Automatic cleanup of old backups

### 5. Web Interface Backup Management

Access via `/backup_management` route (admin only).

**Features:**
- Create backups instantly
- View all available backups
- Download backup files
- Restore from backups with confirmation
- Backup information and status

## Setup Instructions

### 1. Initial Setup

Create your first backup:
```bash
python scripts/backup_database.py backup
```

### 2. Setup Automated Backups

Run the setup script to configure daily automated backups:
```bash
bash scripts/setup_backup_cron.sh
```

This will:
- Create backup and logs directories
- Configure cron job for daily backups at 2 AM
- Test the backup script
- Display current cron configuration

### 3. Verify Setup

Check that everything is working:
```bash
# List current backups
python scripts/backup_database.py list

# Check cron job
crontab -l | grep backup

# View backup logs
tail logs/backup.log
```

## Migration Usage

### Adding New Migrations

To add a new migration, edit `scripts/migrate_database.py` and add to the `MIGRATIONS` list:

```python
Migration(
    version=3,
    name="Add new feature column",
    up_sql=[
        "ALTER TABLE game ADD COLUMN new_feature TEXT;"
    ],
    down_sql=[
        "ALTER TABLE game DROP COLUMN new_feature;"
    ]
)
```

### Applying Migrations

```bash
# Check current status
python scripts/migrate_database.py status

# Apply new migrations
python scripts/migrate_database.py up
```

## File Locations

- **Backups:** `backups/arcade_backup_YYYYMMDD_HHMMSS.db`
- **Logs:** `logs/backup.log`
- **Scripts:** `scripts/`
- **Database:** `arcade.db` or `instance/arcade.db`

## Web Interface Access

1. Log in as an admin user
2. Navigate to the "Backups" menu item
3. Use the interface to:
   - Create new backups
   - View backup history
   - Download backup files
   - Restore from backups

## Troubleshooting

### Backup Issues

If backups fail:
1. Check database file permissions
2. Ensure backup directory exists and is writable
3. Check available disk space
4. Review logs in `logs/backup.log`

### Restore Issues

If restore fails:
1. Verify backup file integrity: `python scripts/restore_database.py --verify <backup-file>`
2. Check that application is not running during restore
3. Ensure sufficient disk space
4. Check file permissions

### Migration Issues

If migrations fail:
1. Check migration status: `python scripts/migrate_database.py status`
2. Review pre-migration backup in `backups/`
3. Check database schema manually with SQLite browser
4. Consider manual schema fixes if needed

### Cron Job Issues

If automated backups aren't running:
1. Check cron is running: `systemctl status cron`
2. Verify cron job exists: `crontab -l`
3. Check backup logs: `tail -f logs/backup.log`
4. Test backup script manually: `python scripts/backup_database.py backup`

## Best Practices

1. **Regular Testing:** Test restore process periodically
2. **External Backups:** Download backups for external storage
3. **Monitor Logs:** Check backup logs regularly
4. **Schema Changes:** Always use migrations for database changes
5. **Backup Before Changes:** Create manual backup before major operations

## Recovery Scenarios

### Complete Data Loss

1. Stop the application
2. Restore from latest backup: `python scripts/restore_database.py --interactive`
3. Restart the application
4. Verify data integrity

### Schema Corruption

1. Stop the application
2. Check migration status: `python scripts/migrate_database.py status`
3. If needed, restore from pre-migration backup
4. Re-apply migrations if necessary
5. Restart the application

### Accidental Data Deletion

1. Stop the application immediately
2. Create backup of current state (for safety)
3. Restore from backup before deletion occurred
4. Restart the application
5. Re-enter any data added since backup

This backup system ensures your Arcade Tracker data is safe and recoverable!