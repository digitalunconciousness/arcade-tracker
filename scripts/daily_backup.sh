#!/usr/bin/bash
# Daily Backup Script for Arcade Tracker
# This script backs up the database and removes backups older than 30 days

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_SCRIPT="$PROJECT_ROOT/scripts/backup_database.py"
VENV_PATH="$PROJECT_ROOT/venv"
LOG_FILE="$PROJECT_ROOT/logs/backup.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "========== Starting Daily Backup =========="

# Activate virtual environment
if [ -f "$VENV_PATH/bin/activate" ]; then
    source "$VENV_PATH/bin/activate"
    log "Virtual environment activated"
else
    log "ERROR: Virtual environment not found at $VENV_PATH"
    exit 1
fi

# Run backup
if python3 "$BACKUP_SCRIPT" backup; then
    log "Backup completed successfully"
else
    log "ERROR: Backup failed with exit code $?"
    exit 1
fi

# Clean up old backups (older than 30 days)
if python3 "$BACKUP_SCRIPT" cleanup; then
    log "Old backups cleaned up successfully"
else
    log "WARNING: Cleanup failed with exit code $?"
fi

log "========== Daily Backup Complete =========="
