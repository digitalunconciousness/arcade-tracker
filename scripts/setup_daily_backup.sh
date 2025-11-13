#!/usr/bin/bash
# Setup Daily Backup Cron Job
# This script adds a cron job to run daily backups at 2 AM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SCRIPT="$SCRIPT_DIR/daily_backup.sh"

echo "Setting up daily backup cron job..."

# Check if backup script exists
if [ ! -f "$BACKUP_SCRIPT" ]; then
    echo "ERROR: Backup script not found at $BACKUP_SCRIPT"
    exit 1
fi

# Create cron job entry (runs at 2 AM every day)
CRON_JOB="0 2 * * * $BACKUP_SCRIPT"

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -F "$BACKUP_SCRIPT" > /dev/null; then
    echo "Cron job already exists. Updating..."
    # Remove old entry
    crontab -l | grep -vF "$BACKUP_SCRIPT" | crontab -
fi

# Add new cron job
(crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -

echo "✅ Daily backup cron job installed successfully!"
echo "   Backups will run at 2:00 AM every day"
echo ""
echo "To view all cron jobs:"
echo "   crontab -l"
echo ""
echo "To remove this cron job:"
echo "   crontab -e"
echo "   (then delete the line with daily_backup.sh)"
