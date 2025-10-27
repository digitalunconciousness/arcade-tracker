#!/bin/bash
#
# Setup automatic daily backups for Arcade Tracker database
# This script configures a cron job to backup the database daily at 2 AM
#

set -e

# Configuration
PROJECT_DIR="/home/jackiegreybard/arcade-tracker"
BACKUP_SCRIPT="$PROJECT_DIR/scripts/backup_database.py"
BACKUP_TIME="0 2 * * *"  # Daily at 2 AM
LOG_FILE="$PROJECT_DIR/logs/backup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Setting up automated database backups for Arcade Tracker${NC}"

# Check if script exists
if [ ! -f "$BACKUP_SCRIPT" ]; then
    echo -e "${RED}❌ Backup script not found at: $BACKUP_SCRIPT${NC}"
    exit 1
fi

# Make backup script executable
chmod +x "$BACKUP_SCRIPT"
echo -e "${GREEN}✅ Made backup script executable${NC}"

# Create logs directory if it doesn't exist
LOGS_DIR="$PROJECT_DIR/logs"
if [ ! -d "$LOGS_DIR" ]; then
    mkdir -p "$LOGS_DIR"
    echo -e "${GREEN}✅ Created logs directory: $LOGS_DIR${NC}"
fi

# Create backup directory if it doesn't exist
BACKUP_DIR="$PROJECT_DIR/backups"
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    echo -e "${GREEN}✅ Created backup directory: $BACKUP_DIR${NC}"
fi

# Create the cron job command
CRON_COMMAND="cd $PROJECT_DIR && /usr/bin/python3 $BACKUP_SCRIPT backup >> $LOG_FILE 2>&1"

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "$BACKUP_SCRIPT"; then
    echo -e "${YELLOW}⚠️  Backup cron job already exists${NC}"
    echo "Current backup cron jobs:"
    crontab -l 2>/dev/null | grep "$BACKUP_SCRIPT" || true
    
    read -p "Do you want to replace it? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Remove existing backup cron jobs
        (crontab -l 2>/dev/null | grep -v "$BACKUP_SCRIPT") | crontab -
        echo -e "${GREEN}✅ Removed existing backup cron job${NC}"
    else
        echo -e "${YELLOW}⭕ Keeping existing cron job${NC}"
        exit 0
    fi
fi

# Add the new cron job
(crontab -l 2>/dev/null; echo "$BACKUP_TIME $CRON_COMMAND") | crontab -

echo -e "${GREEN}✅ Added backup cron job:${NC}"
echo "   Schedule: $BACKUP_TIME (Daily at 2:00 AM)"
echo "   Command: $CRON_COMMAND"
echo "   Logs: $LOG_FILE"

# Test the backup script
echo -e "${BLUE}🧪 Testing backup script...${NC}"
cd "$PROJECT_DIR"
if python3 "$BACKUP_SCRIPT" backup; then
    echo -e "${GREEN}✅ Backup script test successful${NC}"
else
    echo -e "${RED}❌ Backup script test failed${NC}"
    echo -e "${YELLOW}⚠️  Please check the script and try again${NC}"
    exit 1
fi

# Show current cron jobs
echo -e "${BLUE}📋 Current cron jobs:${NC}"
crontab -l

echo
echo -e "${GREEN}🎉 Automated backup setup complete!${NC}"
echo
echo "Your database will now be backed up automatically every day at 2:00 AM."
echo "Backup files will be stored in: $BACKUP_DIR"
echo "Backup logs will be written to: $LOG_FILE"
echo
echo "Useful commands:"
echo "  - Check backup status: crontab -l | grep backup"
echo "  - View backup logs: tail -f $LOG_FILE"
echo "  - Manual backup: cd $PROJECT_DIR && python3 scripts/backup_database.py backup"
echo "  - List backups: cd $PROJECT_DIR && python3 scripts/backup_database.py list"
echo "  - Remove cron job: crontab -e (then delete the backup line)"