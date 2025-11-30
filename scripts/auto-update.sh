#!/bin/bash
# Auto-update script for arcade-tracker
# This script checks for git updates and rebuilds the container if needed
# Run this via cron on the Proxmox server

set -e

DEPLOY_PATH="/opt/arcade-tracker"
LOG_FILE="$DEPLOY_PATH/logs/auto-update.log"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting auto-update check..."

# Change to deployment directory
cd "$DEPLOY_PATH"

# Fetch latest changes
git fetch origin

# Check if there are any updates
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)  # Change 'main' to your branch name if different

if [ "$LOCAL" = "$REMOTE" ]; then
    log "No updates available. Current version: ${LOCAL:0:7}"
    exit 0
fi

log "Updates found! Local: ${LOCAL:0:7}, Remote: ${REMOTE:0:7}"

# Pull latest changes
log "Pulling latest changes..."
git pull origin main

# Backup database before update
log "Creating database backup..."
python scripts/backup_database.py backup || log "Warning: Backup failed"

# Rebuild and restart containers
log "Rebuilding Docker containers..."
docker-compose build --no-cache

log "Restarting containers..."
docker-compose down
docker-compose up -d

# Wait for health check
log "Waiting for application to be healthy..."
sleep 15

# Check if container is running
if docker ps | grep -q arcade-tracker; then
    log "✅ Update successful! Container is running."
    
    # Check if application responds
    if curl -f http://localhost:5000/ > /dev/null 2>&1; then
        log "✅ Application is responding correctly."
    else
        log "⚠️  Warning: Container running but application not responding."
    fi
else
    log "❌ Error: Container failed to start after update!"
    
    # Rollback
    log "Attempting rollback to previous version..."
    git reset --hard "$LOCAL"
    docker-compose build
    docker-compose up -d
    
    log "Rollback complete. Please check the application manually."
    exit 1
fi

log "Auto-update complete!"
