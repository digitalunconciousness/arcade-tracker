#!/bin/bash
# Setup cron job for automatic updates on Proxmox server
# Run this script ON THE PROXMOX SERVER after initial deployment

DEPLOY_PATH="/opt/arcade-tracker"
CRON_SCHEDULE="*/15 * * * *"  # Every 15 minutes (adjust as needed)

echo "Setting up auto-update cron job..."

# Make the auto-update script executable
chmod +x "$DEPLOY_PATH/scripts/auto-update.sh"

# Create cron job
CRON_JOB="$CRON_SCHEDULE $DEPLOY_PATH/scripts/auto-update.sh"

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "auto-update.sh"; then
    echo "Cron job already exists. Updating..."
    (crontab -l 2>/dev/null | grep -v "auto-update.sh"; echo "$CRON_JOB") | crontab -
else
    echo "Adding new cron job..."
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
fi

echo "✅ Cron job installed!"
echo "Current crontab:"
crontab -l | grep "auto-update.sh"
echo ""
echo "The application will check for updates every 15 minutes."
echo "To modify the schedule, edit: $CRON_SCHEDULE"
echo "Common schedules:"
echo "  */5 * * * *    - Every 5 minutes"
echo "  */15 * * * *   - Every 15 minutes"
echo "  0 * * * *      - Every hour"
echo "  0 */6 * * *    - Every 6 hours"
echo "  0 2 * * *      - Daily at 2 AM"
