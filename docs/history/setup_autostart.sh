#!/bin/bash

# Setup script to install Arcade Tracker and ngrok as systemd services
# This will make them start automatically on boot

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🚀 Setting up Arcade Tracker autostart services..."

# Check if running with sufficient privileges
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script needs sudo privileges to install systemd services."
    echo "Please run with: sudo bash scripts/setup_autostart.sh"
    exit 1
fi

# Copy service files to systemd directory
echo "📝 Installing service files..."
cp "$PROJECT_DIR/arcade-tracker.service" /etc/systemd/system/
cp "$PROJECT_DIR/arcade-tracker-ngrok.service" /etc/systemd/system/

# Set proper permissions
chmod 644 /etc/systemd/system/arcade-tracker.service
chmod 644 /etc/systemd/system/arcade-tracker-ngrok.service

# Reload systemd to recognize new services
echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

# Enable services to start on boot
echo "✅ Enabling services to start on boot..."
systemctl enable arcade-tracker.service
systemctl enable arcade-tracker-ngrok.service

# Start services now
echo "🏁 Starting services..."
systemctl start arcade-tracker.service
sleep 3  # Give Flask app time to start before starting ngrok
systemctl start arcade-tracker-ngrok.service

# Show status
echo ""
echo "✨ Setup complete! Services are now running and will start automatically on boot."
echo ""
echo "📊 Service Status:"
echo "=================="
systemctl status arcade-tracker.service --no-pager -l
echo ""
systemctl status arcade-tracker-ngrok.service --no-pager -l
echo ""
echo "📝 Useful commands:"
echo "  View Flask app logs:   sudo journalctl -u arcade-tracker.service -f"
echo "  View ngrok logs:       sudo journalctl -u arcade-tracker-ngrok.service -f"
echo "  Stop services:         sudo systemctl stop arcade-tracker.service arcade-tracker-ngrok.service"
echo "  Restart services:      sudo systemctl restart arcade-tracker.service arcade-tracker-ngrok.service"
echo "  Disable autostart:     sudo systemctl disable arcade-tracker.service arcade-tracker-ngrok.service"
echo "  Check ngrok URL:       curl http://localhost:4040/api/tunnels"
echo ""
