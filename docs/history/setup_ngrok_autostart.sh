#!/bin/bash

# Simple script to setup ngrok to run automatically on boot
# This will run: ngrok http 5000

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🚀 Setting up ngrok autostart service..."

# Check if running with sufficient privileges
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script needs sudo privileges to install the systemd service."
    echo "Please run with: sudo bash scripts/setup_ngrok_autostart.sh"
    exit 1
fi

# Copy service file to systemd directory
echo "📝 Installing ngrok service file..."
cp "$PROJECT_DIR/arcade-tracker-ngrok.service" /etc/systemd/system/

# Set proper permissions
chmod 644 /etc/systemd/system/arcade-tracker-ngrok.service

# Reload systemd to recognize new service
echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

# Enable service to start on boot
echo "✅ Enabling ngrok service to start on boot..."
systemctl enable arcade-tracker-ngrok.service

# Start service now
echo "🏁 Starting ngrok service..."
systemctl start arcade-tracker-ngrok.service

# Wait a moment for ngrok to start
sleep 2

# Show status
echo ""
echo "✨ Setup complete! Ngrok is now running and will start automatically on boot."
echo ""
echo "📊 Service Status:"
echo "=================="
systemctl status arcade-tracker-ngrok.service --no-pager -l
echo ""
echo "📝 Useful commands:"
echo "  View ngrok logs:       sudo journalctl -u arcade-tracker-ngrok.service -f"
echo "  Stop ngrok:            sudo systemctl stop arcade-tracker-ngrok.service"
echo "  Restart ngrok:         sudo systemctl restart arcade-tracker-ngrok.service"
echo "  Disable autostart:     sudo systemctl disable arcade-tracker-ngrok.service"
echo "  Check ngrok URL:       curl http://localhost:4040/api/tunnels | python3 -m json.tool"
echo "  Ngrok web interface:   http://localhost:4040"
echo ""
