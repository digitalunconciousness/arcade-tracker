#!/bin/bash
# Setup GPIO API Server on Raspberry Pi

echo "🚀 Setting up GPIO API Server on Raspberry Pi"
echo "=============================================="

# Make the script executable
chmod +x gpio_api_server.py

# Install Python dependencies via apt (Raspberry Pi OS)
echo "📦 Installing Python dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3-flask python3-rpi.gpio

# Copy systemd service file
echo "📝 Installing systemd service..."
sudo cp gpio-api.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable gpio-api.service

# Start the service
echo "▶️  Starting GPIO API server..."
sudo systemctl start gpio-api.service

# Check status
echo ""
echo "📊 Service Status:"
sudo systemctl status gpio-api.service --no-pager -l

echo ""
echo "✅ Setup complete!"
echo ""
echo "Useful commands:"
echo "  Check status:  sudo systemctl status gpio-api"
echo "  View logs:     sudo journalctl -u gpio-api -f"
echo "  Restart:       sudo systemctl restart gpio-api"
echo "  Stop:          sudo systemctl stop gpio-api"
echo ""
echo "API will be available at: http://$(hostname -I | awk '{print $1}'):5001"
