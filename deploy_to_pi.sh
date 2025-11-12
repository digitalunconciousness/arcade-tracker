#!/bin/bash
# Deploy GPIO API Server to Raspberry Pi

PI_HOST="${1:-skeeproto@sp1.local}"
PI_USER="${2:-skeeproto}"

echo "🚀 Deploying GPIO API Server to $PI_HOST"
echo "==========================================="

# Check if we can reach the Pi
echo "📡 Testing connection..."
if ! ssh "$PI_HOST" "echo '✅ Connection successful'"; then
    echo "❌ Cannot connect to $PI_HOST"
    echo "Usage: $0 [pi_hostname] [pi_user]"
    exit 1
fi

# Create directory on Pi if it doesn't exist
echo "📁 Creating directories..."
ssh "$PI_HOST" "mkdir -p ~/arcade-tracker/rpi_skeeball"

# Copy files to Pi
echo "📤 Copying files..."
scp rpi_skeeball/gpio_api_server.py "$PI_HOST:~/arcade-tracker/rpi_skeeball/"
scp rpi_skeeball/gpio-api.service "$PI_HOST:~/arcade-tracker/rpi_skeeball/"
scp rpi_skeeball/setup_gpio_api.sh "$PI_HOST:~/arcade-tracker/rpi_skeeball/"

# Run setup on Pi
echo "⚙️  Running setup on Pi..."
ssh "$PI_HOST" "cd ~/arcade-tracker/rpi_skeeball && chmod +x setup_gpio_api.sh && ./setup_gpio_api.sh"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "The GPIO API server should now be running on:"
echo "  http://$PI_HOST:5001"
echo ""
echo "Test it with:"
echo "  curl http://$PI_HOST:5001/health"
