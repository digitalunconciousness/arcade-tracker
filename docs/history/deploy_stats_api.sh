#!/bin/bash
# Deploy stats API to Raspberry Pi

set -e

PI_USER="skeeproto"
PI_HOST="sp1.local"
PI_DIR="/home/skeeproto/skeeball"

echo "🚀 Deploying Skeeball Stats API to ${PI_USER}@${PI_HOST}"
echo ""

# Check if we can reach the Pi
echo "📡 Testing connection to Pi..."
if ! ssh -o ConnectTimeout=5 ${PI_USER}@${PI_HOST} "echo 'Connection successful'" 2>/dev/null; then
    echo "❌ Cannot connect to ${PI_USER}@${PI_HOST}"
    echo "   Please check:"
    echo "   - Pi is powered on"
    echo "   - Network connection"
    echo "   - SSH is enabled on Pi"
    exit 1
fi
echo "✅ Connection successful"
echo ""

# Create directory if it doesn't exist
echo "📁 Ensuring directory exists on Pi..."
ssh ${PI_USER}@${PI_HOST} "mkdir -p ${PI_DIR}"

# Copy the stats API server
echo "📤 Copying stats_api_server.py..."
scp rpi_skeeball/stats_api_server.py ${PI_USER}@${PI_HOST}:${PI_DIR}/

# Copy the updated skeeball_main.py
echo "📤 Copying updated skeeball_main.py..."
scp rpi_skeeball/skeeball_main.py ${PI_USER}@${PI_HOST}:${PI_DIR}/

echo ""
echo "✅ Files deployed successfully!"
echo ""
echo "📋 Next steps:"
echo "   1. SSH to the Pi: ssh ${PI_USER}@${PI_HOST}"
echo "   2. Navigate to directory: cd ${PI_DIR}"
echo "   3. Install dependencies: pip3 install flask flask-cors"
echo "   4. Start the system: python3 skeeball_main.py"
echo ""
echo "Or run these commands automatically:"
echo ""
echo "ssh ${PI_USER}@${PI_HOST} 'cd ${PI_DIR} && pip3 install flask flask-cors && python3 skeeball_main.py'"
