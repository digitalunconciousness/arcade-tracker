#!/bin/bash

# Helper script to retrieve the current ngrok public URL
# Ngrok exposes a local API at http://localhost:4040

echo "🌐 Fetching ngrok public URL..."

# Check if ngrok is running
if ! curl -s http://localhost:4040/api/tunnels > /dev/null 2>&1; then
    echo "❌ Error: ngrok doesn't appear to be running or API is not accessible."
    echo "   Check if the service is running: sudo systemctl status arcade-tracker-ngrok.service"
    exit 1
fi

# Fetch the public URL
URL=$(curl -s http://localhost:4040/api/tunnels | python3 -c "import sys, json; data = json.load(sys.stdin); print(data['tunnels'][0]['public_url'] if data.get('tunnels') else 'No tunnels found')")

if [ "$URL" = "No tunnels found" ] || [ -z "$URL" ]; then
    echo "⚠️  No active tunnels found. ngrok might still be starting up."
    echo "   Wait a few seconds and try again."
    exit 1
fi

echo ""
echo "✅ Arcade Tracker is accessible at:"
echo "   $URL"
echo ""
echo "💡 Tip: You can also visit http://localhost:4040 to see the ngrok web interface"
echo ""
