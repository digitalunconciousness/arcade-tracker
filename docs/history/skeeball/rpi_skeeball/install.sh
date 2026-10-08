#!/bin/bash
# Quick installation script for Raspberry Pi skeeball system

echo "=========================================="
echo "Skeeball System - Quick Install"
echo "=========================================="
echo ""

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
    echo "⚠️  Warning: This doesn't appear to be a Raspberry Pi"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update system
echo "📦 Updating system packages..."
sudo apt update

# Install Python and dependencies
echo "🐍 Installing Python dependencies..."
sudo apt install -y python3-pip python3-rpi.gpio

# Install Python packages
echo "📚 Installing Python libraries..."
pip3 install -r requirements.txt

# Make scripts executable
chmod +x skeeball_main.py
chmod +x test_game.py

# Create config if it doesn't exist
if [ ! -f config.json ]; then
    echo "⚙️  Creating configuration file..."
    python3 -c "from skeeball_main import SkeeballGame; SkeeballGame()" 2>/dev/null || true
    
    if [ -f config.json ]; then
        echo ""
        echo "✅ Configuration file created!"
        echo ""
        echo "📝 IMPORTANT: Edit config.json with your settings:"
        echo "   - Server URL and game ID"
        echo "   - Username and password"
        echo "   - GPIO pin assignments"
        echo ""
        echo "Run: nano config.json"
    fi
else
    echo "✅ Configuration file already exists"
fi

echo ""
echo "=========================================="
echo "✅ Installation complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit config.json with your settings"
echo "2. Test without hardware: python3 test_game.py"
echo "3. Test with hardware: python3 skeeball_main.py"
echo "4. Set up autostart (see README.md)"
echo ""
