#!/bin/bash
# Arcade Tracker Complete Installation Script for Linux
# This script will install Arcade Tracker with all dependencies

set -e

echo "🎮 Arcade Tracker Complete Installation"
echo "========================================"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3.8+ and try again."
    exit 1
fi

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    echo "Please install pip3 and try again."
    exit 1
fi

# Get installation directory
read -p "Enter installation directory [/opt/arcade-tracker]: " INSTALL_DIR
INSTALL_DIR=${INSTALL_DIR:-/opt/arcade-tracker}

echo "📁 Installing to: $INSTALL_DIR"

# Check if directory exists
if [ -d "$INSTALL_DIR" ]; then
    read -p "Directory exists. Overwrite? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 1
    fi
    sudo rm -rf "$INSTALL_DIR"
fi

# Create installation directory
echo "📦 Creating installation directory..."
sudo mkdir -p "$INSTALL_DIR"
sudo chown $USER:$USER "$INSTALL_DIR"

# Copy application files
echo "📋 Copying application files..."
cp -r arcade_tracker/* "$INSTALL_DIR/"

# Set up virtual environment
echo "🐍 Setting up Python virtual environment..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Run database migration if needed
echo "🗄️ Setting up database..."
if [ -f "create_work_log_table.py" ]; then
    python create_work_log_table.py
fi

# Create startup script
echo "🚀 Creating startup script..."
cat > "$INSTALL_DIR/start_arcade_tracker.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python app.py
EOF

chmod +x "$INSTALL_DIR/start_arcade_tracker.sh"

# Create desktop entry if running on a desktop system
if command -v desktop-file-install &> /dev/null; then
    echo "🖥️ Creating desktop entry..."
    cat > /tmp/arcade-tracker.desktop << EOF
[Desktop Entry]
Name=Arcade Tracker
Comment=Professional Arcade Management System
Exec=$INSTALL_DIR/start_arcade_tracker.sh
Icon=$INSTALL_DIR/static/favicon.ico
Terminal=true
Type=Application
Categories=Office;Database;
EOF
    
    desktop-file-install --dir=$HOME/.local/share/applications /tmp/arcade-tracker.desktop
fi

echo ""
echo "✅ Installation Complete!"
echo ""
echo "🎯 To start Arcade Tracker:"
echo "   cd $INSTALL_DIR"
echo "   ./start_arcade_tracker.sh"
echo ""
echo "🌐 Then open your browser to: http://localhost:5000"
echo ""
echo "📋 Documentation available in: $INSTALL_DIR/../documentation/"
echo ""

# Ask if user wants to start now
read -p "Start Arcade Tracker now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd "$INSTALL_DIR"
    ./start_arcade_tracker.sh
fi
