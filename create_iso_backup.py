#!/usr/bin/env python3
"""
Create a complete ISO backup of the Arcade Tracker system
Includes application files, database, documentation, and installer
"""

import os
import sys
import shutil
import subprocess
import json
from datetime import datetime
import tempfile

def create_complete_backup():
    """Create a complete backup ISO with installer"""
    
    print("🎮 Creating Arcade Tracker Complete Backup ISO...")
    
    # Create temporary directory for ISO contents
    iso_temp_dir = tempfile.mkdtemp(prefix="arcade_tracker_iso_")
    print(f"📁 Working directory: {iso_temp_dir}")
    
    try:
        # Create directory structure
        app_dir = os.path.join(iso_temp_dir, "arcade_tracker")
        docs_dir = os.path.join(iso_temp_dir, "documentation")
        installer_dir = os.path.join(iso_temp_dir, "installer")
        
        os.makedirs(app_dir)
        os.makedirs(docs_dir)
        os.makedirs(installer_dir)
        
        # Copy application files
        print("📦 Copying application files...")
        app_files = [
            "app.py",
            "create_work_log_table.py",
            "generate_documentation.py",
            "requirements.txt",
            "README.md"
        ]
        
        for file in app_files:
            if os.path.exists(file):
                shutil.copy2(file, app_dir)
                print(f"   ✓ {file}")
        
        # Copy templates directory
        if os.path.exists("templates"):
            shutil.copytree("templates", os.path.join(app_dir, "templates"))
            print("   ✓ templates/")
        
        # Copy static directory if it exists
        if os.path.exists("static"):
            shutil.copytree("static", os.path.join(app_dir, "static"))
            print("   ✓ static/")
        
        # Copy database if it exists
        if os.path.exists("arcade.db"):
            shutil.copy2("arcade.db", app_dir)
            print("   ✓ arcade.db (database)")
        
        # Copy backups directory if it exists
        if os.path.exists("backups"):
            shutil.copytree("backups", os.path.join(app_dir, "backups"))
            print("   ✓ backups/")
        
        # Copy documentation
        print("📋 Copying documentation...")
        doc_files = [
            "Arcade_Tracker_Documentation.pdf",
            "README.md"
        ]
        
        for file in doc_files:
            if os.path.exists(file):
                shutil.copy2(file, docs_dir)
                print(f"   ✓ {file}")
        
        # Create system info
        system_info = {
            "backup_date": datetime.now().isoformat(),
            "version": "2.0",
            "python_version": sys.version,
            "platform": sys.platform,
            "features": [
                "Complete game inventory management",
                "Timestamped work logging system",
                "Role-based user management",
                "Professional reporting with PDF export",
                "Revenue and play tracking",
                "Maintenance workflow management"
            ]
        }
        
        with open(os.path.join(iso_temp_dir, "system_info.json"), "w") as f:
            json.dump(system_info, f, indent=2)
        
        # Create installer script for Linux/Unix
        create_linux_installer(installer_dir, app_dir)
        
        # Create installer script for Windows
        create_windows_installer(installer_dir, app_dir)
        
        # Create README for the ISO
        create_iso_readme(iso_temp_dir)
        
        # Create the ISO file
        iso_filename = f"ArcadeTracker_Complete_Backup_{datetime.now().strftime('%Y%m%d_%H%M')}.iso"
        
        print("💿 Creating ISO file...")
        iso_result = create_iso_file(iso_temp_dir, iso_filename)
        
        if iso_result:
            print(f"\n✅ SUCCESS! Complete backup ISO created: {iso_filename}")
            print(f"📦 Size: {get_file_size(iso_filename)}")
            print("\n🎯 This ISO contains:")
            print("   • Complete Arcade Tracker application")
            print("   • Current database with all data")
            print("   • Comprehensive documentation")
            print("   • Automated installers for Linux and Windows")
            print("   • All templates and static files")
            print("   • Database migration tools")
            print("\n🚀 To use on a new computer:")
            print("   1. Mount or extract the ISO")
            print("   2. Run install_linux.sh (Linux) or install_windows.bat (Windows)")
            print("   3. Follow the installation prompts")
            
            return iso_filename
        else:
            print("❌ Failed to create ISO file")
            return None
            
    except Exception as e:
        print(f"❌ Error creating backup: {e}")
        return None
    finally:
        # Cleanup temporary directory
        try:
            shutil.rmtree(iso_temp_dir)
        except:
            pass

def create_linux_installer(installer_dir, app_dir):
    """Create Linux installer script"""
    
    installer_script = '''#!/bin/bash
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
'''
    
    with open(os.path.join(installer_dir, "install_linux.sh"), "w") as f:
        f.write(installer_script)
    
    # Make executable
    os.chmod(os.path.join(installer_dir, "install_linux.sh"), 0o755)

def create_windows_installer(installer_dir, app_dir):
    """Create Windows installer batch script"""
    
    installer_script = '''@echo off
REM Arcade Tracker Complete Installation Script for Windows
REM This script will install Arcade Tracker with all dependencies

echo 🎮 Arcade Tracker Complete Installation
echo ========================================

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed.
    echo Please install Python 3.8+ from https://python.org and try again.
    pause
    exit /b 1
)

REM Check for pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pip is required but not installed.
    echo Please install pip and try again.
    pause
    exit /b 1
)

REM Get installation directory
set /p INSTALL_DIR="Enter installation directory [C:\\arcade-tracker]: "
if "%INSTALL_DIR%"=="" set INSTALL_DIR=C:\\arcade-tracker

echo 📁 Installing to: %INSTALL_DIR%

REM Check if directory exists
if exist "%INSTALL_DIR%" (
    set /p OVERWRITE="Directory exists. Overwrite? (y/n): "
    if /i not "%OVERWRITE%"=="y" (
        echo Installation cancelled.
        pause
        exit /b 1
    )
    rmdir /s /q "%INSTALL_DIR%"
)

REM Create installation directory
echo 📦 Creating installation directory...
mkdir "%INSTALL_DIR%"

REM Copy application files
echo 📋 Copying application files...
xcopy /e /i arcade_tracker "%INSTALL_DIR%"

REM Set up virtual environment
echo 🐍 Setting up Python virtual environment...
cd /d "%INSTALL_DIR%"
python -m venv venv
call venv\\Scripts\\activate.bat

REM Install dependencies
echo 📚 Installing Python dependencies...
pip install -r requirements.txt

REM Run database migration if needed
echo 🗄️ Setting up database...
if exist "create_work_log_table.py" (
    python create_work_log_table.py
)

REM Create startup script
echo 🚀 Creating startup script...
echo @echo off > start_arcade_tracker.bat
echo cd /d "%%~dp0" >> start_arcade_tracker.bat
echo call venv\\Scripts\\activate.bat >> start_arcade_tracker.bat
echo python app.py >> start_arcade_tracker.bat
echo pause >> start_arcade_tracker.bat

echo.
echo ✅ Installation Complete!
echo.
echo 🎯 To start Arcade Tracker:
echo    Double-click start_arcade_tracker.bat
echo    OR
echo    cd %INSTALL_DIR%
echo    start_arcade_tracker.bat
echo.
echo 🌐 Then open your browser to: http://localhost:5000
echo.
echo 📋 Documentation available in the documentation folder
echo.

REM Ask if user wants to start now
set /p START_NOW="Start Arcade Tracker now? (y/n): "
if /i "%START_NOW%"=="y" (
    start_arcade_tracker.bat
)

pause
'''
    
    with open(os.path.join(installer_dir, "install_windows.bat"), "w") as f:
        f.write(installer_script)

def create_iso_readme(iso_dir):
    """Create README for the ISO"""
    
    readme_content = '''# 🎮 Arcade Tracker Complete Backup ISO

This ISO contains a complete backup of your Arcade Tracker system including:

## 📦 Contents

- **Application Files**: Complete Arcade Tracker v2.0 application
- **Database**: Current database with all your games, plays, and maintenance records
- **Documentation**: Comprehensive PDF documentation and README
- **Installers**: Automated installation scripts for Linux and Windows
- **Templates & Assets**: All web templates and static files
- **Migration Tools**: Database update scripts for future versions

## 🚀 Installation Instructions

### For Linux/Unix Systems:
1. Mount or extract this ISO
2. Open a terminal and navigate to the installer directory
3. Run: `./install_linux.sh`
4. Follow the installation prompts
5. Start the application with the created startup script

### For Windows Systems:
1. Mount or extract this ISO
2. Navigate to the installer directory
3. Double-click `install_windows.bat`
4. Follow the installation prompts
5. Use the created `start_arcade_tracker.bat` to launch

## 🔧 Manual Installation

If the automated installers don't work:

1. Copy the `arcade_tracker` directory to your desired location
2. Install Python 3.8+ if not already installed
3. Create a virtual environment: `python -m venv venv`
4. Activate it: `source venv/bin/activate` (Linux) or `venv\\Scripts\\activate` (Windows)
5. Install dependencies: `pip install -r requirements.txt`
6. Run database migration: `python create_work_log_table.py`
7. Start the application: `python app.py`
8. Open your browser to: http://localhost:5000

## 📋 System Requirements

- **Python**: 3.8 or higher
- **RAM**: 512MB minimum, 1GB recommended
- **Storage**: 100MB for application + database size
- **Network**: Local network access for web interface
- **Browser**: Modern web browser (Chrome, Firefox, Safari, Edge)

## 🆕 Features in This Version

- **Timestamped Work Logging**: Individual work entries with complete audit trails
- **Role-Based Access Control**: 4-tier user permission system
- **Professional PDF Reports**: Fixed formatting with work log integration
- **Visual Timeline Interface**: Chronological work history display
- **Enhanced Maintenance System**: Complete work order management
- **Secure Forms**: CSRF protection on all forms
- **Database Backups**: Built-in backup and restore functionality

## 📞 Getting Started

1. Install using one of the methods above
2. Open your browser to http://localhost:5000
3. Complete the initial admin setup
4. Import your data (it should already be included if from backup)
5. Create user accounts for your team
6. Start tracking your arcade operations!

## 🔒 Data Security

This backup includes your complete database. Keep this ISO secure and store it in a safe location. Consider encrypting the ISO if it contains sensitive business data.

## 📚 Documentation

Complete documentation is available in the `documentation` directory, including:
- User manual with all features
- Role-based permissions guide
- Work logging system documentation
- Technical architecture details
- Troubleshooting guide

---

**🎮 Arcade Tracker v2.0 - Professional Arcade Management System 🔧**

Created: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''
'''
    
    with open(os.path.join(iso_dir, "README.txt"), "w") as f:
        f.write(readme_content)

def create_iso_file(source_dir, iso_filename):
    """Create ISO file using available tools"""
    
    # Try genisoimage first (most common)
    if shutil.which("genisoimage"):
        cmd = [
            "genisoimage",
            "-o", iso_filename,
            "-V", "ARCADE_TRACKER",
            "-R", "-J",
            source_dir
        ]
    # Try mkisofs as fallback
    elif shutil.which("mkisofs"):
        cmd = [
            "mkisofs",
            "-o", iso_filename,
            "-V", "ARCADE_TRACKER",
            "-R", "-J",
            source_dir
        ]
    else:
        print("❌ Neither genisoimage nor mkisofs found.")
        print("Please install genisoimage: sudo apt install genisoimage")
        return False
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error creating ISO: {e}")
        print(f"Command output: {e.stderr}")
        return False

def get_file_size(filename):
    """Get human-readable file size"""
    size = os.path.getsize(filename)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

if __name__ == '__main__':
    # Check if we're in the right directory
    if not os.path.exists("app.py"):
        print("❌ Please run this script from the arcade-tracker directory")
        sys.exit(1)
    
    # Check for required tools
    if not shutil.which("genisoimage") and not shutil.which("mkisofs"):
        print("❌ ISO creation tools not found.")
        print("Installing genisoimage...")
        try:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y", "genisoimage"], check=True)
        except subprocess.CalledProcessError:
            print("❌ Could not install genisoimage. Please install manually:")
            print("   sudo apt install genisoimage")
            sys.exit(1)
    
    iso_file = create_complete_backup()
    if iso_file:
        print(f"\n🎯 Your complete backup ISO is ready: {iso_file}")
        print("Keep this file safe - it contains your complete Arcade Tracker system!")
    else:
        print("❌ Failed to create backup ISO")
        sys.exit(1)