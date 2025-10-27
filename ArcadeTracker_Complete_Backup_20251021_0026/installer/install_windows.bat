@echo off
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
set /p INSTALL_DIR="Enter installation directory [C:\arcade-tracker]: "
if "%INSTALL_DIR%"=="" set INSTALL_DIR=C:\arcade-tracker

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
call venv\Scripts\activate.bat

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
echo call venv\Scripts\activate.bat >> start_arcade_tracker.bat
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
