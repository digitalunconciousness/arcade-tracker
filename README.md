# 🎮 Arcade Tracker

A comprehensive arcade management system for tracking games, play statistics, revenue, and maintenance with advanced work logging capabilities.

## 🌟 Features

### Game Management
- **Game Inventory**: Track arcade games with detailed information (manufacturer, year, genre)
- **Location Tracking**: Monitor game locations (Floor, Warehouse, Shipped) with specific positions  
- **Status Management**: Track game status (Working, Being Fixed, Not Working, Retired)
- **Image Support**: Upload and display cabinet photos
- **Revenue Analytics**: Automatic play and revenue calculation from coin counts

### 🆕 Advanced Maintenance System

#### Work Order Management
- **Create Work Orders**: Report issues with detailed descriptions
- **Status Tracking**: Open, In Progress, Fixed, Deferred status management
- **Technician Assignment**: Assign work orders to specific technicians

#### 🔧 Timestamped Work Logging (New!)
- **Individual Work Entries**: Each update creates a new timestamped work log entry
- **Detailed Work History**: Complete audit trail of all work performed
- **Work Session Tracking**: 
  - Work description with detailed notes
  - Time spent per work session (hours)
  - Parts/materials used per session
  - Cost breakdown per work session
  - Technician attribution per entry

#### Visual Work Timeline
- **Chronological Display**: Work entries shown in timeline format with timestamps
- **Color-coded Information**: Different colors for timestamps, technicians, time, and costs
- **Comprehensive Details**: Full work descriptions, parts used, and session costs
- **Professional Layout**: Clean, organized presentation of work history

### Enhanced Reporting
- **Time-filtered Reports**: View maintenance data for 7, 30, 90 days or full year
- **📋 PDF Reports with Work Logs**: Professional reports including detailed work history
- **CSV Export**: Export game data for external analysis
- **Performance Analytics**: Top/worst performing games with charts and graphs

## 👥 User Roles & Permissions

### Read Only (Level 1)
- View game information and statistics
- View maintenance reports
- Basic dashboard access

### Operator (Level 2) 
- All Read Only permissions
- **Log work entries** in maintenance orders
- View detailed work order history
- Create maintenance requests

### Manager (Level 3)
- All Operator permissions  
- **Update and manage work orders**
- Record play data and revenue
- Add and edit games
- **Access complete work logging system**
- Generate and export reports

### Admin (Level 4)
- All Manager permissions
- User management (create, disable users)
- Database backups and restoration
- Delete games and associated data

## 🔧 New Work Logging Workflow

### For Technicians/Operators:
1. Access maintenance order via **"👁️ View"** or **"✏️ Update"** button
2. Fill out work performed during session:
   - **Work Description**: Detailed notes of what was done
   - **Parts Used**: Materials consumed during this session  
   - **Time Spent**: Hours worked (e.g., 2.5 hours)
   - **Session Cost**: Cost incurred for this specific work
3. Click **"📋 Log Work Entry"**
4. New timestamped entry is created and added to work history

### For Managers:
1. View complete work history via **"👁️ View"** button
2. See chronological timeline of all work performed
3. Track total time and costs across all work sessions
4. Export detailed reports with work summaries
5. Update overall order status and assignments

## 🚀 Quick Start

1. **Run the application:**
   ```bash
   python app.py
   ```

2. **Access the app:**
   - Open your web browser and go to: `http://localhost:5000`
   - Complete initial admin setup
   - The database will be created automatically on first run

## Manual Setup (Alternative)

If you prefer to set up manually:

```bash
cd arcade-tracker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## 🎳 Skeeball Integration

Arcade Tracker includes a complete Raspberry Pi-based skeeball scoring system with automatic scoring, real-time revenue tracking, and scalable multi-lane architecture.

### 🌟 Key Features

#### Automatic Scoring System
- **7-Sensor Configuration**: Coin input + ball counter + 5 scoring holes
  - **Score 10**: 5 switches (10 points each)
  - **Score 50**: 2 switches (50 points each)  
  - **Lane Track**: Ball roll detection (50 points)
- **Infrared Sensors**: Break-beam detection for accurate, reliable scoring
- **Debounce Logic**: Prevents double-counting from sensor bounce (configurable)
- **Real-time Score Display**: Instant feedback on each ball scored

#### Game Management
- **9-Ball Standard Games**: Traditional skeeball format
- **Bonus Games**: Automatic bonus game awards at configurable thresholds
- **Ball Timeout**: Configurable timeout between balls (prevents stuck games)
- **Coin Integration**: Start games via coin acceptor or manual trigger
- **Persistent State**: Game state survives power loss and restarts
- **Revenue Reconciliation**: Daily automated revenue sync with Arcade Tracker database

#### Multi-Lane Architecture
- **Single Lane Mode**: Raspberry Pi 4 connected directly to one machine
- **Multi-Lane Mode**: Unlimited scalability
  - Pi 4 acts as coordinator running Arcade Tracker
  - One Raspberry Pi Pico per skeeball lane
  - USB serial communication between Pi 4 and Picos
  - Independent lane operation (isolated failures)
  - Simplified wiring per machine

#### Web Interface & APIs
- **Main Hub** (`/skeeball/`): Overview, lane selection, and navigation
- **Control Panel** (`/skeeball/control`): Real-time game monitoring with 0.5-second updates
  - Live score tracking during active gameplay
  - Ball counter showing remaining balls
  - Game active status (playing/ready/offline)
  - Instant feedback on coin insertions
- **Simulator** (`/skeeball/simulator`): Full gameplay testing without GPIO hardware
- **Statistics** (`/skeeball/stats`): Live revenue analytics with 1-second updates
  - Total coins inserted (cumulative)
  - Total games played
  - Real-time revenue tracking
- **GPIO Testing** (`/skeeball/gpio-test`): Real-time hardware diagnostics and sensor monitoring
- **RESTful API**: Authenticated endpoints for programmatic control and monitoring

### 🛠️ Hardware Requirements

#### Minimum Setup (Single Lane)
- **Raspberry Pi** (any model with GPIO - Pi 4 recommended)
- **MicroSD Card**: 16GB+ recommended
- **Power Supply**: Appropriate for Pi model (Pi 4: 5V 3A USB-C)
- **Coin Acceptor**: Standard arcade coin mechanism or pushbutton
- **Ball Counter Sensor**: Detects balls entering play area
- **Scoring Sensors**: 7 infrared break-beam sensors
  - 5 for 10-point holes
  - 2 for 50-point holes
  - 1 for lane track (roll-down)
- **Wiring**: Breadboard, jumper wires, pull-up resistors (if not built into sensors)

#### Optional Components
- **TM1637 Display**: 4-digit 7-segment display for on-machine score display
- **Raspberry Pi Pico**: For multi-lane setups (one per lane)
- **USB Cables**: For Pi Pico ↔ Pi 4 communication
- **Relay Modules**: For solenoid control (ball release) and LED power management

#### Default GPIO Pin Assignments (BCM Numbering)
```
Coin Input:       GPIO 2
Ball Counter:     GPIO 3
Score 10 (5x):    GPIO 4, 5, 6, 7, 8
Score 50 (2x):    GPIO 9, 10
Lane Track:       GPIO 11
Solenoid Relay:   GPIO 10 (output)
LED Power Relay:  GPIO 26 (output)
```

### 🚀 Quick Start Guide

#### 1. Installation
The skeeball system is integrated into Arcade Tracker. Dependencies are installed automatically:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

#### 2. Development Testing (No Hardware Required)
```bash
# Start Arcade Tracker
python app.py

# Navigate to simulator
open http://localhost:5000/skeeball/simulator

# Test game logic by clicking buttons:
# - Insert Coin → Start Game
# - Score buttons → Simulate scoring
# - Watch game state and revenue tracking
```

#### 3. Hardware Setup
1. **Wire sensors** to GPIO pins (see pin assignments above)
2. **Configure settings** in `/skeeball/control`
3. **Test sensors** at `/skeeball/gpio-test`
   - Monitor real-time pin states
   - Trigger each sensor to verify connections
   - Check debounce behavior
4. **Launch games** from `/skeeball/control`

#### 4. Production Deployment
See `DEPLOYMENT_CHECKLIST.md` for comprehensive deployment instructions including:
- Sensor wiring diagrams
- Pi Pico firmware setup (multi-lane)
- Production configuration
- Troubleshooting guide

### 📊 Revenue Integration

#### Automatic Revenue Tracking
- **Per-Game Revenue**: Each coin insertion tracked with timestamp
- **Daily Reconciliation**: Automated daily sync at midnight
- **Database Integration**: Revenue stored in Arcade Tracker's play_records table
- **Statistics Dashboard**: Real-time revenue analytics per lane
- **CSV Export**: Revenue data exportable with all other game data

#### 🔄 Real-Time State Synchronization
- **Live Game State Tracking**: Control panel displays current score, balls remaining, and active game status
- **File-Based State Sharing**: Raspberry Pi writes game state to JSON file every second
- **Stats API Server**: Flask API on Pi (port 5002) serves real-time data to main application
- **Fast Polling**: Control panel updates every 0.5 seconds, statistics every 1 second
- **Seamless Integration**: Works with existing `skeeball_main.py` without GPIO conflicts

**Data Flow:**
```
Hardware (GPIO sensors) → skeeball_main.py → skeeball_state.json
  → state_sync.py (watches file) → realtime_state.json
  → stats_api_server.py (HTTP API) → Flask app → Web UI
```

#### Revenue Workflow
1. Player inserts coin → Revenue logged to lane controller
2. Game completes → Final score and revenue stored
3. Daily scheduler (midnight) → Sync all lane revenue to database
4. Arcade Tracker reports → Include skeeball revenue in analytics

### 🔧 Configuration

All configuration is done via Python config files:
- **`config.py`**: GPIO pin assignments, point values, game parameters
- **`.env.skeeball`**: Environment-specific settings (production vs development)
- **Web Interface**: Runtime configuration via control panel

### 📚 Documentation

Comprehensive documentation included:
- **`SKEEBALL_INTEGRATION_SUMMARY.md`**: Integration overview and verification
- **`DEPLOYMENT_CHECKLIST.md`**: Step-by-step production deployment
- **`FLASK_INTEGRATION.md`**: Technical integration details
- **`MULTI_LANE_ARCHITECTURE.md`**: Multi-lane system architecture
- **`GPIO_TESTING_README.md`**: Hardware testing and troubleshooting
- **`SKEEBALL_TROUBLESHOOTING.md`**: Common issues and solutions

### 🔐 Security

All skeeball features protected by:
- **Flask-Login**: Authentication required for all endpoints
- **CSRF Protection**: All forms secured via Flask-WTF
- **Role-Based Access**: Same permission model as main Arcade Tracker
- **API Authentication**: All API endpoints require valid session

### 🎯 Use Cases

- **Arcade Operators**: Automated revenue tracking without manual coin counting
- **Family Entertainment Centers**: Multi-lane management from single interface
- **Developers**: Test game logic with simulator before hardware deployment
- **Technicians**: Hardware diagnostics and sensor testing tools
- **Managers**: Real-time performance analytics and revenue reports

## Usage

### Adding Games
1. Click "Add Game" in the navigation
2. Fill in the game details (only name is required)
3. Set the status: Active, Maintenance, or Storage

### Recording Plays
1. From the dashboard or games list, click "Record Plays" for any game
2. Enter the number of plays you read from the machine
3. Set the date (defaults to today)
4. Add any notes if needed

### Viewing Reports
1. Click "Reports" to see:
   - Top 10 games by total plays
   - Daily play counts for the last 30 days
   - Summary statistics

## Database

The app uses SQLite database stored in `arcade.db`. Your data is stored locally and persists between sessions.

## Customization Ideas

This basic version can be extended with:

- **Revenue tracking**: Add coin/revenue data per play session
- **Maintenance logs**: Track repairs and maintenance activities  
- **Photo uploads**: Add images of games
- **Export data**: CSV/Excel export functionality
- **User accounts**: Multi-user support with different access levels
- **Mobile app**: Responsive design or native mobile app
- **Backup system**: Automated data backups
- **Advanced reports**: Charts, graphs, and trend analysis

## 📈 Recent Updates (v2.1)

### 🎯 Monthly Performance Tracking
- **Monthly Top 5/Top 10 Rankings**: Automatic monthly updates on the 1st of each month
- **Historical Performance Counters**: Track how many times games rank in top 5 and top 10
- **Previous Month Revenue**: Rankings based on prior month's total revenue
- **Smart Update Logic**: Updates at most once per calendar month, preventing double-counting

### 📊 Executive Summary Dashboard
- **Revenue Overview**: Total 30-day revenue with Top 5 and Bottom 3 games at a glance
- **Inventory Status**: Real-time low stock alerts and pending request tracking
- **Maintenance Dashboard**: Active work orders with priority and status indicators
- **Actionable Insights**: Quick links to games, orders, and inventory items

### 🔧 Technical Improvements
- **Multi-Photo Upload Fix**: Resolved duplicate file input causing upload issues
- **30-Day Login Persistence**: Fixed "Remember Me" functionality for extended sessions
- **Clean Interface**: Removed all emoji characters for consistent cross-platform rendering
- **Database Migration**: Added last_ranking_update field for tracking monthly updates

### 🔧 Work Logging System
- **New WorkLog Database Table**: Stores individual work entries with timestamps
- **Enhanced Update Process**: Each update creates new work entry instead of overwriting
- **Complete Audit Trail**: Full history of who did what work and when
- **Visual Timeline Interface**: Professional timeline view of all work performed

### 🎨 UI/UX Improvements  
- **Consistent Button Styling**: Maintenance tables now match games table formatting
- **Smaller, Organized Buttons**: Professional compact button layout
- **Enhanced Visual Hierarchy**: Better organization of information

### 📋 Reporting Enhancements
- **PDF Format Fixes**: Eliminated text cutoff issues with proper column sizing
- **Work History Integration**: Reports now include actual work performed
- **Professional Layout**: Improved fonts, spacing, and organization

### 🔒 Security & Performance
- **CSRF Protection**: All forms now properly secured
- **Database Optimization**: Efficient queries and relationships
- **User Role Management**: Hierarchical permission system

## 🛠️ Technical Architecture

### Database Schema
- **games**: Game inventory and statistics
- **play_records**: Revenue and play tracking
- **maintenance_records**: Work order management
- **work_logs**: 🆕 Individual work entries with timestamps
- **users**: User management and authentication

### Key Technologies
- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: Jinja2 templates with custom CSS
- **Security**: Flask-WTF with CSRF protection
- **Reports**: ReportLab for PDF generation
- **Charts**: Chart.js for analytics visualization

## File Structure

```
arcade-tracker/
├── app.py              # Main application
├── requirements.txt    # Python dependencies
├── run.sh             # Startup script
├── arcade.db          # SQLite database (created on first run)
├── templates/         # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── games.html
│   ├── add_game.html
│   ├── game_detail.html
│   ├── record_plays.html
│   └── reports.html
└── README.md          # This file
```

## 🎯 Use Cases

### Arcade Operators
- Track which games make the most money
- Monitor maintenance costs and frequency
- **Document detailed repair work with timestamps**
- Generate reports for business decisions

### Maintenance Technicians  
- **Log detailed work entries with time tracking**
- Record parts used and costs per work session
- Build comprehensive work history for each machine
- Track repair trends and recurring issues

### Business Management
- **View complete maintenance audit trails**
- Analyze repair costs and technician productivity  
- Export professional reports with work details
- Make data-driven decisions about game lifecycle

## 🔧 Database Migration

If upgrading from an older version, run:
```bash
python create_work_log_table.py
```

This will add the new WorkLog table for timestamped work entries.

## 🚀 Getting Started

1. **First Time Setup**: Navigate to the setup page to create your admin account
2. **Add Games**: Start by adding your arcade games to the inventory
3. **Create Users**: Set up accounts for technicians and operators
4. **Start Tracking**: Begin logging plays and maintenance work!

## 📋 Key Features Summary

✅ **Complete Game Inventory Management**
✅ **Revenue & Play Tracking with Analytics** 
✅ **Professional Work Order System**
✅ **Timestamped Work Logging with Audit Trail**
✅ **Visual Work Timeline Interface**
✅ **Role-based User Management**
✅ **Professional PDF Reports**
✅ **Secure CSRF-Protected Forms**
✅ **Database Backup & Restore**

---

**🎮 Keep your arcade running smoothly with comprehensive tracking and professional work documentation! 🔧**
