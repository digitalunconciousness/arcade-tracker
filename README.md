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

## Skeeball Integration

Arcade Tracker includes a complete Raspberry Pi-based skeeball scoring system with real-time tracking.

### Features
- **Automatic Scoring**: 6-hole detection (10, 20, 30, 40, 50, 100 points)
- **Game Management**: Full 9-ball games with bonus tracking
- **Coin Counter**: Integrated coin acceptor support
- **Real-time Sync**: Automatic data upload to Arcade Tracker
- **Multi-Lane Support**: Scalable architecture for multiple machines
- **Web Interface**: Control panel, simulator, and statistics dashboard
- **GPIO Testing**: Built-in hardware testing tools

### Access Points
- **Main Hub**: `/skeeball/` - Overview and lane selection
- **Control Panel**: `/skeeball/control` - Lane management and monitoring
- **Simulator**: `/skeeball/simulator` - Test without hardware
- **Statistics**: `/skeeball/stats` - Performance analytics
- **GPIO Testing**: `/skeeball/gpio-test` - Hardware diagnostics

### Hardware Setup
**Minimum Requirements:**
- Raspberry Pi (any model with GPIO)
- Coin acceptor/switch
- 6x infrared break-beam sensors
- Optional: TM1637 display for on-machine scoring

**Architecture Options:**
- **Single Lane**: Pi 4 directly connected to one machine
- **Multi-Lane**: Pi 4 coordinator with Pi Pico per lane via USB

### Quick Start
1. Configure GPIO pins in skeeball settings
2. Wire sensors to assigned GPIO pins
3. Navigate to `/skeeball/simulator` to test without hardware
4. Use `/skeeball/gpio-test` to verify sensor connections
5. Launch games from `/skeeball/control`

For detailed setup instructions, see `rpi_skeeball/README.md` and `DEPLOYMENT_CHECKLIST.md`.

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
