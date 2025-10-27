# 🎮 Arcade Tracker - Complete Documentation

**Your Complete Guide to Managing Your Arcade Business**

---

## 🚀 Quick Start

### Starting the System
```bash
cd /home/jackiegreybard/arcade-tracker
source venv/bin/activate
python app.py
```

**Access URLs:**
- **Local:** http://localhost:5000
- **Network:** http://192.168.0.206:5000 (accessible from other devices)

### First Time Setup
1. Visit `/setup` to create your admin account
2. Login with your admin credentials
3. Start adding games and users

---

## 👥 User Management & Permissions

### 🔴 **Admin** (You - Full Control)
**What you can do:**
- ✅ Everything managers and operators can do
- 👥 Create, manage, and disable user accounts
- 🔧 Access user management dashboard
- 🏗️ Full system administration

**Access:** All features + "👥 Users" button in navigation

### 🟡 **Manager** (Business Operations)
**What they can do:**
- 🎮 Add, edit, and delete games
- 💰 Record play counts and handle money/tokens
- 📊 View all reports and analytics
- 📄 Export revenue reports and CSV data
- 🔧 Manage maintenance requests (create, view, close)
- 👀 See all revenue and financial data

**Access:** Dashboard, Games, Add Game, Maintenance, Graphs, Reports

### 🔵 **Operator** (Floor Staff)
**What they can do:**
- 👀 View games list (basic info only)
- 🔧 Report maintenance issues only
- 👀 See game details without revenue data

**Cannot do:**
- ❌ Handle money/tokens/record plays
- ❌ See revenue or financial data
- ❌ Add or edit games
- ❌ Access reports or analytics
- ❌ See existing maintenance requests

**Access:** Dashboard (limited), Games (view only)

### ⚪ **Read Only** (Limited Viewing)
**What they can do:**
- 👀 Basic viewing only (same restrictions as operator)

---

## 🎮 Game Management

### Adding Games
1. **Navigation:** Click "Add Game" (managers+ only)
2. **Required:** Game name
3. **Optional:** Manufacturer, year, genre, location, status, coin value
4. **Image Upload:** Supported formats: PNG, JPG, JPEG, GIF (16MB max)
5. **Initial Coin Count:** Set baseline for play tracking

### Game Locations
- **Floor:** Active games earning money
- **Warehouse:** Stored games
- **Shipped:** Games sent elsewhere

### Game Status
- **Working:** Fully operational
- **Being_Fixed:** Under repair
- **Not_Working:** Broken/offline
- **Retired:** No longer in service

---

## 💰 Play Tracking & Revenue

### Recording Plays (Managers+ Only)
1. **Access:** Click "📈 Plays" button on any game
2. **Coin Count:** Enter current reading from machine
3. **System Calculates:** Plays = (Current Count - Previous Count)
4. **Revenue:** Automatically calculated using coin value
5. **Date:** Defaults to today, can be changed
6. **Notes:** Optional context for the record

### Revenue Tracking
- **Real-time totals** updated on every play record
- **Daily averages** calculated from date game was added
- **Performance rankings** track top/worst performers
- **Automatic calculations** - no manual math needed

---

## 🔧 Maintenance System

### For Operators (Reporting Issues)
1. **Find broken game** in games list
2. **Click "🔧 Fix" button**
3. **Describe the problem** in detail
4. **Submit** - managers will see the request

### For Managers (Managing Requests)
1. **Access:** "🔧 Maintenance" tab
2. **View all requests** by status (Open, In Progress, Fixed)
3. **Assign technicians** and track progress  
4. **Close requests** with resolution details and costs
5. **Export reports** for different time periods

---

## 📊 Reports & Analytics (Managers+ Only)

### Dashboard Analytics
- **System stats** overview
- **Critical systems** requiring attention (worst performers)
- **Active floor systems** with status indicators

### Reports Page
- **Revenue Report (PDF):** Professional report for management
- **CSV Export:** Raw data for spreadsheet analysis
- **Top Performers:** Best earning games
- **Worst Performers:** Games to consider replacing
- **Daily Revenue Trends:** 30-day performance charts

### Maintenance Reports
- **Time Ranges:** Week, Month, Quarter, Year, All Time
- **Export Options:** Open orders, Closed orders, All orders
- **Cost Analysis:** Total maintenance expenses
- **Resolution Times:** Average time to fix issues

---

## 🛠️ System Administration

### Creating User Accounts
1. **Login as admin**
2. **Click "👥 Users"** in navigation
3. **Click "➕ Add New User"**
4. **Fill details:** Username, password, role
5. **Give credentials** to the new user

### Managing Users
- **View all accounts** with roles and status
- **Enable/Disable users** as needed
- **Cannot disable yourself** (safety feature)
- **Role hierarchy:** Admin > Manager > Operator > Read Only

### Database & Files
- **Database:** SQLite file at `arcade.db`
- **Images:** Stored in `static/uploads/`
- **Backups:** Copy `arcade.db` file regularly
- **Logs:** Check terminal output for errors

---

## 🔍 Troubleshooting

### Common Issues

**"Permission denied" errors:**
- User doesn't have required role level
- Check user role in "👥 Users" page
- Operators can only report maintenance issues

**Games not showing revenue:**
- Check if user is operator (they can't see revenue)
- Revenue only visible to managers and admins

**Maintenance requests not visible:**
- Operators can only CREATE requests, not view them
- Managers and admins see all maintenance requests

**Cannot record plays:**
- Only managers and admins can handle money/tokens
- Operators cannot record plays for security

**App won't start:**
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies if missing
pip install -r requirements.txt

# Start app
python app.py
```

### Port Issues
**If port 5000 is busy:**
1. Edit `app.py`
2. Change last line: `app.run(debug=True, host='0.0.0.0', port=5001)`
3. Access at http://localhost:5001

### Database Issues
**Reset database (DANGER - loses all data):**
```bash
rm arcade.db
python app.py  # Creates new empty database
```

---

## 📱 Mobile Access

**Access from phones/tablets:**
- Same URLs work on mobile devices
- Responsive design adapts to small screens
- All features available on mobile

---

## 🔒 Security Best Practices

### Password Management
- **Admin passwords:** Use strong, unique passwords
- **User accounts:** Create with appropriate roles only
- **Regular updates:** Change passwords periodically

### Network Security
- **Internal network only:** Don't expose to internet without VPN
- **Firewall:** Ensure port 5000 is blocked from internet
- **Access control:** Only give access to trusted personnel

### Data Protection
- **Regular backups:** Copy `arcade.db` file frequently
- **Role-based access:** Give users minimum required permissions
- **Monitor usage:** Check who's accessing what features

---

## 📋 Maintenance Schedule

### Daily
- ✅ Check for new maintenance requests
- ✅ Review critical systems alerts
- ✅ Record play counts from machines

### Weekly  
- ✅ Review worst performers list
- ✅ Export maintenance reports
- ✅ Backup database file

### Monthly
- ✅ Generate revenue reports
- ✅ Review user access levels
- ✅ Analyze top/bottom performers for replacements

---

## 🎯 Tips & Best Practices

### Game Management
- **Regular updates:** Keep game info current
- **Photo documentation:** Add images to games
- **Location tracking:** Always set proper location
- **Status monitoring:** Update status when games break

### Revenue Tracking
- **Daily readings:** Check coin counts every day
- **Consistent timing:** Take readings at same time daily
- **Problem games:** Pay attention to critical systems alerts
- **Performance analysis:** Use reports to make business decisions

### Team Management
- **Appropriate roles:** Don't give operators manager access
- **Training:** Show staff what they can/cannot do
- **Regular review:** Check user activity periodically
- **Clear communication:** Tell users their responsibilities

---

## 🆘 Emergency Contacts

### Technical Issues
- **Check this documentation first**
- **Look at terminal output for error messages**
- **Try restarting the application**

### Data Recovery
- **Database backup:** `arcade.db` file contains everything
- **Image backup:** `static/uploads/` folder has game photos
- **Config backup:** Copy entire project folder

---

## 📚 File Structure Reference

```
arcade-tracker/
├── app.py                    # Main application
├── arcade.db                 # Database (auto-created)
├── requirements.txt          # Python dependencies
├── static/
│   ├── css/cyberpunk.css    # Styling
│   └── uploads/             # Game images
├── templates/               # HTML pages
├── venv/                    # Python virtual environment
└── ARCADE_TRACKER_DOCS.md   # This documentation
```

---

**🎮 Happy Gaming!** - Your arcade tracker is now fully documented and ready to help you manage a successful arcade business!