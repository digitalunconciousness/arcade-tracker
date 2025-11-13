# Changelog

All notable changes to Arcade Tracker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-13

### 🎉 Version 1.0 Release

This is the first major release of Arcade Tracker, featuring a complete arcade management system with real-time skeeball integration, automated backups, and comprehensive inventory and maintenance tracking.

### Added

#### Core Features
- Complete game inventory management with location tracking (Floor, Warehouse, Shipped)
- Revenue and play tracking with automatic calculations from coin counters
- Advanced maintenance system with timestamped work logs and audit trails
- Inventory management with parts/supplies tracking and low stock alerts
- Role-based access control system (readonly, operator, manager, admin)
- Professional PDF report generation with ReportLab
- CSV data export functionality
- Database backup and restore with Fernet encryption
- **Automated daily backups** via cron job (runs at 2 AM, cleans up backups >30 days old)
- Monthly performance tracking (top 5/top 10 rankings)
- Executive summary dashboard with actionable insights

#### Skeeball Integration
- Complete Raspberry Pi-based skeeball scoring system
- Automatic scoring with 7-sensor configuration (coin, ball counter, 5 scoring holes)
- **Real-time game state updates** with 0.5-second control panel refresh
- **Statistics page** with 1-second updates showing cumulative totals and best scores
- File-based state synchronization avoiding GPIO conflicts
- Stats API server (port 5002) serving real-time data
- Web-based control panel for lane management
- Simulator mode for testing without hardware
- GPIO testing interface for hardware diagnostics
- Multi-lane architecture support (single Pi 4 + Pico per lane)
- Persistent game state surviving power loss
- Bonus game system with configurable thresholds
- Revenue reconciliation with automatic daily sync

#### Real-Time Skeeball Features (v1.0)
- State saves on coin insert, switch trigger, and ball completion
- Control panel shows live score, balls remaining, and game active status
- Statistics display total games, total coins, and best score
- No page refresh needed - updates appear as you play
- Background `state_sync.py` process watches state file and syncs every second
- Stats API loads game history from source file for accurate statistics

#### User Interface
- Cyberpunk-themed responsive design
- Clean dashboard with revenue overview and inventory alerts
- **Low stock alerts** displayed on home dashboard
- Professional maintenance reports with work timeline visualization
- User management interface without unnecessary email column
- Profile management with picture uploads
- Simplified skeeball statistics (focused on essential metrics)

#### Security
- Flask-Login session-based authentication
- CSRF protection on all forms via Flask-WTF
- Password strength validation and forced password changes
- Account locking after failed login attempts
- Security event logging to `logs/security.log`
- Rate limiting on API endpoints (exempt for skeeball real-time updates)
- File upload validation with type and size restrictions
- Session protection with secure cookies

#### Database & Storage
- SQLite database with SQLAlchemy ORM
- Flask-Migrate for database migrations
- Backup encryption with Fernet keys
- Database location flexibility (root or instance folder)
- Photo storage with image compression (max 1200x1200, 85% quality)
- Optional AWS S3 cloud storage for maintenance photos

#### Documentation
- Comprehensive README.md with installation and usage instructions
- WARP.md for AI-assisted development with common commands
- GitHub Wiki with feature documentation
- Skeeball Integration guide with hardware requirements
- Deployment checklist for production setup
- Troubleshooting guides

### Changed
- Control panel updates every 500ms (was 2000ms)
- Statistics page updates every 1000ms (was 5000ms)
- Skeeball control panel header uses clean styling (removed glitch effect)
- Manage users table simplified (removed email column)
- Add User button maintains text visibility after clicking
- Stats API now correctly displays total score, best score, and average score

### Fixed
- Stats API properly loads game history from skeeball_state.json
- load_realtime_state() reloads game_history on each request for accurate stats
- load_state_from_file() uses absolute path for state file location
- Real-time game state synchronization fully functional
- Skeeball control panel updates on ball completion, not just game start
- Low stock alerts now display correctly on dashboard
- Rate limiting exemption for skeeball API endpoints

### Technical Details
- Flask 3.0.0 backend with SQLAlchemy 2.0+
- Python 3.10+ required
- Chart.js for analytics visualization
- ReportLab 4.0.6 for PDF generation
- Pandas 2.1.4 and NumPy 1.26.2 for data analysis
- Flask-Limiter for rate limiting
- Cryptography library for backup encryption

### Deployment
- Supports Linux environments (tested on Fedora and Raspberry Pi OS)
- Development server via `python app.py`
- Production deployment with Gunicorn recommended
- Automated backup cron job via `scripts/setup_daily_backup.sh`
- Multiple Git branches: master, skeeball-integration, no-skeeball

---

## Future Roadmap

### Planned for v1.1
- Enhanced reporting with custom date ranges
- Bulk game import/export
- Email notifications for low stock and maintenance alerts
- API documentation with Swagger/OpenAPI

### Under Consideration
- Mobile-responsive improvements
- Dark/light theme toggle
- Advanced analytics and forecasting
- Integration with additional hardware systems
- Multi-tenant support for multiple arcades

---

**Full Changelog**: https://github.com/digitalunconciousness/arcade-tracker/compare/v0.1...v1.0.0
