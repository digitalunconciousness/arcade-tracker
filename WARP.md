# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Common Commands

### Running the Application
```bash
# Activate virtual environment
source venv/bin/activate

# Run development server (default port 5000)
python app.py
```

### Testing
```bash
# Test authentication setup
python test_auth.py

# Test basic application functionality (requires app to be running)
python test_features.py
```

### Database Management
```bash
# Initialize database tables
python init_db.py

# Create admin user
python create_admin.py

# Create manager user
python create_manager.py

# List all users
python list_users.py

# Check database schema
python check_db_schema.py
python check_all_schemas.py

# Database migrations (Flask-Migrate/Alembic)
flask db init           # Initialize migrations (already done)
flask db migrate -m "description"  # Generate migration
flask db upgrade        # Apply migrations
flask db downgrade      # Rollback migrations

# Legacy migration scripts (pre-Alembic)
python migrate_db.py
python migrate_all_missing.py
python create_work_log_table.py
python create_inventory_requests_table.py
```

### Backup and Restore
```bash
# Create database backup
python scripts/backup_database.py backup

# List available backups
python scripts/backup_database.py list

# Restore from backup (interactive)
python scripts/restore_database.py --interactive

# Restore specific backup
python scripts/restore_database.py --backup-file backups/arcade_backup_YYYYMMDD_HHMMSS.db

# Verify backup integrity
python scripts/restore_database.py --verify backups/arcade_backup_YYYYMMDD_HHMMSS.db

# Clean up old backups (>30 days)
python scripts/backup_database.py cleanup

# Setup automated daily backups (cron at 2 AM)
bash scripts/setup_backup_cron.sh
```

### Data Export
```bash
# Export CSV from web interface at /export_csv
# Export PDF reports from /export_report or /export_maintenance_report
```

## Project Architecture

### Technology Stack
- **Backend Framework**: Flask 3.0.0
- **Database ORM**: SQLAlchemy via Flask-SQLAlchemy 3.1.1
- **Database**: SQLite (stored in `instance/arcade.db` or `arcade.db`)
- **Authentication**: Flask-Login 0.6.3 with role-based access control
- **Security**: Flask-WTF 1.2.1 with CSRF protection, custom security middleware
- **Migrations**: Flask-Migrate (Alembic)
- **PDF Generation**: ReportLab 4.0.6
- **Data Analysis**: Pandas 2.1.4, NumPy 1.26.2
- **Charting**: Matplotlib 3.7.2, Chart.js (frontend)

### Application Structure
The application is a **monolithic Flask app** with all code in `app.py` (~3200 lines). While not following typical Flask project structure, this is the current architecture:

**Main Application File**: `app.py`
- Database models (lines ~450-650)
- WTForms classes for data validation
- Route handlers (~50+ routes)
- Authentication/authorization logic
- Business logic and data processing
- Security configuration integration

**Security Modules** (imported by app.py):
- `security_config.py` - Security configuration constants
- `security_utils.py` - Security utility functions (logging, password validation, file validation)
- `security_middleware.py` - Security middleware initialization and rate limiting

**Templates**: `templates/` - Jinja2 HTML templates with Bootstrap styling
**Static Assets**: `static/` - CSS, JavaScript, uploaded images
**Database**: `instance/arcade.db` or `arcade.db` (SQLite)
**Uploads**: `uploads/` - Game images; `static/maintenance_photos/` - Maintenance photos
**Backups**: `backups/` - Database backups with timestamps
**Logs**: `logs/` - Application and security logs

### Database Schema

**Core Tables**:
- `user` - User accounts with role-based permissions (readonly, operator, manager, admin)
- `game` - Arcade game inventory with location, status, revenue tracking, and counter management
- `play_record` - Individual play/revenue records per game with coin counts
- `maintenance_record` - Work orders for games or general facility maintenance
- `work_log` - Timestamped work entries associated with maintenance records (audit trail)

**Inventory Management Tables**:
- `inventory_item` - Parts/supplies inventory with stock tracking
- `stock_history` - Historical record of all inventory changes
- `low_stock_alert` - Automated alerts for low inventory
- `maintenance_inventory_usage` - Links maintenance records to parts used
- `inventory_request` - Requests for new inventory items
- `item_game_compatibility` - Many-to-many relationship between items and compatible games

**Key Relationships**:
- Game → PlayRecord (one-to-many, cascade delete)
- Game → MaintenanceRecord (one-to-many, cascade delete)
- MaintenanceRecord → WorkLog (one-to-many, cascade delete, ordered by timestamp)
- User → WorkLog (one-to-many, tracks who performed work)
- MaintenanceRecord → MaintenanceInventoryUsage (one-to-many)
- InventoryItem → StockHistory (one-to-many)

### Role-Based Access Control

**Permission Hierarchy** (higher roles inherit lower permissions):
1. **readonly** (Level 1): View-only access to games, reports, dashboard
2. **operator** (Level 2): + Log work entries, create maintenance requests
3. **manager** (Level 3): + Update work orders, record plays, add/edit games, generate reports
4. **admin** (Level 4): + User management, database backups, delete operations

**Implementation**: `User.has_role(role)` method compares hierarchical levels. Route protection via `@requires_role(role)` decorator.

### Authentication Flow
1. First-time setup: Visit `/setup` to create admin account (only available when no users exist)
2. Login: `/login` with username/password
3. Session-based authentication via Flask-Login
4. Password change enforcement: `must_change_password` flag forces password update on first login
5. Account locking: Failed login attempts tracked in `security_utils.py`
6. Profile management: `/profile` for picture uploads and account info

### Key Features & Routes

**Game Management** (`/games`, `/add_game`, `/edit_game/<id>`, `/game/<id>`):
- Comprehensive game inventory with manufacturer, year, genre
- Location tracking: Floor (with position), Warehouse (with section), Shipped
- Status tracking: Working, Being_Fixed, Not_Working, Retired
- Counter status tracking: Working, No_Counter, Broken_Counter
- Performance metrics: times in top 5/10, total plays, total revenue
- Image uploads with compression

**Play/Revenue Tracking** (`/record_plays/<game_id>`, `/add_baseline/<game_id>`):
- Record cumulative coin counts from machines
- Automatic play calculation from coin count differences
- Revenue calculation using `coins_per_play` setting
- Historical play records with date tracking
- Baseline creation for counter resets

**Maintenance System**:
- **Work Orders** (`/maintenance/game/<game_id>`, `/maintenance/general`): Create orders for games or general facility
- **Order Management** (`/maintenance_orders`, `/maintenance_detail/<id>`): View and update orders
- **Work Logging** (`/update_maintenance/<id>`): Timestamped work entries with parts, time, cost tracking
- **Photo Documentation** (`/maintenance_photos/<id>`): Upload photos with compression, cloud storage optional
- **Status Workflow**: Open → In_Progress → Fixed/Deferred

**Inventory Management** (if implemented):
- Parts/supplies tracking with stock levels
- Low stock alerts
- Usage tracking linked to maintenance records
- Stock history audit trail

**Reporting & Analytics**:
- **Revenue Reports** (`/revenue_reports`): Play and revenue analysis with time filters (7/30/90/365 days)
- **Maintenance Reports** (`/maintenance_reports`): Work order summaries with cost analysis
- **Graphs** (`/graphs`): Visual analytics with Chart.js
- **PDF Export** (`/export_report`, `/export_maintenance_report`): Professional reports via ReportLab
- **CSV Export** (`/export_csv`): Bulk data export

**Administration** (`/admin/users`, `/backup_management`, `/admin/storage`):
- User creation and management
- Database backup/restore interface
- Storage management for photos

### Security Features
- **CSRF Protection**: All forms protected via Flask-WTF
- **Rate Limiting**: Implemented in `security_middleware.py` via Flask-Limiter
- **Password Hashing**: Werkzeug password hashing
- **Password Strength Validation**: Custom validation in `security_utils.py`
- **Account Locking**: Failed login tracking with lockout mechanism
- **Security Logging**: Events logged to `logs/security.log`
- **File Upload Validation**: Strict file type and size checking
- **Safe Path Handling**: Path traversal prevention
- **Session Protection**: "strong" session protection in Flask-Login
- **Cloud Storage Support**: Optional AWS S3 for maintenance photos

### File Upload System
- **Game Images**: Uploaded to `uploads/`, compressed, filename stored in `game.image_filename`
- **Maintenance Photos**: Uploaded to `static/maintenance_photos/`, stored as JSON array in `maintenance_record.photos`
- **Profile Pictures**: Uploaded to `static/profile_pics/`, stored in `user.profile_picture`
- **Compression**: Images resized and compressed via PIL (max 1200x1200, 85% quality)
- **Limits**: 50MB max upload, 10 photos per maintenance record, 500MB total storage (configurable)
- **Cloud Storage**: Optional S3 upload via `upload_to_cloud()` when `USE_CLOUD_STORAGE=true`

### Configuration & Environment
Environment variables in `.env` (see `.env.example`):
- `SECRET_KEY`: Flask secret key (change in production!)
- `DATABASE_URL`: Database connection string (defaults to SQLite)
- `BACKUP_KEY`: Fernet key for encrypted backups
- `USE_CLOUD_STORAGE`: Enable AWS S3 for photos
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_BUCKET_NAME`, `AWS_REGION`: S3 credentials
- `MAX_PHOTOS_PER_RECORD`, `MAX_TOTAL_STORAGE_MB`: Upload limits

### Important Implementation Notes

1. **Game Sorting**: The default sorting order for the all games tab should be alphabetical (per project rules).

2. **Database Location**: Database can be in root (`arcade.db`) or `instance/` folder. Code handles both locations. Backup/restore scripts sync both locations.

3. **Migration Strategy**: Project uses both Alembic (via Flask-Migrate) and legacy migration scripts. Prefer Alembic for new migrations.

4. **Monolithic Structure**: All application code is in a single 3200-line `app.py` file. When making changes, be mindful of:
   - Duplicate configuration sections (lines ~80-200 have some duplication)
   - Model definitions around lines 450-650
   - Route handlers starting around line 662
   - No separate blueprints or modular structure

5. **Work Logging Pattern**: Maintenance updates create new `WorkLog` entries (timestamped audit trail) rather than overwriting. This provides complete work history.

6. **Photo Storage**: Photos are stored locally by default. For production with multiple users, enable cloud storage via environment variables.

7. **Security Middleware**: Security features initialized via `init_security(app)` from `security_middleware.py`. This sets up rate limiting and security headers.

8. **Testing**: Test files (`test_auth.py`, `test_features.py`) are basic smoke tests. No comprehensive test suite with pytest/unittest exists.

9. **Performance Tracking**: The system automatically tracks when games appear in "top 5" or "top 10" performance rankings via `times_in_top_5` and `times_in_top_10` fields.

10. **Counter Management**: Games can have different counter states (Working/No_Counter/Broken_Counter) which affects play tracking reliability.

## Development Workflow

### Making Database Schema Changes
1. Create migration: `flask db migrate -m "description"`
2. Review generated migration in `migrations/versions/`
3. Apply migration: `flask db upgrade`
4. Test thoroughly
5. For production: backup first, then apply migration

### Adding New Routes
1. Add route handler in `app.py` (following existing patterns)
2. Add permission decorator if needed: `@requires_role('manager')`
3. Create/update template in `templates/`
4. Update navigation in `templates/base.html`
5. Test with different user roles

### Adding New Features
1. Backup database first
2. Update models if needed (add migration)
3. Update forms (WTForms classes in `app.py`)
4. Add/update route handlers
5. Create/update templates
6. Test with appropriate user roles
7. Update this WARP.md if architectural changes

### Common Issues
- **Database locked**: Ensure only one app instance is running
- **CSRF errors**: Check that forms include `{{ form.csrf_token }}` and Flask-WTF is properly initialized
- **Permission denied**: Verify user role and route decorator requirements
- **Upload fails**: Check folder permissions and disk space
- **Migration fails**: Backup database, check migration SQL, may need manual fixes
