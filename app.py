# -------------------------------------------------------------
# ✅ Standard Library Imports
# -------------------------------------------------------------
import os
import sys
import io
import json
import uuid
import zipfile
import pandas as pd
from datetime import datetime, date
import datetime as dt
from functools import wraps

# -------------------------------------------------------------
# 🧾 PDF / Report Generation
# -------------------------------------------------------------
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# -------------------------------------------------------------
# 🔐 Security & Encryption
# -------------------------------------------------------------
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# -------------------------------------------------------------
# 🧰 Flask Core
# -------------------------------------------------------------
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    make_response, send_file, send_from_directory
)

# -------------------------------------------------------------
# 👥 Flask Extensions
# -------------------------------------------------------------
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileAllowed



# -------------------------------------------------------------
# 🧩 WTForms Fields & Validators
# -------------------------------------------------------------
from wtforms import (
    StringField, PasswordField, SelectField, SubmitField, FileField,
    MultipleFileField, TextAreaField, IntegerField, FloatField,
    SelectMultipleField, FieldList, FormField, BooleanField
)
from wtforms.validators import (
    DataRequired, Length, EqualTo, Optional, NumberRange
)

# -------------------------------------------------------------
# 🛡️ Custom Security Utilities
# -------------------------------------------------------------
from security_config import SecurityConfig
from security_utils import (
    log_security_event, check_password_strength,
    record_failed_login, is_account_locked, clear_failed_login_attempts,
    get_client_ip, safe_path_join, validate_file_upload
)
from security_middleware import init_security

# Load environment variables
# -------------------------------------------------------------
# ⚙️ Flask Application Configuration
# -------------------------------------------------------------

# Initialize Flask app
app = Flask(__name__)
csrf = CSRFProtect(app)


# -------------------------------------------------------------
# 🔧 Core Configuration
# -------------------------------------------------------------
# It's best to load sensitive values (SECRET_KEY, DB URI) from environment variables in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey-change-this')
app.config['REMEMBER_COOKIE_DURATION'] = dt.timedelta(days=30)
app.config['PERMANENT_SESSION_LIFETIME'] = dt.timedelta(days=30)
app.config['REMEMBER_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_REFRESH_EACH_REQUEST'] = False
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# -------------------------------------------------------------
# ðŸ"§ Core Configuration
# -------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_FOLDER = os.path.join(BASE_DIR, 'instance')

# Ensure instance folder exists BEFORE setting database URI
os.makedirs(INSTANCE_FOLDER, exist_ok=True)

# Use absolute path for database (4 slashes for absolute path)
DB_PATH = os.path.join(INSTANCE_FOLDER, 'arcade.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 
    f'sqlite:///{DB_PATH}'  # 3 slashes + absolute path
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"✅ Database will be created at: {DB_PATH}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------------------------------------------------------------
# 🔐 Security & CSRF
# -------------------------------------------------------------
csrf = CSRFProtect(app)
init_security(app)  # from security_middleware.py
#setup_security_logging(app)  # from security_utils.py

# -------------------------------------------------------------
# 💾 File & Upload Configuration
# -------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
BACKUP_FOLDER = os.path.join(BASE_DIR, 'backups')
INSTANCE_FOLDER = os.path.join(BASE_DIR, 'instance')

for folder in (UPLOAD_FOLDER, BACKUP_FOLDER, INSTANCE_FOLDER):
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB upload limit

# -------------------------------------------------------------
# 🧠 Database
# -------------------------------------------------------------

# -------------------------------------------------------------
# 🔒 Encrypted Backup Key
# -------------------------------------------------------------
# Generate a key using:
# >>> from cryptography.fernet import Fernet
# >>> Fernet.generate_key()
app.config['BACKUP_KEY'] = os.environ.get(
    'BACKUP_KEY',
    b'YOUR-GENERATED-FERNET-KEY-HERE'  # <-- replace this with your real key
)

# -------------------------------------------------------------
# 🧾 Logging
# -------------------------------------------------------------
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_FOLDER, exist_ok=True)
SECURITY_LOG = os.path.join(LOGS_FOLDER, 'security.log')


# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Storage limits
MAX_PHOTOS_PER_RECORD = 10  # Limit photos per maintenance record
MAX_TOTAL_STORAGE_MB = 500  # Total storage limit in MB

# Cloud storage configuration (set these via environment variables)
USE_CLOUD_STORAGE = os.getenv('USE_CLOUD_STORAGE', 'false').lower() == 'true'
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_BUCKET_NAME = os.getenv('AWS_BUCKET_NAME', 'arcade-tracker-photos')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

# -------------------------------------------------------------
# 🔐 Security & CSRF
# -------------------------------------------------------------
csrf = CSRFProtect(app)

# -------------------------------------------------------------
# 💾 File & Upload Configuration
# -------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
BACKUP_FOLDER = os.path.join(BASE_DIR, 'backups')
INSTANCE_FOLDER = os.path.join(BASE_DIR, 'instance')

for folder in (UPLOAD_FOLDER, BACKUP_FOLDER, INSTANCE_FOLDER):
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB upload limit

# -------------------------------------------------------------
# 🔒 Encrypted Backup Key
# -------------------------------------------------------------
app.config['BACKUP_KEY'] = os.environ.get(
    'BACKUP_KEY',
    b'YOUR-GENERATED-FERNET-KEY-HERE'
)

# -------------------------------------------------------------
# 🧾 Logging
# -------------------------------------------------------------
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_FOLDER, exist_ok=True)
SECURITY_LOG = os.path.join(LOGS_FOLDER, 'security.log')

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Storage limits
MAX_PHOTOS_PER_RECORD = 10
MAX_TOTAL_STORAGE_MB = 500

# Cloud storage configuration
USE_CLOUD_STORAGE = os.getenv('USE_CLOUD_STORAGE', 'false').lower() == 'true'
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_BUCKET_NAME = os.getenv('AWS_BUCKET_NAME', 'arcade-tracker-photos')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

# -------------------------------------------------------------
# 🧠 Database
# -------------------------------------------------------------
db = SQLAlchemy(app)
from flask_migrate import Migrate
migrate = Migrate(app, db)


# -------------------------------------------------------------
# 💥 Flask-Login
# -------------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"

# -------------------------------------------------------------
# 🛡️ Initialize Security (includes rate limiting and logging)
# -------------------------------------------------------------
limiter = init_security(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def compress_and_save_image(file, file_path, max_size=(1200, 1200), quality=85):
    """Compress image while maintaining reasonable quality"""
    try:
        from PIL import Image
        
        # Open the uploaded image
        image = Image.open(file)
        
        # Convert RGBA to RGB if necessary (for JPEG compatibility)
        if image.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
            image = background
        elif image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Resize if image is too large
        image.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Save with compression
        image.save(file_path, 'JPEG', quality=quality, optimize=True)
        
    except Exception as e:
        # Fallback: save original file if compression fails
        print(f"Compression failed, saving original: {e}")
        file.seek(0)  # Reset file pointer
        file.save(file_path)

def get_directory_size(directory):
    """Get total size of directory in MB"""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
    except OSError:
        return 0
    return total_size / (1024 * 1024)  # Convert to MB

def cleanup_old_photos(max_age_days=365):
    """Remove photos older than specified days"""
    from datetime import timedelta
    upload_dir = os.path.join(app.root_path, 'static', 'maintenance_photos')
    cutoff_date = datetime.now() - timedelta(days=max_age_days)
    removed_count = 0
    
    try:
        for filename in os.listdir(upload_dir):
            filepath = os.path.join(upload_dir, filename)
            if os.path.isfile(filepath):
                file_date = datetime.fromtimestamp(os.path.getctime(filepath))
                if file_date < cutoff_date:
                    # Check if file is still referenced in database
                    records = MaintenanceRecord.query.all()
                    is_referenced = any(filename in (record.get_photos() or []) for record in records)
                    
                    if not is_referenced:
                        os.remove(filepath)
                        removed_count += 1
    except Exception as e:
        print(f"Cleanup error: {e}")
    
    return removed_count

def upload_to_cloud(file_data, filename):
    """Upload file to cloud storage (AWS S3)"""
    if not USE_CLOUD_STORAGE:
        return None
    
    try:
        import boto3
        from botocore.exceptions import NoCredentialsError, ClientError
        
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        
        # Upload file
        s3_client.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=f'maintenance_photos/{filename}',
            Body=file_data,
            ContentType='image/jpeg'
        )
        
        return f'https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/maintenance_photos/{filename}'
        
    except (NoCredentialsError, ClientError) as e:
        print(f'Cloud upload failed: {e}')
        return None
    except ImportError:
        print('boto3 not installed. Install with: pip install boto3')
        return None

def get_cloud_url(filename):
    """Get cloud URL for a photo"""
    if USE_CLOUD_STORAGE and AWS_BUCKET_NAME:
        return f'https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/maintenance_photos/{filename}'
    return url_for('static', filename=f'maintenance_photos/{filename}')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.context_processor
def utility_processor():
    return dict(today=date.today, get_cloud_url=get_cloud_url)

# Permission decorator
def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not current_user.has_role(role):
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Authentication Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Stay logged in for 30 days', default=True)
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('readonly', 'Read Only'), ('operator', 'Operator'), ('manager', 'Manager')], validators=[DataRequired()])
    submit = SubmitField('Register')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')
    
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

class ProfileForm(FlaskForm):
    profile_picture = FileField('Profile Picture', validators=[
        Optional(),
        FileAllowed(['png', 'jpg', 'jpeg', 'gif'], 'Images only (PNG, JPG, JPEG, GIF)')
    ])
    submit = SubmitField('Update Profile')

class MaintenancePhotoForm(FlaskForm):
    photos = MultipleFileField('Maintenance Photos', validators=[Optional()], render_kw={"multiple": True, "accept": "image/*"})
    submit = SubmitField('Upload Photos')

class InventoryItemForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    stock_quantity = IntegerField('Stock Quantity', validators=[DataRequired(), NumberRange(min=0)])
    unit_price = FloatField('Unit Price ($)', validators=[DataRequired(), NumberRange(min=0)])
    minimum_stock = IntegerField('Minimum Stock Level', validators=[DataRequired(), NumberRange(min=0)])
    supplier = StringField('Supplier', validators=[Optional()])
    part_number = StringField('Part Number', validators=[Optional()])
    compatible_games = SelectMultipleField('Compatible Games', coerce=int, validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Save Item')

class StockAdjustmentForm(FlaskForm):
    adjustment_type = SelectField('Type', choices=[
        ('added', 'Stock Added'),
        ('removed', 'Stock Removed'), 
        ('used', 'Used in Repair'),
        ('adjusted', 'Inventory Adjustment')
    ], validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    reason = StringField('Reason', validators=[Optional()])
    submit = SubmitField('Update Stock')

class InventoryUsageForm(FlaskForm):
    item_id = SelectField('Item', coerce=int, validators=[Optional()])
    quantity_used = IntegerField('Quantity', validators=[Optional(), NumberRange(min=0)])

class MaintenanceWithInventoryForm(FlaskForm):
    issue_description = TextAreaField('Issue Description', validators=[DataRequired()])
    fix_description = TextAreaField('Initial Assessment/Diagnosis', validators=[Optional()])
    cost = FloatField('Total Cost ($)', validators=[Optional(), NumberRange(min=0)])
    technician = StringField('Technician', validators=[Optional()])
    status = SelectField('Status', choices=[
        ('Open', 'Open'),
        ('In_Progress', 'In Progress'),
        ('Fixed', 'Fixed'),
        ('Deferred', 'Deferred')
    ], validators=[DataRequired()])
    
    # Inventory usage fields
    inventory_items = FieldList(FormField(InventoryUsageForm), min_entries=5, max_entries=10)
    
    submit = SubmitField('Save Maintenance Record')

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='readonly')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    must_change_password = db.Column(db.Boolean, default=True)  # Force password change on first login
    profile_picture = db.Column(db.String(255), nullable=True)  # Profile picture filename
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        role_hierarchy = {
            'readonly': 1,
            'operator': 2, 
            'manager': 3,
            'admin': 4
        }
        user_level = role_hierarchy.get(self.role, 0)
        required_level = role_hierarchy.get(role, 0)
        return user_level >= required_level
    
    def get_id(self):
        return str(self.id)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    manufacturer = db.Column(db.String(50), nullable=True)
    year = db.Column(db.Integer, nullable=True)
    genre = db.Column(db.String(50), nullable=True)
    # Enhanced location tracking
    location = db.Column(db.String(20), default='Warehouse')  # Floor, Warehouse, Shipped
    floor_position = db.Column(db.String(50), nullable=True)  # Specific position on floor
    warehouse_section = db.Column(db.String(50), nullable=True)  # Warehouse location
    # Enhanced status tracking
    status = db.Column(db.String(20), default='Working')  # Working, Being_Fixed, Not_Working, Retired
    # Revenue tracking
    coins_per_play = db.Column(db.Float, default=0.25)  # Default quarter per play
    total_plays = db.Column(db.Integer, default=0)
    total_revenue = db.Column(db.Float, default=0.0)
    # Counter status tracking
    counter_status = db.Column(db.String(20), default='Working')  # Working, No_Counter, Broken_Counter
    counter_notes = db.Column(db.Text, nullable=True)  # Additional notes about counter status
    # Metadata
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    notes = db.Column(db.Text, nullable=True)
    # Image - simplified without scraping
    image_filename = db.Column(db.String(255), nullable=True)
    # Performance tracking
    times_in_top_5 = db.Column(db.Integer, default=0)
    times_in_top_10 = db.Column(db.Integer, default=0)
    
    play_records = db.relationship('PlayRecord', backref='game', lazy=True, cascade='all, delete-orphan')
    maintenance_records = db.relationship('MaintenanceRecord', backref='game', lazy=True, cascade='all, delete-orphan')

class PlayRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    coin_count = db.Column(db.Integer, nullable=False, default=0)  # Cumulative coin count from machine
    plays_count = db.Column(db.Integer, nullable=False, default=0)  # Calculated plays from difference
    revenue = db.Column(db.Float, nullable=False, default=0.0)
    date_recorded = db.Column(db.Date, nullable=False, default=date.today)
    notes = db.Column(db.Text, nullable=True)

class MaintenanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=True)  # <-- Change to nullable=True
    work_order_type = db.Column(db.String(50), default='game')  # 'game', 'facility', 'equipment', 'general'
    location_description = db.Column(db.String(200), nullable=True)  # For non-game work orders
    issue_description = db.Column(db.Text, nullable=False)
    fix_description = db.Column(db.Text, nullable=True)  # Initial diagnosis/assessment
    work_notes = db.Column(db.Text, nullable=True)  # Actual work performed (kept for compatibility)
    parts_used = db.Column(db.Text, nullable=True)  # Parts/materials used
    cost = db.Column(db.Float, nullable=True)
    date_reported = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    date_fixed = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Open')  # Open, In_Progress, Fixed, Deferred
    priority = db.Column(db.String(20), default='Medium')  # Low, Medium, High, Critical
    technician = db.Column(db.String(50), nullable=True)
    # Photo documentation
    photos = db.Column(db.Text, nullable=True)  # JSON array of photo filenames
    
    work_logs = db.relationship('WorkLog', backref='maintenance_record', lazy=True, cascade='all, delete-orphan', order_by='WorkLog.timestamp')
    
    def get_photos(self):
        """Get list of photo filenames"""
        if self.photos:
            try:
                return json.loads(self.photos)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    def add_photo(self, filename):
        """Add a photo filename to the record"""
        photos = self.get_photos()
        if filename not in photos:
            photos.append(filename)
            self.photos = json.dumps(photos)
    
    def remove_photo(self, filename):
        """Remove a photo filename from the record"""
        photos = self.get_photos()
        if filename in photos:
            photos.remove(filename)
            self.photos = json.dumps(photos) if photos else None

class WorkLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    maintenance_id = db.Column(db.Integer, db.ForeignKey('maintenance_record.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    work_description = db.Column(db.Text, nullable=False)
    parts_used = db.Column(db.Text, nullable=True)
    time_spent = db.Column(db.Float, nullable=True)  # Hours spent on this work
    cost_incurred = db.Column(db.Float, nullable=True)  # Cost for this specific work entry
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    
    user = db.relationship('User', backref='work_logs')

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    stock_quantity = db.Column(db.Integer, default=0)
    unit_price = db.Column(db.Float, default=0.0)
    minimum_stock = db.Column(db.Integer, default=5)  # For low stock alerts
    supplier = db.Column(db.String(200), nullable=True)
    part_number = db.Column(db.String(100), nullable=True)
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    last_restocked = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Relationship with games (which machines this item works with)
    compatible_games = db.relationship('Game', secondary='item_game_compatibility', backref='compatible_items')
    stock_history = db.relationship('StockHistory', backref='item', lazy=True, cascade='all, delete-orphan')
    
    def is_low_stock(self):
        return self.stock_quantity <= self.minimum_stock
    
    def total_value(self):
        return self.stock_quantity * self.unit_price

# Association table for many-to-many relationship between items and games
item_game_compatibility = db.Table('item_game_compatibility',
    db.Column('item_id', db.Integer, db.ForeignKey('inventory_item.id'), primary_key=True),
    db.Column('game_id', db.Integer, db.ForeignKey('game.id'), primary_key=True)
)

class StockHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    change_type = db.Column(db.String(20), nullable=False)  # 'added', 'removed', 'used', 'adjusted'
    quantity_change = db.Column(db.Integer, nullable=False)  # Positive for add, negative for remove
    previous_quantity = db.Column(db.Integer, nullable=False)
    new_quantity = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref='stock_changes')

class LowStockAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    alert_triggered = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    email_sent = db.Column(db.Boolean, default=False)
    resolved = db.Column(db.Boolean, default=False)
    resolved_date = db.Column(db.DateTime, nullable=True)
    
    item = db.relationship('InventoryItem', backref='alerts')

class MaintenanceInventoryUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    maintenance_id = db.Column(db.Integer, db.ForeignKey('maintenance_record.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    quantity_used = db.Column(db.Integer, nullable=False)
    unit_price_at_time = db.Column(db.Float, nullable=False)  # Store price when used
    total_cost = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    
    maintenance_record = db.relationship('MaintenanceRecord', backref='inventory_usage')
    item = db.relationship('InventoryItem', backref='maintenance_usage')

class InventoryRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=True)  # Null if requesting new item
    maintenance_id = db.Column(db.Integer, db.ForeignKey('maintenance_record.id'), nullable=True)  # Link to work order
    item_name = db.Column(db.String(200), nullable=False)  # Name of item (for new or existing)
    quantity_requested = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=True)  # Why it's needed
    urgency = db.Column(db.String(20), default='Normal')  # Low, Normal, High, Urgent
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Ordered, Received, Rejected
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_requested = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    date_fulfilled = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)  # Admin notes
    tracking_number = db.Column(db.String(200), nullable=True)  # Shipping tracking number
    vendor = db.Column(db.String(200), nullable=True)  # Where ordered from
    estimated_arrival = db.Column(db.Date, nullable=True)  # Expected delivery date
    carrier = db.Column(db.String(50), nullable=True)  # USPS, UPS, FedEx, etc.
    tracking_status = db.Column(db.String(50), nullable=True)  # Latest tracking status from API
    tracking_details = db.Column(db.Text, nullable=True)  # JSON of tracking history
    last_tracking_update = db.Column(db.DateTime, nullable=True)  # When tracking was last fetched
    
    requested_by = db.relationship('User', backref='inventory_requests')
    item = db.relationship('InventoryItem', backref='requests')
    maintenance_record = db.relationship('MaintenanceRecord', backref='inventory_requests')
    history = db.relationship('InventoryRequestHistory', backref='request', lazy=True, cascade='all, delete-orphan', order_by='InventoryRequestHistory.timestamp.desc()')

class InventoryRequestHistory(db.Model):
    """Track all changes to inventory requests for audit trail"""
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('inventory_request.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'created', 'status_changed', 'updated', etc.
    field_changed = db.Column(db.String(50), nullable=True)  # Which field was modified
    old_value = db.Column(db.String(500), nullable=True)
    new_value = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)  # Additional context
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    
    user = db.relationship('User', backref='request_history_actions')

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        
        # Check if account is locked
        if is_account_locked(username):
            log_security_event(
                'LOGIN_ATTEMPT_LOCKED_ACCOUNT',
                details=f"Username: {username}, IP: {get_client_ip()}"
            )
            flash('Account temporarily locked due to multiple failed login attempts. Try again in 15 minutes.', 'error')
            return render_template('login.html', form=form)
        
        # Case-insensitive username lookup
        user = User.query.filter(User.username.ilike(username)).first()
        
        if user and user.check_password(form.password.data) and user.is_active:
            # Clear failed login attempts
            clear_failed_login_attempts(username)
            
            # Update last login
            user.last_login = datetime.now(dt.UTC)
            db.session.commit()
            
            # Make session permanent if remember me is checked
            if form.remember.data:
                from flask import session
                session.permanent = True
            
            login_user(user, remember=form.remember.data)
            
            # Log successful login
            log_security_event(
                'LOGIN_SUCCESS',
                user_id=user.id,
                details=f"Username: {username}"
            )
            
            # Check if user must change password
            if user.must_change_password:
                flash('You must change your password before continuing.', 'warning')
                return redirect(url_for('change_password'))
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Validate redirect URL to prevent open redirect
            next_page = request.args.get('next')
            if next_page and not next_page.startswith('/'):
                next_page = None
            
            return redirect(next_page) if next_page else redirect(url_for('home'))
        
        # Record failed login attempt
        is_locked = record_failed_login(username)
        
        # Log failed login
        log_security_event(
            'LOGIN_FAILED',
            details=f"Username: {username}, IP: {get_client_ip()}"
        )
        
        if is_locked:
            flash('Too many failed login attempts. Account locked for 15 minutes.', 'error')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Main Routes
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                name_part, ext = os.path.splitext(filename)
                unique_filename = f"profile_{current_user.id}_{uuid.uuid4().hex[:8]}{ext}"

                upload_dir = os.path.join(app.root_path, 'static', 'profile_pics')
                os.makedirs(upload_dir, exist_ok=True)
                file_path = os.path.join(upload_dir, unique_filename)

                # Delete old profile picture if it exists
                if current_user.profile_picture:
                    old_path = os.path.join(upload_dir, current_user.profile_picture)
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                        except:
                            pass

                file.save(file_path)
                current_user.profile_picture = unique_filename
                db.session.commit()
                flash('Profile picture updated successfully.', 'success')
            else:
                flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF.', 'error')
        
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form)
@app.route('/')
@login_required
def home():
    # Fetch data for dashboard
    all_games = Game.query.all()
    floor_games = Game.query.filter_by(location='Floor').all()
    total_games = len(all_games)
    total_plays = sum(game.total_plays for game in all_games)
    total_revenue = sum(game.total_revenue for game in all_games)

    # Get recent records and maintenance
    recent_records = PlayRecord.query.order_by(PlayRecord.date_recorded.desc()).limit(5).all()
    recent_maintenance = MaintenanceRecord.query.filter_by(status='Open').limit(5).all()

    # Calculate worst performers (optional dashboard detail)
    worst_performers = []
    if floor_games:
        performers = []
        for game in floor_games:
            if game.counter_status != 'Working':
                continue
            # make sure date_added is timezone aware
            date_added = game.date_added
            if date_added.tzinfo is None:
                date_added = date_added.replace(tzinfo=dt.UTC)
            days_active = max((datetime.now(dt.UTC) - date_added).days, 1)
            daily_revenue_avg = game.total_revenue / days_active
            performers.append((game, daily_revenue_avg))
        worst_performers = sorted(performers, key=lambda x: x[1])[:3]

    # Render template with context
    return render_template(
        'index.html',
        total_games=total_games,
        floor_games=floor_games,
        total_plays=total_plays,
        total_revenue=total_revenue,
        recent_records=recent_records,
        recent_maintenance=recent_maintenance,
        worst_performers=worst_performers)

@app.route('/add_game', methods=['GET', 'POST'])
@login_required
@requires_role('manager')
def add_game():
    if request.method == 'POST':
        name = request.form['name']
        manufacturer = request.form.get('manufacturer', '')
        year = request.form.get('year')
        genre = request.form.get('genre', '')
        location = request.form.get('location', 'Warehouse')
        status = request.form.get('status', 'Working')
        coins_per_play_str = request.form.get('coins_per_play', '0.25')
        if coins_per_play_str and coins_per_play_str.strip():
            coins_per_play = float(coins_per_play_str)
        else:
            coins_per_play = 0.25
        counter_status = request.form.get('counter_status', 'Working')
        counter_notes = request.form.get('counter_notes', '')
        notes = request.form.get('notes', '')
        
        # Convert year to int if provided
        if year and year.strip():
            try:
                year = int(year)
            except ValueError:
                year = None
        else:
            year = None
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add UUID to prevent filename conflicts
                name_part, ext = os.path.splitext(filename)
                filename = f"{name_part}_{uuid.uuid4().hex[:8]}{ext}"
                
                # Ensure upload directory exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_filename = filename
        
        game = Game(
            name=name,
            manufacturer=manufacturer,
            year=year,
            genre=genre,
            location=location,
            status=status,
            coins_per_play=coins_per_play,
            counter_status=counter_status,
            counter_notes=counter_notes,
            notes=notes,
            image_filename=image_filename
        )
        
        db.session.add(game)
        db.session.commit()
        
        # Handle initial coin count if provided and counter is working
        initial_coin_count = request.form.get('initial_coin_count')
        if initial_coin_count and initial_coin_count.strip() and counter_status == 'Working':
            try:
                coin_count = int(initial_coin_count)
                if coin_count > 0:
                    # Create initial play record with baseline
                    initial_record = PlayRecord(
                        game_id=game.id,
                        coin_count=coin_count,
                        plays_count=0,  # No new plays, just setting baseline
                        revenue=0.0,
                        date_recorded=date.today(),
                        notes="Initial baseline coin count"
                    )
                    db.session.add(initial_record)
                    db.session.commit()
                    print(f"Added baseline play record for {game.name}: {coin_count} coins")
            except (ValueError, TypeError):
                pass  # Ignore invalid input
        
        success_msg = f'Game "{game.name}" added successfully!'
        if initial_coin_count and initial_coin_count.strip():
            try:
                coin_count = int(initial_coin_count)
                if coin_count > 0:
                    success_msg += f' (Baseline: {coin_count} coins)'
            except (ValueError, TypeError):
                pass
        flash(success_msg, 'success')
        return redirect(url_for('games_list'))
    
    return render_template('add_game.html')

@app.route('/record_plays/<int:game_id>', methods=['GET', 'POST'])
@login_required
@requires_role('manager')
def record_plays(game_id):
    game = Game.query.get_or_404(game_id)
    
    # Check if counter is working
    if game.counter_status != 'Working':
        flash(f'Cannot record plays for "{game.name}" - Counter status: {game.counter_status.replace("_", " ")}', 'error')
        return redirect(url_for('game_detail', game_id=game_id))
    
    # Get the most recent coin count for this game
    last_record = PlayRecord.query.filter_by(game_id=game_id).order_by(PlayRecord.date_recorded.desc()).first()
    last_coin_count = last_record.coin_count if last_record else 0
    
    if request.method == 'POST':
        try:
            current_coin_count = int(request.form['coin_count'])
        except (ValueError, KeyError):
            flash('Error: Invalid coin count value', 'error')
            return render_template('record_plays.html', game=game, last_coin_count=last_coin_count)
        record_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        notes = request.form.get('notes', '')
        
        # Validate coin count is not less than previous
        if current_coin_count < last_coin_count:
            flash(f'Error: Coin count ({current_coin_count}) cannot be less than the previous reading ({last_coin_count})', 'error')
            return render_template('record_plays.html', game=game, last_coin_count=last_coin_count)
        
        # Calculate plays from difference
        new_plays = current_coin_count - last_coin_count
        
        # Calculate revenue
        revenue = new_plays * game.coins_per_play
        
        # Create play record
        play_record = PlayRecord(
            game_id=game_id,
            coin_count=current_coin_count,
            plays_count=new_plays,
            revenue=revenue,
            date_recorded=record_date,
            notes=notes
        )
        db.session.add(play_record)
        
        # Update totals
        game.total_plays += new_plays
        game.total_revenue += revenue
        db.session.commit()
        
        flash(f'Recorded {new_plays} plays (${revenue:.2f}) for "{game.name}" - Coin count: {current_coin_count}', 'success')
        return redirect(url_for('game_detail', game_id=game_id))
    
    return render_template('record_plays.html', game=game, last_coin_count=last_coin_count)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been successfully updated.', 'success')
            return redirect(url_for('profile'))

    return render_template('change_password.html', form=form)

@app.route('/delete_play_record/<int:record_id>', methods=['POST'])
@login_required
@requires_role('manager')
def delete_play_record(record_id):
    record = PlayRecord.query.get_or_404(record_id)
    game_id = record.game_id
    game = Game.query.get_or_404(game_id)
    
    # Store values before deletion
    plays_to_subtract = record.plays_count
    revenue_to_subtract = record.revenue
    
    # Update game totals
    game.total_plays -= plays_to_subtract
    game.total_revenue -= revenue_to_subtract
    
    # Ensure totals don't go negative
    if game.total_plays < 0:
        game.total_plays = 0
    if game.total_revenue < 0:
        game.total_revenue = 0.0
    
    # Delete the record
    db.session.delete(record)
    db.session.commit()
    
    flash(f'Play record deleted successfully', 'success')
    return redirect(url_for('game_detail', game_id=game_id))

@app.route('/add_baseline/<int:game_id>', methods=['POST'])
@login_required
@requires_role('manager')
def add_baseline(game_id):
    game = Game.query.get_or_404(game_id)
    
    # Check if there are already play records
    existing_records = PlayRecord.query.filter_by(game_id=game_id).count()
    if existing_records > 0:
        flash('Cannot add baseline - play records already exist', 'error')
        return redirect(url_for('game_detail', game_id=game_id))
    
    # Get coin count from form
    try:
        coin_count = int(request.form.get('baseline_coin_count', 0))
        if coin_count < 0:
            flash('Baseline coin count cannot be negative', 'error')
            return redirect(url_for('game_detail', game_id=game_id))
    except ValueError:
        flash('Invalid coin count', 'error')
        return redirect(url_for('game_detail', game_id=game_id))
    
    # Create baseline record
    baseline_record = PlayRecord(
        game_id=game_id,
        coin_count=coin_count,
        plays_count=0,
        revenue=0.0,
        date_recorded=date.today(),
        notes="Baseline coin count"
    )
    
    db.session.add(baseline_record)
    db.session.commit()
    
    flash(f'Baseline set to {coin_count} coins', 'success')
    return redirect(url_for('game_detail', game_id=game_id))


@app.route('/games')
@login_required
def games_list():
    search = request.args.get('search', '')
    location_filter = request.args.get('location', '')
    status_filter = request.args.get('status', '')
    
    query = Game.query
    
    if search:
        query = query.filter(Game.name.contains(search))
    if location_filter:
        query = query.filter_by(location=location_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    # Get all games sorted alphabetically
    games = query.order_by(Game.name.asc()).all()
    
    # Separate into floor and warehouse games
    floor_games = [g for g in games if g.location == 'Floor']
    warehouse_games = [g for g in games if g.location == 'Warehouse']
    
    # Get games with open maintenance requests
    games_with_open_maintenance = set(
        row[0] for row in db.session.query(MaintenanceRecord.game_id)
        .filter(MaintenanceRecord.status.in_(['Open', 'In_Progress']))
        .distinct()
        .all()
    )
    
    # Add maintenance indicator to games
    for game in games:
        game.has_open_maintenance = game.id in games_with_open_maintenance
    
    # Get unique values for filter dropdowns
    locations = db.session.query(Game.location.distinct()).all()
    statuses = db.session.query(Game.status.distinct()).all()
    
    return render_template('games_list.html', 
                         games=games,
                         floor_games=floor_games,
                         warehouse_games=warehouse_games,
                         search=search,
                         location_filter=location_filter,
                         status_filter=status_filter,
                         locations=[l[0] for l in locations],
                         statuses=[s[0] for s in statuses])
                         
#BULK UPDATE GAMES
@app.route('/bulk_update_games', methods=['POST'])
@login_required
@requires_role('manager')
def bulk_update_games():
    """Bulk update multiple games at once"""
    action = request.form.get('action')
    game_ids = request.form.getlist('game_ids')
    
    if not game_ids:
        flash('No games selected', 'error')
        return redirect(url_for('games_list'))
    
    games = Game.query.filter(Game.id.in_(game_ids)).all()
    count = len(games)
    
    try:
        if action == 'move_to_floor':
            for game in games:
                game.location = 'Floor'
            flash(f'Moved {count} game(s) to Floor', 'success')
            
        elif action == 'move_to_warehouse':
            for game in games:
                game.location = 'Warehouse'
            flash(f'Moved {count} game(s) to Warehouse', 'success')
            
        elif action == 'set_working':
            for game in games:
                game.status = 'Working'
            flash(f'Set {count} game(s) to Working status', 'success')
            
        elif action == 'set_not_working':
            for game in games:
                game.status = 'Not_Working'
            flash(f'Set {count} game(s) to Not Working status', 'success')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating games: {str(e)}', 'error')
    
    return redirect(url_for('games_list'))

@app.route('/export_selected_games')
@login_required
@requires_role('manager')
def export_selected_games():
    """Export selected games to CSV"""
    game_ids = request.args.getlist('game_ids')
    
    if not game_ids:
        flash('No games selected', 'error')
        return redirect(url_for('games_list'))
    
    games = Game.query.filter(Game.id.in_(game_ids)).all()
    data = []
    
    for game in games:
        # Make game.date_added timezone-aware if it's naive
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue = game.total_revenue / days_active
        
        data.append({
            'Game Name': game.name,
            'Manufacturer': game.manufacturer,
            'Location': game.location,
            'Status': game.status,
            'Total Plays': game.total_plays,
            'Total Revenue': game.total_revenue,
            'Daily Revenue': round(daily_revenue, 2),
            'Days Active': days_active
        })
    
    df = pd.DataFrame(data)
    
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=selected_games_{len(games)}.csv'
    response.headers['Content-type'] = 'text/csv'
    
    return 
    

@app.route('/game/<int:game_id>')
@login_required
def game_detail(game_id):
    game = Game.query.get_or_404(game_id)
    recent_records = PlayRecord.query.filter_by(game_id=game_id).order_by(PlayRecord.date_recorded.desc()).limit(10).all()
    maintenance_records = MaintenanceRecord.query.filter_by(game_id=game_id).order_by(MaintenanceRecord.date_reported.desc()).all()
    
    # Check if there are no play records (can add baseline)
    all_records_count = PlayRecord.query.filter_by(game_id=game_id).count()
    can_add_baseline = all_records_count == 0
    
    return render_template('game_detail.html', game=game, recent_records=recent_records, 
                         maintenance_records=maintenance_records, can_add_baseline=can_add_baseline)

@app.route('/edit_game/<int:game_id>', methods=['GET', 'POST'])
@login_required
@requires_role('manager')
def edit_game(game_id):
    game = Game.query.get_or_404(game_id)
    
    # Check if game has any play records beyond baseline
    # Allow editing baseline if there's only one record with 0 plays
    all_records = PlayRecord.query.filter_by(game_id=game_id).all()
    has_play_records = len(all_records) > 1 or (len(all_records) == 1 and all_records[0].plays_count > 0)
    
    if request.method == 'POST':
        # Update game details
        game.name = request.form['name']
        game.manufacturer = request.form.get('manufacturer', '')
        year = request.form.get('year')
        game.year = int(year) if year and year.strip() else None
        game.genre = request.form.get('genre', '')
        game.location = request.form.get('location', 'Warehouse')
        game.floor_position = request.form.get('floor_position', '')
        game.warehouse_section = request.form.get('warehouse_section', '')
        game.status = request.form.get('status', 'Working')
        coins_per_play_str = request.form.get('coins_per_play', '0.25')
        if coins_per_play_str and coins_per_play_str.strip():
            game.coins_per_play = float(coins_per_play_str)
        else:
            game.coins_per_play = 0.25
        game.counter_status = request.form.get('counter_status', 'Working')
        game.counter_notes = request.form.get('counter_notes', '')
        game.notes = request.form.get('notes', '')
        
        # Handle new image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add UUID to prevent filename conflicts
                name_part, ext = os.path.splitext(filename)
                filename = f"{name_part}_{uuid.uuid4().hex[:8]}{ext}"
                
                # Ensure upload directory exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Remove old image if it exists
                if game.image_filename:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], game.image_filename)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                game.image_filename = filename
        
        # Handle initial coin count if provided and no actual play records exist
        if not has_play_records:
            initial_coin_count = request.form.get('initial_coin_count')
            if initial_coin_count and initial_coin_count.strip():
                try:
                    coin_count = int(initial_coin_count)
                    if coin_count >= 0:  # Allow 0 as a valid baseline
                        # Check if there's already a baseline record
                        existing_baseline = None
                        if len(all_records) == 1 and all_records[0].plays_count == 0:
                            existing_baseline = all_records[0]
                        
                        if existing_baseline:
                            # Update existing baseline record
                            existing_baseline.coin_count = coin_count
                            existing_baseline.date_recorded = date.today()
                            existing_baseline.notes = "Updated baseline coin count (via edit)"
                            print(f"Updated baseline play record for {game.name}: {coin_count} coins")
                        else:
                            # Create new baseline record
                            initial_record = PlayRecord(
                                game_id=game_id,
                                coin_count=coin_count,
                                plays_count=0,  # No new plays, just setting baseline
                                revenue=0.0,
                                date_recorded=date.today(),
                                notes="Initial baseline coin count (added via edit)"
                            )
                            db.session.add(initial_record)
                            print(f"Added baseline play record for {game.name}: {coin_count} coins")
                except (ValueError, TypeError):
                    pass  # Ignore invalid input
        
        db.session.commit()
        
        success_msg = f'Game "{game.name}" updated successfully!'
        if not has_play_records:
            initial_coin_count = request.form.get('initial_coin_count')
            if initial_coin_count and initial_coin_count.strip():
                try:
                    coin_count = int(initial_coin_count)
                    if coin_count >= 0:
                        action = "Updated" if (len(all_records) == 1 and all_records[0].plays_count == 0) else "Set"
                        success_msg += f' ({action} baseline: {coin_count} coins)'
                except (ValueError, TypeError):
                    pass
        
        flash(success_msg, 'success')
        return redirect(url_for('game_detail', game_id=game_id))
    
    return render_template('edit_game.html', game=game, has_play_records=has_play_records)

@app.route('/maintenance/game/<int:game_id>', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def game_maintenance(game_id):
    game = Game.query.get_or_404(game_id)
    form = MaintenanceWithInventoryForm()
    
    # Populate inventory item choices
    inventory_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    item_choices = [(-1, 'Select an item...')] + [(item.id, f"{item.name} (Stock: {item.stock_quantity})") for item in inventory_items]
    
    for inventory_form in form.inventory_items:
        inventory_form.item_id.choices = item_choices
    
    if form.validate_on_submit():
        priority = request.form.get('priority', 'Medium')
        
        maintenance_record = MaintenanceRecord(
            game_id=game_id,
            issue_description=form.issue_description.data,
            fix_description=form.fix_description.data,
            cost=form.cost.data if form.cost.data else None,
            technician=form.technician.data,
            status=form.status.data,
            priority=priority
        )
        
        if form.status.data == 'Fixed':
            maintenance_record.date_fixed = datetime.now(dt.UTC)
        
        db.session.add(maintenance_record)
        db.session.flush()  # Get the maintenance record ID
        
        # Process inventory usage
        total_inventory_cost = 0
        for inventory_form in form.inventory_items:
            item_id = inventory_form.item_id.data
            quantity = inventory_form.quantity_used.data
            
            if item_id and item_id != -1 and quantity and quantity > 0:
                item = InventoryItem.query.get(item_id)
                if item and item.stock_quantity >= quantity:
                    # Create usage record
                    usage = MaintenanceInventoryUsage(
                        maintenance_id=maintenance_record.id,
                        item_id=item_id,
                        quantity_used=quantity,
                        unit_price_at_time=item.unit_price,
                        total_cost=quantity * item.unit_price
                    )
                    db.session.add(usage)
                    
                    # Update inventory stock
                    old_quantity = item.stock_quantity
                    item.stock_quantity -= quantity
                    
                    # Create stock history record
                    stock_history = StockHistory(
                        item_id=item_id,
                        change_type='used',
                        quantity_change=-quantity,
                        previous_quantity=old_quantity,
                        new_quantity=item.stock_quantity,
                        reason=f'Used in maintenance for {game.name} (Work Order #{maintenance_record.id})',
                        user_id=current_user.id
                    )
                    db.session.add(stock_history)
                    
                    total_inventory_cost += usage.total_cost
                    
                    # Check for low stock alerts
                    _check_low_stock_alert(item)
                elif item:
                    flash(f'Insufficient stock for {item.name}. Available: {item.stock_quantity}, Requested: {quantity}', 'warning')
        
        # Update total cost if inventory was used
        if total_inventory_cost > 0:
            current_cost = maintenance_record.cost or 0
            maintenance_record.cost = current_cost + total_inventory_cost
        
        db.session.commit()
        
        flash(f'Maintenance record added for "{game.name}"', 'success')
        if total_inventory_cost > 0:
            flash(f'Inventory items used: ${total_inventory_cost:.2f}', 'info')
        return redirect(url_for('game_detail', game_id=game_id))
    
    return render_template('maintenance_with_inventory.html', form=form, game=game)

@app.route('/maintenance/general', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def general_maintenance():
    """Create a general work order not tied to a specific game"""
    form = MaintenanceWithInventoryForm()
    
    # Populate inventory item choices
    inventory_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    item_choices = [(-1, 'Select an item...')] + [(item.id, f"{item.name} (Stock: {item.stock_quantity})") for item in inventory_items]
    
    for inventory_form in form.inventory_items:
        inventory_form.item_id.choices = item_choices
    
    if form.validate_on_submit():
        # Get work order type and location from form
        work_order_type = request.form.get('work_order_type', 'general')
        location_description = request.form.get('location_description', '')
        
        priority = request.form.get('priority', 'Medium')
        
        maintenance_record = MaintenanceRecord(
            game_id=None,  # No game associated
            work_order_type=work_order_type,
            location_description=location_description,
            issue_description=form.issue_description.data,
            fix_description=form.fix_description.data,
            cost=form.cost.data if form.cost.data else None,
            technician=form.technician.data,
            status=form.status.data,
            priority=priority
        )
        
        if form.status.data == 'Fixed':
            maintenance_record.date_fixed = datetime.now(dt.UTC)
        
        db.session.add(maintenance_record)
        db.session.flush()
        
        # Process inventory usage (same as regular maintenance)
        total_inventory_cost = 0
        for inventory_form in form.inventory_items:
            item_id = inventory_form.item_id.data
            quantity = inventory_form.quantity_used.data
            
            if item_id and item_id != -1 and quantity and quantity > 0:
                item = InventoryItem.query.get(item_id)
                if item and item.stock_quantity >= quantity:
                    usage = MaintenanceInventoryUsage(
                        maintenance_id=maintenance_record.id,
                        item_id=item_id,
                        quantity_used=quantity,
                        unit_price_at_time=item.unit_price,
                        total_cost=quantity * item.unit_price
                    )
                    db.session.add(usage)
                    
                    old_quantity = item.stock_quantity
                    item.stock_quantity -= quantity
                    
                    stock_history = StockHistory(
                        item_id=item_id,
                        change_type='used',
                        quantity_change=-quantity,
                        previous_quantity=old_quantity,
                        new_quantity=item.stock_quantity,
                        reason=f'Used in {work_order_type} maintenance (Work Order #{maintenance_record.id})',
                        user_id=current_user.id
                    )
                    db.session.add(stock_history)
                    
                    total_inventory_cost += usage.total_cost
                    _check_low_stock_alert(item)
        
        if total_inventory_cost > 0:
            current_cost = maintenance_record.cost or 0
            maintenance_record.cost = current_cost + total_inventory_cost
        
        db.session.commit()
        
        flash(f'General work order created successfully!', 'success')
        return redirect(url_for('maintenance_orders'))
    
    return render_template('general_maintenance.html', form=form)

@app.route('/maintenance_orders')
@login_required
def maintenance_orders():
    """List all maintenance records"""
    search = request.args.get('search', '')
    query = MaintenanceRecord.query
    if search:
        query = query.filter(
            (MaintenanceRecord.issue_description.ilike(f"%{search}%")) |
            (MaintenanceRecord.technician.ilike(f"%{search}%")) |
            (MaintenanceRecord.work_order_type.ilike(f"%{search}%"))
        )
    # Sort by game name (nulls last for general maintenance), then by date
    all_records = query.outerjoin(Game).order_by(Game.name.asc().nullslast(), MaintenanceRecord.date_reported.desc()).all()
    return render_template('maintenance_orders.html', all_records=all_records, search=search)


# ==============================
# 🧩 Maintenance Routes Section
# ==============================

@app.route('/maintenance_detail/<int:record_id>')
@login_required
def maintenance_detail(record_id):
    """Detailed view of a maintenance record"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    return render_template('maintenance_detail.html', record=record)


@app.route('/update_maintenance/<int:record_id>', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def update_maintenance(record_id):
    """Detailed update page for maintenance records"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    
    if request.method == 'POST':
        # Update main record fields
        record.status = request.form.get('status', record.status)
        record.priority = request.form.get('priority', record.priority)
        record.fix_description = request.form.get('fix_description', record.fix_description)
        record.technician = request.form.get('technician', record.technician)
        
        # Update total cost if provided
        cost = request.form.get('cost')
        if cost:
            try:
                record.cost = float(cost)
            except ValueError:
                pass
        
        if record.status == 'Fixed':
            record.date_fixed = datetime.now(dt.UTC)
        
        # Create work log entry
        work_notes = request.form.get('work_notes', '').strip()
        if work_notes:
            work_log = WorkLog(
                maintenance_id=record.id,
                user_id=current_user.id,
                work_description=work_notes,
                parts_used=request.form.get('parts_used', ''),
                time_spent=float(request.form.get('time_spent')) if request.form.get('time_spent') else None,
                cost_incurred=float(request.form.get('work_cost')) if request.form.get('work_cost') else None
            )
            db.session.add(work_log)
        
        # Process inventory usage
        inventory_items = request.form.getlist('inventory_item_id')
        inventory_quantities = request.form.getlist('inventory_quantity')
        
        total_inventory_cost = 0
        for item_id_str, quantity_str in zip(inventory_items, inventory_quantities):
            if item_id_str and quantity_str:
                try:
                    item_id = int(item_id_str)
                    quantity = int(quantity_str)
                    
                    if item_id > 0 and quantity > 0:
                        item = InventoryItem.query.get(item_id)
                        if item and item.stock_quantity >= quantity:
                            # Create usage record
                            usage = MaintenanceInventoryUsage(
                                maintenance_id=record.id,
                                item_id=item_id,
                                quantity_used=quantity,
                                unit_price_at_time=item.unit_price,
                                total_cost=quantity * item.unit_price
                            )
                            db.session.add(usage)
                            
                            # Update inventory
                            old_quantity = item.stock_quantity
                            item.stock_quantity -= quantity
                            
                            # Create stock history
                            stock_history = StockHistory(
                                item_id=item_id,
                                change_type='used',
                                quantity_change=-quantity,
                                previous_quantity=old_quantity,
                                new_quantity=item.stock_quantity,
                                reason=f'Used in Work Order #{record.id}',
                                user_id=current_user.id
                            )
                            db.session.add(stock_history)
                            
                            total_inventory_cost += usage.total_cost
                            _check_low_stock_alert(item)
                        elif item:
                            flash(f'Insufficient stock for {item.name}. Available: {item.stock_quantity}, Requested: {quantity}', 'warning')
                except (ValueError, TypeError):
                    continue
        
        # Update total cost with inventory costs
        if total_inventory_cost > 0:
            if record.cost:
                record.cost += total_inventory_cost
            else:
                record.cost = total_inventory_cost
        
        db.session.commit()
        
        if total_inventory_cost > 0:
            flash(f"Work log added. Inventory used: ${total_inventory_cost:.2f}", "success")
        else:
            flash(f"Maintenance record #{record.id} updated.", "success")
        return redirect(url_for('maintenance_orders'))
    
    # GET request - load inventory items
    inventory_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    return render_template('update_maintenance.html', record=record, inventory_items=inventory_items)


@app.route('/close_maintenance/<int:record_id>', methods=['POST'])
@login_required
@requires_role('operator')
def close_maintenance(record_id):
    """Mark maintenance record as closed"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    record.status = 'Fixed'
    record.date_fixed = datetime.now(dt.UTC)
    db.session.commit()
    flash(f"Order #{record.id} marked as closed.", "success")
    return redirect(url_for('maintenance_orders'))


@app.route('/delete_maintenance/<int:record_id>', methods=['POST'])
@login_required
@requires_role('manager')
def delete_maintenance(record_id):
    """Delete a maintenance record"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    flash(f"Maintenance record #{record.id} deleted.", "warning")
    return redirect(url_for('maintenance_orders'))

@app.route('/download_maintenance_record/<int:record_id>')
@login_required
def download_maintenance_record(record_id):
    """Generate and download PDF of maintenance record"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_text = f"Work Order #{record.id}"
    if record.game:
        title_text += f" - {record.game.name}"
    else:
        title_text += " - General Maintenance"
    title = Paragraph(title_text, styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Basic Info Table
    info_data = [
        ['Status:', record.status or 'Open'],
        ['Reported:', record.date_reported.strftime('%Y-%m-%d %H:%M') if record.date_reported else 'Unknown'],
    ]
    if record.date_fixed:
        info_data.append(['Fixed:', record.date_fixed.strftime('%Y-%m-%d %H:%M')])
    if record.technician:
        info_data.append(['Technician:', record.technician])
    if record.cost:
        info_data.append(['Total Cost:', f'${record.cost:.2f}'])
    
    info_table = Table(info_data, colWidths=[1.5*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(info_table)
    story.append(Spacer(1, 20))
    
    # Original Issue
    story.append(Paragraph("<b>Original Issue:</b>", styles['Heading2']))
    story.append(Paragraph(record.issue_description or 'No description', styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Initial Assessment
    if record.fix_description:
        story.append(Paragraph("<b>Initial Assessment:</b>", styles['Heading2']))
        story.append(Paragraph(record.fix_description, styles['Normal']))
        story.append(Spacer(1, 12))
    
    # Work Log History
    if record.work_logs:
        story.append(Paragraph("<b>Work Log History:</b>", styles['Heading2']))
        story.append(Spacer(1, 6))
        
        for log in record.work_logs:
            log_header = f"{log.timestamp.strftime('%Y-%m-%d %H:%M')} - {log.user.username}"
            if log.time_spent:
                log_header += f" ({log.time_spent}h)"
            if log.cost_incurred:
                log_header += f" (${log.cost_incurred:.2f})"
            
            story.append(Paragraph(f"<b>{log_header}</b>", styles['Normal']))
            story.append(Paragraph(log.work_description, styles['Normal']))
            if log.parts_used:
                story.append(Paragraph(f"<i>Parts: {log.parts_used}</i>", styles['Normal']))
            story.append(Spacer(1, 8))
        
        story.append(Spacer(1, 12))
    
    # Inventory Usage
    if record.inventory_usage:
        story.append(Paragraph("<b>Inventory Used:</b>", styles['Heading2']))
        story.append(Spacer(1, 6))
        
        inv_data = [['Item', 'Quantity', 'Cost']]
        for usage in record.inventory_usage:
            inv_data.append([
                usage.item.name,
                str(usage.quantity_used),
                f'${usage.total_cost:.2f}'
            ])
        
        inv_table = Table(inv_data, colWidths=[3*inch, 1*inch, 1*inch])
        inv_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (2, 0), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(inv_table)
        story.append(Spacer(1, 12))
    
    # Photos note
    photos = record.get_photos()
    if photos:
        story.append(Paragraph(f"<b>Photos:</b> {len(photos)} photo(s) attached (not included in PDF)", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    filename = f"work_order_{record.id}"
    if record.game:
        filename += f"_{record.game.name.replace(' ', '_')}"
    filename += ".pdf"
    
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')


@app.route('/maintenance_photos/<int:maintenance_id>', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def maintenance_photos(maintenance_id):
    """Upload photos for a maintenance record"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)
    form = MaintenancePhotoForm()
    
    if request.method == 'POST':
        print(f"DEBUG: POST request received")
        print(f"DEBUG: Form data: {dict(request.form)}")
        print(f"DEBUG: Files: {dict(request.files)}")
        print(f"DEBUG: CSRF token present: {'csrf_token' in request.form}")
        
        # Check CSRF token manually if form validation fails
        csrf_token = request.form.get('csrf_token')
        if not csrf_token:
            flash('Security token missing. Please try again.', 'error')
            return redirect(url_for('maintenance_photos', maintenance_id=maintenance_id))
        
        print(f"DEBUG: Form validation result: {form.validate_on_submit()}")
        print(f"DEBUG: Form errors: {form.errors}")
        
        # Get files from request (more reliable than form.photos.data)
        uploaded_files = request.files.getlist('photos')
        print(f"DEBUG: Raw uploaded files: {[f.filename if f and hasattr(f, 'filename') else 'No filename' for f in uploaded_files]}")
        print(f"DEBUG: File details: {[(f.filename, f.content_length if hasattr(f, 'content_length') else 'No size', f.content_type if hasattr(f, 'content_type') else 'No type') for f in uploaded_files if f]}")
        
        # Check if files have actual content
        for i, f in enumerate(uploaded_files):
            if f:
                print(f"DEBUG: File {i}: filename='{f.filename}', type='{f.content_type}', has_data={bool(f.filename and f.filename.strip())}")
        
        # If no files from 'photos' field, try the form field name
        if not uploaded_files or not any(f and f.filename and f.filename.strip() for f in uploaded_files):
            uploaded_files = request.files.getlist(form.photos.name)
            print(f"DEBUG: Files from form field name: {[f.filename if f and hasattr(f, 'filename') else 'No filename' for f in uploaded_files]}")
            
        # Also try other possible field names
        if not uploaded_files or not any(f and f.filename and f.filename.strip() for f in uploaded_files):
            all_file_fields = [key for key in request.files.keys()]
            print(f"DEBUG: All file field names in request: {all_file_fields}")
            for field_name in all_file_fields:
                files = request.files.getlist(field_name)
                print(f"DEBUG: Files in '{field_name}': {[f.filename if f and hasattr(f, 'filename') else 'No filename' for f in files]}")
        
        uploaded_count = 0
        
        # Filter out empty files and validate
        valid_files = []
        for file in uploaded_files:
            if file and hasattr(file, 'filename') and file.filename and file.filename.strip() != '':
                print(f"DEBUG: Processing file: {file.filename}")
                if allowed_file(file.filename):
                    valid_files.append(file)
                    print(f"DEBUG: File {file.filename} is valid")
                else:
                    flash(f'File {file.filename} has an invalid file type. Allowed: PNG, JPG, JPEG, GIF', 'warning')
        
        print(f"DEBUG: Valid files count: {len(valid_files)}")
        
        # Check if we have any valid files to process
        if not valid_files:
            flash('No valid image files were selected for upload. Please select image files (PNG, JPG, JPEG, GIF).', 'warning')
            return redirect(url_for('maintenance_photos', maintenance_id=maintenance_id))
        
        # Check current photo count for this record
        current_photos = maintenance.get_photos()
        if len(current_photos) >= MAX_PHOTOS_PER_RECORD:
            flash(f'Maximum {MAX_PHOTOS_PER_RECORD} photos allowed per maintenance record.', 'error')
            return redirect(url_for('maintenance_photos', maintenance_id=maintenance_id))
        
        # Check total storage usage
        upload_dir = os.path.join(app.root_path, 'static', 'maintenance_photos')
        current_size_mb = get_directory_size(upload_dir)
        if current_size_mb > MAX_TOTAL_STORAGE_MB:
            flash(f'Storage limit ({MAX_TOTAL_STORAGE_MB}MB) reached. Please contact administrator.', 'error')
            return redirect(url_for('maintenance_photos', maintenance_id=maintenance_id))
        
        for file in valid_files:
            # Check if we've hit the per-record limit
            if len(maintenance.get_photos()) >= MAX_PHOTOS_PER_RECORD:
                break
            
            filename = secure_filename(file.filename)
            # Add UUID to prevent filename conflicts
            name_part, ext = os.path.splitext(filename)
            unique_filename = f"maintenance_{maintenance_id}_{uuid.uuid4().hex[:8]}{ext}"
            
            # Ensure upload directory exists
            upload_dir = os.path.join(app.root_path, 'static', 'maintenance_photos')
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, unique_filename)
            
            try:
                # Compress and save the file locally
                compress_and_save_image(file, file_path)
                
                # Upload to cloud if enabled
                cloud_url = None
                if USE_CLOUD_STORAGE:
                    with open(file_path, 'rb') as compressed_file:
                        cloud_url = upload_to_cloud(compressed_file.read(), unique_filename)
                
                # Add to maintenance record
                maintenance.add_photo(unique_filename)
                uploaded_count += 1
                
                if cloud_url:
                    print(f"Photo uploaded to cloud: {cloud_url}")
                
            except Exception as e:
                flash(f'Error uploading {filename}: {str(e)}', 'error')
                # Clean up partial file if it exists
                if os.path.exists(file_path):
                    os.remove(file_path)
        
        if uploaded_count > 0:
            db.session.commit()
            flash(f'Successfully uploaded {uploaded_count} photo(s) for maintenance record.', 'success')
        
        return redirect(url_for('view_maintenance', maintenance_id=maintenance_id))
    
    return render_template('maintenance_photos.html', maintenance=maintenance, form=form)

@app.route('/delete_maintenance_photo/<int:maintenance_id>/<filename>', methods=['POST'])
@login_required
@requires_role('manager')
def delete_maintenance_photo(maintenance_id, filename):
    """Delete a photo from a maintenance record"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)
    
    # Remove from database
    maintenance.remove_photo(filename)
    db.session.commit()
    
    # Remove file from filesystem
    file_path = os.path.join(app.root_path, 'static', 'maintenance_photos', filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            flash('Photo deleted successfully.', 'success')
        except Exception as e:
            flash(f'Photo removed from record but file deletion failed: {str(e)}', 'warning')
    else:
        flash('Photo removed from record.', 'success')
    
    return redirect(url_for('view_maintenance', maintenance_id=maintenance_id))


@app.route('/admin/cleanup_photos', methods=['POST'])
@login_required
@requires_role('manager')
def admin_cleanup_photos():
    """Admin function to clean up old/orphaned photos"""
    try:
        removed_count = cleanup_old_photos(max_age_days=365)
        upload_dir = os.path.join(app.root_path, 'static', 'maintenance_photos')
        current_size_mb = get_directory_size(upload_dir)
        
        flash(f'Cleanup complete: {removed_count} photos removed. Current storage: {current_size_mb:.1f}MB', 'success')
    except Exception as e:
        flash(f'Cleanup failed: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('home'))

@app.route('/admin/storage')
@login_required
@requires_role('admin')
def storage_admin():
    """Storage management dashboard"""
    upload_dir = os.path.join(app.root_path, 'static', 'maintenance_photos')
    
    # Get storage stats
    current_size_mb = get_directory_size(upload_dir)
    file_count = len(os.listdir(upload_dir)) if os.path.exists(upload_dir) else 0
    
    # Get record stats
    total_records = MaintenanceRecord.query.count()
    records_with_photos = MaintenanceRecord.query.filter(MaintenanceRecord.photos.isnot(None)).count()
    
    stats = {
        'current_size_mb': current_size_mb,
        'max_size_mb': MAX_TOTAL_STORAGE_MB,
        'usage_percent': (current_size_mb / MAX_TOTAL_STORAGE_MB) * 100,
        'file_count': file_count,
        'total_records': total_records,
        'records_with_photos': records_with_photos
    }
    
    return render_template('storage_admin.html', stats=stats)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@requires_role('admin')
def manage_users():
    """Admin user management dashboard"""
    users = User.query.order_by(User.username.asc()).all()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        user = User.query.get_or_404(user_id)

        if action == 'toggle_active':
            user.is_active = not user.is_active
            db.session.commit()
            flash(f'User {user.username} has been {"activated" if user.is_active else "deactivated"}.', 'info')

        elif action == 'reset_password':
            new_password = 'Arcade123!'
            user.set_password(new_password)
            user.must_change_password = True
            db.session.commit()
            flash(f'Password for {user.username} reset to "{new_password}" (user must change on next login).', 'warning')

        elif action == 'change_role':
            new_role = request.form.get('new_role')
            if new_role in ['readonly', 'operator', 'manager', 'admin']:
                user.role = new_role
                db.session.commit()
                flash(f'{user.username} role changed to {new_role}.', 'success')
            else:
                flash('Invalid role selected.', 'error')

        elif action == 'delete_user':
            if user.id == current_user.id:
                flash('You cannot delete your own account.', 'error')
            else:
                db.session.delete(user)
                db.session.commit()
                flash(f'User {user.username} deleted.', 'warning')

        return redirect(url_for('manage_users'))

    return render_template('manage_users.html', users=users)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@requires_role('admin')
def create_user():
    """Create a new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        role = request.form.get('role', 'readonly')
        
        # Validate inputs
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('create_user.html')
        
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('create_user.html')
        
        # Check if username already exists
        existing_user = User.query.filter(User.username.ilike(username)).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return render_template('create_user.html')
        
        if role not in ['readonly', 'operator', 'manager', 'admin']:
            flash('Invalid role selected.', 'error')
            return render_template('create_user.html')
        
        # Create new user
        new_user = User(
            username=username,
            role=role,
            is_active=True,
            must_change_password=True  # Force password change on first login
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        log_security_event(
            'USER_CREATED',
            user_id=current_user.id,
            details=f"Created user: {username} with role: {role}"
        )
        
        flash(f'User "{username}" created successfully! They will be prompted to change their password on first login.', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('create_user.html')

    """Quick close a maintenance order"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)
    
    # Update the maintenance record
    maintenance.status = request.form.get('status', 'Fixed')
    maintenance.fix_description = request.form.get('fix_description', '')
    maintenance.cost = float(request.form.get('cost', 0)) if request.form.get('cost') else None
    maintenance.technician = request.form.get('technician', '')
    maintenance.date_fixed = datetime.now(dt.UTC)
    
    db.session.commit()
    
    flash(f'Maintenance order for "{maintenance.game.name}" marked as {maintenance.status}!', 'success')
    return redirect(url_for('maintenance_orders'))

@app.route('/revenue_reports')
@login_required
@requires_role('manager')
def revenue_reports():
    """Generate revenue reports with time frame filters"""
    from datetime import timedelta
    
    # Get date range from query params with error handling
    try:
        days = request.args.get('days', 30, type=int)  # Default 30 days
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30
    
    location_filter = request.args.get('location', '')
    start_date = date.today() - timedelta(days=days)
    
    # Base query for play records in date range - only floor games with working counters
    query = PlayRecord.query.join(Game).filter(
        PlayRecord.date_recorded >= start_date,
        Game.location == 'Floor',
        Game.counter_status == 'Working'
    )
    
    # Apply additional location filter if specified (though floor is already filtered)
    if location_filter and location_filter != 'Floor':
        query = query.filter(Game.location == location_filter)
    
    all_records = query.order_by(PlayRecord.date_recorded.desc()).all()
    
    # Get games with revenue in the period - only floor games with working counters
    games_query = Game.query.join(PlayRecord).filter(
        PlayRecord.date_recorded >= start_date,
        Game.location == 'Floor',
        Game.counter_status == 'Working'
    )
    if location_filter and location_filter != 'Floor':
        games_query = games_query.filter(Game.location == location_filter)
    
    revenue_games = games_query.distinct().all()
    
    # Calculate statistics
    total_revenue = sum(r.revenue for r in all_records)
    total_plays = sum(r.plays_count for r in all_records)
    avg_daily_revenue = total_revenue / days if days > 0 else 0
    
    # Top performing games in period
    game_revenues = {}
    for record in all_records:
        if record.game.id not in game_revenues:
            game_revenues[record.game.id] = {
                'game': record.game,
                'revenue': 0,
                'plays': 0
            }
        game_revenues[record.game.id]['revenue'] += record.revenue
        game_revenues[record.game.id]['plays'] += record.plays_count
    
    top_games = sorted(game_revenues.values(), key=lambda x: x['revenue'], reverse=True)[:10]
    
    # Daily revenue breakdown
    daily_revenue = {}
    for record in all_records:
        day_str = record.date_recorded.strftime('%Y-%m-%d')
        if day_str not in daily_revenue:
            daily_revenue[day_str] = 0
        daily_revenue[day_str] += record.revenue
    
    # Get unique locations for filter dropdown
    locations = db.session.query(Game.location.distinct()).all()
    
    return render_template('revenue_reports.html',
                         all_records=all_records,
                         revenue_games=revenue_games,
                         top_games=top_games,
                         days_filter=days,
                         location_filter=location_filter,
                         start_date=start_date,
                         total_revenue=total_revenue,
                         total_plays=total_plays,
                         avg_daily_revenue=avg_daily_revenue,
                         daily_revenue=daily_revenue,
                         locations=[l[0] for l in locations])

@app.route('/maintenance_reports')
@login_required
@requires_role('manager')
def maintenance_reports():
    """Generate maintenance reports with time frame filters"""
    from datetime import timedelta
    
    # Get date range from query params with error handling
    try:
        days = request.args.get('days', 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30
    
    start_date = date.today() - timedelta(days=days)
    
    # Get all maintenance records in date range - USE OUTERJOIN
    all_records = MaintenanceRecord.query.outerjoin(Game).filter(
        MaintenanceRecord.date_reported >= start_date
    ).order_by(MaintenanceRecord.date_reported.desc()).all()
    
    # Separate by status
    open_records = [r for r in all_records if r.status in ['Open', 'In_Progress']]
    closed_records = [r for r in all_records if r.status in ['Fixed', 'Deferred']]
    
    # Calculate statistics
    total_cost = sum(r.cost or 0 for r in closed_records)
    avg_resolution_days = 0
    if closed_records:
        resolution_times = []
        for r in closed_records:
            if r.date_fixed and r.date_reported:
                days_to_fix = (r.date_fixed.date() - r.date_reported.date()).days
                resolution_times.append(max(1, days_to_fix))
        if resolution_times:
            avg_resolution_days = sum(resolution_times) / len(resolution_times)
    
    return render_template('maintenance_reports.html', 
                         all_records=all_records,
                         open_records=open_records,
                         closed_records=closed_records,
                         days_filter=days,
                         start_date=start_date,
                         total_cost=total_cost,
                         avg_resolution_days=avg_resolution_days)

@app.route('/export_maintenance_report')
@login_required
@requires_role('manager')
def export_maintenance_report():
    """Export maintenance report as PDF"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from datetime import timedelta
    from collections import Counter
    import tempfile
    from reportlab.platypus import Image
    from reportlab.lib import colors
    
    # Get parameters with error handling
    report_type = request.args.get('type', 'all')
    try:
        days = request.args.get('days', 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30
    
    start_date = date.today() - timedelta(days=days)
    
    # Get records based on type - USE OUTERJOIN
@app.route('/export_revenue_report')
@login_required
@requires_role('manager')
def export_revenue_report():
    """Export revenue report as PDF"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from datetime import timedelta
    from collections import Counter
    import tempfile
    from reportlab.platypus import Image
    from reportlab.lib import colors
    
    # Get parameters with error handling
    try:
        days = request.args.get('days', 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30
    
    location_filter = request.args.get('location', '')
    start_date = date.today() - timedelta(days=days)
    
    # Get records based on filters - only floor games with working counters
    query = PlayRecord.query.join(Game).filter(
        PlayRecord.date_recorded >= start_date,
        Game.location == 'Floor',
        Game.counter_status == 'Working'
    )
    
    if location_filter and location_filter != 'Floor':
        query = query.filter(Game.location == location_filter)
        title = f"Revenue Report - {location_filter} (Last {days} Days)"
    else:
        title = f"Revenue Report - Floor Games with Working Counters (Last {days} Days)"
    
    records = query.order_by(PlayRecord.date_recorded.desc()).all()
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 12))
    
    # Summary stats
    total_records = len(records)
    total_revenue = sum(r.revenue for r in records)
    total_plays = sum(r.plays_count for r in records)
    avg_daily_revenue = total_revenue / days if days > 0 else 0
    
    summary_data = [
        ['Metric', 'Value'],
        ['Total Records', str(total_records)],
        ['Total Revenue', f'${total_revenue:.2f}'],
        ['Total Plays', str(total_plays)],
        ['Avg Daily Revenue', f'${avg_daily_revenue:.2f}']
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Top games table
    if records:
        story.append(Paragraph("Top Performing Games", styles['Heading2']))
        
        # Calculate game performance
        game_revenues = {}
        for record in records:
            if record.game.id not in game_revenues:
                game_revenues[record.game.id] = {
                    'game': record.game,
                    'revenue': 0,
                    'plays': 0
                }
            game_revenues[record.game.id]['revenue'] += record.revenue
            game_revenues[record.game.id]['plays'] += record.plays_count
        
        top_games = sorted(game_revenues.values(), key=lambda x: x['revenue'], reverse=True)[:10]
        
        revenue_data = [['Game', 'Revenue', 'Plays', 'Avg per Play']]
        
        for game_data in top_games:
            avg_per_play = game_data['revenue'] / game_data['plays'] if game_data['plays'] > 0 else 0
            revenue_data.append([
                game_data['game'].name[:20] + ('...' if len(game_data['game'].name) > 20 else ''),
                f"${game_data['revenue']:.2f}",
                str(game_data['plays']),
                f"${avg_per_play:.2f}"
            ])
        
        revenue_table = Table(revenue_data, colWidths=[150, 80, 60, 80])
        revenue_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(revenue_table)
    
    doc.build(story)
    buffer.seek(0)
    
    filename = f'revenue_report_{days}days.pdf'
    if location_filter:
        filename = f'revenue_report_{location_filter}_{days}days.pdf'
    
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')

@app.route('/reports')
@login_required
@requires_role('manager')
def reports():
    from datetime import timedelta
    thirty_days_ago = date.today() - timedelta(days=30)
    recent_records = PlayRecord.query.filter(PlayRecord.date_recorded >= thirty_days_ago).all()
    
    # Calculate daily revenue
    daily_revenue = {}
    for record in recent_records:
        day = record.date_recorded.strftime('%Y-%m-%d')  # Convert date to string for JSON serialization
        if day not in daily_revenue:
            daily_revenue[day] = 0
        daily_revenue[day] += record.revenue
    
    # Top and worst performers - only floor games with working counters
    floor_games = Game.query.filter_by(location='Floor', counter_status='Working').all()
    performers = []
    for game in floor_games:
        # Make game.date_added timezone-aware if it's naive
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue_avg = game.total_revenue / days_active
        performers.append({
            'game': {
                'id': game.id,
                'name': game.name,
                'times_in_top_5': game.times_in_top_5,
                'times_in_top_10': game.times_in_top_10
            },
            'daily_revenue': daily_revenue_avg,
            'total_revenue': game.total_revenue
        })
    
    # Sort for top and worst
    top_performers = sorted(performers, key=lambda x: x['daily_revenue'], reverse=True)[:10]
    worst_performers = sorted(performers, key=lambda x: x['daily_revenue'])[:10]
    
    # Update top 5 and top 10 counters
    _update_top_rankings()
    
    return render_template('reports.html', 
                         daily_revenue=daily_revenue,
                         top_performers=top_performers,
                         worst_performers=worst_performers,
                         floor_games_count=len(floor_games))

def _update_top_rankings():
    """Update the times_in_top_5 and times_in_top_10 counters - only floor games with working counters"""
    games = Game.query.filter_by(location='Floor', counter_status='Working').all()
    revenue_ranking = []
    
    for game in games:
        # Make game.date_added timezone-aware if it's naive
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue = game.total_revenue / days_active
        revenue_ranking.append((game, daily_revenue))
    
    revenue_ranking.sort(key=lambda x: x[1], reverse=True)
    
    # Update counters
    for i, (game, _) in enumerate(revenue_ranking):
        if i < 5:  # Top 5
            game.times_in_top_5 += 1
        if i < 10:  # Top 10
            game.times_in_top_10 += 1
    
    db.session.commit()

@app.route('/graphs')
@login_required
@requires_role('manager')
def graphs():
    """Dedicated graphs page with all visual analytics"""
    from datetime import timedelta
    from collections import Counter
    
    # Get basic stats - only count floor games with working counters for performance metrics
    all_games = Game.query.all()
    floor_games = Game.query.filter_by(location='Floor', counter_status='Working').all()
    total_games = len(all_games)
    total_plays = sum(game.total_plays for game in floor_games)  # Only floor games with working counters
    total_revenue = sum(game.total_revenue for game in floor_games)  # Only floor games with working counters
    floor_games_count = len(floor_games)
    
    # Daily revenue for last 30 days - only from floor games with working counters
    thirty_days_ago = date.today() - timedelta(days=30)
    recent_records = PlayRecord.query.join(Game).filter(
        PlayRecord.date_recorded >= thirty_days_ago,
        Game.location == 'Floor',
        Game.counter_status == 'Working'
    ).all()
    daily_revenue = {}
    for record in recent_records:
        day = record.date_recorded
        if day not in daily_revenue:
            daily_revenue[day] = 0
        daily_revenue[day] += record.revenue
    
    # Top performers
    performers = []
    for game in floor_games:
        try:
            # Make game.date_added timezone-aware if it's naive
            date_added = game.date_added
            if date_added.tzinfo is None:
                date_added = date_added.replace(tzinfo=dt.UTC)
            days_active = (datetime.now(dt.UTC) - date_added).days or 1
            daily_revenue_avg = game.total_revenue / days_active if game.total_revenue else 0
            performers.append({
                'game': game,
                'daily_revenue': daily_revenue_avg,
                'total_revenue': game.total_revenue or 0
            })
        except Exception as e:
            # Skip games with data issues
            continue
    
    top_performers = sorted(performers, key=lambda x: x['daily_revenue'], reverse=True)
    print(f"Generated {len(top_performers)} performers for graphs")
    
    # Status distribution
    status_distribution = Counter(game.status for game in all_games)
    
    # Location distribution  
    location_distribution = Counter(game.location for game in all_games)
    
    return render_template('graphs.html',
                         total_games=total_games,
                         total_plays=total_plays,
                         total_revenue=total_revenue,
                         floor_games=floor_games,
                         all_games=all_games,
                         daily_revenue=daily_revenue,
                         top_performers=top_performers,
                         status_distribution=status_distribution,
                         location_distribution=location_distribution)

@app.route('/export_report_debug')
@login_required
@requires_role('manager')
def export_report_debug():
    """Simplified PDF report for debugging"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph("Simple Arcade Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Summary stats
    total_games = Game.query.count()
    floor_games = Game.query.filter_by(location='Floor').count()
    total_revenue = sum(game.total_revenue for game in Game.query.all())
    
    summary_data = [
        ['Metric', 'Value'],
        ['Total Games', str(total_games)],
        ['Games on Floor', str(floor_games)],
        ['Total Revenue', f'${total_revenue:.2f}']
    ]
    
    summary_table = Table(summary_data)
    story.append(summary_table)
    
    doc.build(story)
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, download_name='simple_report.pdf', mimetype='application/pdf')

@app.route('/export_report')
@login_required
@requires_role('manager')
def export_report():
    """Generate PDF report for management"""
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    from datetime import timedelta
    from collections import Counter
    import tempfile
    from reportlab.platypus import Image
    from reportlab.lib import colors  # Re-import colors for local scope
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph("Arcade Performance Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Summary stats
    total_games = Game.query.count()
    floor_games = Game.query.filter_by(location='Floor').count()
    total_revenue = sum(game.total_revenue for game in Game.query.all())
    
    summary_data = [
        ['Metric', 'Value'],
        ['Total Games', str(total_games)],
        ['Games on Floor', str(floor_games)],
        ['Total Revenue', f'${total_revenue:.2f}']
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 12))
    
    # Worst performers table - only floor games with working counters
    story.append(Paragraph("Worst Performing Games (Recommended for Replacement)", styles['Heading2']))
    
    floor_games = Game.query.filter_by(location='Floor', counter_status='Working').all()
    worst_data = [['Game Name', 'Daily Revenue', 'Total Revenue', 'Days Active']]
    
    performers = []
    for game in floor_games:
        # Make game.date_added timezone-aware if it's naive
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue = game.total_revenue / days_active
        performers.append((game, daily_revenue, days_active))
    
    performers.sort(key=lambda x: x[1])  # Sort by daily revenue ascending
    
    for game, daily_rev, days in performers[:5]:  # Bottom 5
        worst_data.append([
            game.name,
            f'${daily_rev:.2f}',
            f'${game.total_revenue:.2f}',
            str(days)
        ])
    
    worst_table = Table(worst_data)
    worst_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.red),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(worst_table)
    story.append(Spacer(1, 20))
    
    # Add charts section
    story.append(Paragraph("Performance Charts", styles['Heading1']))
    story.append(Spacer(1, 12))
    
    # Create temporary directory for chart images
    temp_dir = tempfile.mkdtemp()
    
    # Add charts with individual try/catch blocks
    charts_added = 0
    
    # Chart 1: Daily Revenue Trend (Last 30 Days)
    try:
        print("Generating daily revenue chart...")
        thirty_days_ago = date.today() - timedelta(days=30)
        recent_records = PlayRecord.query.join(Game).filter(
            PlayRecord.date_recorded >= thirty_days_ago,
            Game.location == 'Floor',
            Game.counter_status == 'Working'
        ).all()
        daily_revenue = {}
        for record in recent_records:
            day = record.date_recorded
            if day not in daily_revenue:
                daily_revenue[day] = 0
            daily_revenue[day] += record.revenue
        
        if daily_revenue:
            plt.figure(figsize=(10, 6))
            sorted_dates = sorted(daily_revenue.keys())
            revenues = [daily_revenue[d] for d in sorted_dates]
            
            plt.plot(sorted_dates, revenues, marker='o', linewidth=2, markersize=4)
            plt.title('Daily Revenue Trend (Last 30 Days)', fontsize=14, fontweight='bold')
            plt.xlabel('Date')
            plt.ylabel('Revenue ($)')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            revenue_chart_path = os.path.join(temp_dir, 'revenue_trend.png')
            plt.savefig(revenue_chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            story.append(Paragraph("Daily Revenue Trend", styles['Heading2']))
            story.append(Image(revenue_chart_path, width=6*inch, height=3.6*inch))
            story.append(Spacer(1, 12))
            charts_added += 1
            print("✅ Daily revenue chart added")
    except Exception as e:
        print(f"❌ Error creating daily revenue chart: {e}")
        story.append(Paragraph(f"Daily Revenue Chart: Error - {str(e)}", styles['Normal']))
    
    # Chart 2: Top 10 Games by Total Revenue
    try:
        print("Generating top games chart...")
        top_performers = sorted(performers, key=lambda x: x[1], reverse=True)[:10]
        if top_performers:
            plt.figure(figsize=(10, 6))
            game_names = [p[0].name[:15] + ('...' if len(p[0].name) > 15 else '') for p in top_performers]
            revenues = [p[0].total_revenue for p in top_performers]
            
            bars = plt.bar(range(len(game_names)), revenues, color='skyblue', edgecolor='navy')
            plt.title('Top 10 Games by Total Revenue', fontsize=14, fontweight='bold')
            plt.xlabel('Games')
            plt.ylabel('Total Revenue ($)')
            plt.xticks(range(len(game_names)), game_names, rotation=45, ha='right')
            
            # Add value labels on bars
            for bar, revenue in zip(bars, revenues):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(revenues)*0.01,
                        f'${revenue:.0f}', ha='center', va='bottom', fontsize=8)
            
            plt.tight_layout()
            
            top_games_chart_path = os.path.join(temp_dir, 'top_games.png')
            plt.savefig(top_games_chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            story.append(Paragraph("Top Performing Games", styles['Heading2']))
            story.append(Image(top_games_chart_path, width=6*inch, height=3.6*inch))
            story.append(Spacer(1, 12))
            charts_added += 1
            print("✅ Top games chart added")
    except Exception as e:
        print(f"❌ Error creating top games chart: {e}")
        story.append(Paragraph(f"Top Games Chart: Error - {str(e)}", styles['Normal']))
    
    # Chart 3: Game Status Distribution
    try:
        print("Generating status distribution chart...")
        all_games = Game.query.all()
        status_distribution = Counter(game.status for game in all_games)
        
        if status_distribution:
            plt.figure(figsize=(8, 8))
            labels = list(status_distribution.keys())
            sizes = list(status_distribution.values())
            pie_colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
            
            wedges, texts, autotexts = plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=pie_colors,
                                             startangle=90, textprops={'fontsize': 10})
            plt.title('Game Status Distribution', fontsize=14, fontweight='bold')
            plt.axis('equal')
            
            status_chart_path = os.path.join(temp_dir, 'status_distribution.png')
            plt.savefig(status_chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            story.append(Paragraph("Game Status Distribution", styles['Heading2']))
            story.append(Image(status_chart_path, width=5*inch, height=5*inch))
            charts_added += 1
            print("✅ Status distribution chart added")
    except Exception as e:
        print(f"❌ Error creating status distribution chart: {e}")
        story.append(Paragraph(f"Status Chart: Error - {str(e)}", styles['Normal']))
    
    # Summary of chart generation
    print(f"Charts generated: {charts_added}/3")
    if charts_added == 0:
        story.append(Paragraph("Charts could not be generated. Please check server logs.", styles['Normal']))
    
    # Build PDF first, then clean up
    print("Building PDF...")
    doc.build(story)
    buffer.seek(0)
    print("PDF built successfully")
    
    # Clean up temporary files AFTER PDF is built
    try:
        import shutil
        shutil.rmtree(temp_dir)
        print("Temporary files cleaned up")
    except Exception as e:
        print(f"Error cleaning up temp files: {e}")
    
    return send_file(buffer, as_attachment=True, download_name='arcade_report.pdf', mimetype='application/pdf')

@app.route('/backup_management')
@login_required
@requires_role('admin')
def backup_management():
    """Database backup and restore management interface"""
    import subprocess
    import glob
    from datetime import datetime
    
    # Get list of available backups
    backup_dir = 'backups'
    backups = []
    
    if os.path.exists(backup_dir):
        backup_files = glob.glob(os.path.join(backup_dir, 'arcade_backup_*.db'))
        for backup_file in backup_files:
            file_size = os.path.getsize(backup_file)
            file_time = datetime.fromtimestamp(os.path.getmtime(backup_file))
            days_ago = (datetime.now() - file_time).days
            backups.append({
                'filename': os.path.basename(backup_file),
                'filepath': backup_file,
                'size': file_size,
                'created': file_time,
                'days_ago': days_ago
            })
    
    # Sort by creation time (newest first)
    backups.sort(key=lambda x: x['created'], reverse=True)
    
    return render_template('backup_management.html', backups=backups)

@app.route('/create_backup', methods=['POST'])
@login_required
@requires_role('admin')
def create_backup():
    """Create a new database backup"""
    import subprocess
    
    try:
        # Run the backup script
        script_path = os.path.join('scripts', 'backup_database.py')
        result = subprocess.run([sys.executable, script_path, 'backup'], 
                              capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            flash('Database backup created successfully!', 'success')
        else:
            flash(f'Backup failed: {result.stderr}', 'error')
    
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'error')
    
    return redirect(url_for('backup_management'))

@app.route('/restore_backup', methods=['POST'])
@login_required
@requires_role('admin')
def restore_backup():
    """Restore database from backup"""
    backup_file = request.form.get('backup_file')
    
    if not backup_file:
        flash('No backup file specified', 'error')
        return redirect(url_for('backup_management'))
    
    backup_path = os.path.join('backups', backup_file)
    if not os.path.exists(backup_path):
        flash('Backup file not found', 'error')
        return redirect(url_for('backup_management'))
    
    try:
        import subprocess
        
        # Run the restore script
        script_path = os.path.join('scripts', 'restore_database.py')
        result = subprocess.run([sys.executable, script_path, '--backup-file', backup_path], 
                              capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            flash('Database restored successfully! Please restart the application.', 'success')
        else:
            flash(f'Restore failed: {result.stderr}', 'error')
    
    except Exception as e:
        flash(f'Error restoring backup: {str(e)}', 'error')
    
    return redirect(url_for('backup_management'))

@app.route('/download_backup/<filename>')
@login_required
@requires_role('admin')
def download_backup(filename):
    """Download a backup file"""
    backup_path = os.path.join('backups', filename)
    
    if not os.path.exists(backup_path) or not filename.startswith('arcade_backup_'):
        flash('Backup file not found', 'error')
        return redirect(url_for('backup_management'))
    
    return send_file(backup_path, as_attachment=True, download_name=filename)

@app.route('/export_csv')
@login_required
@requires_role('manager')
def export_csv():
    """Export game data to CSV"""
    games = Game.query.all()
    data = []
    
    for game in games:
        # Make game.date_added timezone-aware if it's naive
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue = game.total_revenue / days_active
        
        data.append({
            'Game Name': game.name,
            'Manufacturer': game.manufacturer,
            'Location': game.location,
            'Status': game.status,
            'Total Plays': game.total_plays,
            'Total Revenue': game.total_revenue,
            'Daily Revenue': round(daily_revenue, 2),
            'Days Active': days_active,
            'Top 5 Count': game.times_in_top_5,
            'Top 10 Count': game.times_in_top_10
        })
    
    df = pd.DataFrame(data)
    
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=arcade_data.csv'
    response.headers['Content-type'] = 'text/csv'
    
    return response

@app.route('/delete_game/<int:game_id>', methods=['POST'])
@login_required
@requires_role('admin')
def delete_game(game_id):
    """Delete a game and all associated records"""
    game = Game.query.get_or_404(game_id)
    
    try:
        # Delete associated play records (cascade should handle this, but let's be explicit)
        PlayRecord.query.filter_by(game_id=game_id).delete()
        
        # Delete associated maintenance records
        MaintenanceRecord.query.filter_by(game_id=game_id).delete()
        
        # Delete the game image if it exists
        if game.image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], game.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # Delete the game itself
        game_name = game.name
        db.session.delete(game)
        db.session.commit()
        
        flash(f'Game "{game_name}" and all associated records have been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting game: {str(e)}', 'error')
    
    return redirect(url_for('games_list'))

# =====================================
# INVENTORY MANAGEMENT ROUTES
# =====================================

@app.route('/inventory')
@login_required
@requires_role('operator')
def inventory_list():
    """Display inventory items with search and filter options"""
    search = request.args.get('search', '')
    low_stock_only = request.args.get('low_stock', False, type=bool)
    
    # Base query
    query = InventoryItem.query
    
    # Apply search filter
    if search:
        query = query.filter(
            InventoryItem.name.contains(search) |
            InventoryItem.description.contains(search) |
            InventoryItem.part_number.contains(search)
        )
    
    # Apply low stock filter
    if low_stock_only:
        query = query.filter(InventoryItem.stock_quantity <= InventoryItem.minimum_stock)
    
    items = query.order_by(InventoryItem.name.asc()).all()
    
    # Get low stock items count for badge
    low_stock_count = InventoryItem.query.filter(
        InventoryItem.stock_quantity <= InventoryItem.minimum_stock
    ).count()
    
    # Calculate total inventory value
    total_value = sum(item.total_value() for item in InventoryItem.query.all())
    
    # Get pending requests count for current user
    pending_requests_count = 0
    if current_user.is_authenticated:
        pending_requests_count = InventoryRequest.query.filter_by(
            requested_by_id=current_user.id,
            status='Pending'
        ).count()
    
    # Get recent inventory requests (last 10)
    if current_user.role in ['admin', 'manager']:
        recent_requests = InventoryRequest.query\
            .order_by(InventoryRequest.date_requested.desc()).limit(10).all()
    else:
        recent_requests = InventoryRequest.query\
            .filter_by(requested_by_id=current_user.id)\
            .order_by(InventoryRequest.date_requested.desc()).limit(10).all()
    
    return render_template('inventory_list.html',
                         items=items,
                         search=search,
                         low_stock_only=low_stock_only,
                         low_stock_count=low_stock_count,
                         total_value=total_value,
                         pending_requests_count=pending_requests_count,
                         recent_requests=recent_requests)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
@requires_role('manager')
def add_inventory_item():
    """Add a new inventory item"""
    form = InventoryItemForm()
    
    # Populate game choices for compatibility
    games = Game.query.order_by(Game.name.asc()).all()
    form.compatible_games.choices = [(g.id, g.name) for g in games]
    
    if request.method == 'POST':
        print(f"DEBUG: Form submitted - Method: POST")
        print(f"DEBUG: Form data: {dict(request.form)}")
        
    if form.validate_on_submit():
        item = InventoryItem(
            name=form.name.data,
            description=form.description.data,
            stock_quantity=form.stock_quantity.data,
            unit_price=form.unit_price.data,
            minimum_stock=form.minimum_stock.data,
            supplier=form.supplier.data,
            part_number=form.part_number.data,
            notes=form.notes.data,
            last_restocked=datetime.now(dt.UTC) if form.stock_quantity.data > 0 else None
        )
        
        # Add compatible games
        if form.compatible_games.data:
            compatible_games = Game.query.filter(Game.id.in_(form.compatible_games.data)).all()
            item.compatible_games.extend(compatible_games)
        
        db.session.add(item)
        
        # Create initial stock history if stock > 0
        if form.stock_quantity.data > 0:
            stock_history = StockHistory(
                item=item,
                change_type='added',
                quantity_change=form.stock_quantity.data,
                previous_quantity=0,
                new_quantity=form.stock_quantity.data,
                reason='Initial stock',
                user_id=current_user.id
            )
            db.session.add(stock_history)
        
        db.session.commit()
        
        flash(f'Inventory item "{item.name}" added successfully!', 'success')
        return redirect(url_for('inventory_list'))
    elif request.method == 'POST':
        # Form validation failed
        print(f"DEBUG: Form errors: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')
    
    return render_template('add_inventory_item.html', form=form)

@app.route('/inventory/<int:item_id>')
@login_required
@requires_role('operator')
def inventory_detail(item_id):
    """View detailed information about an inventory item"""
    item = InventoryItem.query.get_or_404(item_id)
    
    # Get recent stock history
    recent_history = StockHistory.query.filter_by(item_id=item_id)\
                                      .order_by(StockHistory.timestamp.desc())\
                                      .limit(10).all()
    
    # Check if item has active low stock alert
    active_alert = LowStockAlert.query.filter_by(
        item_id=item_id, resolved=False
    ).first()
    
    return render_template('inventory_detail.html',
                         item=item,
                         recent_history=recent_history,
                         active_alert=active_alert)

@app.route('/inventory/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
@requires_role('manager')
def edit_inventory_item(item_id):
    """Edit an inventory item"""
    item = InventoryItem.query.get_or_404(item_id)
    form = InventoryItemForm(obj=item)
    
    # Populate game choices
    games = Game.query.order_by(Game.name.asc()).all()
    form.compatible_games.choices = [(g.id, g.name) for g in games]
    
    # Set current compatible games
    if request.method == 'GET':
        form.compatible_games.data = [g.id for g in item.compatible_games]
    
    if form.validate_on_submit():
        old_stock = item.stock_quantity
        
        # Update item fields
        item.name = form.name.data
        item.description = form.description.data
        item.stock_quantity = form.stock_quantity.data
        item.unit_price = form.unit_price.data
        item.minimum_stock = form.minimum_stock.data
        item.supplier = form.supplier.data
        item.part_number = form.part_number.data
        item.notes = form.notes.data
        
        # Update compatible games
        item.compatible_games.clear()
        if form.compatible_games.data:
            compatible_games = Game.query.filter(Game.id.in_(form.compatible_games.data)).all()
            item.compatible_games.extend(compatible_games)
        
        # Record stock change if quantity changed
        if old_stock != form.stock_quantity.data:
            quantity_change = form.stock_quantity.data - old_stock
            stock_history = StockHistory(
                item_id=item_id,
                change_type='adjusted',
                quantity_change=quantity_change,
                previous_quantity=old_stock,
                new_quantity=form.stock_quantity.data,
                reason='Manual adjustment via edit',
                user_id=current_user.id
            )
            db.session.add(stock_history)
            
            if form.stock_quantity.data > old_stock:
                item.last_restocked = datetime.now(dt.UTC)
        
        db.session.commit()
        
        # Check and create low stock alert if needed
        _check_low_stock_alert(item)
        
        flash(f'Inventory item "{item.name}" updated successfully!', 'success')
        return redirect(url_for('inventory_detail', item_id=item_id))
    
    return render_template('edit_inventory_item.html', form=form, item=item)

@app.route('/inventory/<int:item_id>/adjust_stock', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def adjust_stock(item_id):
    """Manually adjust stock levels for an inventory item"""
    item = InventoryItem.query.get_or_404(item_id)
    form = StockAdjustmentForm()
    
    if form.validate_on_submit():
        old_quantity = item.stock_quantity
        adjustment_type = form.adjustment_type.data
        quantity = form.quantity.data
        
        # Calculate new quantity based on adjustment type
        if adjustment_type in ['added']:
            new_quantity = old_quantity + quantity
            quantity_change = quantity
        elif adjustment_type in ['removed', 'used']:
            new_quantity = max(0, old_quantity - quantity)  # Don't go below 0
            quantity_change = -(min(quantity, old_quantity))  # Actual change might be less if we hit 0
        else:  # adjusted - direct set
            new_quantity = quantity
            quantity_change = quantity - old_quantity
        
        # Update item stock
        item.stock_quantity = new_quantity
        if adjustment_type == 'added':
            item.last_restocked = datetime.now(dt.UTC)
        
        # Record stock history
        stock_history = StockHistory(
            item_id=item_id,
            change_type=adjustment_type,
            quantity_change=quantity_change,
            previous_quantity=old_quantity,
            new_quantity=new_quantity,
            reason=form.reason.data or f'Manual {adjustment_type}',
            user_id=current_user.id
        )
        
        db.session.add(stock_history)
        db.session.commit()
        
        # Check and create low stock alert if needed
        _check_low_stock_alert(item)
        
        flash(f'Stock adjusted for "{item.name}": {old_quantity} → {new_quantity}', 'success')
        return redirect(url_for('inventory_detail', item_id=item_id))
    
    return render_template('adjust_stock.html', form=form, item=item)

@app.route('/inventory/<int:item_id>/delete', methods=['POST'])
@login_required
@requires_role('admin')
def delete_inventory_item(item_id):
    """Delete an inventory item and all associated records"""
    item = InventoryItem.query.get_or_404(item_id)
    
    try:
        item_name = item.name
        db.session.delete(item)  # Cascade will handle related records
        db.session.commit()
        
        flash(f'Inventory item "{item_name}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting item: {str(e)}', 'error')
    
    return redirect(url_for('inventory_list'))

@app.route('/inventory/low_stock_alerts')
@login_required
@requires_role('manager')
def low_stock_alerts():
    """View and manage low stock alerts"""
    # Get all active low stock alerts
    active_alerts = LowStockAlert.query.filter_by(resolved=False)\
                                       .join(InventoryItem)\
                                       .order_by(LowStockAlert.alert_triggered.desc()).all()
    
    # Get resolved alerts from last 30 days
    from datetime import timedelta
    thirty_days_ago = date.today() - timedelta(days=30)
    recent_resolved = LowStockAlert.query.filter(
        LowStockAlert.resolved == True,
        LowStockAlert.resolved_date >= thirty_days_ago
    ).join(InventoryItem).order_by(LowStockAlert.resolved_date.desc()).all()
    
    return render_template('low_stock_alerts.html',
                         active_alerts=active_alerts,
                         recent_resolved=recent_resolved)

@app.route('/inventory/resolve_alert/<int:alert_id>', methods=['POST'])
@login_required
@requires_role('manager')
def resolve_low_stock_alert(alert_id):
    """Mark a low stock alert as resolved"""
    alert = LowStockAlert.query.get_or_404(alert_id)
    
    alert.resolved = True
    alert.resolved_date = datetime.now(dt.UTC)
    db.session.commit()
    
    flash(f'Low stock alert for "{alert.item.name}" marked as resolved.', 'success')
    return redirect(url_for('low_stock_alerts'))

def _check_low_stock_alert(item):
    """Check if item needs a low stock alert and create one if needed"""
    if item.is_low_stock():
        # Check if there's already an active alert
        existing_alert = LowStockAlert.query.filter_by(
            item_id=item.id, resolved=False
        ).first()
        
        if not existing_alert:
            # Create new alert
            alert = LowStockAlert(
                item_id=item.id,
                email_sent=False  # Will be handled by email notification system
            )
            db.session.add(alert)
            db.session.commit()
    else:
        # Item is no longer low stock, resolve any active alerts
        active_alerts = LowStockAlert.query.filter_by(
            item_id=item.id, resolved=False
        ).all()
        
        for alert in active_alerts:
            alert.resolved = True
            alert.resolved_date = datetime.now(dt.UTC)
        
        if active_alerts:
            db.session.commit()

# =====================================
# INVENTORY REQUEST ROUTES
# =====================================

@app.route('/inventory/request', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def request_inventory():
    """Create a new inventory request"""
    if request.method == 'POST':
        item_type = request.form.get('item_type')  # 'existing' or 'new'
        item_id = request.form.get('item_id')
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity', type=int)
        reason = request.form.get('reason', '')
        urgency = request.form.get('urgency', 'Normal')
        maintenance_id = request.form.get('maintenance_id')
        
        # Validation
        if not item_name or not quantity or quantity <= 0:
            flash('Please provide valid item name and quantity.', 'error')
            return redirect(url_for('request_inventory'))
        
        # Create the request
        inv_request = InventoryRequest(
            item_id=int(item_id) if item_type == 'existing' and item_id else None,
            item_name=item_name,
            quantity_requested=quantity,
            reason=reason,
            urgency=urgency,
            requested_by_id=current_user.id,
            maintenance_id=int(maintenance_id) if maintenance_id else None
        )
        
        db.session.add(inv_request)
        db.session.flush()  # Get the ID
        
        # Log creation in history
        history = InventoryRequestHistory(
            request_id=inv_request.id,
            user_id=current_user.id,
            action='created',
            notes=f'Request created for {item_name} (Qty: {quantity})'
        )
        db.session.add(history)
        db.session.commit()
        
        flash(f'Request for "{item_name}" (Qty: {quantity}) submitted successfully!', 'success')
        return redirect(url_for('inventory_requests_list'))
    
    # GET request - show form
    existing_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    
    # Get open/active maintenance orders for linking
    open_maintenance = MaintenanceRecord.query.filter(
        MaintenanceRecord.status.in_(['Open', 'In_Progress'])
    ).outerjoin(Game).order_by(MaintenanceRecord.date_reported.desc()).all()
    
    # Check if maintenance_id is passed in query params (from Request Parts button)
    preselected_maintenance_id = request.args.get('maintenance_id', type=int)
    
    return render_template('request_inventory.html', 
                         existing_items=existing_items,
                         open_maintenance=open_maintenance,
                         preselected_maintenance_id=preselected_maintenance_id)

@app.route('/inventory/requests')
@login_required
@requires_role('operator')
def inventory_requests_list():
    """View all inventory requests"""
    # Operators see their own requests, managers/admins see all
    if current_user.role in ['admin', 'manager']:
        pending_requests = InventoryRequest.query.filter_by(status='Pending')\
            .order_by(InventoryRequest.urgency.desc(), InventoryRequest.date_requested.desc()).all()
        all_requests = InventoryRequest.query\
            .order_by(InventoryRequest.date_requested.desc()).all()
    else:
        pending_requests = InventoryRequest.query.filter_by(
            requested_by_id=current_user.id, status='Pending'
        ).order_by(InventoryRequest.date_requested.desc()).all()
        all_requests = InventoryRequest.query.filter_by(requested_by_id=current_user.id)\
            .order_by(InventoryRequest.date_requested.desc()).all()
    
    return render_template('inventory_requests.html',
                         pending_requests=pending_requests,
                         all_requests=all_requests)

@app.route('/inventory/requests/<int:request_id>/update', methods=['POST'])
@login_required
@requires_role('manager')
def update_inventory_request(request_id):
    """Update status of an inventory request"""
    inv_request = InventoryRequest.query.get_or_404(request_id)
    
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')
    tracking_number = request.form.get('tracking_number', '')
    vendor = request.form.get('vendor', '')
    estimated_arrival = request.form.get('estimated_arrival', '')
    
    # Track changes for history
    changes = []
    
    if inv_request.status != new_status:
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action='status_changed',
            field_changed='status',
            old_value=inv_request.status,
            new_value=new_status
        )
        db.session.add(history)
        inv_request.status = new_status
        changes.append(f"Status: {inv_request.status} → {new_status}")
    
    if notes and notes != (inv_request.notes or ''):
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action='notes_updated',
            field_changed='notes',
            notes=notes
        )
        db.session.add(history)
        inv_request.notes = notes
    
    if tracking_number and tracking_number != (inv_request.tracking_number or ''):
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action='tracking_updated',
            field_changed='tracking_number',
            old_value=inv_request.tracking_number,
            new_value=tracking_number
        )
        db.session.add(history)
        inv_request.tracking_number = tracking_number
        changes.append(f"Tracking: {tracking_number}")
    
    if vendor and vendor != (inv_request.vendor or ''):
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action='vendor_updated',
            field_changed='vendor',
            old_value=inv_request.vendor,
            new_value=vendor
        )
        db.session.add(history)
        inv_request.vendor = vendor
        changes.append(f"Vendor: {vendor}")
    
    if estimated_arrival and estimated_arrival != (inv_request.estimated_arrival.strftime('%Y-%m-%d') if inv_request.estimated_arrival else ''):
        try:
            from datetime import datetime as dt_module
            new_eta = dt_module.strptime(estimated_arrival, '%Y-%m-%d').date()
            history = InventoryRequestHistory(
                request_id=request_id,
                user_id=current_user.id,
                action='eta_updated',
                field_changed='estimated_arrival',
                old_value=str(inv_request.estimated_arrival) if inv_request.estimated_arrival else None,
                new_value=str(new_eta)
            )
            db.session.add(history)
            inv_request.estimated_arrival = new_eta
            changes.append(f"ETA: {new_eta}")
        except ValueError:
            pass  # Invalid date format, ignore
    
    if new_status in ['Received', 'Rejected']:
        inv_request.date_fulfilled = datetime.now(dt.UTC)
    
    # If status is "Received", add the quantity to inventory
    if new_status == 'Received':
        if inv_request.item_id:
            # Existing item - add to stock
            item = InventoryItem.query.get(inv_request.item_id)
            if item:
                previous_qty = item.stock_quantity
                item.stock_quantity += inv_request.quantity_requested
                item.last_restocked = datetime.now(dt.UTC)
                
                # Record stock history
                stock_history = StockHistory(
                    item_id=item.id,
                    change_type='added',
                    quantity_change=inv_request.quantity_requested,
                    previous_quantity=previous_qty,
                    new_quantity=item.stock_quantity,
                    reason=f'Inventory request #{request_id} received',
                    user_id=current_user.id
                )
                db.session.add(stock_history)
                
                # Check and resolve low stock alerts if needed
                _check_low_stock_alert(item)
                
                flash(f'Request #{request_id} received! Added {inv_request.quantity_requested} units of "{item.name}" to inventory. New stock: {item.stock_quantity}', 'success')
            else:
                flash(f'Request #{request_id} updated to "{new_status}" but item ID {inv_request.item_id} not found in inventory.', 'error')
        else:
            # New item - create it automatically
            new_item = InventoryItem(
                name=inv_request.item_name,
                stock_quantity=inv_request.quantity_requested,
                unit_price=0.0,  # Default, can be updated later
                minimum_stock=5,  # Default
                last_restocked=datetime.now(dt.UTC)
            )
            db.session.add(new_item)
            db.session.flush()  # Get the ID before committing
            
            # Link the request to the newly created item
            inv_request.item_id = new_item.id
            
            # Record initial stock history
            stock_history = StockHistory(
                item_id=new_item.id,
                change_type='added',
                quantity_change=inv_request.quantity_requested,
                previous_quantity=0,
                new_quantity=inv_request.quantity_requested,
                reason=f'New item created from inventory request #{request_id}',
                user_id=current_user.id
            )
            db.session.add(stock_history)
            
            flash(f'Request #{request_id} received! Created new inventory item "{new_item.name}" with {inv_request.quantity_requested} units. Please update pricing and details.', 'success')
    else:
        flash(f'Request #{request_id} updated to "{new_status}"', 'success')
    
    db.session.commit()
    return redirect(url_for('inventory_requests_list'))

@app.route('/inventory/requests/<int:request_id>/delete', methods=['POST'])
@login_required
@requires_role('operator')
def delete_inventory_request(request_id):
    """Delete an inventory request"""
    inv_request = InventoryRequest.query.get_or_404(request_id)
    
    # Admins/managers can delete any request
    # Regular users can only delete their own pending requests
    if current_user.role in ['admin', 'manager']:
        # Admins/managers can delete any request regardless of status
        pass
    else:
        # Regular users restrictions
        if inv_request.status != 'Pending':
            flash('Only pending requests can be deleted.', 'error')
            return redirect(url_for('inventory_requests_list'))
        
        if inv_request.requested_by_id != current_user.id:
            flash('You can only delete your own requests.', 'error')
            return redirect(url_for('inventory_requests_list'))
    
    item_name = inv_request.item_name
    request_status = inv_request.status
    db.session.delete(inv_request)
    db.session.commit()
    
    flash(f'Request for "{item_name}" (Status: {request_status}) deleted successfully.', 'success')
    return redirect(url_for('inventory_requests_list'))

@app.route('/inventory/requests/<int:request_id>')
@login_required
@requires_role('operator')
def inventory_request_detail(request_id):
    """View detailed information and full audit history of an inventory request"""
    inv_request = InventoryRequest.query.get_or_404(request_id)
    
    # Check permissions - users can only view their own requests unless they're managers/admins
    if current_user.role not in ['admin', 'manager']:
        if inv_request.requested_by_id != current_user.id:
            flash('You can only view your own requests.', 'error')
            return redirect(url_for('inventory_requests_list'))
    
    # Get full history (already ordered by timestamp desc in relationship)
    history = inv_request.history
    
    return render_template('inventory_request_detail.html',
                         request=inv_request,
                         history=history)

@app.route('/inventory/requests/<int:request_id>/update_tracking', methods=['POST'])
@login_required
@requires_role('manager')
def update_request_tracking(request_id):
    """Fetch and update shipment tracking information using EasyPost API"""
    inv_request = InventoryRequest.query.get_or_404(request_id)
    
    if not inv_request.tracking_number:
        flash('No tracking number available for this request.', 'error')
        return redirect(url_for('inventory_request_detail', request_id=request_id))
    
    # Check if EasyPost API key is configured
    api_key = os.getenv('EASYPOST_API_KEY')
    if not api_key or api_key == 'your-easypost-api-key-here':
        flash('Tracking API not configured. Please add EASYPOST_API_KEY to your .env file.', 'warning')
        return redirect(url_for('inventory_request_detail', request_id=request_id))
    
    try:
        import easypost
        client = easypost.EasyPostClient(api_key=api_key)
        
        # Determine carrier (default to USPS if not specified)
        carrier = inv_request.carrier or 'USPS'
        
        # Create or retrieve tracker
        tracker = client.tracker.create(
            tracking_code=inv_request.tracking_number,
            carrier=carrier
        )
        
        # Update request with tracking info
        inv_request.tracking_status = tracker.status  # 'unknown', 'pre_transit', 'in_transit', 'out_for_delivery', 'delivered', etc.
        inv_request.carrier = tracker.carrier or carrier
        inv_request.last_tracking_update = datetime.now(dt.UTC)
        
        # Store tracking details as JSON
        tracking_info = {
            'status': tracker.status,
            'status_detail': tracker.status_detail,
            'est_delivery_date': str(tracker.est_delivery_date) if tracker.est_delivery_date else None,
            'public_url': tracker.public_url,
            'tracking_details': [
                {
                    'datetime': str(detail.datetime) if detail.datetime else None,
                    'status': detail.status,
                    'message': detail.message,
                    'tracking_location': {
                        'city': detail.tracking_location.city if detail.tracking_location else None,
                        'state': detail.tracking_location.state if detail.tracking_location else None,
                    } if detail.tracking_location else None
                }
                for detail in (tracker.tracking_details or [])
            ]
        }
        inv_request.tracking_details = json.dumps(tracking_info)
        
        # Update ETA if available
        if tracker.est_delivery_date:
            try:
                from datetime import datetime as dt_module
                new_eta = dt_module.strptime(tracker.est_delivery_date, '%Y-%m-%d').date()
                if inv_request.estimated_arrival != new_eta:
                    # Log ETA change in history
                    history = InventoryRequestHistory(
                        request_id=request_id,
                        user_id=current_user.id,
                        action='tracking_auto_updated',
                        field_changed='estimated_arrival',
                        old_value=str(inv_request.estimated_arrival) if inv_request.estimated_arrival else None,
                        new_value=str(new_eta),
                        notes=f'Updated from tracking API (Status: {tracker.status})'
                    )
                    db.session.add(history)
                    inv_request.estimated_arrival = new_eta
            except (ValueError, AttributeError):
                pass
        
        # Log tracking update in history
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action='tracking_refreshed',
            notes=f'Tracking refreshed: {tracker.status} ({tracker.status_detail or "No details"})'
        )
        db.session.add(history)
        
        db.session.commit()
        
        # Provide user-friendly status message
        status_messages = {
            'unknown': 'Tracking information not yet available',
            'pre_transit': 'Label created, waiting for carrier pickup',
            'in_transit': 'Package is in transit',
            'out_for_delivery': 'Out for delivery today',
            'delivered': 'Package delivered!',
            'available_for_pickup': 'Available for pickup',
            'return_to_sender': 'Package being returned to sender',
            'failure': 'Delivery issue - check tracking details',
            'cancelled': 'Shipment cancelled',
            'error': 'Tracking error'
        }
        
        status_msg = status_messages.get(tracker.status, tracker.status_detail or tracker.status)
        flash(f'Tracking updated! Status: {status_msg}', 'success')
        
    except ImportError:
        flash('EasyPost library not installed. Run: pip install easypost', 'error')
    except Exception as e:
        flash(f'Error fetching tracking info: {str(e)}', 'error')
        log_security_event(
            'TRACKING_UPDATE_FAILED',
            user_id=current_user.id,
            details=f'Request #{request_id}, Tracking: {inv_request.tracking_number}, Error: {str(e)}'
        )
    
    return redirect(url_for('inventory_request_detail', request_id=request_id))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        ip = get_client_ip()

        # 🧱 lockout check
        if is_account_locked(username, ip):
            flash("Too many failed attempts. Try again later.", "danger")
            log_security_event(f"Locked out login attempt for {username} from {ip}", "warning")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(form.password.data):
            clear_failed_login_attempts(username, ip)
            login_user(user, remember=form.remember.data)
            log_security_event(f"Successful login for {username} from {ip}")
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("home"))
        else:
            record_failed_login(username, ip)
            flash("Invalid username or password.", "danger")
            log_security_event(f"Invalid login for {username} from {ip}", "warning")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)

    # -------------------------------------------------------------
# 💾 ENCRYPTED BACKUP MANAGEMENT SYSTEM
# -------------------------------------------------------------

BACKUP_FOLDER = os.path.join(os.getcwd(), "backups")
os.makedirs(BACKUP_FOLDER, exist_ok=True)

# Locate your SQLite DB (adjust if your app uses another DB)
DB_FILE = os.path.join(os.getcwd(), "instance", "arcade.db")
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)


def encrypt_file(data: bytes) -> bytes:
    """Encrypt bytes with Fernet key."""
    f = Fernet(app.config['BACKUP_KEY'])
    return f.encrypt(data)


def decrypt_file(data: bytes) -> bytes:
    """Decrypt bytes with Fernet key."""
    f = Fernet(app.config['BACKUP_KEY'])
    return f.decrypt(data)
    
    """Create and encrypt a backup of the SQLite database."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"backup_{timestamp}.zip.enc"
    filepath = os.path.join(BACKUP_FOLDER, filename)

    if not os.path.exists(DB_FILE):
        flash('No database found to back up.', 'danger')
        return redirect(url_for('backup_management'))

    # Create a zip archive in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(DB_FILE, os.path.basename(DB_FILE))
    zip_data = zip_buffer.getvalue()

    # Encrypt the zip data
    encrypted_data = encrypt_file(zip_data)

    with open(filepath, 'wb') as f:
        f.write(encrypted_data)

    flash(f'Encrypted backup {filename} created successfully.', 'success')
    return redirect(url_for('backup_management'))

@app.route('/delete_backup', methods=['POST'])
@login_required
def delete_backup():
    """Delete an encrypted backup file."""
    backup_file = request.form.get('backup_file')
    if not backup_file:
        flash('No backup file specified.', 'danger')
        return redirect(url_for('backup_management'))

    backup_path = os.path.join(BACKUP_FOLDER, backup_file)
    if os.path.exists(backup_path):
        os.remove(backup_path)
        flash(f'Backup {backup_file} deleted successfully.', 'success')
    else:
        flash('Backup file not found.', 'warning')

    return redirect(url_for('backup_management'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
