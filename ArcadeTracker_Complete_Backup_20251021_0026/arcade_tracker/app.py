from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import datetime as dt
from functools import wraps
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import pandas as pd
import json
import os
import sys
import io
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-for-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///arcade.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['WTF_CSRF_ENABLED'] = True

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize CSRF protection
csrf = CSRFProtect(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def utility_processor():
    return dict(today=date.today)

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
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('readonly', 'Read Only'), ('operator', 'Operator'), ('manager', 'Manager')], validators=[DataRequired()])
    submit = SubmitField('Register')

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='readonly')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    
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
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    issue_description = db.Column(db.Text, nullable=False)
    fix_description = db.Column(db.Text, nullable=True)  # Initial diagnosis/assessment
    work_notes = db.Column(db.Text, nullable=True)  # Actual work performed (kept for compatibility)
    parts_used = db.Column(db.Text, nullable=True)  # Parts/materials used
    cost = db.Column(db.Float, nullable=True)
    date_reported = db.Column(db.DateTime, default=lambda: datetime.now(dt.UTC))
    date_fixed = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Open')  # Open, In_Progress, Fixed, Deferred
    technician = db.Column(db.String(50), nullable=True)
    
    work_logs = db.relationship('WorkLog', backref='maintenance_record', lazy=True, cascade='all, delete-orphan', order_by='WorkLog.timestamp')

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

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
@requires_role('admin')
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists', 'error')
        else:
            user = User(username=form.username.data, role=form.role.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash(f'User {user.username} created successfully with {user.role} role!', 'success')
            return redirect(url_for('manage_users'))
    return render_template('register.html', form=form)

@app.route('/manage_users')
@login_required
@requires_role('admin')
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('manage_users.html', users=users)

@app.route('/toggle_user/<int:user_id>', methods=['POST'])
@login_required
@requires_role('admin')
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot disable your own account!', 'error')
        return redirect(url_for('manage_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    status = 'enabled' if user.is_active else 'disabled'
    flash(f'User {user.username} has been {status}!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    # Only allow setup if no users exist
    if User.query.first():
        flash('Setup already completed', 'info')
        return redirect(url_for('login'))
    
    form = RegisterForm()
    form.role.choices = [('admin', 'Administrator')]  # Force admin role for setup
    
    if form.validate_on_submit():
        admin_user = User(username=form.username.data, role='admin')
        admin_user.set_password(form.password.data)
        db.session.add(admin_user)
        db.session.commit()
        login_user(admin_user)
        flash(f'Admin user {admin_user.username} created successfully! You are now logged in.', 'success')
        return redirect(url_for('home'))
    
    return render_template('setup.html', form=form)

# Main Routes
@app.route('/')
@login_required
def home():
    # Quick stats for dashboard
    all_games = Game.query.all()
    total_games = len(all_games)
    floor_games = Game.query.filter_by(location='Floor').all()
    total_plays = sum(game.total_plays for game in all_games)
    total_revenue = sum(game.total_revenue for game in all_games)
    
    # Recent activity
    recent_records = PlayRecord.query.order_by(PlayRecord.date_recorded.desc()).limit(5).all()
    recent_maintenance = MaintenanceRecord.query.filter_by(status='Open').limit(5).all()
    
    # Calculate worst performers for the dashboard
    worst_performers = []
    if floor_games:
        performers = []
        for game in floor_games:
            # Make game.date_added timezone-aware if it's naive
            date_added = game.date_added
            if date_added.tzinfo is None:
                date_added = date_added.replace(tzinfo=dt.UTC)
            days_active = (datetime.now(dt.UTC) - date_added).days or 1
            daily_revenue_avg = game.total_revenue / days_active
            performers.append((game, daily_revenue_avg))
        
        # Sort and get worst 3 for dashboard
        worst_performers = sorted(performers, key=lambda x: x[1])[:3]
    
    return render_template('index.html', 
                         total_games=total_games,
                         floor_games=floor_games, 
                         total_plays=total_plays,
                         recent_records=recent_records,
                         recent_maintenance=recent_maintenance,
                         total_revenue=total_revenue,
                         worst_performers=worst_performers)

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
    
    # Sort alphabetically by name by default
    games = query.order_by(Game.name.asc()).all()
    
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
    
    return render_template('games.html', 
                         games=games, 
                         search=search,
                         location_filter=location_filter,
                         status_filter=status_filter,
                         locations=[l[0] for l in locations],
                         statuses=[s[0] for s in statuses])

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
            notes=notes,
            image_filename=image_filename
        )
        
        db.session.add(game)
        db.session.commit()
        
        # Handle initial coin count if provided
        initial_coin_count = request.form.get('initial_coin_count')
        if initial_coin_count and initial_coin_count.strip():
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

@app.route('/game/<int:game_id>')
@login_required
def game_detail(game_id):
    game = Game.query.get_or_404(game_id)
    recent_records = PlayRecord.query.filter_by(game_id=game_id).order_by(PlayRecord.date_recorded.desc()).limit(10).all()
    maintenance_records = MaintenanceRecord.query.filter_by(game_id=game_id).order_by(MaintenanceRecord.date_reported.desc()).all()
    return render_template('game_detail.html', game=game, recent_records=recent_records, maintenance_records=maintenance_records)

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

@app.route('/maintenance/<int:game_id>', methods=['GET', 'POST'])
@login_required
@requires_role('operator')
def maintenance(game_id):
    game = Game.query.get_or_404(game_id)
    
    if request.method == 'POST':
        maintenance_record = MaintenanceRecord(
            game_id=game_id,
            issue_description=request.form['issue_description'],
            fix_description=request.form.get('fix_description'),
            cost=float(request.form['cost']) if request.form.get('cost') else None,
            technician=request.form.get('technician'),
            status=request.form.get('status', 'Open')
        )
        
        if request.form.get('status') == 'Fixed':
            maintenance_record.date_fixed = datetime.now(dt.UTC)
            
        db.session.add(maintenance_record)
        db.session.commit()
        
        flash(f'Maintenance record added for "{game.name}"', 'success')
        return redirect(url_for('game_detail', game_id=game_id))
    
    return render_template('maintenance.html', game=game)

@app.route('/maintenance_orders')
@login_required
@requires_role('manager')
def maintenance_orders():
    """View all maintenance orders in spreadsheet format"""
    # Get all maintenance records, ordered by date
    all_records = MaintenanceRecord.query.join(Game).order_by(MaintenanceRecord.date_reported.desc()).all()
    
    # Separate by status
    open_records = [r for r in all_records if r.status in ['Open', 'In_Progress']]
    closed_records = [r for r in all_records if r.status in ['Fixed', 'Deferred']]
    
    return render_template('maintenance_orders.html', 
                         all_records=all_records,
                         open_records=open_records, 
                         closed_records=closed_records)

@app.route('/update_maintenance/<int:maintenance_id>', methods=['GET', 'POST'])
@login_required
@requires_role('manager')
def update_maintenance(maintenance_id):
    """Update a maintenance work order with progress notes"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)
    
    if request.method == 'POST':
        # Update maintenance record basic info
        maintenance.status = request.form.get('status', maintenance.status)
        maintenance.technician = request.form.get('technician', maintenance.technician)
        maintenance.fix_description = request.form.get('fix_description', maintenance.fix_description)
        
        # Update total cost
        cost_str = request.form.get('cost', '')
        if cost_str:
            try:
                maintenance.cost = float(cost_str)
            except ValueError:
                pass
        
        # Create new work log entry if work description is provided
        work_description = request.form.get('work_notes', '').strip()
        if work_description:
            # Create new work log entry
            work_log = WorkLog(
                maintenance_id=maintenance_id,
                user_id=current_user.id,
                work_description=work_description,
                parts_used=request.form.get('parts_used', '').strip() or None,
                time_spent=float(request.form.get('time_spent', 0)) if request.form.get('time_spent') else None,
                cost_incurred=float(request.form.get('work_cost', 0)) if request.form.get('work_cost') else None
            )
            db.session.add(work_log)
            
            # Also update the legacy work_notes field for backward compatibility
            maintenance.work_notes = work_description
            maintenance.parts_used = request.form.get('parts_used', maintenance.parts_used)
        
        # Set date_fixed if status is Fixed
        if request.form.get('status') == 'Fixed' and maintenance.status != 'Fixed':
            maintenance.date_fixed = datetime.now(dt.UTC)
        elif request.form.get('status') != 'Fixed':
            maintenance.date_fixed = None
        
        db.session.commit()
        
        if work_description:
            flash(f'Work logged for "{maintenance.game.name}" successfully!', 'success')
        else:
            flash(f'Work order for "{maintenance.game.name}" updated successfully!', 'success')
        
        return redirect(url_for('view_maintenance', maintenance_id=maintenance_id))
    
    return render_template('update_maintenance.html', maintenance=maintenance)

@app.route('/view_maintenance/<int:maintenance_id>')
@login_required
@requires_role('operator')
def view_maintenance(maintenance_id):
    """View detailed work order with all updates and history"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)
    return render_template('view_maintenance.html', maintenance=maintenance)

@app.route('/close_maintenance/<int:maintenance_id>', methods=['POST'])
@login_required
@requires_role('manager')
def close_maintenance(maintenance_id):
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

@app.route('/maintenance_reports')
@login_required
@requires_role('manager')
def maintenance_reports():
    """Generate maintenance reports with time frame filters"""
    from datetime import timedelta
    
    # Get date range from query params
    days = request.args.get('days', '30', type=int)  # Default 30 days
    start_date = date.today() - timedelta(days=days)
    
    # Get all maintenance records in date range
    all_records = MaintenanceRecord.query.join(Game).filter(
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
                resolution_times.append(max(1, days_to_fix))  # At least 1 day
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
    
    # Get parameters
    report_type = request.args.get('type', 'all')  # all, open, closed
    days = request.args.get('days', '30', type=int)
    start_date = date.today() - timedelta(days=days)
    
    # Get records based on type
    if report_type == 'open':
        records = MaintenanceRecord.query.join(Game).filter(
            MaintenanceRecord.status.in_(['Open', 'In_Progress'])
        ).order_by(MaintenanceRecord.date_reported.desc()).all()
        title = f"Open Maintenance Orders"
    elif report_type == 'closed':
        records = MaintenanceRecord.query.join(Game).filter(
            MaintenanceRecord.status.in_(['Fixed', 'Deferred']),
            MaintenanceRecord.date_reported >= start_date
        ).order_by(MaintenanceRecord.date_reported.desc()).all()
        title = f"Closed Maintenance Orders (Last {days} Days)"
    else:
        records = MaintenanceRecord.query.join(Game).filter(
            MaintenanceRecord.date_reported >= start_date
        ).order_by(MaintenanceRecord.date_reported.desc()).all()
        title = f"All Maintenance Orders (Last {days} Days)"
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 12))
    
    # Summary stats
    total_records = len(records)
    open_count = len([r for r in records if r.status in ['Open', 'In_Progress']])
    closed_count = len([r for r in records if r.status in ['Fixed', 'Deferred']])
    total_cost = sum(r.cost or 0 for r in records if r.status in ['Fixed', 'Deferred'])
    
    summary_data = [
        ['Metric', 'Value'],
        ['Total Records', str(total_records)],
        ['Open Orders', str(open_count)],
        ['Closed Orders', str(closed_count)],
        ['Total Cost', f'${total_cost:.2f}']
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
    
    # Maintenance records table
    if records:
        story.append(Paragraph("Maintenance Records", styles['Heading2']))
        
        maintenance_data = [['Game', 'Issue', 'Status', 'Date', 'Cost', 'Work Summary']]
        
        for record in records[:15]:  # Limit to 15 for better PDF formatting
            # Get work summary - prioritize work_logs, then work_notes, then fix_description
            work_summary = 'No work logged'
            if hasattr(record, 'work_logs') and record.work_logs:
                # Use the most recent work log entry
                latest_work = record.work_logs[-1]
                work_summary = latest_work.work_description[:35] + '...' if len(latest_work.work_description) > 35 else latest_work.work_description
            elif record.work_notes:
                work_summary = record.work_notes[:35] + '...' if len(record.work_notes) > 35 else record.work_notes
            elif record.fix_description:
                work_summary = record.fix_description[:35] + '...' if len(record.fix_description) > 35 else record.fix_description
            elif record.status in ['Open', 'In_Progress']:
                work_summary = 'In progress...'
            
            maintenance_data.append([
                record.game.name[:12] + '...' if len(record.game.name) > 12 else record.game.name,
                record.issue_description[:20] + '...' if len(record.issue_description) > 20 else record.issue_description,
                record.status.replace('_', ' '),
                record.date_reported.strftime('%m/%d'),
                f'${record.cost:.0f}' if record.cost else '$0',
                work_summary
            ])
        
        # Define column widths (in points) - total should be around 540 for letter size
        col_widths = [90, 120, 60, 40, 40, 190]  # Game, Issue, Status, Date, Cost, Work Summary
        
        maintenance_table = Table(maintenance_data, colWidths=col_widths)
        maintenance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('WORDWRAP', (0, 0), (-1, -1), True)
        ]))
        
        story.append(maintenance_table)
        
        # Add detailed work log section if there are records with work logs
        work_log_records = [r for r in records[:10] if hasattr(r, 'work_logs') and r.work_logs]
        if work_log_records:
            story.append(Spacer(1, 20))
            story.append(Paragraph("Detailed Work Logs (Recent Orders)", styles['Heading2']))
            
            for record in work_log_records:
                story.append(Spacer(1, 12))
                story.append(Paragraph(f"<b>{record.game.name}</b> - Work Order #{record.id}", styles['Heading3']))
                story.append(Paragraph(f"<i>Issue: {record.issue_description[:80]}{'...' if len(record.issue_description) > 80 else ''}</i>", styles['Normal']))
                story.append(Spacer(1, 8))
                
                # Work log entries
                for i, work_log in enumerate(record.work_logs[-3:], 1):  # Show last 3 work entries
                    work_text = f"<b>Entry {i}:</b> {work_log.timestamp.strftime('%m/%d %H:%M')} - {work_log.user.username}<br/>"
                    work_text += f"{work_log.work_description[:120]}{'...' if len(work_log.work_description) > 120 else ''}"
                    if work_log.time_spent:
                        work_text += f"<br/><i>Time: {work_log.time_spent}h</i>"
                    if work_log.cost_incurred:
                        work_text += f" <i>Cost: ${work_log.cost_incurred:.2f}</i>"
                    
                    story.append(Paragraph(work_text, styles['Normal']))
                    story.append(Spacer(1, 6))
    
    doc.build(story)
    buffer.seek(0)
    
    filename = f'maintenance_report_{report_type}_{days}days.pdf'
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
    
    # Top and worst performers
    floor_games = Game.query.filter_by(location='Floor').all()
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
    """Update the times_in_top_5 and times_in_top_10 counters"""
    games = Game.query.filter_by(location='Floor').all()
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
    
    # Get basic stats
    all_games = Game.query.all()
    floor_games = Game.query.filter_by(location='Floor').all()
    total_games = len(all_games)
    total_plays = sum(game.total_plays for game in all_games)
    total_revenue = sum(game.total_revenue for game in all_games)
    floor_games_count = len(floor_games)
    
    # Daily revenue for last 30 days
    thirty_days_ago = date.today() - timedelta(days=30)
    recent_records = PlayRecord.query.filter(PlayRecord.date_recorded >= thirty_days_ago).all()
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
    
    # Worst performers table
    story.append(Paragraph("Worst Performing Games (Recommended for Replacement)", styles['Heading2']))
    
    floor_games = Game.query.filter_by(location='Floor').all()
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
        recent_records = PlayRecord.query.filter(PlayRecord.date_recorded >= thirty_days_ago).all()
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)