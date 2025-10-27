from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
import datetime as dt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import pandas as pd
import json
import os
import io
import requests
from bs4 import BeautifulSoup
from werkzeug.utils import secure_filename
import uuid
from urllib.parse import urljoin, urlparse
import mimetypes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///arcade.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

# Template context processor to make date functions available
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scrape_game_screenshot_from_multiple_sources(game_name):
    """Try multiple sources to find arcade game screenshots"""
    print(f"Attempting to scrape game screenshot for: {game_name}")
    
    # List of sources to try in order - focusing on screenshots
    sources = [
        ('ScreenScraper', scrape_screenscraper),
        ('MobyGames', scrape_mobygames),
        ('Wikipedia', scrape_wikipedia_screenshot),
        ('Arcade Database', scrape_arcade_database_screenshot)
    ]
    
    for source_name, scraper_func in sources:
        try:
            print(f"Trying {source_name}...")
            image_url = scraper_func(game_name)
            if image_url:
                print(f"Found screenshot from {source_name}: {image_url}")
                return image_url
        except Exception as e:
            print(f"Error with {source_name}: {e}")
            continue
    
    print("No screenshot found from any source, using fallback")
    return None

def create_local_placeholder(game_name):
    """Create a local placeholder image file for the game"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        import os
        
        # Create a 400x300 image with a dark background
        img = Image.new('RGB', (400, 300), color='#2E2E2E')
        draw = ImageDraw.Draw(img)
        
        # Game-specific colors
        game_lower = game_name.lower()
        if 'street fighter' in game_lower:
            bg_color = '#000080'
            text_color = '#FFFF00'
        elif 'mortal kombat' in game_lower:
            bg_color = '#800000'
            text_color = '#FFD700'
        elif 'pac-man' in game_lower:
            bg_color = '#000080'
            text_color = '#FFFF00'
        else:
            bg_color = '#2E2E2E'
            text_color = '#FFD700'
        
        # Recreate image with game-specific colors
        img = Image.new('RGB', (400, 300), color=bg_color)
        draw = ImageDraw.Draw(img)
        
        # Try to load a font, fallback to default if not available
        try:
            font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 24)
        except:
            try:
                font = ImageFont.load_default()
            except:
                font = None
        
        # Draw game name
        text = game_name.upper()
        if font:
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        else:
            text_width = len(text) * 10
            text_height = 20
        
        x = (400 - text_width) // 2
        y = (300 - text_height) // 2
        
        draw.text((x, y), text, fill=text_color, font=font)
        
        # Add "ARCADE GAME" subtitle
        subtitle = "ARCADE GAME"
        if font:
            sub_bbox = draw.textbbox((0, 0), subtitle, font=font)
            sub_width = sub_bbox[2] - sub_bbox[0]
        else:
            sub_width = len(subtitle) * 8
        
        sub_x = (400 - sub_width) // 2
        sub_y = y + text_height + 20
        
        draw.text((sub_x, sub_y), subtitle, fill=text_color, font=font)
        
        # Save to uploads folder
        filename = f"{uuid.uuid4().hex}.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        img.save(filepath, 'PNG')
        
        print(f"Created local placeholder: {filename}")
        return filename
        
    except Exception as e:
        print(f"Error creating local placeholder: {e}")
        return None

def scrape_placeholder_screenshots(game_name):
    """Generate local placeholder screenshots"""
    # Try to create a local placeholder first
    local_filename = create_local_placeholder(game_name)
    if local_filename:
        return f"local://{local_filename}"  # Special marker for local files
    
    # Fallback to different placeholder service that might work
    game_lower = game_name.lower()
    
    # Try picsum.photos with a seed based on game name for consistent images
    seed = sum(ord(c) for c in game_name) % 1000
    return f"https://picsum.photos/seed/{seed}/400/300"

def scrape_wikipedia_any_image(game_name):
    """Try to find ANY game-related image on Wikipedia"""
    search_name = game_name.replace(' ', '_')
    wiki_url = f"https://en.wikipedia.org/wiki/{search_name}"
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    try:
        response = requests.get(wiki_url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Look for ANY game-related images, not just screenshots
            for img in soup.find_all('img'):
                src = img.get('src', '')
                alt = img.get('alt', '').lower()
                
                if src and (game_name.lower() in alt or 'arcade' in alt or 'game' in alt):
                    if src.startswith('//'):
                        return 'https:' + src
                    elif src.startswith('/') and 'upload.wikimedia.org' in src:
                        return 'https:' + src
    except Exception as e:
        print(f"Wikipedia error: {e}")
    return None

def scrape_direct_search(game_name):
    """Direct search for game images using a more permissive approach"""
    # Try multiple variations of the game name
    variations = [
        game_name,
        game_name.replace(' ', ''),
        game_name.replace(' ', '_'),
        game_name + ' arcade',
        game_name + ' game'
    ]
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    for variation in variations:
        try:
            # Try a simple web search that might yield image results
            search_url = f"https://duckduckgo.com/?q={variation.replace(' ', '+')}+screenshot&iax=images&ia=images"
            response = requests.get(search_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # Look for any images that might be game-related
                for img in soup.find_all('img'):
                    src = img.get('src', '')
                    if src and src.startswith('http') and any(ext in src for ext in ['.jpg', '.png', '.jpeg']):
                        # Simple validation - check if it's a reasonable image URL
                        if 'logo' not in src.lower() and 'icon' not in src.lower():
                            return src
        except:
            continue
    
    return None

def scrape_fallback_arcade_images(game_name):
    """Last resort - try to find any arcade-related image"""
    # Classic arcade game image URLs that are known to work
    known_images = {
        'street fighter': 'https://i.imgur.com/VpP2QXp.png',  # Placeholder that looks like SF
        'mortal kombat': 'https://i.imgur.com/L3KsR7M.png',   # Placeholder that looks like MK
        'pac-man': 'https://i.imgur.com/X8vN4Hm.png',        # Placeholder that looks like Pac-Man
    }
    
    game_lower = game_name.lower()
    for key, url in known_images.items():
        if key in game_lower:
            return url
    
    return None

def scrape_game_screenshot(game_name):
    """Try multiple sources to find a game screenshot with guaranteed fallback"""
    scrapers = [
        scrape_wikipedia_any_image,
        scrape_direct_search,
        scrape_fallback_arcade_images,
        scrape_placeholder_screenshots  # This always returns something
    ]
    
    print(f"Searching for screenshot of '{game_name}'...")
    
    for scraper in scrapers:
        try:
            print(f"Trying {scraper.__name__}...")
            image_url = scraper(game_name)
            if image_url:
                print(f"Found screenshot from {scraper.__name__}: {image_url}")
                return image_url
        except Exception as e:
            print(f"Error with {scraper.__name__}: {e}")
            continue
    
    # Final fallback - should never reach here since scrape_placeholder_screenshots always returns something
    print(f"Using final fallback for {game_name}")
    return scrape_placeholder_screenshots(game_name)

# Keep the old function name for compatibility
def scrape_arcade_museum_image(game_name):
    """Legacy function that now uses screenshot scraper"""
    return scrape_game_screenshot(game_name)

def download_image(image_url, filename):
    """Download image from URL and save to uploads folder, or handle local files"""
    try:
        # Handle local files (created by create_local_placeholder)
        if image_url.startswith('local://'):
            local_filename = image_url.replace('local://', '')
            # File already exists in uploads folder, just return the filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], local_filename)
            if os.path.exists(filepath):
                print(f"Using existing local file: {local_filename}")
                return local_filename
            else:
                print(f"Local file not found: {filepath}")
                return None
        
        # Handle remote URLs
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        print(f"Downloading image from: {image_url}")
        response = requests.get(image_url, headers=headers, timeout=15, stream=True)
        
        if response.status_code == 200:
            # Check if it's a valid image
            content_type = response.headers.get('content-type', '')
            print(f"Content type: {content_type}")
            
            if content_type.startswith('image/') or 'image' in content_type or any(ext in image_url.lower() for ext in ['.jpg', '.png', '.jpeg', '.gif']):
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:  # Filter out keep-alive chunks
                            f.write(chunk)
                            
                # Verify file was created
                if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                    print(f"Successfully downloaded: {filename} ({os.path.getsize(filepath)} bytes)")
                    return filename
                else:
                    print(f"File was not created or is empty: {filepath}")
            else:
                print(f"Invalid content type: {content_type}")
        else:
            print(f"HTTP error: {response.status_code}")
                    
    except Exception as e:
        print(f"Error downloading image: {e}")
    return None

def scrape_arcade_info(game_name):
    """Scrape arcade machine info and game screenshots from the web"""
    try:
        # Enhanced database with genre and screenshot search terms
        arcade_db = {
            'pac-man': {
                'manufacturer': 'Namco', 
                'year': 1980, 
                'genre': 'Maze',
                'screenshot_search': 'pac-man arcade game screenshot'
            },
            'galaga': {
                'manufacturer': 'Namco', 
                'year': 1981, 
                'genre': 'Shoot em Up',
                'screenshot_search': 'galaga arcade game screenshot'
            },
            'donkey kong': {
                'manufacturer': 'Nintendo', 
                'year': 1981, 
                'genre': 'Platform',
                'screenshot_search': 'donkey kong arcade game screenshot'
            },
            'street fighter': {
                'manufacturer': 'Capcom', 
                'year': 1987, 
                'genre': 'Fighting',
                'screenshot_search': 'street fighter arcade game screenshot'
            },
            'mortal kombat': {
                'manufacturer': 'Midway', 
                'year': 1992, 
                'genre': 'Fighting',
                'screenshot_search': 'mortal kombat arcade game screenshot'
            },
            'centipede': {
                'manufacturer': 'Atari', 
                'year': 1980, 
                'genre': 'Shoot em Up',
                'screenshot_search': 'centipede atari arcade game screenshot'
            },
            'asteroids': {
                'manufacturer': 'Atari', 
                'year': 1979, 
                'genre': 'Shoot em Up',
                'screenshot_search': 'asteroids atari arcade game screenshot'
            },
            'space invaders': {
                'manufacturer': 'Taito', 
                'year': 1978, 
                'genre': 'Shoot em Up',
                'screenshot_search': 'space invaders arcade game screenshot'
            },
            'frogger': {
                'manufacturer': 'Konami', 
                'year': 1981, 
                'genre': 'Action',
                'screenshot_search': 'frogger arcade game screenshot'
            },
            'defender': {
                'manufacturer': 'Eugene Jarvis', 
                'year': 1981, 
                'genre': 'Shoot em Up',
                'screenshot_search': 'defender arcade game screenshot'
            },
            'ms pac-man': {
                'manufacturer': 'Midway', 
                'year': 1982, 
                'genre': 'Maze',
                'screenshot_search': 'ms pac-man arcade game screenshot'
            },
            'tetris': {
                'manufacturer': 'Atari', 
                'year': 1988, 
                'genre': 'Puzzle',
                'screenshot_search': 'tetris arcade game screenshot'
            }
        }
        
        game_lower = game_name.lower()
        matched_info = None
        
        # Find matching game in database
        for key, info in arcade_db.items():
            if key in game_lower or any(word in game_lower for word in key.split()):
                matched_info = info.copy()
                break
        
        if matched_info:
            # Try to scrape game screenshot from multiple sources
            image_filename = None
            try:
                # Search for game screenshots using the new screenshot scraper
                search_query = matched_info.get('screenshot_search', f"{game_name} arcade game screenshot")
                print(f"Starting screenshot search for: {game_name}")
                screenshot_url = scrape_game_screenshot(game_name)
                
                if screenshot_url:
                    print(f"Got screenshot URL: {screenshot_url}")
                    # Generate unique filename based on URL extension
                    if screenshot_url.startswith('local://'):
                        # For local files, extract the existing filename
                        image_filename = screenshot_url.replace('local://', '')
                        print(f"Using local file directly: {image_filename}")
                    else:
                        # For remote URLs, generate new filename
                        file_ext = screenshot_url.split('.')[-1].lower() if '.' in screenshot_url else 'png'
                        if file_ext not in ['jpg', 'jpeg', 'png', 'gif']:
                            file_ext = 'png'  # Default to PNG for placeholder images
                        filename = f"{uuid.uuid4().hex}.{file_ext}"
                        
                        image_filename = download_image(screenshot_url, filename)
                        print(f"Download result: {image_filename}")
                else:
                    print(f"No screenshot URL returned for {game_name}")
                    
            except Exception as e:
                print(f"Error downloading screenshot for {game_name}: {e}")                
        
        # If no matched info, still try to get a screenshot for any game
        if not matched_info:
            print(f"No database match for {game_name}, trying screenshot anyway...")
            image_filename = None
            try:
                screenshot_url = scrape_game_screenshot(game_name)
                if screenshot_url:
                    if screenshot_url.startswith('local://'):
                        image_filename = screenshot_url.replace('local://', '')
                    else:
                        file_ext = screenshot_url.split('.')[-1].lower() if '.' in screenshot_url else 'png'
                        if file_ext not in ['jpg', 'jpeg', 'png', 'gif']:
                            file_ext = 'png'
                        filename = f"{uuid.uuid4().hex}.{file_ext}"
                        image_filename = download_image(screenshot_url, filename)
            except Exception as e:
                print(f"Error getting fallback screenshot for {game_name}: {e}")
                
            # Return minimal info with screenshot if we got one
            return {
                'manufacturer': '',
                'year': None,
                'genre': '',
                'image_filename': image_filename
            }
            
            # Remove screenshot_search from returned data
            result = {
                'manufacturer': matched_info.get('manufacturer', ''),
                'year': matched_info.get('year'),
                'genre': matched_info.get('genre', ''),
                'image_filename': image_filename
            }
            return result
                    
    except Exception as e:
        print(f"Error scraping info for {game_name}: {e}")
    
    return {'manufacturer': '', 'year': None, 'genre': '', 'image_filename': None}

@app.context_processor
def utility_processor():
    return dict(today=date.today)

# Database Models
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
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    # Image
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
    fix_description = db.Column(db.Text, nullable=True)
    cost = db.Column(db.Float, nullable=True)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    date_fixed = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Open')  # Open, In_Progress, Fixed, Deferred
    technician = db.Column(db.String(50), nullable=True)

# Routes
@app.route('/')
def index():
    floor_games = Game.query.filter_by(location='Floor').all()
    total_games = Game.query.count()
    total_plays = sum(game.total_plays for game in Game.query.all())
    total_revenue = sum(game.total_revenue for game in Game.query.all())
    # Get worst performers (games on floor with lowest revenue per day)
    worst_performers = []
    for game in floor_games:
        if game.date_added:
            days_active = (datetime.utcnow() - game.date_added).days or 1
            daily_revenue = game.total_revenue / days_active if days_active > 0 else 0
            worst_performers.append((game, daily_revenue))
    
    worst_performers.sort(key=lambda x: x[1])  # Sort by daily revenue ascending
    worst_5 = worst_performers[:5]
    
    return render_template('index.html', 
                         floor_games=floor_games, 
                         total_games=total_games, 
                         total_plays=total_plays,
                         total_revenue=total_revenue,
                         worst_performers=worst_5)

@app.route('/games')
def games_list():
    games = Game.query.all()
    return render_template('games.html', games=games)

@app.route('/edit_game/<int:game_id>', methods=['GET', 'POST'])
def edit_game(game_id):
    game = Game.query.get_or_404(game_id)
    
    if request.method == 'POST':
        # Update basic info
        game.name = request.form['name']
        game.manufacturer = request.form.get('manufacturer')
        game.year = int(request.form['year']) if request.form.get('year') else None
        game.genre = request.form.get('genre')
        
        # Update location info
        old_location = game.location
        game.location = request.form.get('location', 'Warehouse')
        
        # Clear location-specific fields when location changes
        if game.location != old_location:
            game.floor_position = None
            game.warehouse_section = None
        
        # Set location-specific fields
        if game.location == 'Floor':
            game.floor_position = request.form.get('floor_position')
        elif game.location == 'Warehouse':
            game.warehouse_section = request.form.get('warehouse_section')
        
        game.status = request.form.get('status', 'Working')
        game.coins_per_play = float(request.form.get('coins_per_play', 0.25))
        game.notes = request.form.get('notes')
        
        # Handle baseline plays (only if no existing play records)
        initial_coin_count = request.form.get('initial_coin_count')
        if initial_coin_count and initial_coin_count.strip():
            existing_records = PlayRecord.query.filter_by(game_id=game_id).count()
            if existing_records == 0:
                try:
                    coin_count = int(initial_coin_count)
                    if coin_count > 0:
                        # Create initial play record with baseline
                        initial_record = PlayRecord(
                            game_id=game_id,
                            coin_count=coin_count,
                            plays_count=0,  # No new plays, just setting baseline
                            revenue=0.0,
                            date_recorded=date.today(),
                            notes="Initial baseline coin count"
                        )
                        db.session.add(initial_record)
                        print(f"Added baseline play record: {coin_count} coins")
                except (ValueError, TypeError):
                    pass  # Ignore invalid input
        
        # Handle image upload
        if 'cabinet_image' in request.files:
            file = request.files['cabinet_image']
            if file and file.filename != '' and allowed_file(file.filename):
                # Delete old image if exists
                if game.image_filename:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], game.image_filename)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                # Save new image
                file_ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{file_ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                game.image_filename = filename
        
        db.session.commit()
        flash(f'Game "{game.name}" updated successfully!', 'success')
        return redirect(url_for('game_detail', game_id=game_id))
    
    # Check if game has any play records
    has_play_records = PlayRecord.query.filter_by(game_id=game_id).count() > 0
    
    return render_template('edit_game.html', game=game, has_play_records=has_play_records)

@app.route('/scrape_game_data', methods=['POST'])
def scrape_game_data():
    """Manual scraping endpoint for missing game data - form fields only"""
    game_name = request.json.get('game_name', '').strip()
    if not game_name:
        return {'error': 'Game name is required'}, 400
    
    try:
        scraped_info = scrape_arcade_info(game_name)
        
        # Return the scraped data
        response_data = {
            'manufacturer': scraped_info.get('manufacturer', ''),
            'year': scraped_info.get('year', ''),
            'genre': scraped_info.get('genre', ''),
            'has_image': bool(scraped_info.get('image_filename'))
        }
        
        return response_data
        
    except Exception as e:
        return {'error': f'Scraping failed: {str(e)}'}, 500

@app.route('/update_game_image/<int:game_id>', methods=['POST'])
def update_game_image(game_id):
    """Update a game's screenshot by scraping from the web"""
    game = Game.query.get_or_404(game_id)
    
    try:
        scraped_info = scrape_arcade_info(game.name)
        image_filename = scraped_info.get('image_filename')
        
        if image_filename:
            # Delete old image if exists
            if game.image_filename:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], game.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            # Update game with new image
            game.image_filename = image_filename
            db.session.commit()
            
            return {'success': True, 'message': 'Game screenshot updated successfully!'}
        else:
            return {'success': False, 'message': 'No game screenshot found for this game'}
            
    except Exception as e:
        return {'error': f'Failed to update screenshot: {str(e)}'}, 500

@app.route('/delete_game/<int:game_id>', methods=['POST'])
def delete_game(game_id):
    """Delete a game and all associated records"""
    game = Game.query.get_or_404(game_id)
    
    try:
        # Delete associated image file if it exists
        if game.image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], game.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
                print(f"Deleted image file: {game.image_filename}")
        
        # Delete all play records (cascade should handle this, but being explicit)
        PlayRecord.query.filter_by(game_id=game_id).delete()
        
        # Delete all maintenance records (cascade should handle this, but being explicit)
        MaintenanceRecord.query.filter_by(game_id=game_id).delete()
        
        # Store game name for flash message
        game_name = game.name
        
        # Delete the game itself
        db.session.delete(game)
        db.session.commit()
        
        flash(f'Game "{game_name}" has been successfully deleted along with all its records.', 'success')
        return redirect(url_for('games_list'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting game: {str(e)}', 'error')
        return redirect(url_for('game_detail', game_id=game_id))

@app.route('/add_game', methods=['GET', 'POST'])
def add_game():
    if request.method == 'POST':
        game_name = request.form['name']
        
        # Auto-lookup manufacturer, year, and genre if not provided
        manufacturer = request.form.get('manufacturer')
        year = request.form.get('year')
        genre = request.form.get('genre')
        
        scraped_info = None
        if not manufacturer or not year or not genre:
            scraped_info = scrape_arcade_info(game_name)
            if not manufacturer:
                manufacturer = scraped_info.get('manufacturer')
            if not year and scraped_info.get('year'):
                year = scraped_info.get('year')
            if not genre:
                genre = scraped_info.get('genre')
        
        # Handle file upload or use auto-downloaded image
        image_filename = None
        if 'cabinet_image' in request.files:
            file = request.files['cabinet_image']
            if file and file.filename != '' and allowed_file(file.filename):
                # Generate unique filename
                file_ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{file_ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_filename = filename
        
        # If no manual upload, try to use auto-downloaded image
        if not image_filename and scraped_info and scraped_info.get('image_filename'):
            image_filename = scraped_info.get('image_filename')
        
        game = Game(
            name=game_name,
            manufacturer=manufacturer,
            year=int(year) if year else None,
            genre=genre,
            location=request.form.get('location', 'Warehouse'),
            floor_position=request.form.get('floor_position') if request.form.get('location') == 'Floor' else None,
            warehouse_section=request.form.get('warehouse_section') if request.form.get('location') == 'Warehouse' else None,
            status=request.form.get('status', 'Working'),
            coins_per_play=float(request.form.get('coins_per_play', 0.25)),
            notes=request.form.get('notes'),
            image_filename=image_filename
        )
        db.session.add(game)
        db.session.commit()
        
        # Handle baseline plays if provided
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
        if manufacturer or year:
            success_msg += f' (Auto-filled: {manufacturer} {year})'
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
def record_plays(game_id):
    game = Game.query.get_or_404(game_id)
    
    # Get the most recent coin count for this game
    last_record = PlayRecord.query.filter_by(game_id=game_id).order_by(PlayRecord.date_recorded.desc()).first()
    last_coin_count = last_record.coin_count if last_record else 0
    
    if request.method == 'POST':
        current_coin_count = int(request.form['coin_count'])
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
def game_detail(game_id):
    game = Game.query.get_or_404(game_id)
    recent_records = PlayRecord.query.filter_by(game_id=game_id).order_by(PlayRecord.date_recorded.desc()).limit(10).all()
    maintenance_records = MaintenanceRecord.query.filter_by(game_id=game_id).order_by(MaintenanceRecord.date_reported.desc()).all()
    return render_template('game_detail.html', game=game, recent_records=recent_records, maintenance_records=maintenance_records)

@app.route('/maintenance/<int:game_id>', methods=['GET', 'POST'])
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

@app.route('/reports')
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
                         worst_performers=worst_performers)

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
        # Make game.date_added timezone-aware if it's naive
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue_avg = game.total_revenue / days_active
        performers.append({
            'game': game,
            'daily_revenue': daily_revenue_avg,
            'total_revenue': game.total_revenue
        })
    top_performers = sorted(performers, key=lambda x: x['daily_revenue'], reverse=True)
    
    # Status distribution
    status_distribution = Counter(game.status for game in all_games)
    
    # Location distribution  
    location_distribution = Counter(game.location for game in all_games)
    
    return render_template('graphs.html',
                         total_games=total_games,
                         total_plays=total_plays,
                         total_revenue=total_revenue,
                         floor_games=floor_games,
                         daily_revenue=daily_revenue,
                         top_performers=top_performers,
                         status_distribution=status_distribution,
                         location_distribution=location_distribution)

@app.route('/export_report_debug')
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

@app.route('/export_csv')
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
