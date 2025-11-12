# Skeeball Flask Integration Guide

## Overview
This guide shows how to integrate the skeeball control system into your arcade-tracker Flask app.

## Quick Start

### 1. Copy Skeeball Files to Arcade-Tracker

Copy these files from `/home/jackiegreybard/Skeeball/` to your arcade-tracker directory:

```bash
# Core modules
cp game_logic.py /path/to/arcade-tracker/
cp config.py /path/to/arcade-tracker/skeeball_config.py
cp input_manager.py /path/to/arcade-tracker/
cp lane_controller.py /path/to/arcade-tracker/
cp lane_manager.py /path/to/arcade-tracker/
cp serial_bridge.py /path/to/arcade-tracker/
cp skeeball_routes.py /path/to/arcade-tracker/

# Templates
cp -r templates/skeeball /path/to/arcade-tracker/templates/
```

### 2. Update Arcade-Tracker app.py

In your arcade-tracker `app.py`, add after Flask app initialization:

```python
# Near other imports
from skeeball_routes import register_skeeball_routes

# After app = Flask(__name__)
register_skeeball_routes(app)
```

Example placement in `app.py`:

```python
from flask import Flask, ...
from skeeball_routes import register_skeeball_routes  # ADD THIS

app = Flask(__name__)
csrf = CSRFProtect(app)

# ... other config ...

register_skeeball_routes(app)  # ADD THIS

# ... rest of app ...
```

### 3. Update requirements.txt

Add if not already present:

```
pyserial>=3.5
gpiozero>=2.0
```

Then install:

```bash
pip install -r requirements.txt
```

### 4. Create Skeeball Config (Optional)

If you want custom GPIO pins, create `skeeball_config.py` in your arcade-tracker:

```python
# Customize GPIO pins if needed (default is already configured)
POINT_VALUES = {
    "score_10": 10,
    "score_50": 50,
    "lane_track": 50,
}

TOTAL_BALLS = 9
BOUNCE_TIME = 0.1
```

## Access the Skeeball Interface

Once integrated, access via:

- **Main Hub**: `http://localhost:5000/skeeball/`
- **Simulator**: `http://localhost:5000/skeeball/simulator`
- **Control Panel**: `http://localhost:5000/skeeball/control`
- **Statistics**: `http://localhost:5000/skeeball/stats`

## API Endpoints

All endpoints require login. Base URL: `/skeeball/api`

### Get Lanes
```bash
GET /lanes
# Returns: { "lane_1": {...}, "lane_2": {...} }
```

### Get Lane Status
```bash
GET /lanes/<lane_id>/status
# Returns: { "credits": 2, "score": 150, "balls": 3, ... }
```

### Trigger Event
```bash
POST /lanes/<lane_id>/trigger
Body: { "event": "coin", "data": null }
# or
Body: { "event": "score", "data": "score_10" }
```

### Reset Lane
```bash
POST /lanes/<lane_id>/reset
```

### Get Lane Stats
```bash
GET /lanes/<lane_id>/stats
# Returns: { "total_games": 10, "best_score": 450, ... }
```

### Simulate Roll Outcome
```bash
POST /roll-outcome
Body: { "lane_id": "lane_1", "outcome": "100" }
# Outcomes: "Miss", "10", "20", "30", "40", "50", "100"
```

## Features

### 🎮 Simulator
Interactive testing interface with:
- Live game state display
- Manual control buttons (coin, score, ball)
- Roll outcome simulator (Miss through 100 points)
- Event log with timestamps

### 📊 Control Panel
Real-time dashboard showing:
- All active lanes
- Current credits, score, balls
- Lane online/offline status
- Quick actions (coin insert, reset)

### 📈 Statistics
Performance tracking:
- Total games played per lane
- Best score
- Average score
- Total coins inserted
- Real-time status updates

## Multi-Lane Setup

To add more lanes:

### Local GPIO Lane (Direct on Raspberry Pi)
```python
from lane_manager import LaneManager
from input_manager import InputManager

manager = get_lane_manager()
input_mgr = InputManager(lambda e, d: None)  # Your GPIO handler
manager.register_local_lane("lane_1", input_mgr)
```

### Remote Serial Lane (Pi Pico)
```python
manager.register_serial_lane("lane_2", port="/dev/ttyUSB0")
```

### Auto-Discovery
```python
manager = LaneManager(auto_discover=True)  # Automatically finds Pi Picos
manager.start_polling()  # Start listening for events
```

## Troubleshooting

### "Lane not found" errors
- Ensure `lane_manager` is initialized in `get_lane_manager()`
- Check lane_id matches exactly (case-sensitive)

### GPIO not working
- Install gpiozero: `pip install gpiozero`
- Run on Raspberry Pi or use MockFactory for testing
- Check pin configuration in config.py

### Serial connection issues
- Install pyserial: `pip install pyserial`
- Check Pi Pico is connected: `ls /dev/ttyUSB*`
- Verify baudrate (default 115200)

### Missing templates
- Ensure `templates/skeeball/` directory exists
- Check files: `index.html`, `simulator.html`, `control.html`, `stats.html`

## Environment Variables

Optional configuration via environment:

```bash
# Example: .env
SKEEBALL_AUTO_DISCOVER=true
SKEEBALL_POLL_INTERVAL=100  # ms
SKEEBALL_DEBUG=true
```

## Database Integration (Optional)

To save skeeball game data to arcade.db:

```python
# In skeeball_routes.py, import your User/Game models
from models import db, User, Game

# After game ends, save stats
game_record = GameRecord(
    user_id=current_user.id,
    lane_id=lane_id,
    score=lane.game.score,
    timestamp=datetime.now()
)
db.session.add(game_record)
db.session.commit()
```

## Future Enhancements

- [ ] WebSocket support for real-time updates
- [ ] Player high score leaderboard
- [ ] Game history tracking
- [ ] Revenue analytics
- [ ] Maintenance alerts for lanes
- [ ] Photo capture during gameplay
- [ ] Integration with arcade-tracker maintenance system
