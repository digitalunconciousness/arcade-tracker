# 🎳 Skeeball Flask Integration - Ready to Deploy

## What You Have

Complete skeeball control system with **interactive Flask UI** built in. All testing functionality from `ui_simulator.py` is now available as web pages.

## Files Created

### Core Modules (Ready to copy to arcade-tracker)
- **`skeeball_routes.py`** - Flask blueprint with all routes and API endpoints
- **`lane_manager.py`** - Multi-lane coordinator (already completed)
- **`lane_controller.py`** - Per-lane wrapper (already completed)
- **`serial_bridge.py`** - Pi Pico communication layer (already completed)
- **`game_logic.py`** - Updated with lane_id support (already completed)

### HTML Templates (in `templates/skeeball/`)
- **`index.html`** - Main hub with links to all features
- **`simulator.html`** - Interactive testing UI (matches ui_simulator.py features)
  - Live game state display
  - Manual control buttons (💰 Coin, ⊕ +10, ⊕ +50, 🏌️ Lane, 🎱 Ball)
  - Roll outcome simulator (Miss, 10, 20, 30, 40, 50, 100 points)
  - Event log with timestamps
  - Real-time status refresh

- **`control.html`** - Multi-lane control panel
  - Active lane display
  - Current credits, score, balls
  - Online/offline status
  - Quick actions (coin, reset)
  
- **`stats.html`** - Statistics dashboard
  - Total games played
  - Best score per lane
  - Average score
  - Total coins inserted
  - Live status updates

### Documentation
- **`FLASK_INTEGRATION.md`** - Step-by-step integration guide
- **`MULTI_LANE_ARCHITECTURE.md`** - Scalable architecture overview
- **`FLASK_READY.md`** - This file

## Quick Integration

### 1. Copy Files (5 minutes)
```bash
cd /path/to/arcade-tracker

# Core Python modules
cp /home/jackiegreybard/Skeeball/game_logic.py .
cp /home/jackiegreybard/Skeeball/input_manager.py .
cp /home/jackiegreybard/Skeeball/lane_controller.py .
cp /home/jackiegreybard/Skeeball/lane_manager.py .
cp /home/jackiegreybard/Skeeball/serial_bridge.py .
cp /home/jackiegreybard/Skeeball/skeeball_routes.py .
cp /home/jackiegreybard/Skeeball/config.py .

# Templates
mkdir -p templates/skeeball
cp -r /home/jackiegreybard/Skeeball/templates/skeeball/* templates/skeeball/
```

### 2. Update app.py (1 minute)
Add these lines to your `app.py`:

```python
# At top with other imports
from skeeball_routes import register_skeeball_routes

# After app = Flask(__name__)
register_skeeball_routes(app)
```

### 3. Install Dependencies (2 minutes)
```bash
pip install pyserial>=3.5 gpiozero>=2.0
```

### 4. Access the UI
- Main Hub: `http://localhost:5000/skeeball/`
- Simulator: `http://localhost:5000/skeeball/simulator`
- Control: `http://localhost:5000/skeeball/control`
- Stats: `http://localhost:5000/skeeball/stats`

**Total setup time: ~8 minutes**

## Features Available

### 🎮 Simulator (Matches ui_simulator.py)
✅ Live game state (credits, score, balls)
✅ Manual controls (coin, score_10, score_50, lane_track, ball_scored)
✅ Roll outcome buttons (Miss through 100 points)
✅ Event log with timestamps
✅ Auto-refresh every 500ms
✅ Reset button

### 📊 Control Panel
✅ View all active lanes
✅ See current status of each lane
✅ Quick coin insert button
✅ Quick reset button
✅ Online/offline status
✅ Auto-refresh every 2 seconds

### 📈 Statistics
✅ Total games played per lane
✅ Best score per lane
✅ Average score
✅ Total coins inserted
✅ Real-time status

### 🔌 API Endpoints
```
GET  /skeeball/api/lanes                    - List all lanes
GET  /skeeball/api/lanes/<id>/status        - Get lane status
GET  /skeeball/api/lanes/<id>/stats         - Get lane statistics
POST /skeeball/api/lanes/<id>/trigger       - Trigger event (testing)
POST /skeeball/api/lanes/<id>/reset         - Reset lane
POST /skeeball/api/roll-outcome             - Simulate roll outcome
POST /skeeball/api/simulator/insert-coin    - Insert coin
POST /skeeball/api/simulator/score-10       - Score 10 points
POST /skeeball/api/simulator/score-50       - Score 50 points
POST /skeeball/api/simulator/lane-track     - Lane track
POST /skeeball/api/simulator/ball-scored    - Count ball
```

## Authentication
All routes require login (inherited from arcade-tracker)

## Testing Without Hardware

### Option 1: Use Simulator UI
Just navigate to `/skeeball/simulator` - no GPIO needed

### Option 2: Use Mock GPIO
```python
from gpiozero import Device
from gpiozero.pins.mock import MockFactory

Device.pin_factory = MockFactory()
# Now run your app - GPIO calls use mocks
```

### Option 3: Use API Directly
```bash
# Insert coin
curl -X POST http://localhost:5000/skeeball/api/simulator/insert-coin \
  -H "Content-Type: application/json" \
  -d '{"lane_id": "lane_1"}'

# Score 100 (via roll outcome)
curl -X POST http://localhost:5000/skeeball/api/roll-outcome \
  -H "Content-Type: application/json" \
  -d '{"lane_id": "lane_1", "outcome": "100"}'
```

## Production Deployment

### Single Lane (Current Setup)
- Pi 4 runs arcade-tracker with skeeball
- GPIO pins connected directly
- `lane_manager` auto-initializes with `lane_1`

### Two Lanes
- Pi 4 runs arcade-tracker (lane_1 + coordinator)
- Pi Pico on USB (lane_2)
- Auto-discovery finds and registers lane_2

### N Lanes
- Pi 4 runs coordinator only
- Multiple Pi Picos on USB
- All lanes auto-discovered and registered

## Architecture

```
arcade-tracker (Flask)
    ↓
skeeball_routes.py (Blueprints & API)
    ↓
lane_manager.py (Coordinator)
    ├── lane_controller.py (lane_1 - local GPIO)
    ├── lane_controller.py (lane_2 - serial)
    └── lane_controller.py (lane_N - serial)
        ↓
    game_logic.py (Game state per lane)
```

## Next Steps

1. ✅ Copy files to arcade-tracker
2. ✅ Update app.py
3. ✅ Run arcade-tracker
4. ✅ Access `/skeeball/simulator`
5. ✅ Test with UI
6. ✅ (Later) Connect actual GPIO pins
7. ✅ (Later) Add Pi Picos for additional lanes

## Support

### Simulator Not Working?
- Check Flask is running
- Verify you're logged in
- Browser console for errors

### API Returns 404?
- Check blueprint is registered in app.py
- Verify `/skeeball/` prefix in routes

### GPIO Not Triggering Events?
- On Pi 4: Check pin configuration
- On dev machine: Use MockFactory
- Check `input_manager.py` is working

## Files Summary

```
/home/jackiegreybard/Skeeball/
├── game_logic.py              ← Core game logic (lane_id ready)
├── input_manager.py           ← GPIO handler
├── config.py                  ← Pin config
├── lane_controller.py         ← Per-lane wrapper
├── lane_manager.py            ← Multi-lane coordinator
├── serial_bridge.py           ← Pi Pico communication
├── skeeball_routes.py         ← Flask integration
├── pico_firmware.py           ← Pi Pico MicroPython
├── templates/skeeball/
│   ├── index.html            ← Main hub
│   ├── simulator.html        ← Testing UI
│   ├── control.html          ← Lane dashboard
│   └── stats.html            ← Statistics
├── MULTI_LANE_ARCHITECTURE.md ← Design doc
├── FLASK_INTEGRATION.md       ← Integration steps
└── FLASK_READY.md            ← This file
```

## Status

✅ Single lane simulator ready
✅ Multi-lane architecture designed
✅ Flask UI complete with all testing features
✅ API endpoints implemented
✅ Ready for arcade-tracker integration
✅ Ready for GPIO hardware
✅ Ready for Pi Pico expansion

**You're ready to integrate!**
