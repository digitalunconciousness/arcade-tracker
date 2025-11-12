# 🎳 Skeeball Flask Integration - Deployment Checklist

## Pre-Deployment

### Files Ready
✅ Core Python modules created:
- [x] `game_logic.py` - Refactored with lane_id
- [x] `input_manager.py` - GPIO handler (original)
- [x] `config.py` - Pin configuration (original)
- [x] `lane_controller.py` - NEW: Per-lane wrapper
- [x] `lane_manager.py` - NEW: Multi-lane coordinator
- [x] `serial_bridge.py` - NEW: Pi Pico communication
- [x] `skeeball_routes.py` - NEW: Flask integration

✅ HTML Templates created:
- [x] `templates/skeeball/index.html` - Main hub
- [x] `templates/skeeball/simulator.html` - Interactive testing
- [x] `templates/skeeball/control.html` - Lane dashboard
- [x] `templates/skeeball/stats.html` - Statistics

✅ Documentation created:
- [x] `MULTI_LANE_ARCHITECTURE.md` - Design overview
- [x] `FLASK_INTEGRATION.md` - Integration guide
- [x] `FLASK_READY.md` - Deployment summary
- [x] `DEPLOYMENT_CHECKLIST.md` - This file

✅ Optional/Future:
- [x] `pico_firmware.py` - Pi Pico MicroPython template

## Integration Steps

### Step 1: Copy to Arcade-Tracker Directory
```bash
cd /path/to/arcade-tracker

# Copy Python modules
cp /home/jackiegreybard/Skeeball/game_logic.py .
cp /home/jackiegreybard/Skeeball/input_manager.py .
cp /home/jackiegreybard/Skeeball/lane_controller.py .
cp /home/jackiegreybard/Skeeball/lane_manager.py .
cp /home/jackiegreybard/Skeeball/serial_bridge.py .
cp /home/jackiegreybard/Skeeball/skeeball_routes.py .
cp /home/jackiegreybard/Skeeball/config.py ./skeeball_config.py

# Copy templates
mkdir -p templates/skeeball
cp /home/jackiegreybard/Skeeball/templates/skeeball/* templates/skeeball/

# Verify all files copied
ls -la | grep -E "(game_logic|input_manager|lane_|serial|skeeball_routes)"
ls templates/skeeball/
```

**Checklist:**
- [ ] All Python files in arcade-tracker root
- [ ] All HTML files in templates/skeeball/
- [ ] No import errors when listing files

### Step 2: Update app.py

Add at the top with other imports:
```python
from skeeball_routes import register_skeeball_routes
```

Add after `app = Flask(__name__)`:
```python
register_skeeball_routes(app)
```

**Checklist:**
- [ ] Import statement added
- [ ] `register_skeeball_routes(app)` called
- [ ] No syntax errors in app.py
- [ ] app.py still runs without errors

### Step 3: Install Dependencies

```bash
# In arcade-tracker venv
pip install pyserial>=3.5 gpiozero>=2.0

# Or add to requirements.txt and reinstall
echo "pyserial>=3.5" >> requirements.txt
echo "gpiozero>=2.0" >> requirements.txt
pip install -r requirements.txt
```

**Checklist:**
- [ ] pyserial installed
- [ ] gpiozero installed
- [ ] No import errors: `python -c "import serial; import gpiozero"`

### Step 4: Test Flask App

```bash
# Start arcade-tracker
python app.py

# In another terminal, test
curl -I http://localhost:5000/skeeball/
# Should return 302 or 200 (may redirect to login)
```

**Checklist:**
- [ ] Flask app starts without errors
- [ ] `/skeeball/` endpoint exists
- [ ] Can navigate to login
- [ ] No missing template errors

### Step 5: Test Skeeball UI

1. Log into arcade-tracker
2. Navigate to `http://localhost:5000/skeeball/`
3. Click "Launch Simulator"
4. Test buttons:
   - [ ] "Refresh" button works
   - [ ] "💰 Coin" button adds credit
   - [ ] "⊕ +10" button adds 10 points
   - [ ] "⊕ +50" button adds 50 points
   - [ ] "🏌️ Lane" button adds 50 points
   - [ ] "🎱 Ball" button increments ball count
   - [ ] Roll outcome buttons work (10, 20, 30, 40, 50, 100)
   - [ ] Event log appears and updates
   - [ ] "🔄 Reset" button resets game

**Checklist:**
- [ ] All buttons functional
- [ ] UI responds to clicks
- [ ] Game state updates in real-time
- [ ] Event log displays events with timestamps

### Step 6: Test Control Panel

1. Navigate to `http://localhost:5000/skeeball/control`
2. Verify:
   - [ ] Lane cards display
   - [ ] Status shows correctly (Ready/Playing/Offline)
   - [ ] Coin button works
   - [ ] Reset button works
   - [ ] Panel refreshes every 2 seconds

### Step 7: Test Statistics

1. Navigate to `http://localhost:5000/skeeball/stats`
2. Play a few games in simulator
3. Verify:
   - [ ] Total games increases
   - [ ] Best score tracks correctly
   - [ ] Average score calculates
   - [ ] Stats update after each game

## Hardware Testing (Optional)

### Single Lane GPIO Testing
1. Verify GPIO pins configured in `config.py`
2. Connect physical switches to pins
3. Test each pin manually
4. Verify events trigger in Flask UI

**Checklist:**
- [ ] GPIO pins correct
- [ ] Switches connected
- [ ] Events appear in event log
- [ ] Scores update correctly

### Multi-Lane Pi Pico Testing
1. Flash `pico_firmware.py` to Pi Pico
2. Create `config.json` on Pico with lane_id
3. Connect Pi Pico via USB
4. Check Flask logs for discovery
5. Verify lane appears in control panel

**Checklist:**
- [ ] Pico firmware flashed
- [ ] config.json created on Pico
- [ ] Pico connected via USB
- [ ] Lane auto-discovered
- [ ] Events trigger from Pico

## Troubleshooting

### Simulator UI Not Loading
```bash
# Check templates exist
ls templates/skeeball/
# Should show: control.html, index.html, simulator.html, stats.html

# Check for template errors in Flask logs
# Look for Jinja2 template errors
```

**Solution:**
- Verify all 4 HTML files in templates/skeeball/
- Check for typos in file paths
- Clear browser cache (Ctrl+Shift+Delete)

### API Returns 404
```bash
# Verify blueprint registered
curl http://localhost:5000/skeeball/api/lanes
# Should return JSON, not 404
```

**Solution:**
- Verify `register_skeeball_routes(app)` in app.py
- Check Flask app is restarted after changes
- Verify `/skeeball/` prefix in routes

### GPIO Not Working
```python
# In app context, check:
from lane_manager import LaneManager
manager = LaneManager(auto_discover=False)
manager.register_local_lane("lane_1", None)
lanes = manager.get_all_status()
print(lanes)
```

**Solution:**
- Check config.py pins are correct
- Verify gpiozero installed: `python -c "import gpiozero"`
- Use MockFactory for testing without hardware
- Check GPIO pin permissions (may need sudo on Pi)

### Lane Not Found
```bash
# Check registered lanes
curl http://localhost:5000/skeeball/api/lanes
# Should show lane_1 at minimum
```

**Solution:**
- Verify `lane_manager` initialized in `get_lane_manager()`
- Check lane_id spelling (case-sensitive)
- Verify lane created before use

## Performance Checklist

### Response Times
- [ ] Simulator status updates in <100ms
- [ ] Control panel refreshes smoothly every 2 seconds
- [ ] API endpoints respond in <50ms
- [ ] Roll outcome sequences complete smoothly

### Load Testing
- [ ] System handles rapid button clicks
- [ ] No memory leaks after 1 hour of use
- [ ] Serial connections stable for Pi Picos

**Test with:**
```bash
# Rapid clicks test
for i in {1..100}; do
  curl -X POST http://localhost:5000/skeeball/api/simulator/insert-coin \
    -H "Content-Type: application/json" \
    -d '{"lane_id": "lane_1"}'
done
```

## Security Checklist

- [ ] All routes require `@login_required`
- [ ] No SQL injection in database queries (if added)
- [ ] API validates lane_id input
- [ ] CSRF protection enabled (inherited from app)
- [ ] No sensitive data in logs

## Deployment Ready

**Final Verification:**
- [ ] All files copied to arcade-tracker
- [ ] app.py modified correctly
- [ ] Dependencies installed
- [ ] Flask app starts without errors
- [ ] UI loads and is functional
- [ ] All buttons work as expected
- [ ] Event log displays events
- [ ] Control panel shows lanes
- [ ] Statistics track correctly
- [ ] Documentation is available

## Go Live Checklist

1. [ ] Backup arcade.db
2. [ ] Test in dev environment
3. [ ] Review error logs
4. [ ] Connect GPIO pins (if using hardware)
5. [ ] Test one complete game flow
6. [ ] Verify statistics record correctly
7. [ ] Deploy to production server

## Post-Deployment

### Monitoring
- [ ] Check logs for errors: `tail -f /path/to/logs/*.log`
- [ ] Monitor performance metrics
- [ ] Track GPIO event timing
- [ ] Monitor serial connections for Pi Picos

### Maintenance
- [ ] Backup game statistics regularly
- [ ] Test GPIO pins weekly
- [ ] Check Pi Pico connections if used
- [ ] Review performance trends

## Rollback Plan

If issues occur:
1. Stop arcade-tracker
2. Remove skeeball files
3. Revert app.py changes
4. Restart arcade-tracker

```bash
# Quick rollback
rm -f game_logic.py input_manager.py lane_*.py serial_bridge.py skeeball_routes.py
git checkout app.py  # If using git
# Restart Flask app
```

---

## Status Summary

| Item | Status | Notes |
|------|--------|-------|
| Python modules | ✅ Ready | All 7 files created |
| HTML templates | ✅ Ready | 4 templates in templates/skeeball/ |
| Documentation | ✅ Ready | 3 comprehensive guides |
| Testing | ✅ Complete | Tested with mock GPIO |
| Flask integration | ✅ Ready | Blueprint pattern ready |
| Multi-lane support | ✅ Ready | Extensible architecture |
| Pi Pico firmware | ✅ Ready | Template provided |

**Overall Status: READY FOR DEPLOYMENT** 🚀
