# GPIO Testing & Hardware Setup Guide

## Current Setup: Mock GPIO (Testing Mode) ✅

The skeeball system is currently configured to use **Mock GPIO** by default, which means:
- ✅ Works on any computer (no Raspberry Pi required)
- ✅ No physical hardware needed
- ✅ Perfect for development and testing
- ✅ Simulates GPIO button presses via web interface

## Quick Start - Testing Now

1. **Start the application:**
```bash
python app.py
```

2. **Log in and access skeeball:**
   - Navigate to http://localhost:5000/
   - Log in with your credentials
   - Go to http://localhost:5000/skeeball/

3. **Test with simulated GPIO:**
   - Click "🎮 GPIO Testing" card
   - OR go directly to http://localhost:5000/skeeball/gpio-test
   - Click buttons to simulate hardware switches being pressed
   - Watch the game state update in real-time

## GPIO Test Interface Features

The GPIO test page (`/skeeball/gpio-test`) lets you simulate:

| Button | Description | Real Hardware Equivalent |
|--------|-------------|-------------------------|
| 💰 Coin Switch | Insert a coin/credit | Physical coin acceptor switch |
| ⊕ 10-Point Switch | Score 10 points | Ball landing in 10-point hole |
| ⊕⊕ 50-Point Switch | Score 50 points | Ball landing in 50-point hole |
| 🏌️ Lane Track Switch | Ball on lane track | Ball rolling down lane sensor |
| 🎱 Ball Counter Switch | Count a ball | Ball return counter |
| 🔄 Reset Game | Reset the game | Manual reset |

### Features:
- **Live Game State Display** - See credits, score, balls, status in real-time
- **Event Log** - Monitor all GPIO events with timestamps
- **Mode Switching** - Toggle between mock and real GPIO
- **Auto-Refresh** - Game state updates every 2 seconds

## Switching to Real Hardware

When you're ready to connect actual Raspberry Pi GPIO:

### Option 1: Use the Web Interface (Easiest)
1. Go to http://localhost:5000/skeeball/gpio-test
2. Click "Switch to Real Hardware" button
3. System will attempt to use real GPIO
4. If no GPIO hardware available, it will stay in mock mode

### Option 2: Edit Configuration File
Edit `.env.skeeball` in the arcade-tracker directory:
```bash
# Change this line:
USE_REAL_GPIO=false

# To this:
USE_REAL_GPIO=true
```

Then restart the application:
```bash
python app.py
```

### Option 3: Environment Variable
```bash
export USE_REAL_GPIO=true
python app.py
```

## Hardware Requirements (for Real GPIO)

When using real hardware, you'll need:

### Single Lane Setup:
- **Raspberry Pi 4** (or any Pi with GPIO)
- **GPIO Pins** configured in `config.py`:
  - Coin acceptor switch
  - Score detection switches (10-point, 50-point)
  - Lane track sensor
  - Ball counter sensor
- **Pull-down resistors** (or use internal pull-downs)
- **Proper wiring** following safety guidelines

### GPIO Pin Configuration

Edit `config.py` to match your wiring:
```python
PINS = {
    "coin": 17,              # Coin acceptor
    "score_10": [18, 23],    # 10-point holes (multiple)
    "score_50": [24],        # 50-point hole
    "lane_track": 25,        # Ball on lane sensor
    "ball_count": 27,        # Ball counter
}
```

## Testing Workflow

### 1. Development (Current Setup)
- Use mock GPIO on any computer
- Test game logic without hardware
- Develop UI and features
- Simulate complete game flows

### 2. Hardware Integration
- Wire GPIO pins on Raspberry Pi
- Update `config.py` with correct pin numbers
- Switch to real GPIO mode
- Test individual switches
- Verify event triggering

### 3. Production Deployment
- Connect to actual skeeball machine
- Mount Raspberry Pi securely
- Route wires safely
- Test complete gameplay
- Monitor for issues

## Troubleshooting

### Mock GPIO Mode Not Working
```bash
# Check if gpiozero is installed
python -c "import gpiozero; print('✅ gpiozero installed')"

# If not installed:
pip install gpiozero
```

### Can't Switch to Real GPIO
**Error:** "Real GPIO requested but failed"

**Solution:** This is normal when not on a Raspberry Pi. The system will automatically fall back to mock mode. Only Raspberry Pi hardware supports real GPIO.

### GPIO Test Page Not Loading
```bash
# Verify template exists
ls templates/skeeball/gpio_test.html

# Check app logs for errors
# Look for 404 or template errors
```

### Buttons Not Responding
- Check browser console for JavaScript errors (F12)
- Verify you're logged in
- Check network tab for failed API calls
- Restart the Flask application

## API Endpoints for GPIO Control

You can also control GPIO programmatically:

### Check GPIO Status
```bash
curl http://localhost:5000/skeeball/api/gpio/status
```

Response:
```json
{
  "mode": "mock",
  "description": "Mock GPIO (testing mode)",
  "hardware_required": false,
  "testing_mode": true
}
```

### Switch GPIO Mode
```bash
# Switch to mock
curl -X POST http://localhost:5000/skeeball/api/gpio/switch-mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "mock"}'

# Switch to real (requires Raspberry Pi)
curl -X POST http://localhost:5000/skeeball/api/gpio/switch-mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "real"}'
```

### Trigger GPIO Events
```bash
# Insert coin
curl -X POST http://localhost:5000/skeeball/api/simulator/insert-coin \
  -H "Content-Type: application/json" \
  -d '{"lane_id": "lane_1"}'

# Score 10 points
curl -X POST http://localhost:5000/skeeball/api/simulator/score-10 \
  -H "Content-Type: application/json" \
  -d '{"lane_id": "lane_1"}'
```

## Multi-Lane Support

For multiple skeeball machines:
- Each machine gets its own Pi Pico with GPIO
- Pi Picos connect via USB to main Pi 4
- See `MULTI_LANE_ARCHITECTURE.md` for details
- Mock GPIO still works for testing multi-lane setups

## Safety Notes

When connecting real hardware:
- ⚠️ Use proper voltage levels (3.3V for GPIO)
- ⚠️ Add protective resistors
- ⚠️ Avoid short circuits
- ⚠️ Test with multimeter before connecting
- ⚠️ Follow electrical safety guidelines
- ⚠️ Consider using optocouplers for isolation

## Next Steps

1. **Right Now:** Test with mock GPIO using the web interface
2. **When Ready:** Wire up GPIO on Raspberry Pi
3. **Then:** Switch to real hardware mode
4. **Finally:** Deploy to actual skeeball machine

## Support

- **GPIO Test Interface:** http://localhost:5000/skeeball/gpio-test
- **Full Simulator:** http://localhost:5000/skeeball/simulator
- **Documentation:** See `DEPLOYMENT_CHECKLIST.md` and `FLASK_INTEGRATION.md`

---

**Current Status:** Mock GPIO enabled ✅  
**Hardware Required:** No ✅  
**Ready for Testing:** Yes ✅
