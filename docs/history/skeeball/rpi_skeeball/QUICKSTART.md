# Skeeball System - Quick Start

## What You Have

A complete **Raspberry Pi skeeball scoring system** that:
- ✅ Detects scores from 6 holes (10, 20, 30, 40, 50, 100 points)
- ✅ Tracks coin inserts and manages 9-ball games
- ✅ Awards bonus games for scores ≥ 360 points
- ✅ Displays scores on LED display (optional)
- ✅ Automatically syncs play data to your Flask arcade tracker
- ✅ Saves state (survives power outages)
- ✅ Works in simulation mode for testing without hardware

## Files Overview

```
rpi_skeeball/
├── skeeball_main.py      # Main program (429 lines)
├── test_game.py          # Test simulator
├── install.sh            # Auto-install script
├── requirements.txt      # Python dependencies
├── README.md             # Full documentation
├── WIRING.md             # Hardware wiring guide
└── QUICKSTART.md         # This file
```

## Transfer to Raspberry Pi

### Option 1: SCP (Over Network)
```bash
# From your dev machine (in arcade-tracker directory):
cd /home/jackiegreybard/arcade-tracker
scp -r rpi_skeeball/ pi@raspberrypi.local:~/
```

### Option 2: USB Drive
1. Copy `rpi_skeeball/` folder to USB drive
2. Plug USB into Raspberry Pi
3. Copy from USB: `cp -r /media/usb/rpi_skeeball ~/`

### Option 3: Git (if you use version control)
```bash
# On Pi:
git clone <your-repo-url>
cd arcade-tracker/rpi_skeeball
```

## Installation on Pi (5 Minutes)

```bash
# SSH into your Raspberry Pi
ssh pi@raspberrypi.local

# Navigate to directory
cd ~/rpi_skeeball

# Run auto-installer
bash install.sh

# Edit configuration
nano config.json
```

### Configuration Checklist

Edit these values in `config.json`:

1. **Server settings:**
   - `url`: Your Flask server IP (e.g., "http://192.168.1.100:5000")
   - `game_id`: The game ID from your database (check `/games` in web UI)
   - `username`: Login username (need at least "operator" role)
   - `password`: User password

2. **GPIO pins:** (optional - defaults should work)
   - Verify if using different pins for your hardware

3. **Game settings:** (optional)
   - `balls_per_game`: Default is 9
   - `bonus_threshold`: Default is 360 points

Save and exit: `Ctrl+X`, `Y`, `Enter`

## Testing

### 1. Test Without Hardware (Simulation)
```bash
python3 test_game.py
```

**Expected output:**
- Simulates 3 complete games
- Shows scoring for each ball
- Displays statistics
- Attempts to sync to server

### 2. Test With Hardware
```bash
python3 skeeball_main.py
```

**What to test:**
- Insert coin (or trigger GPIO 17) → Should start game
- Trigger each hole sensor → Should register score
- Complete 9 balls → Should end game and show stats
- Wait 5 minutes → Should sync to server

**Stop with:** `Ctrl+C` (will perform final sync)

## Running Permanently

### Set Up Autostart (Recommended)

```bash
# Create systemd service
sudo nano /etc/systemd/system/skeeball.service
```

**Paste this:**
```ini
[Unit]
Description=Skeeball Scoring System
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/rpi_skeeball
ExecStart=/usr/bin/python3 /home/pi/rpi_skeeball/skeeball_main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable skeeball.service
sudo systemctl start skeeball.service
```

**Check status:**
```bash
sudo systemctl status skeeball.service
```

**View live logs:**
```bash
journalctl -u skeeball.service -f
```

## Verifying Server Integration

### 1. Check Flask App Game ID

1. Open your arcade tracker web interface
2. Go to `/games`
3. Find your skeeball machine
4. Note the game ID (in URL when you click on it: `/game/1` means ID is 1)
5. Update `config.json` with correct `game_id`

### 2. Check User Permissions

1. In Flask app, go to admin panel
2. Verify your user has at least "operator" role
3. Test login: `python3 -c "from skeeball_main import SkeeballGame; g = SkeeballGame(); g.login()"`

### 3. Manual Test Sync

```python
python3
>>> from skeeball_main import SkeeballGame
>>> game = SkeeballGame()
>>> game.login()          # Should print "✅ Logged in to server"
>>> game.total_coins_inserted = 5  # Fake some coins
>>> game.sync_to_server()  # Should print "✅ Synced 5 coins to server"
```

### 4. Verify in Flask App

1. Go to your game detail page in Flask app
2. Check play records - should see new entry
3. Verify coin count matches

## Hardware Setup

See `WIRING.md` for complete details.

**Minimum wiring:**
1. Connect coin acceptor signal to GPIO 17
2. Connect 6 hole sensors to GPIO 22, 23, 24, 25, 27, 18
3. All sensors need common ground
4. Optional: TM1637 display to GPIO 5 (CLK) and 6 (DIO)

**Quick sensor test:**
```bash
# Test if GPIO 17 (coin sensor) is working
python3 -c "
import RPi.GPIO as GPIO
import time
GPIO.setmode(GPIO.BCM)
GPIO.setup(17, GPIO.IN, pull_up_down=GPIO.PUD_UP)
print('Watching GPIO 17 - trigger sensor or short to GND')
while True:
    if GPIO.input(17) == 0:
        print('TRIGGERED!')
        time.sleep(1)
    time.sleep(0.1)
"
```

## Troubleshooting

### Problem: "Config file not found"
**Solution:** Run the program once to generate it: `python3 skeeball_main.py`

### Problem: "Login failed"
**Solution:** 
- Check server URL is correct and reachable: `curl http://YOUR_SERVER:5000`
- Verify username/password in config.json
- Check Flask app logs for authentication errors

### Problem: "GPIO not available"
**Solution:** 
- Runs in simulation mode automatically
- On real Pi, install: `sudo apt install python3-rpi.gpio`

### Problem: Sensors not triggering
**Solution:**
- Check wiring (see WIRING.md)
- Test individual GPIO: See sensor test above
- Enable debug: Set `"debug": true` in config.json

### Problem: Multiple scores per ball
**Solution:** Increase debounce time in config.json: `"bounce_time_ms": 500`

### Problem: Won't sync to server
**Solution:**
- Check network: `ping YOUR_SERVER_IP`
- Check firewall: `sudo ufw status`
- Check Flask app is running: `curl http://YOUR_SERVER:5000/login`
- Check logs: `journalctl -u skeeball.service -n 50`

## How the System Works

### Game Flow
```
1. Player inserts coin
   ↓
2. System increments coin counter, starts game
   ↓
3. Player rolls balls (up to 9)
   ↓
4. System detects which hole each ball enters
   ↓
5. System updates score display
   ↓
6. After 9 balls:
   - If score ≥ 360: Award bonus game (goto step 2)
   - If score < 360: Game over, show stats
   ↓
7. Every 5 minutes: Sync total coins to Flask server
```

### Data Sync
- **Local storage:** `skeeball_state.json` (persists through reboot)
- **Server sync:** Every 300 seconds (configurable)
- **Sync payload:** Total cumulative coins since last sync
- **Flask handles:** Calculating plays from coin difference

### State Persistence
The system saves after every:
- Coin insertion
- Ball scored
- Game completion

If power is lost, it resumes with the same coin count.

## Customization Ideas

### Change Scoring
Edit `SCORE_VALUES` in `skeeball_main.py`:
```python
SCORE_VALUES = {
    'hole_10': 10,
    'hole_20': 25,    # Changed!
    'hole_30': 50,    # Changed!
    # ...
}
```

### Change Balls Per Game
In `config.json`:
```json
"balls_per_game": 12  // Instead of 9
```

### Add Sound Effects
Install pygame and add to `ball_scored()` function

### Add High Score Display
Modify `end_game()` to show high score on display

## Support Resources

- **Full docs:** `README.md`
- **Wiring:** `WIRING.md`
- **Hardware troubleshooting:** Raspberry Pi GPIO docs
- **Flask integration:** Check your arcade tracker WARP.md

## Next Steps

1. ✅ Transfer files to Pi
2. ✅ Run `install.sh`
3. ✅ Edit `config.json`
4. ✅ Test with `test_game.py`
5. ✅ Wire hardware (see WIRING.md)
6. ✅ Test with hardware
7. ✅ Set up autostart
8. ✅ Verify server sync
9. 🎮 Play skeeball!

**You're all set! Plug in the Pi and start playing!** 🎳
