# Skeeball System for Raspberry Pi

Complete skeeball scoring system that tracks games locally and syncs data to your arcade tracker Flask app.

## Features

- ✅ Automatic scoring for 6 holes (10, 20, 30, 40, 50, 100 points)
- 🎮 Full game management (9 balls per game, bonus games)
- 💰 Coin counter integration
- 📊 Score display (TM1637 4-digit LED or console)
- 🌐 Automatic sync to Flask server
- 💾 Persistent state (survives power loss)
- 🧪 Simulation mode for testing

## Hardware Requirements

### Minimum Setup
- Raspberry Pi (any model with GPIO)
- MicroSD card (8GB+)
- Power supply
- Coin acceptor/switch
- 6x infrared break-beam sensors (for score holes)
- Breadboard and jumper wires

### Optional Display
- TM1637 4-digit 7-segment display

### Wiring Example

**Default GPIO Pins** (configurable in `config.json`):
```
Coin Sensor:   GPIO 17
10pt Hole:     GPIO 22
20pt Hole:     GPIO 23
30pt Hole:     GPIO 24
40pt Hole:     GPIO 25
50pt Hole:     GPIO 27
100pt Hole:    GPIO 18

Display CLK:   GPIO 5
Display DIO:   GPIO 6
```

**Sensor Connections:**
- VCC → 3.3V or 5V
- GND → Ground
- Signal → GPIO pin (with pull-up resistor)

## Software Installation

### 1. Prepare Raspberry Pi

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
sudo apt install -y python3-pip python3-rpi.gpio

# Install Python packages
pip3 install requests

# Optional: Install TM1637 display library
pip3 install tm1637
```

### 2. Copy Files to Pi

Transfer these files to your Raspberry Pi:
```
rpi_skeeball/
├── skeeball_main.py    # Main program
├── test_game.py        # Test script
├── config.json         # Configuration (create from sample)
└── README.md           # This file
```

```bash
# From your dev machine:
scp -r rpi_skeeball/ pi@raspberrypi.local:~/

# Or use USB drive, rsync, etc.
```

### 3. Configure System

```bash
cd ~/rpi_skeeball

# First run will create sample config
python3 skeeball_main.py

# Edit configuration
nano config.json
```

**config.json settings:**
```json
{
  "server": {
    "url": "http://192.168.1.100:5000",  // Your Flask server IP
    "game_id": 1,                         // Game ID in database
    "username": "operator",               // Login credentials
    "password": "your-password",
    "sync_interval_seconds": 300          // Sync every 5 minutes
  },
  "gpio_pins": {
    "coin_sensor": 17,
    "hole_10": 22,
    "hole_20": 23,
    "hole_30": 24,
    "hole_40": 25,
    "hole_50": 27,
    "hole_100": 18
  },
  "game": {
    "balls_per_game": 9,
    "ball_timeout_seconds": 30,
    "bonus_threshold": 360              // Score needed for bonus game
  },
  "hardware": {
    "use_gpio": true,
    "bounce_time_ms": 200,              // Debounce time
    "debug": false
  }
}
```

## Testing

### Test Without Hardware (Simulation)

```bash
python3 test_game.py
```

This will simulate 3 complete games and test server connectivity.

### Test With Hardware

1. Make sure sensors are wired correctly
2. Set `"debug": true` in config.json to see detailed logs
3. Run the main program:

```bash
python3 skeeball_main.py
```

4. Test each sensor:
   - Insert coin (should start game)
   - Block each hole sensor (should register score)
   - Check console output

## Running at Startup

### Method 1: systemd Service (Recommended)

```bash
# Create service file
sudo nano /etc/systemd/system/skeeball.service
```

Add this content:
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

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable skeeball.service
sudo systemctl start skeeball.service

# Check status
sudo systemctl status skeeball.service

# View logs
journalctl -u skeeball.service -f
```

### Method 2: Cron (Simple)

```bash
crontab -e

# Add this line:
@reboot sleep 30 && cd /home/pi/rpi_skeeball && python3 skeeball_main.py >> /home/pi/skeeball.log 2>&1
```

## Usage

Once running:
1. Insert coin → Game starts automatically
2. Roll balls → Scores update in real-time
3. After 9 balls → Game ends (or bonus if score ≥ 360)
4. Data syncs to Flask server every 5 minutes
5. View stats in your arcade tracker dashboard

## Data Sync

The system automatically:
- Tracks cumulative coin count
- Saves state every coin/score event
- Syncs to Flask server at configured intervals
- Re-authenticates if session expires
- Performs final sync on shutdown

**Manual Sync:**
```python
# In Python shell or custom script
from skeeball_main import SkeeballGame
game = SkeeballGame()
game.login()
game.sync_to_server()
```

## Troubleshooting

### GPIO Permission Denied
```bash
sudo usermod -a -G gpio pi
# Log out and back in
```

### Sensors Not Triggering
- Check wiring (VCC, GND, Signal)
- Verify GPIO pin numbers (BCM mode)
- Increase `bounce_time_ms` if getting multiple triggers
- Test sensor with: `gpio readall` or `python3 -c "import RPi.GPIO as GPIO; GPIO.setmode(GPIO.BCM); GPIO.setup(17, GPIO.IN); print(GPIO.input(17))"`

### Can't Connect to Server
- Verify Flask app is running: `curl http://SERVER_IP:5000`
- Check firewall rules
- Verify credentials in config.json
- Check logs for authentication errors

### Display Not Working
- Verify TM1637 library is installed: `pip3 show tm1637`
- Check wiring (CLK, DIO)
- Try different GPIO pins
- System still works without display (console output)

### State Not Persisting
- Check file permissions: `ls -l skeeball_state.json`
- Verify disk not full: `df -h`
- Check for SD card corruption: `sudo fsck /dev/mmcblk0p2`

## File Structure

```
rpi_skeeball/
├── skeeball_main.py       # Main application
├── test_game.py           # Test/simulation script
├── config.json            # Configuration (created on first run)
├── skeeball_state.json    # Persistent state (auto-created)
└── README.md              # This file
```

## Flask App Integration

The system uses these Flask routes:
- `POST /login` - Authenticate
- `POST /record_plays/<game_id>` - Submit coin count

**Payload format:**
```json
{
  "coin_count": 123,
  "date": "2025-01-07",
  "notes": "Skeeball auto-sync - 45 games played"
}
```

The Flask app calculates plays based on coin count difference from last record.

## Customization

### Change Score Values
Edit `SCORE_VALUES` in `skeeball_main.py`:
```python
SCORE_VALUES = {
    'hole_10': 10,
    'hole_20': 20,
    'hole_30': 30,
    'hole_40': 40,
    'hole_50': 50,
    'hole_100': 100
}
```

### Add Audio
Install pygame and add to `ball_scored()`:
```python
import pygame
pygame.mixer.init()
sound = pygame.mixer.Sound('ding.wav')
sound.play()
```

### Add LCD Display
Install Adafruit LCD library and add to `display_score()`:
```python
import board
import adafruit_character_lcd.character_lcd as characterlcd
# ... initialize LCD and display score
```

## Support

For issues specific to:
- **Hardware/GPIO**: Check RPi.GPIO documentation
- **Flask integration**: Check your arcade tracker logs
- **This code**: Create an issue or contact developer

## License

Part of the Arcade Tracker project.
