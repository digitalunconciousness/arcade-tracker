# Skeeball System Overview

## Your Hardware Setup

### Scoring Mechanism

Your skeeball machine uses a **multi-switch lane design**:

```
                [100pt Left]  [100pt Right]
                     ↓              ↓
        ╔════════════════════════════════════╗
        ║  🎯  [50pt]  [40pt]  [30pt]  [20pt]  [10pt]  ║
        ║   │      │      │      │      │     ║
        ║   │      │      │      │      │     ║
        ║   5sw    4sw    3sw    2sw    1sw   ║
        ║   │      │      │      │      │     ║
        ║   └──────┴──────┴──────┴──────┴───> ║
        ║                                      ║
        ║            [Ball Counter]            ║
        ╚══════════════════════════════════════╝
```

### How It Works

1. **Ball enters a scoring lane** (10, 20, 30, 40, 50, or 100 point)

2. **As ball rolls down the lane**, it triggers momentary switches:
   - **10pt lane:** Hits 1 switch = 10 points
   - **20pt lane:** Hits 2 switches = 20 points
   - **30pt lane:** Hits 3 switches = 30 points
   - **40pt lane:** Hits 4 switches = 40 points
   - **50pt lane:** Hits 5 switches = 50 points
   - **100pt lanes:** Hits 5 switches + special 100pt switch = 100 points

3. **Ball reaches bottom counter** - score is finalized and added to total

4. **After 9 balls** - game ends, waits for next coin

5. **Coin inserted** - new game starts immediately (even if balls remaining)

### GPIO Configuration

**Total Pins Used: 14**

- **1x** Coin sensor (GPIO 17)
- **1x** Ball counter (GPIO 18)
- **10x** 10-point switches (GPIO 22, 23, 24, 25, 26, 27, 4, 16, 20, 21)
- **2x** 100-point special switches (GPIO 19, 13)

**Optional:**
- **2x** Display (GPIO 5 CLK, GPIO 6 DIO)

### Switch Layout

```
Switch Mapping (0-9 = 10pt switches):
  
Lane:     10pt  20pt  30pt  40pt  50pt  100L  100R
          ───   ───   ───   ───   ───   ───   ───
Switch:    0     0     0     0     0     0     0
                1     1     1     1     1     
                      2     2     2     2
                            3     3     3
                                  4     4
                                        Special
```

**Example Scoring:**
- Ball goes in 30pt hole → Triggers switches 0, 1, 2 → 30 points
- Ball goes in 100pt hole → Triggers switches 0, 1, 2, 3, 4 + special → 100 points

## Software Architecture

### Main Components

1. **`SkeeballGame` class** - Main controller
   - Manages game state
   - Tracks switches hit per ball
   - Handles scoring logic
   - Syncs to Flask server

2. **GPIO Callbacks** - Hardware interrupt handlers
   - `coin_inserted()` - Starts new game
   - `switch_triggered()` - Records 10pt switch hit
   - `switch_100_triggered()` - Records 100pt bonus
   - `ball_completed()` - Finalizes ball score

3. **Scoring Logic**
   ```python
   # Per-ball tracking
   current_ball_switches = set()  # Which switches hit this ball
   current_ball_score = 0         # Running score for current ball
   
   # When ball completes:
   current_score += current_ball_score  # Add to total
   current_ball_switches = set()        # Reset for next ball
   ```

4. **Server Sync Thread**
   - Runs in background
   - Syncs every 5 minutes (configurable)
   - Re-authenticates if session expires
   - Final sync on shutdown

### Game Flow

```
┌─────────────────┐
│  INSERT COIN    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  START GAME     │
│  (9 balls)      │
└────────┬────────┘
         │
    ┌────▼─────┐
    │ Ball #1  │
    │  rolled  │
    └────┬─────┘
         │
    ┌────▼──────────┐
    │ Switches hit  │
    │ (accumulate)  │
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Ball counter  │
    │  triggered    │
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Add to score  │
    │ Reset switches│
    └────┬──────────┘
         │
         ├─ More balls? ──Yes─> Repeat
         │
         No
         │
    ┌────▼──────────┐
    │  END GAME     │
    │ Check bonus   │
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Score ≥ 360?  │
    └────┬──────────┘
         │
    Yes──┴──> BONUS GAME (restart)
         │
         No
         │
    ┌────▼──────────┐
    │ GAME OVER     │
    │ Show stats    │
    └────┬──────────┘
         │
         ▼
    Wait for coin...
```

## Configuration

### `config.json` Structure

```json
{
  "server": {
    "url": "http://192.168.1.100:5000",  // Flask server
    "game_id": 1,                         // Game ID in database
    "username": "operator",               // Login credentials
    "password": "your-password",
    "sync_interval_seconds": 300          // 5 minutes
  },
  "gpio_pins": {
    "coin_sensor": 17,                    // Coin acceptor
    "ball_counter": 18,                   // Bottom counter
    "switches_10pt": [                    // 10pt switches (array)
      22, 23, 24, 25, 26,                // Switches 0-4
      27, 4, 16, 20, 21                  // Switches 5-9
    ],
    "switch_100_left": 19,                // Left 100pt special
    "switch_100_right": 13                // Right 100pt special
  },
  "game": {
    "balls_per_game": 9,                  // Standard skeeball
    "ball_timeout_seconds": 2.0,          // Max time per ball
    "bonus_threshold": 360                // Score for bonus game
  },
  "hardware": {
    "use_gpio": true,                     // Enable GPIO
    "bounce_time_ms": 50,                 // Switch debounce
    "debug": false                        // Verbose logging
  }
}
```

## Key Features

### 1. Per-Ball Switch Tracking
Each ball's score is calculated independently:
- Tracks which switches have been hit
- Each switch only counts once per ball
- Score finalized when ball counter triggers
- Reset for next ball

### 2. Coin Resets Game
Inserting a coin **always** starts a new game:
- Even if balls remaining
- Resets all counters
- Standard arcade behavior

### 3. Persistent State
Survives power loss:
- Total coins inserted
- Total games played
- Game history (last 100 games)
- Last sync timestamp

### 4. Automatic Server Sync
- Background thread syncs every 5 minutes
- Sends cumulative coin count
- Flask calculates plays from difference
- Handles authentication automatically

### 5. Bonus Games
- Score ≥ 360 points → Bonus game
- Starts immediately after game ends
- No coin required
- Same 9 balls

## Data Flow to Flask App

```
┌─────────────────────┐
│  Raspberry Pi       │
│  ─────────────      │
│  Coin counter: 47   │
│  Games played: 15   │
└──────────┬──────────┘
           │
           │ Every 5 minutes
           │
           ▼
    ┌──────────────┐
    │ POST /login  │
    │ Authenticate │
    └──────┬───────┘
           │
           ▼
┌──────────────────────────────┐
│ POST /record_plays/<game_id> │
│ ──────────────────────────── │
│ coin_count: 47               │
│ date: 2025-01-07             │
│ notes: "15 games played"     │
└──────────┬───────────────────┘
           │
           ▼
    ┌──────────────┐
    │  Flask App   │
    │  ──────────  │
    │  Last: 42    │
    │  New:  47    │
    │  Diff: 5     │
    │  ──────────  │
    │  +5 plays    │
    │  +$1.25 rev  │
    └──────────────┘
```

## Testing

### Without Hardware
```bash
python3 test_game.py
```
Simulates complete games with random scores.

### With Hardware (Debug Mode)
```bash
# Enable debug in config.json
"debug": true

python3 skeeball_main.py
```
Shows detailed output for each switch trigger.

### Individual Switch Test
```python
import RPi.GPIO as GPIO
GPIO.setmode(GPIO.BCM)

# Test switch 0 (GPIO 22)
GPIO.setup(22, GPIO.IN, pull_up_down=GPIO.PUD_UP)

while True:
    if GPIO.input(22) == 0:  # LOW = pressed
        print("Switch 0 triggered!")
    time.sleep(0.1)
```

## Maintenance

### View Logs (systemd)
```bash
journalctl -u skeeball.service -f
```

### Check State File
```bash
cat ~/rpi_skeeball/skeeball_state.json
```

### Manual Sync
```python
from skeeball_main import SkeeballGame
game = SkeeballGame()
game.login()
game.sync_to_server()
```

### Reset Counters
```bash
rm ~/rpi_skeeball/skeeball_state.json
# Restart service
sudo systemctl restart skeeball.service
```

## Customization

### Change Bonus Threshold
In `config.json`:
```json
"bonus_threshold": 400  // Now need 400+ for bonus
```

### Change Sync Interval
```json
"sync_interval_seconds": 600  // Sync every 10 minutes
```

### Adjust Debounce
If getting double-triggers:
```json
"bounce_time_ms": 100  // Increase debounce time
```

### Enable Debug Logging
```json
"debug": true  // See every switch hit
```

## Troubleshooting

### Problem: Wrong scores
- **Check:** Switch wiring (each lane should trigger correct number)
- **Test:** Press each switch manually, verify output
- **Debug:** Enable `"debug": true` to see switch IDs

### Problem: Ball not counted
- **Check:** Ball counter switch (GPIO 18)
- **Test:** Manually trigger counter switch
- **Verify:** Ball actually reaches counter

### Problem: Multiple balls counted
- **Cause:** Ball bouncing on counter switch
- **Fix:** Increase `bounce_time_ms` to 100-200

### Problem: 100pt not working
- **Check:** Special switches (GPIO 19, 13) wired correctly
- **Logic:** Must hit 5 switches + special for 100pts
- **Test:** Manually trigger all switches in sequence

### Problem: Coin starts game but no switches work
- **Check:** `game_active` flag (should be True after coin)
- **Check:** All switches wired to correct GPIO pins
- **Test:** Try simulation mode first

## Summary

Your system is a **switch-counting skeeball scorer** where:
- Each lane has multiple switches
- More switches hit = higher score
- Ball counter finalizes each ball
- Coin always starts fresh game
- Auto-syncs to your Flask arcade tracker

Everything is self-contained, persistent, and ready for production use!
