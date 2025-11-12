# Skeeball System Status and Hardware Controls

## Overview
The skeeball control center now displays real-time system status and provides remote hardware control capabilities from the Flask web interface.

## Features Added

### 1. System Status Display
Located at the top of `/skeeball/` page, the status panel shows:

- **Raspberry Pi Status**: 🟢 Online / 🔴 Offline
  - Automatically detects if lanes are responding
  - Updates every 3 seconds

- **GPIO Mode**: 🎮 Real Hardware / 🧪 Mock/Testing
  - Shows whether using actual GPIO pins or mock testing mode
  - Real Hardware mode: Connected to Raspberry Pi GPIO
  - Mock/Testing mode: Simulation mode for development

- **Active Lanes**: Shows count of online lanes (e.g., "1/1")

### 2. Hardware Controls
Four control buttons for remote hardware management:

#### 💡 LED Power ON/OFF
- Controls the LED display power relay (GPIO 26)
- **ON**: Turns on the LED displays
- **OFF**: Turns off the LED displays (power saving)

#### 🎮 Trigger Ball Release
- Pulses the solenoid relay (GPIO 10) for 200ms
- Releases balls for play
- Can be used for manual testing or troubleshooting

#### 🔄 Reset System
- Clears all lane game states
- Resets scores and credits
- Does not affect statistics or revenue tracking

## API Endpoints

### Hardware Control
```bash
POST /skeeball/api/hardware/control
Content-Type: application/json

{
  "device": "led_power|solenoid|system",
  "action": "on|off|pulse|reset"
}
```

**Examples:**

```bash
# Turn LED power on
curl -X POST http://localhost:5000/skeeball/api/hardware/control \
  -H "Content-Type: application/json" \
  -d '{"device": "led_power", "action": "on"}'

# Trigger ball release
curl -X POST http://localhost:5000/skeeball/api/hardware/control \
  -H "Content-Type: application/json" \
  -d '{"device": "solenoid", "action": "pulse"}'

# Reset system
curl -X POST http://localhost:5000/skeeball/api/hardware/control \
  -H "Content-Type: application/json" \
  -d '{"device": "system", "action": "reset"}'
```

### Status Checking
```bash
# Check GPIO status
GET /skeeball/api/gpio/status

# Check lane health
GET /skeeball/api/health

# Get lane details
GET /skeeball/api/lanes
```

## Configuration

GPIO pins are configured in `config.py`:

```python
# Output pins for hardware control
SOLENOID_RELAY_PIN = 10  # Ball release solenoid
LED_POWER_RELAY_PIN = 26  # LED display power
```

Modify these values if your wiring uses different GPIO pins.

## Usage

1. **Access the Control Center**
   - Navigate to `/skeeball/` in your web browser
   - Status panel appears at the top

2. **Monitor System Status**
   - Green 🟢 = System online and working
   - Red 🔴 = System offline or error
   - Status updates automatically every 3 seconds

3. **Control Hardware**
   - Click any control button
   - Confirmation message appears on success
   - Error message shown if operation fails

## Troubleshooting

### System Shows Offline
- Check that Flask app is running (`python app.py`)
- Verify GPIO initialization in logs
- Check `/skeeball/api/health` endpoint

### Hardware Controls Don't Work
- Verify GPIO pins are correctly configured in `config.py`
- Check if using Mock GPIO mode (won't control real hardware)
- Ensure proper wiring and relay connections
- Check Flask app logs for errors

### LED Power Doesn't Respond
- Verify LED_POWER_RELAY_PIN is correctly set
- Check relay wiring to GPIO 26
- Test relay separately to confirm operation

### Ball Release Doesn't Work
- Verify SOLENOID_RELAY_PIN is correctly set
- Check solenoid wiring to GPIO 10
- Ensure solenoid is receiving adequate power (may need external power supply)
- Check if 200ms pulse duration is sufficient

## Security Notes

- All hardware control endpoints require login (`@login_required`)
- Only authenticated users can control hardware
- Controls respect role-based access control
- Use caution with physical hardware controls

## Future Enhancements

Potential additions:
- Individual score sensor testing
- Coin sensor manual trigger
- Display brightness control
- Automatic ball release scheduling
- Hardware diagnostics panel
- GPIO pin status visualization
