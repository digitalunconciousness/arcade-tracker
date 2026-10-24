# Skeeball Remote Control Setup

## Architecture Overview

Your skeeball system now uses a **client-server architecture**:

```
┌─────────────────────────┐         ┌──────────────────────────┐
│  Fedora Machine         │         │  Raspberry Pi            │
│  (jackiegreybard)       │         │  (skeeproto@sp1.local)   │
│                         │         │                          │
│  Flask App (port 5000)  │◄───────►│  GPIO API (port 5001)    │
│  - Web Interface        │  HTTP   │  - Real GPIO Control     │
│  - Database             │         │  - LED Power Relay       │
│  - Game Management      │         │  - Solenoid Control      │
└─────────────────────────┘         └──────────────────────────┘
```

**Why this architecture?**
- Your Fedora machine hosts the main Flask app and database
- The Raspberry Pi has the actual GPIO hardware
- The Flask app sends control commands to the Pi via HTTP

## Setup Instructions

### Step 1: Deploy GPIO API to Raspberry Pi

SSH into your Raspberry Pi:
```bash
ssh skeeproto@sp1.local
```

Navigate to the project directory:
```bash
cd arcade-tracker/rpi_skeeball
```

Run the setup script:
```bash
chmod +x setup_gpio_api.sh
./setup_gpio_api.sh
```

This will:
- Install dependencies
- Set up systemd service
- Start the GPIO API server on port 5001
- Enable auto-start on boot

### Step 2: Configure Flask App

On your Fedora machine, create a `.env` file in the arcade-tracker directory:

```bash
cd ~/arcade-tracker
nano .env
```

Add these lines:
```bash
# Raspberry Pi GPIO API Configuration
RPI_GPIO_HOST=skeeproto@sp1.local
RPI_GPIO_PORT=5001
```

Or use the Pi's IP address if the hostname doesn't resolve:
```bash
RPI_GPIO_HOST=192.168.1.XXX  # Replace with actual IP
RPI_GPIO_PORT=5001
```

### Step 3: Restart Flask App

Restart your Flask app to pick up the new configuration:

```bash
# Stop the current Flask app (Ctrl+C in the terminal where it's running)
# Then restart:
source venv/bin/activate
python app.py
```

### Step 4: Test the Connection

Visit your skeeball control center in the browser:
```
http://localhost:5000/skeeball/
```

You should now see:
- 🟢 **System Status**: Online (if the Pi is reachable)
- **Hardware Controls**: All buttons should work

## Testing GPIO Controls

### From Web Interface
1. Navigate to `/skeeball/`
2. Click any hardware control button:
   - **💡 LED Power ON/OFF**
   - **🎮 Trigger Ball Release**
   - **🔄 Reset System**

### From Command Line (on Fedora)

Test LED control:
```bash
curl -X POST http://skeeproto@sp1.local:5001/gpio/control \
  -H "Content-Type: application/json" \
  -d '{"device": "led_power", "action": "on"}'
```

Test solenoid:
```bash
curl -X POST http://skeeproto@sp1.local:5001/gpio/control \
  -H "Content-Type: application/json" \
  -d '{"device": "solenoid", "action": "pulse"}'
```

Check GPIO status:
```bash
curl http://skeeproto@sp1.local:5001/gpio/status
```

Health check:
```bash
curl http://skeeproto@sp1.local:5001/health
```

## Troubleshooting

### "Cannot connect to Raspberry Pi" Error

**Check if GPIO API is running on the Pi:**
```bash
ssh skeeproto@sp1.local
sudo systemctl status gpio-api
```

**View logs:**
```bash
ssh skeeproto@sp1.local
sudo journalctl -u gpio-api -f
```

**Restart the service:**
```bash
ssh skeeproto@sp1.local
sudo systemctl restart gpio-api
```

### DNS Resolution Issues

If `skeeproto@sp1.local` doesn't resolve, find the Pi's IP:
```bash
ssh skeeproto@sp1.local "hostname -I"
```

Then update your `.env` file with the actual IP address.

### Port 5001 Already in Use

Check what's using the port:
```bash
ssh skeeproto@sp1.local "sudo netstat -tlnp | grep 5001"
```

Kill the process or change the port in both:
- `gpio_api_server.py` (line 123)
- Your `.env` file

### GPIO Permissions

If you get permission errors on the Pi:
```bash
ssh skeeproto@sp1.local
sudo usermod -a -G gpio $USER
# Logout and login again for group changes to take effect
```

### Firewall Blocking Connection

On the Raspberry Pi, ensure port 5001 is open:
```bash
ssh skeeproto@sp1.local
sudo ufw allow 5001/tcp
# Or if using firewalld:
sudo firewall-cmd --permanent --add-port=5001/tcp
sudo firewall-cmd --reload
```

## API Endpoints on Raspberry Pi

The GPIO API server (port 5001) provides these endpoints:

### `GET /health`
Check if the server is running.

**Response:**
```json
{
  "status": "online",
  "gpio_available": true,
  "solenoid_pin": 10,
  "led_power_pin": 26
}
```

### `POST /gpio/control`
Control GPIO devices.

**Request:**
```json
{
  "device": "led_power|solenoid",
  "action": "on|off|pulse"
}
```

**Examples:**
- LED ON: `{"device": "led_power", "action": "on"}`
- LED OFF: `{"device": "led_power", "action": "off"}`
- Solenoid pulse: `{"device": "solenoid", "action": "pulse"}`

### `GET /gpio/status`
Get current GPIO pin states.

**Response:**
```json
{
  "solenoid": {
    "pin": 10,
    "state": "LOW"
  },
  "led_power": {
    "pin": 26,
    "state": "HIGH"
  }
}
```

## GPIO Pin Configuration

Default pins (BCM numbering):
- **GPIO 10**: Solenoid relay (ball release)
- **GPIO 26**: LED power relay

To change pins, edit `rpi_skeeball/gpio_api_server.py`:
```python
SOLENOID_PIN = 10
LED_POWER_PIN = 26
```

## Systemd Service Management

On the Raspberry Pi:

**Start:**
```bash
sudo systemctl start gpio-api
```

**Stop:**
```bash
sudo systemctl stop gpio-api
```

**Restart:**
```bash
sudo systemctl restart gpio-api
```

**Enable auto-start:**
```bash
sudo systemctl enable gpio-api
```

**Disable auto-start:**
```bash
sudo systemctl disable gpio-api
```

**View status:**
```bash
sudo systemctl status gpio-api
```

**View logs:**
```bash
sudo journalctl -u gpio-api -f
```

## Security Considerations

⚠️ **Important**: The GPIO API currently has NO authentication. Anyone who can reach the Pi on your network can control the hardware.

**Recommended security measures:**

1. **Network isolation**: Keep the Pi on a private network
2. **Firewall**: Only allow connections from your Fedora machine
3. **VPN**: Use a VPN if accessing remotely

**To add basic authentication** (future enhancement):
- Implement API key authentication
- Use HTTPS with SSL certificates
- Add rate limiting

## Manual Testing Without Web Interface

Start the GPIO API manually for testing:
```bash
ssh skeeproto@sp1.local
cd arcade-tracker/rpi_skeeball
python3 gpio_api_server.py
```

This runs in the foreground, useful for debugging.

## Files Created

On Raspberry Pi:
- `rpi_skeeball/gpio_api_server.py` - The GPIO control server
- `rpi_skeeball/gpio-api.service` - Systemd service file
- `rpi_skeeball/setup_gpio_api.sh` - Setup automation script

On Fedora machine:
- Updated `skeeball_routes.py` - Now forwards to remote Pi
- `.env` - Configuration for Pi connection

## Next Steps

1. ✅ Deploy the GPIO API to your Raspberry Pi
2. ✅ Configure the connection in `.env`
3. ✅ Restart your Flask app
4. ✅ Test the controls from the web interface
5. 🔄 Monitor the system and adjust as needed
