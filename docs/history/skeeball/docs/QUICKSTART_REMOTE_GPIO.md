# Quick Start: Remote GPIO Control

Get your skeeball hardware controls working in **3 simple steps**!

## Step 1: Deploy to Raspberry Pi (1 minute)

From your Fedora machine, run:

```bash
cd ~/arcade-tracker
./deploy_to_pi.sh
```

This will automatically:
- Copy files to your Pi
- Install dependencies
- Start the GPIO API server
- Enable auto-start on boot

## Step 2: Configure Connection (30 seconds)

Create/edit `.env` file:

```bash
cd ~/arcade-tracker
echo "RPI_GPIO_HOST=skeeproto@sp1.local" >> .env
echo "RPI_GPIO_PORT=5001" >> .env
```

## Step 3: Restart Flask App (30 seconds)

```bash
# Stop current app (Ctrl+C), then:
source venv/bin/activate
python app.py
```

## Test It!

Open your browser: `http://localhost:5000/skeeball/`

You should see:
- 🟢 System Status: **Online**
- Hardware control buttons that work!

### Quick Test Commands

```bash
# Health check
curl http://skeeproto@sp1.local:5001/health

# LED ON
curl -X POST http://skeeproto@sp1.local:5001/gpio/control \
  -H "Content-Type: application/json" \
  -d '{"device": "led_power", "action": "on"}'

# Ball Release
curl -X POST http://skeeproto@sp1.local:5001/gpio/control \
  -H "Content-Type: application/json" \
  -d '{"device": "solenoid", "action": "pulse"}'
```

## Troubleshooting

**"Cannot connect to Raspberry Pi"**
```bash
# Check if API is running on Pi
ssh skeeproto@sp1.local "sudo systemctl status gpio-api"

# View logs
ssh skeeproto@sp1.local "sudo journalctl -u gpio-api -f"

# Restart service
ssh skeeproto@sp1.local "sudo systemctl restart gpio-api"
```

**DNS not resolving?**
```bash
# Get Pi's IP address
ssh skeeproto@sp1.local "hostname -I"

# Update .env with IP instead of hostname
# Example:
# RPI_GPIO_HOST=192.168.1.123
```

## What Was Installed?

On your Raspberry Pi:
- GPIO API Server (Flask app on port 5001)
- Systemd service for auto-start
- Controls for GPIO pins 10 (solenoid) and 26 (LED power)

On your Fedora machine:
- Updated Flask routes to forward commands to Pi
- Configuration in `.env` file

## Next Steps

- Read [SKEEBALL_REMOTE_CONTROL.md](SKEEBALL_REMOTE_CONTROL.md) for detailed documentation
- Read [SKEEBALL_CONTROLS.md](SKEEBALL_CONTROLS.md) for feature overview
- Check system status at `/skeeball/` in your web browser

## Common Commands

```bash
# Deploy updates to Pi
./deploy_to_pi.sh

# Check Pi GPIO status
ssh skeeproto@sp1.local "sudo systemctl status gpio-api"

# View Pi logs
ssh skeeproto@sp1.local "sudo journalctl -u gpio-api -f"

# Test connection
curl http://skeeproto@sp1.local:5001/health
```

That's it! Your skeeball system is now online with remote GPIO control! 🎮
