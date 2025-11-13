# Skeeball Stats API Setup Guide

This guide explains how to enable real-time statistics from your Raspberry Pi skeeball machine to the Flask web app.

## Overview

The stats API integration consists of three components:

1. **Stats API Server** (`stats_api_server.py`) - Runs on the Raspberry Pi, exposes game state via HTTP
2. **Modified Skeeball Main** (`skeeball_main.py`) - Updates the stats API in real-time as the game progresses
3. **Flask App Integration** - Fetches data from the Pi's stats API when available

## Raspberry Pi Setup

### 1. Install Dependencies

On your Raspberry Pi, ensure you have Flask and flask-cors installed:

```bash
pip3 install flask flask-cors
```

### 2. Copy Files to Raspberry Pi

Make sure these files are in your `/home/pi/skeeball/` directory (or wherever your skeeball code lives):

- `skeeball_main.py` (modified version with stats API integration)
- `stats_api_server.py` (new file)
- `config.json` (your existing config)

### 3. Test the Stats API Server

You can test the stats API server independently:

```bash
cd /home/pi/skeeball/
python3 stats_api_server.py
```

This will start the API server on port 5002. You should see:

```
🚀 Skeeball Stats API Server
==================================================
   Access at: http://<raspberry-pi-ip>:5002
   Press Ctrl+C to stop
```

Test it from another machine:

```bash
curl http://<raspberry-pi-ip>:5002/health
curl http://<raspberry-pi-ip>:5002/api/game/status
curl http://<raspberry-pi-ip>:5002/api/lanes
```

### 4. Run the Full Skeeball System

The stats API server is automatically started when you run `skeeball_main.py`:

```bash
python3 skeeball_main.py
```

You should see:

```
✅ Stats API Server started on port 5002
🎳 SKEEBALL SYSTEM STARTED
==================================================
   Server: http://192.168.1.100:5000
   Game ID: 1
   Balls per game: 9
   Bonus at: 360+ pts
==================================================

💰 INSERT COIN TO START
```

### 5. Make it Run on Boot (Optional)

Create a systemd service to auto-start the skeeball system:

```bash
sudo nano /etc/systemd/system/skeeball.service
```

Add:

```ini
[Unit]
Description=Skeeball Game System with Stats API
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/skeeball
ExecStart=/usr/bin/python3 /home/pi/skeeball/skeeball_main.py
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
```

Check status:

```bash
sudo systemctl status skeeball.service
```

View logs:

```bash
sudo journalctl -u skeeball.service -f
```

## Flask App Configuration

### 1. Set Environment Variables

On your Flask app server, create or update `.env`:

```bash
# Raspberry Pi Stats API
RPI_STATS_HOST=sp1.local  # or IP address like 192.168.1.50
RPI_STATS_PORT=5002

# Optional: GPIO API (for hardware control)
RPI_GPIO_HOST=skeeproto@sp1.local
RPI_GPIO_PORT=5001
```

**Note:** The hostname can include the username (like `skeeproto@sp1.local`) or just the hostname/IP. The code will handle both formats.

### 2. Restart Flask App

```bash
# If running manually
python app.py

# If using systemd
sudo systemctl restart arcade-tracker
```

## Verify Integration

### 1. Check API Endpoints

From your Flask server, test the Raspberry Pi connection:

```bash
# Replace with your Pi's hostname/IP
curl http://sp1.local:5002/health
curl http://sp1.local:5002/api/lanes
```

You should see JSON responses with game state.

### 2. Access Web Interface

Open your browser and navigate to:

- **Control Panel:** `http://your-flask-server:5000/skeeball/control`
- **Statistics:** `http://your-flask-server:5000/skeeball/stats`

Both pages should now show real-time data from the Raspberry Pi!

### 3. Test Real-Time Updates

1. Insert a coin on the physical skeeball machine
2. Refresh the control panel - you should see:
   - Credits: 1
   - Game Active status
   - Balls: 0/9

3. Play some balls and watch:
   - Score updates in real-time
   - Balls counter incrementing
   - Last event timestamp updating

## API Endpoints

The Raspberry Pi exposes these endpoints:

### Health Check
```
GET /health
```

### Game Status (Current State)
```
GET /api/game/status
GET /api/lanes/lane_1/status  # Same data, compatible format
```

Returns:
```json
{
  "lane_id": "lane_1",
  "current_score": 150,
  "balls_remaining": 6,
  "game_active": true,
  "current_ball_score": 20,
  "credits": 1,
  "score": 150,
  "balls": 3,
  "total_balls": 9,
  "in_progress": true,
  "is_online": true,
  "last_event": "2024-01-15T14:30:22.123456"
}
```

### Game Statistics (Cumulative)
```
GET /api/game/stats
GET /api/lanes/lane_1/stats  # Same data, compatible format
```

Returns:
```json
{
  "lane_id": "lane_1",
  "total_games": 42,
  "total_coins": 42,
  "total_score": 12650,
  "best_score": 450,
  "average_score": 301.2,
  "games_today": 42
}
```

### All Lanes
```
GET /api/lanes
```

Returns:
```json
{
  "lane_1": {
    "lane_id": "lane_1",
    "credits": 1,
    "score": 150,
    "balls": 3,
    "total_balls": 9,
    "in_progress": true,
    "is_online": true,
    "last_event": "2024-01-15T14:30:22.123456"
  }
}
```

### Game History
```
GET /api/game/history
```

Returns:
```json
{
  "games": [
    {
      "score": 320,
      "timestamp": "2024-01-15T14:25:10.123456"
    },
    ...
  ],
  "total_games": 20
}
```

## Troubleshooting

### Stats API Not Responding

1. **Check if the API server is running:**
   ```bash
   ssh pi@sp1.local
   ps aux | grep stats_api_server
   ```

2. **Check if port 5002 is listening:**
   ```bash
   sudo netstat -tlnp | grep 5002
   ```

3. **Test locally on the Pi:**
   ```bash
   curl http://localhost:5002/health
   ```

4. **Check firewall:**
   ```bash
   sudo ufw status
   sudo ufw allow 5002/tcp  # If firewall is enabled
   ```

### Flask App Shows Local Data Instead of Pi Data

1. **Check environment variables:**
   ```bash
   # On Flask server
   echo $RPI_STATS_HOST
   echo $RPI_STATS_PORT
   ```

2. **Test connection from Flask server:**
   ```bash
   curl http://$RPI_STATS_HOST:$RPI_STATS_PORT/health
   ```

3. **Check Flask logs:**
   Look for connection errors or timeouts

### Stats Not Updating

1. **Verify skeeball_main.py is running:**
   ```bash
   ssh pi@sp1.local
   ps aux | grep skeeball_main
   ```

2. **Check that stats API integration is active:**
   Look for this line in the startup logs:
   ```
   ✅ Stats API Server started on port 5002
   ```

3. **Manually trigger a state update:**
   ```bash
   # On the Pi
   curl -X POST http://localhost:5002/api/test/trigger
   ```

### "STATS_API_AVAILABLE = False" Warning

This means the `stats_api_server.py` module couldn't be imported. Make sure:

1. `stats_api_server.py` is in the same directory as `skeeball_main.py`
2. Flask and flask-cors are installed: `pip3 install flask flask-cors`
3. No syntax errors in `stats_api_server.py`

## Performance Notes

- The stats API server runs in a background thread and doesn't impact game performance
- API calls from Flask app have a 3-second timeout with automatic fallback to local data
- The control panel auto-refreshes every 2 seconds
- State is persisted to `skeeball_state.json` and loaded on restart

## Security Considerations

For production deployment:

1. **Use a reverse proxy (nginx) with HTTPS**
2. **Add authentication to the stats API**
3. **Use a firewall to restrict access to trusted IPs**
4. **Consider VPN for remote access**

Example nginx config:

```nginx
location /skeeball-api/ {
    proxy_pass http://localhost:5002/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    
    # Optional: Basic auth
    auth_basic "Skeeball Stats";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

## Next Steps

- Add WebSocket support for real-time push updates (instead of polling)
- Implement multiple lane support (lane_1, lane_2, etc.)
- Add player profiles and high score leaderboards
- Integrate maintenance alerts based on game statistics
- Add game video recording trigger on high scores
