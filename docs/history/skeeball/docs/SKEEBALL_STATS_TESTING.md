# Skeeball Stats API - Quick Testing Guide

## Quick Start

### 1. On the Raspberry Pi

```bash
# Install dependencies if not already installed
pip3 install flask flask-cors

# Navigate to skeeball directory
cd ~/skeeball  # or wherever your skeeball code is

# Copy the new files (if deploying from dev machine)
# - stats_api_server.py
# - updated skeeball_main.py

# Test the stats API server independently
python3 stats_api_server.py
```

Expected output:
```
🚀 Skeeball Stats API Server
==================================================
   Access at: http://<raspberry-pi-ip>:5002
   Press Ctrl+C to stop
```

### 2. Test from Another Machine

```bash
# Health check
curl http://sp1.local:5002/health

# Get current game status
curl http://sp1.local:5002/api/game/status

# Get all lanes
curl http://sp1.local:5002/api/lanes

# Get statistics
curl http://sp1.local:5002/api/game/stats
```

### 3. Configure Flask App

Add to your `.env` file:

```bash
RPI_STATS_HOST=sp1.local
RPI_STATS_PORT=5002
```

Then restart the Flask app:

```bash
python app.py
```

### 4. Test the Integration

Open in your browser:
- Control Panel: http://localhost:5000/skeeball/control
- Statistics: http://localhost:5000/skeeball/stats

The pages should now show real-time data from the Raspberry Pi!

## Testing Scenarios

### Scenario 1: Verify Fallback Works

**Test:** What happens when Raspberry Pi is offline?

1. Stop the stats API on the Pi (Ctrl+C)
2. Refresh the control panel page
3. **Expected:** Page still loads, shows local lane manager data (no error)

### Scenario 2: Real-Time Updates

**Test:** Do stats update in real-time?

1. Open control panel in browser
2. On Raspberry Pi: insert a coin (physical or simulate)
3. Watch browser - credits should show 1
4. Play some balls
5. Watch score and balls counter update

### Scenario 3: Statistics Persistence

**Test:** Do stats persist across restarts?

1. Play a few games
2. Note the total_games and best_score on the stats page
3. Restart skeeball_main.py
4. Check stats page again - numbers should match

### Scenario 4: Multiple Simultaneous Clients

**Test:** Can multiple browsers view stats at once?

1. Open control panel in Chrome
2. Open control panel in Firefox (or another device)
3. Both should show same data and update together

## Debugging Commands

### Check if Stats API is Running

```bash
ssh pi@sp1.local
ps aux | grep python3 | grep stats
ps aux | grep python3 | grep skeeball_main
```

### Check Port Listening

```bash
ssh pi@sp1.local
sudo netstat -tlnp | grep 5002
```

### Test Locally on Pi

```bash
ssh pi@sp1.local
curl http://localhost:5002/health
curl http://localhost:5002/api/lanes
```

### Check Flask App Connection

From your Flask server machine:

```bash
# Test DNS resolution
ping sp1.local

# Test HTTP connection
curl http://sp1.local:5002/health

# Check with verbose output
curl -v http://sp1.local:5002/health
```

### Monitor API Requests

On the Raspberry Pi, watch API requests in real-time:

```bash
# If running skeeball_main.py manually, you'll see request logs
# Or check systemd logs:
sudo journalctl -u skeeball.service -f
```

## Common Issues and Fixes

### Issue: "Connection refused" from Flask app

**Cause:** Stats API not running on Pi

**Fix:**
```bash
ssh pi@sp1.local
cd ~/skeeball
python3 skeeball_main.py
```

### Issue: "STATS_API_AVAILABLE = False" warning

**Cause:** stats_api_server.py not found or can't be imported

**Fix:**
```bash
ssh pi@sp1.local
cd ~/skeeball
ls -la stats_api_server.py  # Verify file exists
python3 -c "from stats_api_server import *"  # Test import
```

### Issue: Stats show zeros or old data

**Cause:** Data not loading from state file

**Fix:**
```bash
ssh pi@sp1.local
cd ~/skeeball
ls -la skeeball_state.json  # Check if file exists
cat skeeball_state.json  # Verify content
```

### Issue: Flask app shows local data instead of Pi data

**Cause:** Environment variable not set or Pi unreachable

**Debug:**
```bash
# On Flask server
echo $RPI_STATS_HOST
echo $RPI_STATS_PORT

# Test connection
curl http://$RPI_STATS_HOST:$RPI_STATS_PORT/health
```

**Fix:**
Check `.env` file has correct values, restart Flask app

### Issue: Page loads slowly

**Cause:** Connection timeout (3 seconds default)

**Fix:** Check network connection between Flask server and Pi
```bash
ping -c 5 sp1.local
traceroute sp1.local
```

## Manual Testing with curl

### Simulate a Game

```bash
# Start fresh
curl http://sp1.local:5002/api/game/status

# The game needs to run on the actual Pi hardware,
# but you can verify the API responds
```

### Check Real-Time Updates

```bash
# Terminal 1: Watch status continuously
watch -n 1 curl -s http://sp1.local:5002/api/game/status

# Terminal 2: On the Pi, run a simulated game
python3 -c "
from skeeball_main import SkeeballGame
game = SkeeballGame()
game.simulate_coin()
for i in range(9):
    game.simulate_ball(50)
"
```

## Performance Testing

### API Response Time

```bash
# Test response time
time curl http://sp1.local:5002/api/lanes

# Should be < 100ms on local network
```

### Load Testing

```bash
# Simple load test (requires 'apache2-utils' package)
ab -n 1000 -c 10 http://sp1.local:5002/api/lanes

# Should handle 100+ requests/second easily
```

## Success Criteria

✅ **Integration is working if:**

1. Flask control panel shows "lane_1: 🟢 Ready" (or Playing)
2. Statistics page shows accumulated totals (games, coins, scores)
3. Inserting a coin updates the control panel within 2 seconds
4. Playing a ball updates the score in real-time
5. Stats persist after restarting skeeball_main.py
6. Flask app gracefully falls back to local data if Pi is unreachable

## Next Steps After Testing

Once testing is successful:

1. **Set up systemd service** for auto-start on boot
2. **Configure firewall** to allow port 5002
3. **Set up monitoring** (e.g., check if service is running)
4. **Add to documentation** for operators
5. **Consider HTTPS** for production deployment

## Support

If you encounter issues not covered here:

1. Check the main setup guide: `rpi_skeeball/STATS_API_SETUP.md`
2. Review Flask app logs: `logs/flask.log` (if logging is configured)
3. Review Pi logs: `sudo journalctl -u skeeball.service -n 100`
4. Test each component independently (API server, Flask app, network)
