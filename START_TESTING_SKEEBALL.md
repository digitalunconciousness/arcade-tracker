# 🎳 Start Testing Skeeball NOW!

## Quick Start (2 minutes)

### 1. Start the Application
```bash
cd /home/jackiegreybard/arcade-tracker
python app.py
```

You should see:
```
🧪 Mock GPIO initialized (testing mode - no hardware required)
✅ Skeeball routes registered
 * Running on http://0.0.0.0:5000
```

### 2. Log In
Open your browser and go to: http://localhost:5000

Log in with your credentials.

### 3. Access Skeeball

**Option A - Via Navigation Menu:**
1. Click on "Games" in the top navigation
2. Click "🎳 Skeeball" in the dropdown menu

**Option B - Direct URLs:**
- Main hub: http://localhost:5000/skeeball/
- GPIO test: http://localhost:5000/skeeball/gpio-test
- Simulator: http://localhost:5000/skeeball/simulator
- Stats: http://localhost:5000/skeeball/stats

## What to Test

### GPIO Test Interface (Recommended First)
**URL:** http://localhost:5000/skeeball/gpio-test

This simulates pressing physical hardware buttons.

**Try this sequence:**
1. Click "💰 Coin Switch" → Should see Credits: 1
2. Click "⊕ 10-Point Switch" → Should see Score: 10
3. Click "🎱 Ball Counter Switch" → Should see Balls: 1/9
4. Repeat steps 2-3 eight more times
5. After 9 balls, game should end automatically
6. Check the event log for all actions

### Full Simulator
**URL:** http://localhost:5000/skeeball/simulator

This simulates complete roll outcomes.

**Try this:**
1. Click "💰 Coin" to add credit
2. Click roll outcome buttons: "10", "20", "30", "40", "50", "100"
3. Each button simulates a ball being thrown and scored
4. Watch the score rack up!

### Control Panel
**URL:** http://localhost:5000/skeeball/control

View lane status and quick controls.

### Statistics
**URL:** http://localhost:5000/skeeball/stats

View accumulated game statistics.

## Features Working Right Now

✅ **Mock GPIO** - No hardware needed  
✅ **Web interface** - Click buttons to simulate switches  
✅ **Real-time updates** - Game state updates live  
✅ **Event logging** - See every action with timestamps  
✅ **Statistics tracking** - Games, scores, coins tracked  
✅ **Complete game logic** - Full 9-ball games work  
✅ **Multiple interfaces** - GPIO test, simulator, control panel  

## Current Configuration

- **GPIO Mode:** Mock (testing without hardware)
- **Hardware Required:** None ❌
- **Configuration File:** `.env.skeeball` (USE_REAL_GPIO=false)
- **Ready to Test:** Yes ✅

## Troubleshooting

### Can't access skeeball pages
**Check:**
1. Is the app running? (`python app.py`)
2. Are you logged in?
3. Does the URL work: http://localhost:5000/skeeball/

### Navigation link not showing
**Try:**
- Hard refresh (Ctrl+Shift+R)
- Clear browser cache
- Check the Games dropdown menu

### GPIO test buttons not responding
**Check:**
1. Browser console for errors (F12)
2. Network tab shows API calls succeeding
3. You're logged in with valid session

### App won't start
**Common issues:**
```bash
# Missing dependencies
pip install pyserial gpiozero

# Wrong directory
cd /home/jackiegreybard/arcade-tracker

# Check imports work
python -c "from skeeball_routes import register_skeeball_routes"
```

## What You'll See

### GPIO Test Interface Shows:
- **Current GPIO Mode:** Mock or Real
- **Game State:** Credits, Score, Balls, Status
- **Simulated Buttons:** All GPIO switches
- **Event Log:** Timestamped action history
- **Mode Toggle:** Switch between mock/real

### Full Simulator Shows:
- Interactive game display
- Roll outcome buttons
- Complete scoring sequences
- Event history

### Control Panel Shows:
- All active lanes
- Status indicators
- Quick actions
- Auto-refreshing state

### Statistics Shows:
- Total games played
- Best score
- Average score
- Total coins inserted

## Next Steps After Testing

1. ✅ **Test mock GPIO** - Verify everything works
2. 📝 **Try all interfaces** - GPIO test, simulator, control, stats
3. 🎮 **Play complete games** - Test full game flows
4. 📊 **Check statistics** - Verify tracking works
5. 🔧 **When ready for hardware** - Change `.env.skeeball` to `USE_REAL_GPIO=true`

## Documentation

- **This file:** Quick start
- **MOCK_GPIO_SETUP_COMPLETE.md:** Detailed setup info
- **GPIO_TESTING_README.md:** Hardware transition guide
- **SKEEBALL_INTEGRATION_SUMMARY.md:** Complete integration details

---

## Ready? Let's Go! 🚀

```bash
python app.py
```

Then open: http://localhost:5000/skeeball/gpio-test

**Have fun testing! 🎳**
