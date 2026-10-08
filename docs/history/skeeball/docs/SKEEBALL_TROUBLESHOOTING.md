# Skeeball Troubleshooting - Display Not Updating

## Issue
The simulator display shows 0/0/0 and doesn't update when buttons are clicked.

## Recent Fixes Applied

1. **Fixed manual control logic** - Buttons now check for credits OR in_progress correctly
2. **Added error handling** - Better logging when requests fail
3. **Force immediate update** - Page loads and updates display faster
4. **Updated game state immediately** - Local state updates on coin insert

## Troubleshooting Steps

### Step 1: Hard Refresh the Page
The browser may be caching old JavaScript:
- **Chrome/Firefox:** Press `Ctrl + Shift + R` (or `Cmd + Shift + R` on Mac)
- **Clear cache:** DevTools → Network tab → Check "Disable cache"

### Step 2: Check Browser Console
Open DevTools (F12) and look for errors:

**Expected (Good):**
```
Status fetch successful
Game state updating...
```

**Error Signs:**
```
Failed to fetch
Unexpected token '<'
<!DOCTYPE html> is not valid JSON
401 Unauthorized
```

### Step 3: Verify You're Logged In
If you see JSON parse errors, you may have been logged out:
1. Go to main dashboard: http://localhost:5000/
2. Verify you see the navigation bar
3. Return to simulator

### Step 4: Check Network Tab
In DevTools → Network tab:
1. Click "💰 Coin" button
2. Look for request to `/skeeball/api/simulator/insert-coin`
3. Check response:
   - **Status 200** = Good
   - **Status 302** = Redirect (not logged in)
   - **Status 500** = Server error

### Step 5: Restart Application
```bash
# Stop the app (Ctrl+C)
# Restart
python app.py
```

Look for:
```
🧪 Mock GPIO initialized (testing mode - no hardware required)
✅ Skeeball routes registered
 * Running on http://0.0.0.0:5000
```

### Step 6: Test API Directly
Open a new tab and test the API:
```
http://localhost:5000/skeeball/api/lanes/lane_1/status
```

**Expected Response:**
```json
{
  "credits": 0,
  "score": 0,
  "balls": 0,
  "in_progress": false,
  "total_balls": 9,
  ...
}
```

**If you see HTML instead** → You're not logged in or route isn't working

## Common Issues

### Issue: Buttons Say "Insert Coin First"
**Cause:** Manual control buttons require credits
**Fix:** Click "💰 Coin" button first
**OR:** Use the Roll Outcome buttons (they auto-insert coins)

### Issue: Display Shows All Zeros
**Causes:**
1. JavaScript not loading
2. Not logged in (API returns login page HTML)
3. Browser cache showing old version
4. Backend not running

**Solutions:**
1. Hard refresh (Ctrl + Shift + R)
2. Log in again
3. Check console for errors
4. Restart `python app.py`

### Issue: GPIO Test Page Errors
The errors you saw (`Unexpected token '<', "<!doctype "... is not valid JSON`) mean:
1. **You're not logged in** - Flask redirected to login page (HTML)
2. JavaScript tried to parse HTML as JSON → Error

**Fix:** Just log in to the application first

## Testing the Fix

### Test 1: Simulator Display Updates
```
1. Open simulator: http://localhost:5000/skeeball/simulator
2. Open DevTools Console (F12)
3. Click "💰 Coin"
4. Watch display:
   ✅ Should change from Credits: 0 → Credits: 1
   ✅ Status should change from "Idle" → "Ready"
5. Click any Roll Outcome button
   ✅ Should show Score updating
   ✅ Balls should increment
```

### Test 2: Manual Controls
```
1. Click "💰 Coin" first
2. Wait to see Credits: 1
3. Click "⊕ +10" button
4. Click "🎱 Ball" button
   ✅ Should see Score: 10, Balls: 1/9
```

### Test 3: Auto-Update
```
1. Don't touch anything
2. Watch the display for 5 seconds
   ✅ Should see numbers (even if 0)
   ✅ If stuck loading → Check console errors
```

## Quick Fixes

### Fix 1: Clear Everything and Start Fresh
```bash
# Stop app
Ctrl+C

# Clear browser cache
# In browser: Ctrl + Shift + Delete → Clear cache

# Restart app
python app.py

# Log in again
# Hard refresh simulator page: Ctrl + Shift + R
```

### Fix 2: Check Login Status
```
1. Go to: http://localhost:5000/
2. If you see login page → Log in
3. Then go to: http://localhost:5000/skeeball/simulator
```

### Fix 3: Test with curl
```bash
# Test status endpoint (should return JSON)
curl http://localhost:5000/skeeball/api/lanes/lane_1/status

# If it returns HTML → Not logged in or route issue
# If it returns JSON → Backend is working!
```

## What Should Work Now

After the fixes:

✅ Display updates automatically every second
✅ Coin button adds credit (Credits: 0 → 1)
✅ Manual control buttons work when you have credits
✅ Roll outcome buttons auto-insert coin if needed
✅ Game log shows all events clearly
✅ Better error messages in console

## If Still Not Working

### Check These Files Were Updated:
```bash
ls -la game_logic.py
# Should show recent timestamp

ls -la templates/skeeball/simulator.html
# Should show recent timestamp
```

### Verify Game Logic:
```bash
python -c "
from game_logic import GameLogic
game = GameLogic('test')
game.handle_event('coin')
print(f'After coin: credits={game.credits}, in_progress={game.in_progress}')
"
```

**Expected output:**
```
💰 Credit added! Credits: 1
After coin: credits=1, in_progress=False
```

## Contact Points

If none of this works:
1. Check browser console (F12) for specific error
2. Check Flask terminal output for Python errors
3. Share the exact error message from console

---

**The fix is deployed - just need a hard refresh!** 🔄
