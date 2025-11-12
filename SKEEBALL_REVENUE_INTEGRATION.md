# Skeeball Revenue Integration

This document describes how the skeeball system integrates with the arcade tracker's revenue tracking system.

## Overview

The skeeball lanes can now be registered as games in the arcade tracker database, allowing coin insertions to be tracked and automatically synced to the revenue system on a daily basis.

## Features

- **Automatic Coin Tracking**: Every coin inserted is tracked per lane
- **Daily Revenue Sync**: Revenue automatically syncs to the database at midnight
- **Manual Sync**: Ability to manually trigger revenue sync at any time
- **Game Integration**: Skeeball lanes appear in the main games list
- **Revenue Reports**: Skeeball revenue appears in all standard revenue reports

## Setup

### 1. Register a Skeeball Lane as a Game

Use the registration endpoint to create a game entry for your skeeball lane:

```bash
POST /skeeball/api/lanes/{lane_id}/register-game
```

**Request Body:**
```json
{
  "name": "Skeeball Lane 1",
  "manufacturer": "Skeeball Inc.",
  "year": 2025,
  "location": "Floor",
  "floor_position": "Front Row",
  "coins_per_play": 0.25
}
```

**Response:**
```json
{
  "message": "Lane registered as game",
  "game_id": 123,
  "game_name": "Skeeball Lane 1"
}
```

After registration, the lane will automatically track coins and the game will appear in your games list.

### 2. Automatic Revenue Sync

The revenue scheduler runs automatically and syncs all lanes at midnight each night. No manual intervention required!

**What happens at midnight:**
1. System checks all registered lanes
2. For each lane with coins inserted today:
   - Creates a PlayRecord with today's plays and revenue
   - Updates the game's total plays and revenue
   - Resets the lane's daily coin counter to 0

## API Endpoints

### Get Revenue Data for a Lane

```bash
GET /skeeball/api/lanes/{lane_id}/revenue
```

**Response:**
```json
{
  "lane_id": "lane_1",
  "game_db_id": 123,
  "daily_coins": 25,
  "last_sync": "2025-11-07T00:00:00"
}
```

### Manually Sync a Lane's Revenue

```bash
POST /skeeball/api/lanes/{lane_id}/sync-revenue
```

**Response:**
```json
{
  "message": "Revenue synced successfully",
  "game_id": 123,
  "game_name": "Skeeball Lane 1",
  "plays": 25,
  "revenue": 6.25,
  "date": "2025-11-07"
}
```

### Manually Sync All Lanes

```bash
POST /skeeball/api/revenue/sync-all
```

**Response:**
```json
{
  "message": "Revenue sync triggered for all lanes"
}
```

## How It Works

### Coin Tracking

1. When a coin is inserted (via GPIO or simulator):
   - `lane.stats["total_coins"]` increments (lifetime total)
   - `lane.daily_coins` increments (today's count)

2. The daily coin counter tracks how many coins have been inserted since the last sync

### Revenue Recording

When revenue is synced (automatically or manually):

1. **PlayRecord Created**: A new record is added with:
   - `coin_count`: Cumulative total coins (for reference)
   - `plays_count`: Number of plays today (= daily_coins)
   - `revenue`: Calculated as plays × coins_per_play
   - `date_recorded`: Today's date

2. **Game Totals Updated**:
   - `game.total_plays` += daily_coins
   - `game.total_revenue` += calculated revenue

3. **Daily Counter Reset**:
   - `lane.daily_coins` = 0
   - `lane.last_revenue_sync` = current time

### Revenue Scheduler

The `RevenueScheduler` class runs in a background thread:

- Checks every 60 seconds if it's past midnight
- Once per day, syncs all registered lanes
- Logs all sync operations for audit trail
- Handles errors gracefully (continues even if one lane fails)

## Testing

Use the included test script to verify the integration:

```bash
python3 test_skeeball_revenue.py
```

This script will:
1. Register a test lane as a game
2. Insert 5 coins via the simulator
3. Verify coin tracking is working
4. Sync revenue to the database
5. Verify the revenue was recorded correctly

## Production Deployment

### On the Raspberry Pi with Real Hardware

1. **Start the Flask app** - The revenue scheduler starts automatically
2. **Register your lanes** - Use the API or web UI to register each physical lane
3. **Set coin value** - Configure `coins_per_play` for each game (default: $0.25)
4. **Monitor logs** - Check for successful midnight syncs in the application logs

### Configuration

The revenue scheduler uses these defaults:
- **Sync time**: Midnight (00:00)
- **Check interval**: 60 seconds
- **Daemon thread**: Yes (stops when app stops)

To customize the sync time (optional):

```python
# In skeeball_routes.py, modify get_lane_manager():
from datetime import time
scheduler.start(sync_time=time(23, 59))  # 11:59 PM
```

## Revenue Reports

Once lanes are registered and revenue is syncing:

1. **Games List** (`/games`): Shows skeeball lanes alongside other arcade games
2. **Revenue Reports** (`/revenue_reports`): Includes skeeball revenue in totals
3. **Game Details**: Click on a skeeball game to see play history
4. **Export**: CSV and PDF exports include skeeball data

## Maintenance

### View Today's Coins (Before Sync)

Check the simulator page or use:
```bash
GET /skeeball/api/lanes/lane_1/revenue
```

### Force a Sync (Don't Wait for Midnight)

```bash
POST /skeeball/api/lanes/lane_1/sync-revenue
```

Or sync all lanes at once:
```bash
POST /skeeball/api/revenue/sync-all
```

### Unlink a Lane

Currently, there's no automated way to unlink a lane. To remove the connection:
1. Set the game's status to "Retired" in the web UI
2. Or manually clear `lane.game_db_id` via Python console

## Troubleshooting

### Lane Not Syncing

**Check if registered:**
```bash
GET /skeeball/api/lanes/lane_1/revenue
```
If `game_db_id` is `null`, the lane isn't registered.

**Solution:** Register the lane using `/register-game`

### Coins Not Counting

**Check the lane status:**
```bash
GET /skeeball/api/lanes/lane_1/status
```

Verify that coin events are being received by the lane manager.

### Revenue Scheduler Not Running

Check if the scheduler was initialized:
- Look for "✅ Revenue scheduler started" in the logs
- The scheduler starts automatically when the first lane manager is created

### Double-Counting Revenue

**Never manually sync the same day twice!** The daily counter should only be synced once per day. If you accidentally sync twice:

1. Find the duplicate PlayRecord in the database
2. Subtract the duplicate from the game's totals
3. Delete the duplicate record

## Future Enhancements

Possible improvements:
- Web UI button to manually trigger sync
- Dashboard widget showing today's unsynced coins
- Email alerts if sync fails
- Multi-day buffering if system is offline
- Per-lane revenue reports
- Configurable sync times per lane

## Technical Details

### Files Modified/Created

- `lane_controller.py`: Added daily coin tracking
- `skeeball_routes.py`: Added revenue API endpoints
- `revenue_scheduler.py`: New file for automatic syncing
- `test_skeeball_revenue.py`: Test script

### Database Schema

Uses existing tables:
- `Game`: Skeeball lanes registered here
- `PlayRecord`: Daily revenue records created here

No schema changes required!

### Thread Safety

The revenue scheduler runs in a daemon thread. All database operations use Flask's app context to ensure thread safety with SQLAlchemy.
