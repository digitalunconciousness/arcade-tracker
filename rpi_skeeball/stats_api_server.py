#!/usr/bin/env python3
"""
Stats API Server for Raspberry Pi
Exposes real-time skeeball game statistics to the Flask app.
"""

from flask import Flask, jsonify
from flask_cors import CORS
import threading
import json
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
CORS(app)  # Allow Flask app to fetch data from different host

# Shared state - will be updated by skeeball_main.py
game_state = {
    "current_score": 0,
    "balls_remaining": 9,
    "game_active": False,
    "total_coins_inserted": 0,
    "total_games_played": 0,
    "current_ball_score": 0,
    "last_updated": None,
}

game_history = []
game_stats = {
    "high_score": 0,
    "average_score": 0,
    "total_score": 0,
}

state_lock = threading.Lock()
STATE_FILE = 'realtime_state.json'


def update_game_state(state_data):
    """Update the shared game state (called from skeeball_main.py)."""
    global game_state, game_stats
    with state_lock:
        game_state.update(state_data)
        game_state["last_updated"] = datetime.now().isoformat()
        # Persist to a shared file so other processes (GPIO monitor) can update state
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(game_state, f)
        except Exception:
            pass


def load_realtime_state():
    """Load latest state from the shared file and also reload game_history for stats."""
    global game_history, game_stats
    try:
        path = Path(STATE_FILE)
        if path.exists():
            with open(path, 'r') as f:
                file_state = json.load(f)
            last_updated = file_state.get('last_updated')
            if last_updated:
                try:
                    from datetime import datetime as _dt
                    age = (_dt.now() - _dt.fromisoformat(last_updated)).total_seconds()
                    if age < 5:
                        with state_lock:
                            game_state.update(file_state)
                        
                        # Also reload game_history from source file for accurate stats
                        source_file = Path('/home/skeeproto/rpi_skeeball/skeeball_state.json')
                        if source_file.exists():
                            try:
                                with open(source_file, 'r') as sf:
                                    source_state = json.load(sf)
                                history = source_state.get('game_history', [])
                                game_history = history[-100:]  # Keep last 100 games
                                
                                # Recalculate stats
                                if game_history:
                                    scores = [g['score'] for g in game_history]
                                    game_stats["high_score"] = max(scores)
                                    game_stats["total_score"] = sum(scores)
                                    game_stats["average_score"] = sum(scores) / len(scores)
                                else:
                                    game_stats["high_score"] = 0
                                    game_stats["total_score"] = 0
                                    game_stats["average_score"] = 0
                            except Exception:
                                pass
                        
                        return True
                except Exception:
                    # If timestamp parse fails, still update
                    with state_lock:
                        game_state.update(file_state)
                    return True
    except Exception:
        pass
    return False


def update_game_history(game_record):
    """Add a game to the history (called from skeeball_main.py)."""
    global game_history, game_stats
    with state_lock:
        game_history.append(game_record)
        
        # Keep only last 100 games
        if len(game_history) > 100:
            game_history = game_history[-100:]
        
        # Update stats
        scores = [g['score'] for g in game_history]
        game_stats["high_score"] = max(scores) if scores else 0
        game_stats["total_score"] = sum(scores)
        game_stats["average_score"] = sum(scores) / len(scores) if scores else 0


def load_state_from_file():
    """Load persisted state on startup."""
    global game_state, game_history, game_stats
    
    state_file = Path('/home/skeeproto/rpi_skeeball/skeeball_state.json')
    if state_file.exists():
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                
                with state_lock:
                    game_state['total_coins_inserted'] = state.get('total_coins_inserted', 0)
                    game_state['total_games_played'] = state.get('total_games_played', 0)
                    
                    # Load game history
                    history = state.get('game_history', [])
                    game_history.extend(history[-100:])  # Last 100 games
                    
                    # Calculate stats
                    if game_history:
                        scores = [g['score'] for g in game_history]
                        game_stats["high_score"] = max(scores)
                        game_stats["total_score"] = sum(scores)
                        game_stats["average_score"] = sum(scores) / len(scores)
                    
                print(f"📊 Loaded state - Coins: {game_state['total_coins_inserted']}, Games: {game_state['total_games_played']}")
        except Exception as e:
            print(f"⚠️  Error loading state: {e}")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "online",
        "service": "skeeball_stats_api",
        "last_updated": game_state.get("last_updated")
    })


@app.route('/api/game/status', methods=['GET'])
def get_game_status():
    """Get current game status."""
    load_realtime_state()
    with state_lock:
        return jsonify({
            "lane_id": "lane_1",  # Primary lane
            "current_score": game_state["current_score"],
            "balls_remaining": game_state["balls_remaining"],
            "game_active": game_state["game_active"],
            "current_ball_score": game_state.get("current_ball_score", 0),
            "credits": 1 if game_state["game_active"] else 0,
            "score": game_state["current_score"],
            "balls": 9 - game_state["balls_remaining"],  # Balls played
            "total_balls": 9,
            "in_progress": game_state["game_active"],
            "is_online": True,
            "last_event": game_state.get("last_updated"),
            "last_updated": game_state.get("last_updated")
        })


@app.route('/api/game/stats', methods=['GET'])
def get_game_stats():
    """Get accumulated game statistics."""
    load_realtime_state()
    with state_lock:
        return jsonify({
            "lane_id": "lane_1",
            "total_games": game_state["total_games_played"],
            "total_coins": game_state["total_coins_inserted"],
            "total_score": game_stats["total_score"],
            "best_score": game_stats["high_score"],
            "average_score": round(game_stats["average_score"], 1),
            "games_today": len(game_history)
        })


@app.route('/api/game/history', methods=['GET'])
def get_game_history():
    """Get recent game history."""
    with state_lock:
        return jsonify({
            "games": game_history[-20:],  # Last 20 games
            "total_games": len(game_history)
        })


@app.route('/api/lanes', methods=['GET'])
def get_all_lanes():
    """Get all lanes (compatible with Flask app format)."""
    load_realtime_state()
    with state_lock:
        lane_data = {
            "lane_1": {
                "lane_id": "lane_1",
                "credits": 1 if game_state["game_active"] else 0,
                "score": game_state["current_score"],
                "balls": 9 - game_state["balls_remaining"],
                "total_balls": 9,
                "in_progress": game_state["game_active"],
                "is_online": True,
                "last_event": game_state.get("last_updated")
            }
        }
        return jsonify(lane_data)


@app.route('/api/lanes/lane_1/status', methods=['GET'])
def get_lane_status():
    """Get lane status (compatible with Flask app format)."""
    return get_game_status()


@app.route('/api/lanes/lane_1/stats', methods=['GET'])
def get_lane_stats():
    """Get lane statistics (compatible with Flask app format)."""
    return get_game_stats()


def start_api_server(port=5002, debug=False):
    """Start the API server in a background thread."""
    # Load state on startup
    load_state_from_file()
    
    server_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False),
        daemon=True
    )
    server_thread.start()
    print(f"✅ Stats API Server started on port {port}")
    return server_thread


if __name__ == '__main__':
    print("\n🚀 Skeeball Stats API Server")
    print("=" * 50)
    print("   Access at: http://<raspberry-pi-ip>:5002")
    print("   Press Ctrl+C to stop\n")
    
    load_state_from_file()
    app.run(host='0.0.0.0', port=5002, debug=False)
