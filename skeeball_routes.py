#!/usr/bin/env python3
"""Flask routes for skeeball lane control and testing.

Provides HTTP API and WebSocket support for interacting with skeeball lanes.
Integrates with arcade-tracker for UI and management.
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required
import config
from lane_manager import LaneManager
from game_logic import GameLogic
from gpio_init import init_gpio, get_gpio_status, is_using_mock_gpio, switch_to_mock, switch_to_real

# Create blueprint
skeeball_bp = Blueprint(
    'skeeball',
    __name__,
    url_prefix='/skeeball',
    template_folder='templates/skeeball'
)


def get_lane_manager():
    """Get or create the lane manager singleton."""
    if not hasattr(current_app, 'lane_manager'):
        # Initialize GPIO first
        if not hasattr(current_app, 'gpio_initialized'):
            is_mock, message = init_gpio()
            current_app.gpio_initialized = True
            current_app.gpio_is_mock = is_mock
            print(message)
        
        current_app.lane_manager = LaneManager(auto_discover=False)
        current_app.lane_manager.register_local_lane("lane_1", None)
        current_app.lane_manager.start_polling()
        
        # Initialize revenue scheduler
        if not hasattr(current_app, 'revenue_scheduler'):
            from revenue_scheduler import init_revenue_scheduler
            current_app.revenue_scheduler = init_revenue_scheduler(current_app._get_current_object(), current_app.lane_manager)
    
    return current_app.lane_manager


# ============================================================================
# UI ROUTES
# ============================================================================

@skeeball_bp.route('/')
@login_required
def skeeball_home():
    """Main skeeball control page."""
    return render_template('skeeball/index.html')


@skeeball_bp.route('/control')
@login_required
def skeeball_control():
    """Skeeball lane control panel."""
    manager = get_lane_manager()
    lanes = manager.get_all_status()
    return render_template('skeeball/control.html', lanes=lanes)


@skeeball_bp.route('/simulator')
@login_required
def skeeball_simulator():
    """Interactive skeeball simulator for testing."""
    return render_template('skeeball/simulator.html', config=config.__dict__)


@skeeball_bp.route('/stats')
@login_required
def skeeball_stats():
    """Statistics and reporting for all lanes."""
    manager = get_lane_manager()
    stats = {
        lane_id: lane.get_stats()
        for lane_id, lane in manager.get_all_lanes().items()
    }
    return render_template('skeeball/stats.html', stats=stats)


@skeeball_bp.route('/gpio-test')
@login_required
def gpio_test():
    """GPIO testing interface for simulating hardware button presses."""
    return render_template('skeeball/gpio_test.html')


# ============================================================================
# API ROUTES
# ============================================================================

@skeeball_bp.route('/api/lanes', methods=['GET'])
@login_required
def api_get_lanes():
    """Get all lanes and their status."""
    manager = get_lane_manager()
    lanes = manager.get_all_status()
    return jsonify(lanes)


@skeeball_bp.route('/api/lanes/<lane_id>/status', methods=['GET'])
@login_required
def api_get_lane_status(lane_id):
    """Get status of a specific lane."""
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/lanes/<lane_id>/trigger', methods=['POST'])
@login_required
def api_trigger_event(lane_id):
    """Manually trigger an event on a lane (for testing)."""
    data = request.get_json()
    event = data.get('event')
    event_data = data.get('data')
    
    if not event:
        return jsonify({"error": "Missing event"}), 400
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    # Trigger the event
    lane.handle_event(event, event_data)
    
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/lanes/<lane_id>/reset', methods=['POST'])
@login_required
def api_reset_lane(lane_id):
    """Reset a lane's game state."""
    manager = get_lane_manager()
    if manager.reset_lane(lane_id):
        lane = manager.get_lane(lane_id)
        return jsonify(lane.get_status())
    return jsonify({"error": "Lane not found"}), 404


@skeeball_bp.route('/api/lanes/<lane_id>/stats', methods=['GET'])
@login_required
def api_get_lane_stats(lane_id):
    """Get statistics for a specific lane."""
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    return jsonify(lane.get_stats())


@skeeball_bp.route('/api/health', methods=['GET'])
@login_required
def api_health():
    """Get health status of all lanes."""
    manager = get_lane_manager()
    health = {}
    for lane_id, lane in manager.get_all_lanes().items():
        health[lane_id] = {
            "online": lane.is_online(),
            "status": "🟢 OK" if lane.is_online() else "🔴 OFFLINE"
        }
    return jsonify(health)


@skeeball_bp.route('/api/gpio/status', methods=['GET'])
@login_required
def api_gpio_status():
    """Get GPIO mode status (mock or real hardware)."""
    return jsonify(get_gpio_status())


@skeeball_bp.route('/api/gpio/switch-mode', methods=['POST'])
@login_required
def api_gpio_switch_mode():
    """Switch GPIO mode (testing only)."""
    data = request.get_json()
    mode = data.get('mode', 'mock')
    
    if mode == 'mock':
        message = switch_to_mock()
    elif mode == 'real':
        message = switch_to_real()
    else:
        return jsonify({"error": "Invalid mode. Use 'mock' or 'real'"}), 400
    
    return jsonify({
        "message": message,
        "status": get_gpio_status()
    })


@skeeball_bp.route('/api/hardware/control', methods=['POST'])
@login_required
def api_hardware_control():
    """Control hardware switches (LED power, solenoid, etc.)."""
    import requests
    import os
    
    data = request.get_json()
    device = data.get('device')
    action = data.get('action')
    
    if not device or not action:
        return jsonify({"error": "Missing device or action"}), 400
    
    # Special case: system reset is handled locally (no GPIO needed)
    if device == 'system' and action == 'reset':
        try:
            manager = get_lane_manager()
            for lane_id in manager.get_all_lanes().keys():
                manager.reset_lane(lane_id)
            return jsonify({"message": "System reset - all lanes cleared"})
        except Exception as e:
            return jsonify({"error": f"System reset failed: {str(e)}"}), 500
    
    # For hardware controls, forward to Raspberry Pi GPIO API server
    # Get Pi address from environment or use default
    pi_host = os.getenv('RPI_GPIO_HOST', 'skeeproto@sp1.local')
    pi_port = os.getenv('RPI_GPIO_PORT', '5001')
    pi_url = f"http://{pi_host}:{pi_port}/gpio/control"
    
    try:
        # Forward the request to the Raspberry Pi
        response = requests.post(
            pi_url,
            json={'device': device, 'action': action},
            timeout=5
        )
        
        if response.ok:
            result = response.json()
            return jsonify(result)
        else:
            error_data = response.json() if response.headers.get('content-type') == 'application/json' else {"error": response.text}
            return jsonify(error_data), response.status_code
    
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": f"Cannot connect to Raspberry Pi at {pi_host}:{pi_port}",
            "hint": "Make sure the GPIO API server is running on the Pi (python3 rpi_skeeball/gpio_api_server.py)"
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request to Raspberry Pi timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"Hardware control failed: {str(e)}"}), 500


@skeeball_bp.route('/api/roll-outcome', methods=['POST'])
@login_required
def api_roll_outcome():
    """Simulate a roll outcome (sequence of events)."""
    data = request.get_json()
    lane_id = data.get('lane_id', 'lane_1')
    outcome = data.get('outcome', 'Miss')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    # Get or create game if not in progress
    if not lane.game.in_progress:
        if lane.game.credits == 0:
            lane.handle_event("coin", None)
        # Game should start automatically, but ensure credits are consumed
    
    # Map outcome to sequence of events
    sequences = {
        "Miss": [("ball_scored", None)],
        "10": [("score", "score_10"), ("ball_scored", None)],
        "20": [("score", "score_10")] * 2 + [("ball_scored", None)],
        "30": [("score", "score_10")] * 3 + [("ball_scored", None)],
        "40": [("score", "score_10")] * 4 + [("ball_scored", None)],
        "50": [("score", "score_10")] * 5 + [("ball_scored", None)],
        "100": [("score", "score_50")] + [("score", "score_10")] * 5 + [("ball_scored", None)],
    }
    
    sequence = sequences.get(outcome, [("ball_scored", None)])
    
    # Execute sequence
    for event, event_data in sequence:
        lane.handle_event(event, event_data)
    
    return jsonify({
        "outcome": outcome,
        "lane_status": lane.get_status(),
        "sequence_executed": len(sequence)
    })


# ============================================================================
# SIMULATOR API
# ============================================================================

@skeeball_bp.route('/api/simulator/insert-coin', methods=['POST'])
@login_required
def api_simulator_coin():
    """Simulator: insert a coin."""
    data = request.get_json()
    lane_id = data.get('lane_id', 'lane_1')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    lane.handle_event("coin", None)
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/simulator/score-10', methods=['POST'])
@login_required
def api_simulator_score_10():
    """Simulator: trigger 10-point score."""
    data = request.get_json()
    lane_id = data.get('lane_id', 'lane_1')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    lane.handle_event("score", "score_10")
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/simulator/score-50', methods=['POST'])
@login_required
def api_simulator_score_50():
    """Simulator: trigger 50-point score."""
    data = request.get_json()
    lane_id = data.get('lane_id', 'lane_1')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    lane.handle_event("score", "score_50")
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/simulator/lane-track', methods=['POST'])
@login_required
def api_simulator_lane_track():
    """Simulator: trigger lane track."""
    data = request.get_json()
    lane_id = data.get('lane_id', 'lane_1')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    lane.handle_event("score", "lane_track")
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/simulator/ball-scored', methods=['POST'])
@login_required
def api_simulator_ball_scored():
    """Simulator: count a scored ball."""
    data = request.get_json()
    lane_id = data.get('lane_id', 'lane_1')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    lane.handle_event("ball_scored", None)
    return jsonify(lane.get_status())


@skeeball_bp.route('/api/machine/reset', methods=['POST'])
@login_required
def api_machine_reset():
    """Reset the entire machine (clear all lanes and stats)."""
    data = request.get_json() or {}
    lane_id = data.get('lane_id', 'lane_1')
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    # Reset the lane completely
    lane.reset_game()
    # Also reset statistics if requested
    if data.get('reset_stats', False):
        lane.stats = {
            "total_games": 0,
            "total_score": 0,
            "best_score": 0,
            "total_coins": 0,
        }
    
    return jsonify({
        "message": "Machine reset complete",
        "status": lane.get_status(),
        "stats": lane.get_stats()
    })


# ============================================================================
# REVENUE INTEGRATION API
# ============================================================================

@skeeball_bp.route('/api/lanes/<lane_id>/register-game', methods=['POST'])
@login_required
def api_register_lane_as_game(lane_id):
    """Register a skeeball lane as a Game in the arcade tracker database."""
    from app import db, Game
    from datetime import datetime
    import datetime as dt
    
    data = request.get_json() or {}
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    # Check if already registered
    game_name = data.get('name', f"Skeeball {lane_id}")
    existing_game = Game.query.filter_by(name=game_name).first()
    
    if existing_game:
        # Link to existing game
        lane.link_to_game(existing_game.id)
        return jsonify({
            "message": "Lane linked to existing game",
            "game_id": existing_game.id,
            "game_name": existing_game.name
        })
    
    # Create new game entry
    new_game = Game(
        name=game_name,
        manufacturer=data.get('manufacturer', 'Skeeball Inc.'),
        year=data.get('year'),
        genre='Skeeball',
        location=data.get('location', 'Floor'),
        floor_position=data.get('floor_position'),
        status='Working',
        coins_per_play=data.get('coins_per_play', 0.25),
        counter_status='Working',
        counter_notes='Digital counter via GPIO',
        notes=f'Registered skeeball lane: {lane_id}'
    )
    
    db.session.add(new_game)
    db.session.commit()
    
    # Link lane to game
    lane.link_to_game(new_game.id)
    
    return jsonify({
        "message": "Lane registered as game",
        "game_id": new_game.id,
        "game_name": new_game.name
    }), 201


@skeeball_bp.route('/api/lanes/<lane_id>/revenue', methods=['GET'])
@login_required
def api_get_lane_revenue(lane_id):
    """Get current daily revenue data for a lane."""
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    return jsonify(lane.get_daily_revenue_data())


@skeeball_bp.route('/api/lanes/<lane_id>/sync-revenue', methods=['POST'])
@login_required
def api_sync_lane_revenue(lane_id):
    """Sync lane revenue to the main arcade tracker system."""
    from app import db, Game, PlayRecord
    from datetime import date, datetime
    import datetime as dt
    
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    
    if not lane.game_db_id:
        return jsonify({"error": "Lane not linked to game. Call /register-game first."}), 400
    
    if lane.daily_coins == 0:
        return jsonify({"message": "No coins to sync", "daily_coins": 0})
    
    # Get the linked game
    game = Game.query.get(lane.game_db_id)
    if not game:
        return jsonify({"error": "Linked game not found in database"}), 404
    
    # Calculate plays and revenue
    plays = lane.daily_coins  # Each coin = 1 play for skeeball
    revenue = plays * game.coins_per_play
    
    # Create play record
    play_record = PlayRecord(
        game_id=game.id,
        coin_count=lane.stats["total_coins"],  # Cumulative total
        plays_count=plays,  # Today's plays
        revenue=revenue,
        date_recorded=date.today(),
        notes=f'Auto-synced from {lane_id}'
    )
    
    # Update game totals
    game.total_plays += plays
    game.total_revenue += revenue
    
    db.session.add(play_record)
    db.session.commit()
    
    # Reset daily counter
    lane.reset_daily_coins()
    
    return jsonify({
        "message": "Revenue synced successfully",
        "game_id": game.id,
        "game_name": game.name,
        "plays": plays,
        "revenue": revenue,
        "date": date.today().isoformat()
    })


@skeeball_bp.route('/api/revenue/sync-all', methods=['POST'])
@login_required
def api_sync_all_revenue():
    """Manually trigger revenue sync for all lanes."""
    if hasattr(current_app, 'revenue_scheduler'):
        current_app.revenue_scheduler.force_sync()
        return jsonify({"message": "Revenue sync triggered for all lanes"})
    else:
        return jsonify({"error": "Revenue scheduler not initialized"}), 500


def register_skeeball_routes(app):
    """Register skeeball blueprint with Flask app."""
    app.register_blueprint(skeeball_bp)
    print("✅ Skeeball routes registered")
