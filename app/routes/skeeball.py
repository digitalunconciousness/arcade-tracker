"""Skeeball blueprint — lane control, simulator, stats, and API endpoints."""

import os
from datetime import date

import requests as http_requests
from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import login_required

from app.extensions import db
from app.models import Game, PlayRecord

skeeball_bp = Blueprint(
    "skeeball",
    __name__,
    url_prefix="/skeeball",
    template_folder=os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "templates",
        "skeeball",
    ),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def get_or_create_game_for_lane(lane_id):
    """Get or create a Game entry for a skeeball lane."""
    lane_number = lane_id.split("_")[-1] if "_" in lane_id else lane_id
    game_name = f"Skeeball Lane {lane_number}"

    game = db.session.execute(
        db.select(Game).filter_by(name=game_name)
    ).scalar_one_or_none()

    if not game:
        game = Game(
            name=game_name,
            manufacturer="Custom",
            genre="Skeeball",
            location="Floor",
            status="Working",
            counter_status="Working",
            coins_per_play=1.0,
            notes=f"Automated skeeball lane managed by Raspberry Pi (lane_id: {lane_id})",
        )
        db.session.add(game)
        db.session.commit()

    return game


def fetch_from_raspberry_pi(endpoint, timeout=3):
    """Fetch data from Raspberry Pi stats API."""
    rpi_host = os.getenv("RPI_STATS_HOST", os.getenv("RPI_GPIO_HOST", "localhost"))
    rpi_port = os.getenv("RPI_STATS_PORT", "5002")

    if "@" in rpi_host:
        rpi_host = rpi_host.split("@")[1]
    if rpi_host.endswith(".local"):
        rpi_host = rpi_host[:-6]

    url = f"http://{rpi_host}:{rpi_port}{endpoint}"

    try:
        response = http_requests.get(url, timeout=timeout)
        if response.ok:
            return response.json()
        return None
    except (http_requests.RequestException, http_requests.Timeout, ConnectionError):
        return None


def get_lane_manager():
    """Get or create the lane manager singleton."""
    if not hasattr(current_app, "lane_manager"):
        try:
            from skeeball.gpio_init import init_gpio
        except ImportError:
            from gpio_init import init_gpio

        if not hasattr(current_app, "gpio_initialized"):
            is_mock, message = init_gpio()
            current_app.gpio_initialized = True
            current_app.gpio_is_mock = is_mock
            print(message)

        try:
            from skeeball.lane_manager import LaneManager
        except ImportError:
            from lane_manager import LaneManager

        current_app.lane_manager = LaneManager(auto_discover=False)
        current_app.lane_manager.register_local_lane("lane_1", None)
        current_app.lane_manager.start_polling()

        current_app.lane_needs_db_init = True

        if not hasattr(current_app, "revenue_scheduler"):
            try:
                from skeeball.revenue_scheduler import init_revenue_scheduler
            except ImportError:
                from revenue_scheduler import init_revenue_scheduler
            current_app.revenue_scheduler = init_revenue_scheduler(
                current_app._get_current_object(), current_app.lane_manager
            )

    # On first actual request, link to database
    if getattr(current_app, "lane_needs_db_init", False):
        try:
            from flask import has_app_context, has_request_context
            from sqlalchemy import text

            if has_app_context() and has_request_context():
                db_ext = current_app.extensions.get("sqlalchemy")
                if not db_ext:
                    return current_app.lane_manager

                with db.engine.connect() as connection:
                    result = connection.execute(
                        text("SELECT name FROM sqlite_master WHERE type='table' AND name='game'")
                    )
                    if result.fetchone() is None:
                        return current_app.lane_manager

                game = get_or_create_game_for_lane("lane_1")

                lane = current_app.lane_manager.get_lane("lane_1")
                if lane:
                    lane.link_to_game(game.id)

                if not hasattr(current_app, "lane_game_mapping"):
                    current_app.lane_game_mapping = {}
                current_app.lane_game_mapping["lane_1"] = game.id

                current_app.lane_needs_db_init = False
        except Exception as e:
            from flask import has_request_context

            if has_request_context():
                print(f"⚠️ Database not ready for lane initialization: {e}")

    return current_app.lane_manager


# ============================================================================
# UI ROUTES
# ============================================================================


@skeeball_bp.route("/")
@login_required
def skeeball_home():
    """Main skeeball control page."""
    return render_template("skeeball/index.html")


@skeeball_bp.route("/control")
@login_required
def skeeball_control():
    """Skeeball lane control panel."""
    manager = get_lane_manager()
    lanes = manager.get_all_status()
    return render_template("skeeball/control.html", lanes=lanes)


@skeeball_bp.route("/simulator")
@login_required
def skeeball_simulator():
    """Interactive skeeball simulator for testing."""
    try:
        import config as skeeball_config

        conf = skeeball_config.__dict__
    except ImportError:
        conf = {}
    return render_template("skeeball/simulator.html", config=conf)


@skeeball_bp.route("/stats")
@login_required
def skeeball_stats():
    """Statistics and reporting for all lanes."""
    manager = get_lane_manager()
    stats = {
        lane_id: lane.get_stats()
        for lane_id, lane in manager.get_all_lanes().items()
    }
    return render_template("skeeball/stats.html", stats=stats)


@skeeball_bp.route("/gpio-test")
@login_required
def gpio_test():
    """GPIO testing interface."""
    return render_template("skeeball/gpio_test.html")


@skeeball_bp.route("/logs")
@login_required
def skeeball_logs():
    """Live log viewer."""
    return render_template("skeeball/logs.html")


# ============================================================================
# API ROUTES
# ============================================================================


@skeeball_bp.route("/api/lanes", methods=["GET"])
def api_get_lanes():
    """Get all lanes and their status."""
    pi_data = fetch_from_raspberry_pi("/api/lanes")
    if pi_data is not None:
        return jsonify(pi_data)

    manager = get_lane_manager()
    lanes = manager.get_all_status()
    return jsonify(lanes)


@skeeball_bp.route("/api/lanes/<lane_id>/status", methods=["GET"])
def api_get_lane_status(lane_id):
    """Get status of a specific lane."""
    pi_data = fetch_from_raspberry_pi(f"/api/lanes/{lane_id}/status")
    if pi_data is not None:
        return jsonify(pi_data)

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/lanes/<lane_id>/trigger", methods=["POST"])
@login_required
def api_trigger_event(lane_id):
    """Manually trigger an event on a lane (for testing)."""
    data = request.get_json()
    event = data.get("event")
    event_data = data.get("data")

    if not event:
        return jsonify({"error": "Missing event"}), 400

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.handle_event(event, event_data)
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/lanes/<lane_id>/reset", methods=["POST"])
@login_required
def api_reset_lane(lane_id):
    """Reset a lane's game state."""
    manager = get_lane_manager()
    if manager.reset_lane(lane_id):
        lane = manager.get_lane(lane_id)
        return jsonify(lane.get_status())
    return jsonify({"error": "Lane not found"}), 404


@skeeball_bp.route("/api/lanes/<lane_id>/stats", methods=["GET"])
def api_get_lane_stats(lane_id):
    """Get statistics for a specific lane."""
    pi_data = fetch_from_raspberry_pi(f"/api/lanes/{lane_id}/stats")
    if pi_data is not None:
        return jsonify(pi_data)

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404
    return jsonify(lane.get_stats())


@skeeball_bp.route("/api/health", methods=["GET"])
def api_health():
    """Get health status of all lanes."""
    manager = get_lane_manager()
    health = {}
    for lane_id, lane in manager.get_all_lanes().items():
        health[lane_id] = {
            "online": lane.is_online(),
            "status": "🟢 OK" if lane.is_online() else "🔴 OFFLINE",
        }
    return jsonify(health)


@skeeball_bp.route("/api/gpio/status", methods=["GET"])
@login_required
def api_gpio_status():
    """Get GPIO mode status (mock or real hardware)."""
    try:
        from skeeball.gpio_init import get_gpio_status
    except ImportError:
        from gpio_init import get_gpio_status
    return jsonify(get_gpio_status())


@skeeball_bp.route("/api/gpio/switch-mode", methods=["POST"])
@login_required
def api_gpio_switch_mode():
    """Switch GPIO mode (testing only)."""
    try:
        from skeeball.gpio_init import get_gpio_status, switch_to_mock, switch_to_real
    except ImportError:
        from gpio_init import get_gpio_status, switch_to_mock, switch_to_real

    data = request.get_json()
    mode = data.get("mode", "mock")

    if mode == "mock":
        message = switch_to_mock()
    elif mode == "real":
        message = switch_to_real()
    else:
        return jsonify({"error": "Invalid mode. Use 'mock' or 'real'"}), 400

    return jsonify({"message": message, "status": get_gpio_status()})


@skeeball_bp.route("/api/hardware/control", methods=["POST"])
@login_required
def api_hardware_control():
    """Control hardware switches (LED power, solenoid, etc.)."""
    data = request.get_json()
    device = data.get("device")
    action = data.get("action")

    if not device or not action:
        return jsonify({"error": "Missing device or action"}), 400

    # System reset is handled locally
    if device == "system" and action == "reset":
        try:
            manager = get_lane_manager()
            for lane_id in manager.get_all_lanes().keys():
                manager.reset_lane(lane_id)
            return jsonify({"message": "System reset - all lanes cleared"})
        except Exception as e:
            return jsonify({"error": f"System reset failed: {str(e)}"}), 500

    # Forward to Raspberry Pi GPIO API server
    pi_host = os.getenv("RPI_GPIO_HOST", "skeeproto@sp1.local")
    pi_port = os.getenv("RPI_GPIO_PORT", "5001")
    pi_url = f"http://{pi_host}:{pi_port}/gpio/control"

    try:
        response = http_requests.post(
            pi_url, json={"device": device, "action": action}, timeout=5
        )
        if response.ok:
            return jsonify(response.json())
        error_data = (
            response.json()
            if response.headers.get("content-type") == "application/json"
            else {"error": response.text}
        )
        return jsonify(error_data), response.status_code
    except http_requests.exceptions.ConnectionError:
        return jsonify(
            {
                "error": f"Cannot connect to Raspberry Pi at {pi_host}:{pi_port}",
                "hint": "Make sure the GPIO API server is running on the Pi",
            }
        ), 503
    except http_requests.exceptions.Timeout:
        return jsonify({"error": "Request to Raspberry Pi timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"Hardware control failed: {str(e)}"}), 500


@skeeball_bp.route("/api/system/reboot", methods=["POST"])
@login_required
def api_system_reboot():
    """Reboot the Raspberry Pi system."""
    import subprocess

    allow_dev_reboot = os.getenv("ALLOW_DEV_REBOOT", "false").lower() == "true"
    is_raspberry_pi = os.path.exists("/boot/firmware") or os.path.exists(
        "/proc/device-tree/model"
    )

    if not is_raspberry_pi and not allow_dev_reboot:
        return jsonify(
            {
                "error": "System reboot is only available on Raspberry Pi hardware",
                "hint": "Set ALLOW_DEV_REBOOT=true in .env to enable for testing.",
            }
        ), 403

    try:
        if allow_dev_reboot and not is_raspberry_pi:
            return jsonify(
                {
                    "message": "[DEV MODE] Reboot command would be sent (system not actually rebooting)",
                    "warning": "Running in development mode - no actual reboot performed",
                }
            )
        else:
            subprocess.Popen(["sudo", "reboot"])
            return jsonify({"message": "Reboot command sent successfully"})
    except Exception as e:
        return jsonify({"error": f"Reboot failed: {str(e)}"}), 500


@skeeball_bp.route("/api/roll-outcome", methods=["POST"])
@login_required
def api_roll_outcome():
    """Simulate a roll outcome (sequence of events)."""
    data = request.get_json()
    lane_id = data.get("lane_id", "lane_1")
    outcome = data.get("outcome", "Miss")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    if not lane.game.in_progress:
        if lane.game.credits == 0:
            lane.handle_event("coin", None)

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
    for event, event_data in sequence:
        lane.handle_event(event, event_data)

    return jsonify(
        {
            "outcome": outcome,
            "lane_status": lane.get_status(),
            "sequence_executed": len(sequence),
        }
    )


# ============================================================================
# SIMULATOR API
# ============================================================================


@skeeball_bp.route("/api/simulator/insert-coin", methods=["POST"])
@login_required
def api_simulator_coin():
    """Simulator: insert a coin."""
    data = request.get_json()
    lane_id = data.get("lane_id", "lane_1")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.handle_event("coin", None)
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/simulator/score-10", methods=["POST"])
@login_required
def api_simulator_score_10():
    """Simulator: trigger 10-point score."""
    data = request.get_json()
    lane_id = data.get("lane_id", "lane_1")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.handle_event("score", "score_10")
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/simulator/score-50", methods=["POST"])
@login_required
def api_simulator_score_50():
    """Simulator: trigger 50-point score."""
    data = request.get_json()
    lane_id = data.get("lane_id", "lane_1")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.handle_event("score", "score_50")
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/simulator/lane-track", methods=["POST"])
@login_required
def api_simulator_lane_track():
    """Simulator: trigger lane track."""
    data = request.get_json()
    lane_id = data.get("lane_id", "lane_1")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.handle_event("score", "lane_track")
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/simulator/ball-scored", methods=["POST"])
@login_required
def api_simulator_ball_scored():
    """Simulator: count a scored ball."""
    data = request.get_json()
    lane_id = data.get("lane_id", "lane_1")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.handle_event("ball_scored", None)
    return jsonify(lane.get_status())


@skeeball_bp.route("/api/machine/reset", methods=["POST"])
@login_required
def api_machine_reset():
    """Reset the entire machine (clear all lanes and stats)."""
    data = request.get_json() or {}
    lane_id = data.get("lane_id", "lane_1")

    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    lane.reset_game()
    if data.get("reset_stats", False):
        lane.stats = {
            "total_games": 0,
            "total_score": 0,
            "best_score": 0,
            "total_coins": 0,
        }

    return jsonify(
        {"message": "Machine reset complete", "status": lane.get_status(), "stats": lane.get_stats()}
    )


# ============================================================================
# REVENUE INTEGRATION API
# ============================================================================


@skeeball_bp.route("/api/lanes/<lane_id>/register-game", methods=["POST"])
@login_required
def api_register_lane_as_game(lane_id):
    """Register a skeeball lane as a Game in the arcade tracker database."""
    data = request.get_json() or {}
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    game_name = data.get("name", f"Skeeball {lane_id}")
    existing_game = Game.query.filter_by(name=game_name).first()

    if existing_game:
        lane.link_to_game(existing_game.id)
        return jsonify(
            {
                "message": "Lane linked to existing game",
                "game_id": existing_game.id,
                "game_name": existing_game.name,
            }
        )

    new_game = Game(
        name=game_name,
        manufacturer=data.get("manufacturer", "Skeeball Inc."),
        year=data.get("year"),
        genre="Skeeball",
        location=data.get("location", "Floor"),
        floor_position=data.get("floor_position"),
        status="Working",
        coins_per_play=data.get("coins_per_play", 0.25),
        counter_status="Working",
        counter_notes="Digital counter via GPIO",
        notes=f"Registered skeeball lane: {lane_id}",
    )

    db.session.add(new_game)
    db.session.commit()

    lane.link_to_game(new_game.id)

    return jsonify(
        {"message": "Lane registered as game", "game_id": new_game.id, "game_name": new_game.name}
    ), 201


@skeeball_bp.route("/api/lanes/<lane_id>/revenue", methods=["GET"])
@login_required
def api_get_lane_revenue(lane_id):
    """Get current daily revenue data for a lane."""
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    return jsonify(lane.get_daily_revenue_data())


@skeeball_bp.route("/api/lanes/<lane_id>/sync-revenue", methods=["POST"])
@login_required
def api_sync_lane_revenue(lane_id):
    """Sync lane revenue to the main arcade tracker system."""
    manager = get_lane_manager()
    lane = manager.get_lane(lane_id)
    if not lane:
        return jsonify({"error": "Lane not found"}), 404

    if not lane.game_db_id:
        return jsonify({"error": "Lane not linked to game. Call /register-game first."}), 400

    if lane.daily_coins == 0:
        return jsonify({"message": "No coins to sync", "daily_coins": 0})

    game = Game.query.get(lane.game_db_id)
    if not game:
        return jsonify({"error": "Linked game not found in database"}), 404

    plays = lane.daily_coins
    revenue = plays * game.coins_per_play

    play_record = PlayRecord(
        game_id=game.id,
        coin_count=lane.stats["total_coins"],
        plays_count=plays,
        revenue=revenue,
        date_recorded=date.today(),
        notes=f"Auto-synced from {lane_id}",
    )

    game.total_plays += plays
    game.total_revenue += revenue

    db.session.add(play_record)
    db.session.commit()

    lane.reset_daily_coins()

    return jsonify(
        {
            "message": "Revenue synced successfully",
            "game_id": game.id,
            "game_name": game.name,
            "plays": plays,
            "revenue": revenue,
            "date": date.today().isoformat(),
        }
    )


@skeeball_bp.route("/api/revenue/sync-all", methods=["POST"])
@login_required
def api_sync_all_revenue():
    """Manually trigger revenue sync for all lanes."""
    if hasattr(current_app, "revenue_scheduler"):
        current_app.revenue_scheduler.force_sync()
        return jsonify({"message": "Revenue sync triggered for all lanes"})
    return jsonify({"error": "Revenue scheduler not initialized"}), 500
