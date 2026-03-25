#!/usr/bin/env python3
"""Lane controller for managing individual skeeball lanes.

Each lane can be backed by:
- Direct GPIO (Raspberry Pi 4)
- Serial connection to Pi Pico
- Mock interface (for testing)
"""

from typing import Optional, Dict, Any, Callable
from datetime import datetime
import config
from game_logic import GameLogic
from serial_bridge import SerialConnection


class LaneController:
    """Controls a single skeeball lane and its game state."""
    
    def __init__(
        self,
        lane_id: str,
        game_logic: Optional[GameLogic] = None,
        serial_conn: Optional[SerialConnection] = None
    ):
        """
        Initialize a lane controller.
        
        Args:
            lane_id: Unique lane identifier (e.g., "lane_1")
            game_logic: GameLogic instance (created if not provided)
            serial_conn: Serial connection to Pi Pico (if using remote GPIO)
        """
        self.lane_id = lane_id
        self.game = game_logic or GameLogic(lane_id)
        self.serial_conn = serial_conn
        self.last_event_time = None
        self.game_db_id = None  # Link to Game table ID for revenue tracking
        self.stats = {
            "total_games": 0,
            "total_score": 0,
            "best_score": 0,
            "total_coins": 0,
        }
        # Daily revenue tracking
        self.daily_coins = 0
        self.last_revenue_sync = None
    
    def handle_event(self, event: str, data: Any = None):
        """
        Handle a hardware event for this lane.
        
        Args:
            event: Event name (e.g., "coin", "score", "ball_scored")
            data: Event data (e.g., "score_10" for score events)
        """
        self.last_event_time = datetime.now()
        
        # Forward to game logic
        self.game.handle_event(event, data)
        
        # Update stats if game ended
        if event == "ball_scored" and self.game.balls == config.TOTAL_BALLS:
            self.stats["total_games"] += 1
            self.stats["total_score"] += self.game.score
            if self.game.score > self.stats["best_score"]:
                self.stats["best_score"] = self.game.score
        
        if event == "coin":
            self.stats["total_coins"] += 1
            self.daily_coins += 1
    
    def get_status(self) -> Dict[str, Any]:
        """Get current game state for this lane."""
        return {
            "lane_id": self.lane_id,
            "credits": self.game.credits,
            "score": self.game.score,
            "balls": self.game.balls,
            "in_progress": self.game.in_progress,
            "total_balls": config.TOTAL_BALLS,
            "is_online": self.is_online(),
            "last_event": self.last_event_time.isoformat() if self.last_event_time else None,
        }
    
    def reset_game(self):
        """Reset the game state for this lane."""
        self.game = GameLogic(self.lane_id)
        self.last_event_time = None
    
    def is_online(self) -> bool:
        """Check if lane is online (for remote lanes)."""
        if self.serial_conn:
            return self.serial_conn.is_healthy()
        return True  # Local GPIO is always online
    
    def get_stats(self) -> Dict[str, Any]:
        """Get accumulated statistics for this lane."""
        return {
            "lane_id": self.lane_id,
            **self.stats,
            "average_score": (
                self.stats["total_score"] // self.stats["total_games"]
                if self.stats["total_games"] > 0 else 0
            ),
        }
    
    def link_to_game(self, game_id: int):
        """Link this lane to a Game database entry for revenue tracking."""
        self.game_db_id = game_id
    
    def get_daily_revenue_data(self) -> Dict[str, Any]:
        """Get data for daily revenue recording."""
        return {
            "lane_id": self.lane_id,
            "game_db_id": self.game_db_id,
            "daily_coins": self.daily_coins,
            "last_sync": self.last_revenue_sync,
        }
    
    def reset_daily_coins(self):
        """Reset daily coin counter (called after revenue sync)."""
        from datetime import datetime
        self.daily_coins = 0
        self.last_revenue_sync = datetime.now()
