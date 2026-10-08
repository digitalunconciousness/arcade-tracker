# game_logic.py

import config

class GameLogic:
    def __init__(self, lane_id="lane_1"):
        """
        Initialize game logic for a specific lane.
        
        Args:
            lane_id: Unique identifier for this lane (e.g., "lane_1", "lane_2")
                     Enables future multi-lane expansion where each lane runs
                     independently with its own GameLogic instance.
        """
        self.lane_id = lane_id
        self.credits = 0
        self.score = 0
        self.balls = 0
        self.in_progress = False

    def handle_event(self, event, data=None):
        if event == "coin":
            # Reset game state when coin is inserted
            self.in_progress = False
            self.score = 0
            self.balls = 0
            self.credits = 1
            print(f"💰 Credit added! Credits: {self.credits}")
            return

        # Auto-start game on first scoring event if we have credits
        if not self.in_progress and self.credits > 0:
            self.start_game()

        # Don't allow scoring if no game in progress
        if not self.in_progress:
            return

        # Don't allow scoring or ball counting after 9 balls
        if self.balls >= config.TOTAL_BALLS:
            return

        if event == "score":
            self.add_points(config.POINT_VALUES[data])
        elif event == "ball_scored":
            self.next_ball()

    def start_game(self):
        """Start game (used by other methods if needed)."""
        if self.credits > 0:
            self.credits -= 1
            self.score = 0
            self.balls = 0
            self.in_progress = True
            print("🎳 Game started!")

    def add_points(self, pts):
        self.score += pts
        print(f"🏆 +{pts} points! Total: {self.score}")

    def next_ball(self):
        self.balls += 1
        print(f"Ball {self.balls}/{config.TOTAL_BALLS}")

        if self.balls >= config.TOTAL_BALLS:
            self.end_game()

    def end_game(self):
        print(f"🎉 Final Score: {self.score}")
        self.in_progress = False
        self.credits = 0  # Clear credits when game ends
