# input_manager.py

from gpiozero import Button
from signal import pause
import config

class InputManager:
    def __init__(self, event_callback):
        """
        event_callback: function called with (event_name, data)
        """
        self.event_callback = event_callback
        self.buttons = []

        # Setup scoring switches
        for pin in config.PINS["score_10"]:
            b = Button(pin, bounce_time=config.BOUNCE_TIME)
            b.when_pressed = lambda p=pin: self.score_event("score_10")
            self.buttons.append(b)

        for pin in config.PINS["score_50"]:
            b = Button(pin, bounce_time=config.BOUNCE_TIME)
            b.when_pressed = lambda p=pin: self.score_event("score_50")
            self.buttons.append(b)

        # Lane track
        lane = Button(config.PINS["lane_track"], bounce_time=config.BOUNCE_TIME)
        lane.when_pressed = lambda: self.score_event("lane_track")
        self.buttons.append(lane)

        # Coin input
        coin = Button(config.PINS["coin"], bounce_time=config.BOUNCE_TIME)
        coin.when_pressed = lambda: self.event_callback("coin", None)
        self.buttons.append(coin)

        # Ball counter
        ball = Button(config.PINS["ball_count"], bounce_time=config.BOUNCE_TIME)
        ball.when_pressed = lambda: self.event_callback("ball_scored", None)
        self.buttons.append(ball)

    def score_event(self, event):
        self.event_callback("score", event)
