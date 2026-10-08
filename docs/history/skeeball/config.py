# config.py

# GPIO pin assignments (BCM numbering)
PINS = {
    "coin": 2,
    "ball_count": 3,
    "score_10": [4, 5, 6, 7, 8],  # 5 switches, 10 pts each
    "score_50": [9, 10],          # 2 switches, 50 pts each
    "lane_track": 11,             # 50 pts (roll down)
}

# Output pins for hardware control
SOLENOID_RELAY_PIN = 10  # Ball release solenoid
LED_POWER_RELAY_PIN = 26  # LED display power

# Game configuration
POINT_VALUES = {
    "score_10": 10,
    "score_50": 50,
    "lane_track": 50,
}

TOTAL_BALLS = 9
BOUNCE_TIME = 0.1  # seconds
