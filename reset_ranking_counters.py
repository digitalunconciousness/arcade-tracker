#!/usr/bin/env python3
"""Reset Top 5/Top 10 counters for all games"""
from app import app, db, Game

def reset_counters():
    """Reset times_in_top_5 and times_in_top_10 to 0 for all games"""
    with app.app_context():
        games = Game.query.all()
        count = 0
        
        for game in games:
            game.times_in_top_5 = 0
            game.times_in_top_10 = 0
            count += 1
        
        db.session.commit()
        print(f"Reset ranking counters for {count} games")

if __name__ == '__main__':
    reset_counters()
