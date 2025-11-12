#!/usr/bin/env python3
"""Manually register skeeball lanes and create Game entries."""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app import app, db, Game

def register_lane(lane_id):
    """Register a skeeball lane and create Game entry if needed."""
    with app.app_context():
        # Extract lane number
        lane_number = lane_id.split('_')[-1] if '_' in lane_id else lane_id
        game_name = f"Skeeball Lane {lane_number}"
        
        # Check if game already exists
        game = Game.query.filter_by(name=game_name).first()
        
        if game:
            print(f"✅ Game already exists: '{game_name}' (ID: {game.id})")
            return game
        
        # Create new game entry
        game = Game(
            name=game_name,
            manufacturer="Custom",
            genre="Skeeball",
            location="Floor",
            status="Working",
            counter_status="Working",
            coins_per_play=1.0,  # $1 per game
            notes=f"Automated skeeball lane managed by Raspberry Pi (lane_id: {lane_id})"
        )
        
        db.session.add(game)
        db.session.commit()
        
        print(f"✅ Created Game entry: '{game_name}' (ID: {game.id})")
        return game

def list_skeeball_games():
    """List all skeeball games in database."""
    with app.app_context():
        games = Game.query.filter(Game.name.like('Skeeball%')).all()
        
        if not games:
            print("No skeeball games found in database.")
            return
        
        print(f"\nFound {len(games)} skeeball game(s):")
        for game in games:
            print(f"  - {game.name} (ID: {game.id})")
            print(f"    Location: {game.location}, Status: {game.status}")
            print(f"    Total Plays: {game.total_plays}, Revenue: ${game.total_revenue:.2f}")

if __name__ == "__main__":
    print("Skeeball Lane Registration Tool")
    print("=" * 50)
    
    # Register default lane
    register_lane("lane_1")
    
    # List all skeeball games
    list_skeeball_games()
    
    print("\n✅ Registration complete!")
    print("Skeeball lanes should now appear in the 'All Games' tab.")
