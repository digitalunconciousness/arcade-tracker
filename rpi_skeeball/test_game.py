#!/usr/bin/env python3
"""
Test script for skeeball system - simulates games without hardware.
"""

import time
import random
from skeeball_main import SkeeballGame


def simulate_game(game):
    """Simulate a complete skeeball game."""
    print("\n🎮 Starting simulated game...")
    game.simulate_coin()
    
    time.sleep(1)
    
    # Simulate 9 balls with random scoring
    # Scores: 10, 20, 30, 40, 50, 100
    scores = [10, 20, 30, 40, 50, 100]
    weights = [15, 20, 25, 20, 15, 5]  # Probability distribution
    
    for i in range(9):
        score = random.choices(scores, weights=weights)[0]
        game.simulate_ball(score)
        time.sleep(0.5)
    
    time.sleep(2)


def main():
    """Run test simulations."""
    print("=" * 60)
    print("🧪 SKEEBALL SYSTEM TEST MODE")
    print("=" * 60)
    print("\nThis will simulate several games to test the system.")
    print("No hardware required - GPIO will be disabled.\n")
    
    # Create game instance
    game = SkeeballGame()
    
    # Override GPIO setting for testing
    game.config['hardware']['use_gpio'] = False
    
    print("\n--- Running 3 test games ---\n")
    
    for i in range(3):
        print(f"\n{'='*60}")
        print(f"TEST GAME {i+1}/3")
        print('='*60)
        simulate_game(game)
    
    print("\n" + "="*60)
    print("✅ Testing complete!")
    print("="*60)
    game.display_stats()
    
    print(f"\n📊 Total coins collected: {game.total_coins_inserted}")
    print(f"📊 Total games played: {game.total_games_played}")
    
    # Test server sync (will fail if server not available)
    print("\n🌐 Testing server sync...")
    if game.login():
        game.sync_to_server()
    else:
        print("⚠️  Server not available - skipping sync test")


if __name__ == '__main__':
    main()
