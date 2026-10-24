#!/usr/bin/env python3
"""
Simple GPIO monitor that reads hardware and updates stats API via HTTP.
This avoids the GPIO.add_event_detect conflicts.
"""

import RPi.GPIO as GPIO
import time
import requests
from stats_api_server import update_game_state, update_game_history

# GPIO pin configuration (update these to match your hardware)
COIN_PIN = 17
BALL_COUNTER_PIN = 18
SCORE_10_PIN = 22
SCORE_50_PIN = 19

# Game state
current_score = 0
balls_remaining = 9
game_active = False
total_coins = 0
total_games = 0
current_ball_score = 0

def setup_gpio():
    """Setup GPIO pins for input"""
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    
    GPIO.setup(COIN_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(BALL_COUNTER_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(SCORE_10_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(SCORE_50_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    print("✅ GPIO setup complete")

def update_stats():
    """Update the stats API"""
    global current_score, balls_remaining, game_active, total_coins, total_games
    
    state_data = {
        "current_score": current_score,
        "balls_remaining": balls_remaining,
        "game_active": game_active,
        "current_ball_score": current_ball_score,
        "total_coins_inserted": total_coins,
        "total_games_played": total_games,
    }
    
    try:
        update_game_state(state_data)
        print(f"📊 Updated: Score={current_score}, Balls={9-balls_remaining}/9, Active={game_active}")
    except Exception as e:
        print(f"⚠️  Error updating stats: {e}")

def main():
    """Main monitoring loop"""
    global current_score, balls_remaining, game_active, total_coins, total_games, current_ball_score
    
    setup_gpio()
    
    # Previous pin states (for edge detection)
    prev_coin = GPIO.HIGH
    prev_ball = GPIO.HIGH
    prev_10 = GPIO.HIGH
    prev_50 = GPIO.HIGH
    
    print("\n🎳 GPIO Monitor Started")
    print("Monitoring pins for changes...")
    print("=" * 50)
    
    while True:
        try:
            # Read current pin states
            coin_state = GPIO.input(COIN_PIN)
            ball_state = GPIO.input(BALL_COUNTER_PIN)
            score_10_state = GPIO.input(SCORE_10_PIN)
            score_50_state = GPIO.input(SCORE_50_PIN)
            
            # Detect coin insertion (falling edge)
            if prev_coin == GPIO.HIGH and coin_state == GPIO.LOW:
                print("\n💰 COIN INSERTED!")
                total_coins += 1
                current_score = 0
                balls_remaining = 9
                current_ball_score = 0
                game_active = True
                update_stats()
            
            # Detect 10-point score (falling edge)
            if game_active and prev_10 == GPIO.HIGH and score_10_state == GPIO.LOW:
                print("   +10 points")
                current_ball_score += 10
                update_stats()
            
            # Detect 50-point score (falling edge)
            if game_active and prev_50 == GPIO.HIGH and score_50_state == GPIO.LOW:
                print("   +50 points")
                current_ball_score += 50
                update_stats()
            
            # Detect ball completion (falling edge)
            if game_active and prev_ball == GPIO.HIGH and ball_state == GPIO.LOW:
                current_score += current_ball_score
                balls_remaining -= 1
                ball_num = 9 - balls_remaining
                print(f"🎯 Ball {ball_num}: {current_ball_score} pts (Total: {current_score})")
                current_ball_score = 0
                
                if balls_remaining <= 0:
                    print(f"🏁 GAME OVER - Final Score: {current_score}")
                    game_active = False
                    total_games += 1
                    
                    # Record game in history
                    game_record = {
                        'score': current_score,
                        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
                    }
                    try:
                        update_game_history(game_record)
                    except:
                        pass
                
                update_stats()
            
            # Update previous states
            prev_coin = coin_state
            prev_ball = ball_state
            prev_10 = score_10_state
            prev_50 = score_50_state
            
            # Small delay to prevent CPU hogging
            time.sleep(0.05)  # 50ms = 20Hz polling
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Stopping monitor...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            time.sleep(1)
    
    GPIO.cleanup()
    print("👋 Goodbye!")

if __name__ == '__main__':
    main()
