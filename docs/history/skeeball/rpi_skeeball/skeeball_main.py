#!/usr/bin/env python3
"""
Skeeball Scoring System for Raspberry Pi
Complete game management with server sync to arcade tracker Flask app.
"""

import json
import time
import threading
import requests
from datetime import datetime
from pathlib import Path
from collections import deque

# Try to import GPIO
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False
    print("⚠️  GPIO not available - running in simulation mode")

# Import stats API server
try:
    from stats_api_server import update_game_state, update_game_history, start_api_server
    STATS_API_AVAILABLE = True
except ImportError:
    STATS_API_AVAILABLE = False
    print("⚠️  Stats API server not available")


class SkeeballGame:
    """Main skeeball game controller."""
    
    # Switch configuration:
    # - 5x +10pt switches (one per lane: 10, 20, 30, 40, 50)
    # - 2x +50pt switches (100pt holes)
    # - 1x ball counter
    # - 1x coin sensor
    # - 2x LED display outputs
    
    BALLS_PER_GAME = 9
    
    def __init__(self, config_file='config.json'):
        """Initialize the skeeball system."""
        self.config = self.load_config(config_file)
        
        # Game state
        self.current_score = 0
        self.balls_remaining = self.BALLS_PER_GAME
        self.game_active = False
        self.game_history = deque(maxlen=100)  # Last 100 games
        
        # Current ball tracking (which switches have been hit)
        self.current_ball_switches = set()
        self.current_ball_score = 0
        
        # Cumulative tracking
        self.total_coins_inserted = 0
        self.total_games_played = 0
        self.last_sync = None
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Network session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Skeeball/1.0'})
        
        # Load persisted state
        self.load_state()
        
        # Initialize hardware
        if GPIO_AVAILABLE and self.config.get('use_gpio', True):
            self.setup_gpio()
        
        # Start stats API server
        if STATS_API_AVAILABLE:
            start_api_server(port=5002, debug=False)
        
        # Start background sync thread
        self.sync_thread = threading.Thread(target=self.sync_loop, daemon=True)
        self.sync_thread.start()
    
    def load_config(self, config_file):
        """Load configuration from JSON file."""
        config_path = Path(config_file)
        if not config_path.exists():
            print(f"❌ Config file not found: {config_file}")
            self.create_sample_config(config_file)
            raise SystemExit("Please edit config.json with your settings and restart.")
        
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def create_sample_config(self, config_file):
        """Create sample configuration file."""
        sample = {
            "server": {
                "url": "http://192.168.1.100:5000",
                "game_id": 1,
                "username": "operator",
                "password": "your-password",
                "sync_interval_seconds": 300
            },
            "gpio_pins": {
                "coin_sensor": 17,
                "ball_counter": 18,
                "switch_10pt": 22,
                "switch_20pt": 23,
                "switch_30pt": 24,
                "switch_40pt": 25,
                "switch_50pt": 27,
                "switch_100_left": 19,
                "switch_100_right": 13,
                "solenoid_relay": 10,
                "led_power_relay": 26
            },
            "displays": [
                {
                    "type": "tm1637",
                    "clk_pin": 5,
                    "dio_pin": 6,
                    "brightness": 7
                },
                {
                    "type": "tm1637",
                    "clk_pin": 11,
                    "dio_pin": 9,
                    "brightness": 7
                }
            ],
            "game": {
                "balls_per_game": 9,
                "ball_timeout_seconds": 2.0,
                "bonus_threshold": 360,
                "solenoid_pulse_ms": 200
            },
            "hardware": {
                "use_gpio": True,
                "bounce_time_ms": 50,
                "debug": False
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(sample, f, indent=2)
        print(f"✅ Created {config_file}")
    
    def setup_gpio(self):
        """Configure GPIO pins."""
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        
        pins = self.config['gpio_pins']
        bounce_time = self.config['hardware']['bounce_time_ms']
        
        # Coin sensor
        GPIO.setup(pins['coin_sensor'], GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.add_event_detect(
            pins['coin_sensor'],
            GPIO.FALLING,
            callback=self.coin_inserted,
            bouncetime=bounce_time
        )
        
        # Ball counter (triggers when ball reaches bottom)
        GPIO.setup(pins['ball_counter'], GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.add_event_detect(
            pins['ball_counter'],
            GPIO.FALLING,
            callback=self.ball_completed,
            bouncetime=bounce_time
        )
        
        # 5 scoring switches (10, 20, 30, 40, 50 points)
        switch_map = {
            'switch_10pt': 10,
            'switch_20pt': 20,
            'switch_30pt': 30,
            'switch_40pt': 40,
            'switch_50pt': 50
        }
        
        for switch_name, points in switch_map.items():
            pin = pins[switch_name]
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
            GPIO.add_event_detect(
                pin,
                GPIO.FALLING,
                callback=lambda ch, pts=points: self.switch_triggered(pts),
                bouncetime=bounce_time
            )
        
        # 100-point switches (+50 bonus)
        GPIO.setup(pins['switch_100_left'], GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.add_event_detect(
            pins['switch_100_left'],
            GPIO.FALLING,
            callback=lambda ch: self.switch_100_triggered('left'),
            bouncetime=bounce_time
        )
        
        GPIO.setup(pins['switch_100_right'], GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.add_event_detect(
            pins['switch_100_right'],
            GPIO.FALLING,
            callback=lambda ch: self.switch_100_triggered('right'),
            bouncetime=bounce_time
        )
        
        # Output: Solenoid relay
        GPIO.setup(pins['solenoid_relay'], GPIO.OUT)
        GPIO.output(pins['solenoid_relay'], GPIO.LOW)  # Off by default
        
        # Output: LED power relay (optional)
        if 'led_power_relay' in pins:
            GPIO.setup(pins['led_power_relay'], GPIO.OUT)
            GPIO.output(pins['led_power_relay'], GPIO.HIGH)  # On by default
        
        print("✅ GPIO initialized")
        self.print_pin_mapping()
    
    def print_pin_mapping(self):
        """Display GPIO pin configuration."""
        print("\n📌 GPIO Pin Mapping:")
        pins = self.config['gpio_pins']
        print(f"   Coin Sensor:   GPIO {pins['coin_sensor']}")
        print(f"   Ball Counter:  GPIO {pins['ball_counter']}")
        print(f"   10pt Switch:   GPIO {pins['switch_10pt']}")
        print(f"   20pt Switch:   GPIO {pins['switch_20pt']}")
        print(f"   30pt Switch:   GPIO {pins['switch_30pt']}")
        print(f"   40pt Switch:   GPIO {pins['switch_40pt']}")
        print(f"   50pt Switch:   GPIO {pins['switch_50pt']}")
        print(f"   100pt Left:    GPIO {pins['switch_100_left']}")
        print(f"   100pt Right:   GPIO {pins['switch_100_right']}")
        
        displays = self.config.get('displays', [])
        if displays:
            print(f"\n   Displays:")
            for i, disp in enumerate(displays, 1):
                print(f"   Display {i}:    CLK={disp['clk_pin']}, DIO={disp['dio_pin']}")
        
        print(f"\n   Solenoid Relay:  GPIO {pins['solenoid_relay']}")
        if 'led_power_relay' in pins:
            print(f"   LED Relay:       GPIO {pins.get('led_power_relay', 'N/A')}")
    
    def coin_inserted(self, channel):
        """Handle coin insertion."""
        with self.lock:
            self.total_coins_inserted += 1
            self.save_state()
            
            # Reset game (new game always starts on coin, regardless of balls left)
            self.start_game()
            
            if self.config['hardware']['debug']:
                print(f"💰 Coin inserted - Total: {self.total_coins_inserted}")
    
    def start_game(self):
        """Start a new skeeball game."""
        self.current_score = 0
        self.balls_remaining = self.BALLS_PER_GAME
        self.game_active = True
        self.current_ball_switches = set()
        self.current_ball_score = 0
        
        # Update stats API
        self._update_stats_api()
        
        # Activate solenoid to release balls
        self.activate_solenoid()
        
        self.display_score(0)
        print(f"\n🎮 NEW GAME - {self.balls_remaining} balls remaining")
        print("=" * 40)
    
    def switch_triggered(self, points):
        """Handle a scoring switch being triggered."""
        if not self.game_active:
            return
        
        with self.lock:
            # Only count each switch once per ball
            switch_key = f'switch_{points}'
            if switch_key in self.current_ball_switches:
                return
            
            self.current_ball_switches.add(switch_key)
            self.current_ball_score += points
            
            # Update stats API
            self._update_stats_api()
            
            if self.config['hardware']['debug']:
                print(f"   {points}pt switch hit → +{points} pts (ball score: {self.current_ball_score})")
    
    def switch_100_triggered(self, side):
        """Handle 100-point special switch."""
        if not self.game_active:
            return
        
        with self.lock:
            # Mark as 100-point ball (already has 50pts from switches)
            switch_key = f'100_{side}'
            if switch_key in self.current_ball_switches:
                return
            
            self.current_ball_switches.add(switch_key)
            # Add the bonus 50 points (ball already scored 50 from 5 switches)
            self.current_ball_score += 50
            
            if self.config['hardware']['debug']:
                print(f"   💯 100pt switch ({side})! → +50 bonus (ball score: {self.current_ball_score})")
    
    def ball_completed(self, channel):
        """Ball has reached the bottom counter."""
        if not self.game_active:
            return
        
        with self.lock:
            # Add ball score to total
            self.current_score += self.current_ball_score
            self.balls_remaining -= 1
            
            ball_num = self.BALLS_PER_GAME - self.balls_remaining
            print(f"🎯 Ball {ball_num}: {self.current_ball_score} pts (Total: {self.current_score}, Balls left: {self.balls_remaining})")
            
            self.display_score(self.current_score)
            
            # Reset for next ball
            self.current_ball_switches = set()
            self.current_ball_score = 0
            
            # Update stats API
            self._update_stats_api()
            
            # Check if game is over (wait for coin to start new game)
            if self.balls_remaining <= 0:
                self.end_game()
    
    def end_game(self):
        """End the current game."""
        final_score = self.current_score
        self.game_active = False
        
        # Check for bonus
        bonus_threshold = self.config['game']['bonus_threshold']
        if final_score >= bonus_threshold:
            print(f"\n🎉 BONUS! Score: {final_score} (≥{bonus_threshold})")
            # Award bonus game
            self.start_game()
        else:
            print(f"\n🏁 GAME OVER - Final Score: {final_score}")
        
        # Record game
        game_record = {
            'score': final_score,
            'timestamp': datetime.now().isoformat()
        }
        self.game_history.append(game_record)
        self.total_games_played += 1
        self.save_state()
        
        # Update stats API with game history
        if STATS_API_AVAILABLE and not self.game_active:  # Only if not bonus
            update_game_history(game_record)
        
        # Update current state
        self._update_stats_api()
        
        # Show stats
        if not self.game_active:  # Only show if not bonus
            self.display_stats()
    
    def activate_solenoid(self):
        """Pulse solenoid to release balls."""
        if not GPIO_AVAILABLE:
            print("   [SIMULATION] Solenoid activated")
            return
        
        pins = self.config['gpio_pins']
        pulse_ms = self.config['game'].get('solenoid_pulse_ms', 200)
        
        try:
            # Activate relay (solenoid on)
            GPIO.output(pins['solenoid_relay'], GPIO.HIGH)
            print(f"   🔧 Solenoid ON ({pulse_ms}ms)")
            
            # Wait for pulse duration
            time.sleep(pulse_ms / 1000.0)
            
            # Deactivate relay (solenoid off)
            GPIO.output(pins['solenoid_relay'], GPIO.LOW)
            
        except Exception as e:
            print(f"   ⚠️  Solenoid error: {e}")
    
    def display_score(self, score):
        """Display score on hardware displays."""
        displays = self.config.get('displays', [])
        
        if displays:
            try:
                import tm1637
                
                # Update all configured displays
                for display_config in displays:
                    if display_config.get('type') == 'tm1637':
                        clk = display_config['clk_pin']
                        dio = display_config['dio_pin']
                        brightness = display_config.get('brightness', 7)
                        
                        display = tm1637.TM1637(clk=clk, dio=dio, brightness=brightness)
                        display.number(score)
            except Exception as e:
                if self.config['hardware']['debug']:
                    print(f"Display error: {e}")
        
        # Console fallback
        print(f"   📊 SCORE: {score:04d}")
    
    def display_stats(self):
        """Show game statistics."""
        if not self.game_history:
            return
        
        recent_scores = [g['score'] for g in self.game_history]
        avg_score = sum(recent_scores) / len(recent_scores)
        high_score = max(recent_scores)
        
        print(f"\n📈 Statistics:")
        print(f"   Games today: {len(self.game_history)}")
        print(f"   High score: {high_score}")
        print(f"   Average: {avg_score:.1f}")
        print(f"   Total coins: {self.total_coins_inserted}")
    
    def load_state(self):
        """Load persisted state."""
        state_file = Path('skeeball_state.json')
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    self.total_coins_inserted = state.get('total_coins_inserted', 0)
                    self.total_games_played = state.get('total_games_played', 0)
                    self.last_sync = state.get('last_sync')
                    
                    # Restore game history
                    history = state.get('game_history', [])
                    self.game_history = deque(history, maxlen=100)
                    
                    print(f"📊 Loaded state - Coins: {self.total_coins_inserted}, Games: {self.total_games_played}")
            except Exception as e:
                print(f"⚠️  Error loading state: {e}")
    
    def save_state(self):
        """Persist current state."""
        state = {
            'total_coins_inserted': self.total_coins_inserted,
            'total_games_played': self.total_games_played,
            'last_sync': self.last_sync,
            'game_history': list(self.game_history),
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            with open('skeeball_state.json', 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"⚠️  Error saving state: {e}")
    
    def login(self):
        """Authenticate with Flask server."""
        server_url = self.config['server']['url']
        login_url = f"{server_url}/login"
        
        login_data = {
            'username': self.config['server']['username'],
            'password': self.config['server']['password'],
            'remember': True
        }
        
        try:
            resp = self.session.post(login_url, data=login_data, timeout=10, allow_redirects=True)
            
            if resp.status_code == 200 and '/login' not in resp.url:
                print("✅ Logged in to server")
                return True
            else:
                print(f"❌ Login failed - Status: {resp.status_code}")
                return False
        except requests.RequestException as e:
            print(f"❌ Login error: {e}")
            return False
    
    def sync_to_server(self):
        """Sync coin count to Flask server."""
        if self.total_coins_inserted == 0:
            return True
        
        server_url = self.config['server']['url']
        game_id = self.config['server']['game_id']
        record_url = f"{server_url}/record_plays/{game_id}"
        
        payload = {
            'coin_count': self.total_coins_inserted,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'notes': f'Skeeball auto-sync - {self.total_games_played} games played'
        }
        
        try:
            resp = self.session.post(record_url, data=payload, timeout=10, allow_redirects=False)
            
            # Re-authenticate if needed
            if resp.status_code == 302 and '/login' in resp.headers.get('Location', ''):
                if self.login():
                    resp = self.session.post(record_url, data=payload, timeout=10)
                else:
                    return False
            
            if resp.status_code == 200:
                print(f"✅ Synced {self.total_coins_inserted} coins to server")
                self.last_sync = datetime.now().isoformat()
                self.save_state()
                return True
            else:
                print(f"⚠️  Sync failed - Status: {resp.status_code}")
                return False
                
        except requests.RequestException as e:
            print(f"❌ Network error during sync: {e}")
            return False
    
    def sync_loop(self):
        """Background thread for periodic server sync."""
        sync_interval = self.config['server']['sync_interval_seconds']
        
        # Initial login
        time.sleep(5)  # Wait for system to stabilize
        self.login()
        
        while True:
            time.sleep(sync_interval)
            
            with self.lock:
                if self.total_coins_inserted > 0:
                    self.sync_to_server()
    
    def run(self):
        """Main run loop."""
        print("\n" + "=" * 50)
        print("🎳 SKEEBALL SYSTEM STARTED")
        print("=" * 50)
        print(f"   Server: {self.config['server']['url']}")
        print(f"   Game ID: {self.config['server']['game_id']}")
        print(f"   Balls per game: {self.config['game']['balls_per_game']}")
        print(f"   Bonus at: {self.config['game']['bonus_threshold']}+ pts")
        print("=" * 50)
        print("\n💰 INSERT COIN TO START\n")
        
        try:
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n⏹️  Shutting down...")
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources."""
        # Final sync
        if self.total_coins_inserted > 0:
            print(f"📤 Final sync - {self.total_coins_inserted} coins...")
            self.sync_to_server()
        
        if GPIO_AVAILABLE:
            GPIO.cleanup()
        
        print("👋 Goodbye!")
    
    # Simulation methods for testing
    def simulate_coin(self):
        """Simulate coin insertion."""
        print("\n[SIMULATION] Coin inserted")
        self.coin_inserted(None)
    
    def simulate_ball(self, score=50):
        """Simulate ball with specific score."""
        if not self.game_active:
            print("[SIMULATION] Game not active!")
            return
        
        print(f"[SIMULATION] Ball scoring {score} points")
        
        # Simulate switch hit based on score
        if score == 100:
            # 100 point: 50pt switch + special bonus
            self.switch_triggered(50)
            self.switch_100_triggered('left')
        elif score in [10, 20, 30, 40, 50]:
            # Regular score switch
            self.switch_triggered(score)
        
        # Ball completes
        time.sleep(0.2)
        self.ball_completed(None)
    
    def _update_stats_api(self):
        """Update the stats API server with current state."""
        if not STATS_API_AVAILABLE:
            return
        
        state_data = {
            "current_score": self.current_score,
            "balls_remaining": self.balls_remaining,
            "game_active": self.game_active,
            "current_ball_score": self.current_ball_score,
            "total_coins_inserted": self.total_coins_inserted,
            "total_games_played": self.total_games_played,
        }
        
        try:
            update_game_state(state_data)
        except Exception as e:
            # Don't let stats API errors crash the game
            if self.config['hardware'].get('debug', False):
                print(f"⚠️  Stats API update error: {e}")


def main():
    """Entry point."""
    game = SkeeballGame()
    game.run()


if __name__ == '__main__':
    main()
