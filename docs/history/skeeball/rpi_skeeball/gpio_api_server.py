#!/usr/bin/env python3
"""
GPIO Control API Server for Raspberry Pi
Receives remote commands from Flask app to control hardware.
"""

from flask import Flask, request, jsonify
import RPi.GPIO as GPIO
import time
import json
from pathlib import Path

app = Flask(__name__)

# GPIO Configuration (BCM numbering)
SOLENOID_PIN = 10
LED_POWER_PIN = 26

# Initialize GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

# Setup output pins
GPIO.setup(SOLENOID_PIN, GPIO.OUT)
GPIO.setup(LED_POWER_PIN, GPIO.OUT)

# Default states
GPIO.output(SOLENOID_PIN, GPIO.LOW)  # Solenoid off
GPIO.output(LED_POWER_PIN, GPIO.HIGH)  # LED power on

print("✅ GPIO initialized")
print(f"   Solenoid: GPIO {SOLENOID_PIN}")
print(f"   LED Power: GPIO {LED_POWER_PIN}")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "online",
        "gpio_available": True,
        "solenoid_pin": SOLENOID_PIN,
        "led_power_pin": LED_POWER_PIN
    })


@app.route('/gpio/control', methods=['POST'])
def gpio_control():
    """Control GPIO pins remotely."""
    data = request.get_json()
    device = data.get('device')
    action = data.get('action')
    
    if not device or not action:
        return jsonify({"error": "Missing device or action"}), 400
    
    try:
        if device == 'led_power':
            if action == 'on':
                GPIO.output(LED_POWER_PIN, GPIO.HIGH)
                return jsonify({"message": "LED power turned ON", "pin": LED_POWER_PIN})
            elif action == 'off':
                GPIO.output(LED_POWER_PIN, GPIO.LOW)
                return jsonify({"message": "LED power turned OFF", "pin": LED_POWER_PIN})
            else:
                return jsonify({"error": "Invalid action for LED power. Use 'on' or 'off'"}), 400
        
        elif device == 'solenoid':
            if action == 'pulse':
                GPIO.output(SOLENOID_PIN, GPIO.HIGH)
                time.sleep(0.2)  # 200ms pulse
                GPIO.output(SOLENOID_PIN, GPIO.LOW)
                return jsonify({"message": "Solenoid pulsed (200ms)", "pin": SOLENOID_PIN})
            elif action == 'on':
                GPIO.output(SOLENOID_PIN, GPIO.HIGH)
                return jsonify({"message": "Solenoid ON", "pin": SOLENOID_PIN})
            elif action == 'off':
                GPIO.output(SOLENOID_PIN, GPIO.LOW)
                return jsonify({"message": "Solenoid OFF", "pin": SOLENOID_PIN})
            else:
                return jsonify({"error": "Invalid action for solenoid. Use 'pulse', 'on', or 'off'"}), 400
        
        else:
            return jsonify({"error": f"Unknown device: {device}"}), 400
    
    except Exception as e:
        return jsonify({"error": f"GPIO control failed: {str(e)}"}), 500


@app.route('/gpio/status', methods=['GET'])
def gpio_status():
    """Get current GPIO pin states."""
    try:
        return jsonify({
            "solenoid": {
                "pin": SOLENOID_PIN,
                "state": "HIGH" if GPIO.input(SOLENOID_PIN) else "LOW"
            },
            "led_power": {
                "pin": LED_POWER_PIN,
                "state": "HIGH" if GPIO.input(LED_POWER_PIN) else "LOW"
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def cleanup():
    """Cleanup GPIO on shutdown."""
    print("\n🧹 Cleaning up GPIO...")
    GPIO.cleanup()


if __name__ == '__main__':
    import atexit
    atexit.register(cleanup)
    
    # Run on port 5001 (to not conflict with main Flask app)
    print("\n🚀 GPIO API Server starting on port 5001")
    print("   Access at: http://<raspberry-pi-ip>:5001")
    print("   Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5001, debug=False)
