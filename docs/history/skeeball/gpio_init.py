#!/usr/bin/env python3
"""GPIO initialization module for skeeball.

Automatically configures GPIO for either:
- Real hardware (Raspberry Pi GPIO)
- Mock GPIO (for testing on any system)

Configuration is controlled via .env.skeeball or environment variables.
"""

import os
from gpiozero import Device
from gpiozero.pins.mock import MockFactory

# Try to import RPiGPIOFactory, but it may not be available on non-Pi systems
try:
    from gpiozero.pins.rpigpio import RPiGPIOFactory
    RPIGPIO_AVAILABLE = True
except (ImportError, RuntimeError) as e:
    RPIGPIO_AVAILABLE = False
    RPiGPIOFactory = None


def init_gpio():
    """
    Initialize GPIO based on configuration.
    
    Returns:
        tuple: (is_mock, message)
            - is_mock: True if using mock GPIO, False if real hardware
            - message: Status message for logging
    """
    # Check environment variable or .env.skeeball
    use_real_gpio = os.getenv('USE_REAL_GPIO', 'false').lower() == 'true'
    
    # Load from .env.skeeball if exists
    env_file = os.path.join(os.path.dirname(__file__), '.env.skeeball')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('USE_REAL_GPIO='):
                    value = line.split('=', 1)[1].strip().lower()
                    use_real_gpio = value == 'true'
                    break
    
    if use_real_gpio:
        if not RPIGPIO_AVAILABLE:
            # RPi.GPIO not available on this system
            Device.pin_factory = MockFactory()
            return True, "⚠️  Real GPIO requested but RPi.GPIO not available (not a Raspberry Pi?), using mock GPIO"
        
        try:
            # Try to use real GPIO
            Device.pin_factory = RPiGPIOFactory()
            return False, "🎮 Real GPIO initialized (Raspberry Pi hardware mode)"
        except Exception as e:
            # Fall back to mock if real GPIO fails
            Device.pin_factory = MockFactory()
            return True, f"⚠️  Real GPIO requested but failed ({e}), using mock GPIO for testing"
    else:
        # Use mock GPIO
        Device.pin_factory = MockFactory()
        return True, "🧪 Mock GPIO initialized (testing mode - no hardware required)"


def is_using_mock_gpio():
    """Check if currently using mock GPIO."""
    return isinstance(Device.pin_factory, MockFactory)


def switch_to_mock():
    """Switch to mock GPIO (for testing)."""
    Device.pin_factory = MockFactory()
    return "🧪 Switched to mock GPIO (testing mode)"


def switch_to_real():
    """Switch to real GPIO (for hardware)."""
    if not RPIGPIO_AVAILABLE:
        Device.pin_factory = MockFactory()
        return "⚠️  RPi.GPIO not available (not a Raspberry Pi?), staying in mock mode"
    
    try:
        Device.pin_factory = RPiGPIOFactory()
        return "🎮 Switched to real GPIO (hardware mode)"
    except Exception as e:
        Device.pin_factory = MockFactory()
        return f"⚠️  Failed to switch to real GPIO ({e}), staying in mock mode"


def get_gpio_status():
    """Get current GPIO status."""
    is_mock = is_using_mock_gpio()
    return {
        "mode": "mock" if is_mock else "real",
        "description": "Mock GPIO (testing mode)" if is_mock else "Real GPIO (hardware mode)",
        "hardware_required": not is_mock,
        "testing_mode": is_mock
    }
