#!/usr/bin/env python3
"""Serial bridge for communicating with Pi Pico lane controllers.

Each Pi Pico runs pico_firmware.py and sends JSON events over serial.
This module parses those events and routes them to the appropriate lane.
"""

import serial
import json
import threading
import time
from typing import Callable, Optional, Dict, Any
from datetime import datetime
from queue import Queue


class SerialConnection:
    """Manages a single serial connection to a Pi Pico."""
    
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 1.0):
        """
        Initialize serial connection.
        
        Args:
            port: Serial port (e.g., '/dev/ttyUSB0', 'COM3')
            baudrate: Baud rate (default 115200 for Pi Pico)
            timeout: Read timeout in seconds
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.serial = None
        self.is_connected = False
        self.last_activity = None
        self._rx_thread = None
        self._stop_event = threading.Event()
        self.event_queue = Queue()
    
    def connect(self) -> bool:
        """Establish serial connection."""
        try:
            self.serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout
            )
            time.sleep(0.5)  # Wait for Pi Pico to reset
            self.is_connected = True
            self.last_activity = datetime.now()
            print(f"✅ Connected to {self.port}")
            
            # Start receive thread
            self._stop_event.clear()
            self._rx_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._rx_thread.start()
            return True
        except Exception as e:
            print(f"❌ Failed to connect to {self.port}: {e}")
            self.is_connected = False
            return False
    
    def disconnect(self):
        """Close serial connection."""
        self._stop_event.set()
        if self._rx_thread:
            self._rx_thread.join(timeout=2)
        if self.serial:
            self.serial.close()
        self.is_connected = False
        print(f"🔌 Disconnected from {self.port}")
    
    def send_command(self, command: Dict[str, Any]) -> bool:
        """Send a command to the Pi Pico as JSON."""
        if not self.is_connected:
            return False
        try:
            json_str = json.dumps(command) + '\n'
            self.serial.write(json_str.encode())
            self.last_activity = datetime.now()
            return True
        except Exception as e:
            print(f"❌ Failed to send command: {e}")
            return False
    
    def ping(self) -> bool:
        """Ping the Pi Pico to check if it's alive."""
        return self.send_command({"type": "ping"})
    
    def _receive_loop(self):
        """Background thread: read and parse incoming JSON lines."""
        buffer = ""
        while not self._stop_event.is_set():
            if not self.is_connected:
                time.sleep(0.1)
                continue
            
            try:
                if self.serial.in_waiting:
                    data = self.serial.read(1).decode('utf-8', errors='ignore')
                    buffer += data
                    
                    if data == '\n':
                        line = buffer.strip()
                        buffer = ""
                        
                        if line:
                            try:
                                event = json.loads(line)
                                self.event_queue.put(event)
                                self.last_activity = datetime.now()
                            except json.JSONDecodeError as e:
                                print(f"⚠️  Invalid JSON from {self.port}: {line} ({e})")
                else:
                    time.sleep(0.01)
            except Exception as e:
                print(f"❌ Receive error on {self.port}: {e}")
                self.is_connected = False
                break
    
    def get_event(self, timeout: float = 0.1) -> Optional[Dict[str, Any]]:
        """Get next event from queue, non-blocking."""
        try:
            return self.event_queue.get(timeout=timeout)
        except:
            return None
    
    def is_healthy(self, timeout_sec: float = 5.0) -> bool:
        """Check if connection is healthy (recent activity)."""
        if not self.is_connected:
            return False
        if self.last_activity is None:
            return False
        elapsed = (datetime.now() - self.last_activity).total_seconds()
        return elapsed < timeout_sec


class SerialBridge:
    """Manages all serial connections and routes events to lanes."""
    
    def __init__(self):
        """Initialize serial bridge."""
        self.connections: Dict[str, SerialConnection] = {}
        self.event_callback: Optional[Callable] = None
    
    def set_event_callback(self, callback: Callable[[str, str, Any], None]):
        """
        Set callback for received events.
        
        Callback signature: callback(lane_id, event_name, data)
        """
        self.event_callback = callback
    
    def add_connection(self, port: str) -> Optional[str]:
        """
        Add and connect to a serial port.
        
        Returns:
            lane_id if successful, None otherwise
        """
        conn = SerialConnection(port)
        if conn.connect():
            self.connections[port] = conn
            return port  # For now, port is the lane_id
        return None
    
    def remove_connection(self, port: str):
        """Disconnect and remove a serial port."""
        if port in self.connections:
            self.connections[port].disconnect()
            del self.connections[port]
    
    def discover_ports(self) -> Dict[str, str]:
        """
        Discover available serial ports (Pi Picos).
        
        Returns:
            {port: lane_id} mapping
        """
        try:
            import serial.tools.list_ports
            ports = serial.tools.list_ports.comports()
            available = {}
            for p in ports:
                # Heuristic: Pi Pico appears as "Pico" or has VID/PID 2e8a:0005
                if 'Pico' in p.description or (p.vid == 0x2e8a and p.pid == 0x0005):
                    available[p.device] = f"lane_{len(available) + 1}"
            return available
        except Exception as e:
            print(f"⚠️  Could not discover ports: {e}")
            return {}
    
    def poll_events(self):
        """Poll all connections for events and dispatch them."""
        for port, conn in list(self.connections.items()):
            event = conn.get_event(timeout=0.001)
            if event and self.event_callback:
                lane_id = event.get('lane_id', port)
                event_name = event.get('event')
                event_data = event.get('data')
                self.event_callback(lane_id, event_name, event_data)
    
    def check_health(self):
        """Check all connections and log status."""
        for port, conn in self.connections.items():
            status = "🟢 OK" if conn.is_healthy() else "🔴 TIMEOUT"
            print(f"{port}: {status}")
    
    def close_all(self):
        """Close all connections."""
        for port in list(self.connections.keys()):
            self.remove_connection(port)
