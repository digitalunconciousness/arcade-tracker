#!/usr/bin/env python3
"""Lane Manager - central coordinator for multi-lane skeeball systems.

Manages multiple lane controllers, handles discovery of Pi Pico devices,
and routes hardware events to the correct lane.
"""

import threading
import time
from typing import Dict, Optional, List, Any
from lane_controller import LaneController
from serial_bridge import SerialBridge, SerialConnection
import config


class LaneManager:
    """Central coordinator for multi-lane skeeball systems."""
    
    def __init__(self, auto_discover: bool = True):
        """
        Initialize the lane manager.
        
        Args:
            auto_discover: If True, automatically discover and register Pi Picos on startup
        """
        self.lanes: Dict[str, LaneController] = {}
        self.serial_bridge = SerialBridge()
        self.serial_bridge.set_event_callback(self._on_serial_event)
        self._polling_thread = None
        self._stop_event = threading.Event()
        
        if auto_discover:
            self.discover_lanes()
    
    def discover_lanes(self) -> List[str]:
        """
        Discover and auto-register connected Pi Picos.
        
        Returns:
            List of newly discovered lane_ids
        """
        ports = self.serial_bridge.discover_ports()
        new_lanes = []
        
        for port, lane_id in ports.items():
            if lane_id not in self.lanes:
                if self.register_serial_lane(lane_id, port):
                    new_lanes.append(lane_id)
        
        if new_lanes:
            print(f"🎳 Discovered {len(new_lanes)} new lane(s): {new_lanes}")
        else:
            print("📭 No new lanes discovered")
        
        return new_lanes
    
    def register_local_lane(self, lane_id: str, input_manager=None) -> bool:
        """
        Register a lane with local GPIO (on the Pi 4).
        
        Args:
            lane_id: Unique lane identifier
            input_manager: InputManager instance for GPIO handling (optional)
        
        Returns:
            True if registration successful
        """
        if lane_id in self.lanes:
            print(f"⚠️  Lane {lane_id} already registered")
            return False
        
        controller = LaneController(lane_id, serial_conn=None)
        self.lanes[lane_id] = controller
        
        if input_manager:
            # Wrap the input manager's callback to route through lane manager
            original_callback = input_manager.event_callback
            def routed_callback(event, data):
                self.handle_event(lane_id, event, data)
            input_manager.event_callback = routed_callback
        
        print(f"✅ Registered local lane: {lane_id}")
        return True
    
    def register_serial_lane(self, lane_id: str, port: str) -> bool:
        """
        Register a lane connected via serial (Pi Pico).
        
        Args:
            lane_id: Unique lane identifier
            port: Serial port (e.g., '/dev/ttyUSB0')
        
        Returns:
            True if registration successful
        """
        if lane_id in self.lanes:
            print(f"⚠️  Lane {lane_id} already registered")
            return False
        
        # Connect to serial port
        serial_conn = SerialConnection(port)
        if not serial_conn.connect():
            return False
        
        # Store connection in serial bridge
        self.serial_bridge.connections[port] = serial_conn
        
        # Create lane controller
        controller = LaneController(lane_id, serial_conn=serial_conn)
        self.lanes[lane_id] = controller
        
        print(f"✅ Registered serial lane: {lane_id} on {port}")
        return True
    
    def unregister_lane(self, lane_id: str) -> bool:
        """
        Unregister and disconnect a lane.
        
        Args:
            lane_id: Unique lane identifier
        
        Returns:
            True if successful
        """
        if lane_id not in self.lanes:
            print(f"⚠️  Lane {lane_id} not found")
            return False
        
        lane = self.lanes[lane_id]
        if lane.serial_conn:
            lane.serial_conn.disconnect()
        
        del self.lanes[lane_id]
        print(f"🔌 Unregistered lane: {lane_id}")
        return True
    
    def handle_event(self, lane_id: str, event: str, data: Any = None):
        """
        Handle a hardware event for a specific lane.
        
        Args:
            lane_id: Target lane identifier
            event: Event name (e.g., "coin", "score", "ball_scored")
            data: Event data (e.g., "score_10")
        """
        if lane_id not in self.lanes:
            print(f"⚠️  Unknown lane: {lane_id}")
            return
        
        self.lanes[lane_id].handle_event(event, data)
    
    def _on_serial_event(self, lane_id: str, event: str, data: Any):
        """Callback from SerialBridge for incoming events."""
        self.handle_event(lane_id, event, data)
    
    def get_lane(self, lane_id: str) -> Optional[LaneController]:
        """Get a lane controller by ID."""
        return self.lanes.get(lane_id)
    
    def get_all_lanes(self) -> Dict[str, LaneController]:
        """Get all registered lanes."""
        return self.lanes.copy()
    
    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all lanes."""
        return {
            lane_id: lane.get_status()
            for lane_id, lane in self.lanes.items()
        }
    
    def reset_lane(self, lane_id: str) -> bool:
        """Reset a specific lane."""
        lane = self.get_lane(lane_id)
        if not lane:
            return False
        lane.reset_game()
        return True
    
    def start_polling(self):
        """Start background polling of serial connections."""
        if self._polling_thread is not None:
            print("⚠️  Polling already running")
            return
        
        self._stop_event.clear()
        self._polling_thread = threading.Thread(
            target=self._polling_loop,
            daemon=True
        )
        self._polling_thread.start()
        print("🔄 Started serial polling")
    
    def stop_polling(self):
        """Stop background polling."""
        if self._polling_thread is None:
            return
        
        self._stop_event.set()
        self._polling_thread.join(timeout=2)
        self._polling_thread = None
        print("⏹️  Stopped serial polling")
    
    def _polling_loop(self):
        """Background thread: poll serial connections for events."""
        while not self._stop_event.is_set():
            self.serial_bridge.poll_events()
            time.sleep(0.01)  # 100 Hz polling
    
    def check_health(self):
        """Check health of all lanes."""
        print("🏥 Lane Health Check:")
        for lane_id, lane in self.lanes.items():
            status = "🟢 OK" if lane.is_online() else "🔴 OFFLINE"
            print(f"  {lane_id}: {status}")
    
    def shutdown(self):
        """Gracefully shut down all lanes."""
        self.stop_polling()
        self.serial_bridge.close_all()
        print("🛑 Lane Manager shutdown complete")
