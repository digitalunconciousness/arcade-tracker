# Multi-Lane Skeeball Architecture

## Overview
This document outlines a scalable, modular architecture supporting 1-N skeeball lanes, each with independent Pi Pico controllers communicating with a central coordinator.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│          Central Coordinator (Raspberry Pi 4)               │
│  - Lane Manager (discovery, registration, state sync)       │
│  - HTTP Server (Flask for arcade-tracker integration)       │
│  - Serial/Network Multiplexer                               │
└────────────┬────────────┬────────────┬──────────────────────┘
             │            │            │
     ┌───────▼────┐ ┌─────▼────┐ ┌────▼──────┐
     │  Pi Pico 1 │ │ Pi Pico 2 │ │ Pi Pico N │
     │  (Lane 1)  │ │ (Lane 2)  │ │ (Lane N)  │
     │            │ │           │ │           │
     │ GPIO Pins  │ │GPIO Pins  │ │GPIO Pins  │
     │ (Score,    │ │(Score,    │ │(Score,    │
     │  Coin,     │ │ Coin,     │ │ Coin,     │
     │  Ball)     │ │ Ball)     │ │ Ball)     │
     └────────────┘ └───────────┘ └───────────┘
```

## Component Design

### 1. Central Coordinator (lane_manager.py)
**Role**: Manage multiple lane instances, discovery, and inter-lane communication

**Key Classes**:
```python
class LaneManager:
    def __init__(self):
        self.lanes: Dict[str, LaneController] = {}
        self.serial_ports: List[SerialConnection] = []
    
    def discover_lanes(self) -> List[str]:
        """Scan for connected Pi Picos and register them"""
    
    def get_lane(self, lane_id: str) -> LaneController:
        """Get game logic instance for a lane"""
    
    def handle_event(self, lane_id: str, event: str, data: Any):
        """Route hardware events to the correct lane"""
```

### 2. Pi Pico Firmware (pico_firmware.py)
**Role**: Minimal GPIO handler on each Pi Pico, communicates state to coordinator

**Behavior**:
- Runs MicroPython on each Pi Pico
- Listens for GPIO transitions
- Sends JSON events to coordinator via serial/UART
- Pulls lane_id from environment or flash storage

**Protocol** (JSON over serial @ 115200 baud):
```json
{
  "lane_id": "lane_1",
  "event": "score",
  "data": "score_10",
  "timestamp": 1667891234.123
}
```

### 3. GameLogic Refactor (game_logic.py)
**Changes**:
- Add `lane_id` parameter to constructor
- All state keyed by `lane_id`
- Stateless score lookup (no global state)

```python
class GameLogic:
    def __init__(self, lane_id: str):
        self.lane_id = lane_id
        self.credits = 0
        self.score = 0
        # ... rest of fields
```

### 4. Lane Controller (lane_controller.py)
**Role**: Wrapper managing one lane's state and serial connection

```python
class LaneController:
    def __init__(self, lane_id: str, serial_port: str):
        self.lane_id = lane_id
        self.game = GameLogic(lane_id)
        self.serial = SerialConnection(serial_port)
        self.last_seen = datetime.now()
    
    def handle_raw_event(self, event_dict: Dict):
        """Receive JSON event from Pi Pico and forward to GameLogic"""
        self.game.handle_event(event_dict['event'], event_dict['data'])
    
    def is_online(self) -> bool:
        """Check if Pi Pico is still responsive"""
```

### 5. Flask Integration (skeeball_routes.py)
**New Routes**:
```
GET  /api/lanes                          # List all lanes
GET  /api/lanes/<lane_id>/status         # Get lane game state
POST /api/lanes/<lane_id>/trigger        # Manual trigger (testing)
POST /api/lanes/<lane_id>/reset          # Reset lane
WS   /ws/lanes/<lane_id>                 # WebSocket for real-time updates
```

## Communication Protocols

### Pi Pico → Coordinator (Serial JSON)
```json
{
  "type": "event",
  "lane_id": "lane_1",
  "event": "coin",
  "timestamp": 1667891234.123
}
```

### Coordinator → Pi Pico (Commands)
```json
{
  "type": "ping",
  "request_id": "req_123"
}
```

### Coordinator → Web UI (WebSocket)
```json
{
  "lane_id": "lane_1",
  "credits": 2,
  "score": 150,
  "balls": 3,
  "in_progress": true,
  "pin_triggered": "score_50"
}
```

## Deployment Scenarios

### Scenario 1: Single Lane (Current)
- Run on Raspberry Pi 4 directly
- GameLogic runs in-process (no serial needed for initial hardware)
- Optional: Keep serial interface for future expansion

### Scenario 2: Two Lanes
- Lane 1: Existing GPIO on Pi 4
- Lane 2: Pi Pico on USB serial
- Lane Manager detects and initializes both
- Coordinator routes events to correct GameLogic instance

### Scenario 3: N Lanes
- All lanes on Pi Picos
- Pi 4 runs coordinator only (no GPIO)
- Serial multiplexer handles N connections

## File Structure

```
Skeeball/
├── config.py                 # Shared config (pins, game settings)
├── game_logic.py             # ✅ Refactor: add lane_id parameter
├── input_manager.py          # ✅ Keep as-is (local GPIO handler)
├── lane_controller.py        # NEW: Wrapper for one lane
├── lane_manager.py           # NEW: Central coordinator
├── serial_bridge.py          # NEW: Serial protocol handling
├── skeeball_routes.py        # NEW: Flask integration
├── pico_firmware.py          # NEW: MicroPython for Pi Pico
├── main_single_lane.py       # ✅ Current: GameLogic + InputManager
├── main_coordinator.py       # NEW: Start coordinator mode
├── ui_simulator.py           # ✅ Keep with lane_id support
└── tests/
    ├── test_lane_manager.py  # NEW
    ├── test_serial_bridge.py # NEW
    └── test_game_logic.py    # ✅ Update for lane_id
```

## Implementation Roadmap

### Phase 1: Single Lane (Week 1)
- ✅ Current system runs as-is
- Add HTTP bridge for arcade-tracker read-only access
- Refactor GameLogic to accept lane_id (but only use "lane_1")

### Phase 2: Serial Interface (Week 2)
- Create Pi Pico firmware template
- Implement SerialBridge for JSON event parsing
- Create LaneController wrapper
- Test with one lane on USB serial, one on GPIO

### Phase 3: Lane Manager (Week 3)
- Implement LaneManager for multi-lane discovery
- Add automatic Pi Pico detection on startup
- WebSocket support for real-time UI updates
- Flask routes for lane control

### Phase 4: UI Expansion (Week 4)
- Update arcade-tracker to show all lanes
- Dynamic lane dashboard in arcade-tracker
- Per-lane controls and statistics

## Scalability Considerations

1. **Serial Bandwidth**: Each lane sends ~5-10 events/sec. At 115200 baud, easily handles 10+ lanes
2. **CPU**: Lane Manager is single-threaded event dispatcher. O(1) per event
3. **Storage**: Database stores per-lane stats (date-lane-score records)
4. **Expandability**: New lanes added via USB without code changes (discovery-based)

## Testing Strategy

```
Phase 1: Test single lane with mock serial
Phase 2: Test two lanes (GPIO + USB serial)
Phase 3: Test N lanes with simulated Pi Picos
Phase 4: Integration test with arcade-tracker
```

## Migration Path (From Current to Multi-Lane)

**Step 1** (Backward compatible):
```python
game = GameLogic("lane_1")  # Add lane_id, default to "lane_1"
```

**Step 2** (Add coordinator):
```python
manager = LaneManager()
manager.register_lane("lane_1", input_manager, gpio_pins)
```

**Step 3** (Add Pi Pico):
```python
manager.register_lane("lane_2", serial_port="/dev/ttyUSB0")
```

No breaking changes to existing GameLogic logic.
