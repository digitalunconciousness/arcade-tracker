# Skeeball Hardware Wiring Guide

## GPIO Pin Assignments (BCM Mode)

| Component | GPIO Pin | Physical Pin | Notes |
|-----------|----------|--------------|-------|
| Coin Sensor | GPIO 17 | Pin 11 | Active LOW (pull-up) |
| Ball Counter | GPIO 18 | Pin 12 | Active LOW (pull-up) |
| Switch 0 (10pt) | GPIO 22 | Pin 15 | Active LOW (pull-up) |
| Switch 1 (10pt) | GPIO 23 | Pin 16 | Active LOW (pull-up) |
| Switch 2 (10pt) | GPIO 24 | Pin 18 | Active LOW (pull-up) |
| Switch 3 (10pt) | GPIO 25 | Pin 22 | Active LOW (pull-up) |
| Switch 4 (10pt) | GPIO 26 | Pin 37 | Active LOW (pull-up) |
| Switch 5 (10pt) | GPIO 27 | Pin 13 | Active LOW (pull-up) |
| Switch 6 (10pt) | GPIO 4 | Pin 7 | Active LOW (pull-up) |
| Switch 7 (10pt) | GPIO 16 | Pin 36 | Active LOW (pull-up) |
| Switch 8 (10pt) | GPIO 20 | Pin 38 | Active LOW (pull-up) |
| Switch 9 (10pt) | GPIO 21 | Pin 40 | Active LOW (pull-up) |
| 100pt Left | GPIO 19 | Pin 35 | Active LOW (pull-up) |
| 100pt Right | GPIO 13 | Pin 33 | Active LOW (pull-up) |
| Display CLK | GPIO 5 | Pin 29 | TM1637 clock |
| Display DIO | GPIO 6 | Pin 31 | TM1637 data |

## How the Scoring System Works

### Lane-Based Scoring with Multiple Switches

Your skeeball machine uses **momentary switches** placed along each scoring lane:

- **10pt lane (bottom):** 1 switch = 10 points
- **20pt lane:** 2 switches = 20 points  
- **30pt lane:** 3 switches = 30 points
- **40pt lane:** 4 switches = 40 points
- **50pt lane:** 5 switches = 50 points
- **100pt lanes (×2):** 5 switches + 1 special switch = 100 points

**How it works:**
1. Ball enters a lane
2. As ball rolls down, it triggers switches sequentially
3. System counts how many switches were hit
4. Ball reaches bottom counter → score is finalized
5. Each switch only counts once per ball

### Switch Wiring (Momentary Mechanical Switches)

**Wiring per switch:**
```
Switch NO (Normally Open) → Raspberry Pi GPIO
Switch COM (Common) → Raspberry Pi GND
```

**How switches work:**
- Switch at rest = GPIO reads HIGH (software pull-up resistor)
- Ball presses switch = GPIO reads LOW (connected to GND)
- System triggers on FALLING edge (HIGH → LOW)
- 50ms debounce prevents multiple triggers

## Coin Acceptor Wiring

### Standard Arcade Coin Acceptor
**Common models:** CH-926, ICT, Suzo-Happ

**Wiring:**
```
Coin Acceptor VCC → External 12V power supply
Coin Acceptor GND → Common ground with Pi
Coin Acceptor COIN signal → Raspberry Pi GPIO 17
```

**Signal characteristics:**
- Pulse signal (typically 50-100ms LOW pulse)
- May need voltage divider if output is 12V:
  ```
  Coin Signal → 10kΩ resistor → GPIO 17
                             ↓
                          20kΩ resistor
                             ↓
                           GND
  ```

### Simple Arcade Button (for testing)
```
Button NO → GPIO 17
Button COM → GND
```

## TM1637 Display Wiring

**4-Digit 7-Segment Display:**
```
Display VCC → Raspberry Pi 5V (Pin 2 or 4)
Display GND → Raspberry Pi GND
Display CLK → GPIO 5 (Pin 29)
Display DIO → GPIO 6 (Pin 31)
```

**Note:** Most TM1637 modules include current-limiting resistors. If yours doesn't, add 470Ω resistors in series with CLK and DIO.

## Complete Wiring Diagram (Text)

```
Raspberry Pi 40-Pin Header
============================

3.3V   (1) (2)  5V ← Display VCC, Sensors VCC
GPIO2  (3) (4)  5V
GPIO3  (5) (6)  GND ← Common ground
GPIO4  (7) (8)  GPIO14
GND    (9) (10) GPIO15
GPIO17 (11)(12) GPIO18 ← 100pt Hole
GPIO27 (13)(14) GND
GPIO22 (15)(16) GPIO23 ← 20pt Hole
3.3V   (17)(18) GPIO24 ← 30pt Hole
GPIO10 (19)(20) GND
GPIO9  (21)(22) GPIO25 ← 40pt Hole
GPIO11 (23)(24) GPIO8
GND    (25)(26) GPIO7
GPIO0  (27)(28) GPIO1
GPIO5  (29)(30) GND
GPIO6  (31)(32) GPIO12
GPIO13 (33)(34) GND
GPIO19 (35)(36) GPIO16
GPIO26 (37)(38) GPIO20
GND    (39)(40) GPIO21

Connections:
- Pin 11 (GPIO17) ← Coin Sensor
- Pin 15 (GPIO22) ← 10pt Hole
- Pin 16 (GPIO23) ← 20pt Hole
- Pin 18 (GPIO24) ← 30pt Hole
- Pin 22 (GPIO25) ← 40pt Hole
- Pin 13 (GPIO27) ← 50pt Hole
- Pin 12 (GPIO18) ← 100pt Hole
- Pin 29 (GPIO5)  → Display CLK
- Pin 31 (GPIO6)  → Display DIO
```

## Power Considerations

### Raspberry Pi Power
- **Minimum:** 5V 2.5A power supply
- **Recommended:** 5V 3A power supply (if powering sensors from Pi)
- Use official Raspberry Pi power supply or equivalent quality

### Sensor Power
- **IR sensors:** Typically 20mA each × 7 sensors = 140mA
- **Display:** TM1637 draws ~50mA max
- **Total:** ~200mA (well within Pi's capability)

### Coin Acceptor Power
- **DO NOT** power coin acceptor from Raspberry Pi
- Use separate 12V power supply
- **Connect grounds together** (common ground)

## Cable Recommendations

- **Sensor cables:** 22-24 AWG stranded wire
- **Maximum length:** Keep under 3 meters to avoid signal issues
- **Use shielded cable** if running near power lines or motors
- **Twist pairs:** Twist signal and ground wires together to reduce interference

## Mounting Tips

### Sensor Placement
1. **Score holes:** Mount IR sensors directly above each hole
   - Emitter on one side, detector on other
   - Or use reflective sensors pointed at hole

2. **Coin acceptor:** Mount securely, connect signal wire with minimal length

3. **Display:** Mount where visible to players
   - Consider viewing angle
   - Protect from ball impacts

### Enclosure
- Use weatherproof enclosure if in damp environment
- Ensure proper ventilation for Raspberry Pi
- Label all connections for future maintenance

## Testing Sensors

### Test single GPIO input:
```python
import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BCM)
GPIO.setup(17, GPIO.IN, pull_up_down=GPIO.PUD_UP)

try:
    while True:
        state = GPIO.input(17)
        print(f"GPIO 17: {'HIGH' if state else 'LOW'}")
        time.sleep(0.1)
except KeyboardInterrupt:
    GPIO.cleanup()
```

### Test all sensors at once:
```python
import RPi.GPIO as GPIO

pins = [17, 22, 23, 24, 25, 27, 18]
GPIO.setmode(GPIO.BCM)

for pin in pins:
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

try:
    while True:
        for pin in pins:
            state = "OK" if GPIO.input(pin) else "TRIGGERED"
            print(f"GPIO {pin}: {state}", end="  ")
        print("\r", end="")
except KeyboardInterrupt:
    GPIO.cleanup()
```

## Troubleshooting

### Problem: Sensors triggering constantly
- **Check:** Wiring (ensure correct polarity)
- **Check:** Pull-up/pull-down configuration
- **Try:** Increase `bounce_time_ms` in config.json

### Problem: Sensors not triggering
- **Check:** Sensor power (LED should be on)
- **Check:** Alignment (for IR sensors)
- **Check:** GPIO pin numbers (BCM vs BOARD mode)
- **Test:** Manually connect GPIO to GND to verify

### Problem: Multiple triggers from one ball
- **Cause:** Ball bouncing or sensor bounce
- **Fix:** Increase `bounce_time_ms` to 300-500
- **Fix:** Add capacitor (0.1µF) across sensor signal and GND

### Problem: Display not showing
- **Check:** TM1637 library installed: `pip3 show tm1637`
- **Check:** Wiring (CLK and DIO correct)
- **Check:** Brightness (TM1637 has brightness control)
- **Fallback:** System works without display (console output)

## Safety Notes

- ⚠️ **Never connect 12V directly to Raspberry Pi GPIO**
- ⚠️ **Always use common ground** between Pi and external devices
- ⚠️ **Protect against ESD** when handling Pi
- ⚠️ **Disconnect power** before changing wiring
- ⚠️ **Use proper gauge wire** for current requirements
- ⚠️ **Secure all connections** to prevent intermittent faults

## Shopping List

### Required Components
- [ ] Raspberry Pi (any model with 40-pin GPIO)
- [ ] MicroSD card (16GB Class 10 recommended)
- [ ] 5V 3A power supply
- [ ] 6× IR break-beam sensors
- [ ] 1× Coin acceptor (with 12V power supply)
- [ ] Jumper wires (male-to-female)
- [ ] Breadboard (for prototyping)

### Optional Components
- [ ] TM1637 4-digit display
- [ ] Enclosure/case for Raspberry Pi
- [ ] Heat sinks for Pi
- [ ] Cooling fan
- [ ] Screw terminals for permanent installation
- [ ] Cable management (zip ties, labels)

### Tools Needed
- Wire strippers
- Screwdriver set
- Multimeter (for testing)
- Soldering iron (if making permanent connections)
