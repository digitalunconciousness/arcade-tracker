# Skeeball Wiring - Optocoupler + Relay Board Design

## System Overview

**Inputs (Isolated via Optocouplers):**
- 9x switches → 9x optocouplers → Raspberry Pi GPIO

**Outputs (via Relay Board):**
- 2x LED displays (powered separately, controlled via relays or direct)
- 1x Solenoid (ball release) (12V via relay)

**Power:**
- Raspberry Pi: 5V 3A
- Relay board: 12V (can also power solenoid)
- Optocouplers: Powered by Pi 3.3V/5V

---

## Parts List

### Required Components

**Optocoupler Module (Recommended):**
- 8-channel PC817 optocoupler module (x2) OR
- Individual PC817 optocouplers + resistors

**Relay Board:**
- 4-channel 5V relay module (only need 1-2 channels)
- Alternatively: 2-channel relay module

**Switches:**
- 9x momentary switches (already in your skeeball machine)

**Displays:**
- 2x TM1637 4-digit LED displays

**Power:**
- 5V 3A power supply (for Raspberry Pi)
- 12V power supply (for solenoid + relay board)

**Wiring:**
- Dupont jumper wires (male-female)
- Terminal blocks (optional, for permanent install)
- Heat shrink tubing
- Wire (22 AWG stranded)

---

## Wiring Diagram (Text Format)

```
SWITCH SIDE (12V System)          OPTOCOUPLER          RASPBERRY PI SIDE
═══════════════════════════════   ═══════════════      ═════════════════

12V Power Supply                  PC817 Module
    │                            (8-channel x2)
    ├──────┐
    │      │
    │   ┌──┴──┐
    │   │ COM │ (Common for all switches)
    │   └──┬──┘
    │      │
    │   [Switch 1 - Coin]───────► IN1 ──────► GPIO 17
    │   [Switch 2 - Ball]───────► IN2 ──────► GPIO 18
    │   [Switch 3 - 10pt]───────► IN3 ──────► GPIO 22
    │   [Switch 4 - 20pt]───────► IN4 ──────► GPIO 23
    │   [Switch 5 - 30pt]───────► IN5 ──────► GPIO 24
    │   [Switch 6 - 40pt]───────► IN6 ──────► GPIO 25
    │   [Switch 7 - 50pt]───────► IN7 ──────► GPIO 27
    │   [Switch 8 - 100L]───────► IN8 ──────► GPIO 19
    │   [Switch 9 - 100R]───────► IN9 ──────► GPIO 13
    │
    └───[GND]


RELAY BOARD OUTPUTS
═══════════════════════════════

Raspberry Pi ──► Relay Module ──► Solenoid / LEDs

GPIO 10 ──────► IN1 (Relay 1) ──► Solenoid (12V)
               │
               COM ─── 12V+
               NO  ─── Solenoid (+)
                       Solenoid (-) ─── GND

GPIO 26 ──────► IN2 (Relay 2) ──► LED Power (optional)
```

---

## Detailed Connection Tables

### 1. Optocoupler Connections (PC817 Module)

**8-Channel Optocoupler Module (Need 2 modules for 9 inputs):**

#### Module 1 (Inputs 1-8)
| Switch Input | Opto IN | Opto OUT | Pi GPIO | Function |
|--------------|---------|----------|---------|----------|
| Switch 1 | IN1 | OUT1 | GPIO 17 | Coin sensor |
| Switch 2 | IN2 | OUT2 | GPIO 18 | Ball counter |
| Switch 3 | IN3 | OUT3 | GPIO 22 | 10pt switch |
| Switch 4 | IN4 | OUT4 | GPIO 23 | 20pt switch |
| Switch 5 | IN5 | OUT5 | GPIO 24 | 30pt switch |
| Switch 6 | IN6 | OUT6 | GPIO 25 | 40pt switch |
| Switch 7 | IN7 | OUT7 | GPIO 27 | 50pt switch |
| Switch 8 | IN8 | OUT8 | GPIO 19 | 100pt left |

#### Module 2 (Input 9)
| Switch Input | Opto IN | Opto OUT | Pi GPIO | Function |
|--------------|---------|----------|---------|----------|
| Switch 9 | IN1 | OUT1 | GPIO 13 | 100pt right |

**Optocoupler Module Power:**
- VCC → Pi 5V (Pin 2 or 4)
- GND → Pi GND (Pin 6)

**Switch Side (High voltage side):**
- All switch COM terminals → 12V+ (or 5V if using 5V system)
- All switch NO terminals → Optocoupler IN1-IN9

---

### 2. Relay Board Connections

**4-Channel 5V Relay Module:**

| Pi GPIO | Relay | Load | Purpose |
|---------|-------|------|---------|
| GPIO 10 | IN1 (Relay 1) | Solenoid | Ball release mechanism |
| GPIO 26 | IN2 (Relay 2) | LED power | Optional LED power control |
| — | IN3 (Relay 3) | Spare | Future expansion |
| — | IN4 (Relay 4) | Spare | Future expansion |

**Relay Board Power:**
- VCC → Pi 5V (Pin 2 or 4)
- GND → Pi GND (Pin 6)
- JD-VCC → Separate 5V (for relay coil isolation) OR jumper to VCC

**Relay 1 (Solenoid Control):**
```
12V Power Supply (+) ──┬─► COM
                       │
                       └─► NO ──► Solenoid (+)
                                  Solenoid (-) ──► 12V GND
```

**Flyback Diode:** Add 1N4007 diode across solenoid (cathode to +, anode to -)

---

### 3. TM1637 Display Connections

**Display 1:**
- VCC → Pi 5V
- GND → Pi GND
- CLK → GPIO 5 (Pin 29)
- DIO → GPIO 6 (Pin 31)

**Display 2:**
- VCC → Pi 5V
- GND → Pi GND
- CLK → GPIO 11 (Pin 23)
- DIO → GPIO 9 (Pin 21)

**Note:** TM1637 draws ~50mA each, well within Pi's capability.

---

## Complete GPIO Pin Usage

| GPIO Pin | Physical Pin | Function | Direction |
|----------|--------------|----------|-----------|
| **INPUTS (via optocouplers):** ||||
| GPIO 17 | Pin 11 | Coin sensor | INPUT |
| GPIO 18 | Pin 12 | Ball counter | INPUT |
| GPIO 22 | Pin 15 | 10pt switch | INPUT |
| GPIO 23 | Pin 16 | 20pt switch | INPUT |
| GPIO 24 | Pin 18 | 30pt switch | INPUT |
| GPIO 25 | Pin 22 | 40pt switch | INPUT |
| GPIO 27 | Pin 13 | 50pt switch | INPUT |
| GPIO 19 | Pin 35 | 100pt left | INPUT |
| GPIO 13 | Pin 33 | 100pt right | INPUT |
| **OUTPUTS:** ||||
| GPIO 10 | Pin 19 | Solenoid relay | OUTPUT |
| GPIO 26 | Pin 37 | LED power relay (optional) | OUTPUT |
| GPIO 5 | Pin 29 | Display 1 CLK | OUTPUT |
| GPIO 6 | Pin 31 | Display 1 DIO | OUTPUT |
| GPIO 11 | Pin 23 | Display 2 CLK | OUTPUT |
| GPIO 9 | Pin 21 | Display 2 DIO | OUTPUT |

**Total GPIO used: 15 pins**

---

## Compact Installation Layout

### Option A: Stacked Configuration (Smallest Footprint)

```
┌─────────────────────────────┐
│  Raspberry Pi 4             │
│  (85mm x 56mm)              │
└────────┬────────────────────┘
         │ (40-pin stacking header)
┌────────▼────────────────────┐
│  Proto HAT / Breadboard     │
│  - Optocoupler modules (x2) │
│  - Relay module             │
└─────────────────────────────┘

External connections via terminal blocks
```

**Pros:**
- Minimal footprint (~90mm x 60mm x 60mm)
- Clean appearance
- Easy to service

**Cons:**
- Requires custom proto board or HAT
- More assembly time

---

### Option B: Side-by-Side (Easier Install)

```
┌─────────────┐  ┌──────────────┐  ┌─────────────┐
│ Raspberry   │  │ Optocoupler  │  │ Relay       │
│ Pi 4        │──│ Modules (x2) │──│ Module      │
│             │  │              │  │             │
└─────────────┘  └──────────────┘  └─────────────┘
     │                  │                   │
     └──────────────────┴───────────────────┘
              Terminal strip
```

**Pros:**
- Easier to assemble
- Pre-made modules
- Easy troubleshooting

**Cons:**
- Larger footprint (~200mm x 60mm x 40mm)

---

### Recommended: DIN Rail Mount (Professional)

Use DIN rail mounting components:
- Raspberry Pi DIN rail case
- Optocoupler module on DIN mount
- Relay module on DIN mount
- Terminal blocks on DIN rail

**Total size:** ~250mm DIN rail length

---

## Wiring Steps (Side-by-Side Configuration)

### Step 1: Power Distribution
```
12V Power Supply:
  (+) ──┬─► Terminal block "12V+"
        ├─► Switch COM (common for all switches)
        └─► Relay board 12V in

  (-) ──┬─► Terminal block "GND"
        └─► Relay board GND

5V Power Supply (Pi):
  (+) ──┬─► Raspberry Pi (USB-C or pins 2/4)
        ├─► Optocoupler VCC
        └─► Relay board VCC

  (-) ──┬─► Raspberry Pi GND
        └─► Optocoupler GND
```

### Step 2: Switch Inputs (all follow same pattern)
```
For each switch:
  Switch NO ──► Optocoupler INx
  Switch COM ──► 12V+ (common rail)

  Optocoupler OUTx ──► Pi GPIOx
```

### Step 3: Relay Outputs
```
Pi GPIO 10 ──► Relay IN1
Relay 1 COM ──► 12V+
Relay 1 NO ──► Solenoid (+)
Solenoid (-) ──► GND
```

### Step 4: Displays
```
Display VCC ──► Pi 5V
Display GND ──► Pi GND
Display CLK ──► Pi GPIO
Display DIO ──► Pi GPIO
```

---

## Cable Management

### Terminal Block Layout
```
12V+  [====] ─── From 12V PSU
GND   [====] ─── From 12V PSU
5V    [====] ─── From 5V PSU
GND   [====] ─── From 5V PSU
────────────────────────────
SW1   [====] ─── Coin switch
SW2   [====] ─── Ball counter
SW3   [====] ─── 10pt switch
SW4   [====] ─── 20pt switch
SW5   [====] ─── 30pt switch
SW6   [====] ─── 40pt switch
SW7   [====] ─── 50pt switch
SW8   [====] ─── 100pt left
SW9   [====] ─── 100pt right
────────────────────────────
SOL+  [====] ─── Solenoid (+)
SOL-  [====] ─── Solenoid (-)
```

---

## Shopping List (Recommended Products)

### Electronics
- [ ] Raspberry Pi 4 (2GB sufficient)
- [ ] 2x 8-channel PC817 optocoupler module (~$8 each)
- [ ] 4-channel 5V relay module (~$8)
- [ ] 2x TM1637 4-digit LED display (~$3 each)
- [ ] 12V solenoid valve (push/pull type)
- [ ] 1N4007 diodes (x5, for flyback protection)

### Power
- [ ] 5V 3A power supply (official Pi adapter)
- [ ] 12V 2A power supply

### Mounting & Wiring
- [ ] Dual row terminal blocks (10-position)
- [ ] Dupont jumper wires (F-F, M-F)
- [ ] 22 AWG stranded wire (red, black, colors)
- [ ] Heat shrink tubing assortment
- [ ] Project enclosure or DIN rail + case
- [ ] M2.5 standoffs for Pi
- [ ] Cable ties

### Optional
- [ ] Proto HAT for Pi (if going stacked)
- [ ] DIN rail mounting kit
- [ ] Ferrules + crimper (for terminal blocks)
- [ ] Label maker or labels

**Estimated total cost: ~$100-150**

---

## Safety & Best Practices

### Electrical Safety
- ⚠️ Keep 12V and 5V systems separate
- ⚠️ Use proper gauge wire (22 AWG minimum)
- ⚠️ Add fuses: 12V supply (2A), 5V supply (3A)
- ⚠️ Always add flyback diodes across inductive loads (solenoid)
- ⚠️ Double-check polarity before powering on
- ⚠️ Use insulated terminals

### Installation Tips
- Label every wire with tape/labels
- Use different color wires for different voltages:
  - Red: 12V+
  - Black: GND
  - Orange: 5V
  - Blue: Signals
- Keep signal wires away from power wires
- Twist ground and signal pairs together
- Secure all connections with strain relief
- Test each section before final assembly

### Optocoupler Notes
- PC817 provides ~2500V isolation
- Input side can handle 5V-24V (use current-limiting resistor)
- Most modules have built-in resistors (~1kΩ)
- Output side is open-collector, needs pull-up (Pi has internal pull-ups)

### Relay Notes
- Relay coils draw ~70mA each (Pi GPIO max 16mA)
- Use relay module with transistor drivers (don't drive relays directly from GPIO)
- Separate JD-VCC from VCC for better isolation
- Add flyback diodes if not included on module

---

## Testing Procedure

### 1. Power Test (No connections)
```bash
# Power up Pi only
# Check voltage at GPIO header
# 5V should be ~5.0V
# 3.3V should be ~3.3V
```

### 2. Optocoupler Test
```python
import RPi.GPIO as GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(17, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# Manually trigger switch
# Should see GPIO go LOW
print(GPIO.input(17))  # Should print 0 when triggered
```

### 3. Relay Test
```python
GPIO.setup(10, GPIO.OUT)
GPIO.output(10, GPIO.HIGH)  # Relay should click ON
time.sleep(1)
GPIO.output(10, GPIO.LOW)   # Relay should click OFF
```

### 4. Display Test
```python
import tm1637
display = tm1637.TM1637(clk=5, dio=6)
display.number(1234)  # Should display "1234"
```

### 5. System Test
```bash
python3 skeeball_main.py
# Insert coin (or trigger switch)
# Solenoid should activate
# Display should show 0000
```

---

## Troubleshooting

### Problem: Optocoupler not triggering
- Check 12V power to switch side
- Check continuity from switch to optocoupler input
- Verify optocoupler LED lights up when switch pressed
- Check Pi GPIO pull-up is enabled

### Problem: Relay not switching
- Check GPIO output voltage (should be 3.3V HIGH)
- Check relay module power (5V)
- Try manually jumpering relay IN to GND (should trigger)
- Check relay LED indicator

### Problem: Solenoid not working
- Check 12V at relay output (use multimeter)
- Verify solenoid resistance (~10-50Ω typical)
- Check flyback diode orientation
- Try powering solenoid directly from 12V (bypass relay)

### Problem: Display not showing
- Check TM1637 library installed
- Verify CLK/DIO pins in config
- Check 5V power to display
- Try swapping CLK/DIO (might be mislabeled)

---

## Enclosure Recommendations

### Small Footprint (~150mm x 100mm x 50mm)
- Hammond 1591XXSSBK
- Bud Industries CU-1934
- Custom 3D printed case

### DIN Rail Mount
- Phoenix Contact DIN rail (35mm)
- Raspberry Pi DIN case: Italtronic RPI-DIN series
- Relay/opto modules usually have DIN clips

### Panel Mount (for cabinet door)
- Larger enclosure with panel cutouts
- Displays mounted to front panel
- All electronics inside
- Terminal blocks on side/bottom

---

This gives you a robust, isolated, and professional installation! The optocouplers protect your Pi from voltage spikes, and the relay board lets you control high-power loads safely.
