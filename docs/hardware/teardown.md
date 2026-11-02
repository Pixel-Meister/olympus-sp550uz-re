# Olympus SP-550UZ Physical Hardware Teardown & Silicon Architecture

A comprehensive physical hardware teardown guide and silicon Bill of Materials (BOM) for the **Olympus SP-550UZ** bridge digital camera (`07b4:0109`), documenting board layout, component packages, silicon markings, and low-level firmware interconnects.

---

## 1. Executive Summary & Teardown Methodology

Physical disassembly and microscopic inspection of the Olympus SP-550UZ main printed circuit board (PCB) was performed to correlate firmware static analysis discoveries with physical silicon. 

The camera electronics are organized across two primary circuit boards connected via high-density flexible printed circuits (FPCs):
1. **Main Logic Board**: Multi-layer high-density interconnect (HDI) PCB containing the central application processor, multi-chip memory package, power management IC, motor drivers, display controller, and external storage slot.
2. **CCD Sensor & Optical Board**: Houses the 7.1-megapixel 1/2.5-inch interline-transfer CCD image sensor, analog front-end (AFE), and optoelectronic zoom/focus encoder sensors.

---

## 2. Silicon Bill of Materials (BOM)

The physical teardown identified six primary integrated circuits that govern the SP-550UZ hardware architecture:

| IC Role | Manufacturer & Part Number | Package | Hardware Specifications & Firmware Interconnect |
|:---|:---|:---|:---|
| **Main Processor / SoC** | **Sanyo EV1MSS11** | BGA | **Olympus TruePic III / Sanyo Coach platform** (`SG155`, build `v155-77`). Integrates ARM946E-S 32-bit RISC core @ 150 MHz (48 MHz peripheral bus), 8 KB I-Cache, 8 KB D-Cache. Directly executes Section 1 ARM code loaded at `0x40000000`. Reset vector jumps to `0x40000800`. Integrates all 7 MMIO peripheral blocks (`0x80410000` to `0xE081FFFF`). |
| **Flash & Memory (MCP)** | **Samsung K5R Multi-Chip Package** | FBGA | Multi-Chip Package combining **OneNAND Flash** (47MB internal non-volatile storage) and **32MB Mobile SDRAM** (`0x40000000`–`0x41FFFFFF`). Code and resources load into SDRAM; OneNAND flash is managed via Samsung BML/STL translation layer (`0x40339f1e`–`0x4033b2d2`) through the hardware DMA/NAND controller (`0xC04C0000`). |
| **Power Management (PMIC)** | **ROHM BD9739KN** | QFN / Side A | 7-channel switching regulator providing core digital VDD (1.2V/1.3V), Mobile SDRAM IO (1.8V/2.5V), 3.3V logic, CCD AFE rails, and motor drive power. Governs standby sleep state power reduction. Interfaced to firmware sleep inhibit query (`0x40150540`, `0x40184be0`) and battery ADC monitoring (`0x41f8ddfc`). |
| **Dual Motor Driver** | **Sanyo LV8086** | SSOP / Side B | Dedicated dual H-bridge stepper and DC motor driver. Drives the 18x optical zoom lens barrel traversal and autofocus lens group positioning. Controlled by the RTOS event loop (`0x4019e1e8`) via `RTOS_Evt2_LensMotor` (`0x4019e6b8`) and `RTOS_EvtB_Autofocus` (`0x4019e4c0`). |
| **EVF Micro-Display Controller** | **Kopin KCD CyberDisplay** | TQFP / Side B | Dedicated display timing controller for the 0.2-inch electronic viewfinder (EVF) micro-display. Selected when video destination query `0x4012fef4` returns code `1` (built-in LCD is `0`, NTSC video out is `4`, PAL video out is `6`). |
| **Calibration EEPROM** | **2316GO (24C16)** | 8-pin SOP / Side B | 16 Kbit (2,048 bytes / 2 KB) two-wire I2C serial EEPROM (I2C address 0x50). Stores factory lens optical calibration curves, CCD defect bad-pixel maps (`anji_hakuten_pos` mapped to `0x402b8000`), white balance reference matrices, and camera serial number (`000J99208881`). |

---

## 3. PCB Layout Architecture

The main logic board features dual-sided surface mount component placement:

```
                      SIDE A (Primary Processing Side)
+-----------------------------------------------------------------+
|   [FPC: Lens/AF]       [24 MHz Crystal]       [FPC: Top Dial]   |
|                                                                 |
|   +-----------------------+           +---------------------+   |
|   |                       |           |                     |   |
|   |    Sanyo EV1MSS11     |           |     Samsung K5R     |   |
|   |     TruePic III       |           |      MCP FBGA       |   |
|   |     ARM946E-S         |           | (OneNAND + 32MB)    |   |
|   |        BGA            |           |                     |   |
|   +-----------------------+           +---------------------+   |
|                                                                 |
|           +-----------------------+      [Power Inductors]      |
|           |     ROHM BD9739KN     |      [1.2V / 1.8V / 3.3V]   |
|           |       7-Ch PMIC       |                             |
|           |          QFN          |                             |
|           +-----------------------+                             |
|                                                                 |
|   [FPC: CCD Sensor AFE]               [Battery Terminal Rails]  |
+-----------------------------------------------------------------+

                      SIDE B (Interface & Peripheral Side)
+-----------------------------------------------------------------+
|   [xD-Picture Card Slot]                   [FPC: 2.5" LCD]      |
|                                                                 |
|   +-----------------------+           +---------------------+   |
|   |     Sanyo LV8086      |           |      Kopin KCD      |   |
|   |   Dual Motor Driver   |           |  CyberDisplay EVF   |   |
|   |         SSOP          |           |        TQFP         |   |
|   +-----------------------+           +---------------------+   |
|                                                                 |
|           +-----------+               +---------------------+   |
|           |  2316GO   |               |   Olympus Multi-IO  |   |
|           |   24C16   |               |    12-pin USB/AV    |   |
|           | 8-pin SOP |               |      Connector      |   |
|           +-----------+               +---------------------+   |
|                                                                 |
|   [SDRAM Decoupling Caps]                  [FPC: Keypad Matrix] |
+-----------------------------------------------------------------+
```

### 3.1 Side A: Central Computing & Power Distribution
- **Sanyo EV1MSS11 BGA**: Positioned centrally to minimize trace lengths to the memory package and sensor interface. Thermal dissipation is routed through ground planes into the metal camera chassis frame.
- **Samsung K5R MCP FBGA**: Connected via a high-speed 32-bit multiplexed bus to the EV1MSS11 memory controller (`0x80410000`).
- **ROHM BD9739KN PMIC**: Located adjacent to discrete surface-mount inductors and low-ESR ceramic capacitors, generating the necessary voltage steps from 4x AA battery inputs (nominal 4.8V NiMH or 6.0V Alkaline).
- **24 MHz Oscillator**: Reference clock for internal PLL synthesis yielding the 150 MHz CPU core clock and 48 MHz peripheral bus clock.

### 3.2 Side B: Motion Control, Viewfinder & Storage
- **Sanyo LV8086 SSOP**: Dual full-bridge motor driver routing high-current drive signals through the lens FPC to the 18x zoom motor and autofocus stepping motor.
- **Kopin KCD CyberDisplay TQFP**: Interfaced with digital video stream lines from the EV1MSS11 Video DAC Compositor (`0xE0600000`), routing RGB data to the EVF micro-display.
- **2316GO (24C16) 8-pin SOP**: Connected via standard I2C bus lines (SCL / SDA) to EV1MSS11 GPIO lines. Holds factory calibration tables read during early boot.
- **xD-Picture Card Socket**: Multi-pin push-push connector wired to NAND Flash Controller lines (`0xC04C0000`).
- **12-pin Olympus USB/AV Multi-Connector**: Combines USB 2.0 Full-Speed data lines (D+/D-), composite analog video out (NTSC/PAL), monaural audio out, and cable detection pins.

---

## 4. Hardware Interconnect & Bus Topology

```
+-----------------------------------------------------------------------+
|                          Sanyo EV1MSS11 SoC                           |
|                      (Olympus TruePic III / SG155)                    |
|                                                                       |
|   +---------------------------------------------------------------+   |
|   |            ARM946E-S CPU Core @ 150 MHz (ARMv5TEJ)            |   |
|   |                 8 KB I-Cache  /  8 KB D-Cache                 |   |
|   +---------------------------------------------------------------+   |
|                                   |                                   |
|   +--------------------+----------+----------+--------------------+   |
|   |                    |                     |                    |   |
|   v                    v                     v                    v   |
| [Memory Ctrl]   [NAND/DMA Ctrl]      [Video DAC/ISP]        [GPIO/Timers] |
| (0x80410000)     (0xC04C0000)          (0xE0600000)         (0xE0200000)  |
+---+--------------------+---------------------+--------------------+---+
    |                    |                     |                    |
    | 32-bit Bus         | Memory Bus          | Digital Video      | I2C / Control
    v                    v                     v                    v
+-----------+    +---------------+     +---------------+    +---------------+
|  Samsung  |    |  xD-Picture   |     |   Kopin KCD   |    | Sanyo LV8086  |
|  K5R MCP  |    |   Card Slot   |     | CyberDisplay  |    | Motor Driver  |
| (32MB RAM |    +---------------+     |   (EVF Out)   |    +---------------+
| + OneNAND)|                          +---------------+            |
+-----------+                                  |                    v
    |                                          |            [18x Zoom & AF]
    v                                          v
[Section 1 Code: 0x40000000]           [Display Query: 1]   +---------------+
[Section 2 Data: 0x403F5108]                                | 2316GO EEPROM |
[Uncached RAM:   0x41F00000]           +---------------+    | (24C16 16Kbit)|
[Blackboard:     0x41F80000]           | Composite DAC |    +---------------+
[Task Stacks:    0x41FA0000]           |  NTSC / PAL   |            |
                                       +---------------+            v
                                               |            [Lens Cal & SN]
                                               v
                                       [Display Query: 4/6]
```

---

## 5. Firmware-to-Silicon Correlation

The physical components identified during the teardown directly explain key firmware mechanisms recovered during reverse engineering:

1. **OneNAND & SDRAM Co-Packaging (Samsung K5R MCP)**:
   Explains why Section 1 (ARM code) and Section 2 (GUI bitmaps) execute seamlessly in the unified `0x40000000`–`0x40855967` address space, while raw flash storage uses Samsung-specific `BML_` (Block Management Layer) and `STL_` (Sector Translation Layer) algorithms.
2. **Motor Driver Event Routing (Sanyo LV8086)**:
   Explains RTOS events `0x02` (`RTOS_Evt2_LensMotor` at `0x4019e6b8`) and `0x0B` (`RTOS_EvtB_Autofocus` at `0x4019e4c0`). The firmware controls zoom traversal steps and focus coil drive via discrete command words routed to the LV8086.
3. **Display Output Selection (Kopin KCD & Video DAC)**:
   Correlates with the display destination query at `0x4012fef4`. When destination code `1` is active, the EV1MSS11 routes video timings to the Kopin KCD CyberDisplay. When destination code `4` or `6` is active, the internal Video DAC synthesizes composite analog video over the 12-pin connector.
4. **Sleep Inhibit & Power Rails (ROHM BD9739KN)**:
   Correlates with the standby sleep lock mechanism. When composite video is detected (`destination > 1`), `0x40184e48` zeroes the sleep countdown packet (`sp[6]=0`), preventing the BD9739KN from cutting power to the sensor and video subsystems.
5. **Factory Calibration Integrity (2316GO EEPROM)**:
   Explains where the camera retrieves CCD defective pixel coordinates (`anji_hakuten_pos`, `meiji_kokuten_pos` mapped to `0x402b8000`), optical lens center coordinates, and the serial number (`000J99208881` returned by PTP opcode `0x1001`).

---

## 6. Document Metadata & Verification

- **Author**: Olympus Reverse Engineering Team
- **Validation**: Physically confirmed against SP-550UZ chassis and PCB hardware
- **Related Documents**:
  - Main Architecture Reference: [`firmware_architecture_reference.md`](../../Resources/notes/firmware_architecture_reference.md)
  - Memory Map: [`memory_map.md`](../xref/memory_map.md)
  - Subsystems Analysis: [`subsystems.md`](../xref/subsystems.md)
