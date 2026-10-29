# Olympus SP-550UZ Plain-Language Firmware Architecture Guide

## Overview

This guide explains the inner workings of the **Olympus SP-550UZ** digital camera in clear, accessible language. It breaks down the entire software and hardware architecture, showing how the camera boots, processes video, draws menus and graphics, manages battery power and sleep timers, and executes firmware updates.

---

## 1. The Big Picture: Hardware & Silicon

Inside the SP-550UZ is a specialized microcomputer system designed by Sanyo (OEM platform code **SG155**, marketed by Olympus as the **TruePic III** image processor):

```
+---------------------------------------------------------------------------------+
|                                 OLYMPUS SP-550UZ                                |
|                                                                                 |
|  +--------------------+     +------------------------------------------------+  |
|  |     ARM CPU        |     |             Image Processing Subsystem         |  |
|  |  (Controls camera  |<--->|  (CCD Sensor Interface -> Hardware Filters ->  |  |
|  |   logic & RTOS)    |     |   Color Matrix -> Hardware JPEG / YUV Scaler)  |  |
|  +--------------------+     +------------------------------------------------+  |
|            |                                         |                          |
|            v                                         v                          |
|  +--------------------+                     +--------------------------------+  |
|  |    System SDRAM    |<===================>| Hardware Display Compositor    |  |
|  |     (32 MB RAM)    |                     | (Merges live video + OSD layer)|  |
|  +--------------------+                     +--------------------------------+  |
|            ^                                         |                          |
|            |                                         v                          |
|  +--------------------+                     +--------------------------------+  |
|  | Flash Memory / ROM |                     | Video Outputs:                 |  |
|  |  (Stores Firmware) |                     |  - Rear LCD                    |  |
|  +--------------------+                     |  - Electronic Viewfinder (EVF) |  |
|                                             |  - Composite A/V (TV Out)      |  |
|                                             +--------------------------------+  |
+---------------------------------------------------------------------------------+
```

### The Three Core Silicon Engines
1. **The ARM CPU Core:** Runs the camera's master software (firmware), tracking button presses, managing lens motors, running autofocus calculations, and maintaining camera state.
2. **The Hardware Image Signal Processor (ISP):** A dedicated coprocessor that takes high-speed raw image data from the 7.1-megapixel CCD sensor, corrects dead pixels, adjusts white balance, and scales the image into standard video frames at 30 frames per second without burdening the CPU.
3. **The Hardware Display Compositor:** A video chip that takes two independent graphic streams—the **live camera video** on bottom, and a **transparent graphics overlay plane (OSD)** on top—merges them together, and sends the combined picture out to the LCD, EVF, or composite video cable.

---

## 2. Memory Organization: Where Everything Lives

When the camera powers on, the flash memory image is loaded into dynamic memory (SDRAM) at address `0x40000000`:

```
+-------------------------------------------------------------------------------+
| Address Range             | Name / Section  | What It Stores                  |
+---------------------------+-----------------+---------------------------------+
| 0x40000000 - 0x403F50E7   | Section 1       | Executable Program Code         |
|                           | ("NPROG", 4.15MB| All functions, algorithms, RTOS |
+---------------------------+-----------------+---------------------------------+
| 0x403F5108 - 0x40855967   | Section 2       | Graphic & Audio Assets          |
|                           | ("NDATA", 4.59MB| Fonts, icons, menus, sounds     |
+---------------------------+-----------------+---------------------------------+
| 0x41F00000 - 0x41F7FFFF   | Video Buffers   | Live Camera Framebuffers        |
|                           | (512 KB)        | Video frames streamed to TV/LCD |
+---------------------------+-----------------+---------------------------------+
| 0x41F80000 - 0x41F9FFFF   | System State    | Master State Blackboard         |
|                           | (128 KB)        | Current mode, timers, settings  |
+---------------------------+-----------------+---------------------------------+
| 0x41FA0000 - 0x41FD0000   | CPU Stacks      | Function call stacks for RTOS   |
+---------------------------+-----------------+---------------------------------+
| 0x80000000 - 0xEFFFFFFF   | Hardware MMIO   | Motor controls, timers, sensors |
+---------------------------+-----------------+---------------------------------+
```

### The "Blackboard" System State (`0x41f8ddcc` & `0x41f8ddac`)
The firmware uses a centralized memory structure known as the **Master State Blackboard**. Instead of passing hundreds of variables between functions, functions read and write to standardized offsets on this board:
* **Active OSD Mode (`[0x41f8ddcc, #0x9e]`):** Holds the currently selected display view (`0` = Full HUD, `1` = Grid/Histogram, `2` = Minimal View, `8` = Auto Minimal).
* **Power State Machine (`[0x41f8ddcc, #0x60]`):** Tracks whether the camera is in Active Shooting (`0xe7`), Sleep Standby (`0x49`), or Powering Down.
* **Master Timer Block (`0x41f8ddac`):** Tracks inactivity counts, countdown timers for LCD backlight dimming (default 2.5 minutes), and automatic standby sleep (default 3 minutes).

---

## 3. How the Camera Starts Up

1. **Power Button Pressed:** Power regulators energize the ARM processor.
2. **Reset Vector (`0x40000000`):** The CPU jumps to `0x40000800`.
3. **CPU Register Setup:** The processor configures its operating modes (Supervisor, Interrupt, User) and points stack pointers to safe SDRAM memory.
4. **Hardware Initialization:**
   - The memory controller tunes SDRAM clock timings.
   - The lens subsystem runs a home-position calibration sweep (extending the zoom barrel slightly and initializing the stepper motors).
   - The CCD sensor timing generator starts pulsing to capture light.
5. **RTOS Kernel Launch:** The Real-Time Operating System spawns the background worker tasks:
   - **Keypad Task:** Scans buttons and the top mode dial every few milliseconds.
   - **Timer Task:** Ticks real-time clocks and inactivity counters.
   - **Sensor/Exposure Task:** Calculates live autofocus, autoexposure, and auto white balance (3A loop).
   - **Display Manager Task:** Refreshes the on-screen display and updates icons.

---

## 4. The Video & Display Pipeline: How Video and OSD Are Rendered

Understanding how images reach your screen is the key to reverse engineering the display architecture:

```
+----------------+      +----------------+      +----------------------+
|   CCD Sensor   | ---> |  Hardware ISP  | ---> | Live Video Frame     |
| (Raw Pixels)   |      | (Color Matrix) |      | (Pure moving picture)|
+----------------+      +----------------+      +----------------------+
                                                           |
                                                           v
                                                +----------------------+
                                                | Hardware Compositor  | <--- [OSD Overlay Plane]
                                                | (Combines layers)    |
                                                +----------------------+
                                                           |
                                                           v
                                                +----------------------+
                                                | Composite Video Out  | ===> TV / Capture Card
                                                +----------------------+
```

### The Two Video Layers
1. **The Live Sensor Layer:** The pure video stream from the sensor lens. It has **no text, no icons, and no markings**. It runs continuously at 30 frames per second.
2. **The On-Screen Display (OSD) Overlay Layer:** A transparent 2D digital canvas drawn on top of the live picture. The camera draws shutter speeds, aperture numbers, battery bars, and autofocus boxes here.

### How the `DISP` Button Cycles Views
Whenever you tap the `DISP` button:
1. The camera increments the mode counter at `[0x41f8ddcc, #0x9e]`.
2. The **Master OSD Dispatcher** checks this byte:
   * **Mode 0 (Normal HUD):** Draws shutter speed, aperture, ISO, zoom meter, battery gauge, and AF brackets.
   * **Mode 1 (Assist HUD):** Draws rule-of-thirds grid lines and live exposure histogram.
   * **Mode 2 (Manual Minimal):** Draws minimal exposure readouts and battery status.
   * **Mode 4 (Clean Epilogue):** Bypasses element rendering entirely and returns directly to the compositor.
3. The hardware compositor merges the transparent overlay with the sensor video.

---

## 5. Autofocus & The White Brackets `[   ]`

Many cameras draw autofocus brackets inside the same function that prints shutter speed and aperture. The SP-550UZ does something different:

```
                                [Live Preview Loop]
                                         |
                     +-------------------+-------------------+
                     |                                       |
                     v                                       v
          [AF Target Manager]                     [OSD Text Dispatcher]
             (0x401b28b0)                             (0x401b32f4)
                     |                                       |
                     v                                       v
          [AF Box Renderer]                       [Aperture, Shutter, Zoom]
             (0x401ad504)                             (0x401b3874)
                     |                                       |
                     +-------------------+-------------------+
                                         |
                                         v
                            [Composite Video Screen]
```

* **The Dual AF Rendering Systems:**
  The SP-550UZ actually uses two separate rendering systems for autofocus targets:
  1. **The Vector Box Engine (`0x401ad504`):** Draws rectangular colored framing boxes for tracking and macro modes.
  2. **The Glyph Icon Engine (`0x401ba8a4`):** Draws the stationary white/green center brackets by stamping two specialized glyph icons from the camera's asset table—left bracket (resource ID `"0239"`) and right bracket (resource ID `"0240"`), spaced exactly 50 pixels apart!
* **How Build 3b Solves This Definitively:**
  We installed hooks at the entrance of **both** engines (`0x401ad504` and `0x401ba8a4`). Whenever the `DISP` button sets the active view to Minimal mode, both routines immediately exit before drawing, leaving the moving picture 100% clean and free of brackets. Normal HUD and Grid/Histogram modes continue to display their brackets as designed.

---

## 6. Power Management, Inactivity & Auto-Sleep

To protect the CCD sensor and conserve AA batteries, factory firmware aggressively shuts down idle cameras after 3 minutes.

### The Four Stages of Camera Power
```
+---------------+     2.5 Min Idle     +---------------+     3.0 Min Idle     +---------------+
|    ACTIVE     | -------------------> |  SCREEN DIM   | -------------------> |    SLEEP      |
| (Full power,  |                      | (Backlight    |                      | (Sensors off, |
|  lens active) | <------------------- |  drops 50%)   | <------------------- |  lens out)    |
+---------------+      Button Press    +---------------+      Button Press    +---------------+
                                                                                      |
                                                                           15.0 Min   |
                                                                           Inactivity v
                                                                              +---------------+
                                                                              | FULL SHUTDOWN |
                                                                              | (Lens retracts|
                                                                              |  power cut)   |
                                                                              +---------------+
```

### How the Timer Works Architecturally
1. An RTOS timer task ticks every 100 milliseconds.
2. Inactivity counters in the Master Timer Block (`0x41f8ddac`) increment whenever no buttons are pressed.
3. When reaching 150 seconds (2.5 minutes), event `0xca0e` triggers LCD dimming.
4. When reaching 180 seconds (3.0 minutes), event `0xca0f` triggers sleep standby.

### How Sleep Inhibition Works in Hardware
Inside the timer setup engine (`0x40184d84`), the camera prepares a hardware timer configuration packet:
* `sp[4]` = Dimming threshold
* `sp[6]` = Sleep threshold
* `sp[7]` = Full power-off threshold

Before writing these values, the camera calls the **Sleep Permission Query** (`0x40184be0`):
* **When Video Out is connected (`destination > 1` via `0x4012fef4`):** The query sets `sp[6] = 0` (disabled), instructing the hardware timer never to count down or fire a sleep event.
* **When unplugged (internal LCD/EVF):** Standard 180-second threshold is written, allowing the camera to sleep normally after 3 minutes of battery use.

---

## 7. Storage, USB & The Firmware Update Mechanism

The SP-550UZ supports two independent flashing channels:

### 1. Memory Card Flashing (`/FIRMWARE/FIRMWARE.BIN`)
* An xD-Picture Card (or microSD-to-xD adapter) formatted as FAT16 is checked on boot.
* If a directory named `FIRMWARE` containing `FIRMWARE.BIN` is present when the user toggles the green **Playback (`>`)** button:
  1. The bootloader parses the header (`SANE321000000000`, `v155-77`).
  2. It prompts the user on screen: `FIRMWARE VERSION YES / NO`.
  3. If YES is pressed, it flashes SDRAM to ROM and displays `OK` on a blue screen.

### 2. USB PTP-over-SCSI Flashing (`sp550uz_usb_flash.py`)
* When connected to a computer in `Control/PC` mode, the camera communicates via vendor-specific SCSI commands over `/dev/sg0`.
* The updater streams the scrambled container in 63,488-byte chunks (`0x9119`) into SDRAM.
* The camera's bootloader verifies the 32-bit byte-sums of Section 1 and Section 2 (`0x9121`).
* Once verified, opcode `0x9123` executes the flash write and triggers an automatic reboot.

---

## 8. Summary of Reverse Engineered Firmware Subsystems

| Subsystem | Entry Address | Function & Responsibility |
| :--- | :--- | :--- |
| **OSD Dispatcher** | `0x401b32f4` | Evaluates 25 display modes via jump table `0x401b3324` |
| **AF Target Drawer** | `0x401b28b0` | Renders autofocus brackets and target boxes |
| **Preview Loop** | `0x40251934` | Continuous 30 fps viewfinder compositor |
| **Sleep Manager** | `0x40184be0` | Queries display destination and arms standby sleep timer |
| **PTP Dispatcher** | `0x403e7254` | Handles USB vendor-specific SCSI commands |
| **Card Flasher** | `0x40291694` | Validates FAT `/FIRMWARE/FIRMWARE.BIN` container |
