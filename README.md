# Olympus SP-550UZ Firmware Reverse Engineering Framework

A comprehensive, production-grade reverse engineering framework and documentation suite for the **Olympus SP-550UZ** (`07b4:0109`) digital camera and its underlying **Sanyo SG155 / Olympus TruePic III** system-on-chip.

This repository provides an automated static analysis pipeline, decompiler annotation tooling for **Ghidra** and **IDA Pro**, interactive searchable cross-reference documentation, container unpacking and repacking utilities, and a rigorous 214-test verification suite.

---

## 🎯 Target Hardware & Architecture

| Parameter | Specification |
| :--- | :--- |
| **Camera Model** | Olympus SP-550UZ (Ultra Zoom) |
| **USB Identity** | `07b4:0109` Olympus Optical Co., Ltd |
| **Firmware Revision** | v1.1 (`SAN_E_321_1100_0000_0000.BIN`, build string `v155-77`) |
| **Processor Platform** | Sanyo SG155 / Olympus TruePic III |
| **CPU Core** | ARM946E-S (ARMv5TE architecture, Little-Endian) |
| **Clock Frequency** | 150 MHz core, 48 MHz peripheral bus |
| **Cache Architecture** | Harvard: 8 KB Instruction Cache, 8 KB Data Cache |
| **System Memory** | 32 MB SDRAM (`0x40000000`–`0x41FFFFFF`) |
| **Execution Base** | Section 1 (ARM code) loaded at `0x40000000` (Reset vector jumps to `0x40000800`) |
| **Operating System** | Proprietary event-driven Real-Time Operating System (RTOS) |

### Memory Map (8 Physical Domains)

```
0x00000000 +---------------------------------------+
           | Boot ROM / Vector Table Mirror        | (1 MB)
0x40000000 +---------------------------------------+
           | Section 1: Main Code & Static Tables  | (3.95 MB executable)
           | Section 2: GUI Bitmaps, Fonts, Menus  | (4.38 MB resource data)
0x41800000 +---------------------------------------+
           | Dynamic SDRAM: Buffers, Framepools    | (8 MB working RAM)
0x41F80000 +---------------------------------------+
           | RTOS Task Stacks & Global State       | (512 KB state & IPC)
0xE0000000 +---------------------------------------+
           | TruePic III MMIO Hardware Peripherals |
           | - 0xE0000000: Memory Controller       |
           | - 0xE0040000: Interrupt Controller    |
           | - 0xE0080000: Hardware Timers         |
           | - 0xE0100000: Dual UART & Serial Bus  |
           | - 0xE0140000: General-Purpose I/O     |
           | - 0xE0200000: DMA Controller Engines  |
           | - 0xE0400000: Image Signal Processor  |
           | - 0xE0600000: Video DAC & Compositor  |
           | - 0xE0800000: Hardware JPEG Scaler    |
0xE081FFFF +---------------------------------------+
```

### Physical Hardware Teardown & Silicon Bill of Materials

Physical teardown and microscopic inspection of the SP-550UZ main board identified the complete silicon Bill of Materials:

| IC Component | Manufacturer & Part Number | Package | Hardware Role & Firmware Interconnect |
| :--- | :--- | :--- | :--- |
| **Main Processor / SoC** | Sanyo EV1MSS11 | BGA | Olympus TruePic III / Sanyo Coach platform; ARM946E-S @ 150 MHz core, 48 MHz bus; executes Section 1 code at `0x40000000` |
| **Flash & Memory (MCP)** | Samsung K5R Multi-Chip Package | FBGA | Stacks OneNAND Flash (47MB storage via BML/STL) + 32MB Mobile SDRAM (`0x40000000`–`0x41FFFFFF`) |
| **Power Management (PMIC)** | ROHM BD9739KN | QFN / Side A | 7-channel switching regulator supplying core VDD, SDRAM IO, CCD AFE, motor drive, and standby sleep rail |
| **Motor Driver** | Sanyo LV8086 | SSOP / Side B | Dedicated dual stepper/DC motor driver for 18x optical zoom barrel traversal and autofocus lens positioning |
| **EVF Micro-Display Controller** | Kopin KCD CyberDisplay | TQFP / Side B | Drives the electronic viewfinder micro-display; selected via video destination query `0x4012fef4` code `1` |
| **Calibration EEPROM** | 2316GO (24C16) | 8-pin SOP / Side B | 16 Kbit (2 KB) I2C serial EEPROM storing factory lens calibration, CCD defect maps, and camera serial number |

*For complete pinout mappings, PCB Side A/B component placement diagrams, and power rail distribution, see the [Physical Hardware Teardown Guide](docs/hardware/teardown.md).*

---

## 📦 What's in the Repository

```
olympus-sp550uz-re/
├── olympus_re/                     # Core Python Reverse Engineering Framework
│   ├── analysis/                   # Static analysis & ARM disassembly engine
│   │   ├── disassembler.py         # Capstone ARMv5TE streaming disassembly engine
│   │   ├── function_detector.py    # Prologue, BL call target, and pointer detector
│   │   ├── jump_table_analyzer.py  # Switch/case & jump table resolver (308 tables)
│   │   ├── literal_pool.py         # PC-relative literal pool extractor & classifier
│   │   ├── pipeline.py             # Multi-stage symbol & function discovery pipeline
│   │   └── string_extractor.py     # ASCII, Shift-JIS, and UTF-16 string extractor
│   ├── models/                     # Data Models & Domain Architecture
│   │   ├── memory_map.py           # TruePic III memory domains & boundary validator
│   │   └── symbols.py              # Symbol, Function, JumpTable, and MMIO dataclasses
│   ├── decompiler/                 # Decompiler Annotator Scripts & Mock Harness
│   │   ├── ghidra_sp550uz_annotator.py  # Ghidra Python annotator (headless + GUI)
│   │   ├── ida_sp550uz_annotator.py     # IDA Pro IDAPython annotator (headless + GUI)
│   │   └── mock_environment.py          # Offline test harness mocking Ghidra & IDA APIs
│   ├── docgen/                     # Documentation Generators
│   │   ├── generator.py            # Generates HTML single-page app & Markdown
│   │   ├── link_validator.py       # Strict zero-dead-link & memory domain validator
│   │   └── templates/              # Jinja2 documentation templates
│   └── cli.py                      # Unified CLI interface (`python3 -m olympus_re.cli`)
│
├── output/                         # Reverse Engineering Analysis Deliverables
│   ├── symbols.json                # 55,155 symbols (functions, data, literal pools)
│   ├── symbols.csv                 # Tabular export for spreadsheet / external tools
│   ├── jump_tables.json            # 308 resolved jump tables and targets
│   └── xref/                       # Generated Markdown cross-reference reference
│
├── docs/                           # Interactive Cross-Reference Documentation
│   ├── hardware/                   # Physical Hardware Documentation
│   │   └── teardown.md             # PCB teardown, silicon BOM, and pinout architecture
│   ├── xref.html                   # 2.4 MB standalone, zero-dependency web explorer
│   └── xref/                       # Modular reference chapters:
│       ├── index.md                # Platform summary and quick navigation index
│       ├── memory_map.md           # 8 TruePic III physical domains & silicon architecture
│       ├── subsystems.md           # OSD engine, RTOS dispatcher, power management
│       └── jump_tables.md          # Complete resolution of 25 OSD & 16 RTOS tables
│
├── Resources/
│   ├── firmware/                   # Firmware Binaries & Containers
│   │   ├── SAN_E_321_1100_0000_0000.BIN   # Official scrambled v1.1 stock firmware
│   │   ├── SAN_E_321_1100_unscrambled.bin # Unscrambled container (PERM16 + XOR 0xFF)
│   │   ├── sp550uz_v1.1_section1_code.bin # Extracted Section 1 (Code, base 0x40000000)
│   │   └── sp550uz_v1.1_section2_ndata.bin# Extracted Section 2 (GUI resources)
│   ├── scripts/                    # Hardware Probing & Container Utilities
│   │   ├── sp550uz_fw_unpack.py    # De-scrambles container & splits sections
│   │   ├── sp550uz_fw_pack.py      # Roundtrip bit-for-bit repacker with byte sums
│   │   ├── sp550uz_scsi_ptp.py     # Linux SG_IO PTP-over-SCSI communication client
│   │   ├── oly_fw_server.py        # OM Digital server client (28-bit unmasked DES)
│   │   └── sp550uz_usb_flash.py    # USB PTP firmware flasher & memory validator
│   └── notes/                      # In-Depth Technical References & Research Logs
│       ├── firmware_architecture_reference.md  # Deep technical architecture manual
│       ├── plain_language_firmware_guide.md    # Conceptual guide to camera subsystems
│       └── reverse_engineering_log.md          # Chronological reverse engineering log
│
└── tests/                          # 214-Test Verification Suite
    ├── support.py                  # Test harness constants, memory map definitions, mocks
    ├── test_tier1_features.py      # Functional tests for all 15 analysis feature groups
    ├── test_tier2_boundaries.py    # Boundary value analysis & domain limit tests
    ├── test_tier3_pairwise.py      # Combinatorial covering array tests
    ├── test_tier4_scenarios.py     # Real-world reverse engineering workflow tests
    ├── test_adversarial_m3_challenger.py       # Adversarial link and docgen parity tests
    ├── test_adversarial_m3_iter2_challenger.py # XSS escaping and navigation resilience
    ├── validate_v1_analysis.py     # Acceptance criterion V1 validator
    ├── validate_v2_decompiler.py   # Acceptance criterion V2 validator
    └── validate_v3_docs.py         # Acceptance criterion V3 validator
```

---

## 🚀 How to Utilize

### 1. Requirements & Dependencies

- **Python**: Python 3.8 or higher.
- **Framework Dependencies**:
  ```bash
  pip install capstone jinja2
  ```
  - `capstone`: ARM disassembly engine powering `olympus_re.analysis.disassembler`.
  - `jinja2`: Template engine powering `olympus_re.docgen.generator`.
- **Decompilers (Optional)**:
  - Ghidra 10.x+ or IDA Pro 7.x/8.x/9.x.
  - *Offline verification*: Both decompiler annotator scripts can be tested and verified offline without third-party decompiler tools via `olympus_re/decompiler/mock_environment.py`.

---

### Step 1: Unpacking Stock Firmware Containers

Olympus firmware updates use an obfuscated container format (`SAN_E_*.BIN`) combining a 16-byte lane permutation (`PERM16`), bitwise `XOR 0xFF`, and 32-bit unsigned sums. Extract the stock firmware:

```bash
python3 Resources/scripts/sp550uz_fw_unpack.py \
  Resources/firmware/SAN_E_321_1100_0000_0000.BIN
```
*Outputs `SAN_E_321_1100_unscrambled.bin`, `sp550uz_v1.1_section1_code.bin` (Section 1 ARM code, 4,149,416 bytes), and `sp550uz_v1.1_section2_ndata.bin` (Section 2 GUI resources, 4,589,568 bytes).*

---

### Step 2: Running the Static Analysis Pipeline

The framework provides an automated symbol and function discovery pipeline with pure-Python ARM disassembly:

```bash
# Run full analysis on stock Section 1 firmware
python3 -m olympus_re.cli --analyze

# Specify custom inputs, formats, and outputs
python3 -m olympus_re.cli \
  --input Resources/firmware/sp550uz_v1.1_section1_code.bin \
  --data-input Resources/firmware/sp550uz_v1.1_section2_ndata.bin \
  --export-format json,csv \
  --output-dir output
```

**What the pipeline discovers:**
- **55,155 total symbols** cataloged with 100% address validity across TruePic III domains.
- **11,724 distinct function entry points** discovered via prologue patterns (`push {..., lr}`, Sanyo leaf `push {r8, sb}`).
- **308 jump tables** resolved, including the 25-entry master OSD display engine (`0x401b3324`) and the 16-entry RTOS event dispatcher (`0x4019e324`).
- **Literal pool and cross-reference graph** linking callers and callees throughout the 4 MB code binary.

---

### Step 3: Annotating in Ghidra & IDA Pro

The framework includes dedicated decompiler annotator scripts for **Ghidra** and **IDA Pro** that map the 8 TruePic III memory segments, set ARM946E-S processor context, import 55,155 labels, and configure jump tables.

#### A. Headless Ghidra Annotation:
```bash
analyzeHeadless /path/to/ghidra_projects OlympusProject \
  -import Resources/firmware/sp550uz_v1.1_section1_code.bin \
  -processor ARM:LE:32:v5t \
  -baseAddr 0x40000000 \
  -postScript olympus_re/decompiler/ghidra_sp550uz_annotator.py
```

#### B. Headless IDA Pro Annotation:
```bash
# Linux / macOS (IDA Pro 64-bit)
idal64 -A -S"olympus_re/decompiler/ida_sp550uz_annotator.py" \
  Resources/firmware/sp550uz_v1.1_section1_code.bin

# Windows
ida64.exe -A -S"olympus_re\decompiler\ida_sp550uz_annotator.py" \
  Resources\firmware\sp550uz_v1.1_section1_code.bin
```

#### C. Offline Mock Verification (No Decompiler Required):
Both scripts can be verified without proprietary decompiler installations using the built-in offline mocking harness:
```bash
python3 tests/validate_v2_decompiler.py
```
*Emulates `FlatProgramAPI` and `idaapi`/`idc` environments, validating AST parsing, memory segment coverage (`0x40000000` to `0xE081FFFF`), and annotation execution.*

---

### Step 4: Exploring Interactive Cross-Reference Documentation

- **Standalone HTML Web Explorer:** Open [`docs/xref.html`](docs/xref.html) directly in any modern web browser.
  - 100% client-side application (zero web server or internet access required).
  - Instant symbol search across 55,155 entries with filtering by memory domain, symbol type (Function, Data, String, Literal), and subsystem.
  - Interactive caller/callee cross-reference graph viewer.
  - Visual TruePic III memory map navigator.
  - Jump table inspector with complete branch target listings.
- **Markdown Reference Chapters:** Browse [`docs/xref/`](docs/xref/) directly on GitHub:
  - [`index.md`](docs/xref/index.md): Reference platform overview, platform summary, and quick navigation index.
  - [`memory_map.md`](docs/xref/memory_map.md): TruePic III memory layout, 8 physical domains, hardware bus definitions, and physical silicon BOM.
  - [`subsystems.md`](docs/xref/subsystems.md): Reverse engineering analysis of the OSD display pipeline, power management, RTOS executive, and storage layer.
  - [`jump_tables.md`](docs/xref/jump_tables.md): Complete breakdown of the 25-entry OSD dispatcher and 16-entry RTOS event table.
  - [`memory_map.md#mmio-peripherals`](docs/xref/memory_map.md#mmio-peripherals): Base addresses and registers for all 7 TruePic III peripheral controllers.
  - [`subsystems.md#ptp-over-scsi`](docs/xref/subsystems.md#ptp-over-scsi): PTP-over-SCSI vendor protocol specifications, CDB structures, and firmware flashing path.
  - [`teardown.md`](docs/hardware/teardown.md): Detailed physical hardware teardown guide, PCB Side A/B layout, and silicon Bill of Materials.

To regenerate documentation from Jinja2 templates with strict link and memory address validation:
```bash
python3 -m olympus_re.cli --docgen --strict-links
```

---

### Step 5: Repacking Firmware Containers with Verified Checksums

The repacker utility formats official 96-byte ASCII headers, recalculates 32-bit unsigned byte sums, applies `INV_PERM16` lane permutation, and scrambles container bytes via `XOR 0xFF`:

```bash
# Verify bit-for-bit roundtrip repacking against the official Olympus v1.1 firmware
python3 Resources/scripts/sp550uz_fw_pack.py --test

# Repack custom section binaries into a deployable container
python3 Resources/scripts/sp550uz_fw_pack.py \
  section1.bin section2.bin repacked_container.bin
```

---

### Step 6: Running the Comprehensive Verification Suite

The repository includes a rigorous 214-test verification suite and 3 independent acceptance criterion validators:

```bash
# Run the entire test suite (214 tests across all tiers)
python3 -m unittest discover tests -v

# Run the 3 independent acceptance criterion validators
python3 tests/validate_v1_analysis.py    # Symbol & function static analysis validation
python3 tests/validate_v2_decompiler.py  # Ghidra & IDA script quality validation
python3 tests/validate_v3_docs.py        # Documentation link & memory domain validation

# Run bit-for-bit firmware repacker roundtrip test
python3 Resources/scripts/sp550uz_fw_pack.py --test
```

---

## 🔬 Key Reverse Engineering Discoveries

1. **The Olympus DES Decryption Bug:** Olympus firmware update servers use DES encryption with an unmasked 28-bit key derived from a seed. A critical bug in Olympus's OEM C code (`OWSetup.exe`) discards key bits, enabling complete decryption of camera communication sessions (emulated in [`oly_fw_server.py`](Resources/scripts/oly_fw_server.py)).
2. **Container Obfuscation (`PERM16`):** Firmware containers are obfuscated using a fixed 16-byte lane permutation `[2, 0, 3, 1, 5, 7, 4, 6, 11, 10, 9, 8, 14, 12, 13, 15]` combined with `XOR 0xFF`.
3. **Master OSD Display Dispatcher (`0x401b32f4`):** The camera handles on-screen display via a 25-entry jump table at `0x401b3324` bounded by `cmp r2, #0x18`. Mode 0 renders full shooting HUD, Mode 1 renders composition grid and luminance histogram, and Mode 4/15–19 branch directly to the clean epilogue `0x401b3864`.
4. **Hardware Sleep Timer Inhibit (`0x40184be0`):** The sleep timer setup engine (`0x40184d84`) queries video destination (`0x4012fef4`). When a composite video cable is attached (destination code `> 1`), line `0x40184e48` writes `mov r1, #0`, setting the countdown sleep threshold packet to `0` (`sp[6]=0`) to inhibit hardware sleep.
5. **Storage-Based Firmware Update Detection (`0x401efac8`):** Switching to Playback mode with an xD card containing `/FIRMWARE/FIRMWARE.BIN` causes the camera to detect the FAT 8.3 filename string at `0x403c59d8` and invoke the ROM flash commit routine at `0x40291694`.
6. **PTP-over-SCSI Vendor Protocol (`0x403e7254`):** In `Control/PC` mode, the camera implements vendor PTP opcodes encapsulated in SCSI CDB commands: `0x100C` (SendObjectInfo), `0x9119` (SendFirmwareChunk, 63,488 bytes), `0x9121` (FirmwareCheck RAM byte-sum verification), and `0x9123` (UpdateInitiate flash commit).

---

## ⚖️ License & Responsible Research

This repository is published strictly for educational, archival, and hardware interoperability reverse engineering research. All firmware analysis, symbol maps, and scripts are developed via clean-room inspection of publicly distributed firmware updates and live hardware interrogation.
