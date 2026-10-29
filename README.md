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

---

## 📦 What's in the Repository

```
olympus-sp550uz-re/
├── olympus_re/                     # Core Python Reverse Engineering Framework
│   ├── analysis/                   # Static analysis & ARM disassembly engine
│   │   ├── pipeline.py             # Multi-stage symbol & function discovery pipeline
│   │   ├── arm_disasm.py           # Pure-Python ARM946E-S instruction decoder
│   │   ├── jump_table.py           # Switch/case & jump table resolver (308 tables)
│   │   └── strings.py              # ASCII, Shift-JIS, and UTF-16 string extractor
│   ├── decompiler/                 # Decompiler Annotator Scripts
│   │   ├── ghidra_sp550uz_annotator.py  # Ghidra Python annotator (headless + GUI)
│   │   └── ida_sp550uz_annotator.py     # IDA Pro IDAPython annotator (headless + GUI)
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
│   ├── xref.html                   # 2.4 MB standalone, zero-dependency web explorer
│   └── xref/                       # Modular reference chapters:
│       ├── memory_map.md           # 8 TruePic III physical domains & bus architecture
│       ├── subsystems.md           # OSD engine, RTOS dispatcher, power management
│       ├── jump_tables.md          # Complete resolution of 25 OSD & 16 RTOS tables
│       ├── mmio_peripherals.md     # Register map for all 7 MMIO hardware blocks
│       └── ptp_scsi.md             # Reverse engineered PTP-over-SCSI protocol
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
    ├── test_tier1_features.py      # Functional tests for all 15 analysis feature groups
    ├── test_tier2_boundaries.py    # Boundary value analysis & domain limit tests
    ├── test_tier3_pairwise.py      # Combinatorial covering array tests
    ├── test_tier4_scenarios.py     # Real-world reverse engineering workflow tests
    ├── validate_v1_analysis.py     # Acceptance criterion V1 validator
    ├── validate_v2_decompiler.py   # Acceptance criterion V2 validator
    └── validate_v3_docs.py         # Acceptance criterion V3 validator
```

---

## 🚀 How to Utilize

### 1. Requirements

- Python 3.8 or higher.
- Standard library only for analysis and decompiler scripts (no external pip dependencies required).
- Optional: `jinja2` for running the documentation generator templates (`pip install jinja2`).
- Decompilers (optional): Ghidra 10.x+ or IDA Pro 7.x/8.x/9.x.

---

### 2. Running the Static Analysis Pipeline

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

### 3. Annotating in Ghidra

The annotator script [`olympus_re/decompiler/ghidra_sp550uz_annotator.py`](olympus_re/decompiler/ghidra_sp550uz_annotator.py) maps the complete TruePic III memory map, sets the ARM946E-S processor context, labels all 55k+ symbols, and formats jump tables.

#### Headless Mode (Automated / CI/CD):
```bash
analyzeHeadless /path/to/ghidra_projects OlympusProject \
  -import Resources/firmware/sp550uz_v1.1_section1_code.bin \
  -processor ARM:LE:32:v5t \
  -baseAddr 0x40000000 \
  -postScript olympus_re/decompiler/ghidra_sp550uz_annotator.py
```

#### GUI Mode:
1. Open Ghidra and import `Resources/firmware/sp550uz_v1.1_section1_code.bin`.
2. Select Language: **ARM:LE:32:v5t** (ARM v5t, Little-Endian).
3. Set Base Address to **`0x40000000`**.
4. Open the binary in the CodeBrowser (let initial auto-analysis run).
5. Open the **Script Manager** (`Window` &rarr; `Script Manager`).
6. Click the script directory icon and add the path: `olympus-sp550uz-re/olympus_re/decompiler/`.
7. Locate `ghidra_sp550uz_annotator.py` and click **Run**.
8. The script will configure 8 memory blocks, label 55,155 symbols, and resolve all jump tables.

---

### 4. Annotating in IDA Pro

The annotator script [`olympus_re/decompiler/ida_sp550uz_annotator.py`](olympus_re/decompiler/ida_sp550uz_annotator.py) sets up IDA segments, labels functions, types data references, and constructs switch tables.

#### Headless Mode (Automated / CLI):
```bash
# Linux / macOS (IDA Pro 64-bit)
idal64 -A -S"olympus_re/decompiler/ida_sp550uz_annotator.py" \
  Resources/firmware/sp550uz_v1.1_section1_code.bin

# Windows
ida64.exe -A -S"olympus_re\decompiler\ida_sp550uz_annotator.py" \
  Resources\firmware\sp550uz_v1.1_section1_code.bin
```

#### GUI Mode:
1. Open IDA Pro and load `Resources/firmware/sp550uz_v1.1_section1_code.bin`.
2. Select Processor: **ARM Little-endian [ARM]**.
3. In the Disassembly Memory Organization dialog:
   - Set **ROM start address** to `0x40000000`.
   - Set **Loading address** to `0x40000000`.
4. Wait for initial auto-analysis to finish (`AU: idle`).
5. Run the script: press **Alt + F7** (or `File` &rarr; `Script file...`) and select `olympus_re/decompiler/ida_sp550uz_annotator.py`.
6. All 8 TruePic III segments, functions, and symbols will be populated.

---

### 5. Exploring the Interactive Cross-Reference Documentation

- **Standalone HTML Explorer:** Open [`docs/xref.html`](docs/xref.html) directly in any modern browser.
  - Zero server or internet required (100% client-side application).
  - Instant symbol search across 55,155 entries with filtering by memory domain, symbol type (Function, Data, String, Literal), and subsystem.
  - Interactive caller/callee cross-reference graph viewer.
  - Visual memory map navigator.
  - Jump table inspector with complete branch target listings.
- **Markdown Reference:** Browse [`docs/xref/`](docs/xref/) directly on GitHub:
  - [`memory_map.md`](docs/xref/memory_map.md): TruePic III memory layout and hardware bus definitions.
  - [`subsystems.md`](docs/xref/subsystems.md): Reverse engineering analysis of the OSD display pipeline, power management, and RTOS executive.
  - [`jump_tables.md`](docs/xref/jump_tables.md): Complete breakdown of the 25-entry OSD dispatcher and 16-entry RTOS event table.
  - [`mmio_peripherals.md`](docs/xref/mmio_peripherals.md): Base addresses and registers for the 7 TruePic III peripheral controllers.
  - [`ptp_scsi.md`](docs/xref/ptp_scsi.md): PTP-over-SCSI vendor protocol specifications and command structures.

To regenerate the documentation from templates with strict link validation:
```bash
python3 -m olympus_re.cli --analyze --doc all --docs-dir docs --strict-links
```

---

### 6. Unpacking & Repacking Firmware Containers

Olympus firmware updates use a scrambled container format (`SAN_E_*.BIN`) protected by a 16-byte lane permutation (`PERM16`), `XOR 0xFF` obfuscation, and 32-bit unsigned byte sums:

#### Unpacking Stock Firmware:
```bash
python3 Resources/scripts/sp550uz_fw_unpack.py \
  Resources/firmware/SAN_E_321_1100_0000_0000.BIN
```
*Outputs `SAN_E_321_1100_unscrambled.bin`, `sp550uz_v1.1_section1_code.bin` (3,952,192 bytes), and `sp550uz_v1.1_section2_ndata.bin` (4,589,568 bytes).*

#### Repacking Firmware:
```bash
python3 Resources/scripts/sp550uz_fw_pack.py \
  section1.bin section2.bin repacked_container.bin
```
*Calculates Section 1 and Section 2 byte sums, formats the 96-byte ASCII header (`SANE321000000000`, `v155-77`), applies `INV_PERM16` scrambling, and generates a bit-for-bit valid update container.*

---

### 7. Running the Test Suite

The repository includes a comprehensive 214-test suite with 100% pass rate:

```bash
# Run the entire test suite (214 tests across 4 tiers)
python3 -m unittest discover tests

# Run the 3 independent acceptance criterion validators
python3 tests/validate_v1_analysis.py    # Symbol & function static analysis validation
python3 tests/validate_v2_decompiler.py  # Ghidra & IDA script quality validation
python3 tests/validate_v3_docs.py        # Documentation link & memory domain validation
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
