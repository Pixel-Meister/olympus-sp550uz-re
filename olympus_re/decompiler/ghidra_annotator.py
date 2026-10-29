"""
ghidra_sp550uz_annotator.py - Ghidra Decompiler Annotation Tool for Olympus SP-550UZ
===================================================================================
Automated Ghidra script for TruePic III (Sanyo SG155 platform / ARMv5TE) firmware analysis.
Maps memory domains, imports reverse-engineered symbols, labels function entry points,
annotates hardware MMIO registers, Blackboard state variables, and generates rich plate
comments for major subsystem handlers (OSD engine, power management, RTOS event dispatcher,
JPEG/ISP pipeline).

Platform Architecture:
- Target: Olympus SP-550UZ Digital Camera
- Processor: Sanyo SG155 / Olympus TruePic III
- Core: ARM926EJ-S (ARMv5TE architecture, 32-bit Little-Endian)
- Section 1 Code Base: 0x40000000 (Cached SDRAM)
- Section 2 Data Base: 0x403F5108 (Cached NDATA)
- Uncached SDRAM Base: 0x41F00000
- System Blackboard Base: 0x41F80000
- Task Stacks Base: 0x41FA0000
- MMIO SDRAM Controller: 0x80410000
- MMIO DMA & NAND Controller: 0xC04C0000
- MMIO Peripherals & ISP: 0xE0010000
- TruePic III Memory Ceiling: 0xE081FFFF

Interactive GUI Usage (Ghidra Script Manager):
----------------------------------------------
1. Launch Ghidra GUI and open the CodeBrowser tool with the unpacked firmware binary
   loaded at base address 0x40000000 (ARM:LE:32:v5t).
2. Open the Script Manager: 'Window' -> 'Script Manager'.
3. Click 'Script Directories' icon and add this directory:
   '<project_root>/olympus_re/decompiler'
4. Filter by 'sp550uz' or locate 'ghidra_sp550uz_annotator.py'.
5. Click 'Run Script' (green play button).
6. When prompted by 'askFile', select 'output/symbols.json' (or accept default).

Headless Execution Instructions (analyzeHeadless):
--------------------------------------------------
To execute headlessly in automated CI/CD or batch reverse-engineering pipelines:
$GHIDRA_HOME/support/analyzeHeadless <project_dir> <project_name> \\
    -import Resources/firmware/sp550uz_v1.1_section1_code.bin \\
    -processor ARM:LE:32:v5t \\
    -baseAddr 0x40000000 \\
    -postScript olympus_re/decompiler/ghidra_sp550uz_annotator.py \\
    -scriptPath olympus_re/decompiler \\
    -deleteProject

PyGhidra Usage:
---------------
python3 -m pyghidra <project_dir> <project_name> \\
    --post-script olympus_re/decompiler/ghidra_sp550uz_annotator.py
"""

import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# ==============================================================================
# Authoritative TruePic III Memory Map Domain Specifications
# ==============================================================================
# 0x40000000: Section 1 SDRAM base
# 0x403f5108: Section 2 NDATA base
# 0x41f00000: Uncached SDRAM base
# 0x41f80000: Blackboard base
# 0x41fa0000: Stacks base
# 0x80410000: MMIO SDRAM base
# 0xc04c0000: MMIO DMA/NAND base
# 0xe0010000: MMIO Peripherals base
# 0xe081ffff: TruePic III ceiling

MEMORY_SEGMENTS: List[Dict[str, Any]] = [
    {
        "name": "SEC1_SDRAM",
        "start": 0x40000000,
        "end": 0x403F50E7,
        "length": 0x403F50E7 - 0x40000000 + 1,  # 4,149,416 bytes
        "r": True,
        "w": False,
        "x": True,
        "desc": "Section 1 SDRAM (Cached Executable Code)",
    },
    {
        "name": "SEC2_NDATA",
        "start": 0x403F5108,
        "end": 0x40855967,
        "length": 0x40855967 - 0x403F5108 + 1,  # 4,589,568 bytes
        "r": True,
        "w": False,
        "x": False,
        "desc": "Section 2 NDATA (Flash Read-Only Data Tables)",
    },
    {
        "name": "UNCACHED_RAM",
        "start": 0x41F00000,
        "end": 0x41F7FFFF,
        "length": 0x41F7FFFF - 0x41F00000 + 1,  # 524,288 bytes (512 KB)
        "r": True,
        "w": True,
        "x": False,
        "desc": "Uncached SDRAM Buffers (Video & DMA)",
    },
    {
        "name": "BLACKBOARD",
        "start": 0x41F80000,
        "end": 0x41F9FFFF,
        "length": 0x41F9FFFF - 0x41F80000 + 1,  # 131,072 bytes (128 KB)
        "r": True,
        "w": True,
        "x": False,
        "desc": "System State Blackboard (Global State)",
    },
    {
        "name": "STACKS",
        "start": 0x41FA0000,
        "end": 0x41FD0000,
        "length": 0x41FD0000 - 0x41FA0000 + 1,  # 196,609 bytes (~192 KB)
        "r": True,
        "w": True,
        "x": False,
        "desc": "Banked Task Stacks (RTOS Stacks)",
    },
    {
        "name": "MMIO_SDRAM",
        "start": 0x80410000,
        "end": 0x8041FFFF,
        "length": 0x8041FFFF - 0x80410000 + 1,  # 65,536 bytes (64 KB)
        "r": True,
        "w": True,
        "x": False,
        "desc": "MMIO SDRAM Controller & Timings",
    },
    {
        "name": "MMIO_DMA_NAND",
        "start": 0xC04C0000,
        "end": 0xC04CFFFF,
        "length": 0xC04CFFFF - 0xC04C0000 + 1,  # 65,536 bytes (64 KB)
        "r": True,
        "w": True,
        "x": False,
        "desc": "MMIO DMA & NAND Flash Controller",
    },
    {
        "name": "MMIO_PERIPH",
        "start": 0xE0010000,
        "end": 0xE081FFFF,
        "length": 0xE081FFFF - 0xE0010000 + 1,  # 8,454,144 bytes
        "r": True,
        "w": True,
        "x": False,
        "desc": "MMIO Timers, Interrupt, Video DAC, Keypad, ISP",
    },
]

# Recognizable major subsystems requiring plate comments
SUBSYSTEM_PLATE_TARGETS = {
    "OSD",
    "Power",
    "RTOS",
    "Sensor/Capture",
    "Storage/NAND",
    "JPEG",
    "ISP",
    "SystemFunction",
    "System",
    "PTP/USB",
    "Input",
    "Flash/Strobe",
    "Playback",
}

# Known architectural dispatchers requiring high-priority plate comments
KNOWN_DISPATCHER_METADATA = {
    0x401B3324: {
        "name": "OSD_DisplayModeJumpTable",
        "subsystem": "OSD",
        "description": "OSD Display Mode Jump Table (25 Modes: Normal HUD, Assist Grid, Minimal, Clean Epilogue)",
    },
    0x4019E324: {
        "name": "RTOS_EventJumpTable",
        "subsystem": "RTOS",
        "description": "RTOS System Event Dispatcher Jump Table (16 Events: Sleep, Idle, LCD Dimming, Power)",
    },
}


def log(msg: str) -> None:
    """Universal logger supporting both Ghidra println and Python print."""
    if "println" in globals() and callable(globals()["println"]):
        try:
            globals()["println"](msg)
            return
        except Exception:
            pass
    print(msg)


def setup_memory_blocks() -> int:
    """Create all TruePic III memory blocks via Ghidra FlatProgramAPI createMemoryBlock."""
    log("[*] Setting up TruePic III memory domain blocks...")
    created_count = 0

    to_addr_fn = globals().get("toAddr")
    create_mem_block_fn = globals().get("createMemoryBlock")

    for seg in MEMORY_SEGMENTS:
        name = seg["name"]
        start = seg["start"]
        length = seg["length"]
        r = seg["r"]
        w = seg["w"]
        x = seg["x"]

        addr_obj = to_addr_fn(start) if callable(to_addr_fn) else start

        # Check if block already exists when currentProgram is available
        cur_prog = globals().get("currentProgram")
        if cur_prog is not None:
            try:
                mem = cur_prog.getMemory()
                if mem.getBlock(addr_obj) is not None or mem.getBlock(name) is not None:
                    log(f"  - Block {name} already exists, skipping")
                    created_count += 1
                    continue
            except Exception:
                pass

        if callable(create_mem_block_fn):
            try:
                create_mem_block_fn(name, addr_obj, length, r, w, x)
                created_count += 1
                log(f"  + Created block: {name} [0x{start:08X}..0x{seg['end']:08X}] ({seg['desc']})")
            except Exception as exc:
                log(f"  ! Warning creating block {name}: {exc}")

    log(f"[*] Memory block setup complete: {created_count}/{len(MEMORY_SEGMENTS)} blocks active.")
    return created_count


def locate_symbols_file() -> Optional[Path]:
    """Locate symbols.json via interactive askFile or filesystem fallback."""
    # 1. Try interactive askFile if available
    ask_file_fn = globals().get("askFile")
    if callable(ask_file_fn):
        try:
            selected = ask_file_fn("Select symbols.json file", "Open")
            if selected:
                p = Path(str(selected))
                if p.exists() and p.is_file():
                    log(f"[*] Loaded symbols file from askFile: {p}")
                    return p
        except Exception as exc:
            log(f"[*] askFile bypassed/failed: {exc}")

    # 2. Check canonical filesystem paths
    candidates = [
        Path("output/symbols.json"),
        Path("../output/symbols.json"),
        Path("../../output/symbols.json"),
        Path(__file__).resolve().parent.parent.parent / "output" / "symbols.json",
        Path.cwd() / "output" / "symbols.json",
        Path("symbols.json"),
    ]

    for cand in candidates:
        try:
            if cand.exists() and cand.is_file():
                log(f"[*] Found symbols file at: {cand}")
                return cand
        except Exception:
            pass

    log("[!] Warning: symbols.json not found in default search paths.")
    return None


def format_subsystem_plate(sym: Dict[str, Any]) -> str:
    """Format rich multi-line plate comment for subsystem handlers and jump tables."""
    name = sym.get("name", "Unknown")
    addr = sym.get("address", 0)
    subsystem = sym.get("subsystem", "General")
    domain = sym.get("domain", "Unknown")
    stype = sym.get("type", "function")
    metadata = sym.get("metadata") or {}

    # Check for known dispatcher metadata override
    dispatcher_info = KNOWN_DISPATCHER_METADATA.get(addr)
    desc_override = dispatcher_info["description"] if dispatcher_info else None
    if dispatcher_info and subsystem == "General":
        subsystem = dispatcher_info["subsystem"]

    lines = [
        "==================================================================",
        f"Olympus SP-550UZ Subsystem Handler: {name}",
        "==================================================================",
        f"Subsystem:       {subsystem}",
        f"Address:         0x{addr:08X}",
        f"Symbol Type:     {stype}",
        f"Memory Domain:   {domain}",
    ]

    if desc_override:
        lines.append(f"Description:     {desc_override}")

    methods = metadata.get("detection_methods") or []
    if methods:
        lines.append(f"Detection:       {', '.join(methods)}")

    prologue = metadata.get("prologue_type")
    if prologue:
        lines.append(f"Prologue:        {prologue}")

    bounds = metadata.get("bounds")
    if bounds:
        lines.append(f"Jump Bounds:     {bounds}")

    def_target = metadata.get("default_target")
    if def_target:
        lines.append(f"Default Target:  0x{def_target:08X}")

    callers = metadata.get("callers") or []
    if callers:
        c_str = ", ".join(f"0x{c:08X}" for c in callers[:6])
        if len(callers) > 6:
            c_str += f" (+{len(callers)-6} more)"
        lines.append(f"Callers ({len(callers)}):    {c_str}")

    targets = metadata.get("call_targets") or []
    if targets:
        t_str = ", ".join(f"0x{t:08X}" for t in targets[:6])
        if len(targets) > 6:
            t_str += f" (+{len(targets)-6} more)"
        lines.append(f"Callees ({len(targets)}):    {t_str}")

    lines.append("==================================================================")
    return "\n".join(lines)


def annotate_symbols(symbols_path: Path) -> int:
    """Import symbols and annotate Ghidra program."""
    log(f"[*] Parsing symbols from {symbols_path}...")
    try:
        with open(symbols_path, "r", encoding="utf-8") as f:
            symbols = json.load(f)
    except Exception as exc:
        log(f"[-] Error loading JSON from {symbols_path}: {exc}")
        return 0

    if not isinstance(symbols, list):
        log("[-] Error: symbols database root must be a list")
        return 0

    log(f"[*] Ingesting {len(symbols)} symbol records into Ghidra database...")

    to_addr_fn = globals().get("toAddr")
    create_label_fn = globals().get("createLabel")
    set_plate_fn = globals().get("setPlateComment")
    set_eol_fn = globals().get("setEolComment")
    set_pre_fn = globals().get("setPreComment")

    label_count = 0
    plate_count = 0
    eol_count = 0

    for sym in symbols:
        if not isinstance(sym, dict):
            continue

        addr_val = sym.get("address")
        name = sym.get("name")
        if addr_val is None or not name:
            continue

        stype = sym.get("type", "function")
        subsystem = sym.get("subsystem", "General")
        domain = sym.get("domain", "")
        metadata = sym.get("metadata") or {}

        addr_obj = to_addr_fn(addr_val) if callable(to_addr_fn) else addr_val

        # 1. Label Function / Data / Register Symbol
        if callable(create_label_fn):
            try:
                create_label_fn(addr_obj, name, True)
                label_count += 1
            except Exception:
                pass

        # 2. Subsystem Plate Comments (OSD, Power, RTOS, Sensor/Capture, etc.)
        is_subsystem_target = (
            subsystem in SUBSYSTEM_PLATE_TARGETS
            or any(name.startswith(p) for p in ["DISP_", "PWR_", "RTOS_", "SYSFNC_", "REC_", "BML_", "STL_"])
            or addr_val in KNOWN_DISPATCHER_METADATA
        )
        if is_subsystem_target and callable(set_plate_fn) and (stype == "function" or addr_val in KNOWN_DISPATCHER_METADATA):
            try:
                plate_text = format_subsystem_plate(sym)
                set_plate_fn(addr_obj, plate_text)
                plate_count += 1
            except Exception:
                pass

        # 3. System Blackboard Variables (0x41F80000..0x41F9FFFF)
        is_blackboard = (
            stype == "blackboard_var"
            or (0x41F80000 <= addr_val <= 0x41F9FFFF)
            or name.startswith("BB_")
        )
        if is_blackboard and callable(set_eol_fn):
            try:
                eol_text = f"[Blackboard] {name} (Subsystem: {subsystem}, Size: {sym.get('size', 4)}B)"
                set_eol_fn(addr_obj, eol_text)
                eol_count += 1
            except Exception:
                pass

        # 4. MMIO Hardware Registers (0x80410000, 0xC04C0000, 0xE0010000)
        is_mmio = (
            stype == "mmio_register"
            or (0x80410000 <= addr_val <= 0x8041FFFF)
            or (0xC04C0000 <= addr_val <= 0xC04CFFFF)
            or (0xE0010000 <= addr_val <= 0xE081FFFF)
            or name.startswith("MMIO_")
        )
        if is_mmio and callable(set_eol_fn):
            try:
                eol_text = f"[MMIO Register] {name} ({domain})"
                set_eol_fn(addr_obj, eol_text)
                eol_count += 1
            except Exception:
                pass

        # 5. Literal Pointers
        if stype == "literal_pointer" and callable(set_eol_fn):
            try:
                target_ea = metadata.get("pointer_target")
                target_dom = metadata.get("target_domain", "")
                if target_ea is not None:
                    eol_text = f"[Literal Pointer] -> 0x{target_ea:08X} ({target_dom})"
                    set_eol_fn(addr_obj, eol_text)
                    eol_count += 1
            except Exception:
                pass

        # 6. Jump Tables
        if stype == "jump_table" and callable(set_pre_fn):
            try:
                bounds_str = metadata.get("bounds", "unknown")
                def_ea = metadata.get("default_target")
                pre_text = f"Jump Table: {name} (Bounds: {bounds_str}, Default: 0x{def_ea:08X})" if def_ea else f"Jump Table: {name}"
                set_pre_fn(addr_obj, pre_text)
            except Exception:
                pass

    log(f"[*] Symbol annotation complete: {label_count} labels, {plate_count} plates, {eol_count} EOL comments.")
    return label_count


class GhidraAnnotator:
    """Object-oriented interface for Ghidra annotation pipeline."""

    def __init__(self, symbols_path: Optional[Path] = None):
        self.symbols_path = symbols_path

    def setup_memory_blocks(self) -> int:
        return setup_memory_blocks()

    def locate_symbols_file(self) -> Optional[Path]:
        if self.symbols_path and self.symbols_path.exists():
            return self.symbols_path
        return locate_symbols_file()

    def annotate_symbols(self, symbols_path: Optional[Path] = None) -> int:
        target_path = symbols_path or self.locate_symbols_file()
        if target_path:
            return annotate_symbols(target_path)
        return 0

    def run(self) -> None:
        run()


def run() -> None:
    """Main execution entry point for Ghidra script."""
    log("==================================================================")
    log(" Olympus SP-550UZ (TruePic III) Ghidra Annotator")
    log("==================================================================")

    # Phase 1: Create Memory Blocks
    setup_memory_blocks()

    # Phase 2: Ingest Symbols and Annotate
    symbols_file = locate_symbols_file()
    if symbols_file:
        annotate_symbols(symbols_file)
    else:
        log("[!] Skipping symbol annotation as symbols.json was not found.")

    log("[+] Ghidra annotation script execution finished successfully.")


# Execute when run within Ghidra or test harness
if __name__ == "__main__":
    run()
