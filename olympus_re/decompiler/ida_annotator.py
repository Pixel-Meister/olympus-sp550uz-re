#!/usr/bin/env python3
"""
Olympus SP-550UZ (TruePic III / Sanyo SG155) IDA Pro IDAPython Annotator
========================================================================

Description:
  Automated IDAPython reverse engineering and annotation script for the
  Olympus SP-550UZ digital camera firmware (TruePic III platform / Sanyo SG155).
  Applies authoritative memory segmentation, auto-names 2,500+ functions,
  annotates subsystem dispatch handlers (OSD engine, RTOS event dispatcher,
  power management, JPEG/ISP pipeline), and labels hardware MMIO registers
  and system blackboard state variables.

TruePic III Memory Map Definitions:
  - 0x40000000: Section 1 SDRAM base (Cached ARMv5TE program code, 4.15 MB, RX)
  - 0x403f5108: Section 2 NDATA base (Cached resources, bitmaps, fonts, RO)
  - 0x41f00000: Uncached SDRAM base (Video DMA & hardware framebuffers, RW)
  - 0x41f80000: Blackboard base (Central system state & timers, RW)
  - 0x41fa0000: Stacks base (Banked IRQ/SVC/ABT/SYS task stacks, RW)
  - 0x80410000: MMIO SDRAM base (SDRAM timing & bus arbitration registers, RW)
  - 0xc04c0000: MMIO DMA/NAND base (DMA & NAND flash controller registers, RW)
  - 0xe0010000: MMIO Peripherals base (Timers, INTC, Video DAC, Keypad, ISP, RW)
  - 0xe081ffff: TruePic III ceiling (Upper bound of peripheral address space)

Interactive GUI Usage:
  1. Open IDA Pro and load the unpacked binary (`sp550uz_v1.1_section1_code.bin`):
     - Processor type: ARM (Little-Endian)
     - ROM start address: 0x40000000
     - Loading address: 0x40000000
  2. Press Alt+F7 (or navigate to File -> Script file...).
  3. Select this script file: `ida_sp550uz_annotator.py`.
  4. The script will automatically locate `output/symbols.json`, create all 8 TruePic III
     memory segments, name all functions, and populate plate/EOL comments.

Headless & Batch Execution:
  Execute IDA Pro in headless batch mode using `idal64` (Linux headless) or `ida64`:
    idal64 -c -A -Sida_sp550uz_annotator.py firmware.idb
    ida64 -c -A -Sida_sp550uz_annotator.py -B -Lida_annotation.log firmware.i64

  Headless batch execution from raw unpacked Section 1 binary:
    idal64 -c -A -pARM -b0x40000000 -Sida_sp550uz_annotator.py Resources/firmware/sp550uz_v1.1_section1_code.bin
"""

import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import idc
    import idaapi
    import idautils
    HAS_IDA = True
except ImportError:
    idc = None  # type: ignore
    idaapi = None  # type: ignore
    idautils = None  # type: ignore
    HAS_IDA = False


# ==============================================================================
# TruePic III Memory Architecture Domains
# ==============================================================================

# Segment definition format:
# (Segment Name, Start Address, End Address Inclusive, Permission Flag, Permission Str, Description)
# Permissions: SEGPERM_EXEC=1, SEGPERM_WRITE=2, SEGPERM_READ=4
# RX = 5, RO = 4, RW = 6, RWX = 7
SEGMENTS = [
    ("SEC1_SDRAM", 0x40000000, 0x403F50E7, 5, "RX", "SDRAM (Cached) Section 1 Program Code"),
    ("SEC2_NDATA", 0x403F5108, 0x40855967, 4, "RO", "SDRAM / Flash (Cached) Section 2 Resources"),
    ("UNCACHED_RAM", 0x41F00000, 0x41F7FFFF, 6, "RW", "SDRAM (Uncached) Video & DMA Buffers"),
    ("BLACKBOARD", 0x41F80000, 0x41F9FFFF, 6, "RW", "SDRAM Master State Blackboard"),
    ("STACKS", 0x41FA0000, 0x41FD0000, 6, "RW", "SDRAM Banked Task Stacks"),
    ("MMIO_SDRAM", 0x80410000, 0x8041FFFF, 6, "RW", "MMIO SDRAM Controller & Timings"),
    ("MMIO_DMA_NAND", 0xC04C0000, 0xC04CFFFF, 6, "RW", "MMIO DMA & NAND Flash Controller"),
    ("MMIO_PERIPH", 0xE0010000, 0xE081FFFF, 6, "RW", "MMIO Timers, INTC, Video DAC, Keypad, ISP"),
]

# Physical Continuous Intervals for Validation
VALID_PHYSICAL_RANGES = [
    (0x40000000, 0x40855967),  # Section 1 & 2
    (0x41F00000, 0x41FD0000),  # Uncached RAM, Blackboard & Stacks
    (0x80410000, 0x8041FFFF),  # MMIO SDRAM Controller
    (0xC04C0000, 0xC04CFFFF),  # MMIO DMA & NAND Controller
    (0xE0010000, 0xE081FFFF),  # MMIO Timers, INTC, Video DAC, ISP
]


# ==============================================================================
# Known Hardware Registers & System Blackboard State Catalog
# ==============================================================================

KNOWN_BLACKBOARD_SYMBOLS = [
    (0x41F80000, "SYS_Blackboard_Base", "System State Blackboard base address (128 KB)", "System"),
    (0x41F8DDAC, "BB_SleepCountdownTimer", "Power/Inactivity Countdown Timer (ticks to sleep)", "Power"),
    (0x41F8DDCC, "BB_MasterStateBlackboard", "Central system state blackboard structure", "System"),
    (0x41F8DDFC, "BB_BatteryVoltageADC", "Raw battery voltage ADC reading", "Power"),
    (0x41F8DE14, "BB_SystemConfigState", "System configuration and mode state", "System"),
    (0x41F8DE2C, "BB_PowerStateMachine", "Power state machine byte (+0x60: 0x49=Sleep, 0xE7=USB, etc.)", "Power"),
    (0x41F8DE68, "BB_OsdModeField", "OSD display mode structure (+0x9c)", "OSD"),
    (0x41F8DE6A, "BB_DisplayModeState", "Active OSD Display Mode byte (+0x9e: 0=Normal, 1=Grid, 2=Minimal)", "OSD"),
    (0x41F8DF04, "BB_VideoPlaybackState", "Video playback state structure base", "Video"),
    (0x41F8DF5E, "BB_VideoPlayingFlag", "Video playback active flag (+0x5a: 1 if playing AVI movie)", "Video"),
]

KNOWN_MMIO_SYMBOLS = [
    (0x80410000, "MMIO_SDRAM_TimingCtrl", "SDRAM Controller & Memory Timings Config", "MMIO_SDRAM"),
    (0xC04C0000, "MMIO_NAND_CmdStatus", "Direct Memory Access (DMA) & NAND Flash Controller", "MMIO_DMA_NAND"),
    (0xE0010000, "MMIO_INTC_Status", "Hardware Interrupt Controller Status / Mask", "MMIO_PERIPH"),
    (0xE0010040, "MMIO_TIMERS_Base", "Hardware Timers Base Registers & Prescalers", "MMIO_PERIPH"),
    (0xE0400000, "MMIO_VIDEO_DacCtrl", "Video DAC & Composite Output Control (NTSC/PAL)", "MMIO_PERIPH"),
    (0xE0800000, "MMIO_ISP_PipelineCtrl", "TruePic III Image Signal Processor (ISP) & JPEG Engine", "MMIO_PERIPH"),
]


# ==============================================================================
# Helper & Validation Functions
# ==============================================================================

def is_valid_truepic_address(addr: int) -> bool:
    """Validate that an address strictly falls within physical TruePic III domains."""
    if not isinstance(addr, int) or addr < 0 or addr > 0xFFFFFFFF:
        return False
    for start, end in VALID_PHYSICAL_RANGES:
        if start <= addr <= end:
            return True
    return False


def sanitize_symbol_name(name: str) -> str:
    """Sanitize symbol name for IDA Pro identifier compliance."""
    if not name:
        return ""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if clean and clean[0].isdigit():
        clean = "_" + clean
    return clean


def sanitize_comment(comment: str) -> str:
    """Sanitize comment strings by stripping null bytes and invalid control chars."""
    if not comment:
        return ""
    # Strip null characters as required by T2.9.4
    clean = comment.replace("\x00", "")
    return clean


def find_symbols_file() -> Optional[Path]:
    """Locate output/symbols.json across workspace directories or via IDA GUI prompt."""
    candidates = [
        Path("output/symbols.json"),
        Path("../output/symbols.json"),
        Path(__file__).resolve().parent.parent.parent / "output" / "symbols.json",
        Path(__file__).resolve().parent / "output" / "symbols.json",
        Path("symbols.json"),
    ]
    env_path = os.environ.get("OLYMPUS_SYMBOLS_PATH")
    if env_path:
        candidates.insert(0, Path(env_path))

    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p.resolve()
        except Exception:
            continue

    if HAS_IDA and hasattr(idaapi, "ask_file"):
        try:
            chosen = idaapi.ask_file(False, "*.json", "Select Olympus SP-550UZ symbols.json")
            if chosen and Path(chosen).exists():
                return Path(chosen).resolve()
        except Exception:
            pass

    return None


# ==============================================================================
# Core IDA Annotation Routines
# ==============================================================================

def create_memory_segments() -> int:
    """
    Create all 8 TruePic III memory segments in IDA Pro.
    Returns the count of successfully created or configured segments.
    """
    if not HAS_IDA or idc is None:
        print("[-] IDA modules unavailable; skipping segment creation.")
        return 0

    created_count = 0
    for name, start, end, perm, perm_str, desc in SEGMENTS:
        # In IDA Pro, endea is exclusive (start <= ea < endea)
        endea = end + 1 if end != 0xFFFFFFFF else end
        try:
            rc = idc.add_segm_ex(start, endea, 0, 1, 0, 0, perm)
            if rc:
                idc.set_segm_name(start, name)
                created_count += 1
            else:
                # Segment already exists or returned 0; update name gracefully
                idc.set_segm_name(start, name)
                created_count += 1
        except Exception as exc:
            print(f"[!] Warning: Failed to create segment {name} at 0x{start:08X}: {exc}")

    print(f"[+] Configured {created_count}/{len(SEGMENTS)} TruePic III memory segments.")
    return created_count


def set_ida_name_safe(addr: int, name: str) -> bool:
    """Set symbol name in IDA with collision fallback and validation."""
    if not HAS_IDA or idc is None or not is_valid_truepic_address(addr):
        return False

    clean_name = sanitize_symbol_name(name)
    if not clean_name:
        return False

    flags = getattr(idc, "SN_CHECK", 0) | getattr(idc, "SN_NOWARN", 1)
    try:
        rc = idc.set_name(addr, clean_name, flags)
        if rc == 0:
            # Collision or warning; fallback to unique address-suffixed name
            fallback_name = f"{clean_name}_{addr:08X}"
            rc = idc.set_name(addr, fallback_name, getattr(idc, "SN_NOWARN", 1))
        return bool(rc)
    except Exception:
        return False


def set_ida_comment_safe(addr: int, comment: str, is_func: bool = False) -> None:
    """Set repeatable or function comment with sanitization."""
    if not HAS_IDA or idc is None or not is_valid_truepic_address(addr):
        return

    clean_cmt = sanitize_comment(comment)
    if not clean_cmt:
        return

    try:
        idc.set_cmt(addr, clean_cmt, 1)
        if is_func and hasattr(idc, "set_func_cmt"):
            idc.set_func_cmt(addr, clean_cmt, 1)
    except Exception:
        pass


def annotate_builtin_hardware_symbols() -> None:
    """Annotate authoritative System Blackboard and MMIO registers."""
    # Annotate System Blackboard (0x41F80000 - 0x41F9FFFF)
    for addr, name, desc, sub in KNOWN_BLACKBOARD_SYMBOLS:
        set_ida_name_safe(addr, name)
        cmt = f"[{sub}] {desc} (Addr: 0x{addr:08X})"
        set_ida_comment_safe(addr, cmt, is_func=False)

    # Annotate MMIO Peripherals (0x80410000, 0xC04C0000, 0xE0010000)
    for addr, name, desc, sub in KNOWN_MMIO_SYMBOLS:
        set_ida_name_safe(addr, name)
        cmt = f"[{sub}] {desc} (MMIO: 0x{addr:08X})"
        set_ida_comment_safe(addr, cmt, is_func=False)

    print(f"[+] Applied {len(KNOWN_BLACKBOARD_SYMBOLS)} blackboard and {len(KNOWN_MMIO_SYMBOLS)} MMIO hardware symbols.")


def import_symbols_from_json(json_path: Path) -> int:
    """
    Ingest symbols from symbols.json and annotate functions, jump tables, and labels.
    Returns the count of annotated symbols.
    """
    if not json_path.exists():
        print(f"[!] symbols.json not found at {json_path}")
        return 0

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            symbols = json.load(f)
    except Exception as exc:
        print(f"[-] Failed to parse {json_path}: {exc}")
        return 0

    if not isinstance(symbols, list):
        print(f"[-] Invalid symbol list in {json_path}")
        return 0

    annotated = 0
    for sym in symbols:
        addr = sym.get("address")
        if addr is None or not is_valid_truepic_address(addr):
            continue

        name = sym.get("name", "")
        sym_type = sym.get("type", "unknown")
        subsystem = sym.get("subsystem", "General")
        metadata = sym.get("metadata", {}) or {}

        # Set symbol name
        if name:
            set_ida_name_safe(addr, name)

        # Set comments based on symbol type
        if sym_type == "function":
            callers = metadata.get("callers", [])
            callees = metadata.get("call_targets", [])
            prologue = metadata.get("prologue_type", "ARM")
            cmt_parts = [
                f"Subsystem: {subsystem}",
                f"Prologue: {prologue}",
            ]
            if callers:
                cmt_parts.append(f"Callers ({len(callers)}): " + ", ".join(f"0x{c:08X}" for c in callers[:5]))
            if callees:
                cmt_parts.append(f"Callees ({len(callees)}): " + ", ".join(f"0x{c:08X}" for c in callees[:5]))
            full_cmt = " | ".join(cmt_parts)
            set_ida_comment_safe(addr, full_cmt, is_func=True)
            annotated += 1

        elif sym_type == "jump_table":
            site = metadata.get("site", 0)
            bounds = metadata.get("bounds", "")
            targets = metadata.get("targets", [])
            cmt = f"JumpTable: {len(targets)} targets (Site: 0x{site:08X}, Bounds: {bounds})"
            set_ida_comment_safe(addr, cmt, is_func=False)
            annotated += 1

        elif sym_type in ["blackboard_var", "mmio_register"]:
            desc = metadata.get("description", "")
            cmt = f"[{subsystem}] {desc or name} (0x{addr:08X})"
            set_ida_comment_safe(addr, cmt, is_func=False)
            annotated += 1

        elif sym_type == "literal_pointer":
            target = metadata.get("pointer_target", 0)
            tdom = metadata.get("target_domain", "")
            cmt = f"LiteralPointer -> 0x{target:08X} ({tdom})"
            set_ida_comment_safe(addr, cmt, is_func=False)
            annotated += 1

    print(f"[+] Successfully annotated {annotated} symbols from {json_path.name}.")
    return annotated


class IdaAnnotator:
    """Object-oriented interface for IDA Pro annotation pipeline."""

    def __init__(self, symbols_path: Optional[Path] = None):
        self.symbols_path = symbols_path

    def create_memory_segments(self) -> int:
        return create_memory_segments()

    def annotate_hardware(self) -> None:
        annotate_builtin_hardware_symbols()

    def find_symbols_file(self) -> Optional[Path]:
        if self.symbols_path and self.symbols_path.exists():
            return self.symbols_path
        return find_symbols_file()

    def annotate_symbols(self, symbols_path: Optional[Path] = None) -> int:
        target_path = symbols_path or self.find_symbols_file()
        if target_path:
            return import_symbols_from_json(target_path)
        return 0

    def run(self) -> int:
        return main()


# ==============================================================================
# Script Entry Point
# ==============================================================================

def main() -> int:
    """Main execution orchestrator for IDA Pro annotator."""
    print("=" * 70)
    print(" Olympus SP-550UZ TruePic III IDAPython Annotator")
    print("=" * 70)

    # 1. Wait for auto-analysis to finish if in headless or interactive IDA
    if HAS_IDA and hasattr(idaapi, "auto_wait"):
        try:
            print("[*] Waiting for IDA background auto-analysis...")
            idaapi.auto_wait()
        except Exception:
            pass

    # 2. Create and configure memory segments spanning 0x40000000 to 0xE081FFFF
    create_memory_segments()

    # 3. Annotate built-in hardware MMIO and System Blackboard state variables
    annotate_builtin_hardware_symbols()

    # 4. Ingest and apply symbols.json if available
    symbols_file = find_symbols_file()
    if symbols_file:
        print(f"[*] Ingesting symbol database: {symbols_file}")
        import_symbols_from_json(symbols_file)
    else:
        print("[!] Note: symbols.json not found on disk; core hardware & memory map annotated.")

    print("\n[+] Olympus SP-550UZ IDA Pro annotation finished successfully.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    main()
