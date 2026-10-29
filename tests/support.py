"""
Shared test support utilities, path locators, mock environments, reference models, and assertion helpers.
"""

import ast
import csv
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import types
from typing import Any, Dict, List, Optional, Set, Tuple

# Base Directories
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESOURCES_DIR = PROJECT_ROOT / "Resources"
FIRMWARE_DIR = RESOURCES_DIR / "firmware"
NOTES_DIR = RESOURCES_DIR / "notes"

# Firmware Binaries
SECTION1_PATH = FIRMWARE_DIR / "sp550uz_v1.1_section1_code.bin"
SECTION2_PATH = FIRMWARE_DIR / "sp550uz_v1.1_section2_ndata.bin"

# Expected Hashes
EXPECTED_SHA256 = {
    "section1": "29f5a486a2aec0a9810db7ddde9952324d4b07803725b453cb390c49375f30a6",
    "section2": "38e30f72a126dabac3866ebf7f08c0d5a128d997a167fdbdfa32d174f973f7c4",
}

# Output Artifact Paths
OUTPUT_DIR = PROJECT_ROOT / "output"
SYMBOLS_JSON_PATH = OUTPUT_DIR / "symbols.json"
SYMBOLS_CSV_PATH = OUTPUT_DIR / "symbols.csv"
JUMP_TABLES_JSON_PATH = OUTPUT_DIR / "jump_tables.json"

# Documentation Paths
DOCS_DIR = PROJECT_ROOT / "docs"
DOCS_XREF_HTML_PATH = DOCS_DIR / "xref.html"
DOCS_XREF_DIR = DOCS_DIR / "xref"

# Decompiler Script Paths
GHIDRA_SCRIPT_PATH = PROJECT_ROOT / "olympus_re" / "decompiler" / "ghidra_sp550uz_annotator.py"
GHIDRA_SCRIPT_ALT_PATH = PROJECT_ROOT / "olympus_re" / "decompiler" / "ghidra_annotator.py"
IDA_SCRIPT_PATH = PROJECT_ROOT / "olympus_re" / "decompiler" / "ida_sp550uz_annotator.py"
IDA_SCRIPT_ALT_PATH = PROJECT_ROOT / "olympus_re" / "decompiler" / "ida_annotator.py"

# Authoritative TruePic III Memory Map Domains
TRUEPIC_III_DOMAINS = [
    ("SDRAM_CODE", 0x40000000, 0x403F50E7, "RX", "SDRAM (Cached) Section 1"),
    ("SDRAM_NDATA", 0x403F5108, 0x40855967, "RO", "SDRAM / Flash (Cached) Section 2"),
    ("UNCACHED_RAM", 0x41F00000, 0x41F7FFFF, "RW", "SDRAM (Uncached) Video & DMA Buffers"),
    ("BLACKBOARD", 0x41F80000, 0x41F9FFFF, "RW", "SDRAM Master State Blackboard"),
    ("TASK_STACKS", 0x41FA0000, 0x41FD0000, "RW", "SDRAM Banked Task Stacks"),
    ("MMIO_SDRAM_CTRL", 0x80410000, 0x8041FFFF, "RW", "MMIO SDRAM Controller & Timings"),
    ("MMIO_DMA_NAND", 0xC04C0000, 0xC04CFFFF, "RW", "MMIO DMA & NAND Flash Controller"),
    ("MMIO_PERIPHERALS", 0xE0010000, 0xE081FFFF, "RW", "MMIO Timers, Int, Video DAC, Keypad, ISP"),
]

# Physical Continuous Intervals for Validation
VALID_PHYSICAL_MEMORY_RANGES: List[Tuple[int, int, str]] = [
    (0x40000000, 0x40855967, "Section 1 SDRAM & Section 2 NDATA"),
    (0x41F00000, 0x41FD0000, "Uncached SDRAM Buffers, Blackboard & Stacks"),
    (0x80410000, 0x8041FFFF, "MMIO SDRAM Controller"),
    (0xC04C0000, 0xC04CFFFF, "MMIO DMA & NAND Controller"),
    (0xE0000000, 0xE081FFFF, "MMIO Timers, Interrupt, Video DAC, ISP, JPEG"),
]

# Jump Table Constants
KNOWN_OSD_TABLE_ADDR = 0x401B3324
KNOWN_OSD_ENTRY_COUNT = 25
KNOWN_OSD_TARGETS = {
    0: 0x401B3388,   # Mode 0: Normal HUD
    1: 0x401B33D4,   # Mode 1: Assist Grid / Histogram
    2: 0x401B35B4,   # Mode 2: Minimal HUD
    3: 0x401B35B4,   # Mode 3
    4: 0x401B3864,   # Mode 4: Clean Epilogue
    5: 0x401B365C,   # Mode 5
    6: 0x401B3438,   # Mode 6
    7: 0x401B35E8,   # Mode 7
    8: 0x401B361C,   # Mode 8: Auto Minimal HUD
    24: 0x401B3478,  # Mode 0x18: Custom Submode 5
}

KNOWN_RTOS_TABLE_ADDR = 0x4019E324
KNOWN_RTOS_ENTRY_COUNT = 16
KNOWN_RTOS_TARGETS = {
    0: 0x4019E5F0,   # Event 0x0
    1: 0x4019E8F8,   # Event 0x1
    2: 0x4019E6B8,   # Event 0x2
    3: 0x4019E9F8,   # Event 0x3
    4: 0x4019E4A8,   # Event 0x4
    5: 0x4019E9F8,   # Event 0x5
    6: 0x4019E484,   # Event 0x6
    7: 0x4019E9CC,   # Event 0x7: Secondary Idle Sleep handler
    8: 0x4019E49C,   # Event 0x8
    9: 0x4019E4F4,   # Event 0x9
    10: 0x4019E5A4,  # Event 0xA
    11: 0x4019E4C0,  # Event 0xB
    12: 0x4019E4DC,  # Event 0xC
    13: 0x4019E4E8,  # Event 0xD
    14: 0x4019E9F8,  # Event 0xE: LCD Dimming handler
    15: 0x4019E9C0,  # Event 0xF: Primary Idle Sleep handler
}

MIN_REQUIRED_FUNCTIONS = 2500


def is_valid_truepic_address(addr: int) -> bool:
    """Validate if an address falls strictly within known physical TruePic III domains."""
    for _, start, end, _, _ in TRUEPIC_III_DOMAINS:
        if start <= addr <= end:
            return True
    return False


def get_truepic_domain(addr: int) -> Optional[str]:
    """Return the domain name for a given TruePic III address, or None if invalid."""
    for name, start, end, _, _ in TRUEPIC_III_DOMAINS:
        if start <= addr <= end:
            return name
    return None


def is_valid_physical_address(address: int) -> bool:
    """Check if address falls within any of the 5 continuous TruePic III physical domains."""
    for start, end, _ in VALID_PHYSICAL_MEMORY_RANGES:
        if start <= address <= end:
            return True
    return False


# Reference Classes for Progressive Testability
class MemoryPermission:
    RX = "RX"
    RO = "RO"
    RW = "RW"
    RW_MMIO = "RW_MMIO"


class MemoryDomain:
    def __init__(self, name: str, start: int, end: int, permissions: str, description: str = ""):
        self.name = name
        self.start = start
        self.end = end
        self.size = end - start + 1
        self.permissions = permissions
        self.description = description

    def contains(self, addr: int) -> bool:
        return self.start <= addr <= self.end


class TruePicIIIMemoryMap:
    DOMAINS = [
        MemoryDomain("Section 1 SDRAM (NPROG)", 0x40000000, 0x403F50E7, MemoryPermission.RX, "SDRAM Code"),
        MemoryDomain("Section 2 SDRAM (NDATA)", 0x403F5108, 0x40855967, MemoryPermission.RO, "SDRAM NDATA"),
        MemoryDomain("Uncached RAM Buffers", 0x41F00000, 0x41F7FFFF, MemoryPermission.RW, "Uncached RAM"),
        MemoryDomain("System State Blackboard", 0x41F80000, 0x41F9FFFF, MemoryPermission.RW, "Blackboard"),
        MemoryDomain("Banked Task Stacks", 0x41FA0000, 0x41FD0000, MemoryPermission.RW, "Task Stacks"),
        MemoryDomain("MMIO SDRAM Controller", 0x80410000, 0x8041FFFF, MemoryPermission.RW_MMIO, "SDRAM Controller"),
        MemoryDomain("MMIO DMA & NAND Controller", 0xC04C0000, 0xC04CFFFF, MemoryPermission.RW_MMIO, "DMA & NAND"),
        MemoryDomain("MMIO Timers/Interrupts/DAC/ISP", 0xE0010000, 0xE081FFFF, MemoryPermission.RW_MMIO, "MMIO Timers & ISP"),
    ]

    @classmethod
    def classify_address(cls, addr: int) -> Optional[str]:
        for d in cls.DOMAINS:
            if d.contains(addr):
                return d.name
        return None

    @classmethod
    def is_valid_address(cls, addr: int) -> bool:
        return cls.classify_address(addr) is not None


class Symbol:
    def __init__(
        self,
        address: int,
        name: str,
        sym_type: str,
        size: int = 4,
        domain: Optional[str] = None,
        subsystem: str = "General",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.address = address
        self.name = name
        self.type = sym_type
        self.size = size
        self.domain = domain or TruePicIIIMemoryMap.classify_address(address) or "Unknown"
        self.subsystem = subsystem
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "type": self.type,
            "size": self.size,
            "domain": self.domain,
            "subsystem": self.subsystem,
            "metadata": self.metadata,
        }


class JumpTable:
    def __init__(
        self,
        site: int,
        table_address: int,
        entry_count: int,
        bounds: str,
        default_target: int,
        targets: List[int],
    ):
        self.site = site
        self.table_address = table_address
        self.entry_count = entry_count
        self.bounds = bounds
        self.default_target = default_target
        self.targets = targets

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site": self.site,
            "table_address": self.table_address,
            "entry_count": self.entry_count,
            "bounds": self.bounds,
            "default_target": self.default_target,
            "targets": self.targets,
        }


# Fast Firmware Scanning Utilities
def scan_prologues_from_file(binary_path: Path, max_count: Optional[int] = None) -> List[int]:
    """Scan ARM binary for push {..., lr} (0xe92d4xxx) instruction prologues."""
    results: List[int] = []
    with open(binary_path, "rb") as f:
        data = f.read()
    for i in range(0, len(data) - 4, 4):
        w = struct.unpack("<I", data[i : i + 4])[0]
        if (w & 0xFFFF4000) == 0xE92D4000:
            results.append(0x40000000 + i)
            if max_count and len(results) >= max_count:
                break
    return results


def read_jump_table_from_file(binary_path: Path, table_addr: int, count: int) -> List[int]:
    """Read 32-bit little endian target addresses from binary at given table address."""
    results: List[int] = []
    with open(binary_path, "rb") as f:
        f.seek(table_addr - 0x40000000)
        for _ in range(count):
            target = struct.unpack("<I", f.read(4))[0]
            results.append(target)
    return results


# Mock Ghidra & IDA Pro Testing Harness
class MockAddress:
    def __init__(self, offset: int):
        self.offset = offset

    def getOffset(self) -> int:
        return self.offset

    def add(self, delta: int) -> "MockAddress":
        return MockAddress(self.offset + delta)

    def __repr__(self) -> str:
        return f"Addr(0x{self.offset:08X})"


class MockMemoryBlock:
    def __init__(self, name: str, start: MockAddress, length: int, r: bool, w: bool, x: bool):
        self.name = name
        self.start = start
        self.length = length
        self.r = r
        self.w = w
        self.x = x

    def getStart(self) -> MockAddress:
        return self.start

    def getEnd(self) -> MockAddress:
        return MockAddress(self.start.getOffset() + self.length - 1)


class MockGhidraFlatProgramAPI:
    """Mock harness for PyGhidra FlatProgramAPI."""

    def __init__(self):
        self.blocks: Dict[str, MockMemoryBlock] = {}
        self.labels: Dict[int, Dict[str, Any]] = {}
        self.plate_comments: Dict[int, str] = {}
        self.pre_comments: Dict[int, str] = {}
        self.eol_comments: Dict[int, str] = {}

    def toAddr(self, val: Any) -> MockAddress:
        if isinstance(val, int):
            return MockAddress(val)
        if isinstance(val, str):
            clean = val.replace("0x", "")
            return MockAddress(int(clean, 16))
        if isinstance(val, MockAddress):
            return val
        return MockAddress(int(val))

    def createMemoryBlock(
        self, name: str, start: Any, length: int, r: bool = True, w: bool = True, x: bool = False
    ) -> MockMemoryBlock:
        addr = self.toAddr(start)
        block = MockMemoryBlock(name, addr, length, r, w, x)
        self.blocks[name] = block
        return block

    def createLabel(self, addr: Any, name: str, is_primary: bool = True) -> None:
        offset = self.toAddr(addr).getOffset()
        self.labels[offset] = {"name": name, "primary": is_primary}

    def setPlateComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.plate_comments[offset] = comment

    def setPreComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.pre_comments[offset] = comment

    def setEolComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.eol_comments[offset] = comment

    def println(self, msg: str) -> None:
        pass


class MockIDAPython:
    """Mock harness for IDA Pro idc, idaapi, and idautils."""

    def __init__(self):
        self.segments: Dict[int, Dict[str, Any]] = {}
        self.names: Dict[int, str] = {}
        self.comments: Dict[int, str] = {}
        self.func_comments: Dict[int, str] = {}

        # idc module
        self.idc = types.ModuleType("idc")
        self.idc.BADADDR = 0xFFFFFFFF
        self.idc.SN_NOWARN = 1
        self.idc.SN_NOCHECK = 2
        self.idc.add_segm_ex = self._add_segm_ex
        self.idc.add_segm = self._add_segm
        self.idc.set_segm_name = self._set_segm_name
        self.idc.set_name = self._set_name
        self.idc.set_cmt = self._set_cmt
        self.idc.set_func_cmt = self._set_func_cmt

        # idaapi module
        self.idaapi = types.ModuleType("idaapi")
        self.idaapi.BADADDR = 0xFFFFFFFF
        self.idaapi.auto_wait = lambda: None
        self.idaapi.get_segm_by_name = lambda name: 1

        # idautils module
        self.idautils = types.ModuleType("idautils")
        self.idautils.Functions = lambda: iter(self.names.keys())
        self.idautils.Segments = lambda: iter(self.segments.keys())

    def _add_segm_ex(
        self, startea: int, endea: int, base: int, use32: int, align: int, comb: int, perm: int
    ) -> int:
        self.segments[startea] = {
            "start": startea,
            "end": endea,
            "perm": perm,
            "name": f"seg_{startea:08X}",
        }
        return 1

    def _add_segm(self, startea: int, endea: int, base: int, use32: int, align: int, comb: int) -> int:
        return self._add_segm_ex(startea, endea, base, use32, align, comb, 7)

    def set_name(self, ea: int, name: str, flags: int = 0) -> int:
        return self._set_name(ea, name, flags)

    def set_cmt(self, ea: int, comm: str, rpt: int = 0) -> int:
        return self._set_cmt(ea, comm, rpt)

    def add_segm_ex(
        self, startea: int, endea: int, base: int, use32: int, align: int, comb: int, perm: int
    ) -> int:
        return self._add_segm_ex(startea, endea, base, use32, align, comb, perm)

    def _set_segm_name(self, ea: int, name: str) -> int:
        if ea in self.segments:
            self.segments[ea]["name"] = name
            return 1
        return 0

    def _set_name(self, ea: int, name: str, flags: int = 0) -> int:
        self.names[ea] = name
        return 1

    def _set_cmt(self, ea: int, comm: str, rpt: int = 0) -> int:
        self.comments[ea] = comm
        return 1

    def _set_func_cmt(self, ea: int, cmt: str, rpt: int = 0) -> int:
        self.func_comments[ea] = cmt
        return 1
