"""
olympus_re/analysis/function_detector.py - Multi-Method Function Boundary Detection
"""

from dataclasses import dataclass, field
from pathlib import Path
import struct
from typing import Dict, List, Optional, Set, Tuple

from olympus_re.models.symbols import Function, classify_subsystem


@dataclass
class DetectedFunction:
    address: int
    name: str
    size: int = 4
    detection_methods: List[str] = field(default_factory=list)
    epilogues: List[int] = field(default_factory=list)
    callers: Set[int] = field(default_factory=set)
    callees: Set[int] = field(default_factory=set)
    subsystem: str = "General"

    def to_symbol(self) -> Function:
        return Function(
            address=self.address,
            name=self.name,
            size=self.size,
            domain="Section 1 SDRAM (NPROG)",
            subsystem=self.subsystem,
            prologue_type=self.detection_methods[0] if self.detection_methods else "unknown",
            epilogues=self.epilogues,
            call_targets=list(self.callees),
            callers=list(self.callers),
            metadata={
                "detection_methods": self.detection_methods,
                "epilogues": self.epilogues,
                "caller_count": len(self.callers),
                "callee_count": len(self.callees),
            },
        )

    def to_symbol_dict(self) -> Dict:
        return self.to_symbol().to_dict()


class FunctionDetector:
    """Discovers and sizes function boundaries across Section 1 code."""

    SECTION1_START = 0x40000000
    SECTION1_END = 0x403F50E7

    # Authoritative Architectural Handlers
    KNOWN_HANDLERS = {
        0x40000000: ("ResetVector", "System"),
        0x40000800: ("ColdBootInit", "System"),
        0x40000988: ("CP15_Setup", "System"),
        0x40000ADC: ("ColdBootEntry", "System"),
        0x401B32F4: ("DISP_OsdDispatcher", "OSD"),
        0x4019E1E8: ("RTOS_EventLoop", "RTOS"),
        0x401501B4: ("PWR_ResetIdleCounter", "Power"),
        0x40150540: ("PWR_QuerySleepInhibit", "Power"),
        0x4014B264: ("PWR_PrimarySleepTransition", "Power"),
        0x4014BB18: ("PWR_SecondarySleepTransition", "Power"),
        0x4014BFC0: ("PWR_PhysicalShutdown", "Power"),
        0x401247FC: ("KEY_PollMatrix", "Input"),
        0x40176B38: ("REC_ThroughCtrl", "Sensor/Capture"),
        0x400D4AC0: ("SYSFNC_FMT_set_BufA_clock", "SystemFunction"),
        0x40291694: ("FW_FlashProgrammer", "Storage/NAND"),
    }

    def __init__(self, section1_bytes: bytes, base_address: int = SECTION1_START):
        self.code = section1_bytes
        self.base_address = base_address
        self.end_address = base_address + len(section1_bytes) - 1
        self.functions: Dict[int, DetectedFunction] = {}

    def is_valid_code_address(self, addr: int) -> bool:
        return self.base_address <= addr <= self.end_address and (addr % 4 == 0)

    def analyze(self) -> Dict[int, DetectedFunction]:
        """Execute full multi-method function boundary detection pipeline."""
        if len(self.code) < 4:
            return {}

        total_len = len(self.code) - (len(self.code) % 4)

        prologue_funcs: Set[int] = set()
        sanyo_leaf_funcs: Set[int] = set()
        all_epilogues: Set[int] = set()
        bl_calls: List[Tuple[int, int]] = []

        for offset in range(0, total_len, 4):
            pc = self.base_address + offset
            word = struct.unpack("<I", self.code[offset : offset + 4])[0]

            # Method 1: Standard Prologue push {..., lr} (0xE92D4xxx)
            if (word & 0xFFFF4000) == 0xE92D4000:
                prologue_funcs.add(pc)

            # Method 2: Sanyo Leaf Prologue push {r8, sb} or push {..., r11}
            elif word == 0xE92D0300 or (word & 0xFFFF0800) == 0xE92D0800:
                sanyo_leaf_funcs.add(pc)

            # Epilogue: pop {..., pc} (0xE8BD8xxx)
            if (word & 0xFFFF8000) == 0xE8BD8000:
                all_epilogues.add(pc)
            # Epilogue: bx lr (0xE12FFF1E) or conditional bxeq/bxne lr
            elif (word & 0x0FFFFFFF) == 0x012FFF1E:
                all_epilogues.add(pc)
            # Epilogue: mov pc, lr (0xE1A0F00E)
            elif word == 0xE1A0F00E:
                all_epilogues.add(pc)

            # Method 3: Direct BL Call Target (0x..0B000000)
            if (word & 0x0F000000) == 0x0B000000:
                imm24 = word & 0x00FFFFFF
                if imm24 & 0x00800000:
                    imm24 |= 0xFF000000
                target = (pc + 8 + (imm24 << 2)) & 0xFFFFFFFF
                if self.is_valid_code_address(target):
                    bl_calls.append((pc, target))

        # Method 4: Scan for 32-bit aligned words pointing to code
        literal_targets: Set[int] = set()
        for offset in range(0, total_len, 4):
            val = struct.unpack("<I", self.code[offset : offset + 4])[0]
            if self.is_valid_code_address(val):
                literal_targets.add(val)

        # Consolidate candidate entry points
        all_candidates: Set[int] = set()
        all_candidates.update(prologue_funcs)
        all_candidates.update(sanyo_leaf_funcs)
        all_candidates.update(target for _, target in bl_calls)
        for h in self.KNOWN_HANDLERS:
            if self.is_valid_code_address(h):
                all_candidates.add(h)

        for lit in literal_targets:
            if lit in prologue_funcs or lit in sanyo_leaf_funcs or lit in self.KNOWN_HANDLERS:
                all_candidates.add(lit)

        # Ensure base address (e.g. 0x40000000) is always included
        if self.is_valid_code_address(self.base_address):
            all_candidates.add(self.base_address)

        sorted_entries = sorted(all_candidates)
        for i, addr in enumerate(sorted_entries):
            methods = []
            if addr in prologue_funcs:
                methods.append("prologue_push_lr")
            if addr in sanyo_leaf_funcs:
                methods.append("prologue_sanyo_leaf")
            if addr in self.KNOWN_HANDLERS:
                methods.append("known_architecture_entry")

            if addr in self.KNOWN_HANDLERS:
                name, subsystem = self.KNOWN_HANDLERS[addr]
            else:
                name = f"sub_{addr:08X}"
                subsystem = "General"

            next_addr = sorted_entries[i + 1] if i + 1 < len(sorted_entries) else self.end_address + 1
            size = max(4, next_addr - addr)

            func = DetectedFunction(
                address=addr,
                name=name,
                size=size,
                detection_methods=methods,
                subsystem=subsystem,
            )
            self.functions[addr] = func

        for caller_pc, callee_pc in bl_calls:
            if callee_pc in self.functions:
                self.functions[callee_pc].callers.add(caller_pc)
                if "bl_target" not in self.functions[callee_pc].detection_methods:
                    self.functions[callee_pc].detection_methods.append("bl_target")

        # Associate callers with callees
        for caller_pc, callee_pc in bl_calls:
            # find caller function
            caller_fn = self._find_enclosing_function(sorted_entries, caller_pc)
            if caller_fn and caller_fn.address in self.functions:
                self.functions[caller_fn.address].callees.add(callee_pc)

        # Attribute epilogues
        for epi in sorted(all_epilogues):
            encl = self._find_enclosing_function(sorted_entries, epi)
            if encl and encl.address in self.functions:
                self.functions[encl.address].epilogues.append(epi)

        return self.functions

    def _find_enclosing_function(self, sorted_entries: List[int], addr: int) -> Optional[DetectedFunction]:
        import bisect
        idx = bisect.bisect_right(sorted_entries, addr) - 1
        if 0 <= idx < len(sorted_entries):
            fn_addr = sorted_entries[idx]
            fn = self.functions.get(fn_addr)
            if fn and fn.address <= addr < fn.address + fn.size:
                return fn
        return None

    def get_functions(self) -> List[Function]:
        if not self.functions:
            self.analyze()
        return [f.to_symbol() for f in self.functions.values()]
