"""
olympus_re/models/symbols.py - Symbol, Function, JumpTable, and Hardware Models
"""

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional
from olympus_re.models.memory_map import TruePicIIIMemoryMap


SUBSYSTEM_PREFIX_MAP: Dict[str, str] = {
    "DISP_": "OSD",
    "OSC_": "OSD",
    "MNCB_": "OSD",
    "COMM_": "Communication",
    "SYSFNC_": "SystemFunction",
    "REC_": "Sensor/Capture",
    "BML_": "Storage/NAND",
    "STL_": "Storage/NAND",
    "FSB_": "Storage/NAND",
    "TED_": "Storage/NAND",
    "Ptp_": "PTP/USB",
    "PTP_": "PTP/USB",
    "OL_MTP_": "PTP/USB",
    "AF_": "Sensor/Capture",
    "PLAY_": "Playback",
    "Play_": "Playback",
    "FLASH_": "Flash/Strobe",
    "PWR_": "Power",
    "RTOS_": "RTOS",
}


def classify_subsystem(name: str) -> str:
    """Classify subsystem based on longest prefix matching, defaulting to 'General'."""
    if not name:
        return "General"
    for prefix in sorted(SUBSYSTEM_PREFIX_MAP.keys(), key=len, reverse=True):
        if name.startswith(prefix):
            return SUBSYSTEM_PREFIX_MAP[prefix]
    return "General"


class Symbol:
    """Universal symbol record representing a function, label, string, pointer, or register."""

    def __init__(
        self,
        address: int,
        name: str,
        type: str = "unknown",
        size: int = 4,
        domain: Optional[str] = None,
        subsystem: str = "General",
        metadata: Optional[Dict[str, Any]] = None,
        sym_type: Optional[str] = None,
    ):
        self.address = address
        self.name = name
        self.type = sym_type if sym_type is not None else type
        self.size = size
        self.domain = domain or TruePicIIIMemoryMap.classify_address(address) or "Unknown"
        self.subsystem = subsystem if subsystem != "General" else classify_subsystem(name)
        self.metadata = metadata.copy() if metadata is not None else {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize symbol to standard dictionary format."""
        return {
            "address": self.address,
            "name": self.name,
            "type": self.type,
            "size": self.size,
            "domain": self.domain,
            "subsystem": self.subsystem,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"Symbol(0x{self.address:08X}, {self.name!r}, {self.type}, {self.domain})"


class JumpTable:
    """Represents a switch/jump table dispatched by indirect branch."""

    def __init__(
        self,
        site: int,
        table_address: int,
        entry_count: int,
        bounds: str,
        default_target: int,
        targets: List[int],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.site = site
        self.table_address = table_address
        self.entry_count = entry_count
        self.bounds = bounds
        self.default_target = default_target
        self.targets = list(targets)
        self.metadata = metadata.copy() if metadata is not None else {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize jump table to standard dictionary format."""
        return {
            "site": self.site,
            "table_address": self.table_address,
            "entry_count": self.entry_count,
            "bounds": self.bounds,
            "default_target": self.default_target,
            "targets": self.targets,
        }

    def to_symbol(self) -> Symbol:
        """Convert jump table to Symbol record for inclusion in symbol database."""
        return Symbol(
            address=self.table_address,
            name=f"JMPT_{self.table_address:08X}",
            type="jump_table",
            size=self.entry_count * 4,
            subsystem="General",
            metadata={
                "site": self.site,
                "bounds": self.bounds,
                "default_target": self.default_target,
                "targets": self.targets,
            },
        )

    def __repr__(self) -> str:
        return f"JumpTable(0x{self.table_address:08X}, entries={self.entry_count}, site=0x{self.site:08X})"


class Function(Symbol):
    """Subroutine symbol tracking entry point, boundaries, prologues/epilogues, and call graph."""

    def __init__(
        self,
        address: int,
        name: str,
        size: int = 4,
        domain: Optional[str] = None,
        subsystem: Optional[str] = None,
        prologue_type: str = "unknown",
        epilogues: Optional[List[int]] = None,
        call_targets: Optional[List[int]] = None,
        callers: Optional[List[int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        sub = subsystem or classify_subsystem(name)
        meta = metadata.copy() if metadata is not None else {}
        super().__init__(
            address=address,
            name=name,
            type="function",
            size=size,
            domain=domain,
            subsystem=sub,
            metadata=meta,
        )
        self.prologue_type = prologue_type
        self.epilogues = list(epilogues) if epilogues is not None else []
        self.call_targets = list(call_targets) if call_targets is not None else []
        self.callers = list(callers) if callers is not None else []

        self.metadata["prologue_type"] = self.prologue_type
        self.metadata["epilogues"] = self.epilogues
        self.metadata["call_targets"] = self.call_targets
        self.metadata["callers"] = self.callers

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d["metadata"]["prologue_type"] = self.prologue_type
        d["metadata"]["epilogues"] = self.epilogues
        d["metadata"]["call_targets"] = self.call_targets
        d["metadata"]["callers"] = self.callers
        return d


FunctionSymbol = Function  # Backward compatibility alias


class LiteralPoolEntry:
    """PC-relative literal load entry classified into physical memory domain."""

    def __init__(
        self,
        address: int,
        target_address: int,
        target_domain: Optional[str] = None,
        register: str = "r0",
        is_pointer: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.address = address
        self.target_address = target_address
        self.target_domain = target_domain or TruePicIIIMemoryMap.classify_address(target_address)
        self.is_pointer = is_pointer if is_pointer is not None else (self.target_domain is not None)
        self.register = register
        self.metadata = metadata.copy() if metadata is not None else {}

    def to_symbol(self) -> Symbol:
        """Convert to Symbol record with pointer_target metadata."""
        return Symbol(
            address=self.address,
            name=f"PTR_{self.address:08X}",
            type="literal_pointer",
            size=4,
            domain=TruePicIIIMemoryMap.classify_address(self.address) or "Section 1 SDRAM (NPROG)",
            metadata={
                "pointer_target": self.target_address,
                "target_domain": self.target_domain,
                "register": self.register,
                **self.metadata,
            },
        )


LiteralPointer = LiteralPoolEntry  # Backward compatibility alias


class MMIORegister:
    """Hardware peripheral register in TruePic III MMIO space."""

    def __init__(
        self,
        address: int,
        name: str,
        block: str,
        access: str = "RW",
        description: str = "",
        bitfields: Optional[Dict[str, Any]] = None,
    ):
        self.address = address
        self.name = name
        self.block = block
        self.access = access
        self.description = description
        self.bitfields = bitfields.copy() if bitfields is not None else {}

    def to_symbol(self) -> Symbol:
        return Symbol(
            address=self.address,
            name=self.name,
            type="mmio_register",
            size=4,
            domain="MMIO Timers/Interrupts/DAC/ISP",
            subsystem=self.block,
            metadata={
                "block": self.block,
                "access": self.access,
                "description": self.description,
                "bitfields": self.bitfields,
            },
        )
