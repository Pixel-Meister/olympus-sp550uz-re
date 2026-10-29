"""
olympus_re/models/memory_map.py - TruePic III Memory Architecture & Domain Validation
"""

from typing import List, Optional


class MemoryPermission:
    """Memory access permission attributes for TruePic III domains."""
    RX = "RX"
    RO = "RO"
    RW = "RW"
    RW_MMIO = "RW_MMIO"


class MemoryDomain:
    """Represents a continuous physical memory segment in the TruePic III architecture."""

    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        permissions: str,
        description: str = "",
    ):
        self.name = name
        self.start = start
        self.end = end
        self.size = end - start + 1
        self.permissions = permissions
        self.description = description

    def contains(self, addr: int) -> bool:
        """Check whether a physical address resides strictly within this domain."""
        return self.start <= addr <= self.end

    def __repr__(self) -> str:
        return f"MemoryDomain({self.name}, 0x{self.start:08X}-0x{self.end:08X}, {self.permissions})"


class TruePicIIIMemoryMap:
    """
    Authoritative memory map for the TruePic III processor (Sanyo SG155 platform).
    Defines 8 physical memory domains spanning 0x40000000 to 0xE081FFFF.
    """

    DOMAINS: List[MemoryDomain] = [
        MemoryDomain(
            "Section 1 SDRAM (NPROG)",
            0x40000000,
            0x403F50E7,
            MemoryPermission.RX,
            "SDRAM (Cached) Section 1 Program Code",
        ),
        MemoryDomain(
            "Section 2 SDRAM (NDATA)",
            0x403F5108,
            0x40855967,
            MemoryPermission.RO,
            "SDRAM / Flash (Cached) Section 2 Resources & Data",
        ),
        MemoryDomain(
            "Uncached RAM Buffers",
            0x41F00000,
            0x41F7FFFF,
            MemoryPermission.RW,
            "SDRAM (Uncached) Video & DMA Buffers",
        ),
        MemoryDomain(
            "System State Blackboard",
            0x41F80000,
            0x41F9FFFF,
            MemoryPermission.RW,
            "SDRAM Master State Blackboard",
        ),
        MemoryDomain(
            "Banked Task Stacks",
            0x41FA0000,
            0x41FD0000,
            MemoryPermission.RW,
            "SDRAM Banked Task Stacks & User Stack",
        ),
        MemoryDomain(
            "MMIO SDRAM Controller",
            0x80410000,
            0x8041FFFF,
            MemoryPermission.RW_MMIO,
            "MMIO SDRAM Controller & Timings",
        ),
        MemoryDomain(
            "MMIO DMA & NAND Controller",
            0xC04C0000,
            0xC04CFFFF,
            MemoryPermission.RW_MMIO,
            "MMIO DMA & NAND Flash Controller",
        ),
        MemoryDomain(
            "MMIO Timers/Interrupts/DAC/ISP",
            0xE0010000,
            0xE081FFFF,
            MemoryPermission.RW_MMIO,
            "MMIO Timers, Interrupt, Video DAC, Keypad, ISP",
        ),
    ]

    @classmethod
    def classify_address(cls, addr: int) -> Optional[str]:
        """Return the canonical domain name if the address resides in a valid domain, else None."""
        for d in cls.DOMAINS:
            if d.contains(addr):
                return d.name
        return None

    @classmethod
    def is_valid_address(cls, addr: int) -> bool:
        """Predicate checking whether an address falls within any physical TruePic III domain."""
        return cls.classify_address(addr) is not None

    @classmethod
    def get_domain(cls, addr: int) -> Optional[MemoryDomain]:
        """Return the MemoryDomain instance containing the address, or None."""
        for d in cls.DOMAINS:
            if d.contains(addr):
                return d
        return None


def is_valid_truepic_address(addr: int) -> bool:
    """Validate if an address falls strictly within known physical TruePic III domains."""
    return TruePicIIIMemoryMap.is_valid_address(addr)


def get_truepic_domain(addr: int) -> Optional[str]:
    """Return the domain name for a given TruePic III address, or None if invalid."""
    return TruePicIIIMemoryMap.classify_address(addr)
