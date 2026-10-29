"""
olympus_re/analysis/literal_pool.py - Literal Pool Extraction & TruePic III Classifier
"""

from dataclasses import dataclass
import struct
from typing import Dict, List, Optional, Set, Tuple

from olympus_re.models.memory_map import TruePicIIIMemoryMap
from olympus_re.models.symbols import LiteralPoolEntry, Symbol


class LiteralPoolClassifier:
    """Extracts PC-relative literals and classifies them into TruePic III domains."""

    def __init__(self, section1_bytes: bytes, base_address: int = 0x40000000):
        self.code = section1_bytes
        self.base_address = base_address
        self.end_address = base_address + len(section1_bytes) - 1

    @classmethod
    def classify_address(cls, addr: int) -> Optional[str]:
        return TruePicIIIMemoryMap.classify_address(addr)

    @classmethod
    def is_valid_address(cls, addr: int) -> bool:
        return TruePicIIIMemoryMap.is_valid_address(addr)

    def analyze(self) -> List[LiteralPoolEntry]:
        """Scan Section 1 for PC-relative LDRs and extract valid physical pointers."""
        if len(self.code) < 4:
            return []

        results: List[LiteralPoolEntry] = []
        seen_pools: Set[int] = set()

        total_len = len(self.code) - (len(self.code) % 4)

        for offset in range(0, total_len, 4):
            pc = self.base_address + offset
            word = struct.unpack("<I", self.code[offset : offset + 4])[0]

            # Check for LDR Rt, [PC, #+/-imm12]
            # Pattern: (word & 0x0E5F0000) == 0x041F0000
            if (word & 0x0E5F0000) == 0x041F0000:
                u_bit = (word >> 23) & 1
                imm12 = word & 0xFFF
                rd = (word >> 12) & 0xF
                pool_addr = (pc + 8 + imm12) if u_bit else (pc + 8 - imm12)

                # Check if pool address is inside Section 1 binary
                if self.base_address <= pool_addr <= self.end_address - 3:
                    pool_off = pool_addr - self.base_address
                    val = struct.unpack("<I", self.code[pool_off : pool_off + 4])[0]

                    # Filter: Must reside strictly in a valid TruePic III domain
                    domain = self.classify_address(val)
                    if domain is not None:
                        # Reject unaligned code pointers in Section 1
                        if domain == "Section 1 SDRAM (NPROG)" and (val % 4 != 0):
                            continue

                        results.append(
                            LiteralPoolEntry(
                                address=pool_addr,
                                target_address=val,
                                target_domain=domain,
                                register=f"r{rd}",
                                is_pointer=True,
                                metadata={
                                    "referenced_by": pc,
                                    "target_register": f"r{rd}",
                                },
                            )
                        )
                        seen_pools.add(pool_addr)

        return results
