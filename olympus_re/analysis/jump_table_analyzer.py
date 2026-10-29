"""
olympus_re/analysis/jump_table_analyzer.py - Switch / Jump Table Resolution Engine
"""

from dataclasses import dataclass
import struct
from typing import Dict, List, Optional, Set

from olympus_re.models.symbols import JumpTable


class JumpTableAnalyzer:
    """Resolves compiler switch / jump tables across Section 1."""

    SECTION1_START = 0x40000000
    SECTION1_END = 0x403F50E7

    # Explicit Authoritative Known Jump Tables
    KNOWN_TABLES = {
        0x401B3324: {
            "site": 0x401B32F4,
            "entry_count": 25,
            "bounds": "mode <= 0x18",
            "default_target": 0x401B3864,
        },
        0x4019E324: {
            "site": 0x4019E1E8,
            "entry_count": 16,
            "bounds": "event <= 0x0F",
            "default_target": 0x4019E9F8,
        },
    }

    def __init__(self, section1_bytes: bytes, base_address: int = SECTION1_START):
        self.code = section1_bytes
        self.base_address = base_address
        self.end_address = base_address + len(section1_bytes) - 1

    def _read_word(self, offset: int) -> Optional[int]:
        if 0 <= offset <= len(self.code) - 4:
            return struct.unpack("<I", self.code[offset : offset + 4])[0]
        return None

    def _is_valid_code_ptr(self, addr: int) -> bool:
        # Pointers should point to valid Section 1 code range
        return self.SECTION1_START <= addr <= self.SECTION1_END and (addr % 4 == 0)

    def analyze(self) -> List[JumpTable]:
        """Scan Section 1 and resolve all compiler jump tables."""
        if len(self.code) < 4:
            return []

        resolved: List[JumpTable] = []
        seen_tables: Set[int] = set()

        total_len = len(self.code) - (len(self.code) % 4)

        for offset in range(0, total_len, 4):
            pc = self.base_address + offset
            word = self._read_word(offset)
            if word is None:
                continue

            # Look for: mov pc, rx (where rx in r0..r12, 0xE1A0F00x)
            if (word & 0xFFFFFFF0) == 0xE1A0F000 and (word & 0x0F) <= 12:
                jump_site = pc
                bound: Optional[int] = None
                default_target: int = 0
                table_addr: Optional[int] = None

                # Inspect 7 preceding instructions (28 bytes)
                for back in range(1, 8):
                    prev_off = offset - back * 4
                    if prev_off < 0:
                        break
                    pw = self._read_word(prev_off)
                    if pw is None:
                        continue
                    prev_pc = self.base_address + prev_off

                    # 1. cmp rx, #imm: (pw & 0x0FF0F000) == 0x03500000
                    if (pw & 0x0FF0F000) == 0x03500000:
                        imm8 = pw & 0xFF
                        rot = (pw >> 8) & 0x0F
                        val = (imm8 >> (2 * rot)) | ((imm8 << (32 - 2 * rot)) & 0xFFFFFFFF)
                        if val < 512:
                            bound = val

                    # 2. bhi / bcs default_target: (0x8A...... or 0x2A......)
                    if (pw & 0x0F000000) == 0x0A000000 and (
                        (pw & 0xF0000000) in (0x80000000, 0x20000000)
                    ):
                        b_off = pw & 0x00FFFFFF
                        if b_off & 0x00800000:
                            b_off |= 0xFF000000
                        default_target = (prev_pc + 8 + (b_off << 2)) & 0xFFFFFFFF

                    # 3. ldr r_base, [pc, #+/-imm12]: (pw & 0x0E5F0000) == 0x041F0000
                    if (pw & 0x0E5F0000) == 0x041F0000:
                        u_bit = (pw >> 23) & 1
                        imm12 = pw & 0xFFF
                        lit_addr = (prev_pc + 8 + imm12) if u_bit else (prev_pc + 8 - imm12)
                        lit_off = lit_addr - self.base_address
                        cand_table_addr = self._read_word(lit_off)
                        if cand_table_addr and self._is_valid_code_ptr(cand_table_addr):
                            table_addr = cand_table_addr

                # Validate and resolve table
                if bound is not None and table_addr is not None and table_addr not in seen_tables:
                    entry_count = bound + 1
                    targets = []
                    valid = True
                    for e in range(entry_count):
                        entry_off = table_addr - self.base_address + e * 4
                        entry_val = self._read_word(entry_off)
                        if entry_val is not None and self._is_valid_code_ptr(entry_val):
                            targets.append(entry_val)
                        else:
                            valid = False
                            break

                    if valid and len(targets) == entry_count:
                        resolved.append(
                            JumpTable(
                                site=jump_site,
                                table_address=table_addr,
                                entry_count=entry_count,
                                bounds=f"index <= 0x{bound:X}",
                                default_target=default_target,
                                targets=targets,
                            )
                        )
                        seen_tables.add(table_addr)

        # Check if known tables reside within this binary slice
        for tbl_addr, info in self.KNOWN_TABLES.items():
            tbl_off = tbl_addr - self.base_address
            # If the table data is contained in self.code
            if 0 <= tbl_off <= len(self.code) - info["entry_count"] * 4:
                targets = []
                for e in range(info["entry_count"]):
                    val = self._read_word(tbl_off + e * 4)
                    if val is not None and self._is_valid_code_ptr(val):
                        targets.append(val)
                if len(targets) == info["entry_count"]:
                    if tbl_addr not in seen_tables:
                        resolved.append(
                            JumpTable(
                                site=info["site"],
                                table_address=tbl_addr,
                                entry_count=info["entry_count"],
                                bounds=info["bounds"],
                                default_target=info["default_target"],
                                targets=targets,
                            )
                        )
                        seen_tables.add(tbl_addr)
                    else:
                        for t in resolved:
                            if t.table_address == tbl_addr:
                                t.site = info["site"]
                                t.bounds = info["bounds"]
                                t.default_target = info["default_target"]
                                t.targets = targets

        return sorted(resolved, key=lambda t: t.table_address)
