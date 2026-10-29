#!/usr/bin/env python3
"""
tests/validate_v1_analysis.py - V1 Acceptance Criteria Validator
================================================================
Validates Structural & Static Analysis Validity for the Olympus SP-550UZ
reverse engineering framework.

Requirements Verified:
1. 100% of extracted function addresses and memory pointers fall within
   authoritative physical memory ranges:
   - 0x40000000 - 0x40855967 (Section 1 SDRAM + Section 2 NDATA)
   - 0x41F00000 - 0x41FD0000 (Uncached SDRAM + System Blackboard + Stacks)
   - 0x80410000 - 0x8041FFFF (MMIO SDRAM Controller)
   - 0xC04C0000 - 0xC04CFFFF (MMIO DMA & NAND Controller)
   - 0xE0000000 - 0xE081FFFF (MMIO Timers, Interrupt, Video DAC, ISP)
2. At least 2,500 distinct function entry points across Section 1 are identified
   and labeled with valid non-empty names.
3. Jump tables are fully resolved with target destinations documented:
   - OSD dispatcher at 0x401b3324 (25 entries, bounds <= 0x18)
   - RTOS event dispatcher at 0x4019e324 (16 entries, bounds <= 0x0F)

Dual Execution Mode:
- CLI Mode: `python3 tests/validate_v1_analysis.py [--symbols path] [--jump-tables path] [-v]`
- Test Mode: `python3 -m unittest tests/validate_v1_analysis.py`
"""

import argparse
import csv
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import unittest

_curr = Path(__file__).resolve()
_project_root = _curr.parent
while _project_root != _project_root.parent:
    if (_project_root / "Resources").exists() and (_project_root / "tests").exists():
        break
    _project_root = _project_root.parent

if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from tests.support import (
    KNOWN_OSD_ENTRY_COUNT,
    KNOWN_OSD_TABLE_ADDR,
    KNOWN_OSD_TARGETS,
    KNOWN_RTOS_ENTRY_COUNT,
    KNOWN_RTOS_TABLE_ADDR,
    KNOWN_RTOS_TARGETS,
    MIN_REQUIRED_FUNCTIONS,
    SECTION1_PATH,
    VALID_PHYSICAL_MEMORY_RANGES,
    is_valid_physical_address,
)

SECTION1_START = 0x40000000
SECTION1_END = 0x403F50E7


@dataclass
class ValidationStats:
    total_symbols: int = 0
    valid_address_count: int = 0
    invalid_addresses: List[Dict[str, Any]] = field(default_factory=list)
    section1_functions: Set[int] = field(default_factory=set)
    unlabeled_functions: List[int] = field(default_factory=list)
    unaligned_functions: List[int] = field(default_factory=list)
    jump_tables_checked: int = 0
    jump_tables_resolved: List[Dict[str, Any]] = field(default_factory=list)
    jump_table_errors: List[str] = field(default_factory=list)


class V1AnalysisValidator:
    """Core validator implementing Acceptance Criterion V1 assertions."""

    def __init__(
        self,
        symbols_path: Optional[Path] = None,
        jump_tables_path: Optional[Path] = None,
        csv_path: Optional[Path] = None,
        min_functions: int = MIN_REQUIRED_FUNCTIONS,
    ):
        self.symbols_path = symbols_path or Path("output/symbols.json")
        self.jump_tables_path = jump_tables_path or Path("output/jump_tables.json")
        self.csv_path = csv_path or Path("output/symbols.csv")
        self.min_functions = min_functions
        self.stats = ValidationStats()
        self.symbols: List[Dict[str, Any]] = []
        self.jump_tables: List[Dict[str, Any]] = []
        self.source_mode: str = "none"
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def load_data(self) -> None:
        """Load symbols and jump table records from disk.

        Acceptance Criterion V1 strictly mandates running against the generated
        symbol database. If output/symbols.json (or output/symbols.csv) is absent,
        it records a deliverable error rather than silently falling back to raw firmware.
        """
        if self.symbols_path.exists():
            with open(self.symbols_path, "r", encoding="utf-8") as f:
                self.symbols = json.load(f)
            self.source_mode = "json"
        elif self.csv_path.exists():
            self._load_from_csv()
            self.source_mode = "csv"
        else:
            self.source_mode = "missing"
            self.errors.append(
                f"Generated symbol database deliverable not found ({self.symbols_path} or {self.csv_path}). "
                "Acceptance Criterion V1 requires running against the generated symbol database."
            )
            return

        if self.jump_tables_path.exists():
            with open(self.jump_tables_path, "r", encoding="utf-8") as f:
                self.jump_tables = json.load(f)
        else:
            # Fallback: check if jump tables are embedded in symbols database
            embedded = []
            for sym in self.symbols:
                if sym.get("type") == "jump_table" or "targets" in sym.get("metadata", {}):
                    embedded.append({
                        "table_address": sym.get("address"),
                        "entry_count": sym.get(
                            "size", len(sym.get("metadata", {}).get("targets", []))
                        ),
                        "targets": sym.get("metadata", {}).get("targets", []),
                        "bounds": sym.get("metadata", {}).get("bounds", ""),
                        "default_target": sym.get("metadata", {}).get("default_target", 0),
                    })
            if embedded:
                self.jump_tables = embedded
            else:
                self.errors.append(
                    f"Jump table database deliverable not found ({self.jump_tables_path}) "
                    "and no embedded jump tables found in symbol database."
                )

    def _load_from_csv(self) -> None:
        """Parse spreadsheet-compatible CSV export."""
        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr_raw = row.get("address", "0")
                addr = int(addr_raw, 16) if addr_raw.startswith("0x") else int(addr_raw)
                meta_raw = row.get("metadata", "{}")
                try:
                    meta = json.loads(meta_raw) if meta_raw else {}
                except json.JSONDecodeError:
                    meta = {}
                self.symbols.append({
                    "address": addr,
                    "name": row.get("name", ""),
                    "type": row.get("type", "unknown"),
                    "size": int(row.get("size", "4")),
                    "domain": row.get("domain", ""),
                    "subsystem": row.get("subsystem", ""),
                    "metadata": meta,
                })

    def validate_memory_ranges(self) -> None:
        """Assert 100% of symbols and pointers reside in physical memory."""
        for sym in self.symbols:
            self.stats.total_symbols += 1
            addr = sym.get("address", 0)
            if not is_valid_physical_address(addr):
                self.stats.invalid_addresses.append({
                    "address": hex(addr),
                    "name": sym.get("name", "<unnamed>"),
                    "type": sym.get("type", "<unknown>"),
                    "reason": "Address outside physical memory ranges",
                })
            else:
                self.stats.valid_address_count += 1

            meta = sym.get("metadata", {})
            if "pointer_target" in meta:
                target = meta["pointer_target"]
                if target is not None and not is_valid_physical_address(target):
                    self.stats.invalid_addresses.append({
                        "address": hex(target),
                        "name": f"{sym.get('name')}->target",
                        "type": "literal_pointer",
                        "reason": "Pointer target outside physical memory",
                    })

    def validate_functions(self) -> None:
        """Assert Section 1 has >= 2,500 labeled functions."""
        for sym in self.symbols:
            if sym.get("type") == "function":
                addr = sym.get("address", 0)
                if SECTION1_START <= addr <= SECTION1_END:
                    self.stats.section1_functions.add(addr)
                    name = sym.get("name", "").strip()
                    if not name:
                        self.stats.unlabeled_functions.append(addr)
                    if addr % 4 != 0:
                        self.stats.unaligned_functions.append(addr)

    def validate_jump_tables(self) -> None:
        """Assert OSD and RTOS jump tables are completely resolved."""
        table_map = {t.get("table_address"): t for t in self.jump_tables}

        # 1. Validate OSD Jump Table
        if KNOWN_OSD_TABLE_ADDR not in table_map:
            self.stats.jump_table_errors.append(
                f"OSD Jump Table at {hex(KNOWN_OSD_TABLE_ADDR)} is missing from jump table database"
            )
        else:
            osd = table_map[KNOWN_OSD_TABLE_ADDR]
            self.stats.jump_tables_checked += 1
            targets = osd.get("targets", [])
            entry_count = osd.get("entry_count", len(targets))

            if entry_count != KNOWN_OSD_ENTRY_COUNT:
                self.stats.jump_table_errors.append(
                    f"OSD Jump Table entry count mismatch: expected {KNOWN_OSD_ENTRY_COUNT}, got {entry_count}"
                )

            for idx, expected in KNOWN_OSD_TARGETS.items():
                if idx < len(targets):
                    actual = targets[idx]
                    if actual != expected:
                        self.stats.jump_table_errors.append(
                            f"OSD entry {idx} target mismatch: expected {hex(expected)}, got {hex(actual)}"
                        )
                else:
                    self.stats.jump_table_errors.append(f"OSD entry {idx} is missing from resolved targets")

            for idx, target in enumerate(targets):
                if not (SECTION1_START <= target <= SECTION1_END):
                    self.stats.jump_table_errors.append(
                        f"OSD target {idx} ({hex(target)}) outside Section 1 code range"
                    )

            self.stats.jump_tables_resolved.append({
                "name": "OSD Dispatcher",
                "address": hex(KNOWN_OSD_TABLE_ADDR),
                "entries": len(targets),
                "status": "VALID" if not self.stats.jump_table_errors else "ERROR",
            })

        # 2. Validate RTOS Event Jump Table
        if KNOWN_RTOS_TABLE_ADDR not in table_map:
            self.stats.jump_table_errors.append(
                f"RTOS Event Jump Table at {hex(KNOWN_RTOS_TABLE_ADDR)} is missing from jump table database"
            )
        else:
            rtos = table_map[KNOWN_RTOS_TABLE_ADDR]
            self.stats.jump_tables_checked += 1
            targets = rtos.get("targets", [])
            entry_count = rtos.get("entry_count", len(targets))

            if entry_count != KNOWN_RTOS_ENTRY_COUNT:
                self.stats.jump_table_errors.append(
                    f"RTOS Jump Table entry count mismatch: expected {KNOWN_RTOS_ENTRY_COUNT}, got {entry_count}"
                )

            for idx, expected in KNOWN_RTOS_TARGETS.items():
                if idx < len(targets):
                    actual = targets[idx]
                    if actual != expected:
                        self.stats.jump_table_errors.append(
                            f"RTOS entry {idx} target mismatch: expected {hex(expected)}, got {hex(actual)}"
                        )
                else:
                    self.stats.jump_table_errors.append(f"RTOS entry {idx} is missing from resolved targets")

            for idx, target in enumerate(targets):
                if not (SECTION1_START <= target <= SECTION1_END):
                    self.stats.jump_table_errors.append(
                        f"RTOS target {idx} ({hex(target)}) outside Section 1 code range"
                    )

            self.stats.jump_tables_resolved.append({
                "name": "RTOS Event Dispatcher",
                "address": hex(KNOWN_RTOS_TABLE_ADDR),
                "entries": len(targets),
                "status": "VALID",
            })

    def run_all(self) -> bool:
        """Execute full validation suite and return overall boolean result."""
        self.load_data()

        if self.source_mode == "missing":
            return False

        self.validate_memory_ranges()
        self.validate_functions()
        self.validate_jump_tables()

        passed = (
            len(self.errors) == 0
            and len(self.stats.invalid_addresses) == 0
            and len(self.stats.section1_functions) >= self.min_functions
            and len(self.stats.unlabeled_functions) == 0
            and len(self.stats.unaligned_functions) == 0
            and len(self.stats.jump_table_errors) == 0
            and self.stats.jump_tables_checked >= 2
        )
        return passed


# ==============================================================================
# Unittest TestCase Suite
# ==============================================================================

class TestV1AnalysisValidity(unittest.TestCase):
    """Standard unittest suite for CI / test discovery."""

    def setUp(self):
        self.validator = V1AnalysisValidator()
        if not self.validator.symbols_path.exists() and not self.validator.csv_path.exists():
            self.skipTest(
                f"Generated symbol database deliverable not found at {self.validator.symbols_path} (Milestone M1 planned)"
            )
        self.validator.load_data()

    def test_01_all_symbols_within_physical_memory_ranges(self):
        """Assert 100% of extracted symbols reside in TruePic III memory."""
        self.validator.validate_memory_ranges()
        self.assertEqual(
            len(self.validator.stats.invalid_addresses),
            0,
            f"Found {len(self.validator.stats.invalid_addresses)} invalid addresses: "
            f"{self.validator.stats.invalid_addresses[:5]}",
        )
        self.assertGreater(self.validator.stats.valid_address_count, 0)

    def test_02_section1_function_count_and_labeling(self):
        """Assert >= 2,500 distinct 4-byte aligned labeled functions."""
        self.validator.validate_functions()
        func_count = len(self.validator.stats.section1_functions)
        self.assertGreaterEqual(
            func_count,
            MIN_REQUIRED_FUNCTIONS,
            f"Expected at least {MIN_REQUIRED_FUNCTIONS} functions, got {func_count}",
        )
        self.assertEqual(
            len(self.validator.stats.unlabeled_functions),
            0,
            f"Found unlabeled functions: {self.validator.stats.unlabeled_functions[:5]}",
        )
        self.assertEqual(
            len(self.validator.stats.unaligned_functions),
            0,
            f"Found unaligned function addresses: {self.validator.stats.unaligned_functions[:5]}",
        )

    def test_03_osd_and_rtos_jump_tables_resolved(self):
        """Assert OSD (25 entries) and RTOS (16 entries) jump tables are resolved."""
        self.validator.validate_jump_tables()
        self.assertEqual(
            len(self.validator.stats.jump_table_errors),
            0,
            f"Jump table validation failed with errors: {self.validator.stats.jump_table_errors}",
        )
        self.assertGreaterEqual(self.validator.stats.jump_tables_checked, 2)


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate V1 Structural & Static Analysis")
    parser.add_argument(
        "--symbols", type=Path, default=Path("output/symbols.json"), help="Symbols JSON path"
    )
    parser.add_argument(
        "--jump-tables",
        type=Path,
        default=Path("output/jump_tables.json"),
        help="Jump tables JSON path",
    )
    parser.add_argument("--csv", type=Path, default=Path("output/symbols.csv"), help="Symbols CSV path")
    parser.add_argument(
        "--min-functions", type=int, default=MIN_REQUIRED_FUNCTIONS, help="Minimum function count"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose diagnostics")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print(" Olympus SP-550UZ RE: V1 Structural & Static Analysis Validator")
    print("=" * 70)

    validator = V1AnalysisValidator(
        symbols_path=args.symbols,
        jump_tables_path=args.jump_tables,
        csv_path=args.csv,
        min_functions=args.min_functions,
    )

    try:
        passed = validator.run_all()
    except Exception as exc:
        print(f"\n[-] ERROR: Validation terminated prematurely: {exc}")
        return 1

    stats = validator.stats

    print(f"\n[*] Target Deliverables Under Validation:")
    print(
        f"    Symbol Database:      {validator.symbols_path} ({'Found' if validator.symbols_path.exists() else 'Missing'})"
    )
    print(
        f"    Jump Table Database:  {validator.jump_tables_path} ({'Found' if validator.jump_tables_path.exists() else 'Missing'})"
    )

    print(f"\n[*] Data Source Mode: {validator.source_mode}")
    print(f"[*] Symbol Ingestion Statistics:")
    print(f"    Total Symbols Ingested:    {stats.total_symbols:,}")
    valid_pct = (
        (stats.valid_address_count / stats.total_symbols * 100.0)
        if stats.total_symbols > 0
        else 0.0
    )
    print(f"    Valid Address Count:       {stats.valid_address_count:,} ({valid_pct:.1f}%)")
    print(f"    Invalid Address Count:     {len(stats.invalid_addresses)}")

    print(f"\n[*] Section 1 Function Discovery:")
    print(
        f"    Distinct Functions:        {len(stats.section1_functions):,} (Required: >={args.min_functions:,})"
    )
    print(f"    Unlabeled Functions:       {len(stats.unlabeled_functions)}")
    print(f"    Unaligned Addresses:       {len(stats.unaligned_functions)}")

    print(f"\n[*] Jump Table Resolution:")
    print(f"    Tables Validated:          {stats.jump_tables_checked}")
    for tbl in stats.jump_tables_resolved:
        print(f"    - {tbl['name']} ({tbl['address']}): {tbl['entries']} entries [{tbl['status']}]")

    if validator.errors:
        print("\n[-] Validation Errors Detected:")
        for err in validator.errors:
            print(f"    * {err}")

    if stats.jump_table_errors:
        print("\n[-] Jump Table Errors:")
        for err in stats.jump_table_errors:
            print(f"    * {err}")

    if stats.invalid_addresses and args.verbose:
        print("\n[-] First 10 Invalid Addresses:")
        for inv in stats.invalid_addresses[:10]:
            print(f"    * {inv['address']}: {inv['name']} ({inv['type']}) - {inv['reason']}")

    print("\n" + "-" * 70)
    if passed:
        print("[+] RESULT: ACCEPTANCE CRITERION V1 PASSED (100% Conformance)")
        print("-" * 70 + "\n")
        return 0
    else:
        if validator.source_mode == "missing" or not validator.symbols_path.exists():
            print("[-] RESULT: ACCEPTANCE CRITERION V1 FAILED (Target deliverables missing)")
        else:
            print("[-] RESULT: ACCEPTANCE CRITERION V1 FAILED")
        print("-" * 70 + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
