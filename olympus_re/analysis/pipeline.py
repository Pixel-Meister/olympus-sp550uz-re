"""
olympus_re/analysis/pipeline.py - Automated Analysis Pipeline Orchestrator
"""

import csv
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from olympus_re.models.memory_map import TruePicIIIMemoryMap
from olympus_re.models.symbols import (
    Function,
    JumpTable,
    LiteralPoolEntry,
    MMIORegister,
    Symbol,
    classify_subsystem,
)
from olympus_re.analysis.function_detector import FunctionDetector
from olympus_re.analysis.jump_table_analyzer import JumpTableAnalyzer
from olympus_re.analysis.literal_pool import LiteralPoolClassifier
from olympus_re.analysis.string_extractor import StringExtractor


@dataclass
class PipelineConfig:
    """Configuration options for AnalysisPipeline."""
    section1_path: Path
    section2_path: Optional[Path] = None
    output_dir: Path = Path("output")
    docs_dir: Optional[Path] = None
    mode: str = "full"  # "full" or "fast"
    functions_only: bool = False
    strings_only: bool = False
    no_literals: bool = False
    export_formats: List[str] = field(default_factory=lambda: ["json", "csv", "jump_tables"])
    base_address_section1: int = 0x40000000
    base_address_section2: int = 0x403F5108
    min_string_len: int = 4
    verbose: bool = False


@dataclass
class PipelineStats:
    """Telemetry and execution metrics."""
    total_symbols: int = 0
    function_count: int = 0
    jump_table_count: int = 0
    string_count: int = 0
    literal_count: int = 0
    valid_address_count: int = 0
    invalid_address_count: int = 0
    duration_seconds: float = 0.0


class AnalysisPipeline:
    """Main orchestrator for firmware reverse engineering analysis and symbol export."""

    def __init__(self, config: Optional[PipelineConfig] = None, **kwargs):
        if config is not None:
            self.config = config
        else:
            self.config = PipelineConfig(**kwargs)

        self.stats = PipelineStats()
        self.symbols: List[Symbol] = []
        self.jump_tables: List[JumpTable] = []
        self._seen_addresses: Set[Tuple[int, str]] = set()

    def run(self) -> PipelineStats:
        """Execute the complete static analysis pipeline."""
        t0 = time.time()

        # 1. Load firmware binaries
        sec1_data, sec2_data = self._load_binaries()

        # 2. Inject known hardware and blackboard symbols
        self._inject_known_hardware_symbols()

        # 3. Detect functions
        if not self.config.strings_only:
            self._detect_functions(sec1_data)

        # 4. Resolve jump tables
        if not self.config.strings_only:
            self._resolve_jump_tables(sec1_data)

        # 5. Extract literal pool pointers
        if (
            not self.config.functions_only
            and not self.config.strings_only
            and not self.config.no_literals
            and self.config.mode == "full"
        ):
            self._analyze_literal_pools(sec1_data)

        # 6. Extract strings
        if not self.config.functions_only:
            self._extract_strings(sec1_data, sec2_data)

        # 7. Consolidate and validate symbols
        self._consolidate_symbols()

        # 8. Export deliverables
        self._export_deliverables()

        self.stats.duration_seconds = time.time() - t0
        return self.stats

    def _load_binaries(self) -> Tuple[bytes, bytes]:
        sec1_data = b""
        if self.config.section1_path and Path(self.config.section1_path).exists():
            with open(self.config.section1_path, "rb") as f:
                sec1_data = f.read()

        sec2_data = b""
        if self.config.section2_path and Path(self.config.section2_path).exists():
            with open(self.config.section2_path, "rb") as f:
                sec2_data = f.read()

        return sec1_data, sec2_data

    def _inject_known_hardware_symbols(self) -> None:
        """Inject authoritative blackboard variables and TruePic III MMIO registers."""
        known = [
            # Blackboard variables
            Symbol(0x41F8DDAC, "BB_SleepCountdownTimer", "blackboard_var", 4, subsystem="Power"),
            Symbol(0x41F8DDCC, "BB_MasterStateBlackboard", "blackboard_var", 4, subsystem="General"),
            Symbol(0x41F8DE6A, "BB_DisplayModeState", "blackboard_var", 2, subsystem="OSD"),
            Symbol(0x41F8DDFC, "BB_BatteryVoltageADC", "blackboard_var", 4, subsystem="Power"),
            # MMIO Peripheral Registers
            Symbol(0x80410000, "MMIO_SDRAM_TimingCtrl", "mmio_register", 4, subsystem="MMIO_SDRAM"),
            Symbol(0xC04C0000, "MMIO_NAND_CmdStatus", "mmio_register", 4, subsystem="MMIO_DMA_NAND"),
            Symbol(0xE0010040, "MMIO_TIMERS_Base", "mmio_register", 4, subsystem="MMIO_PERIPH"),
            Symbol(0xE0010000, "MMIO_INTC_Status", "mmio_register", 4, subsystem="MMIO_PERIPH"),
            Symbol(0xE0400000, "MMIO_VIDEO_DacCtrl", "mmio_register", 4, subsystem="MMIO_PERIPH"),
            Symbol(0xE0800000, "MMIO_ISP_PipelineCtrl", "mmio_register", 4, subsystem="MMIO_PERIPH"),
        ]
        for sym in known:
            if TruePicIIIMemoryMap.is_valid_address(sym.address):
                self._add_symbol(sym)

    def _detect_functions(self, sec1_data: bytes) -> None:
        if not sec1_data:
            return
        detector = FunctionDetector(sec1_data, base_address=self.config.base_address_section1)
        funcs = detector.get_functions()
        for fn in funcs:
            if TruePicIIIMemoryMap.is_valid_address(fn.address):
                self._add_symbol(fn)
                self.stats.function_count += 1

    def _resolve_jump_tables(self, sec1_data: bytes) -> None:
        if not sec1_data:
            return
        analyzer = JumpTableAnalyzer(sec1_data, base_address=self.config.base_address_section1)
        tables = analyzer.analyze()
        for tbl in tables:
            self.jump_tables.append(tbl)
            sym = tbl.to_symbol()
            if TruePicIIIMemoryMap.is_valid_address(sym.address):
                self._add_symbol(sym)
                self.stats.jump_table_count += 1

    def _analyze_literal_pools(self, sec1_data: bytes) -> None:
        if not sec1_data:
            return
        classifier = LiteralPoolClassifier(sec1_data, base_address=self.config.base_address_section1)
        entries = classifier.analyze()
        for entry in entries:
            sym = entry.to_symbol()
            if TruePicIIIMemoryMap.is_valid_address(sym.address):
                self._add_symbol(sym)
                self.stats.literal_count += 1

    def _extract_strings(self, sec1_data: bytes, sec2_data: bytes) -> None:
        extractor = StringExtractor(min_length=self.config.min_string_len)
        if sec1_data:
            s1_strings = extractor.extract_section1_ascii(sec1_data, base_address=self.config.base_address_section1)
            for s in s1_strings:
                sym = s.to_symbol()
                if TruePicIIIMemoryMap.is_valid_address(sym.address):
                    self._add_symbol(sym)
                    self.stats.string_count += 1

        if sec2_data:
            s2_strings = extractor.extract_section2_utf16le(sec2_data, base_address=self.config.base_address_section2)
            for s in s2_strings:
                sym = s.to_symbol()
                if TruePicIIIMemoryMap.is_valid_address(sym.address):
                    self._add_symbol(sym)
                    self.stats.string_count += 1

    def _add_symbol(self, sym: Symbol) -> None:
        key = (sym.address, sym.type)
        if key not in self._seen_addresses:
            self._seen_addresses.add(key)
            self.symbols.append(sym)

    def _consolidate_symbols(self) -> None:
        """Deduplicate symbols, validate addresses, and sort deterministically."""
        # Priority order when collision occurs at identical address:
        # function > jump_table > mmio_register > blackboard_var > literal_pointer > string
        priority = {
            "function": 1,
            "jump_table": 2,
            "mmio_register": 3,
            "blackboard_var": 4,
            "literal_pointer": 5,
            "string": 6,
        }

        addr_map: Dict[int, List[Symbol]] = {}
        for s in self.symbols:
            # 100% address validity constraint
            if not TruePicIIIMemoryMap.is_valid_address(s.address):
                self.stats.invalid_address_count += 1
                continue

            # Validate pointer target if present
            if "pointer_target" in s.metadata:
                pt = s.metadata["pointer_target"]
                if pt is not None and not TruePicIIIMemoryMap.is_valid_address(pt):
                    self.stats.invalid_address_count += 1
                    continue

            self.stats.valid_address_count += 1
            addr_map.setdefault(s.address, []).append(s)

        consolidated: List[Symbol] = []
        for addr, sym_list in addr_map.items():
            if len(sym_list) == 1:
                consolidated.append(sym_list[0])
            else:
                sym_list.sort(key=lambda x: priority.get(x.type, 99))
                best = sym_list[0]
                # Merge secondary names/metadata if applicable
                consolidated.append(best)

        consolidated.sort(key=lambda s: s.address)
        self.symbols = consolidated
        self.stats.total_symbols = len(self.symbols)

    def _export_deliverables(self) -> None:
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        formats = self.config.export_formats
        export_all = "all" in formats
        export_json = export_all or "json" in formats
        export_csv = export_all or "csv" in formats
        export_jump_tables = export_all or "jump_tables" in formats

        if export_json:
            symbols_path = out_dir / "symbols.json"
            symbols_dicts = [s.to_dict() for s in self.symbols]
            with open(symbols_path, "w", encoding="utf-8") as f:
                json.dump(symbols_dicts, f, indent=2)

        if export_csv:
            csv_path = out_dir / "symbols.csv"
            fieldnames = ["address", "name", "type", "size", "domain", "subsystem", "metadata"]
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for s in self.symbols:
                    writer.writerow({
                        "address": f"0x{s.address:08X}",
                        "name": s.name,
                        "type": s.type,
                        "size": s.size,
                        "domain": s.domain,
                        "subsystem": s.subsystem,
                        "metadata": json.dumps(s.metadata) if s.metadata else "{}",
                    })

        if export_jump_tables:
            jt_path = out_dir / "jump_tables.json"
            jt_dicts = [t.to_dict() for t in self.jump_tables]
            with open(jt_path, "w", encoding="utf-8") as f:
                json.dump(jt_dicts, f, indent=2)
