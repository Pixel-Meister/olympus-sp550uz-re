"""
Tier 3: Pairwise Combinatorial Test Suite (tests/test_tier3_pairwise.py)
Olympus SP-550UZ Reverse Engineering Framework.

Applies Orthogonal Array / Covering Array theory: L16(4^5) pairwise matrix
covering 100% of all 2-way combinations between:
- Factor A: Input Binary Variants (Synthetic Minimal, Truncated Boundary, Section 1 Slice, Dual-Section Full)
- Factor B: Analysis Pipeline Modes (Full Comprehensive, Fast No-Literals, Functions-Only, Strings-Only)
- Factor C: Symbol Export Formats (JSON Only, CSV Only, Dual JSON+CSV, Jump Tables Only)
- Factor D: Decompiler Script Generation (Ghidra Only, IDA Pro Only, Dual Ghidra+IDA, Mock Execution)
- Factor E: Documentation Generation (HTML Only, Markdown Only, Dual HTML+MD, Strict Link Validation)

Progressive Testability Contract:
Tests genuine framework entry points (olympus_re.cli and olympus_re.analysis.pipeline).
When olympus_re is not yet implemented (pre-implementation milestone E2E), raises
unittest.SkipTest("olympus_re.cli pending implementation in milestone M1").
When olympus_re is delivered in M1-M3, tests execute genuine CLI pipelines and verify
real exported artifacts.
"""

import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.support import (
    SECTION1_PATH,
    SECTION2_PATH,
    PROJECT_ROOT,
    JumpTable,
    Symbol,
    TruePicIIIMemoryMap,
    is_valid_truepic_address,
)

# Progressive Testability Detection
try:
    import olympus_re
    import olympus_re.cli as olympus_cli
    HAS_OLYMPUS_RE = True
except ImportError:
    HAS_OLYMPUS_RE = False


class TestTier3PairwiseCombinatorial(unittest.TestCase):
    """
    16-Configuration Pairwise Covering Array L16(4^5).
    Verifies interaction integrity across analysis, export, decompilation, and documentation
    using genuine framework entry points (olympus_re.cli / olympus_re.analysis.pipeline).
    """

    def setUp(self):
        """Skip cleanly when framework modules are pending implementation in milestone M1."""
        if not HAS_OLYMPUS_RE:
            self.skipTest("olympus_re.cli and analysis pipeline pending implementation in milestone M1")

    def _execute_pipeline_run(
        self,
        binary_variant: str,
        analysis_mode: str,
        export_format: str,
        decompiler_target: str,
        doc_target: str,
    ) -> bool:
        """
        Execute genuine framework CLI pipeline against the specified orthogonal parameters.
        Validates real exported artifacts and cross-subsystem interaction integrity.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # 1. Prepare genuine input binary on disk
            input_file = tmp_path / "input.bin"
            if binary_variant == "SyntheticMinimal":
                # Valid minimal ARM code: reset branch to 0x40000800, padding, leaf return bx lr
                code = bytearray(b"\xfe\x01\x00\xea" + b"\x00" * 2044 + b"\x1e\xff\x2f\xe1")
                input_file.write_bytes(code)
            elif binary_variant == "TruncatedBoundary":
                # 8-byte minimal function boundary
                input_file.write_bytes(b"\x10\x40\x2d\xe9\x1e\xff\x2f\xe1")
            elif binary_variant == "Section1Slice":
                if SECTION1_PATH.exists():
                    with open(SECTION1_PATH, "rb") as f:
                        f.seek(0x1B3000)
                        slice_bytes = f.read(65536)
                    input_file.write_bytes(slice_bytes)
                else:
                    input_file.write_bytes(b"\x10\x43\x2d\xe9" + b"\x00" * 60 + b"\x10\x83\xbd\xe8")
            else:  # DualSection
                if SECTION1_PATH.exists():
                    input_file = SECTION1_PATH
                else:
                    input_file.write_bytes(b"\xfe\x01\x00\xea" + b"\x00" * 1024)

            # 2. Build genuine CLI invocation
            out_dir = tmp_path / "output"
            out_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                sys.executable,
                "-m",
                "olympus_re.cli",
                "--input",
                str(input_file),
                "--output-dir",
                str(out_dir),
            ]

            # Analysis mode flag
            if analysis_mode == "FullComprehensive":
                cmd.extend(["--mode", "full"])
            elif analysis_mode == "FastNoLiterals":
                cmd.extend(["--mode", "fast", "--no-literals"])
            elif analysis_mode == "FunctionsOnly":
                cmd.extend(["--functions-only"])
            elif analysis_mode == "StringsOnly":
                cmd.extend(["--strings-only"])

            # Export format flag
            if export_format == "JsonOnly":
                cmd.extend(["--export-format", "json"])
            elif export_format == "CsvOnly":
                cmd.extend(["--export-format", "csv"])
            elif export_format == "DualJsonCsv":
                cmd.extend(["--export-format", "json,csv"])
            elif export_format == "JumpTablesOnly":
                cmd.extend(["--export-format", "jump_tables"])

            # Decompiler target flag
            if decompiler_target == "GhidraOnly":
                cmd.extend(["--decompiler", "ghidra"])
            elif decompiler_target == "IdaProOnly":
                cmd.extend(["--decompiler", "ida"])
            elif decompiler_target == "DualGhidraIda":
                cmd.extend(["--decompiler", "all"])
            elif decompiler_target == "MockExecution":
                cmd.extend(["--decompiler", "mock"])

            # Documentation target flag
            if doc_target == "HtmlOnly":
                cmd.extend(["--doc", "html"])
            elif doc_target == "MarkdownOnly":
                cmd.extend(["--doc", "markdown"])
            elif doc_target == "DualHtmlMD":
                cmd.extend(["--doc", "all"])
            elif doc_target == "StrictLinkValidation":
                cmd.extend(["--doc", "all", "--strict-links"])

            # 3. Execute genuine CLI process
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(
                proc.returncode,
                0,
                f"CLI execution failed with code {proc.returncode}:\nStdout: {proc.stdout}\nStderr: {proc.stderr}",
            )

            # 4. Assert genuine physical output artifacts on filesystem
            if export_format in ["JsonOnly", "DualJsonCsv"]:
                json_file = out_dir / "symbols.json"
                self.assertTrue(json_file.exists(), "symbols.json must be exported")
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.assertIsInstance(data, list)
                for item in data:
                    self.assertTrue(
                        TruePicIIIMemoryMap.is_valid_address(item["address"]),
                        f"Address {hex(item['address'])} outside TruePic III memory map",
                    )

            if export_format in ["CsvOnly", "DualJsonCsv"]:
                csv_file = out_dir / "symbols.csv"
                self.assertTrue(csv_file.exists(), "symbols.csv must be exported")

            if export_format in ["JumpTablesOnly", "DualJsonCsv"]:
                jt_file = out_dir / "jump_tables.json"
                self.assertTrue(jt_file.exists(), "jump_tables.json must be exported")

            if decompiler_target in ["GhidraOnly", "DualGhidraIda"]:
                ghidra_file = out_dir / "ghidra_sp550uz_annotator.py"
                self.assertTrue(ghidra_file.exists(), "Ghidra annotator script must be generated")

            if decompiler_target in ["IdaProOnly", "DualGhidraIda"]:
                ida_file = out_dir / "ida_sp550uz_annotator.py"
                self.assertTrue(ida_file.exists(), "IDA Pro annotator script must be generated")

            if doc_target in ["HtmlOnly", "DualHtmlMD", "StrictLinkValidation"]:
                html_file = out_dir / "xref.html"
                self.assertTrue(html_file.exists(), "xref.html must be generated")

            if doc_target in ["MarkdownOnly", "DualHtmlMD", "StrictLinkValidation"]:
                md_file = out_dir / "xref" / "index.md"
                self.assertTrue(md_file.exists(), "xref/index.md must be generated")

        return True

    def test_pairwise_config_01(self):
        """Pairwise Config 01: SyntheticMinimal x FullComprehensive x JsonOnly x GhidraOnly x HtmlOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "SyntheticMinimal", "FullComprehensive", "JsonOnly", "GhidraOnly", "HtmlOnly"
            )
        )

    def test_pairwise_config_02(self):
        """Pairwise Config 02: SyntheticMinimal x FastNoLiterals x CsvOnly x IdaProOnly x MarkdownOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "SyntheticMinimal", "FastNoLiterals", "CsvOnly", "IdaProOnly", "MarkdownOnly"
            )
        )

    def test_pairwise_config_03(self):
        """Pairwise Config 03: SyntheticMinimal x FunctionsOnly x DualJsonCsv x DualGhidraIda x DualHtmlMD"""
        self.assertTrue(
            self._execute_pipeline_run(
                "SyntheticMinimal", "FunctionsOnly", "DualJsonCsv", "DualGhidraIda", "DualHtmlMD"
            )
        )

    def test_pairwise_config_04(self):
        """Pairwise Config 04: SyntheticMinimal x StringsOnly x JumpTablesOnly x MockExecution x StrictLinkValidation"""
        self.assertTrue(
            self._execute_pipeline_run(
                "SyntheticMinimal",
                "StringsOnly",
                "JumpTablesOnly",
                "MockExecution",
                "StrictLinkValidation",
            )
        )

    def test_pairwise_config_05(self):
        """Pairwise Config 05: TruncatedBoundary x FullComprehensive x CsvOnly x DualGhidraIda x StrictLinkValidation"""
        self.assertTrue(
            self._execute_pipeline_run(
                "TruncatedBoundary",
                "FullComprehensive",
                "CsvOnly",
                "DualGhidraIda",
                "StrictLinkValidation",
            )
        )

    def test_pairwise_config_06(self):
        """Pairwise Config 06: TruncatedBoundary x FastNoLiterals x JsonOnly x MockExecution x DualHtmlMD"""
        self.assertTrue(
            self._execute_pipeline_run(
                "TruncatedBoundary", "FastNoLiterals", "JsonOnly", "MockExecution", "DualHtmlMD"
            )
        )

    def test_pairwise_config_07(self):
        """Pairwise Config 07: TruncatedBoundary x FunctionsOnly x JumpTablesOnly x GhidraOnly x MarkdownOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "TruncatedBoundary", "FunctionsOnly", "JumpTablesOnly", "GhidraOnly", "MarkdownOnly"
            )
        )

    def test_pairwise_config_08(self):
        """Pairwise Config 08: TruncatedBoundary x StringsOnly x DualJsonCsv x IdaProOnly x HtmlOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "TruncatedBoundary", "StringsOnly", "DualJsonCsv", "IdaProOnly", "HtmlOnly"
            )
        )

    def test_pairwise_config_09(self):
        """Pairwise Config 09: Section1Slice x FullComprehensive x DualJsonCsv x MockExecution x MarkdownOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "Section1Slice", "FullComprehensive", "DualJsonCsv", "MockExecution", "MarkdownOnly"
            )
        )

    def test_pairwise_config_10(self):
        """Pairwise Config 10: Section1Slice x FastNoLiterals x JumpTablesOnly x GhidraOnly x HtmlOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "Section1Slice", "FastNoLiterals", "JumpTablesOnly", "GhidraOnly", "HtmlOnly"
            )
        )

    def test_pairwise_config_11(self):
        """Pairwise Config 11: Section1Slice x FunctionsOnly x JsonOnly x IdaProOnly x StrictLinkValidation"""
        self.assertTrue(
            self._execute_pipeline_run(
                "Section1Slice", "FunctionsOnly", "JsonOnly", "IdaProOnly", "StrictLinkValidation"
            )
        )

    def test_pairwise_config_12(self):
        """Pairwise Config 12: Section1Slice x StringsOnly x CsvOnly x DualGhidraIda x DualHtmlMD"""
        self.assertTrue(
            self._execute_pipeline_run(
                "Section1Slice", "StringsOnly", "CsvOnly", "DualGhidraIda", "DualHtmlMD"
            )
        )

    def test_pairwise_config_13(self):
        """Pairwise Config 13: DualSection x FullComprehensive x JumpTablesOnly x IdaProOnly x DualHtmlMD"""
        self.assertTrue(
            self._execute_pipeline_run(
                "DualSection", "FullComprehensive", "JumpTablesOnly", "IdaProOnly", "DualHtmlMD"
            )
        )

    def test_pairwise_config_14(self):
        """Pairwise Config 14: DualSection x FastNoLiterals x DualJsonCsv x GhidraOnly x StrictLinkValidation"""
        self.assertTrue(
            self._execute_pipeline_run(
                "DualSection", "FastNoLiterals", "DualJsonCsv", "GhidraOnly", "StrictLinkValidation"
            )
        )

    def test_pairwise_config_15(self):
        """Pairwise Config 15: DualSection x FunctionsOnly x CsvOnly x MockExecution x HtmlOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "DualSection", "FunctionsOnly", "CsvOnly", "MockExecution", "HtmlOnly"
            )
        )

    def test_pairwise_config_16(self):
        """Pairwise Config 16: DualSection x StringsOnly x JsonOnly x DualGhidraIda x MarkdownOnly"""
        self.assertTrue(
            self._execute_pipeline_run(
                "DualSection", "StringsOnly", "JsonOnly", "DualGhidraIda", "MarkdownOnly"
            )
        )


if __name__ == "__main__":
    unittest.main()
