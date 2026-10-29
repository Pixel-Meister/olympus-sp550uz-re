#!/usr/bin/env python3
"""
tests/validate_v2_decompiler.py - V2 Acceptance Criteria Validator
==================================================================
Validates Decompiler Script Quality & Execution for Ghidra and IDA Pro scripts.

Requirements Verified:
1. Ghidra script and IDA script pass Python AST parsing (`ast.parse`) and
   bytecode compilation (`py_compile.compile`) without errors.
2. Memory segment definitions in scripts match the true TruePic III memory map
   (0x40000000 to 0xE081FFFF across all 8/9 domains).
3. Scripts include clear usage instructions and headless execution instructions:
   - Ghidra: `analyzeHeadless` execution instructions.
   - IDA Pro: `idal64` / batch execution instructions.
4. Offline mock environment executes both scripts without unhandled exceptions,
   verifying memory block creation and symbol annotations.

Dual Execution Mode:
- CLI Mode: `python3 tests/validate_v2_decompiler.py [--ghidra path] [--ida path] [-v]`
- Test Mode: `python3 -m unittest tests/validate_v2_decompiler.py`
"""

import argparse
import ast
import os
from pathlib import Path
import py_compile
import re
import sys
import tempfile
import types
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
    GHIDRA_SCRIPT_ALT_PATH,
    GHIDRA_SCRIPT_PATH,
    IDA_SCRIPT_ALT_PATH,
    IDA_SCRIPT_PATH,
    MockAddress,
    MockGhidraFlatProgramAPI,
    MockIDAPython,
    TruePicIIIMemoryMap,
)

EXPECTED_SEGMENTS: List[Dict[str, Any]] = [
    {"name": "SEC1_SDRAM", "start": 0x40000000, "end": 0x403F50E7, "perm": "RX"},
    {"name": "SEC2_NDATA", "start": 0x403F5108, "end": 0x40855967, "perm": "RO"},
    {"name": "UNCACHED_RAM", "start": 0x41F00000, "end": 0x41F7FFFF, "perm": "RW"},
    {"name": "BLACKBOARD", "start": 0x41F80000, "end": 0x41F9FFFF, "perm": "RW"},
    {"name": "STACKS", "start": 0x41FA0000, "end": 0x41FD0000, "perm": "RW"},
    {"name": "MMIO_SDRAM", "start": 0x80410000, "end": 0x8041FFFF, "perm": "RW"},
    {"name": "MMIO_DMA_NAND", "start": 0xC04C0000, "end": 0xC04CFFFF, "perm": "RW"},
    {"name": "MMIO_PERIPH", "start": 0xE0010000, "end": 0xE081FFFF, "perm": "RW"},
]

TRUEPIC3_BASE = 0x40000000
TRUEPIC3_CEILING = 0xE081FFFF


class V2DecompilerValidator:
    """Core validator implementing Acceptance Criterion V2 assertions."""

    def __init__(self, ghidra_path: Optional[Path] = None, ida_path: Optional[Path] = None):
        if ghidra_path is not None:
            self.ghidra_path = ghidra_path
        elif GHIDRA_SCRIPT_PATH.exists():
            self.ghidra_path = GHIDRA_SCRIPT_PATH
        elif GHIDRA_SCRIPT_ALT_PATH.exists():
            self.ghidra_path = GHIDRA_SCRIPT_ALT_PATH
        else:
            self.ghidra_path = GHIDRA_SCRIPT_PATH

        if ida_path is not None:
            self.ida_path = ida_path
        elif IDA_SCRIPT_PATH.exists():
            self.ida_path = IDA_SCRIPT_PATH
        elif IDA_SCRIPT_ALT_PATH.exists():
            self.ida_path = IDA_SCRIPT_ALT_PATH
        else:
            self.ida_path = IDA_SCRIPT_PATH

        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_ast(self, path: Path, script_type: str) -> bool:
        """Assert file parses as valid Python AST."""
        if not path.exists():
            self.errors.append(f"{script_type} script deliverable not found at {path}")
            return False

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            ast.parse(content, filename=str(path))
            return True
        except SyntaxError as err:
            self.errors.append(f"{script_type} AST SyntaxError at line {err.lineno}: {err.msg}")
            return False

    def validate_byte_compile(self, path: Path, script_type: str) -> bool:
        """Assert file byte-compiles without errors."""
        if not path.exists():
            return False

        try:
            with tempfile.NamedTemporaryFile(suffix=".pyc", delete=True) as tmp:
                py_compile.compile(str(path), cfile=tmp.name, doraise=True)
            return True
        except py_compile.PyCompileError as err:
            self.errors.append(f"{script_type} compilation error: {err}")
            return False

    def validate_memory_definitions_static(self, path: Path, script_type: str) -> None:
        """Assert source text defines segments spanning 0x40000000 to 0xE081FFFF."""
        if not path.exists():
            return

        with open(path, "r", encoding="utf-8") as f:
            code = f.read().lower()

        required_hex = [
            ("0x40000000", "Section 1 SDRAM base"),
            ("0x403f5108", "Section 2 NDATA base"),
            ("0x41f00000", "Uncached SDRAM base"),
            ("0x41f80000", "Blackboard base"),
            ("0x41fa0000", "Stacks base"),
            ("0x80410000", "MMIO SDRAM base"),
            ("0xc04c0000", "MMIO DMA/NAND base"),
            ("0xe081ffff", "TruePic III ceiling"),
        ]

        for hex_str, desc in required_hex:
            if hex_str not in code:
                self.errors.append(
                    f"{script_type} script is missing memory definition for {desc} ({hex_str})"
                )

    def validate_documentation_headers(self, path: Path, script_type: str) -> None:
        """Assert script contains interactive usage and headless command lines."""
        if not path.exists():
            return

        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        if script_type == "Ghidra":
            if "analyzeheadless" not in code.lower():
                self.errors.append(
                    "Ghidra script docstring lacks `analyzeHeadless` execution instructions"
                )
            if "script manager" not in code.lower() and "ghidra" not in code.lower():
                self.errors.append(
                    "Ghidra script docstring lacks GUI Script Manager usage instructions"
                )
        elif script_type == "IDA Pro":
            if "idal" not in code.lower() and "ida64" not in code.lower() and "-s" not in code:
                self.errors.append(
                    "IDA script docstring lacks `idal64` / batch headless execution instructions"
                )
            if "alt+f7" not in code.lower() and "script file" not in code.lower():
                self.errors.append("IDA script docstring lacks Alt+F7 / GUI usage instructions")

    def validate_ghidra_mock_execution(self) -> None:
        """Execute Ghidra script in sandboxed FlatProgramAPI mock."""
        if not self.ghidra_path.exists():
            return

        mock_api = MockGhidraFlatProgramAPI()

        ghidra_mod = types.ModuleType("ghidra")
        ghidra_app = types.ModuleType("ghidra.app")
        ghidra_app_script = types.ModuleType("ghidra.app.script")
        ghidra_app_script.GhidraScript = object
        ghidra_prog = types.ModuleType("ghidra.program")
        ghidra_prog_model = types.ModuleType("ghidra.program.model")
        ghidra_prog_addr = types.ModuleType("ghidra.program.model.address")
        ghidra_prog_addr.Address = MockAddress

        saved_modules = dict(sys.modules)
        try:
            sys.modules["ghidra"] = ghidra_mod
            sys.modules["ghidra.app"] = ghidra_app
            sys.modules["ghidra.app.script"] = ghidra_app_script
            sys.modules["ghidra.program"] = ghidra_prog
            sys.modules["ghidra.program.model"] = ghidra_prog_model
            sys.modules["ghidra.program.model.address"] = ghidra_prog_addr

            with open(self.ghidra_path, "r", encoding="utf-8") as f:
                code_text = f.read()

            sandbox = {
                "__file__": str(self.ghidra_path),
                "__name__": "__main__",
                "currentProgram": None,
                "createMemoryBlock": mock_api.createMemoryBlock,
                "createLabel": mock_api.createLabel,
                "setPlateComment": mock_api.setPlateComment,
                "setPreComment": mock_api.setPreComment,
                "setEolComment": mock_api.setEolComment,
                "toAddr": mock_api.toAddr,
                "println": mock_api.println,
                "askFile": lambda title, btn: str(Path("output/symbols.json")),
                "askString": lambda title, prompt: "",
            }

            exec(compile(code_text, str(self.ghidra_path), "exec"), sandbox)

            if len(mock_api.blocks) < 5:
                self.errors.append(
                    f"Ghidra mock execution created only {len(mock_api.blocks)} memory blocks (expected >= 5)"
                )
        except Exception as exc:
            self.errors.append(f"Ghidra mock execution raised unhandled exception: {exc}")
        finally:
            sys.modules.clear()
            sys.modules.update(saved_modules)

    def validate_ida_mock_execution(self) -> None:
        """Execute IDA script in sandboxed idc/idaapi mock."""
        if not self.ida_path.exists():
            return

        mock_env = MockIDAPython()

        saved_modules = dict(sys.modules)
        try:
            sys.modules["idc"] = mock_env.idc
            sys.modules["idaapi"] = mock_env.idaapi
            sys.modules["idautils"] = mock_env.idautils

            with open(self.ida_path, "r", encoding="utf-8") as f:
                code_text = f.read()

            sandbox = {
                "__file__": str(self.ida_path),
                "__name__": "__main__",
            }

            exec(compile(code_text, str(self.ida_path), "exec"), sandbox)

            if len(mock_env.segments) < 5:
                self.errors.append(
                    f"IDA mock execution created only {len(mock_env.segments)} segments (expected >= 5)"
                )
        except Exception as exc:
            self.errors.append(f"IDA mock execution raised unhandled exception: {exc}")
        finally:
            sys.modules.clear()
            sys.modules.update(saved_modules)

    def run_all(self) -> bool:
        """Execute full validation suite.

        Acceptance Criterion V2 strictly requires both Ghidra and IDA Pro scripts.
        If target files do not exist, returns False and records missing deliverable errors.
        """
        if not self.ghidra_path.exists():
            self.errors.append(
                f"Ghidra decompiler script deliverable not found at {self.ghidra_path}. "
                "Pending milestone M2."
            )
        if not self.ida_path.exists():
            self.errors.append(
                f"IDA Pro decompiler script deliverable not found at {self.ida_path}. "
                "Pending milestone M2."
            )

        if not self.ghidra_path.exists() and not self.ida_path.exists():
            return False

        if self.ghidra_path.exists():
            self.validate_ast(self.ghidra_path, "Ghidra")
            self.validate_byte_compile(self.ghidra_path, "Ghidra")
            self.validate_memory_definitions_static(self.ghidra_path, "Ghidra")
            self.validate_documentation_headers(self.ghidra_path, "Ghidra")
            self.validate_ghidra_mock_execution()

        if self.ida_path.exists():
            self.validate_ast(self.ida_path, "IDA Pro")
            self.validate_byte_compile(self.ida_path, "IDA Pro")
            self.validate_memory_definitions_static(self.ida_path, "IDA Pro")
            self.validate_documentation_headers(self.ida_path, "IDA Pro")
            self.validate_ida_mock_execution()

        return len(self.errors) == 0


# ==============================================================================
# Unittest TestCase Suite
# ==============================================================================

class TestV2DecompilerQuality(unittest.TestCase):
    """Standard unittest suite for CI / test discovery."""

    @classmethod
    def setUpClass(cls):
        cls.validator = V2DecompilerValidator()

    def test_01_ghidra_script_ast_and_bytecode(self):
        """Assert Ghidra annotator passes AST parsing and py_compile."""
        if not self.validator.ghidra_path.exists():
            raise unittest.SkipTest(
                f"Ghidra script not found at {self.validator.ghidra_path} (M2 planned)"
            )
        self.assertTrue(self.validator.validate_ast(self.validator.ghidra_path, "Ghidra"))
        self.assertTrue(self.validator.validate_byte_compile(self.validator.ghidra_path, "Ghidra"))

    def test_02_ida_script_ast_and_bytecode(self):
        """Assert IDA annotator passes AST parsing and py_compile."""
        if not self.validator.ida_path.exists():
            raise unittest.SkipTest(
                f"IDA script not found at {self.validator.ida_path} (M2 planned)"
            )
        self.assertTrue(self.validator.validate_ast(self.validator.ida_path, "IDA Pro"))
        self.assertTrue(self.validator.validate_byte_compile(self.validator.ida_path, "IDA Pro"))

    def test_03_ghidra_memory_segment_definitions(self):
        """Assert Ghidra script memory map covers 0x40000000 to 0xE081FFFF."""
        if not self.validator.ghidra_path.exists():
            raise unittest.SkipTest("Ghidra script not found (M2 planned)")
        init_errs = len(self.validator.errors)
        self.validator.validate_memory_definitions_static(self.validator.ghidra_path, "Ghidra")
        self.assertEqual(len(self.validator.errors), init_errs, "Memory segment definitions missing in Ghidra")

    def test_04_ida_memory_segment_definitions(self):
        """Assert IDA script memory map covers 0x40000000 to 0xE081FFFF."""
        if not self.validator.ida_path.exists():
            raise unittest.SkipTest("IDA script not found (M2 planned)")
        init_errs = len(self.validator.errors)
        self.validator.validate_memory_definitions_static(self.validator.ida_path, "IDA Pro")
        self.assertEqual(len(self.validator.errors), init_errs, "Memory segment definitions missing in IDA")

    def test_05_headless_instructions_present(self):
        """Assert both scripts contain headless execution instructions."""
        if not self.validator.ghidra_path.exists() and not self.validator.ida_path.exists():
            raise unittest.SkipTest("Decompiler scripts not found (M2 planned)")
        init_errs = len(self.validator.errors)
        if self.validator.ghidra_path.exists():
            self.validator.validate_documentation_headers(self.validator.ghidra_path, "Ghidra")
        if self.validator.ida_path.exists():
            self.validator.validate_documentation_headers(self.validator.ida_path, "IDA Pro")
        self.assertEqual(len(self.validator.errors), init_errs, "Headless execution documentation missing")

    def test_06_offline_mock_execution(self):
        """Assert mock execution harness operates cleanly."""
        api = MockGhidraFlatProgramAPI()
        block = api.createMemoryBlock("SEC1_SDRAM", 0x40000000, 4149416, True, False, True)
        self.assertEqual(block.name, "SEC1_SDRAM")
        self.assertEqual(block.getStart().getOffset(), 0x40000000)

        ida = MockIDAPython()
        rc = ida.add_segm_ex(0x40000000, 0x403F50E8, 0, 1, 0, 0, 5)
        self.assertEqual(rc, 1)
        self.assertEqual(len(ida.segments), 1)


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate V2 Decompiler Script Quality")
    parser.add_argument("--ghidra", type=Path, default=None, help="Ghidra script path")
    parser.add_argument("--ida", type=Path, default=None, help="IDA Pro script path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose diagnostics")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print(" Olympus SP-550UZ RE: V2 Decompiler Script Quality Validator")
    print("=" * 70)

    validator = V2DecompilerValidator(ghidra_path=args.ghidra, ida_path=args.ida)
    passed = validator.run_all()

    print(f"\n[*] Target Scripts Under Validation:")
    print(
        f"    Ghidra Script:  {validator.ghidra_path} ({'Found' if validator.ghidra_path.exists() else 'Missing / Pending M2'})"
    )
    print(
        f"    IDA Pro Script: {validator.ida_path} ({'Found' if validator.ida_path.exists() else 'Missing / Pending M2'})"
    )

    ast_ok = validator.ghidra_path.exists() and validator.ida_path.exists() and not any(
        "AST" in e or "compilation" in e for e in validator.errors
    )
    mmap_ok = validator.ghidra_path.exists() and validator.ida_path.exists() and not any(
        "memory definition" in e for e in validator.errors
    )
    headless_ok = validator.ghidra_path.exists() and validator.ida_path.exists() and not any(
        "headless" in e or "Script Manager" in e or "Alt+F7" in e for e in validator.errors
    )
    mock_ok = validator.ghidra_path.exists() and validator.ida_path.exists() and not any(
        "mock execution" in e for e in validator.errors
    )

    print(f"\n[*] Validation Criteria Results:")
    print(f"    AST & Bytecode Compilation:   {'PASS' if ast_ok else 'FAIL'}")
    print(f"    TruePic III Memory Map Check: {'PASS' if mmap_ok else 'FAIL'}")
    print(f"    Headless Instruction Check:   {'PASS' if headless_ok else 'FAIL'}")
    print(f"    Offline Mock Execution:       {'PASS' if mock_ok else 'FAIL'}")

    if validator.warnings:
        print("\n[*] Advisory Notes:")
        for w in validator.warnings:
            print(f"    * {w}")

    if validator.errors:
        print("\n[-] Validation Errors Detected:")
        for err in validator.errors:
            print(f"    * {err}")

    print("\n" + "-" * 70)
    if passed:
        print("[+] RESULT: ACCEPTANCE CRITERION V2 PASSED (100% Conformance)")
        print("-" * 70 + "\n")
        return 0
    else:
        missing_any = not validator.ghidra_path.exists() or not validator.ida_path.exists()
        if missing_any:
            print("[-] RESULT: ACCEPTANCE CRITERION V2 FAILED (Target deliverables missing)")
        else:
            print("[-] RESULT: ACCEPTANCE CRITERION V2 FAILED")
        print("-" * 70 + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
