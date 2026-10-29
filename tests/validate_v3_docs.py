#!/usr/bin/env python3
"""
tests/validate_v3_docs.py - V3 Acceptance Criteria Validator
============================================================
Validates Documentation Completeness & Zero Dead Links for generated
cross-reference documentation (docs/xref.html and docs/xref/*.md).

Requirements Verified:
1. Documentation includes all known MMIO peripherals, major subsystem entry
   points (DISP_, SYSFNC_, REC_, BML_/STL_), and PTP-over-SCSI command handlers.
2. ZERO dead internal links in HTML cross-reference (`href="#..."`).
3. ZERO dead internal or cross-file relative links in Markdown chapters.
4. ZERO unresolvable memory references (all 32-bit hex addresses strictly
   fall within valid TruePic III domains: 0x40000000 to 0xE081FFFF).

Dual Execution Mode:
- CLI Mode: `python3 tests/validate_v3_docs.py [--html path] [--md-dir path] [-v]`
- Test Mode: `python3 -m unittest tests/validate_v3_docs.py`
"""

import argparse
import html.parser
import os
from pathlib import Path
import re
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
    DOCS_DIR,
    DOCS_XREF_DIR,
    DOCS_XREF_HTML_PATH,
    VALID_PHYSICAL_MEMORY_RANGES,
    is_valid_physical_address,
)

REQUIRED_MD_FILES = [
    "index.md",
    "subsystems.md",
    "memory_map.md",
    "jump_tables.md",
]

REQUIRED_DOC_FILES = [DOCS_XREF_HTML_PATH] + [DOCS_XREF_DIR / f for f in REQUIRED_MD_FILES]

REQUIRED_MMIO_PERIPHERALS = [
    ("SDRAM Controller", [r"0x80410000", r"SDRAM\s+Controller"]),
    ("DMA & NAND Controller", [r"0xC04C0000", r"NAND\s+Controller", r"DMA\s+Controller"]),
    ("Timers & Interrupts", [r"0xE0000000", r"0xE0010000", r"Interrupt\s+Controller", r"Timer"]),
    ("GPIO Keypad", [r"0xE0200000", r"GPIO", r"Keypad"]),
    ("Image Signal Processor (ISP)", [r"0xE0400000", r"ISP", r"Sensor"]),
    ("Video DAC Compositor", [r"0xE0600000", r"Video\s+DAC", r"Compositor"]),
    ("Hardware JPEG Scaler", [r"0xE0800000", r"JPEG", r"Scaler"]),
]

REQUIRED_SUBSYSTEM_PATTERNS = [
    ("DISP_ (OSD & GUI Engine)", [r"DISP_", r"0x401b32f4"]),
    ("SYSFNC_ (System Hardware API)", [r"SYSFNC_", r"0x400d4ac0"]),
    ("REC_ (Recording & Preview Loop)", [r"REC_", r"0x40176b38"]),
    ("BML_ / STL_ (NAND Flash Layer)", [r"BML_", r"STL_"]),
]

REQUIRED_PTP_SCSI_ELEMENTS = [
    ("SCSI CDBs", [r"0xC0", r"0xC1", r"0xC4", r"0xDF"]),
    ("PTP Opcodes", [r"0x1001", r"0x100C", r"0x9119", r"0x9121", r"0x9123"]),
    ("PTP Dispatcher", [r"0x40316ed8"]),
    ("Storage Card Update Path", [r"/FIRMWARE/FIRMWARE\.BIN|FIRMWARE\.BIN|FIRMWAREBIN", r"0x402918d4", r"0x40291694"]),
]

KNOWN_NON_MEMORY_CONSTANTS: Set[int] = {
    0x00000000,  # Zero / reset vector
    0xFFFFFFFF,  # 32-bit -1 / BADADDR
    0x00000010,  # 16-byte SCSI container length
    0x80000001,  # PTP Storage ID
    0xEA0000AA,  # ARM opcode: b 0x401B3864 (Relative branch instruction)
    0xEA0001FE,  # ARM opcode: b 0x40000800 (Section 1 reset vector branch)
    0xE12FFF1E,  # ARM opcode: bx lr (Leaf function epilogue return)
    0xE92D4310,  # ARM opcode: push {r4, r8, sb, lr} (Common function prologue)
    0xE92D0300,  # ARM opcode: push {r8, sb} (Sanyo custom leaf prologue)
    0xE92D4000,  # ARM opcode: push {lr} (Prologue mask)
    0xE8BD4000,  # ARM opcode: pop {lr}
    0xE8BD8000,  # ARM opcode: pop {pc}
}


def is_valid_memory_address(addr: int) -> bool:
    """Check if address falls within recognized hardware memory boundaries."""
    if addr in KNOWN_NON_MEMORY_CONSTANTS:
        return True
    return is_valid_physical_address(addr)


def slugify_heading(heading_text: str) -> str:
    """GitHub-compatible anchor slug generator for Markdown headings."""
    cleaned = re.sub(r"[^\w\s-]", "", heading_text.lower()).strip()
    return re.sub(r"[-\s]+", "-", cleaned)


class HTMLLinkCollector(html.parser.HTMLParser):
    """Scrapes all IDs, names, and internal href links from HTML."""

    def __init__(self):
        super().__init__()
        self.defined_anchors: Set[str] = set()
        self.internal_links: List[Tuple[str, int]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        if "id" in attr_dict:
            self.defined_anchors.add(attr_dict["id"])
        if "name" in attr_dict:
            self.defined_anchors.add(attr_dict["name"])

        if "href" in attr_dict:
            href = attr_dict["href"]
            if href.startswith("#") and len(href) > 1:
                lineno, _ = self.getpos()
                self.internal_links.append((href[1:], lineno))


class V3DocsValidator:
    """Core validator implementing Acceptance Criterion V3 assertions."""

    def __init__(self, html_path: Optional[Path] = None, md_dir: Optional[Path] = None):
        self.html_path = html_path or DOCS_XREF_HTML_PATH
        self.md_dir = md_dir or DOCS_XREF_DIR
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.dead_html_links: List[str] = []
        self.dead_md_links: List[str] = []
        self.unresolvable_addresses: List[str] = []
        self.all_doc_text: str = ""

    def load_documentation_corpus(self) -> None:
        """Read all HTML and Markdown files into corpus text."""
        parts = []

        if self.html_path.exists():
            with open(self.html_path, "r", encoding="utf-8") as f:
                parts.append(f.read())

        if self.md_dir.exists():
            for md_file in sorted(self.md_dir.glob("*.md")):
                with open(md_file, "r", encoding="utf-8") as f:
                    parts.append(f.read())

        self.all_doc_text = "\n".join(parts)

    def validate_required_files_exist(self) -> None:
        """Assert all required documentation files exist and have content."""
        if not self.html_path.exists():
            self.errors.append(f"Required HTML cross-reference not found at {self.html_path}")
        elif self.html_path.stat().st_size < 100:
            self.errors.append(
                f"HTML cross-reference {self.html_path} is unexpectedly small (< 100 bytes)"
            )

        for filename in REQUIRED_MD_FILES:
            target = self.md_dir / filename
            if not target.exists():
                self.errors.append(f"Required Markdown document not found at {target}")
            elif target.stat().st_size < 100:
                self.errors.append(
                    f"Markdown document {target} is unexpectedly small (< 100 bytes)"
                )

    def validate_mmio_peripherals(self) -> None:
        """Assert all 7 MMIO hardware blocks are present in docs."""
        if not self.all_doc_text:
            return
        for name, patterns in REQUIRED_MMIO_PERIPHERALS:
            found = False
            for pat in patterns:
                if re.search(pat, self.all_doc_text, re.IGNORECASE):
                    found = True
                    break
            if not found:
                self.errors.append(
                    f"MMIO peripheral '{name}' is missing from documentation (checked {patterns})"
                )

    def validate_subsystem_entry_points(self) -> None:
        """Assert DISP_, SYSFNC_, REC_, and BML_/STL_ entry points are present."""
        if not self.all_doc_text:
            return
        for name, patterns in REQUIRED_SUBSYSTEM_PATTERNS:
            found = False
            for pat in patterns:
                if re.search(pat, self.all_doc_text):
                    found = True
                    break
            if not found:
                self.errors.append(f"Subsystem entry point '{name}' is missing from documentation")

    def validate_ptp_scsi_handlers(self) -> None:
        """Assert PTP opcodes, SCSI CDBs, and update path are present."""
        if not self.all_doc_text:
            return
        for name, patterns in REQUIRED_PTP_SCSI_ELEMENTS:
            found = False
            for pat in patterns:
                if re.search(pat, self.all_doc_text, re.IGNORECASE):
                    found = True
                    break
            if not found:
                self.errors.append(f"PTP/SCSI component '{name}' is missing from documentation")

    def validate_html_internal_links(self) -> None:
        """Assert ZERO dead internal links in docs/xref.html."""
        if not self.html_path.exists():
            return

        with open(self.html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        parser = HTMLLinkCollector()
        parser.feed(html_content)

        for target_id, lineno in parser.internal_links:
            if target_id not in parser.defined_anchors:
                msg = f"{self.html_path}:{lineno} -> dead link target '#{target_id}'"
                self.dead_html_links.append(msg)
                self.errors.append(msg)

    def validate_markdown_internal_links(self) -> None:
        """Assert ZERO dead links across all docs/xref/*.md chapters."""
        if not self.md_dir.exists():
            return

        md_files = list(self.md_dir.glob("*.md"))
        file_anchors: Dict[str, Set[str]] = {}

        for path in md_files:
            anchors: Set[str] = set()
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    match = re.match(r"^#{1,6}\s+(.+)$", line.strip())
                    if match:
                        heading_slug = slugify_heading(match.group(1))
                        anchors.add(heading_slug)

                    for tag_match in re.finditer(
                        r'<a\s+[^>]*(?:id|name)=["\']([^"\']+)["\']', line, re.I
                    ):
                        anchors.add(tag_match.group(1))

            file_anchors[path.name] = anchors

        link_regex = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        for path in md_files:
            with open(path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, start=1):
                    for match in link_regex.finditer(line):
                        dest = match.group(2).strip()

                        if (
                            dest.startswith("http://")
                            or dest.startswith("https://")
                            or dest.startswith("mailto:")
                        ):
                            continue

                        if dest.startswith("#"):
                            target_anchor = dest[1:]
                            if target_anchor not in file_anchors.get(path.name, set()):
                                msg = f"{path.name}:{lineno} -> dead anchor '#{target_anchor}'"
                                self.dead_md_links.append(msg)
                                self.errors.append(msg)
                        elif "#" in dest:
                            target_file, target_anchor = dest.split("#", 1)
                            clean_file = Path(target_file).name
                            if clean_file not in file_anchors:
                                msg = f"{path.name}:{lineno} -> target file '{target_file}' not found"
                                self.dead_md_links.append(msg)
                                self.errors.append(msg)
                            elif target_anchor not in file_anchors[clean_file]:
                                msg = f"{path.name}:{lineno} -> dead anchor '#{target_anchor}' in '{clean_file}'"
                                self.dead_md_links.append(msg)
                                self.errors.append(msg)
                        else:
                            clean_file = Path(dest).name
                            if clean_file not in file_anchors:
                                msg = f"{path.name}:{lineno} -> target file '{dest}' not found"
                                self.dead_md_links.append(msg)
                                self.errors.append(msg)

    def validate_memory_references(self) -> None:
        """Assert ZERO unresolvable 32-bit hex addresses across documentation."""
        if not self.all_doc_text:
            return

        hex_addr_regex = re.compile(r"\b0x([0-9a-fA-F]{8})\b")

        for match in hex_addr_regex.finditer(self.all_doc_text):
            addr_int = int(match.group(1), 16)
            if not is_valid_memory_address(addr_int):
                msg = f"Unresolvable memory reference: {match.group(0)}"
                if msg not in self.unresolvable_addresses:
                    self.unresolvable_addresses.append(msg)
                    self.errors.append(msg)

    def run_all(self) -> bool:
        """Execute full validation suite.

        Acceptance Criterion V3 strictly requires docs/xref.html and docs/xref/*.md.
        If target files do not exist, returns False and records missing deliverable errors.
        """
        self.load_documentation_corpus()

        if not self.html_path.exists() and not self.md_dir.exists():
            self.errors.append(
                f"Documentation deliverables not found ({self.html_path}, {self.md_dir}). "
                "Pending milestone M3."
            )
            return False

        self.validate_required_files_exist()
        self.validate_mmio_peripherals()
        self.validate_subsystem_entry_points()
        self.validate_ptp_scsi_handlers()
        self.validate_html_internal_links()
        self.validate_markdown_internal_links()
        self.validate_memory_references()

        return len(self.errors) == 0


# ==============================================================================
# Unittest TestCase Suite
# ==============================================================================

class TestV3DocsCompleteness(unittest.TestCase):
    """Standard unittest suite for CI / test discovery."""

    @classmethod
    def setUpClass(cls):
        cls.validator = V3DocsValidator()
        cls.validator.load_documentation_corpus()

    def test_01_documentation_files_exist(self):
        """Assert docs/xref.html and docs/xref/*.md exist with content."""
        if not self.validator.html_path.exists() or not self.validator.md_dir.exists():
            raise unittest.SkipTest(
                f"Documentation files not found ({self.validator.html_path}, {self.validator.md_dir}) (M3 planned)"
            )
        self.validator.validate_required_files_exist()
        self.assertEqual(len(self.validator.errors), 0)

    def test_02_all_mmio_peripherals_cataloged(self):
        """Assert all 7 hardware MMIO blocks are present in docs."""
        if not self.validator.all_doc_text:
            raise unittest.SkipTest("Documentation corpus is empty (M3 planned)")
        init_errs = len(self.validator.errors)
        self.validator.validate_mmio_peripherals()
        self.assertEqual(len(self.validator.errors), init_errs)

    def test_03_subsystem_entry_points_documented(self):
        """Assert DISP_, SYSFNC_, REC_, BML_/STL_ entry points are documented."""
        if not self.validator.all_doc_text:
            raise unittest.SkipTest("Documentation corpus is empty (M3 planned)")
        init_errs = len(self.validator.errors)
        self.validator.validate_subsystem_entry_points()
        self.assertEqual(len(self.validator.errors), init_errs)

    def test_04_ptp_scsi_command_handlers_documented(self):
        """Assert SCSI CDBs, PTP opcodes, and storage update path are documented."""
        if not self.validator.all_doc_text:
            raise unittest.SkipTest("Documentation corpus is empty (M3 planned)")
        init_errs = len(self.validator.errors)
        self.validator.validate_ptp_scsi_handlers()
        self.assertEqual(len(self.validator.errors), init_errs)

    def test_05_html_zero_dead_links(self):
        """Assert ZERO dead internal links in docs/xref.html."""
        if not self.validator.html_path.exists():
            raise unittest.SkipTest("docs/xref.html not generated yet (M3 planned)")
        self.validator.validate_html_internal_links()
        self.assertEqual(len(self.validator.dead_html_links), 0)

    def test_06_markdown_zero_dead_links(self):
        """Assert ZERO dead internal or cross-file links in docs/xref/*.md."""
        if not self.validator.md_dir.exists():
            raise unittest.SkipTest("docs/xref directory not generated yet (M3 planned)")
        self.validator.validate_markdown_internal_links()
        self.assertEqual(len(self.validator.dead_md_links), 0)

    def test_07_zero_unresolvable_memory_references(self):
        """Assert ZERO out-of-range memory references across documentation."""
        if not self.validator.all_doc_text:
            raise unittest.SkipTest("Documentation corpus is empty (M3 planned)")
        self.validator.validate_memory_references()
        self.assertEqual(len(self.validator.unresolvable_addresses), 0)

    def test_08_heading_slugification_and_anchor_mechanics(self):
        """Assert slugify_heading correctly formats GitHub-compatible anchors."""
        raw_heading = "OSD Master Record Mode Dispatcher (0x401b32f4)"
        slug = slugify_heading(raw_heading)
        self.assertEqual(slug, "osd-master-record-mode-dispatcher-0x401b32f4")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate V3 Documentation Completeness & Zero Dead Links"
    )
    parser.add_argument(
        "--html", type=Path, default=DOCS_XREF_HTML_PATH, help="HTML cross-reference path"
    )
    parser.add_argument(
        "--md-dir", type=Path, default=DOCS_XREF_DIR, help="Markdown directory path"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose diagnostics")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print(" Olympus SP-550UZ RE: V3 Documentation Completeness Validator")
    print("=" * 70)

    validator = V3DocsValidator(html_path=args.html, md_dir=args.md_dir)
    passed = validator.run_all()

    print(f"\n[*] Target Documentation Paths:")
    print(
        f"    HTML App:       {validator.html_path} ({'Found' if validator.html_path.exists() else 'Missing / Pending M3'})"
    )
    print(
        f"    Markdown Dir:   {validator.md_dir} ({'Found' if validator.md_dir.exists() else 'Missing / Pending M3'})"
    )

    req_files_ok = validator.html_path.exists() and validator.md_dir.exists() and not any(
        "not found" in e or "small" in e for e in validator.errors
    )
    mmio_ok = bool(validator.all_doc_text) and not any("MMIO peripheral" in e for e in validator.errors)
    subsystems_ok = bool(validator.all_doc_text) and not any("Subsystem entry point" in e for e in validator.errors)
    ptp_ok = bool(validator.all_doc_text) and not any("PTP/SCSI component" in e for e in validator.errors)
    html_links_ok = validator.html_path.exists() and len(validator.dead_html_links) == 0
    md_links_ok = validator.md_dir.exists() and len(validator.dead_md_links) == 0
    mem_refs_ok = bool(validator.all_doc_text) and len(validator.unresolvable_addresses) == 0

    print(f"\n[*] Validation Criteria Results:")
    print(f"    Required Files Check:         {'PASS' if req_files_ok else 'FAIL'}")
    print(f"    MMIO Peripherals Check:       {'PASS' if mmio_ok else 'FAIL'}")
    print(f"    Subsystem Entry Points Check: {'PASS' if subsystems_ok else 'FAIL'}")
    print(f"    PTP-over-SCSI Check:          {'PASS' if ptp_ok else 'FAIL'}")
    print(f"    HTML Zero Dead Links:         {'PASS' if html_links_ok else 'FAIL'}")
    print(f"    Markdown Zero Dead Links:     {'PASS' if md_links_ok else 'FAIL'}")
    print(f"    Zero Unresolvable Memory:     {'PASS' if mem_refs_ok else 'FAIL'}")

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
        print("[+] RESULT: ACCEPTANCE CRITERION V3 PASSED (100% Conformance)")
        print("-" * 70 + "\n")
        return 0
    else:
        missing_any = not validator.html_path.exists() or not validator.md_dir.exists()
        if missing_any:
            print("[-] RESULT: ACCEPTANCE CRITERION V3 FAILED (Target deliverables missing)")
        else:
            print("[-] RESULT: ACCEPTANCE CRITERION V3 FAILED")
        print("-" * 70 + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
