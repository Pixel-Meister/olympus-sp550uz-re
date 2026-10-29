"""
olympus_re/docgen/link_validator.py - Documentation Link & Memory Reference Validator
======================================================================================
Validates Documentation Completeness & Zero Dead Links for generated cross-reference
documentation (docs/xref.html and docs/xref/*.md).
"""

from dataclasses import dataclass, field
import html.parser
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

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

VALID_PHYSICAL_MEMORY_RANGES: List[Tuple[int, int, str]] = [
    (0x40000000, 0x40855967, "Section 1 SDRAM & Section 2 NDATA"),
    (0x41F00000, 0x41FD0000, "Uncached SDRAM Buffers, Blackboard & Stacks"),
    (0x80410000, 0x8041FFFF, "MMIO SDRAM Controller"),
    (0xC04C0000, 0xC04CFFFF, "MMIO DMA & NAND Controller"),
    (0xE0000000, 0xE081FFFF, "MMIO Timers, Interrupt, Video DAC, ISP, JPEG"),
]

REQUIRED_MD_FILES = [
    "index.md",
    "subsystems.md",
    "memory_map.md",
    "jump_tables.md",
]

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


def is_valid_physical_address(addr: int) -> bool:
    """Predicate checking whether an address falls within any physical TruePic III domain."""
    for start, end, _ in VALID_PHYSICAL_MEMORY_RANGES:
        if start <= addr <= end:
            return True
    return False


def is_valid_memory_address(addr: int) -> bool:
    """Check if address is either recognized non-memory constant or within hardware bounds."""
    if addr in KNOWN_NON_MEMORY_CONSTANTS:
        return True
    return is_valid_physical_address(addr)


def slugify_heading(heading_text: str) -> str:
    """GitHub-compatible anchor slug generator for Markdown headings."""
    cleaned = re.sub(r"[^\w\s-]", "", heading_text.lower()).strip()
    return re.sub(r"[-\s]+", "-", cleaned)


def escape_pipe(value: Any) -> str:
    """Escape pipe '|' characters for Markdown table cells."""
    if value is None:
        return ""
    return str(value).replace("|", r"\|")


@dataclass
class ValidationReport:
    """Report detailing documentation integrity and link validation results."""
    passed: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    dead_html_links: List[str] = field(default_factory=list)
    dead_md_links: List[str] = field(default_factory=list)
    unresolvable_addresses: List[str] = field(default_factory=list)


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
            if href == "#":
                return  # Ignore self-referencing links
            if href.startswith("#") and len(href) > 1:
                lineno, _ = self.getpos()
                self.internal_links.append((href[1:], lineno))


class LinkValidator:
    """
    Automated link checker matching Acceptance Criterion V3.
    Asserts zero dead links, zero unresolvable addresses, and complete subsystem coverage.
    """

    def __init__(self, html_path: Optional[Path] = None, md_dir: Optional[Path] = None):
        self.html_path = html_path or Path("docs/xref.html")
        self.md_dir = md_dir or Path("docs/xref")
        self.report = ValidationReport()
        self.all_doc_text: str = ""

    def load_corpus(self) -> None:
        parts = []
        if self.html_path.exists():
            with open(self.html_path, "r", encoding="utf-8") as f:
                parts.append(f.read())
        if self.md_dir.exists():
            for md_file in sorted(self.md_dir.glob("*.md")):
                with open(md_file, "r", encoding="utf-8") as f:
                    parts.append(f.read())
        self.all_doc_text = "\n".join(parts)

    def validate_required_files(self) -> None:
        if not self.html_path.exists():
            self.report.errors.append(f"Required HTML cross-reference not found at {self.html_path}")
        elif self.html_path.stat().st_size < 100:
            self.report.errors.append(f"HTML cross-reference {self.html_path} is < 100 bytes")

        for filename in REQUIRED_MD_FILES:
            target = self.md_dir / filename
            if not target.exists():
                self.report.errors.append(f"Required Markdown document not found at {target}")
            elif target.stat().st_size < 100:
                self.report.errors.append(f"Markdown document {target} is < 100 bytes")

    def validate_html_links(self) -> None:
        if not self.html_path.exists():
            return
        with open(self.html_path, "r", encoding="utf-8") as f:
            content = f.read()
        collector = HTMLLinkCollector()
        collector.feed(content)
        for target_id, lineno in collector.internal_links:
            if target_id not in collector.defined_anchors:
                msg = f"{self.html_path}:{lineno} -> dead link target '#{target_id}'"
                self.report.dead_html_links.append(msg)
                self.report.errors.append(msg)

    def validate_markdown_links(self) -> None:
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
                        anchors.add(slugify_heading(match.group(1)))
                    for tag_match in re.finditer(r'<a\s+[^>]*(?:id|name)=["\']([^"\']+)["\']', line, re.I):
                        anchors.add(tag_match.group(1))
            file_anchors[path.name] = anchors

        link_regex = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        for path in md_files:
            with open(path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, start=1):
                    for match in link_regex.finditer(line):
                        dest = match.group(2).strip()

                        # Ignore external protocols and self-referencing hash
                        if dest.startswith(("http://", "https://", "mailto:")) or dest == "#":
                            continue

                        # Directory traversal security check
                        if ".." in dest:
                            resolved = os.path.normpath(os.path.join(str(self.md_dir), dest.split("#")[0]))
                            if not resolved.startswith(str(self.md_dir)):
                                msg = f"{path.name}:{lineno} -> path traversal outside doc root: '{dest}'"
                                self.report.dead_md_links.append(msg)
                                self.report.errors.append(msg)
                                continue

                        if dest.startswith("#"):
                            target_anchor = dest[1:]
                            if target_anchor not in file_anchors.get(path.name, set()):
                                msg = f"{path.name}:{lineno} -> dead anchor '#{target_anchor}'"
                                self.report.dead_md_links.append(msg)
                                self.report.errors.append(msg)
                        elif "#" in dest:
                            target_file, target_anchor = dest.split("#", 1)
                            clean_file = Path(target_file).name
                            if clean_file not in file_anchors:
                                msg = f"{path.name}:{lineno} -> target file '{target_file}' not found"
                                self.report.dead_md_links.append(msg)
                                self.report.errors.append(msg)
                            elif target_anchor not in file_anchors[clean_file]:
                                msg = f"{path.name}:{lineno} -> dead anchor '#{target_anchor}' in '{clean_file}'"
                                self.report.dead_md_links.append(msg)
                                self.report.errors.append(msg)
                        else:
                            clean_file = Path(dest).name
                            if clean_file not in file_anchors:
                                msg = f"{path.name}:{lineno} -> target file '{dest}' not found"
                                self.report.dead_md_links.append(msg)
                                self.report.errors.append(msg)

    def validate_memory_references(self) -> None:
        if not self.all_doc_text:
            return
        hex_regex = re.compile(r"\b0x([0-9a-fA-F]{8})\b")
        for match in hex_regex.finditer(self.all_doc_text):
            addr = int(match.group(1), 16)
            if not is_valid_memory_address(addr):
                msg = f"Unresolvable memory reference: {match.group(0)}"
                if msg not in self.report.unresolvable_addresses:
                    self.report.unresolvable_addresses.append(msg)
                    self.report.errors.append(msg)

    def validate_peripherals_and_subsystems(self) -> None:
        if not self.all_doc_text:
            return
        for name, patterns in REQUIRED_MMIO_PERIPHERALS:
            found = False
            for pat in patterns:
                if re.search(pat, self.all_doc_text, re.IGNORECASE):
                    found = True
                    break
            if not found:
                self.report.errors.append(f"MMIO peripheral '{name}' missing from documentation")

        for name, patterns in REQUIRED_SUBSYSTEM_PATTERNS:
            found = False
            for pat in patterns:
                if re.search(pat, self.all_doc_text):
                    found = True
                    break
            if not found:
                self.report.errors.append(f"Subsystem entry point '{name}' missing from documentation")

        for name, patterns in REQUIRED_PTP_SCSI_ELEMENTS:
            found = False
            for pat in patterns:
                if re.search(pat, self.all_doc_text, re.IGNORECASE):
                    found = True
                    break
            if not found:
                self.report.errors.append(f"PTP/SCSI component '{name}' missing from documentation")

    def validate_all(self) -> ValidationReport:
        self.load_corpus()
        self.validate_required_files()
        self.validate_html_links()
        self.validate_markdown_links()
        self.validate_memory_references()
        self.validate_peripherals_and_subsystems()
        self.report.passed = len(self.report.errors) == 0
        return self.report
