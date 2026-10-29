"""
olympus_re/cli.py - Unified Command-Line Runner
"""

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import List, Optional

from olympus_re.models.memory_map import TruePicIIIMemoryMap
from olympus_re.analysis.pipeline import AnalysisPipeline, PipelineConfig
from olympus_re.docgen.generator import DocumentationGenerator
from olympus_re.docgen.link_validator import LinkValidator

DEFAULT_SEC1 = Path("Resources/firmware/sp550uz_v1.1_section1_code.bin")
DEFAULT_SEC2 = Path("Resources/firmware/sp550uz_v1.1_section2_ndata.bin")


def generate_ghidra_script(dest_path: Path) -> None:
    """Generate standalone Ghidra annotation script matching TruePic III memory map."""
    content = '''"""
Ghidra Annotator for Olympus SP-550UZ (TruePic III / Sanyo SG155)
==================================================================

Interactive Usage:
Open Ghidra, open the Script Manager, and run this script on the loaded binary.

Headless Execution:
Run with analyzeHeadless:
  support/analyzeHeadless <project_dir> <project_name> -import firmware.bin -postScript ghidra_sp550uz_annotator.py
"""

# TruePic III Memory Map Definitions
# 0x40000000: Section 1 SDRAM base
# 0x403f5108: Section 2 NDATA base
# 0x41f00000: Uncached SDRAM base
# 0x41f80000: Blackboard base
# 0x41fa0000: Stacks base
# 0x80410000: MMIO SDRAM base
# 0xc04c0000: MMIO DMA/NAND base
# 0xe0010000: MMIO Peripherals base
# 0xe081ffff: TruePic III ceiling

SEGMENTS = [
    ("SEC1_SDRAM", 0x40000000, 0x403F50E7, True, False, True),
    ("SEC2_NDATA", 0x403F5108, 0x40855967, True, False, False),
    ("UNCACHED_RAM", 0x41F00000, 0x41F7FFFF, True, True, False),
    ("BLACKBOARD", 0x41F80000, 0x41F9FFFF, True, True, False),
    ("STACKS", 0x41FA0000, 0x41FD0000, True, True, False),
    ("MMIO_SDRAM", 0x80410000, 0x8041FFFF, True, True, False),
    ("MMIO_DMA_NAND", 0xC04C0000, 0xC04CFFFF, True, True, False),
    ("MMIO_PERIPH", 0xE0010000, 0xE081FFFF, True, True, False),
]

def run():
    try:
        from ghidra.app.script import GhidraScript
        # Running in Ghidra environment
        for name, start, end, r, w, x in SEGMENTS:
            try:
                createMemoryBlock(name, toAddr(start), end - start + 1, r, w, x)
            except Exception:
                pass
    except (ImportError, NameError):
        pass

if __name__ == "__main__":
    run()
'''
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as f:
        f.write(content)


def generate_ida_script(dest_path: Path) -> None:
    """Generate standalone IDA Pro annotation script matching TruePic III memory map."""
    content = '''"""
IDA Pro Annotator for Olympus SP-550UZ (TruePic III / Sanyo SG155)
==================================================================

Interactive Usage:
Open IDA Pro, press Alt+F7, and select this script file.

Headless Execution:
Run with idal64 or batch execution:
  idal64 -c -A -Sida_sp550uz_annotator.py firmware.bin
"""

# TruePic III Memory Map Definitions
# 0x40000000: Section 1 SDRAM base
# 0x403f5108: Section 2 NDATA base
# 0x41f00000: Uncached SDRAM base
# 0x41f80000: Blackboard base
# 0x41fa0000: Stacks base
# 0x80410000: MMIO SDRAM base
# 0xc04c0000: MMIO DMA/NAND base
# 0xe0010000: MMIO Peripherals base
# 0xe081ffff: TruePic III ceiling

SEGMENTS = [
    ("SEC1_SDRAM", 0x40000000, 0x403F50E7, 7),
    ("SEC2_NDATA", 0x403F5108, 0x40855967, 5),
    ("UNCACHED_RAM", 0x41F00000, 0x41F7FFFF, 6),
    ("BLACKBOARD", 0x41F80000, 0x41F9FFFF, 6),
    ("STACKS", 0x41FA0000, 0x41FD0000, 6),
    ("MMIO_SDRAM", 0x80410000, 0x8041FFFF, 6),
    ("MMIO_DMA_NAND", 0xC04C0000, 0xC04CFFFF, 6),
    ("MMIO_PERIPH", 0xE0010000, 0xE081FFFF, 6),
]

def run():
    try:
        import idc
        import idaapi
        for name, start, end, perm in SEGMENTS:
            idc.add_segm_ex(start, end, 0, 1, 0, 0, perm)
            idc.set_segm_name(start, name)
    except (ImportError, NameError):
        pass

if __name__ == "__main__":
    run()
'''
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as f:
        f.write(content)


def generate_xref_html(dest_path: Path, pipeline: Optional[AnalysisPipeline] = None) -> None:
    """Generate searchable interactive single-page HTML cross-reference."""
    symbols = pipeline.symbols if pipeline else None
    jump_tables = pipeline.jump_tables if pipeline else None
    generator = DocumentationGenerator(symbols=symbols, jump_tables=jump_tables)
    generator.generate_html(dest_path)


def generate_xref_markdown(dest_dir: Path, pipeline: Optional[AnalysisPipeline] = None) -> None:
    """Generate linked markdown chapters for documentation."""
    symbols = pipeline.symbols if pipeline else None
    jump_tables = pipeline.jump_tables if pipeline else None
    generator = DocumentationGenerator(symbols=symbols, jump_tables=jump_tables)
    generator.generate_markdown(dest_dir)


def create_argument_parser() -> argparse.ArgumentParser:
    """Construct argument parser supporting all tier tests and scenario workflows."""
    parser = argparse.ArgumentParser(
        prog="olympus_re",
        description="Olympus SP-550UZ Reverse Engineering & Decompilation Framework",
    )
    # Inputs
    parser.add_argument(
        "--input",
        "-i",
        "--section1",
        dest="section1",
        type=Path,
        default=DEFAULT_SEC1 if DEFAULT_SEC1.exists() else Path("input.bin"),
        help="Path to Section 1 ARM code binary",
    )
    parser.add_argument(
        "--data-input",
        "-d",
        "--section2",
        dest="section2",
        type=Path,
        default=DEFAULT_SEC2 if DEFAULT_SEC2.exists() else None,
        help="Path to Section 2 data binary",
    )

    # Outputs
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("output"),
        help="Output directory for generated symbol artifacts",
    )
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=None,
        help="Output directory for generated documentation",
    )

    # Modes & Filters
    parser.add_argument(
        "--mode",
        choices=["full", "fast"],
        default="full",
        help="Analysis mode: full (comprehensive) or fast",
    )
    parser.add_argument("--functions-only", action="store_true", help="Analyze function boundaries only")
    parser.add_argument("--strings-only", action="store_true", help="Extract strings only")
    parser.add_argument("--no-literals", action="store_true", help="Skip literal pool extraction")
    parser.add_argument(
        "--analyze",
        action="store_true",
        default=True,
        help="Run static analysis pipeline (default: active)",
    )

    # Export Formats
    parser.add_argument(
        "--export-format",
        "-f",
        "--format",
        dest="export_format",
        default="all",
        help="Export formats: json, csv, jump_tables, all, or comma-separated list",
    )

    # Tooling Extensions
    parser.add_argument(
        "--decompiler",
        choices=["ghidra", "ida", "all", "mock"],
        help="Generate decompiler annotation scripts for Ghidra or IDA Pro",
    )
    parser.add_argument(
        "--doc",
        choices=["html", "markdown", "all"],
        help="Generate searchable HTML and/or Markdown documentation",
    )
    parser.add_argument(
        "--docgen",
        action="store_true",
        help="Generate production documentation deliverables (docs/xref.html and docs/xref/*.md)",
    )
    parser.add_argument(
        "--strict-links",
        action="store_true",
        help="Verify 100%% zero dead internal links in documentation",
    )

    # Verbosity
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose diagnostic output")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_argument_parser()
    args = parser.parse_args(argv)

    # Parse export formats
    raw_fmt = args.export_format.lower()
    if raw_fmt == "all":
        formats = ["all"]
    else:
        formats = [f.strip() for f in raw_fmt.split(",") if f.strip()]
        if "json" in formats and "csv" in formats and "jump_tables" not in formats:
            formats.append("jump_tables")

    config = PipelineConfig(
        section1_path=args.section1,
        section2_path=args.section2,
        output_dir=args.output_dir,
        docs_dir=args.docs_dir,
        mode=args.mode,
        functions_only=args.functions_only,
        strings_only=args.strings_only,
        no_literals=args.no_literals,
        export_formats=formats,
        verbose=args.verbose,
    )

    pipeline = AnalysisPipeline(config=config)
    stats = pipeline.run()

    if args.verbose:
        print(f"[*] Analysis complete: {stats.total_symbols} symbols, {stats.duration_seconds:.2f}s")

    # Handle Decompiler Target Generation
    if args.decompiler in ["ghidra", "all"]:
        generate_ghidra_script(args.output_dir / "ghidra_sp550uz_annotator.py")
    if args.decompiler in ["ida", "all"]:
        generate_ida_script(args.output_dir / "ida_sp550uz_annotator.py")

    # Handle Documentation Target Generation
    doc_dirs = set()
    if args.docs_dir:
        doc_dirs.add(Path(args.docs_dir))
    if args.doc:
        doc_dirs.add(Path(args.output_dir))
    if args.docgen:
        doc_dirs.add(Path(args.docs_dir) if args.docs_dir else Path("docs"))

    for d in doc_dirs:
        if args.doc in ["html", "all"] or args.docs_dir or args.docgen:
            generate_xref_html(d / "xref.html", pipeline=pipeline)
        if args.doc in ["markdown", "all"] or args.docgen:
            generate_xref_markdown(d / "xref", pipeline=pipeline)

    # If --strict-links passed, validate links
    if args.strict_links:
        for d in doc_dirs:
            validator = LinkValidator(html_path=d / "xref.html", md_dir=d / "xref")
            report = validator.validate_all()
            if not report.passed:
                print(f"[-] ERROR: Documentation validation failed: {report.errors}", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
