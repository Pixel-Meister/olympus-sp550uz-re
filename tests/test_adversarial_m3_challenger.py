"""
tests/test_adversarial_m3_challenger.py - Adversarial Stress Test Suite for Milestone 3
======================================================================================
Empirical verification and challenge suite for:
- LinkValidator & V3DocsValidator
  * Broken HTML anchor detection (#nonexistent_anchor)
  * Broken Markdown relative & cross-file link detection (missing.md, file.md#bad_anchor)
  * Directory traversal detection (../../etc/passwd, ../outside)
  * Out-of-bounds 32-bit hex address detection vs TruePic III memory map
  * Whitelisted non-memory constants & 2/4-digit hex values acceptance
- DocumentationGenerator & Framework CLI
  * Idempotence & SHA-256 byte-for-byte consistency across repeated docgen runs
  * Strict link validation exit code on broken link injection
  * Resiliency under empty / edge-case symbol inputs
"""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

# Ensure project root is in sys.path
_curr = Path(__file__).resolve()
_project_root = _curr.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from olympus_re.docgen.link_validator import (
    LinkValidator,
    KNOWN_NON_MEMORY_CONSTANTS,
    VALID_PHYSICAL_MEMORY_RANGES,
    is_valid_memory_address,
    is_valid_physical_address,
    slugify_heading,
)
from tests.validate_v3_docs import (
    V3DocsValidator,
    REQUIRED_MD_FILES,
    REQUIRED_MMIO_PERIPHERALS,
    REQUIRED_SUBSYSTEM_PATTERNS,
    REQUIRED_PTP_SCSI_ELEMENTS,
)
from olympus_re.docgen.generator import DocumentationGenerator


class TestAdversarialHtmlLinks(unittest.TestCase):
    """Stress tests for HTML anchor and internal href resolution."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.html_file = self.temp_path / "xref.html"
        self.md_dir = self.temp_path / "xref"
        self.md_dir.mkdir(parents=True, exist_ok=True)
        # Populate dummy valid md files
        for f in REQUIRED_MD_FILES:
            (self.md_dir / f).write_text(f"# {f}\nValid content > 100 bytes\n" + "x" * 120)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_broken_html_anchor_detected(self):
        """Adversarial: Link targeting nonexistent anchor must be detected as dead link."""
        html_content = """<!DOCTYPE html>
        <html>
        <head><title>Test</title></head>
        <body>
            <div id="valid_section">Section Content</div>
            <a href="#valid_section">Valid Link</a>
            <a href="#nonexistent_anchor">Broken Link</a>
        </body>
        </html>
        """
        self.html_file.write_text(html_content, encoding="utf-8")
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        report = validator.validate_all()
        self.assertFalse(report.passed)
        self.assertTrue(any("nonexistent_anchor" in err for err in report.dead_html_links))
        self.assertFalse(any("valid_section" in err for err in report.dead_html_links))

    def test_html_self_referencing_hash_ignored(self):
        """Standard behavior: href='#' (top-of-page or button link) must not be flagged as dead."""
        html_content = """<!DOCTYPE html>
        <html>
        <body>
            <div id="top">Header</div>
            <a href="#">Back to top</a>
            <a href="#top">Top Link</a>
        </body>
        </html>
        """
        self.html_file.write_text(html_content, encoding="utf-8")
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        validator.load_corpus()
        validator.validate_html_links()
        self.assertEqual(len(validator.report.dead_html_links), 0)

    def test_html_multiple_broken_links_captured_with_linenos(self):
        """Verify multiple broken links on different lines are all logged."""
        html_content = """<!DOCTYPE html>
        <html>
        <body>
            <a href="#ghost1">Ghost 1</a>
            <div>Some content</div>
            <a href="#ghost2">Ghost 2</a>
        </body>
        </html>"""
        self.html_file.write_text(html_content, encoding="utf-8")
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        validator.load_corpus()
        validator.validate_html_links()
        self.assertEqual(len(validator.report.dead_html_links), 2)
        err_text = " ".join(validator.report.dead_html_links)
        self.assertIn("ghost1", err_text)
        self.assertIn("ghost2", err_text)


class TestAdversarialMarkdownLinks(unittest.TestCase):
    """Stress tests for Markdown cross-file, anchor, and directory traversal links."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.html_file = self.temp_path / "xref.html"
        self.html_file.write_text("<!DOCTYPE html><html><body>Valid</body></html>" + "x" * 100)
        self.md_dir = self.temp_path / "xref"
        self.md_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_broken_markdown_internal_anchor_detected(self):
        """Adversarial: Link [text](#missing-anchor) must be flagged when anchor missing."""
        doc = self.md_dir / "index.md"
        doc.write_text(
            "# Overview\n\n"
            "Here is a valid heading: [Go](#overview)\n"
            "Here is a broken heading: [Bad](#nonexistent-anchor)\n"
            + "x" * 100
        )
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        validator.load_corpus()
        validator.validate_markdown_links()
        self.assertTrue(any("nonexistent-anchor" in err for err in validator.report.dead_md_links))
        self.assertFalse(any("overview" in err for err in validator.report.dead_md_links))

    def test_broken_markdown_cross_file_missing_target_file(self):
        """Adversarial: Link [text](nonexistent.md) or [text](nonexistent.md#fake) must be flagged."""
        doc = self.md_dir / "index.md"
        doc.write_text(
            "# Overview\n\n"
            "Link to nonexistent file: [Missing](nonexistent.md)\n"
            "Link with anchor: [Missing Anchor](nonexistent.md#fake)\n"
            + "x" * 100
        )
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        validator.load_corpus()
        validator.validate_markdown_links()
        self.assertGreaterEqual(len(validator.report.dead_md_links), 2)
        err_text = " ".join(validator.report.dead_md_links)
        self.assertIn("nonexistent.md", err_text)

    def test_broken_markdown_cross_file_existing_file_bad_anchor(self):
        """Adversarial: Target file exists, but target anchor does not."""
        doc_a = self.md_dir / "subsystems.md"
        doc_a.write_text("# Subsystem Deep Dive\n\n## OSD Engine\nContent\n" + "x" * 100)
        doc_b = self.md_dir / "index.md"
        doc_b.write_text(
            "# Index\n\n"
            "Valid: [OSD](subsystems.md#osd-engine)\n"
            "Invalid: [Fake](subsystems.md#nonexistent-heading)\n"
            + "x" * 100
        )
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        validator.load_corpus()
        validator.validate_markdown_links()
        err_text = " ".join(validator.report.dead_md_links)
        self.assertIn("nonexistent-heading", err_text)
        self.assertNotIn("osd-engine", err_text)

    def test_directory_traversal_attack_paths_detected(self):
        """Adversarial: Links containing '../' escaping doc root must be caught and blocked."""
        doc = self.md_dir / "index.md"
        doc.write_text(
            "# Index\n\n"
            "Traversal 1: [Passwd](../../etc/passwd)\n"
            "Traversal 2: [Shadow](../outside.txt)\n"
            "Traversal 3: [Etc](../../../../../../etc/passwd#root)\n"
            + "x" * 100
        )
        validator = LinkValidator(html_path=self.html_file, md_dir=self.md_dir)
        validator.load_corpus()
        validator.validate_markdown_links()
        self.assertGreaterEqual(len(validator.report.dead_md_links), 3)
        for dead in validator.report.dead_md_links:
            self.assertTrue("traversal" in dead.lower() or "not found" in dead.lower())


class TestAdversarialMemoryMapAndConstants(unittest.TestCase):
    """Stress tests for 32-bit hex address boundaries and constant whitelisting."""

    def test_out_of_bounds_addresses_rejected(self):
        """Adversarial: 32-bit hex addresses outside physical hardware ranges must be invalid."""
        out_of_bounds = [
            0x00000001,  # Non-whitelisted low vector
            0x10000000,  # Unmapped bottom space
            0x20000000,  # Unmapped
            0x3FFFFFFF,  # 1 byte below Section 1 SDRAM
            0x40855968,  # 1 byte above Section 2 NDATA (unmapped gap)
            0x41000000,  # Unmapped gap between NDATA and uncached SDRAM
            0x41EFFFFF,  # 1 byte below Uncached SDRAM buffers
            0x41FD0001,  # 1 byte above Stacks
            0x50000000,  # Unmapped mid-range
            0x8040FFFF,  # 1 byte below MMIO SDRAM Controller
            0x80420000,  # 1 byte above MMIO SDRAM Controller
            0x90000000,  # Unmapped MMIO gap
            0xC04BFFFF,  # 1 byte below MMIO DMA/NAND Controller
            0xC04D0000,  # 1 byte above MMIO DMA/NAND Controller
            0xDFFFFFFF,  # 1 byte below MMIO Peripherals block
            0xE0820000,  # 1 byte above MMIO Peripherals block
            0xF0000000,  # High unmapped space
            0xDEADBEEF,  # Classic debug canary
            0x12345678,  # Random test pattern
        ]
        for addr in out_of_bounds:
            self.assertFalse(
                is_valid_memory_address(addr),
                f"Address 0x{addr:08X} was incorrectly accepted as valid memory!"
            )

    def test_boundary_physical_addresses_accepted(self):
        """Empirical: All valid physical memory range boundaries must be accepted."""
        valid_boundaries = [
            # Section 1 & Section 2 SDRAM
            0x40000000,
            0x403F50E7,
            0x403F5108,
            0x40855967,
            # Uncached SDRAM, Blackboard, Stacks
            0x41F00000,
            0x41F7FFFF,
            0x41F80000,
            0x41F9FFFF,
            0x41FA0000,
            0x41FD0000,
            # MMIO SDRAM Controller
            0x80410000,
            0x8041FFFF,
            # MMIO DMA & NAND Controller
            0xC04C0000,
            0xC04CFFFF,
            # MMIO Timers, Interrupts, GPIO, ISP, Video DAC, JPEG
            0xE0000000,
            0xE0010000,
            0xE0200000,
            0xE0400000,
            0xE0600000,
            0xE0800000,
            0xE081FFFF,
        ]
        for addr in valid_boundaries:
            self.assertTrue(
                is_valid_memory_address(addr),
                f"Boundary address 0x{addr:08X} was incorrectly rejected!"
            )

    def test_all_12_whitelisted_non_memory_constants(self):
        """Verify 100% of the 12 recognized non-memory constants pass cleanly."""
        expected_constants = [
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
        ]
        self.assertEqual(len(KNOWN_NON_MEMORY_CONSTANTS), 12)
        for c in expected_constants:
            self.assertIn(c, KNOWN_NON_MEMORY_CONSTANTS)
            self.assertTrue(is_valid_memory_address(c), f"Constant 0x{c:08X} was rejected!")

    def test_doc_text_memory_scanning(self):
        """Adversarial: LinkValidator must detect 0xDEADBEEF in document text but pass 0xC0 or 0x1001."""
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            html_file = tp / "xref.html"
            md_dir = tp / "xref"
            md_dir.mkdir()
            html_file.write_text("<!DOCTYPE html><html><body>Valid 0x40000000 text</body></html>" + "x" * 100)

            # Test text with invalid 8-digit hex and valid non-memory 2-digit/4-digit hex
            bad_md = md_dir / "index.md"
            bad_md.write_text(
                "# Memory\n"
                "Valid 32-bit: 0x40000800\n"
                "Whitelisted opcode: 0xE12FFF1E\n"
                "2-digit SCSI CDB: 0xC0, 0xC4\n"
                "4-digit PTP opcode: 0x1001, 0x9119\n"
                "Adversarial bad address: 0xDEADBEEF\n"
                + "x" * 100
            )

            validator = LinkValidator(html_path=html_file, md_dir=md_dir)
            validator.load_corpus()
            validator.validate_memory_references()

            self.assertEqual(len(validator.report.unresolvable_addresses), 1)
            self.assertIn("0xDEADBEEF", validator.report.unresolvable_addresses[0])


class TestDocgenAndCliIdempotence(unittest.TestCase):
    """Stress tests for DocumentationGenerator, CLI flags, idempotence, and failure exit codes."""

    def test_cli_docgen_idempotence_and_sha256_parity(self):
        """Regenerate documentation multiple times and verify byte-for-byte SHA256 integrity."""
        docs_html = Path("docs/xref.html")
        docs_md = Path("docs/xref")

        self.assertTrue(docs_html.exists(), "docs/xref.html must exist")
        self.assertTrue(docs_md.exists(), "docs/xref must exist")

        def compute_hashes():
            hashes = {}
            hashes["xref.html"] = hashlib.sha256(docs_html.read_bytes()).hexdigest()
            for md in sorted(docs_md.glob("*.md")):
                hashes[md.name] = hashlib.sha256(md.read_bytes()).hexdigest()
            return hashes

        initial_hashes = compute_hashes()

        # Run CLI docgen
        cmd = [sys.executable, "-m", "olympus_re.cli", "--docgen", "--strict-links"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0, f"CLI docgen failed: {res.stderr}")

        second_hashes = compute_hashes()
        self.assertEqual(initial_hashes, second_hashes, "Docgen regeneration was NOT byte-for-byte idempotent!")

        # Run CLI docgen a third time
        res2 = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res2.returncode, 0, f"Second CLI docgen failed: {res2.stderr}")

        third_hashes = compute_hashes()
        self.assertEqual(second_hashes, third_hashes, "Docgen regeneration drifted on third run!")

    def test_cli_strict_links_detects_broken_link_and_exits_1(self):
        """Verify CLI with --strict-links terminates with exit code 1 when bad link is injected."""
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            # Run generator into temp dir
            gen = DocumentationGenerator()
            gen.generate_all(docs_dir=tp)

            # Check that temp docs pass initially
            validator = LinkValidator(html_path=tp / "xref.html", md_dir=tp / "xref")
            self.assertTrue(validator.validate_all().passed)

            # Inject broken link into temp index.md
            index_path = tp / "xref" / "index.md"
            with open(index_path, "a", encoding="utf-8") as f:
                f.write("\n\n[Broken Link Test](nonexistent_chapter.md#bad_anchor)\n")

            # Run CLI link validator via --strict-links pointing to custom docs dir
            cmd = [
                sys.executable,
                "-m",
                "olympus_re.cli",
                "--docs-dir",
                str(tp),
                "--strict-links",
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(res.returncode, 1, "CLI must exit with code 1 when dead links are detected!")
            self.assertIn("ERROR: Documentation validation failed", res.stderr)

    def test_generator_with_minimal_empty_inputs(self):
        """Verify DocumentationGenerator does not crash when symbols/jump tables are empty."""
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            gen = DocumentationGenerator(symbols=[], jump_tables=[])
            gen.generate_all(docs_dir=tp)

            html_file = tp / "xref.html"
            self.assertTrue(html_file.exists())
            self.assertGreater(html_file.stat().st_size, 1000)

            for f in REQUIRED_MD_FILES:
                p = tp / "xref" / f
                self.assertTrue(p.exists())
                self.assertGreater(p.stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
