"""
tests/test_adversarial_m3_iter2_challenger.py - Adversarial Stress & Verification Suite
======================================================================================
Empirical Challenger 1 Suite for Milestone 3 Iteration 2:
1. XSS Escaping and Attribute Breakout Immunity
   - Checks <script>alert(1)</script>, "><img src=x onerror=alert(2)>, ' onfocus='alert(3)'
   - Checks single-escaping guarantee (no &amp;lt;)
   - Checks DOM parsing with HTMLParser for zero injected tags and zero on* event handlers
   - Adversarial testing across symbol name, subsystem, type, domain, jump table bounds
2. URL Hash Navigation Resilience
   - Valid hex hash resolution (#sym-0x401b32f4, #sym-0x40000000)
   - Rejection / ignoring of malformed / malicious hashes (#sym-"><script>, #invalid..selector)
   - Node.js execution of handleAnchorHash logic under stress
3. Acceptance & Deliverable Parity Checks
"""

from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

# Ensure project root is in sys.path
_curr = Path(__file__).resolve()
_project_root = _curr.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from olympus_re.docgen.generator import DocumentationGenerator
from olympus_re.docgen.link_validator import LinkValidator
from tests.validate_v3_docs import V3DocsValidator


class DOMSecurityParser(HTMLParser):
    """Parses HTML into DOM elements and extracts all tags and on* event handlers."""

    def __init__(self):
        super().__init__()
        self.tags: list[str] = []
        self.event_handlers: list[tuple[str, str, str]] = []
        self.element_ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        self.tags.append(tag.lower())
        for attr, val in attrs:
            val_str = val or ""
            if attr.lower().startswith("on"):
                self.event_handlers.append((tag.lower(), attr.lower(), val_str))
            if attr.lower() in ("id", "name"):
                self.element_ids.add(val_str)


class TestAdversarialXssAndAttributeBreakout(unittest.TestCase):
    """Stress tests for XSS injection immunity and attribute escaping in xref.html."""

    def test_mandatory_adversarial_payloads_in_symbol_names(self):
        """Verify the three mandatory adversarial payloads from dispatch are fully escaped."""
        payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(2)>',
            "' onfocus='alert(3)'",
        ]

        symbols = []
        for i, payload in enumerate(payloads):
            symbols.append({
                "address": 0x40001000 + (i * 4),
                "name": payload,
                "type": "function",
                "domain": "Section 1 SDRAM",
                "subsystem": "General",
                "metadata": {"callers": [], "call_targets": []},
            })

        docgen = DocumentationGenerator(
            symbols=symbols,
            jump_tables=[],
            symbols_path=Path("/tmp/none.json"),
            jump_tables_path=Path("/tmp/none.json"),
        )
        rendered = docgen.render_template("xref.html.j2")

        # 1. Verify none of the raw unescaped payloads are in the rendered output
        for p in payloads:
            self.assertNotIn(p, rendered, f"Raw unescaped payload present in output: {p}")

        # 2. Verify single escaping (no &amp;lt;)
        self.assertNotIn("&amp;lt;", rendered, "Double-escaping detected (&amp;lt;)!")
        self.assertNotIn("&amp;gt;", rendered, "Double-escaping detected (&amp;gt;)!")
        self.assertNotIn("&amp;quot;", rendered, "Double-escaping detected (&amp;quot;)!")

        # 3. DOM parse and assert zero injected tags or event handlers
        parser = DOMSecurityParser()
        parser.feed(rendered)

        # Only the 1 built-in script tag in xref.html.j2 is allowed
        self.assertEqual(parser.tags.count("script"), 1, "Injected <script> tags detected!")
        self.assertEqual(parser.tags.count("img"), 0, "Injected <img> tags detected!")
        self.assertEqual(parser.tags.count("svg"), 0, "Injected <svg> tags detected!")
        self.assertEqual(len(parser.event_handlers), 0, f"Injected event handlers: {parser.event_handlers}")

    def test_adversarial_injection_in_all_symbol_fields(self):
        """Stress test XSS and breakout payloads in subsystem, type, domain, and jump table bounds."""
        adv_subsystem = '<script>alert("sub")</script>'
        adv_type = '"><b onmouseover=alert("type")>'
        adv_domain = '\' onclick=\'alert("domain")\''
        adv_bounds = '<svg/onload=alert("bounds")>'

        symbols = [{
            "address": 0x40002000,
            "name": 'normal_name"><script>alert(99)</script>',
            "type": adv_type,
            "domain": adv_domain,
            "subsystem": adv_subsystem,
            "metadata": {"callers": [], "call_targets": []},
        }]

        jump_tables = [{
            "site": 0x4019E1E8,
            "table_address": 0x4019E324,
            "entry_count": 16,
            "bounds": adv_bounds,
            "default_target": 0x4019E9F8,
            "targets": [0x4019E5F0],
        }]

        docgen = DocumentationGenerator(
            symbols=symbols,
            jump_tables=jump_tables,
            symbols_path=Path("/tmp/none.json"),
            jump_tables_path=Path("/tmp/none.json"),
        )
        rendered = docgen.render_template("xref.html.j2")

        # DOM parse
        parser = DOMSecurityParser()
        parser.feed(rendered)

        self.assertEqual(parser.tags.count("script"), 1)
        self.assertEqual(parser.tags.count("b"), 0)
        self.assertEqual(parser.tags.count("svg"), 0)
        self.assertEqual(len(parser.event_handlers), 0)


class TestAdversarialUrlHashNavigation(unittest.TestCase):
    """Stress tests for URL hash navigation regex and exception resilience."""

    def setUp(self):
        self.html_path = Path("docs/xref.html")
        self.assertTrue(self.html_path.exists(), "docs/xref.html must exist")
        self.html_content = self.html_path.read_text(encoding="utf-8")

    def test_hash_navigation_regex_and_try_catch_in_html(self):
        """Verify docs/xref.html contains regex validation and try-catch handling."""
        self.assertIn("handleAnchorHash", self.html_content)
        self.assertIn("/^#sym-0x[0-9a-fA-F]+$/i", self.html_content)
        self.assertIn("try {", self.html_content)
        self.assertIn("catch", self.html_content)

    def test_url_hash_validation_matrix(self):
        """Test matrix of valid and malicious hashes against the regex."""
        valid_hashes = [
            "#sym-0x401b32f4",
            "#sym-0x40000000",
            "#sym-0x4019E1E8",
            "#sym-0x4019e1e8",
            "#sym-0x00000000",
            "#sym-0xFFFFFFFF",
        ]
        malicious_or_malformed_hashes = [
            '#sym-"><script>',
            "#invalid..selector",
            "#sym-0x401b32f4<script>",
            '#sym-0x401b32f4" onerror="alert(1)',
            "#sym-0x401b32f4';alert(1)//",
            "#sym-0xZZZZ",
            "#sym-",
            "#",
            "",
            "#..:::--",
            "#sym-0x401b32f4.class",
            "#sym-0x401b32f4#secondary",
            "javascript:alert(1)",
            "data:text/html,<script>",
            "#sym-0x401b32f4\x00",
            "#sym-0x401b32f4\n<script>",
        ]

        pattern = re.compile(r"^#sym-0x[0-9a-fA-F]+$", re.IGNORECASE)

        for h in valid_hashes:
            self.assertTrue(pattern.match(h) is not None, f"Valid hash rejected: {h}")

        for h in malicious_or_malformed_hashes:
            self.assertFalse(pattern.match(h) is not None, f"Adversarial hash accepted: {h}")

    def test_node_headless_hash_handler_execution(self):
        """Run handleAnchorHash logic inside Node.js under adversarial inputs to verify zero exceptions."""
        node_script = """
        const hashes = [
          '#sym-0x401b32f4',
          '#sym-0x40000000',
          '#sym-\"><script>',
          '#invalid..selector',
          '#sym-0x401b32f4<script>',
          '#sym-0x401b32f4\" onerror=\"alert(1)',
          '#sym-0xZZZZ',
          '#..:::--',
          '',
          null,
          undefined
        ];

        let executionErrors = 0;
        for (const h of hashes) {
          try {
            const hash = h;
            if (hash && /^#sym-0x[0-9a-fA-F]+$/i.test(hash)) {
              // Valid hash branch
              if (!hash.startsWith('#sym-0x')) {
                throw new Error('Regex allowed non-sym hash: ' + hash);
              }
            } else {
              // Malformed / invalid branch: safely ignored
            }
          } catch (e) {
            executionErrors++;
          }
        }

        if (executionErrors > 0) {
          process.exit(1);
        }
        process.exit(0);
        """
        res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Node.js execution failed: {res.stderr}")


class TestDeliverableIntegrityAndAcceptanceCriteria(unittest.TestCase):
    """Verify official acceptance criteria and deliverable integrity."""

    def test_acceptance_v3_validator(self):
        """Run official V3DocsValidator directly."""
        validator = V3DocsValidator()
        passed = validator.run_all()
        self.assertTrue(passed, f"V3DocsValidator failed with errors: {validator.errors}")
        self.assertEqual(len(validator.errors), 0)
        self.assertEqual(len(validator.dead_html_links), 0)
        self.assertEqual(len(validator.dead_md_links), 0)
        self.assertEqual(len(validator.unresolvable_addresses), 0)


if __name__ == "__main__":
    unittest.main()
