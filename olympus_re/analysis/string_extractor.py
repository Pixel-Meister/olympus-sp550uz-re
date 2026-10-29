"""
olympus_re/analysis/string_extractor.py - ASCII & UTF-16LE String Scanning
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional

from olympus_re.models.symbols import Symbol, classify_subsystem


@dataclass
class ExtractedString:
    address: int
    text: str
    encoding: str  # "ascii" or "utf-16le"
    length: int
    domain: str
    subsystem: str

    def to_symbol(self) -> Symbol:
        return Symbol(
            address=self.address,
            name=f"str_{self.address:08X}",
            type="string",
            size=self.length,
            domain=self.domain,
            subsystem=self.subsystem,
            metadata={
                "text": self.text,
                "encoding": self.encoding,
            },
        )

    def to_symbol_dict(self) -> Dict:
        return self.to_symbol().to_dict()


class StringExtractor:
    """Scans and extracts strings from Section 1 (ASCII) and Section 2 (UTF-16LE)."""

    MAX_STRING_LEN = 4096

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        self._ascii_pattern = re.compile(b"[\x20-\x7e]{" + str(min_length).encode() + b",}")
        self._utf16_pattern = re.compile(b"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + b",}")

    def classify_subsystem(self, text: str) -> str:
        return classify_subsystem(text)

    def extract_section1_ascii(
        self, data: bytes, base_address: int = 0x40000000
    ) -> List[ExtractedString]:
        """Extract clean ASCII strings from Section 1 code binary."""
        results: List[ExtractedString] = []
        if len(data) < self.min_length:
            return results

        for m in self._ascii_pattern.finditer(data):
            raw = m.group()
            raw_clean = raw[: self.MAX_STRING_LEN]
            try:
                decoded = raw_clean.decode("ascii")
            except UnicodeDecodeError:
                continue

            addr = base_address + m.start()
            subsystem = self.classify_subsystem(decoded)
            results.append(
                ExtractedString(
                    address=addr,
                    text=decoded,
                    encoding="ascii",
                    length=len(raw_clean),
                    domain="Section 1 SDRAM (NPROG)",
                    subsystem=subsystem,
                )
            )

        return results

    def extract_section2_utf16le(
        self, data: bytes, base_address: int = 0x403F5108
    ) -> List[ExtractedString]:
        """Extract UTF-16LE strings from Section 2 NDATA binary."""
        results: List[ExtractedString] = []
        if len(data) < self.min_length * 2:
            return results

        # Regex scan handles arbitrary byte alignment (even and odd offsets)
        for m in self._utf16_pattern.finditer(data):
            raw = m.group()
            even_len = len(raw) - (len(raw) % 2)
            raw_clean = raw[: min(even_len, self.MAX_STRING_LEN * 2)]
            try:
                decoded = raw_clean.decode("utf-16le")
            except UnicodeDecodeError:
                continue

            addr = base_address + m.start()
            subsystem = self.classify_subsystem(decoded)
            results.append(
                ExtractedString(
                    address=addr,
                    text=decoded,
                    encoding="utf-16le",
                    length=len(raw_clean),
                    domain="Section 2 SDRAM (NDATA)",
                    subsystem=subsystem,
                )
            )

        return results
