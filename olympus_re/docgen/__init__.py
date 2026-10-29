"""
olympus_re/docgen - Documentation & Cross-Reference Generation Engine
======================================================================
Provides interactive HTML and linked Markdown documentation generators and
strict link/memory reference validation tooling.
"""

from olympus_re.docgen.generator import DocumentationGenerator
from olympus_re.docgen.link_validator import (
    HTMLLinkCollector,
    KNOWN_NON_MEMORY_CONSTANTS,
    LinkValidator,
    REQUIRED_MD_FILES,
    REQUIRED_MMIO_PERIPHERALS,
    REQUIRED_PTP_SCSI_ELEMENTS,
    REQUIRED_SUBSYSTEM_PATTERNS,
    VALID_PHYSICAL_MEMORY_RANGES,
    ValidationReport,
    escape_pipe,
    is_valid_memory_address,
    is_valid_physical_address,
    slugify_heading,
)

__all__ = [
    "DocumentationGenerator",
    "LinkValidator",
    "ValidationReport",
    "HTMLLinkCollector",
    "slugify_heading",
    "escape_pipe",
    "is_valid_memory_address",
    "is_valid_physical_address",
    "KNOWN_NON_MEMORY_CONSTANTS",
    "VALID_PHYSICAL_MEMORY_RANGES",
    "REQUIRED_MD_FILES",
    "REQUIRED_MMIO_PERIPHERALS",
    "REQUIRED_SUBSYSTEM_PATTERNS",
    "REQUIRED_PTP_SCSI_ELEMENTS",
]
