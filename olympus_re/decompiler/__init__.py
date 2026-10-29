"""
olympus_re.decompiler - Decompiler Annotation and Tooling Package
=================================================================
Automated annotation tooling, memory segmentation, symbol import,
and mock execution environments for Ghidra and IDA Pro.
"""

from pathlib import Path

from olympus_re.decompiler.ghidra_sp550uz_annotator import (
    GhidraAnnotator,
    MEMORY_SEGMENTS,
    annotate_symbols as annotate_ghidra_symbols,
    format_subsystem_plate,
    locate_symbols_file as locate_ghidra_symbols_file,
    setup_memory_blocks,
)
from olympus_re.decompiler.ida_sp550uz_annotator import (
    IdaAnnotator,
    SEGMENTS as IDA_SEGMENTS,
    annotate_builtin_hardware_symbols,
    create_memory_segments as create_ida_memory_segments,
    find_symbols_file as find_ida_symbols_file,
    import_symbols_from_json as import_ida_symbols,
    is_valid_truepic_address,
    sanitize_comment,
    sanitize_symbol_name,
)
from olympus_re.decompiler.mock_environment import (
    FaultInjectingMockAPI,
    MockAddress,
    MockFlatProgramAPI,
    MockGhidraFlatProgramAPI,
    MockIDAPython,
    MockIdaAPI,
    MockMemoryBlock,
    sandbox_ghidra_execution,
    sandbox_ida_execution,
)

_DECOMPILER_DIR = Path(__file__).resolve().parent
GHIDRA_SCRIPT_PATH = _DECOMPILER_DIR / "ghidra_sp550uz_annotator.py"
GHIDRA_SCRIPT_ALT_PATH = _DECOMPILER_DIR / "ghidra_annotator.py"
IDA_SCRIPT_PATH = _DECOMPILER_DIR / "ida_sp550uz_annotator.py"
IDA_SCRIPT_ALT_PATH = _DECOMPILER_DIR / "ida_annotator.py"

__all__ = [
    # Ghidra Tooling
    "GhidraAnnotator",
    "MEMORY_SEGMENTS",
    "setup_memory_blocks",
    "annotate_ghidra_symbols",
    "format_subsystem_plate",
    "locate_ghidra_symbols_file",
    "GHIDRA_SCRIPT_PATH",
    "GHIDRA_SCRIPT_ALT_PATH",
    # IDA Pro Tooling
    "IdaAnnotator",
    "IDA_SEGMENTS",
    "create_ida_memory_segments",
    "annotate_builtin_hardware_symbols",
    "import_ida_symbols",
    "is_valid_truepic_address",
    "sanitize_symbol_name",
    "sanitize_comment",
    "find_ida_symbols_file",
    "IDA_SCRIPT_PATH",
    "IDA_SCRIPT_ALT_PATH",
    # Mock Environment
    "MockAddress",
    "MockMemoryBlock",
    "MockGhidraFlatProgramAPI",
    "MockFlatProgramAPI",
    "MockIDAPython",
    "MockIdaAPI",
    "FaultInjectingMockAPI",
    "sandbox_ghidra_execution",
    "sandbox_ida_execution",
]
