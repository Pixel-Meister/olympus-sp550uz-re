"""
Acceptance Test Suite for Criterion V2: Decompiler Script Quality & Execution.
Wraps TestV2DecompilerQuality for standard unittest discovery.
"""
import unittest
from tests.validate_v2_decompiler import TestV2DecompilerQuality

__all__ = ["TestV2DecompilerQuality"]

if __name__ == "__main__":
    unittest.main()
