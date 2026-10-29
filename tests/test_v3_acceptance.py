"""
Acceptance Test Suite for Criterion V3: Documentation Completeness & Link Quality.
Wraps TestV3DocsCompleteness for standard unittest discovery.
"""
import unittest
from tests.validate_v3_docs import TestV3DocsCompleteness

__all__ = ["TestV3DocsCompleteness"]

if __name__ == "__main__":
    unittest.main()
