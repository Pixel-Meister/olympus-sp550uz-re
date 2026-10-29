"""
Acceptance Test Suite for Criterion V1: Structural & Static Analysis Validity.
Wraps TestV1AnalysisValidity for standard unittest discovery.
"""
import unittest
from tests.validate_v1_analysis import TestV1AnalysisValidity

__all__ = ["TestV1AnalysisValidity"]

if __name__ == "__main__":
    unittest.main()
