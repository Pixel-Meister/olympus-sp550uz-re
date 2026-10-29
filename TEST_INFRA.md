# Test Infrastructure & Quality Assurance Specification

## 1. Testing Philosophy
The Olympus SP-550UZ Reverse Engineering Framework testing suite adheres to an **opaque-box, requirement-driven, and forensically honest** architecture.
- **Opaque-Box:** Tests validate system behavior strictly through external contracts, public APIs, CLI invocations, and exported artifacts (`symbols.json`, `symbols.csv`, `jump_tables.json`, `docs/xref.html`, `ghidra_annotator.py`, `ida_annotator.py`).
- **Requirement-Driven:** Every test case maps directly to requirements R1, R2, R3 and acceptance criteria V1, V2, V3 from `ORIGINAL_REQUEST.md`, as well as the 58 features in `PROJECT.md`.
- **Honest Progressive Testability:** Tests assert correctness against physical hardware truth (TruePic III memory map `0x40000000`–`0xE081FFFF`, known reset vectors, verified jump table targets). When testing framework deliverables prior to their implementation, tests cleanly report `unittest.SkipTest("pending milestone MX")` rather than substituting dummy mock pipelines or self-certifying tautologies.
- **Forensic Integrity:** No test may assert identity on locally declared literals (`x = 5; assertEqual(x, 5)`). No test may simulate execution using private mock pipelines that synthesize fake symbols.

---

## 2. Directory Layout
All test files reside in `tests/` at the project root:
```text
tests/
├── __init__.py                 # Test package initialization (standard recursive discovery)
├── support.py                  # Shared test fixtures, mock engines, binary loaders, schemas
├── test_tier1_features.py      # Tier 1: Feature coverage (81 tests across 15 Feature Groups)
├── test_tier2_boundaries.py    # Tier 2: Boundary value analysis & corner cases (75 tests)
├── test_tier3_pairwise.py      # Tier 3: Pairwise combinatorial matrix L16(4^5) (16 tests)
├── test_tier4_scenarios.py     # Tier 4: Real-world reverse engineering workflows (5 scenarios)
├── test_v1_acceptance.py       # V1 Acceptance Test Suite wrapper (3 tests)
├── test_v2_acceptance.py       # V2 Acceptance Test Suite wrapper (6 tests)
├── test_v3_acceptance.py       # V3 Acceptance Test Suite wrapper (8 tests)
├── validate_v1_analysis.py     # V1 Acceptance Criteria Validator & Standalone CLI
├── validate_v2_decompiler.py   # V2 Acceptance Criteria Validator & Standalone CLI
└── validate_v3_docs.py         # V3 Acceptance Criteria Validator & Standalone CLI
```

---

## 3. Test Runner Commands & Semantics
- **Full Test Suite Run (Canonical Command):**
  ```bash
  python3 -m unittest discover tests -v
  ```
  Discovers all 7 `test_*.py` suites and runs all 194 distinct tests.
- **Exit Code Semantics:**
  - `0`: All tests passed or cleanly skipped.
  - `1`: One or more tests failed or encountered errors.
  - `5`: No tests discovered (fails CI gate).
- **Standalone Acceptance Gate Runs (CLI Mode):**
  ```bash
  python3 tests/validate_v1_analysis.py
  python3 tests/validate_v2_decompiler.py
  python3 tests/validate_v3_docs.py
  ```
  - Exit `0`: Target deliverables exist and pass 100% of acceptance criteria.
  - Exit `1`: Target deliverables are absent or fail one or more acceptance checks.

---

## 4. Testing Methodology

### 4.1 Category-Partition (Tier 1)
Inputs and operations are partitioned into equivalence categories across 15 Feature Groups:
1. **Memory Domains:** 9 TruePic III regions (Section 1 Code, Section 2 NDATA, Uncached RAM, Blackboard, Banked Stacks, MMIO SDRAM, MMIO DMA/NAND, MMIO Peripherals, Full Span).
2. **Instruction Streams:** ARMv5TE pure 32-bit instructions, function prologues (`push {..., lr}`, `push {r8, sb}`), function epilogues (`bx lr`, `pop {..., pc}`), branch calls (`BL`), literal loads (`LDR [pc, #imm]`).
3. **Dispatch Tables:** Compiler switch tables, indexed jump tables, bounds-checked indirect branches.
4. **Export Formats:** Structured JSON, tabular CSV, Jinja2 single-page interactive HTML, Markdown chapters, PyGhidra Python, IDAPython.

### 4.2 Boundary Value Analysis (Tier 2)
BVA focuses on transitions and extreme limits:
- **Address Limits:** `0x3FFFFFFF` (out-of-bounds low), `0x40000000` (code start), `0x403F50E7` (code end), `0x403F50E8` (unmapped gap), `0x403F5108` (NDATA start), `0x40855967` (NDATA end), `0x41F00000` (uncached start), `0x41F80000` (blackboard start), `0x41FA0000` (stacks start), `0x80410000` (SDRAM MMIO), `0xC04C0000` (DMA/NAND MMIO), `0xE0010000` (Timers/ISP MMIO), `0xE081FFFF` (MMIO end), `0xE0820000` (out-of-bounds high).
- **Jump Table Indices:** Mode `0x00` (min), `0x18` (max bound), `0x19` (first out-of-bound target), negative indices.
- **Threshold Boundaries:** 2,499 functions (fail), 2,500 functions (exact threshold pass), 8,154 (empirical ground truth).
- **Binary Boundaries:** 0 bytes (empty), truncated headers (8 bytes, 16 bytes), odd length binaries.

### 4.3 Pairwise Combinatorial Testing (Tier 3)
Orthogonal combinations across multi-dimensional CLI parameters ($L_{16}(4^5)$ covering array):
- `Input Binary`: {Synthetic Minimal, Truncated Boundary, Section 1 Slice, Dual-Section Full}
- `Analysis Modes`: {Full Comprehensive, Fast No-Literals, Functions-Only, Strings-Only}
- `Output Formats`: {JSON only, CSV only, JSON + CSV, Jump Tables only}
- `Decompiler Targets`: {Ghidra, IDA Pro, Both, Mock}
- `Documentation Formats`: {HTML, Markdown, Both, Strict Link Validation}

Tier 3 invokes the actual framework entry point `olympus_re.cli` using `subprocess.run`, verifying genuine exported artifacts in temporary directories. In Milestone E2E, it cleanly skips with `unittest.SkipTest("olympus_re.cli and analysis pipeline pending implementation in milestone M1")`.

### 4.4 Real-World Workload Testing (Tier 4)
Realistic workflows simulating reverse engineering tasks:
1. Cold boot analysis and hardware register audit.
2. OSD display engine, jump tables, and epilogue dispatch verification.
3. Power management, sleep inhibit, and RTOS event dispatch table audit.
4. Storage, firmware update (`/FIRMWARE/FIRMWARE.BIN`), and PTP-over-SCSI flasher command structure extraction.
5. End-to-end production pipeline run and forensic link audit.

---

## 5. Coverage Thresholds & Progressive Verification State

| Tier / Suite | Target Threshold | Pre-Implementation (E2E) State | Post-Implementation (M1–M4) State |
| :--- | :--- | :--- | :--- |
| **Tier 1 (Features)** | **81 tests** across 15 Feature Groups | 42 passing (binary ground truth); 39 cleanly skipped pending M1–M3 | 100% Pass against production `olympus_re` |
| **Tier 2 (Boundaries)**| **75 tests** across 15 Feature Groups | 56 passing (domain limits & memory transitions); 19 cleanly skipped pending M1–M3 | 100% Pass against production `olympus_re` |
| **Tier 3 (Pairwise)**  | **16 tests** ($L_{16}(4^5)$ Covering Array) | 16 tests cleanly skip pending `olympus_re.cli` | 100% Pass against genuine CLI output artifacts |
| **Tier 4 (Scenarios)** | **5 tests** (Real-world RE workflows) | 4 passing (cold boot, OSD pipeline, power, firmware update & PTP); 1 cleanly skipped | 100% Pass against full toolchain |
| **Acceptance V1**      | **3 tests** (Static analysis validity) | 3 cleanly skipped; CLI exits 1 with deliverable failure banner | 100% Pass against `output/symbols.json` |
| **Acceptance V2**      | **6 tests** (Decompiler script quality) | 1 passing (offline mock harness); 5 cleanly skipped | 100% Pass against `olympus_re/decompiler/` scripts |
| **Acceptance V3**      | **8 tests** (Documentation completeness)| 1 passing (heading slugifier); 7 cleanly skipped | 100% Pass against `docs/xref.html` (0 dead links) |
| **Total**              | **194 distinct tests** | Clean execution: 104 PASS, 90 SKIPPED, 0 FAIL, 0 ERROR | **100% Clean Pass (194 Passed, 0 Skipped, 0 Failed)** |
