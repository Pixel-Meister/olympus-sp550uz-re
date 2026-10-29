# Project: Olympus SP-550UZ Reverse Engineering & Decompilation Framework

## Architecture
The framework provides an end-to-end reverse engineering, decompilation annotation, and documentation toolchain for the Olympus SP-550UZ camera (Sanyo SG155 platform, TruePic III processor).

### Core Components
1. **Models (`olympus_re/models/`)**:
   - `memory_map.py`: Definitions of all 9 TruePic III memory domains (`0x40000000` to `0xE081FFFF`), permissions, bus domains, and address validation routines.
   - `symbols.py`: Data structures for Symbols, Functions, Jump Tables, Literal Pools, and MMIO Registers.
2. **Analysis Pipeline (`olympus_re/analysis/`)**:
   - `disassembler.py`: Capstone 5.0.9 ARM LE disassembler streaming engine with `skipdata=True`.
   - `function_detector.py`: Multi-method function boundary detection (prologue patterns `push {..., lr}` / `push {r8, sb}`, direct `BL` call targets, literal pool function pointers).
   - `jump_table_analyzer.py`: Switch/jump table resolution engine (bounds checks `#imm`, stride, base load, indirect branch).
   - `literal_pool.py`: PC-relative `LDR` extraction and physical memory domain classification.
   - `string_extractor.py`: ASCII and UTF-16LE string scanning and subsystem API prefix indexing.
   - `pipeline.py`: Main orchestrator exporting symbol database (`symbols.json`, `symbols.csv`, `jump_tables.json`).
3. **Decompiler Tooling (`olympus_re/decompiler/`)**:
   - `ghidra_sp550uz_annotator.py`: Standalone Ghidra Python / PyGhidra script mapping memory blocks, creating labels, plate comments, and MMIO register tags via `FlatProgramAPI`.
   - `ida_sp550uz_annotator.py`: Standalone IDA Pro IDAPython script using `idc`/`idaapi` to create segments, name functions, and comment hardware registers.
   - `mock_environment.py`: Static analysis & unit testing harness mocking Ghidra and IDA APIs for offline execution.
4. **Documentation Generator (`olympus_re/docgen/`)**:
   - `generator.py`: Jinja2 generator producing interactive searchable single-page HTML (`docs/xref.html`) and structured Markdown (`docs/xref/`).
   - `link_validator.py`: Automated link & anchor scraper ensuring 0 dead links.
5. **CLI Runner (`olympus_re/cli.py`)**:
   - Unified command-line interface for analysis, symbol export, decompiler script packaging, and documentation generation.

---

## Feature Inventory
Every feature identified during the Phase 0 survey is mapped to an implementation milestone.

| # | Feature | Description | Milestone | Source |
|---|---|---|---|---|
| 1 | Section 1 SDRAM Memory Domain | `0x40000000`–`0x403F50E7`, 4.15 MB, Cached RX ARM code | M1 | Survey Spec & Binary |
| 2 | Section 2 NDATA Memory Domain | `0x403F5108`–`0x40855967`, 4.59 MB, Cached RO Resources | M1 | Survey Spec & Binary |
| 3 | Uncached RAM Buffers Domain | `0x41F00000`–`0x41F7FFFF`, 512 KB, RW DMA/framebuffers | M1 | Survey Spec |
| 4 | System Blackboard Domain | `0x41F80000`–`0x41F9FFFF`, 128 KB, RW master state variables | M1 | Survey Spec |
| 5 | Banked Task Stacks Domain | `0x41FA0000`–`0x41FD0000`, 192 KB, RW IRQ/SVC/ABT/SYS stacks | M1 | Survey Spec |
| 6 | MMIO SDRAM Controller Domain | `0x80410000`–`0x8041FFFF`, 64 KB, RW timing registers | M1 | Survey Spec |
| 7 | MMIO DMA & NAND Controller Domain | `0xC04C0000`–`0xC04CFFFF`, 64 KB, RW DMA/NAND registers | M1 | Survey Spec |
| 8 | MMIO Timers/Int/DAC/ISP Domain | `0xE0010000`–`0xE081FFFF`, ~8 MB, RW peripheral registers | M1 | Survey Spec |
| 9 | TruePic III Full Address Space | `0x40000000`–`0xE081FFFF` address boundary validation | M1 | Survey Spec |
| 10 | Pure ARM Mode Enforcer | 32-bit ARM (ARMv5TE) instruction set enforcement (no Thumb) | M1 | Survey Binary |
| 11 | Reset Handler & Cold Boot Detection | Analysis of vector entry `0x40000000` -> `0x40000800` | M1 | Survey Binary |
| 12 | Function Prologue Scanner | Scanner for `push {..., lr}` (`0xe92d4xxx`) and `push {r8, sb}` | M1 | Survey Binary |
| 13 | Function Epilogue Scanner | Detection of `pop {..., pc}` and `bx lr` (`0xe12fff1e`) | M1 | Survey Binary |
| 14 | BL Direct Call Target Extractor | Extract 61,863 BL call sites to resolve function destinations | M1 | Survey Binary |
| 15 | Multi-Method Function Boundary Resolver | Combines prologues, BL calls, and literal function pointers | M1 | Survey Binary |
| 16 | Target >= 2,500 Function Entry Points | Extract and label at least 2,500 distinct functions across Section 1 | M1 | ORIGINAL_REQUEST (V1) |
| 17 | OSD Jump Table Resolver | Resolve 25 entries at `0x401b3324` from dispatcher `0x401b32f4` | M1 | ORIGINAL_REQUEST (R1, V1) |
| 18 | RTOS Event Jump Table Resolver | Resolve 16 entries at `0x4019e324` from event dispatcher `0x4019e1e8` | M1 | ORIGINAL_REQUEST (R1, V1) |
| 19 | General Compiler Jump Table Analyzer | Resolve >300 structured compiler jump tables across Section 1 | M1 | Survey Binary |
| 20 | Literal Pool Memory Classifier | Map 26,000+ PC-relative literals to 8 physical memory domains | M1 | Survey Binary |
| 21 | 100% Valid Address Pointer Constraint | Validate that 100% of exported pointers fall within physical memory | M1 | ORIGINAL_REQUEST (V1) |
| 22 | Section 1 ASCII String Extractor | Extract 6,940 ASCII strings with subsystem API prefixes | M1 | Survey Binary |
| 23 | Section 2 UTF-16LE String Extractor | Extract multi-language strings and font glyph table pointers | M1 | Survey Binary |
| 24 | Subsystem Prefix Classifier | Identify `DISP_`, `COMM_`, `SYSFNC_`, `REC_`, `BML_`, `STL_`, `Ptp_` | M1 | Survey Notes & Binary |
| 25 | Machine-Readable Symbol Exporter | Export structured JSON database (`symbols.json`) | M1 | ORIGINAL_REQUEST (R1) |
| 26 | CSV Symbol Exporter | Export spreadsheet-compatible symbol database (`symbols.csv`) | M1 | ORIGINAL_REQUEST (R1) |
| 27 | Jump Table Metadata Exporter | Export structured jump table mapping (`jump_tables.json`) | M1 | ORIGINAL_REQUEST (R1) |
| 28 | Ghidra Memory Segment Mapper | Define all TruePic III segments in Ghidra `FlatProgramAPI` | M2 | ORIGINAL_REQUEST (R2) |
| 29 | Ghidra Function & Label Importer | Auto-label functions and entry points in Ghidra | M2 | ORIGINAL_REQUEST (R2) |
| 30 | Ghidra Subsystem Handler Annotator | Plate comments for OSD, Power, RTOS, ISP, PTP subsystems | M2 | ORIGINAL_REQUEST (R2) |
| 31 | Ghidra State Blackboard Annotator | Label variables in `0x41F80000` (state `+0x9e`, timer `0x41f8ddac`) | M2 | ORIGINAL_REQUEST (R2) |
| 32 | Ghidra MMIO Peripheral Annotator | Label MMIO registers across `0x80410000`, `0xC04C0000`, `0xE0010000` | M2 | ORIGINAL_REQUEST (R2) |
| 33 | Ghidra Headless & GUI Execution Docs | Instructions for `analyzeHeadless` and Ghidra Script Manager | M2 | ORIGINAL_REQUEST (V2) |
| 34 | IDA Pro Memory Segment Mapper | Create IDA segments via `idc.add_segm_ex` / `idaapi.add_segm` | M2 | ORIGINAL_REQUEST (R2) |
| 35 | IDA Pro Function & Name Importer | Auto-name functions via `idc.set_name` | M2 | ORIGINAL_REQUEST (R2) |
| 36 | IDA Pro Subsystem Handler Annotator | Set function comments for subsystem handlers via `idc.set_cmt` | M2 | ORIGINAL_REQUEST (R2) |
| 37 | IDA Pro State Blackboard Annotator | Name and annotate blackboard structures in `0x41F80000` | M2 | ORIGINAL_REQUEST (R2) |
| 38 | IDA Pro MMIO Peripheral Annotator | Label and comment MMIO registers | M2 | ORIGINAL_REQUEST (R2) |
| 39 | IDA Pro Headless & GUI Execution Docs | Instructions for `idal64 -S...` and IDA Alt+F7 execution | M2 | ORIGINAL_REQUEST (V2) |
| 40 | AST Syntax Validation Harness | Validate Python syntax of Ghidra & IDA scripts via `ast.parse` | M2 | ORIGINAL_REQUEST (V2) |
| 41 | Offline Mock Execution Harness | Mock `FlatProgramAPI` and `idaapi`/`idc` to verify memory map | M2 | Survey Tooling & V2 |
| 42 | Searchable HTML Cross-Reference Engine | Single-page interactive HTML app (`olympus_xref.html`) | M3 | ORIGINAL_REQUEST (R3) |
| 43 | Client-Side Subsystem & Address Filter | Fast interactive search by address, subsystem, and keyword | M3 | ORIGINAL_REQUEST (R3) |
| 44 | Structured Markdown Cross-Reference Suite | Linked Markdown chapters (`docs/xref/index.md`, `subsystems.md`, etc.) | M3 | ORIGINAL_REQUEST (R3) |
| 45 | Subsystem Documentation Index | Detailed documentation for OSD, Power, RTOS, Sensor/ISP, Storage | M3 | ORIGINAL_REQUEST (R3) |
| 46 | Caller / Callee Cross-Reference Graph | Cross-reference table linking callers and callees per function | M3 | ORIGINAL_REQUEST (R3) |
| 47 | RTOS Tasks & Event Table Documentation | Document event loop `0x4019e1e8` and all 16 event destinations | M3 | ORIGINAL_REQUEST (R3) |
| 48 | OSD Display Modes Documentation | Document modes `0x00`..`0x18`, minimal modes, and clean passthrough | M3 | ORIGINAL_REQUEST (R3) |
| 49 | Video Destination Logic Documentation | Document `0x4012fef4`, destination codes (LCD/EVF/NTSC/PAL), sleep lock | M3 | ORIGINAL_REQUEST (R3) |
| 50 | Known MMIO Peripherals Catalog | Catalog all MMIO blocks, bitfields, and peripheral maps | M3 | ORIGINAL_REQUEST (V3) |
| 51 | PTP-over-SCSI Documentation | Document SCSI CDBs `0xC0`–`0xC4`, PTP opcodes `0x100C`, `0x9119`–`0x9123` | M3 | ORIGINAL_REQUEST (V3) |
| 52 | Zero Dead Internal Links Validator | Automated test asserting 100% anchor and reference resolution | M3 | ORIGINAL_REQUEST (V3) |
| 53 | Automated Validation Script (V1 Validator) | Script validating 100% address ranges, >=2500 funcs, jump tables | E2E | ORIGINAL_REQUEST (V1) |
| 54 | Decompiler Script Quality Validator (V2) | Script validating syntax, segment definitions `0x40000000`–`0xE081FFFF` | E2E | ORIGINAL_REQUEST (V2) |
| 55 | Documentation Link & Content Validator (V3)| Script validating all peripherals, subsystems, PTP, zero dead links | E2E | ORIGINAL_REQUEST (V3) |
| 56 | E2E Integration Test Suite | Comprehensive integration tests verifying end-to-end framework run | E2E | Project Dual Track |
| 57 | Pairwise Combinatorial Tests (Tier 3) | Cross-feature combination tests covering pipeline & toolchain | E2E | Project Dual Track |
| 58 | Real-World Reverse Engineering Scenarios (Tier 4) | Realistic RE workflows (patch verification, symbol lookup, import) | E2E | Project Dual Track |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| E2E | E2E Testing Track | Test harness, validation scripts (V1, V2, V3), test tiers 1-4 | none | DONE |
| M1 | Automated Function & Symbol Analysis Pipeline (R1, V1) | `olympus_re/analysis/`, `olympus_re/models/`, symbol export (JSON/CSV) | none | DONE |
| M2 | Decompiler Annotation & Import Tooling (R2, V2) | `olympus_re/decompiler/`, Ghidra & IDA scripts, AST/mock harness | M1 | DONE |
| M3 | Searchable Cross-Reference Documentation (R3, V3) | `olympus_re/docgen/`, HTML & Markdown generators, link validator | M1 | DONE |
| M4 | Final Milestone: 100% E2E Pass & Adversarial Hardening | Pass 100% E2E test suite (Tiers 1-4) + Tier 5 coverage hardening | E2E, M1, M2, M3 | DONE |

---

## Interface Contracts

### M1 ↔ M2 (Analysis Pipeline ↔ Decompiler Tooling)
- Output Artifacts:
  - `output/symbols.json`: JSON format containing list of Symbol objects.
    - Fields: `address` (int), `name` (str), `type` (`function`|`jump_table`|`string`|`mmio_register`|`literal_pointer`|`blackboard_var`), `size` (int), `domain` (str), `subsystem` (str), `metadata` (dict).
  - `output/jump_tables.json`: JSON list of JumpTable objects.
    - Fields: `site` (int), `table_address` (int), `entry_count` (int), `bounds` (str), `default_target` (int), `targets` (list[int]).
- Contract Guarantees:
  - 100% of addresses fall within TruePic III domains (`0x40000000`–`0xE081FFFF`).
  - Minimum 2,500 distinct function symbols.
  - OSD jump table (`0x401b3324`, 25 entries) and RTOS event table (`0x4019e324`, 16 entries) present.

### M1 ↔ M3 (Analysis Pipeline ↔ Documentation Generator)
- Ingests `output/symbols.json` and `output/jump_tables.json` along with caller/callee cross-reference graph.
- Generates:
  - `docs/xref.html`: Interactive client-side single page app.
  - `docs/xref/index.md`, `docs/xref/subsystems.md`, `docs/xref/memory_map.md`, `docs/xref/jump_tables.md`.
- Contract Guarantees:
  - Every function and symbol address has a unique anchor id (`id="sym-0x401b32f4"`).
  - Zero dead internal links.

### E2E Testing Track ↔ All Milestones
- Test command: `python3 -m unittest discover tests -v`
- Publishes `TEST_READY.md` containing full test runner commands and verification criteria for V1, V2, V3.

---

## Code Layout
```text
/home/justin/Dev/olympus/
├── olympus_re/                     # Core Python framework package
│   ├── __init__.py                 # Package version and export
│   ├── cli.py                      # Main unified CLI runner
│   ├── analysis/                   # Static analysis pipeline (M1)
│   │   ├── __init__.py
│   │   ├── disassembler.py         # Capstone wrapper (ARM LE, skipdata=True)
│   │   ├── function_detector.py    # Prologue, BL target, and pointer scanning
│   │   ├── jump_table_analyzer.py  # Switch/jump table resolution engine
│   │   ├── literal_pool.py         # PC-relative LDR extraction and domain classifier
│   │   ├── string_extractor.py     # ASCII/Unicode string identification
│   │   └── pipeline.py             # Pipeline orchestrator (exports JSON/CSV)
│   ├── decompiler/                 # Decompiler scripts and annotation tooling (M2)
│   │   ├── __init__.py
│   │   ├── ghidra_annotator.py     # Ghidra Python / PyGhidra import script
│   │   ├── ida_annotator.py        # IDA Pro IDAPython import script
│   │   └── mock_environment.py     # Mock flatapi/idaapi harness for offline tests
│   ├── docgen/                     # Searchable documentation generator (M3)
│   │   ├── __init__.py
│   │   ├── generator.py            # Jinja2 template renderer for HTML & Markdown
│   │   ├── link_validator.py       # Scraper validating 100% internal links
│   │   └── templates/
│   │       ├── xref.html.j2        # Searchable interactive HTML template
│   │       └── xref.md.j2          # Linked Markdown templates
│   └── models/                     # Shared data structures and schemas (M1)
│       ├── __init__.py
│       ├── memory_map.py           # TruePic III domains (0x40000000 to 0xE081FFFF)
│       └── symbols.py              # Symbol, Function, JumpTable, MMIO dataclasses
├── tests/                          # E2E Test Suite (Dual Track)
│   ├── __init__.py
│   ├── test_tier1_features.py      # Tier 1: Feature coverage (>=5 per feature)
│   ├── test_tier2_boundaries.py    # Tier 2: Boundary & corner cases
│   ├── test_tier3_pairwise.py      # Tier 3: Cross-feature combinations
│   ├── test_tier4_scenarios.py     # Tier 4: Real-world application scenarios
│   ├── validate_v1_analysis.py     # V1 acceptance criteria validator
│   ├── validate_v2_decompiler.py   # V2 acceptance criteria validator
│   └── validate_v3_docs.py         # V3 acceptance criteria validator
├── docs/                           # Generated cross-reference documentation (M3)
│   ├── xref.html                   # Interactive searchable HTML
│   └── xref/                       # Linked markdown chapters
├── output/                         # Generated symbol database artifacts (M1)
│   ├── symbols.json
│   ├── symbols.csv
│   └── jump_tables.json
├── TEST_INFRA.md                   # Test infrastructure index
├── TEST_READY.md                   # Signal that E2E test suite is complete
└── Resources/                      # Existing repository resources (untouched)
    ├── firmware/
    ├── notes/
    └── scripts/
```
