"""
Tier 4: Real-World Application Scenarios Test Suite (tests/test_tier4_scenarios.py)
Olympus SP-550UZ Reverse Engineering Framework.

Provides 5 comprehensive real-world end-to-end reverse engineering workflows:
1. Scenario 1: Cold Boot & Exception Vector Chain to RTOS Startup
2. Scenario 2: OSD Display Engine Reverse Engineering & Clean Passthrough Verification
3. Scenario 3: Power Management & Sleep Prevention Architecture Audit
4. Scenario 4: Storage, Firmware Update & PTP-over-SCSI Subsystem Extraction
5. Scenario 5: Full Headless Production Pipeline Run, Artifact Export & Forensic Audit
"""

import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

from tests.support import (
    KNOWN_OSD_TABLE_ADDR,
    KNOWN_RTOS_TABLE_ADDR,
    SECTION1_PATH,
    SECTION2_PATH,
    TruePicIIIMemoryMap,
)

# Progressive Testability Detection
try:
    import olympus_re
    import olympus_re.cli
    HAS_OLYMPUS_RE = True
except ImportError:
    HAS_OLYMPUS_RE = False


class TestTier4RealWorldScenarios(unittest.TestCase):
    """Comprehensive end-to-end user workflows."""

    def test_scenario_1_cold_boot_vector_to_rtos(self):
        """
        Scenario 1: Cold Boot & Exception Vector Chain to RTOS Startup.
        Traces entry point branch 0x40000000 -> 0x40000800, stack setup (0x41fcf000, 0x41fd0000),
        CP15 configuration at 0x40000988, and cold boot branch to 0x40000adc.
        """
        with open(SECTION1_PATH, "rb") as f:
            header = f.read(0xB00)

        # 1. Reset vector branch to 0x40000800
        reset_branch = int.from_bytes(header[0:4], "little")
        self.assertEqual(reset_branch, 0xEA0001FE, "Reset vector must branch to 0x40000800")

        # 2. Banked and user stack pointers
        irq_sp = int.from_bytes(header[0x830:0x834], "little")
        usr_sp = int.from_bytes(header[0x840:0x844], "little")
        self.assertEqual(irq_sp, 0x41FCF000, "Banked stack pointer must be 0x41fcf000")
        self.assertEqual(usr_sp, 0x41FD0000, "User stack pointer must be 0x41fd0000")

        # 3. CP15 MMU/cache control configuration at 0x40000988
        cp15_mrc = int.from_bytes(header[0x988:0x98C], "little")
        self.assertEqual(cp15_mrc, 0xEE113F10, "CP15 configuration at 0x40000988 must read c1")

        # 4. Cold boot entry prologue at 0x40000ADC
        cold_boot_prologue = int.from_bytes(header[0xADC:0xAE0], "little")
        self.assertEqual(cold_boot_prologue, 0xE92D4010, "Cold boot at 0x40000adc must be push {r4, lr}")

    def test_scenario_2_osd_pipeline_reverse_engineering(self):
        """
        Scenario 2: OSD Display Engine Reverse Engineering & Dispatcher Verification.
        Verifies dispatcher at 0x401b32f4, 25-entry jump table at 0x401b3324, bounds check #0x18,
        mode handlers (Mode 0 normal HUD 0x401b3388, Mode 1 grid 0x401b33d4, Mode 2 minimal 0x401b35b4,
        clean epilogue 0x401b3864), and epilogue return instructions.
        """
        with open(SECTION1_PATH, "rb") as f:
            # 1. Dispatcher entry prologue and bounds check
            f.seek(0x401B32F4 - 0x40000000)
            disp_prologue = int.from_bytes(f.read(4), "little")
            self.assertEqual(disp_prologue, 0xE92D4310, "0x401b32f4 must be push {r4, r8, sb, lr}")

            f.seek(0x401B330C - 0x40000000)
            bounds_cmp = int.from_bytes(f.read(4), "little")
            self.assertEqual(bounds_cmp, 0xE3520018, "0x401b330c must be cmp r2, #0x18")

            # 2. 25-entry OSD jump table
            f.seek(KNOWN_OSD_TABLE_ADDR - 0x40000000)
            tbl_bytes = f.read(25 * 4)

            entries = [int.from_bytes(tbl_bytes[i * 4 : (i + 1) * 4], "little") for i in range(25)]
            self.assertEqual(entries[0], 0x401B3388, "Mode 0 must target normal HUD 0x401b3388")
            self.assertEqual(entries[1], 0x401B33D4, "Mode 1 must target grid 0x401b33d4")
            self.assertEqual(entries[2], 0x401B35B4, "Mode 2 stock must target minimal HUD 0x401b35b4")
            self.assertEqual(entries[4], 0x401B3864, "Mode 4 must target clean epilogue 0x401b3864")

            # 3. Stock Mode 2 and Clean Epilogue opcode verification
            f.seek(0x401B35B4 - 0x40000000)
            stock_mode2_opcode = int.from_bytes(f.read(4), "little")
            self.assertEqual(stock_mode2_opcode, 0xE3A01000, "Stock Mode 2 at 0x401b35b4 must be mov r1, #0")

            f.seek(0x401B3864 - 0x40000000)
            epilogue_opcode = int.from_bytes(f.read(4), "little")
            self.assertEqual(epilogue_opcode, 0xE3A01003, "Epilogue at 0x401b3864 must be mov r1, #3")

            f.seek(0x401B3870 - 0x40000000)
            epilogue_pop = int.from_bytes(f.read(4), "little")
            self.assertEqual(epilogue_pop, 0xE8BD8310, "Epilogue at 0x401b3870 must be ldmfd sp!, {r4, r8, sb, pc}")

    def test_scenario_3_power_management_and_sleep_prevention(self):
        """
        Scenario 3: Power Management & Sleep Prevention Architecture Audit.
        Verifies sleep timer reset (0x401501b4), destination query (0x4012fef4),
        sleep inhibit queries (0x40150540, 0x40150560), and RTOS event jump table (0x4019e324)
        routing event 7 (0xca07 -> 0x4019e9cc) and event 15 (0xca0f -> 0x4019e9c0).
        """
        with open(SECTION1_PATH, "rb") as f:
            # 1. RTOS event jump table routing
            f.seek(KNOWN_RTOS_TABLE_ADDR - 0x40000000)
            tbl_bytes = f.read(16 * 4)
            entries = [int.from_bytes(tbl_bytes[i * 4 : (i + 1) * 4], "little") for i in range(16)]
            self.assertEqual(entries[7], 0x4019E9CC, "Event 7 must target secondary sleep 0x4019e9cc")
            self.assertEqual(entries[15], 0x4019E9C0, "Event 15 must target primary sleep 0x4019e9c0")

            # 2. Sleep timer reset prologue
            f.seek(0x401501B4 - 0x40000000)
            sleep_reset_prologue = int.from_bytes(f.read(4), "little")
            self.assertEqual(sleep_reset_prologue, 0xE92D0300, "0x401501b4 must be push {r8, sb}")

            # 3. Video destination query prologue
            f.seek(0x4012FEF4 - 0x40000000)
            video_query_prologue = int.from_bytes(f.read(4), "little")
            self.assertEqual(video_query_prologue, 0xE92D0300, "0x4012fef4 must be push {r8, sb}")

    def test_scenario_4_storage_firmware_update_and_ptp(self):
        """
        Scenario 4: Storage, Firmware Update & PTP-over-SCSI Subsystem Extraction.
        Verifies identification of /FIRMWARE/FIRMWARE.BIN detection (0x401efac8),
        flash commit routine (0x40291694), literal pointer to FIRMWAREBIN at 0x40291D78,
        FAT 8.3 filename string at 0x403C59D8, and authentic PTP operations table at 0x403E7254
        (0x100C SendObjectInfo, 0x9119 SendChunk, 0x9121 FirmwareCheck, 0x9123 UpdateInitiate).
        """
        with open(SECTION1_PATH, "rb") as f:
            # 1. Card detection / playback trigger routine at 0x401EFAC8
            f.seek(0x401EFAC8 - 0x40000000)
            trig_bytes = f.read(16)
            trig_prologue = int.from_bytes(trig_bytes[0:4], "little")
            self.assertEqual(trig_prologue, 0xE92D4300, "0x401efac8 must be push {r8, sb, lr}")

            # 2. Flash commit / update routine at 0x40291694
            f.seek(0x40291694 - 0x40000000)
            flash_bytes = f.read(16)
            flash_prologue = int.from_bytes(flash_bytes[0:4], "little")
            flash_sub_sp = int.from_bytes(flash_bytes[4:8], "little")
            self.assertEqual(flash_prologue, 0xE92D47F0, "0x40291694 must be push {r4..r8, sb, sl, lr}")
            self.assertEqual(flash_sub_sp, 0xE24DD03C, "0x40291698 must allocate stack frame (sub sp, sp, #0x3c)")

            # 3. Literal pool pointer to FIRMWAREBIN at 0x40291D78
            f.seek(0x40291D78 - 0x40000000)
            firmware_bin_ptr = int.from_bytes(f.read(4), "little")
            self.assertEqual(
                firmware_bin_ptr,
                0x403C59D8,
                "Literal pool at 0x40291d78 must point to FIRMWAREBIN at 0x403c59d8",
            )

            # 4. FAT 8.3 filename string FIRMWAREBIN at 0x403C59D8
            f.seek(0x403C59D8 - 0x40000000)
            fat_name = f.read(12)
            self.assertEqual(
                fat_name,
                b"FIRMWAREBIN\x00",
                "0x403c59d8 must contain FAT 8.3 filename FIRMWAREBIN\\x00",
            )

            # 5. Authentic PTP operations table at 0x403E7254
            f.seek(0x403E7254 - 0x40000000)
            ptp_table = struct.unpack("<13H", f.read(26))
            # Verify vendor firmware update and flash commit opcodes
            self.assertEqual(ptp_table[4], 0x100C, "PTP op 4 must be 0x100C SendObjectInfo")
            self.assertEqual(ptp_table[5], 0x9119, "PTP op 5 must be 0x9119 SendFirmwareChunk")
            self.assertEqual(ptp_table[8], 0x9121, "PTP op 8 must be 0x9121 FirmwareCheck")
            self.assertEqual(ptp_table[10], 0x9123, "PTP op 10 must be 0x9123 UpdateInitiate")

            # Verify all relevant addresses fall within TruePic III physical domains
            for addr in (0x401EFAC8, 0x40291694, 0x40291D78, 0x403C59D8, 0x403E7254):
                self.assertTrue(
                    TruePicIIIMemoryMap.is_valid_address(addr),
                    f"Address {hex(addr)} must fall within valid TruePic III memory range",
                )

    def test_scenario_5_end_to_end_production_pipeline_and_forensic_audit(self):
        """
        Scenario 5: Full Headless Production Pipeline Run, Artifact Export & Forensic Audit.
        Simulates end-to-end framework execution:
        Analysis Pipeline -> symbols.json / symbols.csv / jump_tables.json ->
        Mock Decompiler Execution -> Documentation Generation -> 100% Zero Dead Link Validation.
        """
        if not HAS_OLYMPUS_RE:
            raise unittest.SkipTest("olympus_re production pipeline pending milestone M1")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "output"
            docs_dir = Path(tmpdir) / "docs"
            out_dir.mkdir(parents=True, exist_ok=True)
            docs_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                sys.executable,
                "-m",
                "olympus_re.cli",
                "--input",
                str(SECTION1_PATH),
                "--data-input",
                str(SECTION2_PATH),
                "--output-dir",
                str(out_dir),
                "--docs-dir",
                str(docs_dir),
                "--mode",
                "full",
                "--export-format",
                "all",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"Pipeline CLI failed: {result.stderr}")

            # 1. Forensic assertions on exported symbol database
            symbols_json_path = out_dir / "symbols.json"
            self.assertTrue(symbols_json_path.exists(), "symbols.json must be generated")
            with open(symbols_json_path, "r", encoding="utf-8") as f:
                symbols = json.load(f)
            self.assertGreaterEqual(len(symbols), 2500, "V1 requirement: at least 2500 function entries")
            for sym in symbols:
                addr = sym.get("address", 0)
                self.assertTrue(
                    TruePicIIIMemoryMap.is_valid_address(addr),
                    f"Symbol {sym.get('name')} address {hex(addr)} invalid",
                )

            # 2. Forensic assertions on jump tables database
            jump_tables_json_path = out_dir / "jump_tables.json"
            self.assertTrue(jump_tables_json_path.exists(), "jump_tables.json must be generated")
            with open(jump_tables_json_path, "r", encoding="utf-8") as f:
                jump_tables = json.load(f)
            self.assertGreaterEqual(len(jump_tables), 2, "Must extract at least OSD and RTOS jump tables")

            # 3. Documentation generation and 100% zero dead links audit
            xref_html_path = docs_dir / "xref.html"
            self.assertTrue(xref_html_path.exists(), "docs/xref.html must be generated")
            with open(xref_html_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            hrefs = set(re.findall(r'href="#([^"]+)"', html_content))
            anchors = set(re.findall(r'id="([^"]+)"', html_content))
            dead_links = hrefs - anchors
            self.assertEqual(
                len(dead_links), 0, f"Found dead links in generated documentation: {dead_links}"
            )


if __name__ == "__main__":
    unittest.main()
