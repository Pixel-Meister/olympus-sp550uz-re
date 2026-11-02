# Olympus SP-550UZ Reverse Engineering Log & Research Notes

**Last Updated:** 2026-10-25 (evening - firmware unpacked)
**Target Device:** Olympus SP-550UZ (`07b4:0109`)
**Goal:** Acquire and reverse engineer the Olympus SP-550UZ / Sanyo SG155 firmware architecture, memory map, OSD display pipeline, and power management subsystems.

---

## 1. Current Status & Milestones

- [x] **Firmware Architecture Reference Created:** Detailed technical documentation of the entire firmware architecture, memory map, RTOS executive, MMIO peripherals, and sensor pipeline compiled in [`firmware_architecture_reference.md`](firmware_architecture_reference.md).
- [x] **USB / Linux Device Mapping:** Identified how the SP-550UZ enumerates in `Control/PC` mode (`/dev/sg0` SCSI Generic + `/dev/sda` Mass Storage) and verified user-space read/write access without `sudo`.
- [x] **Updater Unpacking & Disassembly:** Unpacked `OWSetup_64bit(1).exe` -> `OW_Pack_Framework.cab` -> `application.cab` and disassembled `CameraUpdate.exe`, `OlyGin.dll`, `OlyBar.dll`, `OlyWebAccess.dll`, and `OlyWebXMLMgr.dll`.
- [x] **Olympus PTP-over-SCSI Protocol (`OlyGin.dll`):** Reverse-engineered `CDevCtrlSpti` (`0x10009440`–`0x10009e4f`) and built a working Python client using `fcntl.ioctl(fd, SG_IO, ...)`.
- [x] **Live Camera Interrogation:** Queried `GetDeviceInfo` (`0x1001`), `GetFirmwareUpdateMode` (`0x911c`), `GetVersions` (`0x9120`), `GetDeviceStatus` (`0x9122`), and `GetLanguageCode` (`0x9124`) from the attached SP-550UZ.
- [x] **Custom Buggy DES Cipher & `olysurf.bin` Decryption (`OlyWebAccess.dll`):** Reverse-engineered the custom DES-ECB implementation (`0x10001000`–`0x10002b79`), discovered an unmasked 28-bit key-schedule rotation bug, and decrypted `olysurf.bin` to recover the active OM Digital Solutions firmware server URLs.
- [x] **Exact `<firmware_demand>` XML Schema (`CameraUpdate.exe` + `OlyBar.dll` + `OlyWebXMLMgr.dll`):** Reconstructed every XML tag and header field sent by the updater and successfully queried `https://fw01.om-digitalsolutions.net/ww_inform/fcache.do`.
- [x] **Official Firmware Located:** Obtained the signed download URL for **SP-550UZ Firmware v1.1 (`1100`)** (`SAN_E_321_1100_0000_0000.BIN`, 8,739,184 bytes).
- [x] **Firmware Downloaded:** `Resources/firmware/SAN_E_321_1100_0000_0000.BIN` (8,739,184 B) + `index01a.html` release notes + sanitized `sp550uz_firmware_result.xml`.
- [x] **Container De-obfuscated:** Not DES at all - a byte-invert + 16-byte lane permutation. Both section checksums verify exactly (see Section 5).
- [x] **Architecture Identified:** 32-bit little-endian **ARM** (ARM-mode code: `e92d....` push / `e8bd....` pop / `e12fff1e` return), image load base **`0x40000000`**.
- [x] **Master OSD Overlay Engine Isolated:** Disassembled Section 1 (`0x40000000`). Located the master record overlay dispatcher (`0x401b32f4`), the central element rendering worker (`0x401b3874`), the Mode 8 Auto-minimal handler (`0x401b361c`), and the AF target mark renderer (`0x401b6668`).
- [x] **Cable-Conditional Sleep Engine Isolated:** Located global power manager sleep inhibit routine (`0x40150560`) and display destination query (`0x4012fef4`).
- [x] **Card-Based Flash Update Path Isolated:** Discovered and verified storage-based update mechanism: switching to Playback mode with `/FIRMWARE/FIRMWARE.BIN` triggers on-screen firmware confirmation.
- [x] **Subsystem Reverse Engineering Complete:** Decoded OSD mode dispatcher table, AF target rendering pipelines, RTOS event tables, and power management standby timers.

---

## 2. Thought Process & Investigation Trail

### Phase 1: Why does `Control/PC` mode still look like USB Mass Storage?
When the camera was switched to `Control/PC` on its USB menu, `lsusb` still reported `07b4:0109` (`Olympus Optical Co., Ltd C-370Z / D-535Z / X-450`) with a single interface:
- `bInterfaceClass = 8` (Mass Storage)
- `bInterfaceSubClass = 6` (SCSI)
- `bInterfaceProtocol = 80` (Bulk-Only)

Rather than switching to a USB Still Image (PTP class `6`) PID, older Olympus/Sanyo cameras tunnel PTP containers over vendor-specific SCSI CDBs (`0xC0`–`0xC4`, `0xDF`) sent to the Mass Storage device. In Linux, the block layer claims `/dev/sda`, while the SCSI Generic driver exposes `/dev/sg0` (`crw-rw-r--+ 1 root plugdev`, giving user `justin` direct `SG_IO` ioctl read/write access).

### Phase 2: Dissecting `OlyGin.dll` (`CDevCtrlSpti`)
By disassembling `OlyGin.dll` (`CDevCtrlSpti` at `0x10009440`–`0x10009e4f`), we found how Windows `DeviceIoControl(..., IOCTL_SCSI_PASS_THROUGH_DIRECT, ...)` is used:
- Every command uses a 16-byte SCSI CDB (`CDB[0]` = opcode, `CDB[6..9]` = 32-bit big-endian transfer length).
- Initial pitfall: when reading Data-In via `0xC4` (query length) followed by `0xC2` (read data), offset `0` of the `0xC4` response is always `0x00000010` (the 16-byte length of the `0xC4` PTP container itself). The actual upcoming `0xC2` transfer length (`12 + payload_len`) is stored at offset `12` (`qdata[12:16]`) as a 32-bit little-endian integer.

### Phase 3: Cracking `olysurf.bin` and the Buggy DES Key Schedule
`OlyBar.dll` loads `olysurf.bin` (2,351 bytes) via `OlyWebAccess.dll` (`0x10004900` -> `0x10001e30`).
- The file length is `2351 = 293 * 8 + 7`. The last 7 bytes (`0a 31 07 69 01 4c 2b`) are the 56-bit DES key (`raw[-7:]`), expanded to 8 bytes with parity bits via `0x10001c10`.
- Standard DES-ECB with the exact S-boxes and permutation tables (`IP`, `FP`, `E`, `P`, `PC1`, `PC2`) from `.rdata` (`0x10009130`–`0x10009c80`) produced garbage!
- **Why?** Tracing the key schedule generator at `0x10001880` and the 28-bit left-rotation helper at `0x100016c0` revealed a classic implementation bug in Olympus's C++ code:
  ```c
  // Olympus's buggy 28-bit left rotate at 0x100016c0:
  uint64_t tmp = ((uint64_t)val) << shift;
  val = (uint32_t)(((tmp >> 28) & mask) | (tmp & ~mask)); // BUG: missing `& 0x0fffffff`!
  ```
  Because `val` is not masked to 28 bits (`& 0x0fffffff`), bits 28–31 remain set after shifting. When `C` and `D` are combined via `(uint64_t)C | ((uint64_t)D << 28)` in `PC2`, bits 28–31 of `C` **bleed into bits 0–3 of `D`** via bitwise OR, and on the next round shift into the upper 32-bit word (`>> 28`), corrupting all subsequent round subkeys!
- Once we emulated this exact bug in Python, `olysurf.bin` decrypted cleanly into a 32-byte header (`SETF...MITUBISHICARISDANGER`) followed by UTF-16LE XML containing the live OM Digital Solutions server URLs.

### Phase 4: Reconstructing `<firmware_demand>` to Query `fcache.do`
- `OlyWebXMLMgr.dll` builds the `<firmware_demand>` XML document, but the caller (`CameraUpdate.exe` -> `OlyBar.dll`) supplies the header and hardware fields.
- Tracing `CameraUpdate.exe` (`0x40ac20`, `0x410786`–`0x410956`) and `OlyBar.dll` (`0x1000436f`–`0x10004870`, `0x100083b0`, `0x10008d40`) revealed the exact values expected by `fcache.do`:
  - `<application>FWUT</application>`
  - `<version>00005000</version>` (formatted with `%08x` from `0x5000`)
  - `<language>ENU</language>`
  - `<type>0000</type>`
  - `<country_code>0001</country_code>`
  - `<firmup_mode>0002</firmup_mode>`
  - `<hard_code>SANE321000000000</hard_code>`
  - `<firmware_version>00001001</firmware_version>`
  - `<serial_no>000000000</serial_no>`
  - `<default_languages><code>ENU</code><code>FRA</code><code>ESP</code><code>PTG</code></default_languages>`

---

## 3. Technical Reference: Camera Protocol & Live Data

### 3.1 Olympus PTP-over-SCSI CDBs (`/dev/sg0`)
All vendor PTP-over-SCSI commands use a 16-byte CDB (except `0xDF` which is 12 bytes):
`CDB = [opcode, 0, 0, 0, 0, 0, len_b3, len_b2, len_b1, len_b0, 0, 0, 0, 0, 0, 0]`

| SCSI Opcode | Direction | Transfer Length | Description |
| :--- | :--- | :--- | :--- |
| `0xC0` | Data-Out | `0x40` (64 B) | **Send PTP Command Container:** `<IHHI` (`length`, `type=1`, `ptp_opcode`, `tx_id`) + up to 5 `uint32` params |
| `0xC1` | Data-Out | `12 + payload` | **Send PTP Data-Out Container:** `<IHHI` (`12 + len`, `type=2`, `ptp_opcode`, `tx_id`) + payload |
| `0xC4` | Data-In | `0x40` (64 B) | **Query PTP Data-In Length:** Returns 16-byte container; `uint32` LE at offset `12` (`qdata[12:16]`) is total length for `0xC2` |
| `0xC2` | Data-In | `qdata[12:16]` | **Receive PTP Data-In Container:** Returns 12-byte PTP header + payload (`ddata[12:]`) |
| `0xC3` | Data-In | `0x40` (64 B) | **Receive PTP Response Container:** `<IHHI` (`length`, `type=3`, `resp_code`, `tx_id`) + response params (`0x2001` = OK) |
| `0xDF` | None | `mode` (in `CDB[6..9]`) | **ChangePid:** 12-byte CDB, switches USB mode |

### 3.2 Live SP-550UZ Device Information
- **SCSI `INQUIRY` (`0x12`):** `OLYMPUS SP550UZ         1.00`
- **PTP `GetDeviceInfo` (`0x1001`):**
  - **Manufacturer:** `OLYMPUS`
  - **Model:** `SP550UZ`
  - **DeviceVersion:** `1.0`
  - **SerialNumber:** `000J99208881`
  - **Supported Operations (13 total):**
    - `0x1001` (`GetDeviceInfo`)
    - `0x1002` (`OpenSession`)
    - `0x1003` (`CloseSession`)
    - `0x1004` (`GetStorageIDs`)
    - `0x100C` (`SendObjectInfo` — used with storage ID `0x80000001` to prepare firmware transfer)
    - `0x9111` (`RebootCamera` / `ReconnectStorage`)
    - `0x9119` (`SendFirmwareChunk` — sends firmware in `0xF800` / 63,488-byte chunks with `(offset, chunk_size)`)
    - `0x911C` (`GetFirmwareUpdateMode` — returns `0x00000002` on SP-550UZ)
    - `0x9120` (`GetVersions` — returns `SANE321000000000-00001001-000J99208881`)
    - `0x9121` (`FirmwareCheck` — verifies transferred firmware in RAM before flashing)
    - `0x9122` (`GetDeviceStatus` — polls flashing status; returns two `uint32` status words)
    - `0x9123` (`UpdateInitiate` — triggers flash write)
    - `0x9124` (`GetLanguageCode` — `param1=1` returns default languages `ENU, FRA, ESP, PTG`; `param1=0x8001` returns additional languages)

### 3.3 Firmware Transfer Sequence (`OlyGin.dll` `0x10001da0`)
1. `SendObjectInfo` (`0x100C`) with param1 = `0x80000001` and a 60-byte (`0x3C`) payload where:
   - `offset 0x00` (`uint32`): `0x80000001`
   - `offset 0x04` (`uint16`): target ID (`1` = body firmware)
   - `offset 0x08` (`uint32`): total firmware byte size
2. Loop over the firmware buffer in `0xF800` (63,488-byte) chunks using opcode `0x9119` with 2 parameters: `(byte_offset, chunk_byte_size)`.
3. Call `FirmwareCheck` (`0x9121`) and poll `GetDeviceStatus` (`0x9122`) until ready.
4. Call `UpdateInitiate` (`0x9123`) and poll `GetDeviceStatus` (`0x9122`) until flashing completes.

---

## 4. Unique & Interesting Discoveries

1. **`"MITUBISHICARISDANGER"` Header in `olysurf.bin` and `.cam` Files:**
   - The decrypted 32-byte header of `olysurf.bin` (and cached `.cam` firmware containers in `OlyBar.dll` at `0x10023750`) literally contains the ASCII string:
     `SETF\x01\x0001\x02\t\x00\x00MITUBISHICARISDANGER`
   - A developer at Olympus (or their contractor) embedded `"MITUBISHICARISDANGER"` ("Mitsubishi car is danger", likely referencing the early-2000s Mitsubishi Motors recall scandal in Japan) as the magic signature inside Olympus's encrypted configuration/firmware cache format!
2. **Sanyo OEM Heritage (`SANE321000000000`):**
   - `GetVersions` (`0x9120`) reports hardware code `SANE321000000000`, and the firmware server reports `<maker_code>SAN</maker_code>` and `<model_id>3210</model_id>` (`SAN_E_321_1100_0000_0000.BIN`).
   - While branded Olympus, the SP-550UZ hardware and firmware platform (`3210`) were built by **Sanyo** (`SAN`), which manufactured many compact/bridge digital cameras for Olympus during this era (often running a Sanyo Coach/MIPS/ARM SoC platform).
3. **The Unmasked 28-bit DES Key Rotation Bug:**
   - Both `OlyWebAccess.dll` (`0x100016c0`) and `OlyBar.dll` (`0x10005e20`) share the same copy-pasted DES implementation where the 28-bit `C` and `D` registers are not masked with `0x0fffffff` after left rotation. Standard DES libraries cannot decrypt Olympus `.bin`/`.cam` files unless they replicate this exact bit-bleed bug.
4. **Hidden `LocalBin.ini` and `debug.ini` Overrides in `OlyBar.dll`:**
   - `OlyBar.dll` (`0x10003f40`) checks for a local `debug.ini` file (`[Debug]` keys `TestSv` and `xmlPath`).
   - `OlyBar.dll` (`0x1000a780`) also supports a local firmware override file `LocalBin.ini` (`[BODY]` keys `NAME`, `DATE`, `INFOURL`, `PATH` = `olyfirm.bin`, `SIZE`, `VERSION`, `LICENCE`).

---

## 5. Firmware Container Format (`SAN_E_321_1100_0000_0000.BIN`)

### 5.1 How it was cracked (thought process)
1. Raw header bytes `0x40..0x5F` were all `0xDF` = `~0x20` -> strong hint of **bitwise inversion** (padding of ASCII spaces).
2. XOR `0xFF` gave near-ASCII but scrambled text: `EGLN=T4H49416 1S...`. Letters were all present but out of order -> **byte permutation**, not encryption.
3. Comparing against obvious targets (`LENGTH=`, `VER=`, known strings like `Copyright (c) 2003 Tokyo Electron Device Ltd.` deep in the image) pinned the permutation to a fixed **16-byte period**.
4. Verified with the header `SUM=` fields: the byte-sum of each unscrambled section matches exactly.

> Correction to an earlier chat message: I initially guessed the header said `LENGTH=8739092 ... VER=550UZv1.1`. That guess was wrong. The real decoded header is below.

### 5.2 Algorithm
```python
PERM16 = [2,0,3,1, 5,7,4,6, 11,10,9,8, 14,12,13,15]
plain[blk+i] = raw[blk + PERM16[i]] ^ 0xFF     # for each aligned 16-byte block
```
Script: [`scripts/sp550uz_fw_unpack.py`](../scripts/sp550uz_fw_unpack.py)

### 5.3 Layout (unscrambled offsets)
| Offset | Size | Content |
| :--- | :--- | :--- |
| `0x000000` | 96 | `LENGTH=4149416 SG155 VER=v155-77 DVR=77 SUM=445413452\r\n` + spaces |
| `0x000060` | 4,149,416 | **Section 1 "NPROG"** - ARM program image (first word `0xEA0001FE` = ARM `b` reset vector) |
| `0x3F5108` | 96 | `NDATA LENGTH=4589568 SG155 VER=v155-77 DVR=77 SUM=480118548\r\n` (preceded by 16-byte marker `de c0 ad 0b ...`) |
| `0x3F5168` | 4,589,568 | **Section 2 "NDATA"** - resource data (fonts/GUI bitmaps/tables; ends with a JPEG `ff d9`) |
| `0x855968` | 8 | padding |

Output files in `Resources/firmware/`:
- `SAN_E_321_1100_unscrambled.bin` (whole container, unscrambled)
- `sp550uz_v1.1_section1_code.bin` (load at `0x40000000`)
- `sp550uz_v1.1_section2_ndata.bin`

Both checksums verified: S1 sum = 445,413,452 ✔, S2 sum = 480,118,548 ✔.

### 5.4 Internal identity
- Internal platform/model code: **`SG155`**, firmware build **`v155-77`**, DVR 77.
- USB/PTP strings: `OLYMPUS`, `SP550UZ`, `OLYMPUS DIGITAL CAMERA`, `D4321`.
- Filesystem library: `Copyright (c) 2003 Tokyo Electron Device Ltd.` (FSB 1.2.1, FAT12/16, `[STL:ERR]`/`BML_` = Samsung-style NAND flash translation layer).

### 5.5 The camera's own updater parser (inside the firmware)
Literal-pool refs at `0x40291D60..0x4029297C` point to the string table at `0x403C5980`:
`LENGTH=`, `%ld`, `SUM=`, `LOADADDRESS=`, `FIRMWAREBIN`, `FIRMWARE   ` (8.3 name), `SG`/`SX`/`SG155`, `VER=`, `FONT`, `SUB_FIRMHEX`, `FNTUPLODBIN`, `LANG=`, `MODEL_CODE`, and section names `NPROG` / `NDATA` / `NLIPI`.
- **Interesting:** the camera appears to also support updating from a file named `FIRMWARE.BIN` on the card (8.3 `FIRMWARE   `), plus separate font (`FNTUPLOD.BIN`) and sub-CPU (`SUB_FIRM.HEX`) updates. Card-based update is a possible alternative to the USB `0x9119` path - **not tested**.
- `LOADADDRESS=` suggests a header field can specify the load address; our image header doesn't include it, so the default (`0x40000000`) is used.

## 6. Firmware Internals - First Findings (Section 1)

The image keeps **hundreds of function-name strings** (used by debug/assert tables), which will make Ghidra work much easier. Highlights relevant to the goal:

| Area | Example symbols (string offset in Section 1) |
| :--- | :--- |
| Display control | `COMM_DispCtrl_On_Wait_And_Set` (`0x395bc0`), `COMM_DispCtrl_DispEndWait` |
| OSD text/bitmaps ("Osc" = on-screen character layer) | `DISP_OscF` (`0x396ae8`), `DISP_StrCtrl`, `DISP_Osc_GetLineCnt_*`, `DISP_GuiLib_OscRectFill_SamplePicture` |
| Info overlays (what we want to hide) | `DISP_InfoRec_ZoomBarIcon` (`0x399b00`), `DISP_InfoPlay_DispNormalInfo`, `DISP_Info_SilentIcon`, `DISP_MenuGuideInfoOff` (`0x39a12c`), `DISP_EasyPrintInfoOff` |
| Menu callbacks | `MNCB_MenuDispMute` (`0x399240`) - name suggests "mute display", worth tracing |
| Video out setting | `DISP_GuiLib_BranchVideoOut` (`0x3a12c4`), `Comm_bef_Av_InOut` (`0x398660`) - A/V cable plug/unplug handler |
| Power on/off | `DISP_GuiLib_BranchPwOnOffScreen`, `..._BranchPwOnOffSound`, `COMM_menuChkSyncPointAftTmpOff` |
| PTP | `Ptp_GetCurrentBatteryLevel`, `Ptp_GetCurrentDateTime`, `OL_MTP_*` |

No plain strings for `sleep`/`APO`/`PowerOff` yet - the auto-off timer is probably a numeric setting; next step is to find it via the Setup-menu "sleep" item and xrefs in Ghidra.

### 6.1 Reverse-Engineered OSD Subsystem Architecture

1. **Master Record Mode OSD Dispatcher (`0x401b32f4`):**
   - Takes `r0 = display_mode` and branches via a 25-entry jump table (`0x401b3324`..`0x401b3384`).
   - Modes that display info overlays invoke `0x401b3874` with specific element IDs (`r0 = element_id, r1 = 1 to show / 0 to hide`).
   - Clean modes (such as entries at `0x401b3334`, `0x401b3348`, `0x401b3350`) immediately jump to the function epilogue (`0x401b3864`), leaving the live preview unadorned.

2. **Master Element Rendering Worker (`0x401b3874`):**
   - The central bottleneck for all record-mode overlay rendering.
   - Takes `(r0 = element_id, r1 = action)`.
   - Dispatches across the overlay rendering routines:
     - `Case 0` (`0x401b38e8` -> `0x401b3984`): Primary shooting HUD (aperture `%-3.1f`, shutter speed `%-3d` / `BULB`, frame counter `8888`, battery icon, and zoom bar via `0x401b73cc`).
     - `Case 1` (`0x401b38f4` -> `0x401b3b40`): Frame assist grid overlay.
     - `Case 2` (`0x401b3900` -> `0x401b3e40`): Live histogram overlay.
     - `Case 3` (`0x401b390c` -> `0x401b4768`): AF target frame / focus bracket mark.
     - `Case 4` (`0x401b3918` -> `0x401b4134`): Date/time stamp.
     - `Case 5` (`0x401b3924` -> `0x401b4314`): Panorama guide.
     - `Case 6` (`0x401b3930` -> `0x401b4260`): Scene guide / wizard icons.
     - `Case 7` (`0x401b393c` -> `0x401b42b4`): Self-timer / sound / auxiliary icons.

### Next steps
1. Import `sp550uz_v1.1_section1_code.bin` into Ghidra: ARM v5 LE, base `0x40000000`; mark `0x40000000` as entry.
2. Use the name-string table to label functions (strings are referenced by pointer tables next to function addresses).
3. Trace `Comm_bef_Av_InOut` (what changes when the A/V cable is inserted) and the info-display mode cycling (`DISP_InfoRec_*`) to find a "no-info" state.
4. Find the auto-power-off timer (search Setup-menu code near `BranchPwOnOff*` and the battery/power manager).

---

## 7. Auto-Power-Off & Sleep Subsystem Reverse Engineering

### 7.1 Architecture & Control Flow
1. **Idle / Inactivity Timer (`0x41f8ddac` in RAM):**
   - The camera maintains a central idle countdown timer in RAM at address `0x41f8ddac`.
   - Every physical button press, mode dial change, or zoom lever event resets this timer via `0x401501b4` (`strh r0, [0x403ea8e4]; str r0, [0x41f8ddac]`).
   - The hardware key polling task (`0x401247fc`) scans all keypad matrix lines (keys `0x19`, `0x27`, `0x2b`, `0x2d`, `0x2e`, `0x34`) and calls the reset routine when any activity is detected.

2. **The Global Sleep Inhibit Check (`0x40150540`):**
   - Before the camera enters temporary power down (`TmpOff`), sleep, or auto-power-off, it invokes `0x40150540`.
   - In stock firmware, `0x40150540` inspects the operating mode (`[0x41f8ddcc + 0x60]`):
     - If in USB mode (`0xe7`), it returns `1` (sleep inhibited).
     - Otherwise, it queries device state register `0x1a` via an indirect dispatch. If not suppressed, it returns `0` (sleep allowed).
   - Key Callers of `0x40150540`:
     - `0x4015046c`: If `0x40150540` returns 0, it calls `0x4014bfc0` to trigger physical shutdown! If `1`, shutdown is skipped.
     - `0x4014c434`: If `0x40150540` returns 0, it invokes `0x4014c5d0` to enter sleep mode. If `1`, sleep is skipped.
     - `0x401abe18`: Mode change inactivity check; if `1`, keeps camera awake.
     - `0x4014c910`: Standby manager transition check.

3. **Inactivity Sleep Timeout Check (`0x4014bd40`):**
   - At `0x4014bd40..0x4014bd50`, the firmware checks if the idle timer is set to `-1` (`0xFFFFFFFF`):
     ```arm
     0x4014bd40: ldr sb, [pc, #-0x60]  ; loads 0x41f8ddac
     0x4014bd44: ldr r1, [sb]
     0x4014bd48: mvn r2, #0            ; r2 = 0xFFFFFFFF
     0x4014bd4c: cmp r1, r2
     0x4014bd50: bne 0x4014bc0c        ; if != -1, enters power-down loop
     ```

---

## 9. Repacker Implementation & Verification (`sp550uz_fw_pack.py`)

### 9.1 Container Assembly & Checksum Recalculation
- **Checksum Algorithm:** Simple 32-bit unsigned summation of all bytes in the section (`sum(data) & 0xFFFFFFFF`).
- **Section 1 (Stock):** Length = 4,149,416 bytes | `SUM = 445413452` (`0x1a8c784c`)
- **Section 2 (NDATA):** Length = 4,589,568 bytes | `SUM = 480118548` (`0x1c9e0714`) (unmodified)
- **Container Obfuscation:** 16-byte lane permutation using `INV_PERM16 = [1, 3, 0, 2, 6, 4, 7, 5, 11, 10, 9, 8, 13, 14, 12, 15]` followed by `XOR 0xFF`.

### 9.2 Verification Milestones
- [x] **Bit-for-Bit Official Roundtrip:** Unpacking `SAN_E_321_1100_0000_0000.BIN` and repacking via `sp550uz_fw_pack.py` produced an exact bit-identical SHA-256 match (`716fb9cf1a59c6e9269f361e8a32fc7c063975b247132fbc2144ad452eb94f14`).
- [x] **Container Roundtrip Verification:** Repacked containers unscrambled cleanly; Section 1 byte sum matched `445413452` and Section 2 byte sum matched `480118548` with zero errors.

---

## 11. Disassembly Analysis: Card-Based Firmware Updater Trigger

### 11.1 Directory Requirement Trace (`0x402918d4`)
Reverse engineering the storage scan routine revealed why placing `FIRMWARE.BIN` in the card root failed:
1. `0x40291900` loads string literal `"FIRMWARE   "` (11-byte FAT 8.3 entry with 3 trailing spaces for directory attribute).
2. It calls `0x40105034("FIRMWARE   ", 1)` and `0x40104024("FIRMWARE   ", ...)` to locate the subdirectory.
3. If `/FIRMWARE/` is not found, it immediately aborts with `-2` (`0x40291974: mvn r0, #1`).
4. If `/FIRMWARE/` is present, it proceeds to line `0x40291988` calling `0x40109784` to open `/FIRMWARE/FIRMWARE.BIN` (`"FIRMWAREBIN"`).

### 11.2 Header & Safety Checks (`0x40290d0c` -> `0x40291104`)
1. Reads 96 bytes (`0x60`) from `/FIRMWARE/FIRMWARE.BIN`.
2. Verifies obfuscation marker `0xBA 0xB8 0xB3 0xB1` and descrambles the header.
3. Validates tags: `LENGTH=`, model code `SG155`, and ensures string does not match `FONT`.
4. Returns `1` to `0x40160170`.

### 11.3 Playback Mode Trigger (`0x401efac8`)
Hardware testing confirmed that the card updater is tied to the **Playback Mode (`>`) state transition**. 
1. When booting in shooting mode (Auto/P/A/S/M), the card update check is bypassed.
2. Pressing or switching to the **green Playback (`>`) button** executes `0x401efac8` -> `0x40160170` -> `0x402918d4`.
3. The camera prompts:
   ```text
   FIRMWARE VERSION
   YES / NO
   v155-77
   ```
4. Selecting **YES** triggers `0x40291694` card flashing. Selecting **NO** enters standard playback.

---

## 12. USB Flash Flashing Milestone (`sp550uz_usb_flash.py`)

### 12.1 Implementation of Full SCSI-PTP Protocol Stack
Disassembling `OlyGin.dll` (`0x10009440`–`0x100098a1`) revealed the exact 16-byte SCSI CDB requirements:
* `0xC0` (PTP Command): 16-byte CDB
* `0xC1` (PTP Data-Out): 16-byte CDB with big-endian total length at bytes `6..9`
* `0xC4` + `0xC2` (PTP Data-In): query container length at offset 12 followed by data read
* `0xC3` (PTP Response Code)

### 12.2 Live Flashing Execution & Results
1. **PTP Session:** Successfully established session (`0x1002`).
2. **SendObjectInfo (`0x100C`):** Transmitted 60-byte metadata structure for target body ID `1` (8,739,184 bytes). Returned `0x2001` (`OK`), ObjectHandle `0x000A031C`.
3. **Chunk Transfer (`0x9119`):** Streamed all 138 chunks of `SAN_E_321_1100_0000_0000.BIN` at 576 KB/s into camera SDRAM.
4. **On-Camera RAM Verification (`0x9121`):** Bootloader de-scrambled and computed 32-bit unsigned sums for Section 1 (`445413452`) and Section 2 (`480118548`). Returned `0x2001` (`PTP_RC_OK`).
5. **Physical Flash Write (`0x9123`):** Triggered `UpdateInitiate`. Flash burn executed for ~116 seconds, completing successfully before triggering an automatic reboot.

### Option 2: USB PTP-over-SCSI Flashing (`sp550uz_scsi_ptp.py`)
1. Connect camera in `Control/PC` mode.
2. Send `SendObjectInfo` (`0x100C`, `0x80000001`, target body ID `1`, length 8,739,184).
3. Transmit firmware container in `0xF800` (63,488-byte) chunks via opcode `0x9119`.
4. Run `FirmwareCheck` (`0x9121`) to verify memory checksum in RAM.
5. Trigger `UpdateInitiate` (`0x9123`) only upon explicit user confirmation.
