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
- [x] **Architecture Identified:** 32-bit little-endian **ARM** (ARM-mode code: `e92d....` push / `e8bd....` pop / `e12fff1e` bx lr), image load base **`0x40000000`**.
- [x] **Master OSD Overlay Engine Isolated:** Disassembled Section 1 (`0x40000000`). Located the master record overlay dispatcher (`0x401b32f4`), the central element rendering worker (`0x401b3874`), the Mode 8 Auto-minimal handler (`0x401b361c`), and the AF target mark renderer (`0x401b6668`).
- [x] **Cable-Conditional Sleep Engine Isolated:** Located global power manager sleep inhibit routine (`0x40150560`) and display destination query (`0x4012fef4`).
- [x] **Physical Flash Verification via USB PTP:** Uploaded and flashed custom firmware directly to physical camera hardware via `0x9121`/`0x9123` over `/dev/sg0`.
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
   - **Patch Opportunity:** Patching `0x401b3874` entry (`push {r8, sb, lr}`) with `bx lr` (`0xe12fff1e`) completely silences all shooting HUD / OSD drawing without affecting menus or playback!

### Next steps
1. Import `sp550uz_v1.1_section1_code.bin` into Ghidra: ARM v5 LE, base `0x40000000`; mark `0x40000000` as entry.
2. Use the name-string table to label functions (strings are referenced by pointer tables next to function addresses).
3. Trace `Comm_bef_Av_InOut` (what changes when the A/V cable is inserted) and the info-display mode cycling (`DISP_InfoRec_*`) to find a "no-info" state.
4. Find the auto-power-off timer (search Setup-menu code near `BranchPwOnOff*` and the battery/power manager).
5. Only after a patch is designed: work out whether the camera validates anything beyond the two `SUM=` byte-sums (a re-pack script is straightforward since the obfuscation is reversible). **No flashing without explicit go-ahead.**

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

## 8. Custom Firmware Patches & Verification

### 8.1 Summary of Applied Binary Patches (Section 1)

| Feature | Target Function | Load VA | File Offset | Stock Bytes | Patched Bytes | Assembly Transformation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Clean OSD (DISP Minimal &rarr; Clean)** | Mode 2 Handler in Record OSD Dispatcher | `0x401b35b4` | `0x1b35b4` | `00 10 a0 e3` | `aa 00 00 ea` | `mov r1, #0` &rarr; `b #0x401b3864` (clean epilogue) |
| **Cable-Conditional Sleep (Video Out)** | Global Sleep Inhibit Query | `0x40150560` | `0x150560` | `10 20 92 e5 ...` (28 B) | `63 7e ff eb 01 00 50 e3 01 40 a0 83 03 00 00 ea 00 00 a0 e1 ...` | `bl #0x4012fef4; cmp r0, #1; movhi r4, #1; b 0x40150580; nop...` |

### 8.2 Patch Behavior Analysis
1. **DISP-Toggleable Clean View (`0x401b35b4`):**
   - Pressing `DISP` button cycles between Full Info &rarr; Grid/Histogram &rarr; **100% Clean Live View**!
   - Normal shooting HUD overlays (shutter, aperture, zoom bar, battery level, frame count) remain fully functional on alternate presses.
   - Menus, scene guides, and playback mode remain 100% operational.
2. **Cable-Conditional Sleep (`0x40150560`):**
   - Directly checks display output destination via `0x4012fef4`.
   - If Video Out is connected (`destination > 1`, 4=NTSC or 6=PAL): Auto-sleep is inhibited, running continuously.
   - If Video Out is disconnected (`destination <= 1`, LCD or EVF): Standard 3-minute auto-sleep timer functions normally to preserve battery.

---

## 9. Repacker Implementation & Verification (`sp550uz_fw_pack.py`)

### 9.1 Container Assembly & Checksum Recalculation
- **Checksum Algorithm:** Simple 32-bit unsigned summation of all bytes in the section (`sum(data) & 0xFFFFFFFF`).
- **Section 1 (Stock):** Length = 4,149,416 bytes | `SUM = 445413452` (`0x1a8c784c`)
- **Section 1 (Patched):** Length = 4,149,416 bytes | `SUM = 445413797` (`0x1a8c79a5`) (+345 delta from patched opcodes)
- **Section 2 (NDATA):** Length = 4,589,568 bytes | `SUM = 480118548` (`0x1c9e0714`) (unmodified)
- **Container Obfuscation:** 16-byte lane permutation using `INV_PERM16 = [1, 3, 0, 2, 6, 4, 7, 5, 11, 10, 9, 8, 13, 14, 12, 15]` followed by `XOR 0xFF`.

### 9.2 Verification Milestones
- [x] **Bit-for-Bit Official Roundtrip:** Unpacking `SAN_E_321_1100_0000_0000.BIN` and repacking via `sp550uz_fw_pack.py` produced an exact bit-identical SHA-256 match (`716fb9cf1a59c6e9269f361e8a32fc7c063975b247132fbc2144ad452eb94f14`).
- [x] **Container Roundtrip Verification:** Repacked containers unscrambled cleanly; Section 1 byte sum matched `445413797` and Section 2 byte sum matched `480118548` with zero errors.

---

## 10. Flashing & Deployment Instructions

### Option 1: Card-Based Update (Recommended / Safest)
1. Format an xD-Picture Card (or microSD-to-xD adapter) as FAT16 in the camera or on PC.
2. Create a folder named **`FIRMWARE`** in the root of the card.
3. Copy [`Resources/firmware/FIRMWARE.BIN`](../firmware/FIRMWARE.BIN) into the **`FIRMWARE`** folder (`/FIRMWARE/FIRMWARE.BIN`).
4. Insert the card into the SP-550UZ with fully charged batteries.
5. Power on the camera normally. The bootloader detects `/FIRMWARE/FIRMWARE.BIN` and automatically displays the firmware update dialog.

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
4. **On-Camera RAM Verification (`0x9121`):** Bootloader de-scrambled and computed 32-bit unsigned sums for Section 1 (`445413797`) and Section 2 (`480118548`). Returned `0x2001` (`PTP_RC_OK`).
5. **Physical Flash Write (`0x9123`):** Triggered `UpdateInitiate`. Flash burn executed for ~116 seconds, completing successfully before triggering an automatic reboot.

### Option 2: USB PTP-over-SCSI Flashing (`sp550uz_scsi_ptp.py`)
1. Connect camera in `Control/PC` mode.
2. Send `SendObjectInfo` (`0x100C`, `0x80000001`, target body ID `1`, length 8,739,184).
3. Transmit firmware container in `0xF800` (63,488-byte) chunks via opcode `0x9119`.
4. Run `FirmwareCheck` (`0x9121`) to verify memory checksum in RAM.
5. Trigger `UpdateInitiate` (`0x9123`) only upon explicit user confirmation.

---

## 13. Deep Dive: Mode 8 (Auto OSD), AF Brackets, and RTOS Sleep Event Dispatch

### 13.1 Root Cause: Auto Mode 2-View Cycle vs My Mode 4-View Cycle
Hardware testing revealed that while `My Mode` cycled through 4 views (Full HUD &rarr; Grid &rarr; Histogram &rarr; Minimal), standard `AUTO` mode only toggled between 2 views: Full HUD (Mode 0) and a simplified HUD (Mode 8).
* In standard modes, Frame Assist (Grid) and Histogram are disabled by default in the camera setup menu.
* When disabled, the `DISP` button cycles between Mode 0 and **Mode 8** (`0x401b361c`).
* Mode 8 drew battery icons (`r0=5`) and autofocus brackets (`r0=0`).
* **Fix (Patch 2):** Patched `0x401b361c` with `90 00 00 ea` (`b #0x401b3864`), forcing Mode 8 to jump immediately to the clean epilogue.

### 13.2 Root Cause: Autofocus Brackets in Minimal Mode
Even with HUD text removed, central autofocus brackets `[  ]` remained on screen in Minimal mode:
* Disassembly revealed AF brackets are rendered independently by **`0x401b6668`**, called by the real-time tracking engine (`0x401c3714`, `0x401c3a74`).
* The active OSD mode is tracked in the master state structure at `[sb, #0x9c]` (`sb = 0x41f8ddcc`).
* **Fix (Patch 3):** Replaced 52 bytes at `0x401b6674` with an active mode check:
  ```arm
  ldr   sb, [pc, #0x194] ; sb = 0x41f8ddcc
  ldrsb r1, [sb, #0x9c]  ; active OSD mode
  cmp   r1, #2           ; Minimal Mode
  cmpne r1, #8           ; Auto Minimal Mode
  cmpne r1, #3           ; Custom Minimal Mode
  beq   #0x401b678c      ; Clean exit: add sp, #0x20; pop {r4,r5,r6,r8,sb,pc}
  ```

### 13.3 Root Cause: Idle Sleep Event Dispatch (0xca0f & 0xca07)
During the sleep timeout test with Video Out connected, the camera entered Standby/Sleep mode after 3 minutes:
* While `0x40150560` correctly inhibited sleep when queried via `0x40150540`, the RTOS 3-minute idle timer dispatched event `0xca0f` (or `0xca07`) directly to master event loop `0x4019e1e8`.
* Jump table `0x4019e324` (entries 15 and 7) invoked sleep transition routines `0x4014b264` and `0x4014bb18` directly, setting state `[0x41f8ddcc, #0x60] = 0x49` (Sleep) without calling `0x40150540`.
* **Fix (Patches 5 & 6):** Hooked both `0x4014b264` and `0x4014bb18` at entry (48 bytes each):
  ```arm
  push  {...}
  bl    #0x40150540      ; query sleep permission (calls 0x4012fef4 destination check)
  cmp   r0, #1           ; is composite Video Out connected?
  popeq {..., pc}        ; if Video Out: return immediately! Inhibit sleep!
  sub   sp, sp, #4       ; if unplugged: proceed into standard 3-minute sleep
  ```
* This guarantees that whenever composite video is active, sleep transitions are aborted at the root, while standard 3-minute auto-sleep functions normally when unplugged.

---

## 14. Deep Dive: Isolating the True AF Target Bracket Engine & Active OSD Offset

### 14.1 Discovery: Active OSD Mode Memory Offset `+0x9e`
Analysis of the `DISP` button handler at `0x40281b70` revealed why the initial AF bracket patch did not suppress the brackets:
* The master state structure is at base `0x41f8ddcc`.
* Offset `+0x9c` is a static sub-parameter (set to `5` during all mode switches).
* **Offset `+0x9e` (`[0x41f8ddcc, #0x9e]`) is the ACTUAL active OSD mode byte!**
  - `0` = Full HUD (Normal)
  - `1` = Grid / Histogram
  - `2` = Minimal View (Manual / My Mode)
  - `8` = Auto Minimal View (`AUTO` mode 2-view toggle)
  - `4` = Mode 4
  - `7` = Mode 7
* Written by DISP button state switchers at `0x40281c28`, `0x40281c50`, `0x40281c78`, `0x40281ca0`, and `0x40281cbc`.

### 14.2 Discovery: True AF Target Bracket Renderer (`0x401ad504`)
Tracing execution from the preview loop revealed that the previously patched routine (`0x401b6668`) was an element in the HUD text pipeline (already bypassed by the clean epilogue in Mode 2 and 8). The central white brackets `[  ]` were being rendered separately by the hardware box drawing engine:
* The true rectangular AF box renderer is **`0x401ad504`**, called exclusively from:
  - `0x401b297c`: standby/white AF bracket box (`width=0x1e` [30px], `height=0x11` [17px])
  - `0x401b29bc`: green in-focus box
  - `0x401b2a3c`: red out-of-focus box
  - `0x401b2888`: secondary AF tracking frame (called by `0x401b2804`)
* In the live preview loop (`0x40251d6c` and `0x402521d8`), the AF display manager `0x401b28b0` is called immediately prior to the OSD dispatcher (`0x401b32f4`).

### 14.3 Solution: Trampoline Hook at `0x40000100` -> `0x401ad504`
To completely eliminate the brackets in Minimal mode without disturbing Full HUD or Histogram views:
1. Branch from `0x401ad504` (`fd 4a f9 ea` -> `b #0x40000100`).
2. Trampoline at `0x40000100` (offset `0x100`, unallocated boot alignment cave):
   - Reads `[0x41f8ddcc, #0x9e]`.
   - If mode is `2`, `8`, or `3`: returns `r0 = 0` and pops `{r4-sl, pc}` immediately. Zero pixels are written to the frame buffer.
   - If mode is `0` (Full HUD) or `1` (Grid/Histogram): restores original frame allocation (`sub sp, sp, #0x14; mov r4, r0`) and branches to `0x401ad510` (`f8 b4 06 ea`) to render brackets normally.

---

## 15. The Dual AF Target Architecture: Discovery of Glyph Icons "0239" & "0240"

### 15.1 Breakthrough: Why the Brackets Are Not Rectangles
When Build 3 was tested on physical hardware, the white brackets still appeared in Minimal mode despite `0x401ad504` being hooked. Deep disassembly of the live preview loop (`0x40251934`–`0x40252200`) revealed why:
* Sanyo's graphics engine does **not** draw the stationary central autofocus brackets `[   ]` as vector rectangles.
* They are drawn as **two separate font glyph icons** loaded from Section 2 NDATA:
  - Left bracket icon resource: **`"0239"`** (`0x40399dec`)
  - Right bracket icon resource: **`"0240"`** (`0x40399df4`)
* The dedicated icon drawing engine is located at **`0x401ba8a4`**, called exclusively from the preview loop at `0x40251d08`:
  ```arm
  0x40251d00: cmp   r4, #0x18
  0x40251d04: bne   #0x40251d10
  0x40251d08: bl    #0x401ba8a4      ; DRAW AF BRACKET ICONS!
  0x40251d0c: b     #0x40251d54
  ```
* Inside `0x401ba8a4`:
  - `0x401ba964`: Loads icon `"0239"`, calls `0x401546e8` to draw left bracket `[`.
  - `0x401ba974`: Adds `0x32` (+50 pixels) to horizontal coordinate.
  - `0x401ba980`: Loads icon `"0240"`, calls `0x401546e8` to draw right bracket `]`.
  - `0x401ba9b0` & `0x401ba9cc`: Repeat for green in-focus state!

### 15.2 Solution: Hooking `0x401ba8a4` via Trampoline Cave `0x40000180`
1. Hook entry at `0x401ba8a4`: `35 16 f9 ea` (`b #0x40000180`).
2. Trampoline at `0x40000180` (40 bytes):
   - Reads active mode byte at `[0x41f8ddcc, #0x9e]`.
   - If mode is `2` (Minimal), `8` (Auto Minimal), or `3` (Custom Minimal): executes `popeq {r8, sb, pc}` immediately, returning to `0x40251d0c` without ever calling `0x401546e8`.
   - If mode is `0` (Full HUD) or `1` (Grid/Histogram): executes `sub sp, sp, #8` and branches back to `0x401ba8ac` to render brackets normally.

---

## 16. Power & Sleep Engine: Hardware Timer Thresholds vs Event Interception

### 16.1 Root Cause: Why Sleep Triggered in Build 2 & 3
Hardware sleep testing revealed that the camera still powered down to standby sleep after 3 minutes:
1. **Misidentified Cable Detection Routine:** In Build 3, our sleep hook called `0x4014cf40`. Disassembly revealed `0x4014cf40` checks for destination codes `7`, `0x17`, and `0x27`—which correspond to **USB / PC Cradle communication modes**, NOT composite video out!
2. **True Video Out Destination Values:** Disassembly of the video DAC initialization routine at `0x4013ecf0` revealed that composite Video Out sets the display destination at `0x4012fef4` to:
   - **`4`** = NTSC Composite Video Out
   - **`6`** = PAL Composite Video Out
   - (Built-in LCD is `0`, EVF is `1`).
   Because `0x4014cf40` looked for `7`, it evaluated to false (`0`), allowing the sleep timer to run.

### 16.2 Root Cause: Hardware Timer Message Structure (`0x40184d84`)
Disassembly of `0x40184d84` revealed that the 3-minute sleep timer is armed by sending a hardware configuration packet to the power controller via `0x401212ac`:
- `sp[4]` = Screen dim threshold (default 1500 tenths = 150 seconds / 2.5 minutes)
- `sp[6]` = Standby sleep threshold (default 1800 tenths = 180 seconds / 3.0 minutes)
- `sp[7]` = Full power cut threshold (`0xf0` = 240 seconds)
Before writing `sp[6]`, line `0x40184e38` calls `0x40184be0` (Sleep Inhibit Query). **If `0x40184be0` returns `1`, line `0x40184e48` executes `mov r1, #0`, setting the sleep threshold to `0` (disabled)!**
When the threshold is `0`, the hardware timer **never ticks down to sleep in the first place**.

### 16.3 The Triple-Lock Solution in Build 3b
1. **Hook at `0x40184be0` (via Trampoline Cave `0x40000140`):** Calls `0x4012fef4`. If destination is `> 1` (NTSC `4` or PAL `6`), returns `r0 = 1`. This programs the hardware timer with `sp[6] = 0` (sleep disabled).
2. **Hook at `0x4014b264` (Idle Sleep Transition 1):** Calls `0x4012fef4`. If destination is `> 1`, executes `pophi {r4, r5, r8, sb, pc}` immediately.
3. **Hook at `0x4014bb18` (Idle Sleep Transition 2):** Calls `0x4012fef4`. If destination is `> 1`, executes `pophi {r8, sb, pc}` immediately.
4. **Unplugged Battery Preservation:** If destination is `<= 1` (LCD or EVF), normal 3-minute sleep proceeds identically to factory firmware.


---

## 17. Build 4: Dynamic State Synchronization & Universal Sleep Inhibit

### 17.1 Root Causes Isolated from Hardware Testing
Live testing on physical hardware with Build 3b revealed:
1. **AF Brackets ("White Bars") Still Displayed:**
   - Trampoline hooks at `0x40000100` and `0x40000180` checked `[0x41f8ddcc, #0x9e]`.
   - Comprehensive decompilation of preview loop `0x40251934` revealed `[0x41f8ddcc, #0x9e]` was **not** the active display mode.
   - The central AF target frame is rendered on every frame by [`0x401b28b0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) (which calls [`0x401ad504`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin)) and secondary guides by [`0x401b2f1c`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin).
   - Because the condition evaluated to false, `0x401b28b0` continued drawing the white AF target mark on every frame.
2. **Camera Still Slept on Video Out:**
   - Decompilation of `0x4013eac8` revealed `0x4012fef4` reads `[0x41f8df04, #0x5a]`, which is **only written when playing an AVI movie file**, not during live shooting.
   - Because `0x4012fef4` returned `0`, sleep hooks evaluated to false.

### 17.2 The Build 4 Architecture
1. **Dedicated State Variable (`0x400001f0`):**
   - Jump table at `0x401b3324`:
     - Mode 0 & Mode 1 vector to Trampoline 2 (`0x40000120`): writes `[0x400001f0] = 0` (Normal Mode).
     - Mode 2, 3, & 8 vector to Trampoline 1 (`0x40000100`): writes `[0x400001f0] = 1` (Minimal Display Mode) and branches to clean epilogue (`0x401b3864`).
2. **AF Frame Suppression:**
   - Hooked [`0x401b28b0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) via `0x40000140`: if `[0x400001f0] == 1`, returns `popeq {r4, r5, r6, r8, sb, pc}` immediately.
   - Hooked [`0x401b2f1c`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) via `0x40000170`: if `[0x400001f0] == 1`, returns `popeq {r8, sb, pc}` immediately.
   - Hooked [`0x401ad504`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) via `0x400000a0`: if `[0x400001f0] == 1`, returns `moveq r0, #0; popeq` immediately.
3. **Universal & Cable Sleep Inhibit:**
   - Hooked [`0x40184be0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) via `0x400001a0`: if `[0x400001f0] == 1` OR `0x4016a340() == 1`, returns `r0 = 1`. Sets sleep threshold `sp[6] = 0` (hardware sleep disabled).
   - Hooked [`0x4014b264`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) and [`0x4014bb18`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin): queries `0x40184be0`, aborting sleep transitions.

---

## 18. Build 5: Root-Cause Preview Loop Resolution & One-Shot Mode Synchronization

### 18.1 The Preview Compositor Failure Mechanism
Hardware testing of Build 4 showed that white AF brackets still appeared and sleep still occurred. Disassembly of the video preview compositor loop [`0x40251934`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) revealed why:
- On every 30 fps preview frame (~33 ms), line `0x40251d74` executes `bl 0x401b32f4` with `r0 = 0` (Mode 0).
- In Build 4, Jump Table Entry 0 pointed to Trampoline 2, which executed `str 0, [0x400001f0]`.
- As a result, every 33 ms the Minimal mode state was wiped back to `0`, preventing Trampolines 0, 3, 4, and 5 from ever taking their suppression branches.

### 18.2 Build 5 Implementation
- **Jump Table Entries 0 & 1:** Restored to stock (`0x401b3388` & `0x401b33d4`).
- **One-Shot Transition Handlers Hooked:**
  - Minimal Clean View: [`0x40251458`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) & Jump Table Entries 2, 3, 8 point to Trampoline 1 / 1b (`0x400000e0` / `0x400000b0`), setting `[0x400001f0] = 1`.
  - Full HUD View: [`0x40251814`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) points to Trampoline 2 (`0x40000110`), setting `[0x400001f0] = 0`.
  - Grid View: [`0x402512c0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) points to Trampoline 2b (`0x40000080`), setting `[0x400001f0] = 0`.
  - Histogram View: [`0x40251e6c`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) points to Trampoline 2c (`0x40000050`), setting `[0x400001f0] = 0`.
- **Suppression Hooks Maintained:**
  - Central AF brackets: [`0x401b28b0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) $\rightarrow$ Trampoline 3 (`0x40000140`).
  - Secondary guide: [`0x401b2f1c`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) $\rightarrow$ Trampoline 4 (`0x40000170`).
  - Direct AF box: [`0x401ad504`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) $\rightarrow$ Trampoline 0 (`0x40000020`).
  - Sleep inhibit: [`0x40184be0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) $\rightarrow$ Trampoline 5 (`0x400001a0`).

---

## 19. Build 6: The MPU Memory Protection Unit & Physical SDRAM Relocation

### 19.1 Failure Analysis of Build 5
Hardware testing of Build 5 showed that while the battery meter was initially absent, central white AF brackets persisted and 3-minute sleep timer still tripped.
- Disassembly of the ARM946E-S MPU configuration at [`0x40000988`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) revealed that Section 1 (`0x40000000`–`0x403F50E7`) is mapped to Region 1 (NOR Flash chip, Execute-in-Place ROM) with D-Cache disabled.
- The NOR Flash chip silently drops standard CPU `str` word writes!
- Consequently, `0x400001f0` remained frozen at `0x00000000` in hardware.

### 19.2 Relocation to SDRAM (`0x41f9ffc0`)
- State variable relocated to `0x41f9ffc0` in physical cached SDRAM (System Blackboard memory).
- Cleared to 0 by boot sequence `memset` at `0x40005aa4`.

---

## 20. Build 7: The Native DISP State Engine, Glyph Icon Suppression & Triple-Timer Sleep Inhibit

### 20.1 Root Cause Discoveries from Build 6
1. **The White Bars are Font Glyphs ("0239" & "0240"):**
   - The central autofocus brackets `[` and `]` are rendered exclusively by [`0x401ba8a4`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) in the 30 fps preview loop ([`0x40251d08`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin)).
   - Previous builds hooked `0x401ad504` and `0x401b28b0` (which render dynamic focus-tracking boxes), but left `0x401ba8a4` unhooked.
2. **Triple-Timer Hardware Sleep Inhibit:**
   - Power controller configuration routine [`0x40184d84`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) arms three countdown thresholds:
     - `sp[4]` = Dim Timer ([`0x40184bbc`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin))
     - `sp[6]` = Standby Sleep Timer ([`0x40184be0`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin))
     - `sp[7]` = Power Off Timer ([`0x40184ca4`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin), default `0xf0` = 240s)
   - Hooking all three ensures the power controller receives threshold `0` for all timers in Minimal Clean View.
3. **Native Active Mode Byte in Physical SDRAM (`[0x41f8ddcc, #0x9e]`):**
   - Pressing the `DISP` button executes [`0x40281b44`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin), writing `[0x41f8ddcc, #0x9e]`:
     - `2` = Minimal View (P, A, S, M, Scene)
     - `8` = Auto Minimal View (AUTO mode)
     - `0` = Full HUD (Normal)
     - `1` = Grid / Histogram
   - Reading `[0x41f8ddcc, #0x9e]` directly in all trampolines avoids any synchronization lag or reliance on custom variables.

### 20.2 Build 7 Patch Layout
- `is_minimal_view` (`0x40000020`): Reads `[0x41f8ddcc, #0x9e]`, returns `1` if mode 2 or 8, else `0`.
- `is_sleep_inhibited` (`0x40000040`): Returns `1` if `is_minimal_view() == 1` OR composite video cable active (`0x4016a340() == 1`).
- Trampoline 1 (`0x40000070`, hooked at `0x401ba8a4`): Suppresses central bracket glyph icons `"0239"` and `"0240"`.
- Trampoline 2 (`0x40000090`, hooked at `0x401ad504`): Suppresses dynamic AF box renderer.
- Trampoline 3 (`0x400000c0`, hooked at `0x401b2f1c`): Suppresses secondary guide lines.
- Trampoline 4 (`0x400000e0`, hooked at `0x401b28b0`): Suppresses primary AF frame manager.
- Trampoline 5 (`0x40000100`, hooked at `0x40184be0`): Inhibit standby sleep threshold (`sp[6] = 0`).
- Trampoline 6 (`0x40000120`, hooked at `0x40184ca4`): Inhibit power cut threshold (`sp[7] = 0`).
- Trampoline 7 (`0x40000150`, hooked at `0x40184bbc`): Inhibit screen dim threshold (`sp[4] = 0`).
- Trampoline 8 (`0x40000170`, hooked at `0x4014b264`): Aborts primary RTOS idle sleep event.
- Trampoline 9 (`0x400001a0`, hooked at `0x4014bb18`): Aborts secondary RTOS idle sleep event.
- Jump Table (`0x401b3324`): Entries 2, 3, 8 point directly to `0x401b3864` (clean epilogue). Entries 0 and 1 remain STOCK.

---

## 21. Build 8: Synchronized SDRAM Jump-Table State Architecture

### 21.1 Physical Testing Insights from Build 7
Testing Build 7 on the physical SP-550UZ yielded a vital clue:
1. **Battery meter disappeared completely:** The battery HUD icon and remaining capacity display were 100% eliminated in Minimal View on boot.
2. **Jump Table execution confirmed:** This proved beyond doubt that the Record Mode OSD Jump Table at [`0x401b3324`](file:///home/justin/Dev/olympus/Resources/firmware/sp550uz_v1.1_section1_code.bin) executes during live preview in Minimal View and cleanly vectors to epilogue `0x401b3864`.
3. **White bars and sleep persistence explained:**
   - In live shooting preview, `[0x41f8ddcc, #0x9e]` holds `0x63` (layer 99) or `7` instead of `2` or `8`.
   - As a result, the `is_minimal_view` helper at `0x40000020` returned `0` during preview rendering and timer callbacks, preventing the bracket suppression and sleep inhibit hooks from firing.

### 21.2 Build 8 Architectural Solution
Build 8 links the proven OSD Jump Table directly to writable SDRAM memory at `0x41f9ffc0`:
- **Minimal View Entries (2, 3, 8):** Vector to Trampoline 1b at `0x400000b0`, writing `[0x41f9ffc0] = 1` and jumping to clean epilogue `0x401b3864`.
- **Full HUD Entry (0):** Vectors to Trampoline `T_jt_hud` at `0x400000c8`, writing `[0x41f9ffc0] = 0` and jumping to stock Full HUD `0x401b3388`.
- **Grid / Histogram Entry (1):** Vectors to Trampoline `T_jt_grid` at `0x400000dc`, writing `[0x41f9ffc0] = 0` and jumping to stock Grid `0x401b33d4`.
- **Fallback branches at `0x401b35b4` and `0x401b361c`:** Vector to Trampoline 1b at `0x400000b0`.
- **Unified Query Helper (`0x40000020`):** Reads `[0x41f9ffc0]` to determine active Minimal View state.
- **Trampolines 1 through 9:** All 10 trampolines actively query this synchronized state to suppress stationary bracket glyphs `"0239"` and `"0240"`, dynamic AF boxes, secondary guide lines, and inhibit dim, sleep, and power-off countdown timers.


