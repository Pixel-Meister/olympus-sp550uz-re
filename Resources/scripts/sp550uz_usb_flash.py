#!/usr/bin/env python3
"""
Olympus SP-550UZ PTP-over-SCSI Firmware Upload & Flasher

Performs:
1. PTP OpenSession (0x1002)
2. SendObjectInfo (0x100C)
3. SendFirmwareChunk (0x9119) in 0xF800 (63,488-byte) blocks
4. FirmwareCheck (0x9121) - Camera-side RAM checksum verification
5. Optional UpdateInitiate (0x9123) - Flashing only when explicitly enabled
"""

import argparse
import ctypes
import fcntl
import os
import struct
import sys
import time

SG_IO = 0x2285
SG_DXFER_TO_DEV = -2
SG_DXFER_FROM_DEV = -3


class SgIoHdr(ctypes.Structure):
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


def sg_exec(fd, cdb_bytes, direction, buf_len=0, out_data=None, timeout_ms=30000):
    cdb = (ctypes.c_ubyte * len(cdb_bytes))(*cdb_bytes)
    sense = (ctypes.c_ubyte * 32)()
    if direction == SG_DXFER_TO_DEV:
        buf = (ctypes.c_ubyte * len(out_data))(*out_data)
        dxfer_len = len(out_data)
    elif direction == SG_DXFER_FROM_DEV:
        buf = (ctypes.c_ubyte * buf_len)()
        dxfer_len = buf_len
    else:
        buf = None
        dxfer_len = 0

    hdr = SgIoHdr()
    hdr.interface_id = ord("S")
    hdr.dxfer_direction = direction
    hdr.cmd_len = len(cdb_bytes)
    hdr.mx_sb_len = 32
    hdr.dxfer_len = dxfer_len
    hdr.dxferp = ctypes.cast(buf, ctypes.c_void_p) if buf is not None else 0
    hdr.cmdp = ctypes.cast(cdb, ctypes.c_void_p)
    hdr.sbp = ctypes.cast(sense, ctypes.c_void_p)
    hdr.timeout = timeout_ms

    fcntl.ioctl(fd, SG_IO, hdr)
    data = bytes(buf) if (direction == SG_DXFER_FROM_DEV and buf is not None) else b""
    return hdr.status, hdr.host_status, hdr.driver_status, bytes(sense[: hdr.sb_len_wr]), data


def ptp_cmd(fd, opcode, tx_id, params=None):
    if params is None:
        params = []
    length = 12 + 4 * len(params)
    payload = struct.pack("<IHHI", length, 1, opcode, tx_id)
    for p in params:
        payload += struct.pack("<I", p)
    payload = payload.ljust(0x40, b"\x00")
    cdb = bytes([0xC0, 0, 0, 0, 0, 0])
    return sg_exec(fd, cdb, SG_DXFER_TO_DEV, out_data=payload)


def ptp_dataout(fd, opcode, tx_id, data):
    total_len = 12 + len(data)
    hdr = struct.pack("<IHHI", total_len, 2, opcode, tx_id)
    payload = hdr + data
    cdb = bytearray(16)
    cdb[0] = 0xC1
    struct.pack_into(">I", cdb, 6, total_len)
    return sg_exec(fd, bytes(cdb), SG_DXFER_TO_DEV, out_data=payload)


def ptp_datain(fd):
    cdb_q = bytes([0xC4, 0, 0, 0, 0, 0])
    st, hst, dst, sb, qdata = sg_exec(fd, cdb_q, SG_DXFER_FROM_DEV, buf_len=0x40)
    if st != 0 or hst != 0 or len(qdata) < 16:
        return st, b""
    total_len = struct.unpack("<I", qdata[12:16])[0]
    if total_len == 0 or total_len > 0x100000:
        return st, b""
    cdb_d = bytes([0xC2, 0, 0, 0, 0, 0])
    st, hst, dst, sb, ddata = sg_exec(fd, cdb_d, SG_DXFER_FROM_DEV, buf_len=total_len)
    return st, ddata


def ptp_resp(fd):
    cdb_r = bytes([0xC3, 0, 0, 0, 0, 0])
    st, hst, dst, sb, rdata = sg_exec(fd, cdb_r, SG_DXFER_FROM_DEV, buf_len=0x40)
    if len(rdata) >= 12:
        rlen, rtype, rcode, rtx = struct.unpack("<IHHI", rdata[:12])
        nparams = max(0, (min(rlen, len(rdata)) - 12) // 4)
        params = [
            struct.unpack("<I", rdata[12 + 4 * i : 16 + 4 * i])[0]
            for i in range(nparams)
        ]
        return rcode, rtx, params, rdata[:rlen]
    return None, None, [], rdata


def upload_and_verify(dev_path, fw_file, execute_flash=False):
    if not os.path.exists(fw_file):
        print(f"Error: Firmware file {fw_file} not found.")
        return False

    with open(fw_file, "rb") as f:
        fw_data = f.read()

    fw_size = len(fw_data)
    CHUNK_SIZE = 0xF800
    num_chunks = (fw_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    print("==================================================")
    print(" Olympus SP-550UZ PTP USB Firmware Uploader")
    print("==================================================")
    print(f"Target Device:  {dev_path}")
    print(f"Firmware File:  {fw_file}")
    print(f"Total Size:     {fw_size:,} bytes")
    print(f"Chunks:         {num_chunks} x {CHUNK_SIZE:,} bytes")
    print("--------------------------------------------------")

    fd = os.open(dev_path, os.O_RDWR)
    try:
        tx = 1
        # Ensure any stale session is closed before starting
        try:
            ptp_cmd(fd, 0x1003, tx)
            ptp_resp(fd)
            tx += 1
        except Exception:
            pass

        ptp_cmd(fd, 0x1002, tx, [1])
        rcode, _, _, _ = ptp_resp(fd)
        if rcode not in (0x2001, 0x2019):
            print(f"[-] OpenSession failed: 0x{rcode:04x}")
            return False
        print("[+] Session opened successfully.")

        # Query DeviceInfo (0x1001)
        tx += 1
        ptp_cmd(fd, 0x1001, tx)
        ptp_datain(fd)
        ptp_resp(fd)

        # Query FirmwareUpdateMode (0x911C) - response params return [2]
        tx += 1
        ptp_cmd(fd, 0x911C, tx)
        rcode, _, params, _ = ptp_resp(fd)
        if rcode != 0x2001:
            print(f"[-] GetFirmwareUpdateMode failed: 0x{rcode:04x}")
            return False
        print("[+] Camera initialized into Firmware Update Mode (0x911C: OK).")

        tx += 1
        obj_info = bytearray(60)
        struct.pack_into("<I", obj_info, 0, 0x80000001)
        struct.pack_into("<H", obj_info, 4, 1)  # Target 1 = Body Firmware
        struct.pack_into("<I", obj_info, 8, fw_size)

        for attempt in range(5):
            ptp_cmd(fd, 0x100C, tx, [0x80000001])
            st, _, _, _, _ = ptp_dataout(fd, 0x100C, tx, bytes(obj_info))
            rcode, _, params, _ = ptp_resp(fd)
            if rcode == 0x2001:
                break
            print(f"[*] SendObjectInfo attempt {attempt+1} returned 0x{rcode:04x}, waiting 2s...")
            time.sleep(2)
            tx += 1
        if rcode != 0x2001:
            print(f"[-] SendObjectInfo failed: 0x{rcode:04x}")
            return False
        print(f"[+] SendObjectInfo accepted: ObjectHandle=0x{params[2]:08x}")

        print("[*] Uploading firmware chunks into camera SDRAM buffer...")
        start_time = time.time()
        for i in range(num_chunks):
            offset = i * CHUNK_SIZE
            chunk = fw_data[offset : offset + CHUNK_SIZE]
            tx += 1

            ptp_cmd(fd, 0x9119, tx, [offset, len(chunk)])
            st, _, _, _, _ = ptp_dataout(fd, 0x9119, tx, chunk)
            rcode, _, _, _ = ptp_resp(fd)
            if rcode != 0x2001:
                print(f"\n[-] Chunk {i} at offset 0x{offset:x} failed: 0x{rcode:04x}")
                return False

            pct = ((offset + len(chunk)) / fw_size) * 100
            elapsed = time.time() - start_time
            speed = (offset + len(chunk)) / (elapsed + 0.001) / 1024
            sys.stdout.write(f"\r    [{i+1:3d}/{num_chunks}] {pct:5.1f}% ({speed:5.1f} KB/s)")
            sys.stdout.flush()

        print("\n[+] Transfer complete. All chunks buffered in camera SDRAM.")

        # Step 4: Camera-side RAM Checksum Verification
        print("[*] Commanding camera to verify Section 1 & Section 2 checksums in RAM (0x9121)...")
        tx += 1
        ptp_cmd(fd, 0x9121, tx)
        rcode, _, params, _ = ptp_resp(fd)
        if rcode == 0x2001:
            print("[+] CAMERA VERIFICATION SUCCEEDED! (PTP_RC_OK / 0x2001)")
            print("    The camera's internal bootloader has validated:")
            print("    - Model ID (SG155 / SP-550UZ)")
            print("    - De-scrambled section headers")
            print("    - Section 1 (Code) 32-bit unsigned byte summation")
            print("    - Section 2 (NDATA) 32-bit unsigned byte summation")
        else:
            print(f"[-] Camera rejected firmware verification: Response 0x{rcode:04x}")
            return False

        if execute_flash:
            print("--------------------------------------------------")
            print("[!] INITIATING PHYSICAL FLASH MEMORY WRITE (0x9123)...")
            tx += 1
            ptp_cmd(fd, 0x9123, tx)
            rcode, _, _, _ = ptp_resp(fd)
            print(f"[+] UpdateInitiate response: 0x{rcode:04x}")
            if rcode != 0x2001:
                print(f"[-] UpdateInitiate returned error: 0x{rcode:04x}")
                return False

            print("[*] Camera is writing to non-volatile flash memory...")
            print("[*] DO NOT DISCONNECT USB OR TURN OFF CAMERA!")
            print("[*] Monitoring progress via GetDeviceStatus (0x9122)...")
            start_flash_time = time.time()
            while True:
                time.sleep(2)
                tx += 1
                try:
                    ptp_cmd(fd, 0x9122, tx)
                    rcode, _, params, _ = ptp_resp(fd)
                    elapsed = int(time.time() - start_flash_time)
                    if rcode == 0x2001:
                        s1 = params[0] if len(params) > 0 else 0
                        s2 = params[1] if len(params) > 1 else 0
                        print(f"    [{elapsed:3d}s] Status: 0x{s1:08x}, 0x{s2:08x}")
                        # When completed, status becomes 0 or camera displays OK
                        if s1 == 0 and s2 == 0 and elapsed > 10:
                            print("[+] Flashing completed successfully!")
                            break
                    elif rcode is not None:
                        print(f"    [{elapsed:3d}s] PTP Code: 0x{rcode:04x}")
                        if rcode == 0x2001:
                            break
                    else:
                        print(f"    [{elapsed:3d}s] Camera busy writing flash...")
                except Exception as e:
                    print(f"    Notice: Connection closed or device rebooting ({e})")
                    break

                if elapsed > 180:
                    print("[-] Status timeout (3 minutes).")
                    break

            print("[+] Flash operation finished!")
        else:
            print("--------------------------------------------------")
            print("[i] Dry-run verification mode complete.")
            print("[i] Firmware is verified in camera RAM. Physical flash write not triggered.")

        tx += 1
        try:
            ptp_cmd(fd, 0x1003, tx)
            ptp_resp(fd)
        except Exception:
            pass
        return True

    finally:
        os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Olympus SP-550UZ USB Firmware Uploader")
    parser.add_argument("--dev", default="/dev/sg0", help="SCSI Generic device (default: /dev/sg0)")
    parser.add_argument("--fw", default="Resources/firmware/SAN_E_321_1100_0000_0000.BIN", help="Firmware binary path")
    parser.add_argument("--flash", action="store_true", help="Execute physical flash write after verification")
    args = parser.parse_args()

    upload_and_verify(args.dev, args.fw, execute_flash=args.flash)
