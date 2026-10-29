#!/usr/bin/env python3
"""
Olympus SP-550UZ PTP-over-SCSI Interrogation Tool (/dev/sg0)

Implements the Olympus custom SCSI CDB wrapper around PTP/MTP containers
as reverse-engineered from CDevCtrlSpti in OlyGin.dll:
  - 0xC0 (Data-Out, 0x40 B): Send PTP Command container (type = 1)
  - 0xC1 (Data-Out, 12+N B): Send PTP Data-Out container (type = 2)
  - 0xC4 (Data-In,  0x40 B): Query incoming PTP Data-In length at offset 12
  - 0xC2 (Data-In,  len  B): Receive PTP Data-In container (type = 2)
  - 0xC3 (Data-In,  0x40 B): Receive PTP Response container (type = 3)
  - 0xDF (No-Data, 12-B CDB): ChangePid(mode)

SAFETY: Does NOT invoke UpdateInitiate (0x9123) or TransFirmware (0x9119).
"""

import ctypes
import os
import struct
import sys

SG_IO = 0x2285
SG_DXFER_NONE = -1
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


def sg_exec(fd, cdb_bytes, direction, buf_len=0, out_data=None, timeout_ms=10000):
    import fcntl

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


def ptp_datain(fd):
    cdb_q = bytes([0xC4, 0, 0, 0, 0, 0])
    st, hst, dst, sb, qdata = sg_exec(fd, cdb_q, SG_DXFER_FROM_DEV, buf_len=0x40)
    if st != 0 or hst != 0:
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


def read_ptp_string(data, offset):
    nchars = data[offset]
    offset += 1
    if nchars == 0:
        return "", offset
    raw = data[offset : offset + 2 * nchars]
    offset += 2 * nchars
    s = raw.decode("utf-16le", errors="replace").rstrip("\x00")
    return s, offset


def read_u16_array(data, offset):
    count = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    arr = [
        struct.unpack("<H", data[offset + 2 * i : offset + 2 * (i + 1)])[0]
        for i in range(count)
    ]
    offset += 2 * count
    return arr, offset


def parse_device_info(payload):
    off = 0
    std_ver, vnd_ext_id, vnd_ext_ver = struct.unpack("<HIH", payload[off : off + 8])
    off += 8
    vnd_desc, off = read_ptp_string(payload, off)
    func_mode = struct.unpack("<H", payload[off : off + 2])[0]
    off += 2
    ops, off = read_u16_array(payload, off)
    evts, off = read_u16_array(payload, off)
    props, off = read_u16_array(payload, off)
    cap_fmts, off = read_u16_array(payload, off)
    img_fmts, off = read_u16_array(payload, off)
    mfg, off = read_ptp_string(payload, off)
    model, off = read_ptp_string(payload, off)
    dev_ver, off = read_ptp_string(payload, off)
    serial, off = read_ptp_string(payload, off)
    return {
        "std_ver": std_ver,
        "vnd_ext_id": vnd_ext_id,
        "vnd_ext_ver": vnd_ext_ver,
        "vnd_desc": vnd_desc,
        "func_mode": func_mode,
        "ops": ops,
        "evts": evts,
        "props": props,
        "cap_fmts": cap_fmts,
        "img_fmts": img_fmts,
        "mfg": mfg,
        "model": model,
        "dev_ver": dev_ver,
        "serial": serial,
    }


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else "/dev/sg0"
    fd = os.open(dev, os.O_RDWR)
    try:
        tx = 0
        ptp_cmd(fd, 0x1002, tx, [1])
        rcode, _, _, _ = ptp_resp(fd)
        print(f"OpenSession(1): 0x{rcode:04x}")

        tx += 1
        ptp_cmd(fd, 0x1001, tx)
        _, ddata = ptp_datain(fd)
        rcode, _, _, _ = ptp_resp(fd)
        info = parse_device_info(ddata[12:])
        print(f"GetDeviceInfo (0x{rcode:04x}):")
        print(f"  Manufacturer: {info['mfg']}")
        print(f"  Model:        {info['model']}")
        print(f"  DeviceVer:    {info['dev_ver']}")
        print(f"  Serial:       {info['serial']}")
        print(f"  VendorDesc:   {info['vnd_desc']}")
        print(f"  Operations:   {[hex(x) for x in info['ops']]}")

        tx += 1
        ptp_cmd(fd, 0x911C, tx)
        rcode, _, params, _ = ptp_resp(fd)
        print(f"GetFirmwareUpdateMode (0x911C): 0x{rcode:04x}, mode={params}")

        tx += 1
        ptp_cmd(fd, 0x9120, tx)
        _, ddata = ptp_datain(fd)
        rcode, _, _, _ = ptp_resp(fd)
        ver_str, _ = read_ptp_string(ddata[12:], 0)
        print(f"GetVersions (0x9120): 0x{rcode:04x} -> {ver_str}")

        for lang_param, label in [(1, "Default"), (0x8001, "Additional")]:
            tx += 1
            ptp_cmd(fd, 0x9124, tx, [lang_param])
            _, ddata = ptp_datain(fd)
            rcode, _, _, _ = ptp_resp(fd)
            payload = ddata[12:]
            count = struct.unpack("<I", payload[:4])[0]
            codes = [
                struct.unpack("<H", payload[4 + 2 * i : 6 + 2 * i])[0]
                for i in range(count)
            ]
            print(
                f"GetLanguageCode (0x9124, {label}): 0x{rcode:04x} -> count={count}, codes={[hex(c) for c in codes]}"
            )

        tx += 1
        ptp_cmd(fd, 0x1003, tx)
        rcode, _, _, _ = ptp_resp(fd)
        print(f"CloseSession: 0x{rcode:04x}")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
