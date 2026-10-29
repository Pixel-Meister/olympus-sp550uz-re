#!/usr/bin/env python3
"""
Olympus Firmware Server Client & Custom DES Decryptor

1. Replicates the custom Olympus DES implementation in OlyWebAccess.dll / OlyBar.dll
   (which omits the 28-bit mask after left-rotating C and D in the key schedule).
2. Decrypts olysurf.bin with key b"OlymWebZ" to obtain server paths.
3. Queries https://fw01.om-digitalsolutions.net/ww_inform/fcache.do with the exact
   <firmware_demand> XML schema expected by the server for the SP-550UZ (SANE321000000000).
4. Downloads SAN_E_321_1100_0000_0000.BIN and its release notes HTML.
"""

import os
import re
import struct
import sys
import urllib.request
import xml.etree.ElementTree as ET

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

SBOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def oly_rot28_bug(val, shift):
    """Replicates OlyWebAccess.dll 0x100016c0 28-bit rotation without 0x0fffffff mask."""
    mask = 1 if shift == 1 else 3
    v64 = (val & 0xFFFFFFFF) << shift
    low = (v64 >> 28) & mask
    high = v64 & (~mask & 0xFFFFFFFF)
    return (low | high) & 0xFFFFFFFF


def oly_key_schedule(key8):
    k_lo, k_hi = struct.unpack("<II", key8)
    k64 = (k_hi << 32) | k_lo

    c = 0
    d = 0
    for i in range(28):
        bit_c = (k64 >> (64 - PC1[i])) & 1
        c |= bit_c << (27 - i)
        bit_d = (k64 >> (64 - PC1[i + 28])) & 1
        d |= bit_d << (27 - i)

    subkeys = []
    for sh in SHIFTS:
        c = oly_rot28_bug(c, sh)
        d = oly_rot28_bug(d, sh)
        rk = []
        for i in range(24):
            pos = 28 - PC2[i]
            rk.append((c >> pos) & 1)
        for i in range(24, 48):
            pos = 56 - PC2[i]
            rk.append((d >> pos) & 1)
        subkeys.append(rk)
    return subkeys


def oly_des_block(block8, subkeys, decrypt=True):
    b_lo, b_hi = struct.unpack("<II", block8)
    b64 = (b_hi << 32) | b_lo

    ip_bits = [(b64 >> (64 - IP[i])) & 1 for i in range(64)]
    L = 0
    R = 0
    for i in range(32):
        L |= ip_bits[i] << (31 - i)
        R |= ip_bits[i + 32] << (31 - i)

    rounds = range(15, -1, -1) if decrypt else range(16)
    for r in rounds:
        rk = subkeys[r]
        s_out = 0
        for s in range(8):
            b6 = []
            for j in range(6):
                ebit = (R >> (32 - E[s * 6 + j])) & 1
                b6.append(ebit ^ rk[s * 6 + j])
            row = (b6[0] << 1) | b6[5]
            col = (b6[1] << 3) | (b6[2] << 2) | (b6[3] << 1) | b6[4]
            val = SBOX[s][row][col]
            s_out |= val << (28 - 4 * s)

        f_val = 0
        for i in range(32):
            bit = (s_out >> (32 - P[i])) & 1
            f_val |= bit << (31 - i)

        L, R = R, L ^ f_val

    pre_fp = (R << 32) | L
    out64 = 0
    for i in range(64):
        bit = (pre_fp >> (64 - FP[i])) & 1
        out64 |= bit << (63 - i)

    return struct.pack("<II", out64 & 0xFFFFFFFF, (out64 >> 32) & 0xFFFFFFFF)


def oly_des_ecb(data, key8, decrypt=True):
    subkeys = oly_key_schedule(key8)
    out = bytearray()
    for off in range(0, len(data) - (len(data) % 8), 8):
        out.extend(oly_des_block(data[off : off + 8], subkeys, decrypt=decrypt))
    return bytes(out)


def query_sp550uz_firmware():
    xml_req = (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        "<firmware_demand>"
        "<revision>001</revision>"
        "<mac_address>00-00-00-00-00-00</mac_address>"
        "<time>20261025195000</time>"
        "<language>ENU</language>"
        "<application>FWUT</application>"
        "<type>0000</type>"
        "<version>00005000</version>"
        "<os>WIN</os>"
        "<country_code>0001</country_code>"
        "<hardwares>"
        "<firmup_mode>0002</firmup_mode>"
        "<hardware_info>"
        "<hard_code>SANE321000000000</hard_code>"
        "<firmware_version>00001001</firmware_version>"
        "<serial_no>000000000</serial_no>"
        "<default_languages>"
        "<code>ENU</code>"
        "<code>FRA</code>"
        "<code>ESP</code>"
        "<code>PTG</code>"
        "</default_languages>"
        "</hardware_info>"
        "</hardwares>"
        "</firmware_demand>"
    ).encode("utf-8")

    url = "https://fw01.om-digitalsolutions.net/ww_inform/fcache.do"
    req = urllib.request.Request(
        url,
        data=xml_req,
        headers={
            "Content-Type": "text/xml",
            "User-Agent": "Olympus Update Control",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw_xml = resp.read().decode("utf-8", errors="replace")

    # Strip <license_agreement> boilerplate before parsing/saving
    sanitized_xml = re.sub(
        r"<license_agreement>.*?</license_agreement>",
        "<license_agreement>[REDACTED_EULA]</license_agreement>",
        raw_xml,
        flags=re.DOTALL,
    )
    return sanitized_xml


def main():
    out_dir = "/home/justin/Dev/olympus/Resources/firmware"
    os.makedirs(out_dir, exist_ok=True)

    print("[*] Querying OM Digital Solutions firmware server (fcache.do)...")
    sanitized_xml = query_sp550uz_firmware()

    xml_path = os.path.join(out_dir, "sp550uz_firmware_result.xml")
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(sanitized_xml)
    print(f"[+] Saved sanitized XML response to {xml_path}")

    root = ET.fromstring(sanitized_xml)
    fw_node = root.find(".//firmware_info")
    if fw_node is None:
        print("[-] No <firmware_info> node found in response!")
        sys.exit(1)

    file_name = fw_node.findtext("file_name", "SAN_E_321_1100_0000_0000.BIN")
    file_size = int(fw_node.findtext("file_size", "0"))
    dl_url = fw_node.findtext("url", "").strip()
    detail_url = fw_node.findtext("detail_url", "").strip()
    version = fw_node.findtext("version", "").strip()

    print(f"[+] Found Firmware: {file_name} (version {version}, {file_size} bytes)")

    if detail_url:
        detail_path = os.path.join(out_dir, "index01a.html")
        urllib.request.urlretrieve(detail_url, detail_path)
        print(f"[+] Downloaded release notes to {detail_path}")

    bin_path = os.path.join(out_dir, file_name)
    if os.path.exists(bin_path) and os.path.getsize(bin_path) == file_size:
        print(f"[+] Firmware binary already downloaded at {bin_path} ({file_size} bytes)")
    else:
        print(f"[*] Downloading {file_name} ({file_size} bytes)...")
        req = urllib.request.Request(
            dl_url, headers={"User-Agent": "Olympus Update Control"}
        )
        with urllib.request.urlopen(req, timeout=60) as r, open(bin_path, "wb") as f:
            data = r.read()
            f.write(data)
        print(f"[+] Downloaded {len(data)} bytes to {bin_path}")


if __name__ == "__main__":
    main()
