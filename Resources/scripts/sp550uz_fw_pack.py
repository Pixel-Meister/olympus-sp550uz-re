#!/usr/bin/env python3
"""
sp550uz_fw_pack.py - Repack and scramble firmware containers for Olympus SP-550UZ.

Features:
- Exact roundtrip bit-for-bit verified against SAN_E_321_1100_0000_0000.BIN.
- Recalculates 32-bit unsigned SUM= for Section 1 and Section 2.
- Formats official 96-byte ASCII headers.
- Re-scrambles container via inverse 16-byte lane permutation + bitwise inversion.
- Repacks Section 1 and Section 2 binaries with verified 32-bit checksums.
"""

import sys
import os
import hashlib

# Forward permutation used during unpacking:
# plain[blk + i] = scrambled[blk + PERM16[i]] ^ 0xFF
PERM16 = [2, 0, 3, 1, 5, 7, 4, 6, 11, 10, 9, 8, 14, 12, 13, 15]

# Inverse permutation for packing:
# scrambled[blk + j] = plain[blk + INV_PERM16[j]] ^ 0xFF
INV_PERM16 = [0] * 16
for i, p in enumerate(PERM16):
    INV_PERM16[p] = i

assert INV_PERM16 == [1, 3, 0, 2, 6, 4, 7, 5, 11, 10, 9, 8, 13, 14, 12, 15]


def scramble_bytes(plain: bytes) -> bytes:
    """Scramble plain bytes using 16-byte block inverse permutation + XOR 0xFF."""
    assert len(plain) % 16 == 0, f"Length {len(plain)} must be a multiple of 16"
    out = bytearray(len(plain))
    inv = INV_PERM16
    for blk in range(0, len(plain), 16):
        for j in range(16):
            out[blk + j] = plain[blk + inv[j]] ^ 0xFF
    return bytes(out)


def unscramble_bytes(scrambled: bytes) -> bytes:
    """Unscramble scrambled bytes using 16-byte block forward permutation + XOR 0xFF."""
    assert len(scrambled) % 16 == 0, f"Length {len(scrambled)} must be a multiple of 16"
    out = bytearray(len(scrambled))
    perm = PERM16
    for blk in range(0, len(scrambled), 16):
        for i in range(16):
            out[blk + i] = scrambled[blk + perm[i]] ^ 0xFF
    return bytes(out)


def calc_byte_sum(data: bytes) -> int:
    """Calculate the 32-bit unsigned byte sum as expected by the camera bootloader."""
    return sum(data) & 0xFFFFFFFF


def format_header_s1(length: int, byte_sum: int, ver: str = "v155-77", dvr: int = 77) -> bytes:
    """Format 96-byte ASCII header for Section 1."""
    hdr_str = f"LENGTH={length} SG155 VER={ver} DVR={dvr} SUM={byte_sum} NDATA\r\n"
    hdr_bytes = hdr_str.encode("ascii")
    assert len(hdr_bytes) <= 96, f"Header too long ({len(hdr_bytes)} bytes)"
    return hdr_bytes.ljust(96, b" ")


def format_header_s2(length: int, byte_sum: int, ver: str = "v155-77", dvr: int = 77) -> bytes:
    """Format 96-byte ASCII header for Section 2."""
    hdr_str = f"NDATA LENGTH={length} SG155 VER={ver} DVR={dvr} SUM={byte_sum}\r\n"
    hdr_bytes = hdr_str.encode("ascii")
    assert len(hdr_bytes) <= 96, f"Header too long ({len(hdr_bytes)} bytes)"
    return hdr_bytes.ljust(96, b" ")


def assemble_container(s1_data: bytes, s2_data: bytes) -> bytes:
    """Assemble the unscrambled container with headers and padding."""
    s1_sum = calc_byte_sum(s1_data)
    s2_sum = calc_byte_sum(s2_data)

    s1_hdr = format_header_s1(len(s1_data), s1_sum)
    s2_hdr = format_header_s2(len(s2_data), s2_sum)

    plain = bytearray()
    plain.extend(s1_hdr)
    plain.extend(s1_data)
    plain.extend(s2_hdr)
    plain.extend(s2_data)

    # Pad with zeroes to 16-byte boundary if needed
    rem = len(plain) % 16
    if rem != 0:
        plain.extend(b"\x00" * (16 - rem))

    return bytes(plain)


def pack_firmware_file(s1_path: str, s2_path: str, out_scrambled_path: str, out_unscrambled_path: str = None):
    """Read Section 1 & Section 2 from disk, assemble, scramble, and write output."""
    with open(s1_path, "rb") as f:
        s1_data = f.read()
    with open(s2_path, "rb") as f:
        s2_data = f.read()

    s1_sum = calc_byte_sum(s1_data)
    s2_sum = calc_byte_sum(s2_data)
    print(f"[*] Section 1: {len(s1_data):,} bytes, byte-sum: {s1_sum} (0x{s1_sum:08x})")
    print(f"[*] Section 2: {len(s2_data):,} bytes, byte-sum: {s2_sum} (0x{s2_sum:08x})")

    container = assemble_container(s1_data, s2_data)
    print(f"[*] Unscrambled container size: {len(container):,} bytes ({len(container)//16:,} blocks)")

    if out_unscrambled_path:
        with open(out_unscrambled_path, "wb") as f:
            f.write(container)
        print(f"[+] Wrote unscrambled container to {out_unscrambled_path}")

    scrambled = scramble_bytes(container)
    with open(out_scrambled_path, "wb") as f:
        f.write(scrambled)
    print(f"[+] Wrote scrambled firmware to {out_scrambled_path} ({len(scrambled):,} bytes)")
    return scrambled


def test_roundtrip():
    """Verify bit-for-bit roundtrip on the official firmware."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    fw_dir = os.path.join(base_dir, "firmware")
    orig_path = os.path.join(fw_dir, "SAN_E_321_1100_0000_0000.BIN")
    s1_path = os.path.join(fw_dir, "sp550uz_v1.1_section1_code.bin")
    s2_path = os.path.join(fw_dir, "sp550uz_v1.1_section2_ndata.bin")

    print("=== Testing Bit-for-Bit Roundtrip on Official Firmware ===")
    with open(orig_path, "rb") as f:
        orig_bytes = f.read()

    test_out = os.path.join(fw_dir, "SAN_E_321_1100_ROUNDTRIP_TEST.BIN")
    repacked = pack_firmware_file(s1_path, s2_path, test_out)

    assert len(repacked) == len(orig_bytes), f"Size mismatch: {len(repacked)} vs {len(orig_bytes)}"

    orig_sha = hashlib.sha256(orig_bytes).hexdigest()
    repack_sha = hashlib.sha256(repacked).hexdigest()

    print(f"Original SHA-256: {orig_sha}")
    print(f"Repacked SHA-256: {repack_sha}")

    if orig_sha == repack_sha:
        print("[SUCCESS] PERFECT 100% BIT-FOR-BIT MATCH TO OFFICIAL OLYMPUS BINARY!")
        if os.path.exists(test_out):
            os.remove(test_out)
        return True
    else:
        diffs = [i for i in range(len(orig_bytes)) if orig_bytes[i] != repacked[i]]
        print(f"[FAIL] {len(diffs)} byte differences found! First 10 diffs: {diffs[:10]}")
        return False


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_roundtrip()
    elif len(sys.argv) >= 4:
        pack_firmware_file(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        test_roundtrip()
