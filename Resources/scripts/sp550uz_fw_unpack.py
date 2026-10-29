#!/usr/bin/env python3
"""
SP-550UZ (SG155) firmware container unscrambler / splitter.

Container obfuscation (discovered empirically, 2026-10-25):
  - Every byte is inverted (XOR 0xFF).
  - Within each aligned 16-byte block, bytes are permuted:
        out[i] = in[PERM16[i]] ^ 0xFF
    PERM16 = [2,0,3,1, 5,7,4,6, 11,10,9,8, 14,12,13,15]

Unscrambled layout:
  0x000000  96-byte ASCII header "LENGTH=4149416 SG155 VER=v155-77 DVR=77 SUM=445413452\r\n" + spaces
  0x000060  Section 1 "NPROG" (ARM code, 4,149,416 B, starts with ARM branch 0xEA0001FE)
  0x3F5108  96-byte ASCII header "NDATA LENGTH=4589568 SG155 VER=v155-77 DVR=77 SUM=480118548\r\n"
  0x3F5168  Section 2 "NDATA" (4,589,568 B, resource data; byte-sum matches SUM= exactly)
  0x855968  8 bytes padding

Usage: sp550uz_fw_unpack.py [input.BIN] [output_dir]
"""
import os
import re
import sys

PERM16 = [2, 0, 3, 1, 5, 7, 4, 6, 11, 10, 9, 8, 14, 12, 13, 15]


def unscramble(data: bytes) -> bytes:
    pad = (-len(data)) % 16
    data = data + b"\xff" * pad
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        blk = data[off:off + 16]
        for i in range(16):
            out[off + i] = blk[PERM16[i]] ^ 0xFF
    return bytes(out[:len(out) - pad] if pad else out)


def parse_header(h: bytes) -> dict:
    txt = h.decode("latin1")
    return {k: v for k, v in re.findall(r"([A-Z]+)=(\S+)", txt)}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/justin/Dev/olympus/Resources/firmware/SAN_E_321_1100_0000_0000.BIN"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(src)

    raw = open(src, "rb").read()
    u = unscramble(raw)
    open(os.path.join(out_dir, "SAN_E_321_1100_unscrambled.bin"), "wb").write(u)

    h1 = parse_header(u[0:0x60])
    len1 = int(h1["LENGTH"])
    s1 = u[0x60:0x60 + len1]
    h2_off = 0x60 + len1
    # 16 bytes of trailer/marker (de c0 ad 0b ...) precede the NDATA header
    h2_off = u.find(b"NDATA LENGTH=", h2_off)
    h2 = parse_header(u[h2_off:h2_off + 0x60])
    len2 = int(h2["LENGTH"])
    s2 = u[h2_off + 0x60:h2_off + 0x60 + len2]

    open(os.path.join(out_dir, "sp550uz_v1.1_section1_code.bin"), "wb").write(s1)
    open(os.path.join(out_dir, "sp550uz_v1.1_section2_ndata.bin"), "wb").write(s2)

    print("Header 1:", h1, "| sum calc:", sum(s1))
    print("Header 2:", h2, "@0x%x | sum calc:" % h2_off, sum(s2))


if __name__ == "__main__":
    main()
