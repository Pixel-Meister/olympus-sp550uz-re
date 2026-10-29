"""
olympus_re/analysis/disassembler.py - Pure ARM Capstone Streaming Disassembler
"""

import io
from pathlib import Path
from typing import Generator, Iterator, Optional, Union
import capstone


class ArmDisassembler:
    """High-performance Capstone disassembler wrapper for ARMv5TE (32-bit Little-Endian)."""

    CHUNK_SIZE = 65536  # 64 KB, strictly divisible by 4

    def __init__(self, detail: bool = False, skipdata: bool = True):
        self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self._md.detail = detail
        self._md.skipdata = skipdata

    @property
    def is_thumb_allowed(self) -> bool:
        """Enforces pure 32-bit ARM instruction mode; Thumb mode is strictly prohibited."""
        return False

    def disassemble(self, code: bytes, base_address: int) -> Iterator[capstone.CsInsn]:
        """Disassemble contiguous bytes in memory at given base address."""
        if base_address % 4 != 0:
            raise ValueError(
                f"Unaligned instruction offset: base_address 0x{base_address:08X} "
                "must be 4-byte aligned for pure ARM mode."
            )
        if len(code) < 4:
            return iter(())
        return self._md.disasm(code, base_address)

    def disassemble_stream(
        self,
        stream_or_path: Union[io.BufferedIOBase, bytes, Path, str],
        base_address: int = 0x40000000,
        chunk_size: int = CHUNK_SIZE,
    ) -> Generator[capstone.CsInsn, None, None]:
        """Stream disassembly over a large binary in chunks to minimize memory consumption."""
        if base_address % 4 != 0:
            raise ValueError(
                f"Unaligned instruction offset: base_address 0x{base_address:08X} "
                "must be 4-byte aligned for pure ARM mode."
            )
        if chunk_size % 4 != 0:
            raise ValueError("chunk_size must be a multiple of 4 bytes.")

        if isinstance(stream_or_path, (str, Path)):
            with open(stream_or_path, "rb") as f:
                yield from self._stream_file(f, base_address, chunk_size)
        elif isinstance(stream_or_path, bytes):
            stream = io.BytesIO(stream_or_path)
            yield from self._stream_file(stream, base_address, chunk_size)
        else:
            yield from self._stream_file(stream_or_path, base_address, chunk_size)

    def _stream_file(
        self, stream: io.BufferedIOBase, base_address: int, chunk_size: int
    ) -> Generator[capstone.CsInsn, None, None]:
        current_addr = base_address
        while True:
            chunk = stream.read(chunk_size)
            if not chunk or len(chunk) < 4:
                break
            aligned_len = len(chunk) - (len(chunk) % 4)
            for insn in self._md.disasm(chunk[:aligned_len], current_addr):
                yield insn
            current_addr += aligned_len

    def decode_instruction(self, code: bytes, address: int) -> Optional[capstone.CsInsn]:
        """Decode a single 4-byte instruction at address."""
        if address % 4 != 0 or len(code) < 4:
            return None
        insns = list(self._md.disasm(code[:4], address))
        return insns[0] if insns else None
