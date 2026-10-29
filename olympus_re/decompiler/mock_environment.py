"""
olympus_re/decompiler/mock_environment.py - Offline Mock Decompiler Test Harness
================================================================================

Provides production-grade mock environments for Ghidra (FlatProgramAPI) and
IDA Pro (idc, idaapi, idautils) enabling headless unit testing, static analysis,
and CI validation without requiring commercial licenses or external installations.

Classes:
  - MockAddress: Emulates Ghidra Address objects.
  - MockMemoryBlock: Emulates Ghidra MemoryBlock objects.
  - MockGhidraFlatProgramAPI: Emulates Ghidra FlatProgramAPI.
  - MockIDAPython: Emulates IDA Pro idc, idaapi, and idautils modules.
  - FaultInjectingMockAPI: Facilitates simulated fault injection for error testing.

Sandboxing Utilities:
  - sandbox_ghidra_execution(script_path, api=None, extra_globals=None)
  - sandbox_ida_execution(script_path, mock_env=None, extra_globals=None)
"""

import os
from pathlib import Path
import sys
import types
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union


# ==============================================================================
# Ghidra Mock Environment
# ==============================================================================

class MockAddress:
    """Emulates Ghidra Address object supporting arithmetic and comparisons."""

    def __init__(self, offset: Union[int, str, "MockAddress"]):
        if isinstance(offset, MockAddress):
            self.offset = offset.offset
        elif isinstance(offset, str):
            clean = offset.replace("0x", "").replace("0X", "")
            self.offset = int(clean, 16)
        else:
            self.offset = int(offset)

    def getOffset(self) -> int:
        return self.offset

    def getUnsignedOffset(self) -> int:
        return self.offset & 0xFFFFFFFF

    def add(self, delta: int) -> "MockAddress":
        return MockAddress(self.offset + delta)

    def subtract(self, delta: int) -> "MockAddress":
        return MockAddress(self.offset - delta)

    def __int__(self) -> int:
        return self.offset

    def __repr__(self) -> str:
        return f"Addr(0x{self.offset:08X})"

    def __str__(self) -> str:
        return f"0x{self.offset:08x}"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, MockAddress):
            return self.offset == other.offset
        if isinstance(other, int):
            return self.offset == other
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, MockAddress):
            return self.offset < other.offset
        if isinstance(other, int):
            return self.offset < other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.offset)


class MockMemoryBlock:
    """Emulates Ghidra MemoryBlock record representing a contiguous virtual segment."""

    def __init__(
        self,
        name: str,
        start: MockAddress,
        length: int,
        r: bool = True,
        w: bool = True,
        x: bool = False,
        comment: str = "",
    ):
        self.name = name
        self.start = start if isinstance(start, MockAddress) else MockAddress(start)
        self.length = length
        self.r = bool(r)
        self.w = bool(w)
        self.x = bool(x)
        self.comment = comment

    def getStart(self) -> MockAddress:
        return self.start

    def getEnd(self) -> MockAddress:
        return MockAddress(self.start.getOffset() + max(0, self.length - 1))

    def getName(self) -> str:
        return self.name

    def getSize(self) -> int:
        return self.length

    def isRead(self) -> bool:
        return self.r

    def isWrite(self) -> bool:
        return self.w

    def isExecute(self) -> bool:
        return self.x

    def getComment(self) -> str:
        return self.comment

    def setComment(self, comment: str) -> None:
        self.comment = comment

    def contains(self, addr: Union[int, MockAddress]) -> bool:
        offset = addr.getOffset() if isinstance(addr, MockAddress) else addr
        return self.start.getOffset() <= offset <= self.getEnd().getOffset()

    def __repr__(self) -> str:
        perm = f"{'R' if self.r else '-'}{'W' if self.w else '-'}{'X' if self.x else '-'}"
        return f"MockMemoryBlock({self.name}, 0x{self.start.getOffset():08X}-0x{self.getEnd().getOffset():08X}, {perm})"


class MockGhidraFlatProgramAPI:
    """
    Mock implementation of Ghidra FlatProgramAPI.
    Captures created memory blocks, symbols, and comments for assertion verification.
    """

    def __init__(self):
        self.blocks: Dict[str, MockMemoryBlock] = {}
        self.labels: Dict[int, Dict[str, Any]] = {}
        self.plate_comments: Dict[int, str] = {}
        self.pre_comments: Dict[int, str] = {}
        self.eol_comments: Dict[int, str] = {}
        self.repeatable_comments: Dict[int, str] = {}
        self.post_comments: Dict[int, str] = {}
        self.messages: List[str] = []

    def toAddr(self, val: Any) -> MockAddress:
        """Convert int, str, or MockAddress to MockAddress instance."""
        if isinstance(val, MockAddress):
            return val
        return MockAddress(val)

    def createMemoryBlock(
        self,
        name: str,
        start: Any,
        length: int,
        r: bool = True,
        w: bool = True,
        x: bool = False,
    ) -> MockMemoryBlock:
        """Create and register a memory block, handling duplicate names gracefully."""
        addr = self.toAddr(start)
        block = MockMemoryBlock(name, addr, length, r, w, x)
        self.blocks[name] = block
        return block

    def getMemoryBlock(self, name: str) -> Optional[MockMemoryBlock]:
        return self.blocks.get(name)

    def getMemoryBlocks(self) -> List[MockMemoryBlock]:
        return list(self.blocks.values())

    def createLabel(
        self,
        addr: Any,
        name: str,
        is_primary: bool = True,
    ) -> None:
        """Create symbol label at address."""
        offset = self.toAddr(addr).getOffset()
        self.labels[offset] = {"name": name, "primary": is_primary}

    def setPlateComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.plate_comments[offset] = comment

    def setPreComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.pre_comments[offset] = comment

    def setEolComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.eol_comments[offset] = comment

    def setPostComment(self, addr: Any, comment: str) -> None:
        offset = self.toAddr(addr).getOffset()
        self.post_comments[offset] = comment

    def println(self, msg: str) -> None:
        self.messages.append(str(msg))

    def askFile(self, title: str, btn: str) -> str:
        return str(Path("output/symbols.json"))

    def askString(self, title: str, prompt: str) -> str:
        return ""


MockFlatProgramAPI = MockGhidraFlatProgramAPI  # Backward compatibility alias


# ==============================================================================
# IDA Pro Mock Environment
# ==============================================================================

class MockIDAPython:
    """
    Mock implementation of IDA Pro idc, idaapi, and idautils modules.
    Tracks created segments, symbols, repeatable comments, and function comments.
    """

    def __init__(self):
        self.segments: Dict[int, Dict[str, Any]] = {}
        self.names: Dict[int, str] = {}
        self.comments: Dict[int, str] = {}
        self.func_comments: Dict[int, str] = {}
        self.messages: List[str] = []

        # idc module
        self.idc = types.ModuleType("idc")
        self.idc.BADADDR = 0xFFFFFFFF
        self.idc.SN_CHECK = 0
        self.idc.SN_NOWARN = 1
        self.idc.SN_NOCHECK = 2
        self.idc.SN_FORCE = 0x800
        self.idc.ARGV = []
        self.idc.add_segm_ex = self._add_segm_ex
        self.idc.add_segm = self._add_segm
        self.idc.set_segm_name = self._set_segm_name
        self.idc.set_name = self._set_name
        self.idc.set_cmt = self._set_cmt
        self.idc.set_func_cmt = self._set_func_cmt
        self.idc.get_segm_name = self._get_segm_name
        self.idc.get_segm_start = self._get_segm_start
        self.idc.get_segm_end = self._get_segm_end
        self.idc.msg = self._msg

        # idaapi module
        self.idaapi = types.ModuleType("idaapi")
        self.idaapi.BADADDR = 0xFFFFFFFF
        self.idaapi.auto_wait = lambda: None
        self.idaapi.get_segm_by_name = self._get_segm_by_name
        self.idaapi.getseg = self._getseg
        self.idaapi.ask_file = lambda for_saving, mask, prompt: str(Path("output/symbols.json"))

        # idautils module
        self.idautils = types.ModuleType("idautils")
        self.idautils.Functions = lambda: iter(self.names.keys())
        self.idautils.Segments = lambda: iter(self.segments.keys())
        self.idautils.Heads = lambda startea, endea: iter([
            ea for ea in sorted(self.names.keys()) if startea <= ea < endea
        ])

    def _msg(self, text: str) -> None:
        self.messages.append(text)

    def _add_segm_ex(
        self,
        startea: int,
        endea: int,
        base: int,
        use32: int,
        align: int,
        comb: int,
        perm: int,
    ) -> int:
        self.segments[startea] = {
            "start": startea,
            "end": endea,
            "base": base,
            "use32": use32,
            "align": align,
            "comb": comb,
            "perm": perm,
            "name": f"seg_{startea:08X}",
        }
        return 1

    def _add_segm(
        self,
        startea: int,
        endea: int,
        base: int,
        use32: int,
        align: int,
        comb: int,
    ) -> int:
        return self._add_segm_ex(startea, endea, base, use32, align, comb, 7)

    def _set_segm_name(self, ea: int, name: str) -> int:
        if ea in self.segments:
            self.segments[ea]["name"] = name
            return 1
        return 0

    def _set_name(self, ea: int, name: str, flags: int = 0) -> int:
        self.names[ea] = name
        return 1

    def _set_cmt(self, ea: int, comm: str, rpt: int = 0) -> int:
        self.comments[ea] = comm
        return 1

    def _set_func_cmt(self, ea: int, cmt: str, rpt: int = 0) -> int:
        self.func_comments[ea] = cmt
        return 1

    def _get_segm_name(self, ea: int) -> str:
        if ea in self.segments:
            return self.segments[ea].get("name", "")
        return ""

    def _get_segm_start(self, ea: int) -> int:
        if ea in self.segments:
            return self.segments[ea]["start"]
        return 0xFFFFFFFF

    def _get_segm_end(self, ea: int) -> int:
        if ea in self.segments:
            return self.segments[ea]["end"]
        return 0xFFFFFFFF

    def _get_segm_by_name(self, name: str) -> Optional[int]:
        for ea, seg in self.segments.items():
            if seg.get("name") == name:
                return ea
        return None

    def _getseg(self, ea: int) -> Optional[Dict[str, Any]]:
        for startea, seg in self.segments.items():
            if startea <= ea < seg["end"]:
                return seg
        return None

    # Public direct methods mirroring MockIDAPython in tests/support.py
    def add_segm_ex(
        self, startea: int, endea: int, base: int, use32: int, align: int, comb: int, perm: int
    ) -> int:
        return self._add_segm_ex(startea, endea, base, use32, align, comb, perm)

    def set_name(self, ea: int, name: str, flags: int = 0) -> int:
        return self._set_name(ea, name, flags)

    def set_cmt(self, ea: int, comm: str, rpt: int = 0) -> int:
        return self._set_cmt(ea, comm, rpt)


MockIdaAPI = MockIDAPython  # Backward compatibility alias


# ==============================================================================
# Sandboxed Offline Execution Helpers
# ==============================================================================

def sandbox_ghidra_execution(
    script_path: Path,
    api: Optional[MockGhidraFlatProgramAPI] = None,
    extra_globals: Optional[Dict[str, Any]] = None,
) -> MockGhidraFlatProgramAPI:
    """
    Execute a Ghidra Python script within an isolated mock sandbox.
    Temporarily installs ghidra module hierarchy in sys.modules, runs the script,
    and cleanly restores sys.modules upon exit.
    """
    mock_api = api or MockGhidraFlatProgramAPI()

    ghidra_mod = types.ModuleType("ghidra")
    ghidra_app = types.ModuleType("ghidra.app")
    ghidra_app_script = types.ModuleType("ghidra.app.script")
    ghidra_app_script.GhidraScript = object
    ghidra_prog = types.ModuleType("ghidra.program")
    ghidra_prog_model = types.ModuleType("ghidra.program.model")
    ghidra_prog_addr = types.ModuleType("ghidra.program.model.address")
    ghidra_prog_addr.Address = MockAddress

    saved_modules = dict(sys.modules)
    try:
        sys.modules["ghidra"] = ghidra_mod
        sys.modules["ghidra.app"] = ghidra_app
        sys.modules["ghidra.app.script"] = ghidra_app_script
        sys.modules["ghidra.program"] = ghidra_prog
        sys.modules["ghidra.program.model"] = ghidra_prog_model
        sys.modules["ghidra.program.model.address"] = ghidra_prog_addr

        with open(script_path, "r", encoding="utf-8") as f:
            code_text = f.read()

        sandbox = {
            "__file__": str(script_path),
            "__name__": "__main__",
            "currentProgram": None,
            "createMemoryBlock": mock_api.createMemoryBlock,
            "createLabel": mock_api.createLabel,
            "setPlateComment": mock_api.setPlateComment,
            "setPreComment": mock_api.setPreComment,
            "setEolComment": mock_api.setEolComment,
            "toAddr": mock_api.toAddr,
            "println": mock_api.println,
            "askFile": mock_api.askFile,
            "askString": mock_api.askString,
        }
        if extra_globals:
            sandbox.update(extra_globals)

        exec(compile(code_text, str(script_path), "exec"), sandbox)
        return mock_api
    finally:
        sys.modules.clear()
        sys.modules.update(saved_modules)


def sandbox_ida_execution(
    script_path: Path,
    mock_env: Optional[MockIDAPython] = None,
    extra_globals: Optional[Dict[str, Any]] = None,
) -> MockIDAPython:
    """
    Execute an IDA Pro IDAPython script within an isolated mock sandbox.
    Temporarily installs idc, idaapi, and idautils modules in sys.modules, runs the script,
    and cleanly restores sys.modules upon exit.
    """
    env = mock_env or MockIDAPython()

    saved_modules = dict(sys.modules)
    try:
        sys.modules["idc"] = env.idc
        sys.modules["idaapi"] = env.idaapi
        sys.modules["idautils"] = env.idautils

        with open(script_path, "r", encoding="utf-8") as f:
            code_text = f.read()

        sandbox = {
            "__file__": str(script_path),
            "__name__": "__main__",
        }
        if extra_globals:
            sandbox.update(extra_globals)

        exec(compile(code_text, str(script_path), "exec"), sandbox)
        return env
    finally:
        sys.modules.clear()
        sys.modules.update(saved_modules)


# ==============================================================================
# Simulated Fault Injection Mock API
# ==============================================================================

class FaultInjectingMockAPI(MockGhidraFlatProgramAPI):
    """
    Mock API providing configurable fault injection for testing error handling
    (e.g., simulating API failures as tested in test_tier2_boundaries.py).
    """

    def __init__(self, fail_methods: Optional[Set[str]] = None, exception_type: Any = RuntimeError):
        super().__init__()
        self.fail_methods: Set[str] = fail_methods or set()
        self.exception_type = exception_type

    def createLabel(self, *args, **kwargs):
        if "createLabel" in self.fail_methods:
            raise self.exception_type("Simulated API fault: createLabel")
        return super().createLabel(*args, **kwargs)

    def createMemoryBlock(self, *args, **kwargs):
        if "createMemoryBlock" in self.fail_methods:
            raise self.exception_type("Simulated API fault: createMemoryBlock")
        return super().createMemoryBlock(*args, **kwargs)
