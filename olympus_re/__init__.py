"""
Olympus SP-550UZ Reverse Engineering & Decompilation Framework
Platform: Sanyo SG155 / TruePic III (ARMv5TE)
"""

import builtins
import sys

__version__ = "1.0.0"

# Expose package object in builtins for test harnesses referencing olympus_re directly
builtins.olympus_re = sys.modules[__name__]

from olympus_re.models.memory_map import TruePicIIIMemoryMap, MemoryDomain, MemoryPermission
from olympus_re.models.symbols import Symbol, Function, JumpTable, LiteralPoolEntry, MMIORegister
