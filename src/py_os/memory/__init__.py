"""Memory subsystem — physical allocation, virtual memory, and swap.

Re-exports public symbols so callers can write::

    from py_os.memory import MemoryManager, VirtualMemory
"""

from py_os.memory.manager import MemoryManager, OutOfMemoryError
from py_os.memory.mmap import MmapError, MmapRegion
from py_os.memory.swap import (
    ClockPolicy,
    FIFOPolicy,
    LRUPolicy,
    Pager,
    ReplacementPolicy,
    SwapSpace,
)
from py_os.memory.virtual import PageFaultError, PageTable, VirtualMemory

__all__ = [
    "ClockPolicy",
    "FIFOPolicy",
    "LRUPolicy",
    "MemoryManager",
    "MmapError",
    "MmapRegion",
    "OutOfMemoryError",
    "PageFaultError",
    "PageTable",
    "Pager",
    "ReplacementPolicy",
    "SwapSpace",
    "VirtualMemory",
]
