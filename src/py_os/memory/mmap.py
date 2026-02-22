"""Memory-mapped files — map filesystem data into virtual address space.

In a real OS, ``mmap()`` lets a process treat a file's contents as if
they were ordinary memory.  Instead of calling ``read()`` and
``write()`` syscalls, the process just reads and writes memory
addresses — the OS handles moving data between the file and RAM
behind the scenes.

Two modes:
    - **MAP_PRIVATE** — the process gets its own copy.  Writes stay
      local and are never written back to the file.
    - **MAP_SHARED** — multiple processes share the same physical
      frames.  Writes by one process are visible to the others, and
      ``msync`` writes dirty data back to the underlying file.
"""

from dataclasses import dataclass


class MmapError(Exception):
    """Raise when a memory-mapping operation fails."""


@dataclass(frozen=True)
class MmapRegion:
    """Describe one memory-mapped region within a process's address space.

    Frozen so that once a mapping is established, its parameters cannot
    be accidentally mutated — unmapping and re-mapping is required to
    change them.
    """

    path: str
    """Filesystem path of the mapped file."""

    inode_number: int
    """Inode number — used as the shared-frame cache key."""

    start_vpn: int
    """First virtual page number in this mapping."""

    num_pages: int
    """Number of virtual pages the mapping spans."""

    offset: int
    """Byte offset into the file where the mapping starts."""

    length: int
    """Number of bytes mapped (may be less than num_pages * page_size)."""

    shared: bool
    """True for MAP_SHARED, False for MAP_PRIVATE."""
