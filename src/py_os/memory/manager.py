"""Memory manager — page-based physical memory allocation.

Physical memory is divided into fixed-size **frames** (the physical
counterpart of virtual pages).  The memory manager tracks which frames
are free, allocates them to processes, and frees them on termination.

Each process gets a **page table** — a list of physical frame numbers
that represent its virtual address space.  Virtual page 0 maps to
``page_table[0]``, page 1 to ``page_table[1]``, and so on.  The
process sees contiguous memory starting at 0; the manager scatters
the frames across physical memory as needed.

Why pages instead of variable-size blocks?
    Fixed-size allocation eliminates **external fragmentation** — the
    situation where total free memory is sufficient but no single
    contiguous block is large enough.  With pages, any free frame can
    satisfy any request.

Why a free list (set) instead of a bitmap?
    A set gives O(1) membership testing and O(1) pop for allocation.
    A bitmap would be more memory-efficient at scale, but for a
    learning simulator, clarity wins.
"""

from collections import defaultdict


class OutOfMemoryError(Exception):
    """Raise when a memory allocation cannot be satisfied."""


class MemoryManager:
    """Manage physical memory frames and per-process page tables.

    The manager owns two data structures:
    - A **free set** of available frame numbers.
    - A **page table dict** mapping each PID to its list of frames.
    """

    def __init__(self, *, total_frames: int) -> None:
        """Create a memory manager with the given number of physical frames.

        Args:
            total_frames: Total number of frames in physical memory.

        """
        self._total_frames = total_frames
        self._free: set[int] = set(range(total_frames))
        self._page_tables: defaultdict[int, list[int]] = defaultdict(list)

    @property
    def total_frames(self) -> int:
        """Return the total number of physical frames."""
        return self._total_frames

    @property
    def free_frames(self) -> int:
        """Return the number of currently unallocated frames."""
        return len(self._free)

    def pages_for(self, pid: int) -> list[int]:
        """Return the list of physical frames allocated to a process.

        Args:
            pid: The process identifier.

        Returns:
            A list of frame numbers (empty if none allocated).

        """
        return list(self._page_tables[pid])

    def allocate(self, pid: int, *, num_pages: int) -> list[int]:
        """Allocate physical frames to a process.

        Frames are taken from the free set and appended to the process's
        page table.  The order of frames is implementation-defined (set
        pop order), which is fine — the page table provides the mapping.

        Args:
            pid: The process requesting memory.
            num_pages: Number of frames to allocate.

        Returns:
            The list of newly allocated frame numbers.

        Raises:
            OutOfMemoryError: If fewer than num_pages frames are free.

        """
        if num_pages > len(self._free):
            msg = f"Cannot allocate {num_pages} frames for PID {pid}: only {len(self._free)} free"
            raise OutOfMemoryError(msg)

        allocated: list[int] = []
        for _ in range(num_pages):
            frame = self._free.pop()
            allocated.append(frame)

        self._page_tables[pid].extend(allocated)
        return allocated

    def free(self, pid: int) -> None:
        """Free all frames allocated to a process.

        The frames are returned to the free set and the page table is
        cleared.  Freeing an unknown PID is a no-op (idempotent), which
        simplifies cleanup — you don't need to check before freeing.

        Args:
            pid: The process whose memory to release.

        """
        frames = self._page_tables.pop(pid, [])
        self._free.update(frames)
