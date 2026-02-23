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

import contextlib
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
        self._refcounts: dict[int, int] = {}

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

    def refcount(self, frame: int) -> int:
        """Return the reference count for a physical frame.

        Args:
            frame: The physical frame number.

        Returns:
            The number of processes sharing this frame (0 if unallocated).

        """
        return self._refcounts.get(frame, 0)

    def increment_refcount(self, frame: int) -> None:
        """Bump the reference count for a frame by 1.

        Args:
            frame: The physical frame number.

        Raises:
            ValueError: If the frame is not currently allocated.

        """
        if frame not in self._refcounts:
            msg = f"Frame {frame} is not allocated"
            raise ValueError(msg)
        self._refcounts[frame] += 1

    def decrement_refcount(self, frame: int) -> None:
        """Drop the reference count for a frame by 1.

        If the count reaches 0 the frame is returned to the free pool
        and the refcount entry is deleted.

        Args:
            frame: The physical frame number.

        """
        count = self._refcounts.get(frame, 0)
        if count <= 1:
            self._refcounts.pop(frame, None)
            self._free.add(frame)
        else:
            self._refcounts[frame] = count - 1

    def allocate_one(self, pid: int) -> int:
        """Pop one frame from the free pool and assign it to a process.

        Sets the frame's refcount to 1 and appends it to the process's
        page table.

        Args:
            pid: The process receiving the frame.

        Returns:
            The allocated frame number.

        Raises:
            OutOfMemoryError: If no frames are free.

        """
        if not self._free:
            msg = f"Cannot allocate 1 frame for PID {pid}: 0 free"
            raise OutOfMemoryError(msg)
        frame = self._free.pop()
        self._refcounts[frame] = 1
        self._page_tables[pid].append(frame)
        return frame

    def share_frame(self, *, pid: int, frame: int) -> None:
        """Record a frame in a process's page table without touching the free pool.

        The caller is responsible for incrementing the refcount first.

        Args:
            pid: The process that will share the frame.
            frame: The physical frame number to share.

        """
        self._page_tables[pid].append(frame)

    def unshare_frame(self, *, pid: int, frame: int) -> None:
        """Remove a single frame from a process's page table.

        Counterpart to ``share_frame()``.  Does NOT change refcounts —
        the caller must decrement separately.

        Args:
            pid: The process to remove the frame from.
            frame: The physical frame number to remove.

        """
        frames = self._page_tables.get(pid)
        if frames is not None:
            with contextlib.suppress(ValueError):
                frames.remove(frame)

    @property
    def shared_frame_count(self) -> int:
        """Return the number of frames currently shared (refcount > 1)."""
        return sum(1 for rc in self._refcounts.values() if rc > 1)

    def allocate(self, pid: int, *, num_pages: int) -> list[int]:
        """Allocate physical frames to a process.

        Frames are taken from the free set and appended to the process's
        page table.  Each frame's refcount is set to 1.

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
            self._refcounts[frame] = 1
            allocated.append(frame)

        self._page_tables[pid].extend(allocated)
        return allocated

    def free(self, pid: int) -> None:
        """Free all frames allocated to a process.

        Each frame's refcount is decremented.  A frame only returns to
        the free pool when its refcount reaches 0 (i.e. no other process
        still shares it).  Freeing an unknown PID is a no-op.

        Args:
            pid: The process whose memory to release.

        """
        frames = self._page_tables.pop(pid, [])
        for frame in frames:
            self.decrement_refcount(frame)
