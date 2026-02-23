"""Shared memory IPC — named memory regions for inter-process communication.

Shared memory is the fastest IPC mechanism.  Unlike pipes (streaming,
one-way) or message queues (discrete messages), shared memory lets
multiple processes read and write the same underlying bytearrays with
zero copying.  Unlike mmap (file-backed), shared memory is
**anonymous** — no associated file, identified only by name.

Think of it like a shared whiteboard in the school hallway.  Any
student can walk up and write on it, and everyone else can see what's
there instantly.  But if two students try to write at the same time,
their writing might overlap — so they need a system (like taking turns
with a semaphore).
"""

from dataclasses import dataclass, field


class SharedMemoryError(Exception):
    """Raise when a shared memory operation fails."""


@dataclass
class SharedMemorySegment:
    """Describe a named shared memory segment.

    Unlike ``MmapRegion`` (frozen), this is mutable because processes
    attach/detach and the deletion flag changes over the segment's
    lifetime.
    """

    name: str
    """Unique identifier for this segment."""

    size: int
    """Requested size in bytes."""

    num_pages: int
    """Number of physical pages (ceil(size / page_size))."""

    frames: list[int]
    """Physical frame numbers backing this segment."""

    storage: list[bytearray]
    """Backing storage — one bytearray per frame."""

    creator_pid: int
    """PID of the process that created this segment."""

    attachments: dict[int, int] = field(default_factory=lambda: {})  # noqa: PIE807
    """Map of pid → start virtual page number for each attached process."""

    marked_for_deletion: bool = False
    """True after shm_destroy is called while processes are still attached."""
