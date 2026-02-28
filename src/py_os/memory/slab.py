"""Slab allocator — fixed-size object pools backed by physical frames.

The frame-based memory manager (``manager.py``) allocates *whole frames*
(256 bytes each).  Kernel objects like PCBs, inodes, and semaphore structs
are much smaller — allocating a full frame for each one wastes space.

A **slab allocator** pre-divides frames into equal-sized slots for a
specific object type, giving O(1) allocation/deallocation with zero
internal fragmentation.

Architecture (three levels):

- ``Slab`` — one physical frame divided into equal-sized slots.
- ``SlabCache`` — a pool of slabs for one object size (auto-grows).
- ``SlabAllocator`` — a registry of named caches backed by a
  ``MemoryManager``.

In real kernels (Linux ``mm/slab.c``), the slab allocator sits *above*
the page allocator and *below* ``kmalloc``.  Our design mirrors this
layering: ``MemoryManager`` provides raw frames, and ``SlabAllocator``
provides fine-grained slots.
"""

from collections.abc import Callable
from typing import Any

from py_os.memory.manager import MemoryManager


class SlabError(Exception):
    """Raise when a slab operation fails."""


class Slab:
    """One physical frame divided into equal-sized object slots.

    The slab owns a ``bytearray`` of ``page_size`` bytes (the frame's
    backing storage) and tracks which slots are free using a stack.
    Allocation pops from the stack (O(1)); deallocation pushes (O(1)).
    """

    def __init__(self, *, frame: int, obj_size: int, page_size: int) -> None:
        """Create a slab backed by a single frame.

        Args:
            frame: Physical frame number backing this slab.
            obj_size: Bytes per object slot.
            page_size: Total bytes in the frame.

        """
        self._frame = frame
        self._obj_size = obj_size
        self._capacity = page_size // obj_size
        self._storage = bytearray(page_size)
        # Free list: stack of free slot indices (all free initially)
        self._free: list[int] = list(range(self._capacity - 1, -1, -1))
        # Track which slots are currently allocated
        self._allocated: set[int] = set()

    @property
    def frame(self) -> int:
        """Return the physical frame number backing this slab."""
        return self._frame

    @property
    def capacity(self) -> int:
        """Return the total number of slots in this slab."""
        return self._capacity

    @property
    def used_count(self) -> int:
        """Return the number of currently allocated slots."""
        return len(self._allocated)

    @property
    def is_full(self) -> bool:
        """Return True if all slots are allocated."""
        return len(self._free) == 0

    @property
    def is_empty(self) -> bool:
        """Return True if no slots are allocated."""
        return len(self._allocated) == 0

    def allocate(self) -> int:
        """Pop a free slot index and mark it as allocated.

        Returns:
            The slot index.

        Raises:
            SlabError: If the slab is full.

        """
        if not self._free:
            msg = f"Slab for frame {self._frame} is full"
            raise SlabError(msg)
        slot = self._free.pop()
        self._allocated.add(slot)
        return slot

    def free(self, slot: int) -> None:
        """Return a slot to the free list.

        Args:
            slot: The slot index to free.

        Raises:
            SlabError: If the slot is not currently allocated.

        """
        if slot not in self._allocated:
            msg = f"Slot {slot} is not allocated in slab for frame {self._frame}"
            raise SlabError(msg)
        self._allocated.discard(slot)
        self._free.append(slot)

    def _validate_slot(self, slot: int) -> None:
        """Raise SlabError if slot is out of range."""
        if slot < 0 or slot >= self._capacity:
            msg = f"Slot {slot} out of range (capacity {self._capacity})"
            raise SlabError(msg)

    def read(self, slot: int) -> bytes:
        """Return the bytes stored in a slot.

        Args:
            slot: The slot index to read.

        Returns:
            A bytes object of length ``obj_size``.

        Raises:
            SlabError: If slot is out of range.

        """
        self._validate_slot(slot)
        start = slot * self._obj_size
        return bytes(self._storage[start : start + self._obj_size])

    def write(self, slot: int, data: bytes) -> None:
        """Write data into a slot.

        Args:
            slot: The slot index to write to.
            data: The bytes to write (must be <= obj_size).

        Raises:
            SlabError: If slot is out of range or data exceeds obj_size.

        """
        self._validate_slot(slot)
        if len(data) > self._obj_size:
            msg = f"Data ({len(data)} bytes) exceeds slot size ({self._obj_size} bytes)"
            raise SlabError(msg)
        start = slot * self._obj_size
        self._storage[start : start + len(data)] = data


class SlabCache:
    """Pool of slabs for one fixed object size.

    A cache starts with zero slabs and auto-grows by requesting new
    frames from a callback whenever all existing slabs are full.  The
    callback is provided by the ``SlabAllocator`` and ultimately calls
    ``MemoryManager.allocate_one()``.
    """

    # Type alias for the allocator callback
    type _AllocatorFn = Callable[[], tuple[int, bytearray]]

    def __init__(
        self,
        *,
        name: str,
        obj_size: int,
        allocator_fn: _AllocatorFn,
        page_size: int,
    ) -> None:
        """Create a slab cache for objects of the given size.

        Args:
            name: Cache name (e.g. "pcb", "inode").
            obj_size: Bytes per object.
            allocator_fn: Callback returning ``(frame, storage)`` to
                back a new slab.
            page_size: Frame size in bytes.

        """
        self._name = name
        self._obj_size = obj_size
        self._slabs: list[Slab] = []
        self._allocator_fn = allocator_fn
        self._page_size = page_size

    @property
    def name(self) -> str:
        """Return the cache name."""
        return self._name

    @property
    def obj_size(self) -> int:
        """Return the object size in bytes."""
        return self._obj_size

    @property
    def slab_count(self) -> int:
        """Return the number of slabs in this cache."""
        return len(self._slabs)

    def allocate(self) -> tuple[int, int]:
        """Allocate a slot from the cache, auto-growing if needed.

        Returns:
            ``(slab_index, slot_index)`` identifying the allocated slot.

        """
        # Prefer a partial (non-full) slab
        for i, slab in enumerate(self._slabs):
            if not slab.is_full:
                slot = slab.allocate()
                return (i, slot)
        # All slabs are full (or none exist) — grow
        return self._grow_and_allocate()

    def _grow_and_allocate(self) -> tuple[int, int]:
        """Allocate a new frame, create a slab, and allocate from it."""
        frame, _storage = self._allocator_fn()
        slab = Slab(frame=frame, obj_size=self._obj_size, page_size=self._page_size)
        self._slabs.append(slab)
        slab_idx = len(self._slabs) - 1
        slot = slab.allocate()
        return (slab_idx, slot)

    def free(self, slab_index: int, slot_index: int) -> None:
        """Free a slot back to its slab.

        Args:
            slab_index: Index of the slab within this cache.
            slot_index: Index of the slot within the slab.

        Raises:
            SlabError: If the slab index is out of range.

        """
        if slab_index < 0 or slab_index >= len(self._slabs):
            msg = f"Invalid slab index {slab_index} (cache '{self._name}' has {len(self._slabs)} slabs)"
            raise SlabError(msg)
        self._slabs[slab_index].free(slot_index)

    def _validate_slab_index(self, slab_index: int) -> None:
        """Raise SlabError if slab_index is out of range."""
        if slab_index < 0 or slab_index >= len(self._slabs):
            msg = f"Invalid slab index {slab_index} (cache '{self._name}' has {len(self._slabs)} slabs)"
            raise SlabError(msg)

    def read(self, slab_index: int, slot_index: int) -> bytes:
        """Read data from a slot.

        Args:
            slab_index: Index of the slab.
            slot_index: Index of the slot.

        Returns:
            The bytes stored in the slot.

        Raises:
            SlabError: If slab or slot index is out of range.

        """
        self._validate_slab_index(slab_index)
        return self._slabs[slab_index].read(slot_index)

    def write(self, slab_index: int, slot_index: int, data: bytes) -> None:
        """Write data to a slot.

        Args:
            slab_index: Index of the slab.
            slot_index: Index of the slot.
            data: The bytes to write.

        Raises:
            SlabError: If slab or slot index is out of range.

        """
        self._validate_slab_index(slab_index)
        self._slabs[slab_index].write(slot_index, data)

    def stats(self) -> dict[str, Any]:
        """Return usage statistics for this cache.

        Returns:
            Dict with name, obj_size, total_slabs, total_slots,
            used_slots, and free_slots.

        """
        total_slots = sum(s.capacity for s in self._slabs)
        used_slots = sum(s.used_count for s in self._slabs)
        return {
            "name": self._name,
            "obj_size": self._obj_size,
            "total_slabs": len(self._slabs),
            "total_slots": total_slots,
            "used_slots": used_slots,
            "free_slots": total_slots - used_slots,
        }

    def frames(self) -> list[int]:
        """Return the frame numbers backing all slabs in this cache."""
        return [slab.frame for slab in self._slabs]


class SlabAllocator:
    """Registry of named slab caches backed by physical frames.

    The allocator is the top-level interface.  It owns a reference to
    the ``MemoryManager`` and creates a frame-allocation callback for
    each cache that charges frames to the kernel PID.
    """

    def __init__(
        self,
        *,
        memory: MemoryManager,
        page_size: int,
        kernel_pid: int,
    ) -> None:
        """Create a slab allocator backed by a memory manager.

        Args:
            memory: The physical memory manager to request frames from.
            page_size: Frame size in bytes.
            kernel_pid: PID to charge frame allocations to.

        """
        self._memory = memory
        self._page_size = page_size
        self._kernel_pid = kernel_pid
        self._caches: dict[str, SlabCache] = {}

    def create_cache(self, name: str, *, obj_size: int) -> SlabCache:
        """Register a new slab cache.

        Args:
            name: Unique cache name.
            obj_size: Bytes per object slot.

        Returns:
            The newly created SlabCache.

        Raises:
            SlabError: If the name already exists or obj_size is invalid.

        """
        if name in self._caches:
            msg = f"Cache '{name}' already exists"
            raise SlabError(msg)
        if obj_size <= 0 or obj_size > self._page_size:
            msg = f"obj_size must be between 1 and {self._page_size}, got {obj_size}"
            raise SlabError(msg)

        mm = self._memory
        pid = self._kernel_pid
        ps = self._page_size

        def _alloc() -> tuple[int, bytearray]:
            frame = mm.allocate_one(pid)
            return (frame, bytearray(ps))

        cache = SlabCache(
            name=name,
            obj_size=obj_size,
            allocator_fn=_alloc,
            page_size=self._page_size,
        )
        self._caches[name] = cache
        return cache

    def _get_cache(self, name: str) -> SlabCache:
        """Look up a cache by name or raise.

        Args:
            name: The cache name.

        Returns:
            The SlabCache.

        Raises:
            SlabError: If the cache is not found.

        """
        cache = self._caches.get(name)
        if cache is None:
            msg = f"Cache '{name}' not found"
            raise SlabError(msg)
        return cache

    def allocate(self, cache_name: str) -> tuple[str, int, int]:
        """Allocate an object slot from a named cache.

        Args:
            cache_name: The cache to allocate from.

        Returns:
            ``(cache_name, slab_index, slot_index)``.

        Raises:
            SlabError: If the cache is not found.

        """
        cache = self._get_cache(cache_name)
        slab_idx, slot_idx = cache.allocate()
        return (cache_name, slab_idx, slot_idx)

    def free(self, cache_name: str, slab_index: int, slot_index: int) -> None:
        """Free an object slot back to a named cache.

        Args:
            cache_name: The cache name.
            slab_index: The slab index.
            slot_index: The slot index.

        """
        cache = self._get_cache(cache_name)
        cache.free(slab_index, slot_index)

    def read(self, cache_name: str, slab_index: int, slot_index: int) -> bytes:
        """Read data from an object slot.

        Args:
            cache_name: The cache name.
            slab_index: The slab index.
            slot_index: The slot index.

        Returns:
            The bytes stored in the slot.

        """
        cache = self._get_cache(cache_name)
        return cache.read(slab_index, slot_index)

    def write(self, cache_name: str, slab_index: int, slot_index: int, data: bytes) -> None:
        """Write data to an object slot.

        Args:
            cache_name: The cache name.
            slab_index: The slab index.
            slot_index: The slot index.
            data: The bytes to write.

        """
        cache = self._get_cache(cache_name)
        cache.write(slab_index, slot_index, data)

    def info(self) -> dict[str, dict[str, Any]]:
        """Return stats for all registered caches.

        Returns:
            Dict mapping cache name to its stats dict.

        """
        return {name: cache.stats() for name, cache in self._caches.items()}

    def destroy_cache(self, name: str) -> None:
        """Remove a cache and free its backing frames.

        Args:
            name: The cache to destroy.

        Raises:
            SlabError: If the cache is not found.

        """
        cache = self._get_cache(name)
        # Free all backing frames back to the memory manager
        for frame in cache.frames():
            self._memory.decrement_refcount(frame)
        del self._caches[name]
