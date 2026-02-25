"""Tests for the slab allocator module.

A slab allocator sits *on top of* the frame-based memory manager and
pre-divides physical frames into equal-sized slots for a specific object
type.  This gives O(1) allocation/deallocation with zero internal
fragmentation for small kernel objects (PCBs, inodes, etc.).

Cycle 1: Slab / SlabError — single-frame slot management
Cycle 2: SlabCache — multi-slab pool for one object size
Cycle 3: SlabAllocator — registry of named caches
Cycle 4: Kernel integration
Cycle 5: Syscall integration
Cycle 6: Shell commands
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.memory.manager import MemoryManager
from py_os.memory.slab import Slab, SlabAllocator, SlabCache, SlabError
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# -- Named constants (PLR2004) ------------------------------------------------

PAGE_SIZE = 256
OBJ_SIZE_64 = 64
OBJ_SIZE_48 = 48
OBJ_SIZE_32 = 32
SLOTS_PER_64 = PAGE_SIZE // OBJ_SIZE_64  # 4
SLOTS_PER_32 = PAGE_SIZE // OBJ_SIZE_32  # 8
TOTAL_FRAMES = 16
KERNEL_PID = 0
FRAME_42 = 42
TWO_ALLOCS = 2


# ===========================================================================
# Cycle 1 — SlabError + Slab
# ===========================================================================


class TestSlabError:
    """Verify the slab error exception."""

    def test_inherits_from_exception(self) -> None:
        """SlabError should be a standard exception subclass."""
        assert issubclass(SlabError, Exception)

    def test_message_is_preserved(self) -> None:
        """The error message should be accessible via str()."""
        err = SlabError("test message")
        assert str(err) == "test message"


class TestSlab:
    """Verify a single slab — one frame divided into fixed-size slots."""

    def test_capacity_is_page_size_divided_by_obj_size(self) -> None:
        """A slab of 256 bytes with 64-byte objects should have 4 slots."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        assert slab.capacity == SLOTS_PER_64

    def test_all_slots_free_initially(self) -> None:
        """A new slab should have all slots free."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        assert slab.used_count == 0
        assert slab.is_empty

    def test_allocate_returns_slot_index(self) -> None:
        """Allocating should return a valid slot index."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slot = slab.allocate()
        assert 0 <= slot < SLOTS_PER_64

    def test_allocate_increments_used_count(self) -> None:
        """Each allocation should increment the used count."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slab.allocate()
        assert slab.used_count == 1

    def test_allocate_until_full(self) -> None:
        """Allocating all slots should make the slab full."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        for _ in range(SLOTS_PER_64):
            slab.allocate()
        assert slab.is_full
        assert slab.used_count == SLOTS_PER_64

    def test_allocate_when_full_raises(self) -> None:
        """Allocating from a full slab should raise SlabError."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        for _ in range(SLOTS_PER_64):
            slab.allocate()
        with pytest.raises(SlabError, match="full"):
            slab.allocate()

    def test_free_makes_slot_available(self) -> None:
        """Freeing a slot should decrease used count."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slot = slab.allocate()
        slab.free(slot)
        assert slab.used_count == 0
        assert slab.is_empty

    def test_free_unallocated_slot_raises(self) -> None:
        """Freeing a slot that isn't allocated should raise SlabError."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        with pytest.raises(SlabError, match="not allocated"):
            slab.free(0)

    def test_double_free_raises(self) -> None:
        """Freeing the same slot twice should raise SlabError."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slot = slab.allocate()
        slab.free(slot)
        with pytest.raises(SlabError, match="not allocated"):
            slab.free(slot)

    def test_write_and_read_roundtrip(self) -> None:
        """Data written to a slot should be readable."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slot = slab.allocate()
        data = b"hello slab"
        slab.write(slot, data)
        result = slab.read(slot)
        assert result[: len(data)] == data

    def test_read_returns_obj_size_bytes(self) -> None:
        """Read should return exactly obj_size bytes."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slot = slab.allocate()
        result = slab.read(slot)
        assert len(result) == OBJ_SIZE_64

    def test_write_oversized_data_raises(self) -> None:
        """Writing more bytes than obj_size should raise SlabError."""
        slab = Slab(frame=0, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        slot = slab.allocate()
        too_big = b"x" * (OBJ_SIZE_64 + 1)
        with pytest.raises(SlabError, match="exceeds"):
            slab.write(slot, too_big)

    def test_frame_property(self) -> None:
        """The slab should expose which frame it backs."""
        slab = Slab(frame=FRAME_42, obj_size=OBJ_SIZE_64, page_size=PAGE_SIZE)
        assert slab.frame == FRAME_42


# ===========================================================================
# Cycle 2 — SlabCache
# ===========================================================================


def _make_allocator_fn(
    mm: MemoryManager,
    page_size: int = PAGE_SIZE,
) -> tuple[MemoryManager, "SlabCache._AllocatorFn"]:
    """Build an allocator callback that requests frames from a MemoryManager."""

    def _alloc() -> tuple[int, bytearray]:
        frame = mm.allocate_one(KERNEL_PID)
        return (frame, bytearray(page_size))

    return mm, _alloc


class TestSlabCache:
    """Verify a slab cache — pool of slabs for one object size."""

    def test_create_cache_with_name_and_obj_size(self) -> None:
        """A new cache should record its name and object size."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        assert cache.name == "pcb"
        assert cache.obj_size == OBJ_SIZE_64

    def test_allocate_returns_slab_and_slot_indices(self) -> None:
        """Allocating should return (slab_index, slot_index)."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        slab_idx, slot_idx = cache.allocate()
        assert slab_idx == 0
        assert 0 <= slot_idx < SLOTS_PER_64

    def test_auto_grows_when_first_slab_full(self) -> None:
        """Allocating beyond one slab's capacity should auto-grow."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        # Fill first slab
        for _ in range(SLOTS_PER_64):
            cache.allocate()
        # Next allocation should auto-grow
        slab_idx, _slot_idx = cache.allocate()
        assert slab_idx == 1

    def test_free_makes_slot_reusable(self) -> None:
        """Freeing a slot should allow it to be re-allocated."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        slab_idx, slot_idx = cache.allocate()
        cache.free(slab_idx, slot_idx)
        # Should be able to re-allocate
        slab_idx2, slot_idx2 = cache.allocate()
        assert slab_idx2 == slab_idx
        assert slot_idx2 == slot_idx

    def test_read_write_through_cache(self) -> None:
        """Read and write should work through the cache interface."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        slab_idx, slot_idx = cache.allocate()
        cache.write(slab_idx, slot_idx, b"hello cache")
        result = cache.read(slab_idx, slot_idx)
        assert result[: len(b"hello cache")] == b"hello cache"

    def test_stats_reports_correct_counts(self) -> None:
        """Stats should reflect total/used/free slot counts."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        cache.allocate()
        cache.allocate()
        stats = cache.stats()
        assert stats["name"] == "pcb"
        assert stats["obj_size"] == OBJ_SIZE_64
        assert stats["total_slabs"] == 1
        assert stats["total_slots"] == SLOTS_PER_64
        assert stats["used_slots"] == TWO_ALLOCS
        assert stats["free_slots"] == SLOTS_PER_64 - TWO_ALLOCS

    def test_free_invalid_slab_index_raises(self) -> None:
        """Freeing with an out-of-range slab index should raise SlabError."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        with pytest.raises(SlabError, match="Invalid slab index"):
            cache.free(99, 0)

    def test_allocate_prefers_partial_slab(self) -> None:
        """Allocation should fill a partial slab before growing a new one."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        _, alloc_fn = _make_allocator_fn(mm)
        cache = SlabCache(
            name="pcb", obj_size=OBJ_SIZE_64, allocator_fn=alloc_fn, page_size=PAGE_SIZE
        )
        # Allocate 2 slots, free the first one
        s0, slot0 = cache.allocate()
        cache.allocate()
        cache.free(s0, slot0)
        # Next allocation should reuse partial slab 0
        slab_idx, _slot_idx = cache.allocate()
        assert slab_idx == 0


# ===========================================================================
# Cycle 3 — SlabAllocator
# ===========================================================================


class TestSlabAllocator:
    """Verify the top-level slab allocator registry."""

    def test_create_cache(self) -> None:
        """Creating a cache should make it available."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        cache = alloc.create_cache("pcb", obj_size=OBJ_SIZE_64)
        assert cache.name == "pcb"

    def test_create_duplicate_cache_raises(self) -> None:
        """Creating a cache with an existing name should raise SlabError."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        alloc.create_cache("pcb", obj_size=OBJ_SIZE_64)
        with pytest.raises(SlabError, match="already exists"):
            alloc.create_cache("pcb", obj_size=OBJ_SIZE_64)

    def test_create_cache_invalid_obj_size_raises(self) -> None:
        """Object size must be > 0 and <= page_size."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        with pytest.raises(SlabError, match="obj_size"):
            alloc.create_cache("zero", obj_size=0)
        with pytest.raises(SlabError, match="obj_size"):
            alloc.create_cache("huge", obj_size=PAGE_SIZE + 1)

    def test_allocate_and_free(self) -> None:
        """Allocate → free cycle should work through the allocator."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        alloc.create_cache("pcb", obj_size=OBJ_SIZE_64)
        name, slab_idx, slot_idx = alloc.allocate("pcb")
        assert name == "pcb"
        alloc.free("pcb", slab_idx, slot_idx)

    def test_allocate_unknown_cache_raises(self) -> None:
        """Allocating from an unknown cache should raise SlabError."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        with pytest.raises(SlabError, match="not found"):
            alloc.allocate("nope")

    def test_read_write_through_allocator(self) -> None:
        """Read/write should work through the top-level allocator."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        alloc.create_cache("pcb", obj_size=OBJ_SIZE_64)
        _, si, sl = alloc.allocate("pcb")
        alloc.write("pcb", si, sl, b"allocator test")
        data = alloc.read("pcb", si, sl)
        assert data[: len(b"allocator test")] == b"allocator test"

    def test_info_reports_all_caches(self) -> None:
        """Info should return stats for all registered caches."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        alloc.create_cache("pcb", obj_size=OBJ_SIZE_64)
        alloc.create_cache("inode", obj_size=OBJ_SIZE_48)
        alloc.allocate("pcb")
        info = alloc.info()
        assert "pcb" in info
        assert "inode" in info
        assert info["pcb"]["used_slots"] == 1
        assert info["inode"]["used_slots"] == 0

    def test_destroy_cache_removes_it(self) -> None:
        """Destroying a cache should remove it and free frames."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        alloc.create_cache("tmp", obj_size=OBJ_SIZE_32)
        alloc.allocate("tmp")
        free_before = mm.free_frames
        alloc.destroy_cache("tmp")
        # Frame should be returned to memory manager
        assert mm.free_frames > free_before
        with pytest.raises(SlabError, match="not found"):
            alloc.allocate("tmp")

    def test_destroy_unknown_cache_raises(self) -> None:
        """Destroying an unknown cache should raise SlabError."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        with pytest.raises(SlabError, match="not found"):
            alloc.destroy_cache("nope")


# ===========================================================================
# Cycle 4 — Kernel integration
# ===========================================================================


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


class TestSlabKernel:
    """Verify slab allocator integration with the kernel."""

    def test_kernel_has_slab_allocator_after_boot(self) -> None:
        """A booted kernel should have a slab allocator."""
        kernel = _booted_kernel()
        assert kernel.slab_allocator is not None

    def test_pre_registered_caches_exist(self) -> None:
        """Boot should pre-register 'pcb' and 'inode' caches."""
        kernel = _booted_kernel()
        assert kernel.slab_allocator is not None
        info = kernel.slab_allocator.info()
        assert "pcb" in info
        assert "inode" in info

    def test_slab_create_cache_wrapper(self) -> None:
        """Kernel wrapper should create a new slab cache."""
        kernel = _booted_kernel()
        cache = kernel.slab_create_cache("test", obj_size=OBJ_SIZE_32)
        assert cache.name == "test"

    def test_slab_alloc_and_free_wrappers(self) -> None:
        """Kernel alloc/free wrappers should delegate to the allocator."""
        kernel = _booted_kernel()
        name, si, sl = kernel.slab_alloc("pcb")
        assert name == "pcb"
        kernel.slab_free("pcb", si, sl)

    def test_slab_info_wrapper(self) -> None:
        """Kernel info wrapper should return stats dict."""
        kernel = _booted_kernel()
        info = kernel.slab_info()
        assert "pcb" in info
        assert "inode" in info

    def test_shutdown_clears_slab_allocator(self) -> None:
        """Shutting down should set slab_allocator to None."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.slab_allocator is None


# ===========================================================================
# Cycle 5 — Syscall integration
# ===========================================================================


class TestSlabSyscall:
    """Verify slab allocator syscalls."""

    def test_slab_create_syscall(self) -> None:
        """SYS_SLAB_CREATE should create a named cache."""
        kernel = _booted_kernel()
        result: dict[str, object] = kernel.syscall(
            SyscallNumber.SYS_SLAB_CREATE,
            name="test",
            obj_size=OBJ_SIZE_32,
        )
        assert result["name"] == "test"
        assert result["obj_size"] == OBJ_SIZE_32

    def test_slab_alloc_syscall(self) -> None:
        """SYS_SLAB_ALLOC should allocate from a named cache."""
        kernel = _booted_kernel()
        result: dict[str, object] = kernel.syscall(
            SyscallNumber.SYS_SLAB_ALLOC,
            cache="pcb",
        )
        assert result["cache"] == "pcb"
        assert "slab_index" in result
        assert "slot_index" in result

    def test_slab_free_syscall(self) -> None:
        """SYS_SLAB_FREE should free an allocated slot."""
        kernel = _booted_kernel()
        alloc_result: dict[str, object] = kernel.syscall(
            SyscallNumber.SYS_SLAB_ALLOC,
            cache="pcb",
        )
        kernel.syscall(
            SyscallNumber.SYS_SLAB_FREE,
            cache="pcb",
            slab_index=alloc_result["slab_index"],
            slot_index=alloc_result["slot_index"],
        )

    def test_slab_info_syscall(self) -> None:
        """SYS_SLAB_INFO should return stats for all caches."""
        kernel = _booted_kernel()
        info: dict[str, dict[str, object]] = kernel.syscall(SyscallNumber.SYS_SLAB_INFO)
        assert "pcb" in info
        assert "inode" in info

    def test_slab_create_duplicate_raises_syscall_error(self) -> None:
        """Creating a duplicate cache via syscall should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="already exists"):
            kernel.syscall(SyscallNumber.SYS_SLAB_CREATE, name="pcb", obj_size=OBJ_SIZE_64)

    def test_slab_alloc_unknown_cache_raises_syscall_error(self) -> None:
        """Allocating from unknown cache via syscall should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_SLAB_ALLOC, cache="nope")


# ===========================================================================
# Cycle 6 — Shell commands
# ===========================================================================


class TestSlabShell:
    """Verify slab allocator shell commands."""

    def test_slabcreate_creates_cache(self) -> None:
        """The slabcreate command should create and report a new cache."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("slabcreate test 32")
        assert "test" in result
        assert "32" in result

    def test_slaballoc_allocates_object(self) -> None:
        """The slaballoc command should allocate and report the location."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("slaballoc pcb")
        assert "pcb" in result
        assert "slab" in result
        assert "slot" in result

    def test_slabfree_frees_object(self) -> None:
        """The slabfree command should free a previously allocated object."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        shell.execute("slaballoc pcb")
        result = shell.execute("slabfree pcb 0 0")
        assert "Freed" in result

    def test_slabinfo_shows_all_caches(self) -> None:
        """The slabinfo command should show a table of all caches."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("slabinfo")
        assert "pcb" in result
        assert "inode" in result

    def test_slabcreate_usage_on_missing_args(self) -> None:
        """Show usage when slabcreate is called with missing args."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("slabcreate")
        assert "Usage:" in result

    def test_slaballoc_error_on_unknown_cache(self) -> None:
        """Show error when slaballoc targets an unknown cache."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("slaballoc nope")
        assert "Error:" in result

    def test_help_includes_slab_commands(self) -> None:
        """The help command should list slab commands."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "slabcreate" in result
        assert "slabinfo" in result
