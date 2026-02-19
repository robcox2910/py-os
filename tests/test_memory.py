"""Tests for the memory manager module.

The memory manager divides physical memory into fixed-size pages (frames)
and allocates them to processes.  Each process gets a page table that
maps its virtual pages to physical frames, giving the illusion of
contiguous private memory.
"""

import pytest

from py_os.memory import MemoryManager, OutOfMemoryError

TOTAL_FRAMES = 8
SMALL_ALLOCATION = 3
LARGE_ALLOCATION = 5
SINGLE_FRAME = 1


class TestMemoryManagerCreation:
    """Verify initial state of the memory manager."""

    def test_all_frames_are_free_initially(self) -> None:
        """A new memory manager should have all frames available."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        assert mm.free_frames == TOTAL_FRAMES

    def test_total_frames_is_stored(self) -> None:
        """The total number of frames should be accessible."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        assert mm.total_frames == TOTAL_FRAMES

    def test_no_allocations_initially(self) -> None:
        """No process should have any allocated frames initially."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        assert mm.pages_for(pid) == []


class TestMemoryAllocation:
    """Verify allocating frames to processes."""

    def test_allocate_reduces_free_frames(self) -> None:
        """Allocating pages should decrease the free count."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        expected_free = TOTAL_FRAMES - SMALL_ALLOCATION
        assert mm.free_frames == expected_free

    def test_allocate_returns_frame_numbers(self) -> None:
        """Allocation should return the list of assigned physical frames."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        frames = mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        assert len(frames) == SMALL_ALLOCATION

    def test_allocated_frames_are_unique(self) -> None:
        """No two allocations should receive the same physical frame."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        frames_a = mm.allocate(pid=1, num_pages=SMALL_ALLOCATION)
        frames_b = mm.allocate(pid=2, num_pages=SMALL_ALLOCATION)
        assert set(frames_a).isdisjoint(set(frames_b))

    def test_pages_for_returns_allocated_frames(self) -> None:
        """The page table should reflect what was allocated."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        frames = mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        assert mm.pages_for(pid) == frames

    def test_multiple_allocations_accumulate(self) -> None:
        """A process can request more memory over time."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        first = mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        second = mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        assert mm.pages_for(pid) == [*first, *second]

    def test_allocate_zero_pages_returns_empty(self) -> None:
        """Requesting zero pages is valid and returns nothing."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        frames = mm.allocate(pid, num_pages=0)
        assert frames == []
        assert mm.free_frames == TOTAL_FRAMES


class TestMemoryAllocationFailure:
    """Verify behaviour when memory is exhausted."""

    def test_allocate_more_than_available_raises(self) -> None:
        """Requesting more frames than available should raise OutOfMemoryError."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        too_many = TOTAL_FRAMES + 1
        with pytest.raises(OutOfMemoryError, match="Cannot allocate"):
            mm.allocate(pid, num_pages=too_many)

    def test_allocate_after_partial_use_raises_if_insufficient(self) -> None:
        """After some allocation, the remaining must be enough."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        mm.allocate(pid=1, num_pages=LARGE_ALLOCATION)
        remaining = TOTAL_FRAMES - LARGE_ALLOCATION
        too_many = remaining + 1
        with pytest.raises(OutOfMemoryError):
            mm.allocate(pid=2, num_pages=too_many)


class TestMemoryFree:
    """Verify freeing allocated frames."""

    def test_free_restores_frames(self) -> None:
        """Freeing a process's memory should return frames to the free pool."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        mm.free(pid)
        assert mm.free_frames == TOTAL_FRAMES

    def test_free_clears_page_table(self) -> None:
        """After freeing, the process should have no pages."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        pid = 1
        mm.allocate(pid, num_pages=SMALL_ALLOCATION)
        mm.free(pid)
        assert mm.pages_for(pid) == []

    def test_freed_frames_can_be_reallocated(self) -> None:
        """Freed frames should be available for new allocations."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        mm.allocate(pid=1, num_pages=TOTAL_FRAMES)
        mm.free(pid=1)
        frames = mm.allocate(pid=2, num_pages=TOTAL_FRAMES)
        assert len(frames) == TOTAL_FRAMES

    def test_free_unknown_pid_is_noop(self) -> None:
        """Freeing a PID with no allocation should not raise."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        mm.free(pid=999)
        assert mm.free_frames == TOTAL_FRAMES

    def test_free_only_affects_target_process(self) -> None:
        """Freeing one process should not affect another's allocation."""
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        mm.allocate(pid=1, num_pages=SMALL_ALLOCATION)
        frames_2 = mm.allocate(pid=2, num_pages=SMALL_ALLOCATION)
        mm.free(pid=1)
        assert mm.pages_for(2) == frames_2
        expected_free = TOTAL_FRAMES - SMALL_ALLOCATION
        assert mm.free_frames == expected_free
