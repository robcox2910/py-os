"""Tests for page replacement algorithms and swap space.

When physical memory is full and a process accesses a page not in RAM,
the OS must decide which resident page to evict to make room.  This is
the **page replacement problem** — one of the classic OS challenges.

Components tested:
    - **SwapSpace**: Simulated disk storage for evicted pages.
    - **Replacement Policies**: Algorithms that choose which page to evict.
        - FIFO: Evict the oldest page (simple, but Belady's anomaly).
        - LRU: Evict the least recently used (approximates optimal).
        - Clock: Second-chance approximation of LRU using reference bits.
    - **Pager**: Demand paging orchestrator — ties VM, swap, and policy
      together so pages are transparently swapped in/out as needed.
"""

import pytest

from py_os.swap import (
    ClockPolicy,
    FIFOPolicy,
    LRUPolicy,
    Pager,
    SwapSpace,
)

# -- Swap Space ---------------------------------------------------------------


class TestSwapSpace:
    """Verify swap space (simulated disk for evicted pages)."""

    def test_store_and_retrieve(self) -> None:
        """Stored page data should be retrievable."""
        swap = SwapSpace(capacity=10)
        swap.store(page_id=0, data=b"hello page")
        assert swap.retrieve(page_id=0) == b"hello page"

    def test_retrieve_missing_raises(self) -> None:
        """Retrieving a page not in swap should raise KeyError."""
        swap = SwapSpace(capacity=10)
        with pytest.raises(KeyError):
            swap.retrieve(page_id=99)

    def test_remove_frees_slot(self) -> None:
        """Removing a page from swap should free its slot."""
        swap = SwapSpace(capacity=10)
        swap.store(page_id=0, data=b"data")
        swap.remove(page_id=0)
        assert not swap.contains(page_id=0)

    def test_contains_tracks_presence(self) -> None:
        """Contains should report whether a page is in swap."""
        swap = SwapSpace(capacity=10)
        assert not swap.contains(page_id=0)
        swap.store(page_id=0, data=b"x")
        assert swap.contains(page_id=0)

    def test_capacity_limit(self) -> None:
        """Storing beyond capacity should raise MemoryError."""
        capacity = 2
        swap = SwapSpace(capacity=capacity)
        swap.store(page_id=0, data=b"a")
        swap.store(page_id=1, data=b"b")
        with pytest.raises(MemoryError):
            swap.store(page_id=2, data=b"c")

    def test_used_count(self) -> None:
        """Used count should track the number of stored pages."""
        swap = SwapSpace(capacity=10)
        expected_empty = 0
        assert swap.used == expected_empty
        swap.store(page_id=0, data=b"a")
        expected_one = 1
        assert swap.used == expected_one

    def test_overwrite_preserves_count(self) -> None:
        """Overwriting an existing page should not increase the count."""
        swap = SwapSpace(capacity=10)
        swap.store(page_id=0, data=b"old")
        swap.store(page_id=0, data=b"new")
        assert swap.retrieve(page_id=0) == b"new"
        expected_one = 1
        assert swap.used == expected_one


# -- FIFO Policy --------------------------------------------------------------


class TestFIFOPolicy:
    """Verify FIFO (First In, First Out) page replacement.

    FIFO always evicts the page that has been in memory the longest.
    Simple to implement (just a queue) but can suffer from Belady's
    anomaly — adding more frames can actually *increase* page faults.
    """

    def test_selects_oldest_page(self) -> None:
        """FIFO should evict the page that was loaded first."""
        policy = FIFOPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.add_page(3)
        assert policy.select_victim() == 1

    def test_access_does_not_change_order(self) -> None:
        """In FIFO, re-accessing a page has no effect on eviction order."""
        policy = FIFOPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.record_access(1)
        assert policy.select_victim() == 1

    def test_remove_page(self) -> None:
        """Removing a page should exclude it from victim selection."""
        policy = FIFOPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.remove_page(1)
        remaining = 2
        assert policy.select_victim() == remaining

    def test_empty_raises(self) -> None:
        """Selecting from an empty policy should raise IndexError."""
        policy = FIFOPolicy()
        with pytest.raises(IndexError):
            policy.select_victim()


# -- LRU Policy ---------------------------------------------------------------


class TestLRUPolicy:
    """Verify LRU (Least Recently Used) page replacement.

    LRU evicts the page that hasn't been accessed for the longest time.
    It approximates the optimal algorithm and doesn't suffer from
    Belady's anomaly.  Real implementations use hardware reference bits
    or approximate with aging counters.
    """

    def test_selects_least_recently_used(self) -> None:
        """LRU should evict the page accessed longest ago."""
        policy = LRUPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.add_page(3)
        assert policy.select_victim() == 1

    def test_access_updates_recency(self) -> None:
        """Accessing a page should make it the most recently used."""
        policy = LRUPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.add_page(3)
        policy.record_access(1)
        # Page 2 is now least recently used
        expected_victim = 2
        assert policy.select_victim() == expected_victim

    def test_remove_page(self) -> None:
        """Removing a page should exclude it from victim selection."""
        policy = LRUPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.remove_page(1)
        remaining = 2
        assert policy.select_victim() == remaining

    def test_empty_raises(self) -> None:
        """Selecting from an empty policy should raise IndexError."""
        policy = LRUPolicy()
        with pytest.raises(IndexError):
            policy.select_victim()


# -- Clock Policy --------------------------------------------------------------


class TestClockPolicy:
    """Verify Clock (Second Chance) page replacement.

    The Clock algorithm uses a circular buffer and a reference bit per
    page.  When seeking a victim, it checks the bit: if set, it clears
    the bit and moves on (second chance); if clear, it evicts the page.

    This is the most common real-world algorithm — nearly as good as
    LRU but much cheaper (one bit per page, no access history).
    """

    def test_evicts_unreferenced_page(self) -> None:
        """Clock should evict the first unreferenced page."""
        policy = ClockPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.add_page(3)
        assert policy.select_victim() == 1

    def test_second_chance_skips_referenced(self) -> None:
        """A referenced page gets its bit cleared and is skipped."""
        policy = ClockPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.add_page(3)
        policy.record_access(1)
        # Page 1 ref=1 -> clear, skip.  Page 2 ref=0 -> evict.
        expected_victim = 2
        assert policy.select_victim() == expected_victim

    def test_all_referenced_wraps_around(self) -> None:
        """If all pages are referenced, clock clears all and evicts first."""
        policy = ClockPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.record_access(1)
        policy.record_access(2)
        # Pass 1: clear both bits.  Pass 2: evict page 1.
        assert policy.select_victim() == 1

    def test_remove_page(self) -> None:
        """Removing a page should exclude it from the clock ring."""
        policy = ClockPolicy()
        policy.add_page(1)
        policy.add_page(2)
        policy.remove_page(1)
        remaining = 2
        assert policy.select_victim() == remaining


# -- Pager (Demand Paging Orchestrator) ----------------------------------------


class TestPager:
    """Verify demand paging — the full page replacement pipeline.

    The Pager manages a limited set of physical frames for a larger
    virtual address space, swapping pages in and out as needed using
    a configurable replacement policy.
    """

    def _make_pager(
        self,
        *,
        num_physical: int = 2,
        num_virtual: int = 4,
        page_size: int = 16,
        policy: FIFOPolicy | LRUPolicy | ClockPolicy | None = None,
    ) -> Pager:
        """Create a pager with limited physical frames."""
        return Pager(
            num_physical_frames=num_physical,
            num_virtual_pages=num_virtual,
            page_size=page_size,
            policy=policy or LRUPolicy(),
        )

    def test_write_and_read(self) -> None:
        """Data written to a resident page should be readable."""
        pager = self._make_pager()
        pager.write(virtual_page=0, offset=0, data=b"A")
        assert pager.read(virtual_page=0, offset=0, size=1) == b"A"

    def test_page_fault_triggers_replacement(self) -> None:
        """Accessing a non-resident page should trigger replacement."""
        pager = self._make_pager(num_physical=2, num_virtual=4)
        pager.write(virtual_page=0, offset=0, data=b"X")
        pager.write(virtual_page=1, offset=0, data=b"Y")
        # Page 2 not resident — triggers fault and eviction
        pager.write(virtual_page=2, offset=0, data=b"Z")
        assert pager.read(virtual_page=2, offset=0, size=1) == b"Z"

    def test_evicted_data_preserved_in_swap(self) -> None:
        """Data from an evicted page should survive in swap and restore."""
        pager = self._make_pager(num_physical=2, num_virtual=4)
        pager.write(virtual_page=0, offset=0, data=b"A")
        pager.write(virtual_page=1, offset=0, data=b"B")
        # Evict page 0 by accessing page 2
        pager.write(virtual_page=2, offset=0, data=b"C")
        # Bring page 0 back from swap — data should be intact
        result = pager.read(virtual_page=0, offset=0, size=1)
        assert result == b"A"

    def test_page_fault_count(self) -> None:
        """Pager should track the number of page faults."""
        pager = self._make_pager(num_physical=2, num_virtual=4)
        pager.write(virtual_page=0, offset=0, data=b"A")
        pager.write(virtual_page=1, offset=0, data=b"B")
        initial = pager.page_faults
        pager.write(virtual_page=2, offset=0, data=b"C")
        assert pager.page_faults == initial + 1

    def test_fifo_eviction_order(self) -> None:
        """With FIFO, the oldest loaded page should be evicted first."""
        pager = self._make_pager(num_physical=2, num_virtual=4, policy=FIFOPolicy())
        pager.write(virtual_page=0, offset=0, data=b"A")
        pager.write(virtual_page=1, offset=0, data=b"B")
        # FIFO evicts page 0 (loaded first)
        pager.write(virtual_page=2, offset=0, data=b"C")
        # Page 1 should still be resident
        assert pager.read(virtual_page=1, offset=0, size=1) == b"B"

    def test_lru_eviction_order(self) -> None:
        """With LRU, the least recently accessed page is evicted."""
        pager = self._make_pager(num_physical=2, num_virtual=4, policy=LRUPolicy())
        pager.write(virtual_page=0, offset=0, data=b"A")
        pager.write(virtual_page=1, offset=0, data=b"B")
        # Re-access page 0 — makes it most recently used
        pager.read(virtual_page=0, offset=0, size=1)
        # LRU evicts page 1 (least recently used)
        pager.write(virtual_page=2, offset=0, data=b"C")
        # Page 0 should still be resident
        assert pager.read(virtual_page=0, offset=0, size=1) == b"A"

    def test_clock_policy_works(self) -> None:
        """Clock policy should manage replacement correctly."""
        pager = self._make_pager(num_physical=2, num_virtual=4, policy=ClockPolicy())
        pager.write(virtual_page=0, offset=0, data=b"A")
        pager.write(virtual_page=1, offset=0, data=b"B")
        # Fault: evict and load page 2
        pager.write(virtual_page=2, offset=0, data=b"C")
        assert pager.read(virtual_page=2, offset=0, size=1) == b"C"
        # Evicted data survives in swap
        result = pager.read(virtual_page=0, offset=0, size=1)
        assert result == b"A"

    def test_invalid_page_raises(self) -> None:
        """Accessing beyond the virtual address space should raise ValueError."""
        pager = self._make_pager(num_virtual=4)
        beyond = 10
        with pytest.raises(ValueError, match="beyond"):
            pager.read(virtual_page=beyond, offset=0, size=1)

    def test_resident_pages_tracked(self) -> None:
        """Pager should report which pages are currently in RAM."""
        pager = self._make_pager(num_physical=2, num_virtual=4)
        pager.write(virtual_page=0, offset=0, data=b"A")
        assert 0 in pager.resident_pages

    def test_multiple_eviction_cycles(self) -> None:
        """Data should survive multiple eviction and reload cycles."""
        pager = self._make_pager(num_physical=2, num_virtual=4)
        pager.write(virtual_page=0, offset=0, data=b"A")
        pager.write(virtual_page=1, offset=0, data=b"B")
        # Cycle 1: evict 0, load 2
        pager.write(virtual_page=2, offset=0, data=b"C")
        # Cycle 2: evict 1, load 3
        pager.write(virtual_page=3, offset=0, data=b"D")
        # Cycle 3: reload 0 from swap
        assert pager.read(virtual_page=0, offset=0, size=1) == b"A"
        # Cycle 4: reload 1 from swap
        assert pager.read(virtual_page=1, offset=0, size=1) == b"B"
