"""Page replacement and swap space — demand paging support.

When physical memory is full and a process needs a page that isn't in
RAM, the OS must:
    1. Choose a **victim page** to evict (the replacement policy).
    2. Save the victim's data to **swap space** (simulated disk).
    3. Load the requested page into the freed frame.
    4. Update the page table.

This is called **demand paging** — pages are loaded into RAM only when
accessed, not all at once.

Replacement Policies (Strategy pattern, like the scheduler):
    - **FIFO** — evict the oldest page.  Simple but can suffer from
      Belady's anomaly (more frames → more faults for some patterns).
    - **LRU** — evict the least recently used page.  Approximates the
      optimal algorithm.  Implemented with an OrderedDict for O(1)
      move-to-end on access.
    - **Clock** — second-chance approximation of LRU.  Uses a circular
      buffer and one reference bit per page.  When the hand reaches a
      page with ref=1, it clears the bit and moves on; ref=0 → evict.
      Most common in real OSes because it's nearly as good as LRU but
      much cheaper.

Swap Space:
    A simple key-value store mapping page IDs to byte data.  In a real
    OS, swap is a disk partition or file.  Ours uses a dict — the
    abstraction is what matters for learning.

Pager:
    The orchestrator that ties VirtualMemory, SwapSpace, and a
    ReplacementPolicy together for transparent demand paging.
"""

from collections import OrderedDict
from typing import Protocol

from py_os.memory.virtual import VirtualMemory

# ---------------------------------------------------------------------------
# Replacement Policy Protocol (Strategy pattern)
# ---------------------------------------------------------------------------


class ReplacementPolicy(Protocol):
    """Interface for page replacement algorithms.

    Each policy tracks which pages are in RAM and decides which one
    to evict when space is needed.
    """

    def add_page(self, page_id: int) -> None:
        """Record that a page was loaded into RAM."""
        ...

    def remove_page(self, page_id: int) -> None:
        """Record that a page was removed from RAM."""
        ...

    def record_access(self, page_id: int) -> None:
        """Record that a page was accessed (read or written)."""
        ...

    def select_victim(self) -> int:
        """Choose which page to evict.

        Returns:
            The page_id of the victim.

        Raises:
            IndexError: If no pages are available to evict.

        """
        ...


# ---------------------------------------------------------------------------
# Swap Space
# ---------------------------------------------------------------------------


class SwapSpace:
    """Simulated disk storage for evicted pages.

    In a real OS, swap is a dedicated disk partition or a swap file.
    Our version uses an in-memory dict — the interface is what matters
    for understanding the concept.
    """

    def __init__(self, capacity: int) -> None:
        """Create swap space with the given slot capacity.

        Args:
            capacity: Maximum number of pages that can be stored.

        """
        self._capacity = capacity
        self._slots: dict[int, bytes] = {}

    @property
    def used(self) -> int:
        """Return the number of pages currently stored in swap."""
        return len(self._slots)

    def store(self, *, page_id: int, data: bytes) -> None:
        """Store a page's data in swap.

        Overwrites if the page_id already exists (no extra slot used).

        Raises:
            MemoryError: If swap is full and page_id is new.

        """
        if page_id not in self._slots and len(self._slots) >= self._capacity:
            msg = f"Swap space full ({self._capacity} slots)"
            raise MemoryError(msg)
        self._slots[page_id] = data

    def retrieve(self, *, page_id: int) -> bytes:
        """Retrieve a page's data from swap.

        Raises:
            KeyError: If the page is not in swap.

        """
        if page_id not in self._slots:
            msg = f"Page {page_id} not in swap"
            raise KeyError(msg)
        return self._slots[page_id]

    def remove(self, *, page_id: int) -> None:
        """Remove a page from swap, freeing the slot."""
        self._slots.pop(page_id, None)

    def contains(self, *, page_id: int) -> bool:
        """Check whether a page is stored in swap."""
        return page_id in self._slots


# ---------------------------------------------------------------------------
# FIFO Policy
# ---------------------------------------------------------------------------


class FIFOPolicy:
    """First In, First Out — evict the oldest loaded page.

    Uses a simple list as a queue.  The first element is always the
    oldest (earliest added).
    """

    def __init__(self) -> None:
        """Create an empty FIFO policy."""
        self._queue: list[int] = []

    def add_page(self, page_id: int) -> None:
        """Record that a page was loaded (appended to the queue)."""
        self._queue.append(page_id)

    def remove_page(self, page_id: int) -> None:
        """Remove a page from the queue."""
        self._queue.remove(page_id)

    def record_access(self, page_id: int) -> None:
        """FIFO ignores accesses — order is purely by load time."""

    def select_victim(self) -> int:
        """Return the oldest page (front of the queue).

        Raises:
            IndexError: If no pages are tracked.

        """
        if not self._queue:
            msg = "No pages to evict"
            raise IndexError(msg)
        return self._queue[0]


# ---------------------------------------------------------------------------
# LRU Policy
# ---------------------------------------------------------------------------


class LRUPolicy:
    """Least Recently Used — evict the page accessed longest ago.

    Uses an OrderedDict for O(1) move-to-end on access.  The first
    key is always the least recently used.
    """

    def __init__(self) -> None:
        """Create an empty LRU policy."""
        self._order: OrderedDict[int, None] = OrderedDict()

    def add_page(self, page_id: int) -> None:
        """Record that a page was loaded (most recently used)."""
        self._order[page_id] = None
        self._order.move_to_end(page_id)

    def remove_page(self, page_id: int) -> None:
        """Remove a page from LRU tracking."""
        self._order.pop(page_id, None)

    def record_access(self, page_id: int) -> None:
        """Move the page to the most recently used position."""
        if page_id in self._order:
            self._order.move_to_end(page_id)

    def select_victim(self) -> int:
        """Return the least recently used page (front of the order).

        Raises:
            IndexError: If no pages are tracked.

        """
        if not self._order:
            msg = "No pages to evict"
            raise IndexError(msg)
        return next(iter(self._order))


# ---------------------------------------------------------------------------
# Clock Policy
# ---------------------------------------------------------------------------


class ClockPolicy:
    """Second Chance (Clock) — approximate LRU with reference bits.

    Maintains a circular buffer of pages.  A clock hand sweeps through:
    - ref bit = 1 → clear it, skip (second chance)
    - ref bit = 0 → evict this page

    Much cheaper than true LRU — only one bit per page, no ordering.
    """

    def __init__(self) -> None:
        """Create an empty clock policy."""
        self._ring: list[int] = []
        self._ref_bits: dict[int, bool] = {}
        self._hand: int = 0

    def add_page(self, page_id: int) -> None:
        """Add a page to the clock ring with ref bit cleared."""
        self._ring.append(page_id)
        self._ref_bits[page_id] = False

    def remove_page(self, page_id: int) -> None:
        """Remove a page from the clock ring."""
        idx = self._ring.index(page_id)
        self._ring.remove(page_id)
        del self._ref_bits[page_id]
        # Adjust hand position after removal
        if not self._ring:
            self._hand = 0
        elif self._hand > idx:
            self._hand -= 1
        elif self._hand >= len(self._ring):
            self._hand = 0

    def record_access(self, page_id: int) -> None:
        """Set the reference bit for this page."""
        if page_id in self._ref_bits:
            self._ref_bits[page_id] = True

    def select_victim(self) -> int:
        """Sweep the clock hand to find a page to evict.

        Raises:
            IndexError: If no pages are in the ring.

        """
        if not self._ring:
            msg = "No pages to evict"
            raise IndexError(msg)
        while True:
            page = self._ring[self._hand]
            if self._ref_bits[page]:
                # Second chance: clear the bit, move on
                self._ref_bits[page] = False
                self._hand = (self._hand + 1) % len(self._ring)
            else:
                # Victim found
                return page


# ---------------------------------------------------------------------------
# Pager (Demand Paging Orchestrator)
# ---------------------------------------------------------------------------


class Pager:
    """Demand paging system — transparent page replacement.

    The pager manages a virtual address space larger than physical
    memory.  Pages are loaded on demand and evicted when physical
    frames run out, using the configured replacement policy.

    Args:
        num_physical_frames: Number of physical frames available.
        num_virtual_pages: Total virtual address space in pages.
        page_size: Size of each page in bytes.
        policy: The replacement algorithm to use.

    """

    def __init__(
        self,
        *,
        num_physical_frames: int,
        num_virtual_pages: int,
        page_size: int = 256,
        policy: FIFOPolicy | LRUPolicy | ClockPolicy,
    ) -> None:
        """Create a pager with limited physical frames."""
        self._vm = VirtualMemory(page_size=page_size)
        self._swap = SwapSpace(capacity=num_virtual_pages)
        self._policy = policy
        self._num_physical = num_physical_frames
        self._num_virtual = num_virtual_pages
        self._page_size = page_size
        self._page_faults = 0

        # Track resident pages and frame allocation
        self._resident: set[int] = set()
        self._free_frames: list[int] = list(range(num_physical_frames))
        self._vpn_to_frame: dict[int, int] = {}

        # Pre-map the first batch of pages (up to physical frame count)
        initial = min(num_physical_frames, num_virtual_pages)
        for vpn in range(initial):
            frame = self._free_frames.pop(0)
            self._vm.page_table.map(virtual_page=vpn, physical_frame=frame)
            self._vpn_to_frame[vpn] = frame
            self._resident.add(vpn)
            self._policy.add_page(vpn)

    @property
    def page_faults(self) -> int:
        """Return the total number of page faults."""
        return self._page_faults

    @property
    def resident_pages(self) -> frozenset[int]:
        """Return the set of virtual pages currently in RAM."""
        return frozenset(self._resident)

    def _ensure_resident(self, vpn: int) -> None:
        """Make sure a virtual page is in RAM, swapping if needed."""
        if vpn >= self._num_virtual:
            msg = f"Virtual page {vpn} beyond address space (max {self._num_virtual - 1})"
            raise ValueError(msg)

        if vpn in self._resident:
            self._policy.record_access(vpn)
            return

        # Page fault!
        self._page_faults += 1

        if not self._free_frames:
            # Need to evict a page to make room
            victim = self._policy.select_victim()
            self._evict(victim)

        # Allocate a frame for the new page
        frame = self._free_frames.pop(0)
        self._vm.page_table.map(virtual_page=vpn, physical_frame=frame)
        self._vpn_to_frame[vpn] = frame
        self._resident.add(vpn)
        self._policy.add_page(vpn)

        # If the page was previously evicted to swap, restore its data
        if self._swap.contains(page_id=vpn):
            data = self._swap.retrieve(page_id=vpn)
            self._swap.remove(page_id=vpn)
            addr = vpn * self._page_size
            self._vm.write(virtual_address=addr, data=data)

        self._policy.record_access(vpn)

    def _evict(self, vpn: int) -> None:
        """Evict a page from RAM to swap space."""
        # Save the frame's data to swap
        addr = vpn * self._page_size
        data = self._vm.read(virtual_address=addr, size=self._page_size)
        self._swap.store(page_id=vpn, data=data)

        # Free the frame
        frame = self._vpn_to_frame.pop(vpn)
        self._vm.page_table.unmap(virtual_page=vpn)
        self._resident.discard(vpn)
        self._policy.remove_page(vpn)
        self._free_frames.append(frame)

    def read(self, *, virtual_page: int, offset: int, size: int) -> bytes:
        """Read bytes from a virtual page.

        Triggers demand paging if the page is not resident.

        Args:
            virtual_page: The virtual page number.
            offset: Byte offset within the page.
            size: Number of bytes to read.

        Returns:
            The data at the given location.

        """
        self._ensure_resident(virtual_page)
        addr = virtual_page * self._page_size + offset
        return self._vm.read(virtual_address=addr, size=size)

    def write(self, *, virtual_page: int, offset: int, data: bytes) -> None:
        """Write bytes to a virtual page.

        Triggers demand paging if the page is not resident.

        Args:
            virtual_page: The virtual page number.
            offset: Byte offset within the page.
            data: The bytes to write.

        """
        self._ensure_resident(virtual_page)
        addr = virtual_page * self._page_size + offset
        self._vm.write(virtual_address=addr, data=data)
