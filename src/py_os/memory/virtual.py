"""Virtual memory — per-process address space abstraction.

In a real OS, processes don't see physical memory directly.  Each
process has its own **virtual address space** — a contiguous range of
addresses starting from 0.  The hardware MMU (Memory Management Unit)
translates virtual addresses to physical frame addresses on every
memory access, using a **page table** maintained by the kernel.

This gives three critical properties:
    1. **Isolation** — processes can't access each other's memory.
    2. **Contiguity** — the process sees contiguous memory even when
       physical frames are scattered.
    3. **Abstraction** — the process doesn't need to know where its
       data physically lives.

Address translation::

    virtual address  →  (virtual page number, offset within page)
    page table[vpn]  →  physical frame number
    physical address →  frame_number * page_size + offset

Design choices:
    - **PageTable** is a dict mapping virtual page → physical frame.
    - **PageFaultError** is raised on access to unmapped pages — in a real
      OS this triggers the kernel's page fault handler.
    - **VirtualMemory** stores data in a dict of bytearrays keyed by
      physical frame number, simulating physical RAM.
"""

from collections.abc import Callable

# Type alias for the COW fault handler callback.
# Given a virtual page number, return (new_frame, new_storage).
CowFaultHandler = Callable[[int], tuple[int, bytearray]]


class PageFaultError(Exception):
    """Raised when a virtual address has no physical mapping."""


class PageTable:
    """Map virtual page numbers to physical frame numbers.

    This is the core data structure of virtual memory.  The MMU
    consults it on every memory access to translate virtual → physical.
    """

    def __init__(self) -> None:
        """Create an empty page table."""
        self._entries: dict[int, int] = {}

    def map(self, *, virtual_page: int, physical_frame: int) -> None:
        """Create a mapping from a virtual page to a physical frame."""
        self._entries[virtual_page] = physical_frame

    def unmap(self, *, virtual_page: int) -> None:
        """Remove a virtual page mapping (no-op if not mapped)."""
        self._entries.pop(virtual_page, None)

    def translate(self, virtual_page: int) -> int:
        """Translate a virtual page number to a physical frame number.

        Raises:
            PageFaultError: If the virtual page is not mapped.

        """
        frame = self._entries.get(virtual_page)
        if frame is None:
            msg = f"Virtual page {virtual_page} is not mapped"
            raise PageFaultError(msg)
        return frame

    def mappings(self) -> dict[int, int]:
        """Return all virtual→physical mappings."""
        return dict(self._entries)

    def __len__(self) -> int:
        """Return the number of mapped pages."""
        return len(self._entries)


class VirtualMemory:
    """Per-process virtual address space with read/write access.

    Translates virtual addresses through the page table and stores
    data in simulated physical frames (bytearrays).
    """

    def __init__(self, *, page_size: int = 256) -> None:
        """Create a virtual memory space.

        Args:
            page_size: Size of each page/frame in bytes.

        """
        self._page_size = page_size
        self._page_table = PageTable()
        # Simulated physical RAM: frame_number → bytearray
        self._physical: dict[int, bytearray] = {}
        # COW tracking
        self._cow_pages: set[int] = set()
        self._cow_fault_handler: CowFaultHandler | None = None

    @property
    def page_size(self) -> int:
        """Return the page size in bytes."""
        return self._page_size

    @property
    def page_table(self) -> PageTable:
        """Return the page table for this address space."""
        return self._page_table

    def mark_cow(self, *, virtual_page: int) -> None:
        """Mark a virtual page as copy-on-write protected."""
        self._cow_pages.add(virtual_page)

    def clear_cow(self, *, virtual_page: int) -> None:
        """Remove copy-on-write protection from a virtual page."""
        self._cow_pages.discard(virtual_page)

    def is_cow(self, *, virtual_page: int) -> bool:
        """Return True if the virtual page is copy-on-write protected."""
        return virtual_page in self._cow_pages

    @property
    def cow_pages(self) -> frozenset[int]:
        """Return the set of virtual page numbers that are COW-protected."""
        return frozenset(self._cow_pages)

    @property
    def cow_fault_handler(self) -> CowFaultHandler | None:
        """Return the currently installed COW fault handler."""
        return self._cow_fault_handler

    @cow_fault_handler.setter
    def cow_fault_handler(self, handler: CowFaultHandler | None) -> None:
        """Install a COW fault handler callback."""
        self._cow_fault_handler = handler

    def share_physical(self, *, frame: int, storage: bytearray) -> None:
        """Install a shared bytearray as the storage for a physical frame.

        Used by the kernel at fork time to make parent and child point
        to the same underlying buffer until a COW fault separates them.

        Args:
            frame: The physical frame number.
            storage: The bytearray to use as backing storage.

        """
        self._physical[frame] = storage

    def physical_storage(self, frame: int) -> bytearray:
        """Return the underlying bytearray for a physical frame.

        Args:
            frame: The physical frame number.

        Returns:
            The frame's storage buffer.

        """
        return self._ensure_frame(frame)

    def _resolve(self, virtual_address: int) -> tuple[int, int]:
        """Translate a virtual address to (physical_frame, offset).

        Raises:
            PageFaultError: If the virtual page is not mapped.

        """
        vpn = virtual_address // self._page_size
        offset = virtual_address % self._page_size
        frame = self._page_table.translate(vpn)
        return frame, offset

    def _ensure_frame(self, frame: int) -> bytearray:
        """Get or create the physical frame storage."""
        if frame not in self._physical:
            self._physical[frame] = bytearray(self._page_size)
        return self._physical[frame]

    def read(self, *, virtual_address: int, size: int) -> bytes:
        """Read bytes from a virtual address.

        Args:
            virtual_address: The starting virtual address.
            size: Number of bytes to read.

        Returns:
            The data at the given address.

        Raises:
            PageFaultError: If the address is not mapped.

        """
        frame, offset = self._resolve(virtual_address)
        storage = self._ensure_frame(frame)
        return bytes(storage[offset : offset + size])

    def write(self, *, virtual_address: int, data: bytes) -> None:
        """Write bytes to a virtual address.

        If the target page is COW-protected, a fault handler is invoked
        to allocate a private copy before the write proceeds.

        Args:
            virtual_address: The starting virtual address.
            data: The bytes to write.

        Raises:
            PageFaultError: If the address is not mapped.
            RuntimeError: If a COW page has no fault handler installed.

        """
        vpn = virtual_address // self._page_size
        if vpn in self._cow_pages:
            self._handle_cow_fault(vpn)
        frame, offset = self._resolve(virtual_address)
        storage = self._ensure_frame(frame)
        storage[offset : offset + len(data)] = data

    def _handle_cow_fault(self, vpn: int) -> None:
        """Handle a copy-on-write fault for a virtual page.

        Calls the installed fault handler to get a new private frame
        and storage, remaps the page table, and clears the COW flag.

        Args:
            vpn: The virtual page number that was written to.

        Raises:
            RuntimeError: If no fault handler is installed.

        """
        if self._cow_fault_handler is None:
            msg = f"No COW fault handler for virtual page {vpn}"
            raise RuntimeError(msg)
        new_frame, new_storage = self._cow_fault_handler(vpn)
        self._page_table.map(virtual_page=vpn, physical_frame=new_frame)
        self._physical[new_frame] = new_storage
        self._cow_pages.discard(vpn)
