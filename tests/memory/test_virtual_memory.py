"""Tests for the virtual memory system.

Virtual memory gives each process its own private address space.
Processes use virtual page numbers (0, 1, 2, ...) that get translated
to physical frame numbers via a page table. This decouples the
process's view of memory from the physical layout.
"""

import pytest

from py_os.kernel import Kernel
from py_os.memory.virtual import PageFaultError, PageTable, VirtualMemory

PAGE_SIZE = 256


class TestPageTable:
    """Verify the page table mapping."""

    def test_map_and_translate(self) -> None:
        """Mapping a virtual page should make it translatable."""
        pt = PageTable()
        pt.map(virtual_page=0, physical_frame=42)
        expected_frame = 42
        assert pt.translate(0) == expected_frame

    def test_translate_unmapped_raises(self) -> None:
        """Translating an unmapped page should raise PageFaultError."""
        pt = PageTable()
        with pytest.raises(PageFaultError, match="not mapped"):
            pt.translate(5)

    def test_unmap(self) -> None:
        """Unmapping a page should make it no longer translatable."""
        pt = PageTable()
        pt.map(virtual_page=0, physical_frame=10)
        pt.unmap(virtual_page=0)
        with pytest.raises(PageFaultError):
            pt.translate(0)

    def test_unmap_unmapped_is_noop(self) -> None:
        """Unmapping a page that isn't mapped should be a no-op."""
        pt = PageTable()
        pt.unmap(virtual_page=99)  # should not raise

    def test_mappings(self) -> None:
        """Mappings should return all virtual→physical pairs."""
        frame_a = 10
        frame_b = 20
        pt = PageTable()
        pt.map(virtual_page=0, physical_frame=frame_a)
        pt.map(virtual_page=1, physical_frame=frame_b)
        m = pt.mappings()
        expected_count = 2
        assert len(m) == expected_count
        assert m[0] == frame_a
        assert m[1] == frame_b

    def test_len(self) -> None:
        """Len should return the number of mapped pages."""
        pt = PageTable()
        expected_empty = 0
        assert len(pt) == expected_empty
        pt.map(virtual_page=0, physical_frame=5)
        expected_one = 1
        assert len(pt) == expected_one


class TestVirtualMemory:
    """Verify the virtual memory read/write interface."""

    def test_write_and_read(self) -> None:
        """Writing to a virtual address should be readable back."""
        vm = VirtualMemory(page_size=PAGE_SIZE)
        # Map virtual page 0 to physical frame 0
        vm.page_table.map(virtual_page=0, physical_frame=0)
        vm.write(virtual_address=0, data=b"hello")
        result = vm.read(virtual_address=0, size=5)
        assert result == b"hello"

    def test_write_spans_offset(self) -> None:
        """Writing at an offset within a page should work."""
        vm = VirtualMemory(page_size=PAGE_SIZE)
        vm.page_table.map(virtual_page=0, physical_frame=0)
        offset = 100
        vm.write(virtual_address=offset, data=b"test")
        result = vm.read(virtual_address=offset, size=4)
        assert result == b"test"

    def test_read_unmapped_raises(self) -> None:
        """Reading from an unmapped page should raise PageFaultError."""
        vm = VirtualMemory(page_size=PAGE_SIZE)
        with pytest.raises(PageFaultError):
            vm.read(virtual_address=0, size=1)

    def test_write_unmapped_raises(self) -> None:
        """Writing to an unmapped page should raise PageFaultError."""
        vm = VirtualMemory(page_size=PAGE_SIZE)
        with pytest.raises(PageFaultError):
            vm.write(virtual_address=0, data=b"x")

    def test_different_pages_are_independent(self) -> None:
        """Data on different virtual pages should be independent."""
        vm = VirtualMemory(page_size=PAGE_SIZE)
        vm.page_table.map(virtual_page=0, physical_frame=0)
        vm.page_table.map(virtual_page=1, physical_frame=1)
        vm.write(virtual_address=0, data=b"page0")
        vm.write(virtual_address=PAGE_SIZE, data=b"page1")
        assert vm.read(virtual_address=0, size=5) == b"page0"
        assert vm.read(virtual_address=PAGE_SIZE, size=5) == b"page1"

    def test_page_size_property(self) -> None:
        """Page size should be accessible."""
        vm = VirtualMemory(page_size=PAGE_SIZE)
        assert vm.page_size == PAGE_SIZE


class TestKernelVirtualMemory:
    """Verify kernel integration with virtual memory."""

    def test_process_gets_virtual_memory(self) -> None:
        """A created process should have virtual memory with mapped pages."""
        kernel = Kernel()
        kernel.boot()
        num_pages = 4
        proc = kernel.create_process(name="test", num_pages=num_pages)
        assert proc.virtual_memory is not None
        assert len(proc.virtual_memory.page_table) == num_pages

    def test_process_virtual_pages_are_contiguous(self) -> None:
        """Virtual pages should be 0, 1, 2, ... regardless of physical layout."""
        kernel = Kernel()
        kernel.boot()
        num_pages = 3
        proc = kernel.create_process(name="test", num_pages=num_pages)
        assert proc.virtual_memory is not None
        mappings = proc.virtual_memory.page_table.mappings()
        # Virtual pages 0, 1, 2 should all be mapped
        assert 0 in mappings
        assert 1 in mappings
        expected_last = 2
        assert expected_last in mappings

    def test_two_processes_have_separate_address_spaces(self) -> None:
        """Two processes should have independent virtual memory."""
        kernel = Kernel()
        kernel.boot()
        p1 = kernel.create_process(name="a", num_pages=2)
        p2 = kernel.create_process(name="b", num_pages=2)
        assert p1.virtual_memory is not None
        assert p2.virtual_memory is not None
        # Both map virtual page 0, but to different physical frames
        frame1 = p1.virtual_memory.page_table.translate(0)
        frame2 = p2.virtual_memory.page_table.translate(0)
        assert frame1 != frame2
