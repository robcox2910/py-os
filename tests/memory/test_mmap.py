"""Tests for memory-mapped files (mmap).

Memory-mapped files let a process map file data directly into its
virtual address space.  Instead of explicit read/write syscalls,
the process reads and writes memory addresses that correspond to
file contents.

Two mapping modes:
    - **MAP_PRIVATE** — the process gets its own copy.  Writes modify
      only the local pages.  Changes are NOT written back to the file.
    - **MAP_SHARED** — multiple processes share the same physical frames.
      Writes by one are immediately visible to the others.  ``msync``
      writes dirty data back to the file.
"""

import pytest

from py_os.kernel import Kernel
from py_os.memory.mmap import MmapError, MmapRegion
from py_os.process.signals import Signal
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


# ---------------------------------------------------------------------------
# Cycle 1: MmapRegion dataclass + MmapError
# ---------------------------------------------------------------------------

# Constants for MmapRegion test values
EXPECTED_INODE = 42
EXPECTED_START_VPN = 4
EXPECTED_NUM_PAGES = 2
EXPECTED_LENGTH = 512


class TestMmapRegion:
    """Verify the MmapRegion frozen dataclass and MmapError exception."""

    def test_region_fields(self) -> None:
        """MmapRegion should store all mapping metadata."""
        region = MmapRegion(
            path="/data.txt",
            inode_number=EXPECTED_INODE,
            start_vpn=EXPECTED_START_VPN,
            num_pages=EXPECTED_NUM_PAGES,
            offset=0,
            length=EXPECTED_LENGTH,
            shared=False,
        )
        assert region.path == "/data.txt"
        assert region.inode_number == EXPECTED_INODE
        assert region.start_vpn == EXPECTED_START_VPN
        assert region.num_pages == EXPECTED_NUM_PAGES
        assert region.offset == 0
        assert region.length == EXPECTED_LENGTH
        assert region.shared is False

    def test_region_is_frozen(self) -> None:
        """MmapRegion should be immutable (frozen dataclass)."""
        region = MmapRegion(
            path="/f.txt",
            inode_number=1,
            start_vpn=0,
            num_pages=1,
            offset=0,
            length=256,
            shared=True,
        )
        with pytest.raises(AttributeError):
            region.path = "/other.txt"  # type: ignore[misc]

    def test_mmap_error_is_exception(self) -> None:
        """MmapError should be a standard exception with a message."""
        err = MmapError("bad mapping")
        assert str(err) == "bad mapping"
        assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# Cycle 2: MAP_PRIVATE — private mapping
# ---------------------------------------------------------------------------


def _kernel_with_file(data: bytes = b"Hello, mmap!") -> tuple[Kernel, str]:
    """Boot a kernel, create a file with data, and return (kernel, path)."""
    kernel = _booted_kernel()
    assert kernel.filesystem is not None
    kernel.filesystem.create_file("/data.txt")
    kernel.filesystem.write("/data.txt", data)
    return kernel, "/data.txt"


class TestMmapPrivate:
    """Verify MAP_PRIVATE mapping loads file data into process memory."""

    def test_private_map_returns_virtual_address(self) -> None:
        """Mmap_file should return the virtual address of the mapping."""
        kernel, path = _kernel_with_file()
        proc = kernel.create_process(name="reader", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        assert isinstance(addr, int)
        assert addr >= 0

    def test_private_map_loads_file_data(self) -> None:
        """Mapped pages should contain the file's data."""
        file_data = b"ABCDEFGH"
        kernel, path = _kernel_with_file(file_data)
        proc = kernel.create_process(name="reader", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        assert proc.virtual_memory is not None
        result = proc.virtual_memory.read(virtual_address=addr, size=len(file_data))
        assert result == file_data

    def test_private_map_allocates_frames(self) -> None:
        """Private mapping should allocate new physical frames."""
        kernel, path = _kernel_with_file(b"x" * 300)  # >1 page (256 bytes)
        assert kernel.memory is not None
        proc = kernel.create_process(name="reader", num_pages=1)
        free_before = kernel.memory.free_frames
        kernel.mmap_file(pid=proc.pid, path=path)
        expected_new_pages = 2  # ceil(300/256) = 2
        assert kernel.memory.free_frames == free_before - expected_new_pages

    def test_private_write_does_not_affect_file(self) -> None:
        """Writing to a private mapping should not change the file."""
        kernel, path = _kernel_with_file(b"original")
        assert kernel.filesystem is not None
        proc = kernel.create_process(name="writer", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(virtual_address=addr, data=b"CHANGED!")
        assert kernel.filesystem.read(path) == b"original"

    def test_private_map_extends_address_space(self) -> None:
        """Mapping should add pages beyond existing address space."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=2)
        assert proc.virtual_memory is not None
        existing_pages = len(proc.virtual_memory.page_table.mappings())
        kernel.mmap_file(pid=proc.pid, path=path)
        new_pages = len(proc.virtual_memory.page_table.mappings())
        assert new_pages > existing_pages

    def test_private_map_records_region(self) -> None:
        """Kernel should track the MmapRegion after mapping."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        assert proc.virtual_memory is not None
        start_vpn = addr // proc.virtual_memory.page_size
        regions = kernel.mmap_regions(proc.pid)
        assert start_vpn in regions
        region = regions[start_vpn]
        assert region.path == path
        assert region.shared is False

    def test_private_map_with_offset(self) -> None:
        """Mapping with an offset should load data from that offset."""
        file_data = b"AABBCCDD"
        kernel, path = _kernel_with_file(file_data)
        proc = kernel.create_process(name="reader", num_pages=1)
        offset = 4
        length = 4
        addr = kernel.mmap_file(pid=proc.pid, path=path, offset=offset, length=length)
        assert proc.virtual_memory is not None
        result = proc.virtual_memory.read(virtual_address=addr, size=length)
        assert result == b"CCDD"

    def test_private_map_nonexistent_file_raises(self) -> None:
        """Mapping a non-existent file should raise MmapError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="proc", num_pages=1)
        with pytest.raises(MmapError, match="not found"):
            kernel.mmap_file(pid=proc.pid, path="/no/such/file.txt")

    def test_private_map_directory_raises(self) -> None:
        """Mapping a directory should raise MmapError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="proc", num_pages=1)
        with pytest.raises(MmapError, match="directory"):
            kernel.mmap_file(pid=proc.pid, path="/")


# ---------------------------------------------------------------------------
# Cycle 3: MAP_SHARED — shared mapping
# ---------------------------------------------------------------------------


class TestMmapShared:
    """Verify MAP_SHARED mapping shares physical frames between processes."""

    def test_shared_map_loads_file_data(self) -> None:
        """Shared mapping should load the file data into memory."""
        kernel, path = _kernel_with_file(b"shared-data")
        proc = kernel.create_process(name="mapper", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path, shared=True)
        assert proc.virtual_memory is not None
        result = proc.virtual_memory.read(virtual_address=addr, size=11)
        assert result == b"shared-data"

    def test_shared_map_records_shared_flag(self) -> None:
        """Shared region should have shared=True."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="mapper", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path, shared=True)
        assert proc.virtual_memory is not None
        start_vpn = addr // proc.virtual_memory.page_size
        regions = kernel.mmap_regions(proc.pid)
        assert regions[start_vpn].shared is True

    def test_two_processes_share_frames(self) -> None:
        """Two processes mapping the same file shared should use same frames."""
        kernel, path = _kernel_with_file(b"shared")
        p1 = kernel.create_process(name="p1", num_pages=1)
        p2 = kernel.create_process(name="p2", num_pages=1)
        assert p1.virtual_memory is not None
        assert p2.virtual_memory is not None

        addr1 = kernel.mmap_file(pid=p1.pid, path=path, shared=True)
        addr2 = kernel.mmap_file(pid=p2.pid, path=path, shared=True)

        vpn1 = addr1 // p1.virtual_memory.page_size
        vpn2 = addr2 // p2.virtual_memory.page_size
        frame1 = p1.virtual_memory.page_table.translate(vpn1)
        frame2 = p2.virtual_memory.page_table.translate(vpn2)
        assert frame1 == frame2

    def test_shared_write_visible_to_other_process(self) -> None:
        """A write through one shared mapping should be visible via the other."""
        kernel, path = _kernel_with_file(b"original")
        p1 = kernel.create_process(name="p1", num_pages=1)
        p2 = kernel.create_process(name="p2", num_pages=1)

        addr1 = kernel.mmap_file(pid=p1.pid, path=path, shared=True)
        addr2 = kernel.mmap_file(pid=p2.pid, path=path, shared=True)

        assert p1.virtual_memory is not None
        assert p2.virtual_memory is not None
        p1.virtual_memory.write(virtual_address=addr1, data=b"MODIFIED")

        result = p2.virtual_memory.read(virtual_address=addr2, size=8)
        assert result == b"MODIFIED"

    def test_second_shared_map_uses_zero_new_frames(self) -> None:
        """Second mapper of the same shared file should allocate no frames."""
        kernel, path = _kernel_with_file(b"shared")
        assert kernel.memory is not None
        p1 = kernel.create_process(name="p1", num_pages=1)
        kernel.mmap_file(pid=p1.pid, path=path, shared=True)
        free_after_first = kernel.memory.free_frames

        p2 = kernel.create_process(name="p2", num_pages=1)
        kernel.mmap_file(pid=p2.pid, path=path, shared=True)
        # Second map should not consume any new frames (only refcount bump)
        expected_free = free_after_first - 1  # -1 for p2's process page
        assert kernel.memory.free_frames == expected_free


# ---------------------------------------------------------------------------
# Cycle 4: munmap_file
# ---------------------------------------------------------------------------


class TestMunmap:
    """Verify munmap_file unmaps pages and handles shared writeback."""

    def test_private_munmap_removes_pages(self) -> None:
        """Unmapping a private region should remove its page table entries."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        assert proc.virtual_memory is not None
        pages_before = len(proc.virtual_memory.page_table.mappings())
        kernel.munmap_file(pid=proc.pid, virtual_address=addr)
        pages_after = len(proc.virtual_memory.page_table.mappings())
        assert pages_after == pages_before - 1

    def test_private_munmap_frees_frames(self) -> None:
        """Unmapping a private region should return frames to the free pool."""
        kernel, path = _kernel_with_file(b"data")
        assert kernel.memory is not None
        proc = kernel.create_process(name="proc", num_pages=1)
        kernel.mmap_file(pid=proc.pid, path=path)
        free_before = kernel.memory.free_frames
        kernel.munmap_file(pid=proc.pid, virtual_address=proc.virtual_memory.page_size)  # type: ignore[union-attr]
        assert kernel.memory.free_frames == free_before + 1

    def test_private_munmap_removes_region(self) -> None:
        """Unmapping should remove the region from kernel tracking."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        kernel.munmap_file(pid=proc.pid, virtual_address=addr)
        assert not kernel.mmap_regions(proc.pid)

    def test_shared_munmap_writes_back_to_file(self) -> None:
        """Unmapping a shared region should write data back to the file."""
        kernel, path = _kernel_with_file(b"original")
        assert kernel.filesystem is not None
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path, shared=True)
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(virtual_address=addr, data=b"CHANGED!")
        kernel.munmap_file(pid=proc.pid, virtual_address=addr)
        assert kernel.filesystem.read(path) == b"CHANGED!"

    def test_shared_munmap_with_two_mappers_preserves_other(self) -> None:
        """Unmapping one sharer should not affect the other's access."""
        kernel, path = _kernel_with_file(b"shared")
        p1 = kernel.create_process(name="p1", num_pages=1)
        p2 = kernel.create_process(name="p2", num_pages=1)
        addr1 = kernel.mmap_file(pid=p1.pid, path=path, shared=True)
        addr2 = kernel.mmap_file(pid=p2.pid, path=path, shared=True)

        kernel.munmap_file(pid=p1.pid, virtual_address=addr1)

        # p2 should still be able to read the data
        assert p2.virtual_memory is not None
        result = p2.virtual_memory.read(virtual_address=addr2, size=6)
        assert result == b"shared"

    def test_munmap_invalid_address_raises(self) -> None:
        """Unmapping an address that isn't a mapped region should raise."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="proc", num_pages=1)
        nonexistent_addr = 9999
        with pytest.raises(MmapError, match="No mmap region"):
            kernel.munmap_file(pid=proc.pid, virtual_address=nonexistent_addr)

    def test_munmap_invalid_pid_raises(self) -> None:
        """Unmapping with an invalid PID should raise."""
        kernel = _booted_kernel()
        nonexistent = 999
        with pytest.raises(MmapError, match="not found"):
            kernel.munmap_file(pid=nonexistent, virtual_address=0)


# ---------------------------------------------------------------------------
# Cycle 5: msync_file
# ---------------------------------------------------------------------------


class TestMsync:
    """Verify msync_file writes shared mapping data back to the file."""

    def test_msync_writes_shared_data_to_file(self) -> None:
        """Msync should write modified shared data back to the file."""
        kernel, path = _kernel_with_file(b"original")
        assert kernel.filesystem is not None
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path, shared=True)
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(virtual_address=addr, data=b"SYNCED!!")
        kernel.msync_file(pid=proc.pid, virtual_address=addr)
        assert kernel.filesystem.read(path) == b"SYNCED!!"

    def test_msync_on_private_raises(self) -> None:
        """Msync on a private mapping should raise MmapError."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path)
        with pytest.raises(MmapError, match="private"):
            kernel.msync_file(pid=proc.pid, virtual_address=addr)

    def test_msync_preserves_mapping(self) -> None:
        """After msync, the mapping should still be active."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path, shared=True)
        kernel.msync_file(pid=proc.pid, virtual_address=addr)
        # Mapping still tracked
        assert proc.virtual_memory is not None
        vpn = addr // proc.virtual_memory.page_size
        assert vpn in kernel.mmap_regions(proc.pid)
        # Can still read data
        result = proc.virtual_memory.read(virtual_address=addr, size=4)
        assert result == b"data"

    def test_msync_invalid_address_raises(self) -> None:
        """Msync with invalid address should raise MmapError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="proc", num_pages=1)
        nonexistent_addr = 9999
        with pytest.raises(MmapError, match="No mmap region"):
            kernel.msync_file(pid=proc.pid, virtual_address=nonexistent_addr)


# ---------------------------------------------------------------------------
# Cycle 6: Fork interaction
# ---------------------------------------------------------------------------


class TestMmapFork:
    """Verify mmap regions interact correctly with fork."""

    def test_private_mmap_cow_on_fork(self) -> None:
        """Private mmap pages should be COW-marked after fork."""
        kernel, path = _kernel_with_file(b"data")
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.mmap_file(pid=parent.pid, path=path)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None
        assert parent.virtual_memory is not None
        # The mmap vpn should be COW-marked on both sides
        mmap_vpn = 1  # vpn 0 is the process page, vpn 1 is the mmap page
        assert parent.virtual_memory.is_cow(virtual_page=mmap_vpn)
        assert child.virtual_memory.is_cow(virtual_page=mmap_vpn)

    def test_private_mmap_fork_write_isolation(self) -> None:
        """Writing to private mmap in child should not affect parent."""
        kernel, path = _kernel_with_file(b"original")
        parent = kernel.create_process(name="parent", num_pages=1)
        addr = kernel.mmap_file(pid=parent.pid, path=path)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert parent.virtual_memory is not None
        assert child.virtual_memory is not None
        child.virtual_memory.write(virtual_address=addr, data=b"CHILD!!!")
        parent_data = parent.virtual_memory.read(virtual_address=addr, size=8)
        assert parent_data == b"original"

    def test_shared_mmap_stays_shared_on_fork(self) -> None:
        """Shared mmap pages should NOT be COW-marked after fork."""
        kernel, path = _kernel_with_file(b"shared")
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.mmap_file(pid=parent.pid, path=path, shared=True)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert parent.virtual_memory is not None
        assert child.virtual_memory is not None
        mmap_vpn = 1  # vpn 0 is process page, vpn 1 is mmap page
        assert not parent.virtual_memory.is_cow(virtual_page=mmap_vpn)
        assert not child.virtual_memory.is_cow(virtual_page=mmap_vpn)

    def test_shared_mmap_fork_write_visible_to_both(self) -> None:
        """Writing to shared mmap in child should be visible in parent."""
        kernel, path = _kernel_with_file(b"original")
        parent = kernel.create_process(name="parent", num_pages=1)
        addr = kernel.mmap_file(pid=parent.pid, path=path, shared=True)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert parent.virtual_memory is not None
        assert child.virtual_memory is not None
        child.virtual_memory.write(virtual_address=addr, data=b"VISIBLE!")
        parent_data = parent.virtual_memory.read(virtual_address=addr, size=8)
        assert parent_data == b"VISIBLE!"

    def test_child_inherits_mmap_regions(self) -> None:
        """Fork should copy mmap region metadata to the child."""
        kernel, path = _kernel_with_file(b"data")
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.mmap_file(pid=parent.pid, path=path)
        child = kernel.fork_process(parent_pid=parent.pid)
        child_regions = kernel.mmap_regions(child.pid)
        parent_regions = kernel.mmap_regions(parent.pid)
        assert len(child_regions) == len(parent_regions)
        for vpn, region in parent_regions.items():
            assert vpn in child_regions
            assert child_regions[vpn].path == region.path


# ---------------------------------------------------------------------------
# Cycle 7: Terminate cleanup
# ---------------------------------------------------------------------------


class TestMmapTerminate:
    """Verify terminate cleans up mmap regions."""

    def test_terminate_cleans_private_mmap(self) -> None:
        """Terminating a process should remove private mmap regions."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        kernel.mmap_file(pid=proc.pid, path=path)
        assert kernel.mmap_regions(proc.pid)
        # SIGKILL works from any state (force_terminate)
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert not kernel.mmap_regions(proc.pid)

    def test_terminate_syncs_shared_mmap(self) -> None:
        """Terminating with a shared mapping should write back to the file."""
        kernel, path = _kernel_with_file(b"original")
        assert kernel.filesystem is not None
        proc = kernel.create_process(name="proc", num_pages=1)
        addr = kernel.mmap_file(pid=proc.pid, path=path, shared=True)
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(virtual_address=addr, data=b"TERMSYNC")
        # Dispatch→running, then terminate
        proc.dispatch()
        kernel.terminate_process(pid=proc.pid)
        assert kernel.filesystem.read(path) == b"TERMSYNC"

    def test_sigkill_cleans_mmap(self) -> None:
        """SIGKILL should clean up mmap regions."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        kernel.mmap_file(pid=proc.pid, path=path)
        assert kernel.mmap_regions(proc.pid)
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert not kernel.mmap_regions(proc.pid)


# ---------------------------------------------------------------------------
# Cycle 8: Syscalls + Shell
# ---------------------------------------------------------------------------


class TestMmapSyscall:
    """Verify mmap operations through the syscall interface."""

    def test_sys_mmap_returns_address(self) -> None:
        """SYS_MMAP should return a dict with virtual_address and num_pages."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        result = kernel.syscall(
            SyscallNumber.SYS_MMAP,
            pid=proc.pid,
            path=path,
        )
        assert "virtual_address" in result
        assert "num_pages" in result
        assert result["num_pages"] == 1

    def test_sys_mmap_shared(self) -> None:
        """SYS_MMAP with shared=True should create a shared mapping."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        result = kernel.syscall(
            SyscallNumber.SYS_MMAP,
            pid=proc.pid,
            path=path,
            shared=True,
        )
        assert proc.virtual_memory is not None
        vpn = result["virtual_address"] // proc.virtual_memory.page_size
        assert kernel.mmap_regions(proc.pid)[vpn].shared is True

    def test_sys_mmap_error_wraps(self) -> None:
        """SYS_MMAP with bad path should raise SyscallError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="proc", num_pages=1)
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_MMAP,
                pid=proc.pid,
                path="/nope",
            )

    def test_sys_munmap(self) -> None:
        """SYS_MUNMAP should unmap a region."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        result = kernel.syscall(
            SyscallNumber.SYS_MMAP,
            pid=proc.pid,
            path=path,
        )
        kernel.syscall(
            SyscallNumber.SYS_MUNMAP,
            pid=proc.pid,
            virtual_address=result["virtual_address"],
        )
        assert not kernel.mmap_regions(proc.pid)

    def test_sys_msync(self) -> None:
        """SYS_MSYNC should write shared data back to the file."""
        kernel, path = _kernel_with_file(b"original")
        assert kernel.filesystem is not None
        proc = kernel.create_process(name="proc", num_pages=1)
        result = kernel.syscall(
            SyscallNumber.SYS_MMAP,
            pid=proc.pid,
            path=path,
            shared=True,
        )
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(
            virtual_address=result["virtual_address"],
            data=b"SYNCED!!",
        )
        kernel.syscall(
            SyscallNumber.SYS_MSYNC,
            pid=proc.pid,
            virtual_address=result["virtual_address"],
        )
        assert kernel.filesystem.read(path) == b"SYNCED!!"

    def test_sys_msync_error_wraps(self) -> None:
        """SYS_MSYNC on private mapping should raise SyscallError."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        result = kernel.syscall(
            SyscallNumber.SYS_MMAP,
            pid=proc.pid,
            path=path,
        )
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_MSYNC,
                pid=proc.pid,
                virtual_address=result["virtual_address"],
            )


class TestMmapShell:
    """Verify mmap shell commands."""

    def test_mmap_command(self) -> None:
        """Shell mmap should map a file and show address."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"mmap {proc.pid} {path}")
        assert "Mapped" in result
        assert path in result

    def test_mmap_shared_command(self) -> None:
        """Shell mmap --shared should create a shared mapping."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"mmap {proc.pid} {path} --shared")
        assert "Mapped" in result

    def test_mmap_no_args_shows_usage(self) -> None:
        """Shell mmap without arguments should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("mmap")
        assert "Usage" in result

    def test_munmap_command(self) -> None:
        """Shell munmap should unmap a region."""
        kernel, path = _kernel_with_file(b"data")
        proc = kernel.create_process(name="proc", num_pages=1)
        shell = Shell(kernel=kernel)
        shell.execute(f"mmap {proc.pid} {path}")
        assert proc.virtual_memory is not None
        start_vpn = max(proc.virtual_memory.page_table.mappings())
        addr = start_vpn * proc.virtual_memory.page_size
        result = shell.execute(f"munmap {proc.pid} {addr}")
        assert "Unmapped" in result

    def test_msync_command(self) -> None:
        """Shell msync should sync shared data back."""
        kernel, path = _kernel_with_file(b"original")
        assert kernel.filesystem is not None
        proc = kernel.create_process(name="proc", num_pages=1)
        shell = Shell(kernel=kernel)
        shell.execute(f"mmap {proc.pid} {path} --shared")
        assert proc.virtual_memory is not None
        start_vpn = max(proc.virtual_memory.page_table.mappings())
        addr = start_vpn * proc.virtual_memory.page_size
        proc.virtual_memory.write(virtual_address=addr, data=b"SHELLSYN")
        result = shell.execute(f"msync {proc.pid} {addr}")
        assert "Synced" in result
        assert kernel.filesystem.read(path) == b"SHELLSYN"

    def test_help_includes_mmap_commands(self) -> None:
        """Help should list mmap, munmap, and msync commands."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "mmap" in result
        assert "munmap" in result
        assert "msync" in result
