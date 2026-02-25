"""Tests for file descriptors — per-process fd tables and open file tracking.

In real operating systems, programs interact with files through **file
descriptors** (small integers).  You ``open()`` a file to get an fd,
``read()``/``write()`` through that fd (which tracks your position),
``seek()`` to jump around, and ``close()`` when done.

This module tests the low-level data structures (``FdError``,
``SeekWhence``, ``FileMode``, ``OpenFileDescription``, ``FdTable``)
as well as kernel-level fd integration.
"""

import pytest

from py_os.fs.fd import FdError, FdTable, FileMode, OpenFileDescription, SeekWhence
from py_os.kernel import ExecutionMode, Kernel
from py_os.process.signals import Signal
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# -- Data structure basics ---------------------------------------------------


class TestFdDataStructures:
    """Verify the fd enums, error, and OpenFileDescription dataclass."""

    def test_fd_error_is_an_exception(self) -> None:
        """FdError should be a standard exception."""
        with pytest.raises(FdError, match="bad fd"):
            raise FdError("bad fd")

    def test_seek_whence_values(self) -> None:
        """SeekWhence should have set, cur, and end members."""
        expected_count = 3
        assert len(SeekWhence) == expected_count
        assert SeekWhence.SET == "set"
        assert SeekWhence.CUR == "cur"
        assert SeekWhence.END == "end"

    def test_file_mode_values(self) -> None:
        """FileMode should have r, w, and rw members."""
        expected_count = 3
        assert len(FileMode) == expected_count
        assert FileMode.READ == "r"
        assert FileMode.WRITE == "w"
        assert FileMode.READ_WRITE == "rw"

    def test_open_file_description_defaults(self) -> None:
        """OpenFileDescription should default offset=0 and inode_number=0."""
        ofd = OpenFileDescription(path="/hello.txt", mode=FileMode.READ)
        assert ofd.path == "/hello.txt"
        assert ofd.mode is FileMode.READ
        assert ofd.offset == 0
        assert ofd.inode_number == 0

    def test_open_file_description_offset_is_mutable(self) -> None:
        """The offset field must be mutable (not frozen)."""
        ofd = OpenFileDescription(path="/data.bin", mode=FileMode.WRITE)
        ofd.offset = 42
        expected_offset = 42
        assert ofd.offset == expected_offset


# -- FdTable -----------------------------------------------------------------


class TestFdTable:
    """Verify fd allocation, lookup, close, reuse, listing, and duplication."""

    def test_first_allocation_starts_at_three(self) -> None:
        """The first fd should be 3 (0-2 reserved for stdin/out/err)."""
        table = FdTable()
        ofd = OpenFileDescription(path="/a.txt", mode=FileMode.READ)
        fd = table.allocate(ofd)
        first_fd = 3
        assert fd == first_fd

    def test_sequential_allocation(self) -> None:
        """Consecutive allocations should produce 3, 4, 5, …."""
        table = FdTable()
        fds = [
            table.allocate(OpenFileDescription(path=f"/f{i}.txt", mode=FileMode.READ))
            for i in range(3)
        ]
        assert fds == [3, 4, 5]

    def test_lookup_returns_correct_ofd(self) -> None:
        """Lookup should return the exact OpenFileDescription for a given fd."""
        table = FdTable()
        ofd = OpenFileDescription(path="/data.txt", mode=FileMode.WRITE)
        fd = table.allocate(ofd)
        assert table.lookup(fd) is ofd

    def test_lookup_missing_fd_raises(self) -> None:
        """Looking up a non-existent fd should raise FdError."""
        table = FdTable()
        bad_fd = 99
        with pytest.raises(FdError, match="Bad file descriptor"):
            table.lookup(bad_fd)

    def test_close_removes_fd(self) -> None:
        """After close, looking up the fd should raise."""
        table = FdTable()
        fd = table.allocate(OpenFileDescription(path="/a.txt", mode=FileMode.READ))
        table.close(fd)
        with pytest.raises(FdError):
            table.lookup(fd)

    def test_close_missing_fd_raises(self) -> None:
        """Closing a non-existent fd should raise FdError."""
        table = FdTable()
        bad_fd = 42
        with pytest.raises(FdError, match="Bad file descriptor"):
            table.close(bad_fd)

    def test_closed_fd_is_reused(self) -> None:
        """After closing fd 3, the next allocation should reuse 3."""
        table = FdTable()
        fd3 = table.allocate(OpenFileDescription(path="/a.txt", mode=FileMode.READ))
        _fd4 = table.allocate(OpenFileDescription(path="/b.txt", mode=FileMode.READ))
        table.close(fd3)
        fd_reused = table.allocate(OpenFileDescription(path="/c.txt", mode=FileMode.READ))
        first_fd = 3
        assert fd_reused == first_fd

    def test_list_fds_returns_snapshot(self) -> None:
        """list_fds should return a dict of all open fds."""
        table = FdTable()
        ofd_a = OpenFileDescription(path="/a.txt", mode=FileMode.READ)
        ofd_b = OpenFileDescription(path="/b.txt", mode=FileMode.WRITE)
        table.allocate(ofd_a)
        table.allocate(ofd_b)
        fds = table.list_fds()
        expected_count = 2
        assert len(fds) == expected_count
        first_fd = 3
        assert fds[first_fd] is ofd_a

    def test_duplicate_creates_independent_copy(self) -> None:
        """Duplicated table should have same fds but independent offsets."""
        table = FdTable()
        ofd = OpenFileDescription(path="/a.txt", mode=FileMode.READ, offset=10)
        fd = table.allocate(ofd)
        copy = table.duplicate()
        # Same fd numbers and paths
        copy_ofd = copy.lookup(fd)
        assert copy_ofd.path == "/a.txt"
        original_offset = 10
        assert copy_ofd.offset == original_offset
        # But independent — changing one doesn't affect the other
        copy_ofd.offset = 99
        assert ofd.offset == original_offset


# -- Kernel fd integration ---------------------------------------------------


def _booted_kernel_with_file(path: str = "/data.txt", content: bytes = b"Hello, world!") -> Kernel:
    """Return a booted kernel with a file already created and written."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    assert kernel.filesystem is not None
    kernel.filesystem.create_file(path)
    kernel.filesystem.write(path, content)
    # Create a process so we have a valid pid
    kernel.create_process(name="test", num_pages=1)
    return kernel


class TestKernelOpen:
    """Verify kernel.open_file() — the fd allocation entry point."""

    def test_open_returns_fd_starting_at_three(self) -> None:
        """The first open should return fd 3."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        first_fd = 3
        assert fd == first_fd

    def test_open_nonexistent_file_raises(self) -> None:
        """Opening a path that doesn't exist should raise FdError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        with pytest.raises(FdError, match="not found"):
            kernel.open_file(pid, "/nope.txt", FileMode.READ)

    def test_open_directory_raises(self) -> None:
        """Opening a directory should raise FdError."""
        kernel = _booted_kernel_with_file()
        assert kernel.filesystem is not None
        kernel.filesystem.create_dir("/mydir")
        pid = next(iter(kernel.processes))
        with pytest.raises(FdError, match="directory"):
            kernel.open_file(pid, "/mydir", FileMode.READ)

    def test_open_bad_pid_raises(self) -> None:
        """Opening a file for a nonexistent process should raise FdError."""
        kernel = _booted_kernel_with_file()
        bad_pid = 9999
        with pytest.raises(FdError, match="not found"):
            kernel.open_file(bad_pid, "/data.txt", FileMode.READ)


class TestKernelClose:
    """Verify kernel.close_file() — releasing an fd."""

    def test_close_valid_fd(self) -> None:
        """Closing a valid fd should succeed without error."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        kernel.close_file(pid, fd)

    def test_close_invalid_fd_raises(self) -> None:
        """Closing an fd that was never opened should raise FdError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        bad_fd = 99
        with pytest.raises(FdError):
            kernel.close_file(pid, bad_fd)


class TestKernelReadFd:
    """Verify kernel.read_fd() — reading through a file descriptor."""

    def test_read_returns_bytes(self) -> None:
        """Reading from a valid fd should return file data."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        data = kernel.read_fd(pid, fd, count=5)
        assert data == b"Hello"

    def test_read_advances_offset(self) -> None:
        """Sequential reads should advance the offset."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        first = kernel.read_fd(pid, fd, count=5)
        second = kernel.read_fd(pid, fd, count=2)
        assert first == b"Hello"
        assert second == b", "

    def test_read_write_only_fd_raises(self) -> None:
        """Reading from a write-only fd should raise FdError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.WRITE)
        with pytest.raises(FdError, match="not readable"):
            kernel.read_fd(pid, fd, count=5)

    def test_read_rw_fd_succeeds(self) -> None:
        """Reading from a read-write fd should work."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ_WRITE)
        data = kernel.read_fd(pid, fd, count=5)
        assert data == b"Hello"


class TestKernelWriteFd:
    """Verify kernel.write_fd() — writing through a file descriptor."""

    def test_write_updates_file(self) -> None:
        """Writing through an fd should modify the file on disk."""
        kernel = _booted_kernel_with_file()
        assert kernel.filesystem is not None
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.WRITE)
        kernel.write_fd(pid, fd, b"Jello")
        assert kernel.filesystem.read("/data.txt") == b"Jello, world!"

    def test_write_advances_offset(self) -> None:
        """After writing, the offset should advance by the number of bytes."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.WRITE)
        kernel.write_fd(pid, fd, b"Hey")
        # Offset should be at 3 now — write again
        kernel.write_fd(pid, fd, b"!!")
        assert kernel.filesystem is not None
        assert kernel.filesystem.read("/data.txt") == b"Hey!!, world!"

    def test_write_read_only_fd_raises(self) -> None:
        """Writing to a read-only fd should raise FdError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        with pytest.raises(FdError, match="not writable"):
            kernel.write_fd(pid, fd, b"nope")

    def test_write_rw_fd_succeeds(self) -> None:
        """Writing to a read-write fd should work."""
        kernel = _booted_kernel_with_file()
        assert kernel.filesystem is not None
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ_WRITE)
        kernel.write_fd(pid, fd, b"Yo")
        assert kernel.filesystem.read("/data.txt") == b"Yollo, world!"


class TestKernelSeek:
    """Verify kernel.seek_fd() — repositioning the file offset."""

    def test_seek_set(self) -> None:
        """SeekWhence.SET should set an absolute offset."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        new_offset = kernel.seek_fd(pid, fd, offset=7, whence=SeekWhence.SET)
        expected_offset = 7
        assert new_offset == expected_offset
        data = kernel.read_fd(pid, fd, count=5)
        assert data == b"world"

    def test_seek_cur(self) -> None:
        """SeekWhence.CUR should move relative to the current position."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        kernel.read_fd(pid, fd, count=5)  # offset now at 5
        new_offset = kernel.seek_fd(pid, fd, offset=2, whence=SeekWhence.CUR)
        expected_offset = 7
        assert new_offset == expected_offset

    def test_seek_end(self) -> None:
        """SeekWhence.END should offset from the end of the file."""
        kernel = _booted_kernel_with_file(content=b"Hello, world!")
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        # File is 13 bytes; seek to 1 before the end
        new_offset = kernel.seek_fd(pid, fd, offset=-1, whence=SeekWhence.END)
        expected_offset = 12
        assert new_offset == expected_offset
        data = kernel.read_fd(pid, fd, count=1)
        assert data == b"!"

    def test_seek_negative_offset_raises(self) -> None:
        """Seeking to a negative absolute position should raise FdError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        with pytest.raises(FdError, match=r"[Nn]egative"):
            kernel.seek_fd(pid, fd, offset=-1, whence=SeekWhence.SET)


class TestKernelListFds:
    """Verify kernel.list_fds() — listing open fds for a process."""

    def test_list_fds_empty(self) -> None:
        """A process with no open fds should return an empty dict."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fds = kernel.list_fds(pid)
        assert fds == {}

    def test_list_fds_shows_open_files(self) -> None:
        """Open fds should appear in the listing."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        kernel.open_file(pid, "/data.txt", FileMode.READ)
        fds = kernel.list_fds(pid)
        first_fd = 3
        assert first_fd in fds
        assert fds[first_fd].path == "/data.txt"


# -- Cleanup and fork -------------------------------------------------------


class TestFdCleanup:
    """Verify fd tables are cleaned up on process termination and shutdown."""

    def test_terminate_cleans_up_fds(self) -> None:
        """Terminating a process should remove its fd table."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        kernel.open_file(pid, "/data.txt", FileMode.READ)
        # Process must be RUNNING to terminate
        proc = kernel.processes[pid]
        proc.dispatch()
        kernel.terminate_process(pid=pid)
        assert kernel.list_fds(pid) == {}

    def test_sigkill_cleans_up_fds(self) -> None:
        """SIGKILL should clean up the process's fd table."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        kernel.open_file(pid, "/data.txt", FileMode.READ)
        # Process needs to be dispatchable — READY is fine for SIGKILL
        kernel.send_signal(pid, Signal.SIGKILL)
        assert kernel.list_fds(pid) == {}

    def test_run_process_cleans_up_fds(self) -> None:
        """run_process should clean up fds after execution."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
        assert kernel.filesystem is not None
        kernel.filesystem.create_file("/data.txt")
        kernel.filesystem.write("/data.txt", b"test")
        proc = kernel.create_process(name="runner", num_pages=1)
        pid = proc.pid
        kernel.open_file(pid, "/data.txt", FileMode.READ)
        kernel.exec_process(pid=pid, program=lambda: "done")
        kernel.run_process(pid=pid)
        assert kernel.list_fds(pid) == {}

    def test_shutdown_clears_all_fd_tables(self) -> None:
        """Shutdown should clear the fd tables dict."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        kernel.open_file(pid, "/data.txt", FileMode.READ)
        kernel.shutdown()
        # After shutdown, kernel state is reset — no fd tables should remain
        # We verify by checking the internal dict directly
        assert kernel._fd_tables == {}


class TestFdFork:
    """Verify fd tables are copied on fork with independent offsets."""

    def test_fork_copies_fd_table(self) -> None:
        """Forking should give the child the same open fds."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        child = kernel.fork_process(parent_pid=pid)
        child_fds = kernel.list_fds(child.pid)
        assert fd in child_fds
        assert child_fds[fd].path == "/data.txt"

    def test_fork_offsets_are_independent(self) -> None:
        """After fork, reading from parent should not affect child's offset."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        fd = kernel.open_file(pid, "/data.txt", FileMode.READ)
        child = kernel.fork_process(parent_pid=pid)
        # Read from parent — advances parent's offset
        kernel.read_fd(pid, fd, count=5)
        # Child's offset should still be 0
        child_fds = kernel.list_fds(child.pid)
        assert child_fds[fd].offset == 0

    def test_fork_without_fds_works(self) -> None:
        """Forking a process with no open fds should produce empty child table."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        child = kernel.fork_process(parent_pid=pid)
        assert kernel.list_fds(child.pid) == {}


# -- Syscall dispatch -------------------------------------------------------


class TestFdSyscall:
    """Verify syscall dispatch for fd operations."""

    def test_sys_open(self) -> None:
        """SYS_OPEN should return an fd in a dict."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        result = kernel.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/data.txt", mode="r")
        first_fd = 3
        assert result["fd"] == first_fd

    def test_sys_close(self) -> None:
        """SYS_CLOSE should succeed for a valid fd."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        result = kernel.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/data.txt", mode="r")
        kernel.syscall(SyscallNumber.SYS_CLOSE, pid=pid, fd=result["fd"])

    def test_sys_read_fd(self) -> None:
        """SYS_READ_FD should return data and count."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        result = kernel.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/data.txt", mode="r")
        read_result = kernel.syscall(SyscallNumber.SYS_READ_FD, pid=pid, fd=result["fd"], count=5)
        assert read_result["data"] == b"Hello"
        expected_count = 5
        assert read_result["count"] == expected_count

    def test_sys_write_fd(self) -> None:
        """SYS_WRITE_FD should return bytes_written."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        result = kernel.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/data.txt", mode="w")
        write_result = kernel.syscall(
            SyscallNumber.SYS_WRITE_FD, pid=pid, fd=result["fd"], data=b"Hey"
        )
        expected_bytes = 3
        assert write_result["bytes_written"] == expected_bytes

    def test_sys_seek(self) -> None:
        """SYS_SEEK should return the new offset."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        result = kernel.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/data.txt", mode="r")
        seek_result = kernel.syscall(
            SyscallNumber.SYS_SEEK,
            pid=pid,
            fd=result["fd"],
            offset=7,
            whence="set",
        )
        expected_offset = 7
        assert seek_result["offset"] == expected_offset

    def test_sys_open_error_wraps_in_syscall_error(self) -> None:
        """Opening a nonexistent file via syscall should raise SyscallError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/nope.txt", mode="r")

    def test_sys_close_error_wraps_in_syscall_error(self) -> None:
        """Closing a bad fd via syscall should raise SyscallError."""
        kernel = _booted_kernel_with_file()
        pid = next(iter(kernel.processes))
        bad_fd = 99
        with pytest.raises(SyscallError, match="Bad file descriptor"):
            kernel.syscall(SyscallNumber.SYS_CLOSE, pid=pid, fd=bad_fd)


# -- Shell commands ----------------------------------------------------------


def _shell_with_file() -> tuple[Shell, int]:
    """Return a shell and the pid of a process with /data.txt written."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    assert kernel.filesystem is not None
    kernel.filesystem.create_file("/data.txt")
    kernel.filesystem.write("/data.txt", b"Hello, world!")
    kernel.create_process(name="test", num_pages=1)
    shell = Shell(kernel=kernel)
    pid = next(iter(kernel.processes))
    return shell, pid


class TestFdShell:
    """Verify shell commands for fd operations."""

    def test_open_command(self) -> None:
        """The open command should report the fd and path."""
        shell, pid = _shell_with_file()
        result = shell.execute(f"open {pid} /data.txt r")
        assert "fd 3" in result
        assert "/data.txt" in result

    def test_close_command(self) -> None:
        """The close command should report success."""
        shell, pid = _shell_with_file()
        shell.execute(f"open {pid} /data.txt r")
        result = shell.execute(f"close {pid} 3")
        assert "Closed fd 3" in result

    def test_readfd_command(self) -> None:
        """The readfd command should display the bytes read."""
        shell, pid = _shell_with_file()
        shell.execute(f"open {pid} /data.txt r")
        result = shell.execute(f"readfd {pid} 3 5")
        assert "Hello" in result

    def test_writefd_command(self) -> None:
        """The writefd command should report bytes written."""
        shell, pid = _shell_with_file()
        shell.execute(f"open {pid} /data.txt w")
        result = shell.execute(f"writefd {pid} 3 Hey!!")
        assert "5 bytes" in result

    def test_seek_command(self) -> None:
        """The seek command should report the new offset."""
        shell, pid = _shell_with_file()
        shell.execute(f"open {pid} /data.txt r")
        result = shell.execute(f"seek {pid} 3 7 set")
        assert "offset 7" in result

    def test_lsfd_command(self) -> None:
        """The lsfd command should display a table of open fds."""
        shell, pid = _shell_with_file()
        shell.execute(f"open {pid} /data.txt r")
        result = shell.execute(f"lsfd {pid}")
        assert "FD" in result
        assert "/data.txt" in result

    def test_open_usage(self) -> None:
        """Calling open with no args should show usage."""
        shell, _pid = _shell_with_file()
        result = shell.execute("open")
        assert "Usage:" in result

    def test_open_error_shows_message(self) -> None:
        """Opening a bad path should show an error message."""
        shell, pid = _shell_with_file()
        result = shell.execute(f"open {pid} /nope.txt r")
        assert "Error:" in result

    def test_lsfd_no_open_fds(self) -> None:
        """Lsfd with no open fds should indicate none are open."""
        shell, pid = _shell_with_file()
        result = shell.execute(f"lsfd {pid}")
        assert "No open" in result or "FD" not in result
