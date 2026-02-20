"""Tests for the system call interface.

System calls are the controlled gateway between user-space and
kernel-space.  Instead of reaching directly into kernel subsystems,
user programs invoke numbered operations via kernel.syscall().

The kernel validates each request, dispatches to the right subsystem,
and returns a result — just like a real OS trap handler.
"""

import pytest

from py_os.kernel import Kernel
from py_os.process import ProcessState
from py_os.syscalls import SyscallError, SyscallNumber

NUM_PAGES = 2
DEFAULT_TOTAL_FRAMES = 64


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


class TestSyscallProcessOps:
    """Verify process-related system calls."""

    def test_create_process(self) -> None:
        """SYS_CREATE_PROCESS should create and return a process."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="init",
            num_pages=NUM_PAGES,
        )
        assert result["pid"] > 0
        assert result["name"] == "init"
        assert result["state"] == ProcessState.READY

    def test_list_processes(self) -> None:
        """SYS_LIST_PROCESSES should return all processes."""
        kernel = _booted_kernel()
        kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="daemon",
            num_pages=NUM_PAGES,
        )
        result = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert len(result) == 1
        assert result[0]["name"] == "daemon"

    def test_list_processes_empty(self) -> None:
        """SYS_LIST_PROCESSES with no processes returns empty list."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert result == []

    def test_terminate_process(self) -> None:
        """SYS_TERMINATE_PROCESS should terminate by PID."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="victim",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        # Dispatch so it's RUNNING (required for termination)
        assert kernel.scheduler is not None
        kernel.scheduler.dispatch()
        kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=pid)
        procs = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert all(p["pid"] != pid for p in procs)

    def test_terminate_nonexistent_process(self) -> None:
        """Terminating a non-existent PID should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=999)


class TestSyscallFileOps:
    """Verify file-system-related system calls."""

    def test_create_file(self) -> None:
        """SYS_CREATE_FILE should create a file at the given path."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/hello.txt")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "hello.txt" in result

    def test_create_dir(self) -> None:
        """SYS_CREATE_DIR should create a directory."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/docs")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "docs" in result

    def test_write_and_read_file(self) -> None:
        """SYS_WRITE_FILE and SYS_READ_FILE round-trip data."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/msg.txt")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/msg.txt",
            data=b"hello kernel",
        )
        result = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/msg.txt")
        assert result == b"hello kernel"

    def test_delete_file(self) -> None:
        """SYS_DELETE_FILE should remove a file."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/temp.txt")
        kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/temp.txt")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "temp.txt" not in result

    def test_read_nonexistent_file(self) -> None:
        """Reading a non-existent file should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/nope.txt")

    def test_list_dir(self) -> None:
        """SYS_LIST_DIR should return directory contents."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/a.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/b.txt")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "a.txt" in result
        assert "b.txt" in result


class TestSyscallMemoryOps:
    """Verify memory-related system calls."""

    def test_memory_info(self) -> None:
        """SYS_MEMORY_INFO should return memory statistics."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
        assert "total_frames" in result
        assert "free_frames" in result
        assert result["total_frames"] == DEFAULT_TOTAL_FRAMES
        assert result["free_frames"] == DEFAULT_TOTAL_FRAMES

    def test_memory_info_after_allocation(self) -> None:
        """Free frames should decrease after process creation."""
        kernel = _booted_kernel()
        kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="hog",
            num_pages=NUM_PAGES,
        )
        result = kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
        expected_free = 62
        assert result["free_frames"] == expected_free


class TestSyscallValidation:
    """Verify that syscalls validate inputs and kernel state."""

    def test_syscall_before_boot_raises(self) -> None:
        """Syscalls should fail if the kernel isn't running."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)

    def test_unknown_syscall_raises(self) -> None:
        """An invalid syscall number should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="Unknown syscall"):
            kernel.syscall(999)  # type: ignore[arg-type]
