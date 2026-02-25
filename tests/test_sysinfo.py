"""Tests for the system information / monitoring module.

The sysinfo syscall aggregates status from all kernel subsystems
into a single snapshot — like ``top`` or ``/proc`` in Linux.
"""

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


class TestSyscallSysinfo:
    """Verify the SYS_SYSINFO syscall."""

    def test_sysinfo_returns_dict(self) -> None:
        """Sysinfo should return a dict with system stats."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        assert isinstance(info, dict)

    def test_sysinfo_has_uptime(self) -> None:
        """Sysinfo should include uptime."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        assert "uptime" in info
        min_uptime = 0.0
        assert info["uptime"] > min_uptime

    def test_sysinfo_has_memory(self) -> None:
        """Sysinfo should include memory stats."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        assert "memory_total" in info
        assert "memory_free" in info
        assert info["memory_total"] == info["memory_free"]  # no processes yet

    def test_sysinfo_has_process_count(self) -> None:
        """Sysinfo should include the number of processes (init always present)."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        expected_count = 1  # init process
        assert info["process_count"] == expected_count

    def test_sysinfo_process_count_after_create(self) -> None:
        """Process count should reflect created processes plus init."""
        kernel = _booted_kernel()
        kernel.create_process(name="test", num_pages=2)
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        expected_count = 2  # init + created process
        assert info["process_count"] == expected_count

    def test_sysinfo_has_device_count(self) -> None:
        """Sysinfo should include the number of devices."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        min_devices = 3  # null, console, random
        assert info["device_count"] >= min_devices

    def test_sysinfo_has_user_info(self) -> None:
        """Sysinfo should include user info."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        assert "current_user" in info
        assert info["current_user"] == "root"

    def test_sysinfo_has_env_count(self) -> None:
        """Sysinfo should include the number of environment variables."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        min_vars = 3  # PATH, HOME, USER
        assert info["env_count"] >= min_vars

    def test_sysinfo_has_log_count(self) -> None:
        """Sysinfo should include the number of log entries."""
        kernel = _booted_kernel()
        info = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        # At least the boot message
        min_entries = 1
        assert info["log_count"] >= min_entries

    def test_sysinfo_memory_changes_after_allocation(self) -> None:
        """Free memory should decrease after process creation."""
        kernel = _booted_kernel()
        info_before = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        num_pages = 4
        kernel.create_process(name="test", num_pages=num_pages)
        info_after = kernel.syscall(SyscallNumber.SYS_SYSINFO)
        assert info_after["memory_free"] == info_before["memory_free"] - num_pages


class TestShellTopCommand:
    """Verify the shell's top command."""

    def test_top_shows_system_info(self) -> None:
        """Top should display system status information."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("top")
        assert "uptime" in result.lower() or "Uptime" in result
        assert "memory" in result.lower() or "Memory" in result

    def test_top_shows_processes(self) -> None:
        """Top should show process count."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("top")
        assert "process" in result.lower() or "Process" in result

    def test_help_includes_top(self) -> None:
        """Help should list the top command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "top" in result
