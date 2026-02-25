"""Tests for the kernel logging and audit system.

The logger records structured log entries for system events.
It provides an audit trail of what happened, when, and who did it.
"""

from py_os.kernel import ExecutionMode, Kernel
from py_os.logging import LogEntry, Logger, LogLevel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


class TestLogLevel:
    """Verify log level ordering."""

    def test_levels_are_ordered(self) -> None:
        """DEBUG < INFO < WARNING < ERROR."""
        assert LogLevel.DEBUG < LogLevel.INFO
        assert LogLevel.INFO < LogLevel.WARNING
        assert LogLevel.WARNING < LogLevel.ERROR


class TestLogEntry:
    """Verify log entry structure."""

    def test_entry_has_fields(self) -> None:
        """A log entry should store level, message, source, and uid."""
        entry = LogEntry(
            level=LogLevel.INFO,
            message="test message",
            source="test",
            uid=0,
        )
        assert entry.level is LogLevel.INFO
        assert entry.message == "test message"
        assert entry.source == "test"
        assert entry.uid == 0

    def test_entry_str(self) -> None:
        """String representation should include level and message."""
        entry = LogEntry(
            level=LogLevel.WARNING,
            message="disk full",
            source="fs",
            uid=1,
        )
        text = str(entry)
        assert "WARNING" in text
        assert "disk full" in text


class TestLogger:
    """Verify the logger."""

    def test_log_stores_entries(self) -> None:
        """Logged entries should be retrievable."""
        logger = Logger()
        logger.log(LogLevel.INFO, "booted", source="kernel")
        assert len(logger.entries) == 1
        assert logger.entries[0].message == "booted"

    def test_log_with_uid(self) -> None:
        """Entries should record the uid."""
        logger = Logger()
        logger.log(LogLevel.INFO, "file read", source="syscall", uid=42)
        expected_uid = 42
        assert logger.entries[0].uid == expected_uid

    def test_entries_are_ordered(self) -> None:
        """Entries should be in chronological order."""
        logger = Logger()
        logger.log(LogLevel.INFO, "first", source="test")
        logger.log(LogLevel.INFO, "second", source="test")
        assert logger.entries[0].message == "first"
        assert logger.entries[1].message == "second"

    def test_filter_by_level(self) -> None:
        """Filtering should return only entries at or above the level."""
        logger = Logger()
        logger.log(LogLevel.DEBUG, "debug msg", source="test")
        logger.log(LogLevel.INFO, "info msg", source="test")
        logger.log(LogLevel.ERROR, "error msg", source="test")
        warnings_and_above = logger.filter(min_level=LogLevel.WARNING)
        assert len(warnings_and_above) == 1
        assert warnings_and_above[0].level is LogLevel.ERROR

    def test_filter_by_source(self) -> None:
        """Filtering by source should return matching entries."""
        logger = Logger()
        logger.log(LogLevel.INFO, "kernel event", source="kernel")
        logger.log(LogLevel.INFO, "syscall event", source="syscall")
        kernel_logs = logger.filter(source="kernel")
        assert len(kernel_logs) == 1
        assert kernel_logs[0].source == "kernel"

    def test_clear(self) -> None:
        """Clearing should remove all entries."""
        logger = Logger()
        logger.log(LogLevel.INFO, "test", source="test")
        logger.clear()
        assert len(logger.entries) == 0


class TestKernelLogging:
    """Verify that the kernel logs events."""

    def test_kernel_has_logger_after_boot(self) -> None:
        """The kernel should have a logger after booting."""
        kernel = _booted_kernel()
        assert kernel.logger is not None

    def test_boot_is_logged(self) -> None:
        """Booting should produce log entries."""
        kernel = _booted_kernel()
        assert kernel.logger is not None
        assert any("boot" in e.message.lower() for e in kernel.logger.entries)

    def test_syscall_is_logged(self) -> None:
        """Syscalls should produce log entries."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert kernel.logger is not None
        assert any("SYS_LIST_PROCESSES" in e.message for e in kernel.logger.entries)

    def test_logger_none_after_shutdown(self) -> None:
        """The logger should be torn down after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.logger is None


class TestShellLogCommand:
    """Verify the shell's log command."""

    def test_log_shows_recent_entries(self) -> None:
        """The log command should display recent log entries."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("log")
        assert "boot" in result.lower() or "INFO" in result

    def test_help_includes_log(self) -> None:
        """Help should list the log command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "log" in result
