"""Tests for strace mode — syscall tracing for debugging and education.

TDD plan: 8 cycles covering strace state, capture, sanitization,
log management, exclusion, syscall numbers, shell command, and demo/completer.
"""

from __future__ import annotations

import pytest

from py_os.completer import Completer
from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# Named constants for magic numbers
_EXPECTED_SEQUENCE_ONE = 1
_EXPECTED_SEQUENCE_TWO = 2
_EXPECTED_SEQUENCE_THREE = 3
_FIFO_LIMIT = 1000
_OVERFLOW_COUNT = 5
_TRUNCATION_LIMIT = 50
_LONG_STRING_LENGTH = 80
_BYTES_LENGTH = 128
_LONG_LIST_LENGTH = 10
_MAX_LIST_ITEMS = 5
_LONG_DICT_SIZE = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _booted_kernel() -> Kernel:
    """Return a freshly booted kernel."""
    k = Kernel()
    k.boot()
    return k


# ---------------------------------------------------------------------------
# Cycle 1 — Strace state management
# ---------------------------------------------------------------------------


class TestStraceState:
    """Verify strace enable/disable state transitions."""

    def test_starts_disabled(self) -> None:
        """Strace should be disabled by default on a fresh kernel."""
        k = _booted_kernel()
        assert k.strace_enabled is False

    def test_enable_sets_flag(self) -> None:
        """Enabling strace should set the enabled flag."""
        k = _booted_kernel()
        k.strace_enable()
        assert k.strace_enabled is True

    def test_disable_clears_flag(self) -> None:
        """Disabling strace should clear the enabled flag."""
        k = _booted_kernel()
        k.strace_enable()
        k.strace_disable()
        assert k.strace_enabled is False

    def test_enable_clears_log(self) -> None:
        """Enabling strace should start with an empty log."""
        k = _booted_kernel()
        k.strace_enable()
        # Generate some entries
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert len(k.strace_log()) > 0
        # Re-enable should clear
        k.strace_enable()
        assert k.strace_log() == []

    def test_enable_resets_sequence(self) -> None:
        """Enabling strace should reset the sequence counter."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        # Re-enable
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entries = k.strace_log()
        assert entries[0].startswith(f"#{_EXPECTED_SEQUENCE_ONE} ")


# ---------------------------------------------------------------------------
# Cycle 2 — Strace capture
# ---------------------------------------------------------------------------


class TestStraceCapture:
    """Verify syscall tracing captures correct information."""

    def test_captured_when_enabled(self) -> None:
        """Syscalls should be captured when strace is enabled."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert len(k.strace_log()) == _EXPECTED_SEQUENCE_ONE

    def test_not_captured_when_disabled(self) -> None:
        """Syscalls should NOT be captured when strace is disabled."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert k.strace_log() == []

    def test_sequence_increments(self) -> None:
        """Each captured entry should have an incrementing sequence number."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entries = k.strace_log()
        assert entries[0].startswith(f"#{_EXPECTED_SEQUENCE_ONE} ")
        assert entries[1].startswith(f"#{_EXPECTED_SEQUENCE_TWO} ")

    def test_entry_has_name(self) -> None:
        """Entry should contain the syscall name."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entry = k.strace_log()[0]
        assert "SYS_LIST_PROCESSES" in entry

    def test_entry_has_args(self) -> None:
        """Entry should contain the syscall arguments."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        entry = k.strace_log()[0]
        assert 'path="/"' in entry

    def test_entry_has_return_value(self) -> None:
        """Entry should contain the syscall return value."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entry = k.strace_log()[0]
        assert "= " in entry

    def test_errors_formatted(self) -> None:
        """Failed syscalls should show ERROR in the trace entry."""
        k = _booted_kernel()
        k.strace_enable()
        with pytest.raises(SyscallError):
            k.syscall(SyscallNumber.SYS_READ_FILE, path="/nonexistent")
        entries = k.strace_log()
        assert len(entries) == _EXPECTED_SEQUENCE_ONE
        assert "ERROR:" in entries[0]


# ---------------------------------------------------------------------------
# Cycle 3 — Strace sanitization
# ---------------------------------------------------------------------------


class TestStraceSanitization:
    """Verify that traced values are properly sanitized for display."""

    def test_callable_shown_as_placeholder(self) -> None:
        """Callable values should display as <callable>."""
        k = _booted_kernel()
        assert k._sanitize_value(lambda: None) == "<callable>"

    def test_long_string_truncated(self) -> None:
        """Strings longer than the limit should be truncated."""
        k = _booted_kernel()
        long_str = "a" * _LONG_STRING_LENGTH
        result = k._sanitize_value(long_str)
        # Truncated to 50 chars + ... + surrounding quotes = 55 chars
        assert len(result) <= _TRUNCATION_LIMIT + len('"..."')
        assert result.endswith('..."')

    def test_bytes_shown_as_size(self) -> None:
        """Bytes values should display as <N bytes>."""
        k = _booted_kernel()
        data = b"x" * _BYTES_LENGTH
        assert k._sanitize_value(data) == f"<{_BYTES_LENGTH} bytes>"

    def test_long_list_truncated(self) -> None:
        """Lists longer than the limit should be truncated."""
        k = _booted_kernel()
        long_list = list(range(_LONG_LIST_LENGTH))
        result = k._sanitize_value(long_list)
        assert "..." in result
        # Should show at most MAX_LIST_ITEMS items
        assert result.startswith("[")

    def test_long_dict_truncated(self) -> None:
        """Dicts larger than the limit should be truncated."""
        k = _booted_kernel()
        long_dict = {f"key{i}": i for i in range(_LONG_DICT_SIZE)}
        result = k._sanitize_value(long_dict)
        assert "..." in result

    def test_short_values_unchanged(self) -> None:
        """Short values should be represented faithfully."""
        k = _booted_kernel()
        assert k._sanitize_value(42) == "42"
        assert k._sanitize_value("hi") == '"hi"'
        assert k._sanitize_value(None) == "None"


# ---------------------------------------------------------------------------
# Cycle 4 — Strace log management
# ---------------------------------------------------------------------------


class TestStraceLogManagement:
    """Verify log retrieval, clearing, and FIFO eviction."""

    def test_strace_log_returns_entries(self) -> None:
        """strace_log() should return a copy of the log entries."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        log = k.strace_log()
        assert len(log) == _EXPECTED_SEQUENCE_ONE
        # Should be a copy
        log.clear()
        assert len(k.strace_log()) == _EXPECTED_SEQUENCE_ONE

    def test_strace_clear_empties(self) -> None:
        """strace_clear() should empty the log."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        k.strace_clear()
        assert k.strace_log() == []

    def test_clear_resets_sequence(self) -> None:
        """strace_clear() should reset the sequence counter."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        k.strace_clear()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entries = k.strace_log()
        assert entries[0].startswith(f"#{_EXPECTED_SEQUENCE_ONE} ")

    def test_fifo_eviction_at_limit(self) -> None:
        """Log should evict oldest entries when exceeding the FIFO limit."""
        k = _booted_kernel()
        k.strace_enable()
        for _ in range(_FIFO_LIMIT + _OVERFLOW_COUNT):
            k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert len(k.strace_log()) == _FIFO_LIMIT

    def test_sequence_continues_after_eviction(self) -> None:
        """Sequence numbers should keep incrementing even after eviction."""
        k = _booted_kernel()
        k.strace_enable()
        for _ in range(_FIFO_LIMIT + _OVERFLOW_COUNT):
            k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entries = k.strace_log()
        # First entry in log should be #6 (after 5 were evicted)
        expected_first = _OVERFLOW_COUNT + _EXPECTED_SEQUENCE_ONE
        assert entries[0].startswith(f"#{expected_first} ")


# ---------------------------------------------------------------------------
# Cycle 5 — Strace exclusion
# ---------------------------------------------------------------------------


class TestStraceExclusion:
    """Verify that strace management syscalls are excluded from tracing."""

    def test_strace_enable_not_logged(self) -> None:
        """SYS_STRACE_ENABLE should not appear in the trace log."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        log = k.strace_log()
        assert not any("SYS_STRACE_ENABLE" in entry for entry in log)

    def test_strace_log_not_logged(self) -> None:
        """SYS_STRACE_LOG should not appear in the trace log."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        k.syscall(SyscallNumber.SYS_STRACE_LOG)
        log = k.strace_log()
        assert not any("SYS_STRACE_LOG" in entry for entry in log)

    def test_read_log_not_logged(self) -> None:
        """SYS_READ_LOG should not appear in the trace log."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_READ_LOG)
        assert k.strace_log() == []


# ---------------------------------------------------------------------------
# Cycle 6 — Strace syscall numbers
# ---------------------------------------------------------------------------


class TestStraceSyscalls:
    """Verify the four strace syscalls work via the dispatch table."""

    def test_sys_strace_enable_works(self) -> None:
        """SYS_STRACE_ENABLE should enable strace."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        assert k.strace_enabled is True

    def test_sys_strace_disable_works(self) -> None:
        """SYS_STRACE_DISABLE should disable strace."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        k.syscall(SyscallNumber.SYS_STRACE_DISABLE)
        assert k.strace_enabled is False

    def test_sys_strace_log_returns_entries(self) -> None:
        """SYS_STRACE_LOG should return the strace entries."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        entries: list[str] = k.syscall(SyscallNumber.SYS_STRACE_LOG)
        assert len(entries) == _EXPECTED_SEQUENCE_ONE

    def test_sys_strace_clear_clears(self) -> None:
        """SYS_STRACE_CLEAR should clear the log and reset sequence."""
        k = _booted_kernel()
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        k.syscall(SyscallNumber.SYS_STRACE_CLEAR)
        assert k.strace_log() == []


# ---------------------------------------------------------------------------
# Cycle 7 — Shell strace command
# ---------------------------------------------------------------------------


class TestShellStrace:
    """Verify the shell strace command and inline trace output."""

    def test_strace_on_enables(self) -> None:
        """'strace on' should enable strace on the kernel."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("strace on")
        assert "enabled" in result.lower()
        assert k.strace_enabled is True

    def test_strace_off_disables(self) -> None:
        """'strace off' should disable strace on the kernel."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        sh.execute("strace on")
        result = sh.execute("strace off")
        assert "disabled" in result.lower()
        assert k.strace_enabled is False

    def test_strace_show_displays_log(self) -> None:
        """'strace show' should display the current strace log entries."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        # Enable strace, then generate entries via kernel directly
        # (not through shell.execute which auto-clears)
        k.strace_enable()
        k.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        result = sh.execute("strace show")
        assert "SYS_LIST_DIR" in result

    def test_strace_clear_empties(self) -> None:
        """'strace clear' should empty the strace log."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        sh.execute("strace on")
        sh.execute("ls /")
        result = sh.execute("strace clear")
        assert "cleared" in result.lower()
        assert k.strace_log() == []

    def test_inline_output_after_command(self) -> None:
        """When strace is on, command output should include trace entries."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        sh.execute("strace on")
        result = sh.execute("ls /")
        assert "--- strace ---" in result
        assert "SYS_LIST_DIR" in result

    def test_no_inline_when_disabled(self) -> None:
        """When strace is off, no trace section should appear."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("ls /")
        assert "--- strace ---" not in result


# ---------------------------------------------------------------------------
# Cycle 8 — Strace demo and completer
# ---------------------------------------------------------------------------


class TestStraceDemoAndCompleter:
    """Verify the strace demo and tab completion."""

    def test_demo_has_steps(self) -> None:
        """'strace demo' should produce a multi-step walkthrough."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("strace demo")
        assert "Step 1" in result
        assert "Step 2" in result
        # Should disable strace after the demo
        assert k.strace_enabled is False

    def test_command_completes(self) -> None:
        """'strace' should appear in command completion."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        comp = Completer(sh)
        candidates = comp.completions("str", "str")
        assert "strace" in candidates

    def test_subcommands_complete(self) -> None:
        """Strace subcommands should complete."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        comp = Completer(sh)
        candidates = comp.completions("", "strace ")
        assert "on" in candidates
        assert "off" in candidates
        assert "show" in candidates
        assert "clear" in candidates
        assert "demo" in candidates
