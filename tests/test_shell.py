"""Tests for the shell module.

The shell is the command interpreter — it parses user input, dispatches
to built-in commands, and returns string output.  It operates on a
booted kernel, using its subsystems (scheduler, memory, file system).
"""

import pytest

from py_os.kernel import Kernel
from py_os.shell import Shell

NUM_PAGES = 2


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


class TestShellCreation:
    """Verify shell initialisation."""

    def test_shell_requires_booted_kernel(self) -> None:
        """The shell should reject a non-running kernel."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            Shell(kernel=kernel)

    def test_shell_accepts_booted_kernel(self) -> None:
        """The shell should accept a running kernel."""
        _kernel, shell = _booted_shell()
        assert shell is not None


class TestShellExecute:
    """Verify command parsing and dispatch."""

    def test_empty_command_returns_empty(self) -> None:
        """An empty command should produce no output."""
        _kernel, shell = _booted_shell()
        assert shell.execute("") == ""

    def test_whitespace_only_returns_empty(self) -> None:
        """Whitespace-only input should produce no output."""
        _kernel, shell = _booted_shell()
        assert shell.execute("   ") == ""

    def test_unknown_command_returns_error(self) -> None:
        """An unknown command should produce an error message."""
        _kernel, shell = _booted_shell()
        result = shell.execute("foobar")
        assert "Unknown command" in result
        assert "foobar" in result


class TestShellHelp:
    """Verify the help command."""

    def test_help_lists_commands(self) -> None:
        """Help should list available commands."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "ps" in result
        assert "ls" in result
        assert "help" in result


class TestShellPs:
    """Verify the ps (process status) command."""

    def test_ps_with_no_processes(self) -> None:
        """Ps with no user processes should show a header only or empty."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ps")
        assert "PID" in result

    def test_ps_shows_created_process(self) -> None:
        """Ps should list processes created via the kernel."""
        kernel, shell = _booted_shell()
        kernel.create_process(name="daemon", num_pages=NUM_PAGES)
        result = shell.execute("ps")
        assert "daemon" in result


class TestShellFilesystemCommands:
    """Verify ls, mkdir, touch, cat, write, rm commands."""

    def test_ls_root(self) -> None:
        """Ls on root should work (empty initially)."""
        _kernel, shell = _booted_shell()
        result = shell.execute("ls /")
        # Root is empty, so just no error
        assert result is not None

    def test_mkdir_then_ls(self) -> None:
        """Creating a directory should make it appear in ls."""
        _kernel, shell = _booted_shell()
        shell.execute("mkdir /docs")
        result = shell.execute("ls /")
        assert "docs" in result

    def test_touch_then_ls(self) -> None:
        """Creating a file should make it appear in ls."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /hello.txt")
        result = shell.execute("ls /")
        assert "hello.txt" in result

    def test_write_then_cat(self) -> None:
        """Writing to a file then reading it back with cat."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /hello.txt")
        shell.execute("write /hello.txt Hello, OS!")
        result = shell.execute("cat /hello.txt")
        assert "Hello, OS!" in result

    def test_cat_nonexistent_file(self) -> None:
        """Cat on a missing file should produce an error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("cat /nope.txt")
        assert "not found" in result.lower() or "error" in result.lower()

    def test_rm_file(self) -> None:
        """Rm should delete a file."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /hello.txt")
        shell.execute("rm /hello.txt")
        result = shell.execute("ls /")
        assert "hello.txt" not in result

    def test_mkdir_missing_arg(self) -> None:
        """Mkdir without an argument should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("mkdir")
        assert "usage" in result.lower() or "error" in result.lower()


class TestShellScheduler:
    """Verify the scheduler command for viewing and switching policies."""

    def test_scheduler_shows_current_policy(self) -> None:
        """Default scheduler should report FCFS."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler")
        assert "FCFS" in result

    def test_scheduler_switch_to_priority(self) -> None:
        """Switching to priority policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler priority")
        assert "Priority" in result

    def test_scheduler_switch_to_rr(self) -> None:
        """Switching to round robin with a quantum should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler rr 3")
        assert "Round Robin" in result

    def test_scheduler_missing_rr_quantum(self) -> None:
        """Round robin without a quantum should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler rr")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_scheduler_unknown_policy(self) -> None:
        """An unknown policy name should produce an error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler foo")
        assert "error" in result.lower() or "unknown" in result.lower()

    def test_scheduler_switch_to_mlfq(self) -> None:
        """Switching to MLFQ policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler mlfq")
        assert "MLFQ" in result

    def test_scheduler_mlfq_with_params(self) -> None:
        """Switching to MLFQ with custom levels and base quantum."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler mlfq 4 3")
        assert "4 levels" in result
        assert "base_quantum=3" in result

    def test_scheduler_boost(self) -> None:
        """Scheduler boost should succeed when MLFQ is active."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler mlfq")
        result = shell.execute("scheduler boost")
        assert "boost" in result.lower()

    def test_scheduler_boost_without_mlfq(self) -> None:
        """Scheduler boost with a non-MLFQ policy should error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler boost")
        assert "error" in result.lower()

    def test_scheduler_show_mlfq(self) -> None:
        """Showing scheduler info with MLFQ should display levels and quanta."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler mlfq")
        result = shell.execute("scheduler")
        assert "MLFQ" in result
        assert "levels" in result.lower()
        assert "quanta" in result.lower()

    def test_scheduler_switch_to_aging(self) -> None:
        """Switching to aging priority policy should be confirmed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("scheduler aging")
        assert "Aging Priority" in result

    def test_scheduler_show_aging(self) -> None:
        """Showing scheduler info with aging active should display boost and max_age."""
        _kernel, shell = _booted_shell()
        shell.execute("scheduler aging")
        result = shell.execute("scheduler")
        assert "Aging Priority" in result
        assert "boost" in result.lower()
        assert "max_age" in result.lower()


class TestShellRunWithPriority:
    """Verify the run command accepts an optional priority argument."""

    def test_run_with_priority(self) -> None:
        """Running a program with a priority should succeed."""
        _kernel, shell = _booted_shell()
        result = shell.execute("run hello 5")
        assert "Hello from PyOS!" in result


class TestShellKill:
    """Verify the kill command."""

    def test_kill_terminates_running_process(self) -> None:
        """Kill should terminate a process by PID."""
        kernel, shell = _booted_shell()
        process = kernel.create_process(name="victim", num_pages=NUM_PAGES)
        # Dispatch so it's RUNNING (only RUNNING can be terminated)
        assert kernel.scheduler is not None
        kernel.scheduler.dispatch()
        result = shell.execute(f"kill {process.pid}")
        assert "terminated" in result.lower() or "killed" in result.lower()

    def test_kill_missing_arg(self) -> None:
        """Kill without a PID should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("kill")
        assert "usage" in result.lower() or "error" in result.lower()
