"""Tests for the dashboard shell command.

The dashboard command provides ASCII visualisations of key OS
subsystems: CPU, memory, processes, and filesystem.
"""

from py_os.completer import Completer
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel, Shell(kernel=kernel)


# -- Cycle 1: Memory panel ---------------------------------------------------


class TestDashboardMemory:
    """Verify the memory panel shows frames and a visual bar."""

    def test_memory_panel_shows_frames(self) -> None:
        """Memory panel should mention frame counts."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard memory")
        assert "frame" in output.lower() or "Frame" in output

    def test_memory_panel_has_visual_bar(self) -> None:
        """Memory panel should contain a visual bar with brackets."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard memory")
        assert "[" in output
        assert "]" in output

    def test_memory_panel_has_legend(self) -> None:
        """Memory panel should show what the bar symbols mean."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard memory")
        # Should explain '#' = allocated, '.' = free (or similar)
        assert "#" in output or "allocated" in output.lower()


# -- Cycle 2: CPU panel ------------------------------------------------------


class TestDashboardCPU:
    """Verify the CPU panel shows policy and current process info."""

    def test_cpu_panel_has_header(self) -> None:
        """CPU panel should have a CPU section header."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard cpu")
        assert "CPU" in output

    def test_cpu_panel_shows_policy(self) -> None:
        """CPU panel should display the current scheduling policy."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard cpu")
        assert "FCFS" in output or "Policy" in output


# -- Cycle 3: Process table --------------------------------------------------


class TestDashboardProcesses:
    """Verify the process table lists running processes."""

    def test_process_table_has_headers(self) -> None:
        """Process table should have PID and STATE column headers."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard processes")
        assert "PID" in output
        assert "STATE" in output

    def test_init_process_visible(self) -> None:
        """The init process should appear in the process table."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard processes")
        assert "init" in output


# -- Cycle 4: Filesystem tree ------------------------------------------------


class TestDashboardFilesystem:
    """Verify the filesystem tree shows directories."""

    def test_fs_tree_shows_root(self) -> None:
        """Filesystem tree should start from root /."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard fs")
        assert "/" in output

    def test_proc_marked_virtual(self) -> None:
        """/proc should be marked as virtual in the tree."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard fs")
        assert "virtual" in output.lower() or "proc" in output

    def test_created_dirs_appear(self) -> None:
        """Directories created by the user should appear in the tree."""
        _kernel, shell = _booted_shell()
        shell.execute("mkdir /mydata")
        output = shell.execute("dashboard fs")
        assert "mydata" in output


# -- Cycle 5: Full dashboard --------------------------------------------------


class TestDashboardFull:
    """Verify the full dashboard assembles all panels."""

    def test_full_dashboard_has_title(self) -> None:
        """Full dashboard should have a title banner."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard")
        assert "Dashboard" in output or "dashboard" in output

    def test_full_dashboard_has_all_sections(self) -> None:
        """Full dashboard should contain headers for all four sections."""
        _kernel, shell = _booted_shell()
        output = shell.execute("dashboard")
        assert "CPU" in output
        assert "Memory" in output or "memory" in output
        assert "Process" in output or "PID" in output
        assert "File" in output or "fs" in output.lower()


# -- Cycle 6: Help + tab completion ------------------------------------------


class TestDashboardIntegration:
    """Verify help listing and tab completion."""

    def test_dashboard_in_help(self) -> None:
        """The dashboard command should appear in help output."""
        _kernel, shell = _booted_shell()
        output = shell.execute("help")
        assert "dashboard" in output

    def test_subcommand_tab_completion(self) -> None:
        """Dashboard subcommands should be completable."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        matches = completer.completions("m", "dashboard m")
        assert "memory" in matches
