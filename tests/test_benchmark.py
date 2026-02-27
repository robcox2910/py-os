"""Tests for the benchmark shell command.

The benchmark command compares scheduler policies by running
identical workloads under each policy and displaying timing
results in an ASCII table.
"""

from py_os.completer import Completer
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel, Shell(kernel=kernel)


# -- Cycle 1: SYS_PERF_RESET syscall ------------------------------------------


class TestPerfReset:
    """Verify the SYS_PERF_RESET syscall zeroes performance counters."""

    def test_perf_reset_returns_status(self) -> None:
        """SYS_PERF_RESET should return a status dict."""
        kernel, _shell = _booted_shell()
        result: dict[str, object] = kernel.syscall(SyscallNumber.SYS_PERF_RESET)
        assert result["status"] == "reset"

    def test_metrics_zeroed_after_reset(self) -> None:
        """After SYS_PERF_RESET, completed count and context switches should be zero."""
        kernel, shell = _booted_shell()
        # Create some activity first
        shell.execute("run hello")
        metrics_before: dict[str, object] = kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
        assert int(str(metrics_before["total_completed"])) > 0

        # Reset
        kernel.syscall(SyscallNumber.SYS_PERF_RESET)
        metrics_after: dict[str, object] = kernel.syscall(SyscallNumber.SYS_PERF_METRICS)

        expected_completed = 0
        expected_switches = 0
        assert metrics_after["total_completed"] == expected_completed
        assert metrics_after["context_switches"] == expected_switches


# -- Cycle 2: CPU workload ----------------------------------------------------


class TestBenchmarkCPUWorkload:
    """Verify the CPU-bound benchmark workload."""

    def test_cpu_workload_creates_processes(self) -> None:
        """CPU workload should create and run processes."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark run cpu")
        assert "CPU-bound" in output

    def test_cpu_workload_produces_output(self) -> None:
        """CPU workload should produce meaningful benchmark output."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark run cpu")
        # Should contain numeric data
        assert "completed" in output.lower() or "context" in output.lower()


# -- Cycle 3: FCFS row in output -----------------------------------------------


class TestBenchmarkFCFS:
    """Verify FCFS policy appears in benchmark results."""

    def test_fcfs_row_in_output(self) -> None:
        """FCFS should appear as a row in the benchmark table."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark run cpu")
        assert "FCFS" in output


# -- Cycle 4: All policies + restore ------------------------------------------


class TestBenchmarkAllPolicies:
    """Verify all policies are tested and the original is restored."""

    EXPECTED_POLICY_COUNT = 5

    def test_all_policy_names_in_output(self) -> None:
        """All five scheduling policies should appear in benchmark output."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark run cpu")
        policies = ["FCFS", "RR", "Priority", "Aging", "CFS"]
        for policy in policies:
            assert policy in output, f"Missing policy: {policy}"

    def test_original_policy_restored(self) -> None:
        """The original scheduling policy should be restored after benchmark."""
        _kernel, shell = _booted_shell()
        original = shell.execute("scheduler")
        shell.execute("benchmark run cpu")
        restored = shell.execute("scheduler")
        assert original == restored


# -- Cycle 5: Table headers + usage -------------------------------------------


class TestBenchmarkTableFormat:
    """Verify table formatting and usage messages."""

    def test_table_has_column_headers(self) -> None:
        """The benchmark table should have column headers."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark run cpu")
        assert "Policy" in output
        assert "Switches" in output or "switches" in output

    def test_no_args_shows_usage(self) -> None:
        """Running benchmark with no args should show usage."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark")
        assert "Usage" in output or "usage" in output.lower()


# -- Cycle 6: Demo + tab completion -------------------------------------------


class TestBenchmarkDemo:
    """Verify the demo mode and tab completion."""

    def test_demo_has_steps(self) -> None:
        """The demo should contain numbered steps."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark demo")
        assert "Step" in output or "step" in output

    def test_demo_has_analogy(self) -> None:
        """The demo should use a sports day analogy."""
        _kernel, shell = _booted_shell()
        output = shell.execute("benchmark demo")
        assert "sports" in output.lower() or "coach" in output.lower()

    def test_tab_completion(self) -> None:
        """Benchmark subcommands should be in the completer."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        # Use completions() directly — complete("benchmark r") to get "run"
        matches = completer.completions("r", "benchmark r")
        assert "run" in matches

    def test_benchmark_in_help(self) -> None:
        """The benchmark command should appear in help output."""
        _kernel, shell = _booted_shell()
        output = shell.execute("help")
        assert "benchmark" in output
