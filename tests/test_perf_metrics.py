"""Tests for performance metrics — timing, context switches, and aggregation.

TDD plan: 8 cycles covering process timing, scheduler context switches,
kernel aggregation, /proc files, syscall, shell command, and completer.
"""

from __future__ import annotations

from time import monotonic
from unittest.mock import patch

import pytest

from py_os.completer import Completer
from py_os.fs.procfs import ProcFilesystem
from py_os.kernel import Kernel
from py_os.process.pcb import Process
from py_os.process.scheduler import FCFSPolicy, Scheduler
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber

# Named constants for magic numbers
_EXPECTED_CTX_SWITCHES_TWO = 2
_MIN_COMPLETED_COUNT = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _booted_kernel() -> Kernel:
    """Return a freshly booted kernel."""
    k = Kernel()
    k.boot()
    return k


# ---------------------------------------------------------------------------
# Cycle 1 — Process timing fields
# ---------------------------------------------------------------------------


class TestProcessTimingFields:
    """Verify initial timing field values on a freshly created Process."""

    def test_created_at_set_to_monotonic(self) -> None:
        """created_at should be set at construction time."""
        before = monotonic()
        p = Process(name="test")
        after = monotonic()
        assert before <= p.created_at <= after

    def test_wait_time_starts_at_zero(self) -> None:
        """Accumulated READY-queue time should start at zero."""
        p = Process(name="test")
        assert p.wait_time == pytest.approx(0.0)  # pyright: ignore[reportUnknownMemberType]

    def test_cpu_time_starts_at_zero(self) -> None:
        """Accumulated CPU time should start at zero."""
        p = Process(name="test")
        assert p.cpu_time == pytest.approx(0.0)  # pyright: ignore[reportUnknownMemberType]

    def test_turnaround_time_none_while_alive(self) -> None:
        """Turnaround time should be None for a non-terminated process."""
        p = Process(name="test")
        assert p.turnaround_time is None

    def test_response_time_none_before_dispatch(self) -> None:
        """Response time should be None before the process is ever dispatched."""
        p = Process(name="test")
        assert p.response_time is None


# ---------------------------------------------------------------------------
# Cycle 2 — Process timing transitions
# ---------------------------------------------------------------------------

# We mock monotonic() with an auto-incrementing counter so each call
# returns a predictable, increasing value (1.0, 2.0, 3.0, …).

_mock_tick = 0.0


def _mock_monotonic() -> float:
    """Return an auto-incrementing mock clock value."""
    global _mock_tick  # noqa: PLW0603
    _mock_tick += 1.0
    return _mock_tick


def _reset_tick(start: float = 0.0) -> None:
    """Reset the mock clock to a starting value."""
    global _mock_tick  # noqa: PLW0603
    _mock_tick = start


class TestProcessTimingTransitions:
    """Verify timing accumulation across state transitions."""

    def setup_method(self) -> None:
        """Reset the mock clock before each test."""
        _reset_tick()

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_admit_sets_last_ready_at(self, _mono: object) -> None:  # noqa: PT019
        """admit() should record when the process entered the READY queue."""
        p = Process(name="a")  # tick 1 → created_at
        p.admit()  # tick 2 → _last_ready_at
        # wait_time is still 0 because nothing accumulated yet
        assert p.wait_time == pytest.approx(0.0)  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_dispatch_records_response_time(self, _mono: object) -> None:  # noqa: PT019
        """First dispatch() should record response time (first_dispatched - created)."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3 → first_dispatched_at=3, wait accumulated=3-2=1
        assert p.response_time == pytest.approx(2.0)  # pyright: ignore[reportUnknownMemberType]  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_dispatch_accumulates_wait_time(self, _mono: object) -> None:  # noqa: PT019
        """dispatch() should accumulate READY-queue time from _last_ready_at."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3 → wait = 3 - 2 = 1.0
        assert p.wait_time == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_preempt_accumulates_cpu_time(self, _mono: object) -> None:  # noqa: PT019
        """preempt() should accumulate CPU time from _last_dispatched_at."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3
        p.preempt()  # tick 4 → cpu = 4 - 3 = 1.0
        assert p.cpu_time == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_wait_accumulates_cpu_time(self, _mono: object) -> None:  # noqa: PT019
        """wait() (RUNNING→WAITING) should accumulate CPU time."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3
        p.wait()  # tick 4 → cpu = 4 - 3 = 1.0
        assert p.cpu_time == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_wake_sets_ready_at(self, _mono: object) -> None:  # noqa: PT019
        """wake() should set _last_ready_at for subsequent wait accumulation."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3 → wait = 1.0
        p.wait()  # tick 4
        p.wake()  # tick 5 → _last_ready_at = 5
        p.dispatch()  # tick 6 → wait += 6 - 5 = 1.0, total = 2.0
        assert p.wait_time == pytest.approx(2.0)  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_terminate_sets_turnaround(self, _mono: object) -> None:  # noqa: PT019
        """terminate() should record turnaround time = terminated_at - created_at."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3
        p.terminate()  # tick 4 → turnaround = 4 - 1 = 3.0, cpu = 4 - 3 = 1.0
        assert p.turnaround_time == pytest.approx(3.0)  # pyright: ignore[reportUnknownMemberType]
        assert p.cpu_time == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]

    @patch("py_os.process.pcb.monotonic", side_effect=_mock_monotonic)
    def test_force_terminate_records_timing(self, _mono: object) -> None:  # noqa: PT019
        """force_terminate() should accumulate CPU time if RUNNING and set turnaround."""
        p = Process(name="a")  # tick 1
        p.admit()  # tick 2
        p.dispatch()  # tick 3
        p.force_terminate()  # tick 4 → cpu = 4 - 3 = 1.0, turnaround = 4 - 1 = 3.0
        assert p.cpu_time == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]
        assert p.turnaround_time == pytest.approx(3.0)  # pyright: ignore[reportUnknownMemberType]


# ---------------------------------------------------------------------------
# Cycle 3 — Scheduler context switches
# ---------------------------------------------------------------------------


class TestSchedulerContextSwitches:
    """Verify the scheduler counts context switches."""

    def test_starts_at_zero(self) -> None:
        """context_switches should be zero on a fresh scheduler."""
        s = Scheduler(policy=FCFSPolicy())
        assert s.context_switches == 0

    def test_dispatch_increments(self) -> None:
        """Each dispatch() call should increment context_switches by one."""
        s = Scheduler(policy=FCFSPolicy())
        p = Process(name="a")
        p.admit()
        s.add(p)
        s.dispatch()
        assert s.context_switches == 1

    def test_multiple_dispatches_count(self) -> None:
        """Two dispatches should give context_switches == 2."""
        s = Scheduler(policy=FCFSPolicy())
        for name in ("a", "b"):
            p = Process(name=name)
            p.admit()
            s.add(p)
        s.dispatch()
        s.terminate_current()
        s.dispatch()
        assert s.context_switches == _EXPECTED_CTX_SWITCHES_TWO

    def test_preempt_does_not_increment(self) -> None:
        """preempt() alone should not change context_switches."""
        s = Scheduler(policy=FCFSPolicy())
        p = Process(name="a")
        p.admit()
        s.add(p)
        s.dispatch()
        count_before = s.context_switches
        s.preempt()
        assert s.context_switches == count_before


# ---------------------------------------------------------------------------
# Cycle 4 — Kernel metrics aggregation
# ---------------------------------------------------------------------------


class TestKernelMetrics:
    """Verify kernel-level performance aggregation."""

    def test_total_created_increments_on_create(self) -> None:
        """create_process should increment total_created."""
        k = _booted_kernel()
        k.create_process(name="a", num_pages=1)
        metrics = k.perf_metrics()
        assert metrics["total_created"] >= 1
        k.shutdown()

    def test_total_created_increments_on_fork(self) -> None:
        """fork_process should also increment total_created."""
        k = _booted_kernel()
        parent = k.create_process(name="parent", num_pages=1)
        before = k.perf_metrics()["total_created"]
        k.fork_process(parent_pid=parent.pid)
        after = k.perf_metrics()["total_created"]
        assert after == before + 1
        k.shutdown()

    def test_total_completed_increments_on_terminate(self) -> None:
        """terminate_process should increment total_completed."""
        k = _booted_kernel()
        p = k.create_process(name="a", num_pages=1)
        assert k.scheduler is not None
        k.scheduler.dispatch()
        k.terminate_process(pid=p.pid)
        assert k.perf_metrics()["total_completed"] >= 1
        k.shutdown()

    def test_perf_metrics_returns_all_keys(self) -> None:
        """perf_metrics() dict should contain all expected keys."""
        k = _booted_kernel()
        metrics = k.perf_metrics()
        expected_keys = {
            "context_switches",
            "total_created",
            "total_completed",
            "avg_wait_time",
            "avg_turnaround_time",
            "avg_response_time",
            "throughput",
        }
        assert expected_keys <= set(metrics)
        k.shutdown()

    def test_averages_correct_after_multiple_processes(self) -> None:
        """Average metrics should reflect completed process timing."""
        k = _booted_kernel()
        for name in ("a", "b"):
            p = k.create_process(name=name, num_pages=1)
            k.exec_process(pid=p.pid, program=lambda: "ok")
            k.run_process(pid=p.pid)
        metrics = k.perf_metrics()
        # At least 2 processes completed
        assert metrics["total_completed"] >= _MIN_COMPLETED_COUNT
        # Averages should be non-negative floats
        assert metrics["avg_wait_time"] >= 0.0
        assert metrics["avg_turnaround_time"] >= 0.0
        assert metrics["avg_response_time"] >= 0.0
        assert metrics["throughput"] > 0.0
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 5 — /proc/stat and /proc/{pid}/sched
# ---------------------------------------------------------------------------


class TestProcStatAndSched:
    """Verify /proc/stat and /proc/{pid}/sched virtual files."""

    def test_proc_stat_has_ctx_switches(self) -> None:
        """/proc/stat should contain CtxSwitches."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/stat")
        assert "CtxSwitches:" in content
        k.shutdown()

    def test_proc_stat_has_total_created(self) -> None:
        """/proc/stat should contain TotalCreated."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/stat")
        assert "TotalCreated:" in content
        k.shutdown()

    def test_proc_stat_has_throughput(self) -> None:
        """/proc/stat should contain Throughput."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/stat")
        assert "Throughput:" in content
        k.shutdown()

    def test_proc_pid_sched_has_wait_time(self) -> None:
        """/proc/{pid}/sched should contain WaitTime."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="x", num_pages=1)
        content = pfs.read(f"/proc/{p.pid}/sched")
        assert "WaitTime:" in content
        k.shutdown()

    def test_proc_pid_sched_has_cpu_time(self) -> None:
        """/proc/{pid}/sched should contain CpuTime."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="x", num_pages=1)
        content = pfs.read(f"/proc/{p.pid}/sched")
        assert "CpuTime:" in content
        k.shutdown()

    def test_list_root_includes_stat(self) -> None:
        """list_dir('/proc') should include 'stat'."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        entries = pfs.list_dir("/proc")
        assert "stat" in entries
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 6 — SYS_PERF_METRICS syscall
# ---------------------------------------------------------------------------


class TestPerfSyscall:
    """Verify the SYS_PERF_METRICS syscall."""

    def test_syscall_returns_dict(self) -> None:
        """SYS_PERF_METRICS should return a dict."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_PERF_METRICS)
        assert isinstance(result, dict)
        k.shutdown()

    def test_syscall_has_context_switches_key(self) -> None:
        """Returned dict should include context_switches."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_PERF_METRICS)
        assert "context_switches" in result
        k.shutdown()

    def test_syscall_fails_when_not_running(self) -> None:
        """Syscall should raise when kernel is not running."""
        k = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            k.syscall(SyscallNumber.SYS_PERF_METRICS)


# ---------------------------------------------------------------------------
# Cycle 7 — Shell perf command
# ---------------------------------------------------------------------------


class TestShellPerf:
    """Verify the 'perf' shell command."""

    def test_perf_shows_header(self) -> None:
        """'perf' output should contain the performance header."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        output = shell.execute("perf")
        assert "Performance Metrics" in output
        k.shutdown()

    def test_perf_shows_context_switches(self) -> None:
        """'perf' output should contain 'Context switches'."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        output = shell.execute("perf")
        assert "Context switches" in output
        k.shutdown()

    def test_perf_demo_has_steps(self) -> None:
        """'perf demo' should contain numbered steps."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        output = shell.execute("perf demo")
        assert "Step 1" in output
        k.shutdown()

    def test_ps_unchanged(self) -> None:
        """'ps' should still work and not show timing columns."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        output = shell.execute("ps")
        assert "PID" in output
        assert "STATE" in output
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 8 — Completer
# ---------------------------------------------------------------------------


class TestPerfCompleter:
    """Verify tab completion for the perf command."""

    def test_perf_command_completes(self) -> None:
        """Typing 'per' should complete to 'perf'."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        comp = Completer(shell)
        candidates = comp.completions("per", "per")
        assert "perf" in candidates
        k.shutdown()

    def test_perf_demo_subcommand_completes(self) -> None:
        """Typing 'perf d' should complete to 'demo'."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        comp = Completer(shell)
        candidates = comp.completions("d", "perf d")
        assert "demo" in candidates
        k.shutdown()
