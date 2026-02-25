"""Tests for background execution with ``&``.

Background execution lets users run a command silently with ``command &``.
The process runs to completion, its output is captured in a job, and the
user gets a ``[job_id] pid`` notification.  Output is retrieved later
via ``fg`` or ``waitjob``.
"""

import re

from py_os.kernel import ExecutionMode, Kernel
from py_os.process.pcb import Process
from py_os.shell import Shell


def _shell() -> Shell:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return Shell(kernel=kernel)


# -- Cycle 2: & parsing -------------------------------------------------------


class TestBackgroundParsing:
    """Verify ``&`` detection and stripping in ``execute()``."""

    def test_ampersand_stripped_from_command(self) -> None:
        """A trailing ``&`` should not appear in the command dispatched."""
        shell = _shell()
        # echo is a simple builtin — its output proves the & was stripped
        result = shell.execute("echo hello &")
        assert result == "hello"

    def test_ampersand_only_at_end(self) -> None:
        """An ``&`` in the middle of args should not trigger background mode."""
        shell = _shell()
        result = shell.execute("echo a & b")
        # Not a background command — & is part of the echo text
        assert "a" in result

    def test_pipes_with_ampersand_returns_error(self) -> None:
        """Pipes combined with ``&`` should return an error."""
        shell = _shell()
        result = shell.execute("ls / | grep txt &")
        assert "Error" in result
        assert "background" in result.lower()

    def test_bare_ampersand_is_noop(self) -> None:
        """Just ``&`` with no command should return empty string."""
        shell = _shell()
        result = shell.execute("&")
        assert result == ""

    def test_builtin_with_ampersand_runs_normally(self) -> None:
        """Non-run builtins with ``&`` execute normally (no job created)."""
        shell = _shell()
        shell.execute("touch /testfile &")
        result = shell.execute("ls /")
        assert "testfile" in result


# -- Cycle 3: run <program> & ------------------------------------------------


class TestBackgroundRun:
    """Verify ``run <program> &`` creates a job with captured output."""

    def test_returns_job_notification(self) -> None:
        """``run hello &`` should return ``[1] <pid>``."""
        shell = _shell()
        result = shell.execute("run hello &")
        assert re.match(r"\[1\] \d+", result), f"Expected [1] <pid>, got: {result}"

    def test_creates_done_job(self) -> None:
        """The background job should be in DONE status."""
        shell = _shell()
        shell.execute("run hello &")
        jobs_output = shell.execute("jobs")
        assert "done" in jobs_output.lower()

    def test_captures_output(self) -> None:
        """The job should store the program's output."""
        shell = _shell()
        shell.execute("run hello &")
        # Retrieve via fg
        fg_result = shell.execute("fg 1")
        assert "Hello from PyOS!" in fg_result

    def test_captures_exit_code(self) -> None:
        """The job should store the exit code."""
        shell = _shell()
        shell.execute("run hello &")
        fg_result = shell.execute("fg 1")
        assert "[exit code: 0]" in fg_result

    def test_multiple_background_jobs(self) -> None:
        """Multiple ``&`` runs should create separate jobs."""
        shell = _shell()
        shell.execute("run hello &")
        shell.execute("run counter &")
        jobs_output = shell.execute("jobs")
        assert "hello" in jobs_output
        assert "counter" in jobs_output

    def test_background_counter_captures_full_output(self) -> None:
        """Counter program output should be fully captured."""
        shell = _shell()
        shell.execute("run counter &")
        fg_result = shell.execute("fg 1")
        for i in range(1, 6):
            assert str(i) in fg_result

    def test_unknown_program_returns_error(self) -> None:
        """``run nonexistent &`` should return an error."""
        shell = _shell()
        result = shell.execute("run nonexistent &")
        assert "Unknown program" in result

    def test_run_without_args_background(self) -> None:
        """``run &`` (no program name) should return usage message."""
        shell = _shell()
        result = shell.execute("run &")
        assert "Usage" in result or "usage" in result.lower()


# -- Cycle 4: enhanced fg with output ----------------------------------------


def _running_process(kernel: Kernel, name: str = "test") -> Process:
    """Create a process and dispatch it so it's RUNNING."""
    proc = kernel.create_process(name=name, num_pages=4)
    assert kernel.scheduler is not None
    kernel.scheduler.dispatch()
    return proc


class TestFgWithOutput:
    """Verify ``fg`` displays captured output for background jobs."""

    def test_fg_shows_captured_output(self) -> None:
        """``fg`` should return the job's captured output."""
        shell = _shell()
        shell.execute("run hello &")
        result = shell.execute("fg 1")
        assert "Hello from PyOS!" in result
        assert "[exit code: 0]" in result

    def test_fg_removes_job(self) -> None:
        """``fg`` should remove the job from the job list."""
        shell = _shell()
        shell.execute("run hello &")
        shell.execute("fg 1")
        result = shell.execute("jobs")
        assert "No background jobs" in result

    def test_fg_bg_job_still_shows_message(self) -> None:
        """``fg`` on a ``bg``-created job should show the old-style message."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        shell = Shell(kernel=kernel)
        proc = _running_process(kernel, name="worker")
        shell.execute(f"bg {proc.pid}")
        result = shell.execute("fg 1")
        assert "foreground" in result.lower()

    def test_fg_after_multiple_bg_jobs(self) -> None:
        """``fg 2`` should return only the second job's output."""
        shell = _shell()
        shell.execute("run hello &")
        shell.execute("run counter &")
        result = shell.execute("fg 2")
        # Should have counter output, not hello output
        assert "1\n2\n3\n4\n5" in result


# -- Cycle 5: waitjob command ------------------------------------------------


class TestWaitjob:
    """Verify the ``waitjob`` shell command."""

    def test_waitjob_specific_job(self) -> None:
        """``waitjob 1`` should return that job's output and remove it."""
        shell = _shell()
        shell.execute("run hello &")
        result = shell.execute("waitjob 1")
        assert "Hello from PyOS!" in result
        # Job should be removed
        assert "No background jobs" in shell.execute("jobs")

    def test_waitjob_all_jobs(self) -> None:
        """``waitjob`` with no args should collect all job outputs."""
        shell = _shell()
        shell.execute("run hello &")
        shell.execute("run counter &")
        result = shell.execute("waitjob")
        assert "Hello from PyOS!" in result
        assert "1\n2\n3\n4\n5" in result
        assert "No background jobs" in shell.execute("jobs")

    def test_waitjob_no_jobs(self) -> None:
        """``waitjob`` when there are no jobs should say so."""
        shell = _shell()
        result = shell.execute("waitjob")
        assert "No background jobs" in result

    def test_waitjob_invalid_id(self) -> None:
        """``waitjob abc`` should return an error."""
        shell = _shell()
        result = shell.execute("waitjob abc")
        assert "Error" in result

    def test_waitjob_nonexistent_id(self) -> None:
        """``waitjob 99`` should return an error when job doesn't exist."""
        shell = _shell()
        result = shell.execute("waitjob 99")
        assert "Error" in result
        assert "not found" in result.lower()

    def test_waitjob_in_help(self) -> None:
        """``help`` should list waitjob as an available command."""
        shell = _shell()
        result = shell.execute("help")
        assert "waitjob" in result

    def test_waitjob_removes_only_targeted_job(self) -> None:
        """``waitjob 1`` should leave job 2 intact."""
        shell = _shell()
        shell.execute("run hello &")
        shell.execute("run counter &")
        shell.execute("waitjob 1")
        jobs_output = shell.execute("jobs")
        assert "counter" in jobs_output
        assert "hello" not in jobs_output
