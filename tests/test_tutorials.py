"""Tests for the interactive tutorial system.

The tutorial system teaches OS concepts through guided, hands-on
lessons that use real syscalls with educational commentary.
"""

import pytest

from py_os.completer import Completer
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.tutorials import TutorialRunner

EXPECTED_LESSON_COUNT = 9


def _booted_kernel() -> Kernel:
    """Create a booted kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = _booted_kernel()
    return kernel, Shell(kernel=kernel)


# -- Cycle 1: Runner creation ------------------------------------------------


class TestTutorialRunner:
    """Verify runner creation, lesson listing, and error handling."""

    def test_runner_requires_running_kernel(self) -> None:
        """TutorialRunner needs a running kernel."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        assert runner is not None

    def test_runner_lists_lessons(self) -> None:
        """Runner should list all available lessons."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        lessons = runner.list_lessons()
        assert len(lessons) == EXPECTED_LESSON_COUNT

    def test_lessons_sorted(self) -> None:
        """Lesson names should be returned in sorted order."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        lessons = runner.list_lessons()
        assert lessons == sorted(lessons)

    def test_unknown_lesson_raises(self) -> None:
        """Running an unknown lesson should raise KeyError."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        with pytest.raises(KeyError):
            runner.run("nonexistent")


# -- Cycle 2: Processes lesson -----------------------------------------------


class TestProcessesLesson:
    """Verify the processes lesson output."""

    def test_has_title(self) -> None:
        """Processes lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("processes")
        assert "Process" in output

    def test_has_steps(self) -> None:
        """Processes lesson should contain numbered steps."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("processes")
        assert "Step" in output

    def test_has_analogy(self) -> None:
        """Processes lesson should use a recipe/cook analogy."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("processes")
        assert "recipe" in output.lower() or "cook" in output.lower()

    def test_has_summary(self) -> None:
        """Processes lesson should end with a summary."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("processes")
        assert "summary" in output.lower() or "learned" in output.lower()

    def test_has_next_pointer(self) -> None:
        """Processes lesson should suggest the next lesson."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("processes")
        assert "next" in output.lower() or "memory" in output.lower()


# -- Cycle 3: Memory lesson -------------------------------------------------


class TestMemoryLesson:
    """Verify the memory lesson output."""

    def test_has_title(self) -> None:
        """Memory lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("memory")
        assert "Memory" in output

    def test_has_frame_counts(self) -> None:
        """Memory lesson should mention frame counts."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("memory")
        assert "frame" in output.lower()


# -- Cycle 4: Filesystem lesson ---------------------------------------------


class TestFilesystemLesson:
    """Verify the filesystem lesson output."""

    def test_has_title(self) -> None:
        """Filesystem lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("filesystem")
        assert "Filesystem" in output or "File" in output

    def test_has_file_paths(self) -> None:
        """Filesystem lesson should show file paths being created."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("filesystem")
        assert "/" in output


# -- Cycle 5: Scheduling lesson ---------------------------------------------


class TestSchedulingLesson:
    """Verify the scheduling lesson output."""

    def test_has_title(self) -> None:
        """Scheduling lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("scheduling")
        assert "Scheduling" in output or "Scheduler" in output

    def test_has_policy_names(self) -> None:
        """Scheduling lesson should mention policy names."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("scheduling")
        assert "FCFS" in output or "Round Robin" in output


# -- Cycle 6: Signals lesson ------------------------------------------------


class TestSignalsLesson:
    """Verify the signals lesson output."""

    def test_has_title(self) -> None:
        """Signals lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("signals")
        assert "Signal" in output

    def test_has_signal_names(self) -> None:
        """Signals lesson should mention specific signals."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("signals")
        assert "SIGTERM" in output or "SIGUSR" in output


# -- Cycle 7: IPC lesson ----------------------------------------------------


class TestIPCLesson:
    """Verify the IPC lesson output."""

    def test_has_title(self) -> None:
        """IPC lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("ipc")
        assert "IPC" in output or "Communication" in output

    def test_has_shared_memory(self) -> None:
        """IPC lesson should demonstrate shared memory data."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("ipc")
        assert "shared" in output.lower() or "shm" in output.lower()


# -- Cycle 8: Networking lesson ----------------------------------------------


class TestNetworkingLesson:
    """Verify the networking lesson output."""

    def test_has_title(self) -> None:
        """Networking lesson should have a title."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("networking")
        assert "Network" in output

    def test_has_dns(self) -> None:
        """Networking lesson should demonstrate DNS records."""
        kernel = _booted_kernel()
        runner = TutorialRunner(kernel)
        output = runner.run("networking")
        assert "dns" in output.lower() or "DNS" in output


# -- Cycle 9: Shell integration ---------------------------------------------


class TestLearnCommand:
    """Verify shell integration and tab completion."""

    def test_learn_lists_lessons(self) -> None:
        """Running 'learn' with no args should list available lessons."""
        _kernel, shell = _booted_shell()
        output = shell.execute("learn")
        assert "processes" in output
        assert "memory" in output

    def test_learn_runs_lesson(self) -> None:
        """Running 'learn processes' should run the processes lesson."""
        _kernel, shell = _booted_shell()
        output = shell.execute("learn processes")
        assert "Process" in output

    def test_learn_unknown_errors(self) -> None:
        """Running 'learn bogus' should return an error."""
        _kernel, shell = _booted_shell()
        output = shell.execute("learn bogus")
        assert "error" in output.lower() or "unknown" in output.lower()

    def test_learn_all_runs(self) -> None:
        """Running 'learn all' should run all lessons."""
        _kernel, shell = _booted_shell()
        output = shell.execute("learn all")
        assert "Process" in output
        assert "Memory" in output

    def test_learn_in_help(self) -> None:
        """The learn command should appear in help output."""
        _kernel, shell = _booted_shell()
        output = shell.execute("help")
        assert "learn" in output

    def test_tab_completion(self) -> None:
        """Learn subcommands should be completable."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        matches = completer.completions("p", "learn p")
        assert "processes" in matches
