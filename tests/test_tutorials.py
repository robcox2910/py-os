"""Tests for the interactive tutorial system.

The tutorial system teaches OS concepts through guided, hands-on
lessons that use real syscalls with educational commentary.
"""

from unittest.mock import patch

import pytest

from py_os.completer import Completer
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError
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


# -- Cycle 10: Error path coverage -------------------------------------------


def _failing_kernel() -> Kernel:
    """Create a kernel whose syscall always raises SyscallError."""
    return _booted_kernel()


class TestProcessesLessonErrors:
    """Verify processes lesson error paths."""

    def test_list_processes_error(self) -> None:
        """Error listing processes should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("fail")):
            output = runner.run("processes")
        assert "Could not list processes" in output

    def test_create_process_error(self) -> None:
        """Error creating a process should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_on_second(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:  # noqa: PLR2004
                raise SyscallError("fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_on_second):
            output = runner.run("processes")
        assert "(Error: fail)" in output


class TestMemoryLessonErrors:
    """Verify memory lesson error paths."""

    def test_memory_info_error(self) -> None:
        """Error getting memory info should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("fail")):
            output = runner.run("memory")
        assert "(Error: fail)" in output

    def test_slab_error(self) -> None:
        """Error in slab operations should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_on_second(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:  # noqa: PLR2004
                raise SyscallError("slab fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_on_second):
            output = runner.run("memory")
        assert "(Error: slab fail)" in output


class TestFilesystemLessonErrors:
    """Verify filesystem lesson error paths."""

    def test_all_fs_errors(self) -> None:
        """All filesystem operations failing should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("fs fail")):
            output = runner.run("filesystem")
        error_count = output.count("(Error: fs fail)")
        min_errors = 4
        assert error_count >= min_errors


class TestSchedulingLessonErrors:
    """Verify scheduling lesson error paths."""

    def test_scheduler_info_error(self) -> None:
        """Error getting scheduler info should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("sched fail")):
            output = runner.run("scheduling")
        error_count = output.count("(Error: sched fail)")
        min_errors = 2
        assert error_count >= min_errors


class TestSignalsLessonErrors:
    """Verify signals lesson error paths."""

    def test_create_process_error_returns_early(self) -> None:
        """Error creating the signal target should return early."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("sig fail")):
            output = runner.run("signals")
        assert "(Error: sig fail)" in output
        assert "Step 2" not in output

    def test_handler_and_send_errors(self) -> None:
        """Error in handler registration and signal sending should be caught."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_after_first(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:  # noqa: PLR2004
                raise SyscallError("sig op fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_after_first):
            output = runner.run("signals")
        assert "(Error: sig op fail)" in output


class TestIPCLessonErrors:
    """Verify IPC lesson error paths."""

    def test_shm_create_error_returns_early(self) -> None:
        """Error creating shared memory should return early."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("ipc fail")):
            output = runner.run("ipc")
        assert "(Error: ipc fail)" in output
        assert "Step 2" not in output


class TestNetworkingLessonErrors:
    """Verify networking lesson error paths."""

    def test_dns_errors(self) -> None:
        """Error in DNS operations should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0

        def _fail_first_two(*_args: object, **_kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            raise SyscallError("dns fail")

        with patch.object(kernel, "syscall", side_effect=_fail_first_two):
            output = runner.run("networking")
        assert "(Error: dns fail)" in output

    def test_socket_error_returns_early(self) -> None:
        """Error creating server socket should return early."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("sock fail")):
            output = runner.run("networking")
        assert "(Error: sock fail)" in output
        assert "Step 4" not in output

    def test_client_connect_error(self) -> None:
        """Error in client connection should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_on_client(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count > 4:  # noqa: PLR2004
                raise SyscallError("client fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_on_client):
            output = runner.run("networking")
        assert "(Error: client fail)" in output


class TestInterruptsLessonErrors:
    """Verify interrupts lesson error paths."""

    def test_all_interrupt_errors(self) -> None:
        """All interrupt operations failing should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("int fail")):
            output = runner.run("interrupts")
        error_count = output.count("(Error: int fail)")
        min_errors = 4
        assert error_count >= min_errors


class TestTcpLessonErrors:
    """Verify TCP lesson error paths."""

    def test_listen_error_returns_early(self) -> None:
        """Error in TCP listen should return early."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        with patch.object(kernel, "syscall", side_effect=SyscallError("tcp fail")):
            output = runner.run("tcp")
        assert "(Error: tcp fail)" in output
        assert "Step 2" not in output

    def test_send_error(self) -> None:
        """Error in TCP send should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_on_send(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count > 3:  # noqa: PLR2004
                raise SyscallError("send fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_on_send):
            output = runner.run("tcp")
        assert "(Error: send fail)" in output

    def test_recv_error(self) -> None:
        """Error in TCP receive should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_on_recv(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count > 4:  # noqa: PLR2004
                raise SyscallError("recv fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_on_recv):
            output = runner.run("tcp")
        assert "(Error: recv fail)" in output

    def test_info_error(self) -> None:
        """Error getting TCP info should be caught gracefully."""
        kernel = _failing_kernel()
        runner = TutorialRunner(kernel)
        call_count = 0
        original = kernel.syscall

        def _fail_on_info(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count > 5:  # noqa: PLR2004
                raise SyscallError("info fail")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(kernel, "syscall", side_effect=_fail_on_info):
            output = runner.run("tcp")
        assert "(Error: info fail)" in output
