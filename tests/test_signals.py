"""Tests for the signal delivery system.

Signals are asynchronous notifications sent to processes. They mirror
Unix signals: SIGTERM (polite shutdown), SIGKILL (forced kill),
SIGSTOP (pause), and SIGCONT (resume).
"""

import pytest

from py_os.kernel import Kernel
from py_os.process import Process, ProcessState
from py_os.shell import Shell
from py_os.signals import Signal, SignalError
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


def _running_process(kernel: Kernel, name: str = "test") -> Process:
    """Create a process and dispatch it so it's RUNNING."""
    proc = kernel.create_process(name=name, num_pages=4)
    assert kernel.scheduler is not None
    kernel.scheduler.dispatch()
    return proc


class TestSignalEnum:
    """Verify signal definitions."""

    def test_signal_values_match_unix(self) -> None:
        """Signals should have standard Unix numeric values."""
        expected_sigkill = 9
        expected_sigterm = 15
        expected_sigcont = 18
        expected_sigstop = 19
        assert expected_sigkill == Signal.SIGKILL
        assert expected_sigterm == Signal.SIGTERM
        assert expected_sigcont == Signal.SIGCONT
        assert expected_sigstop == Signal.SIGSTOP


class TestSignalDelivery:
    """Verify that signals produce the correct effects on processes."""

    def test_sigkill_terminates_running(self) -> None:
        """SIGKILL should terminate a running process."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert proc.state is ProcessState.TERMINATED

    def test_sigkill_terminates_ready(self) -> None:
        """SIGKILL should terminate a ready process."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="ready", num_pages=4)
        # proc is READY (admitted but not dispatched)
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert proc.state is ProcessState.TERMINATED

    def test_sigkill_terminates_waiting(self) -> None:
        """SIGKILL should terminate a waiting process."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        proc.wait()  # RUNNING → WAITING
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert proc.state is ProcessState.TERMINATED

    def test_sigkill_cannot_be_handled(self) -> None:
        """SIGKILL should ignore any registered handler."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGKILL, handler)
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert proc.state is ProcessState.TERMINATED
        assert not handler_called

    def test_sigterm_terminates_running(self) -> None:
        """SIGTERM should terminate a running process."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
        assert proc.state is ProcessState.TERMINATED

    def test_sigterm_calls_handler(self) -> None:
        """SIGTERM should invoke a registered handler before terminating."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGTERM, handler)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
        assert handler_called
        assert proc.state is ProcessState.TERMINATED

    def test_sigstop_pauses_running(self) -> None:
        """SIGSTOP should move a running process to WAITING."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGSTOP)
        assert proc.state is ProcessState.WAITING

    def test_sigcont_resumes_waiting(self) -> None:
        """SIGCONT should move a waiting process to READY."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        proc.wait()  # RUNNING → WAITING
        kernel.send_signal(proc.pid, Signal.SIGCONT)
        assert proc.state is ProcessState.READY

    def test_sigcont_on_non_waiting_is_noop(self) -> None:
        """SIGCONT on a running process should be a no-op."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGCONT)
        assert proc.state is ProcessState.RUNNING

    def test_signal_to_nonexistent_raises(self) -> None:
        """Sending a signal to a missing PID should raise."""
        kernel = _booted_kernel()
        with pytest.raises(SignalError, match="not found"):
            kernel.send_signal(9999, Signal.SIGTERM)

    def test_signal_to_terminated_raises(self) -> None:
        """Sending a signal to a terminated process should raise."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        proc.terminate()
        with pytest.raises(SignalError, match="terminated"):
            kernel.send_signal(proc.pid, Signal.SIGTERM)

    def test_signal_is_logged(self) -> None:
        """Signal delivery should be logged."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
        assert kernel.logger is not None
        assert any("SIGTERM" in e.message for e in kernel.logger.entries)


class TestSignalHandlers:
    """Verify signal handler registration."""

    def test_register_handler(self) -> None:
        """A handler should be callable on signal delivery."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        messages: list[str] = []

        def cleanup() -> None:
            messages.append("cleaned up")

        kernel.register_signal_handler(proc.pid, Signal.SIGTERM, cleanup)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
        assert messages == ["cleaned up"]

    def test_handler_not_called_for_different_signal(self) -> None:
        """A SIGTERM handler should not fire on SIGKILL."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGTERM, handler)
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert not handler_called

    def test_handler_for_nonexistent_process_raises(self) -> None:
        """Registering a handler for a missing PID should raise."""
        kernel = _booted_kernel()
        with pytest.raises(SignalError, match="not found"):
            kernel.register_signal_handler(9999, Signal.SIGTERM, lambda: None)


class TestSyscallSignal:
    """Verify the signal syscall."""

    def test_sys_send_signal(self) -> None:
        """SYS_SEND_SIGNAL should deliver a signal via the kernel."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.syscall(SyscallNumber.SYS_SEND_SIGNAL, pid=proc.pid, signal=Signal.SIGTERM)
        assert proc.state is ProcessState.TERMINATED

    def test_sys_send_signal_invalid_pid(self) -> None:
        """SYS_SEND_SIGNAL to a missing PID should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SEND_SIGNAL, pid=9999, signal=Signal.SIGTERM)


class TestShellSignalCommand:
    """Verify the shell's signal command."""

    def test_signal_command(self) -> None:
        """The signal command should deliver a signal by name."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"signal {proc.pid} SIGTERM")
        assert "delivered" in result.lower() or "SIGTERM" in result

    def test_signal_missing_args(self) -> None:
        """Signal without args should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("signal")
        assert "usage" in result.lower()

    def test_signal_invalid_name(self) -> None:
        """An invalid signal name should produce an error."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"signal {proc.pid} SIGFOO")
        assert "error" in result.lower() or "unknown" in result.lower()

    def test_help_includes_signal(self) -> None:
        """Help should list the signal command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "signal" in result
