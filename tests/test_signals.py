"""Tests for the signal delivery system.

Signals are asynchronous notifications sent to processes. They mirror
Unix signals: SIGTERM (polite shutdown), SIGKILL (forced kill),
SIGSTOP (pause), SIGCONT (resume), and user-defined SIGUSR1/SIGUSR2.
"""

import pytest

from py_os.kernel import Kernel
from py_os.process import Process, ProcessState
from py_os.shell import Shell
from py_os.signals import (
    DEFAULT_ACTIONS,
    UNCATCHABLE,
    Signal,
    SignalAction,
    SignalError,
)
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

    def test_sigusr1_value_matches_unix(self) -> None:
        """SIGUSR1 should have the standard Unix value 10."""
        expected = 10
        assert expected == Signal.SIGUSR1

    def test_sigusr2_value_matches_unix(self) -> None:
        """SIGUSR2 should have the standard Unix value 12."""
        expected = 12
        assert expected == Signal.SIGUSR2

    def test_all_signals_have_default_action(self) -> None:
        """Every Signal member should have a DEFAULT_ACTIONS entry."""
        for sig in Signal:
            assert sig in DEFAULT_ACTIONS, f"{sig.name} missing from DEFAULT_ACTIONS"

    def test_uncatchable_signals(self) -> None:
        """UNCATCHABLE should contain exactly SIGKILL and SIGSTOP."""
        expected = frozenset({Signal.SIGKILL, Signal.SIGSTOP})
        assert expected == UNCATCHABLE


class TestSignalActions:
    """Verify the default action table maps signals correctly."""

    def test_default_action_sigterm(self) -> None:
        """SIGTERM default action should be TERMINATE."""
        assert DEFAULT_ACTIONS[Signal.SIGTERM] is SignalAction.TERMINATE

    def test_default_action_sigkill(self) -> None:
        """SIGKILL default action should be TERMINATE."""
        assert DEFAULT_ACTIONS[Signal.SIGKILL] is SignalAction.TERMINATE

    def test_default_action_sigstop(self) -> None:
        """SIGSTOP default action should be STOP."""
        assert DEFAULT_ACTIONS[Signal.SIGSTOP] is SignalAction.STOP

    def test_default_action_sigcont(self) -> None:
        """SIGCONT default action should be CONTINUE."""
        assert DEFAULT_ACTIONS[Signal.SIGCONT] is SignalAction.CONTINUE

    def test_default_action_sigusr1(self) -> None:
        """SIGUSR1 default action should be IGNORE."""
        assert DEFAULT_ACTIONS[Signal.SIGUSR1] is SignalAction.IGNORE

    def test_default_action_sigusr2(self) -> None:
        """SIGUSR2 default action should be IGNORE."""
        assert DEFAULT_ACTIONS[Signal.SIGUSR2] is SignalAction.IGNORE


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
        proc.wait()  # RUNNING -> WAITING
        kernel.send_signal(proc.pid, Signal.SIGKILL)
        assert proc.state is ProcessState.TERMINATED

    def test_sigkill_cannot_be_handled(self) -> None:
        """Registering a SIGKILL handler should raise SignalError."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)

        with pytest.raises(SignalError, match="uncatchable"):
            kernel.register_signal_handler(proc.pid, Signal.SIGKILL, lambda: None)

    def test_sigterm_terminates_running(self) -> None:
        """SIGTERM with no handler should terminate a running process."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
        assert proc.state is ProcessState.TERMINATED

    def test_sigterm_calls_handler(self) -> None:
        """SIGTERM with a handler should invoke the handler but NOT terminate."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGTERM, handler)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
        assert handler_called
        # Handler replaces default action -- process stays alive
        assert proc.state is ProcessState.RUNNING

    def test_sigterm_without_handler_terminates(self) -> None:
        """SIGTERM with no handler should perform default terminate."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGTERM)
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
        proc.wait()  # RUNNING -> WAITING
        kernel.send_signal(proc.pid, Signal.SIGCONT)
        assert proc.state is ProcessState.READY

    def test_sigcont_on_non_waiting_is_noop(self) -> None:
        """SIGCONT on a running process should be a no-op."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGCONT)
        assert proc.state is ProcessState.RUNNING

    def test_sigcont_calls_handler_and_resumes(self) -> None:
        """SIGCONT with a handler should fire the handler AND resume."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        proc.wait()  # RUNNING -> WAITING
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGCONT, handler)
        kernel.send_signal(proc.pid, Signal.SIGCONT)
        assert handler_called
        assert proc.state is ProcessState.READY

    def test_sigusr1_ignored_by_default(self) -> None:
        """SIGUSR1 with no handler should be a no-op."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGUSR1)
        assert proc.state is ProcessState.RUNNING

    def test_sigusr2_ignored_by_default(self) -> None:
        """SIGUSR2 with no handler should be a no-op."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        kernel.send_signal(proc.pid, Signal.SIGUSR2)
        assert proc.state is ProcessState.RUNNING

    def test_sigusr1_calls_handler(self) -> None:
        """SIGUSR1 with a handler should invoke the handler."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGUSR1, handler)
        kernel.send_signal(proc.pid, Signal.SIGUSR1)
        assert handler_called

    def test_sigusr2_calls_handler(self) -> None:
        """SIGUSR2 with a handler should invoke the handler."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        messages: list[str] = []

        kernel.register_signal_handler(proc.pid, Signal.SIGUSR2, lambda: messages.append("usr2"))
        kernel.send_signal(proc.pid, Signal.SIGUSR2)
        assert messages == ["usr2"]

    def test_sigstop_cannot_be_handled(self) -> None:
        """Registering a SIGSTOP handler should raise SignalError."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)

        with pytest.raises(SignalError, match="uncatchable"):
            kernel.register_signal_handler(proc.pid, Signal.SIGSTOP, lambda: None)

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

    def test_register_handler_sigkill_raises(self) -> None:
        """Registering a SIGKILL handler should raise with 'uncatchable'."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        with pytest.raises(SignalError, match="uncatchable"):
            kernel.register_signal_handler(proc.pid, Signal.SIGKILL, lambda: None)

    def test_register_handler_sigstop_raises(self) -> None:
        """Registering a SIGSTOP handler should raise with 'uncatchable'."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        with pytest.raises(SignalError, match="uncatchable"):
            kernel.register_signal_handler(proc.pid, Signal.SIGSTOP, lambda: None)

    def test_register_handler_sigusr1_succeeds(self) -> None:
        """Registering a SIGUSR1 handler should succeed without error."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        # Should not raise
        kernel.register_signal_handler(proc.pid, Signal.SIGUSR1, lambda: None)

    def test_handler_isolation_across_user_signals(self) -> None:
        """A SIGUSR1 handler should not fire for SIGUSR2."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        usr1_called = False

        def usr1_handler() -> None:
            nonlocal usr1_called
            usr1_called = True

        kernel.register_signal_handler(proc.pid, Signal.SIGUSR1, usr1_handler)
        kernel.send_signal(proc.pid, Signal.SIGUSR2)
        assert not usr1_called


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


class TestSyscallRegisterHandler:
    """Verify the SYS_REGISTER_HANDLER syscall."""

    def test_sys_register_handler(self) -> None:
        """SYS_REGISTER_HANDLER should succeed and return confirmation."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        result: str = kernel.syscall(
            SyscallNumber.SYS_REGISTER_HANDLER,
            pid=proc.pid,
            signal=Signal.SIGTERM,
            handler=lambda: None,
        )
        assert "handler registered" in result.lower()

    def test_sys_register_handler_uncatchable(self) -> None:
        """SYS_REGISTER_HANDLER for SIGKILL should raise SyscallError."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        with pytest.raises(SyscallError, match="uncatchable"):
            kernel.syscall(
                SyscallNumber.SYS_REGISTER_HANDLER,
                pid=proc.pid,
                signal=Signal.SIGKILL,
                handler=lambda: None,
            )

    def test_sys_register_handler_invalid_pid(self) -> None:
        """SYS_REGISTER_HANDLER for a missing PID should raise SyscallError."""
        kernel = _booted_kernel()
        invalid_pid = 9999
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(
                SyscallNumber.SYS_REGISTER_HANDLER,
                pid=invalid_pid,
                signal=Signal.SIGTERM,
                handler=lambda: None,
            )


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

    def test_signal_sigusr1_command(self) -> None:
        """'signal <pid> SIGUSR1' should work without error."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"signal {proc.pid} SIGUSR1")
        assert "SIGUSR1" in result

    def test_signal_sigusr2_command(self) -> None:
        """'signal <pid> SIGUSR2' should work without error."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"signal {proc.pid} SIGUSR2")
        assert "SIGUSR2" in result


class TestShellHandleCommand:
    """Verify the shell's handle command for registering signal handlers."""

    def test_handle_registers_handler(self) -> None:
        """'handle <pid> SIGTERM log' should return success."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"handle {proc.pid} SIGTERM log")
        assert "handler registered" in result.lower()

    def test_handle_log_fires_on_signal(self) -> None:
        """Register 'log' for SIGUSR1, send SIGUSR1, check env var."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        shell.execute(f"handle {proc.pid} SIGUSR1 log")
        shell.execute(f"signal {proc.pid} SIGUSR1")
        env_key = f"_LAST_SIGNAL_{proc.pid}"
        value = kernel.syscall(SyscallNumber.SYS_GET_ENV, key=env_key)
        assert value == "SIGUSR1"

    def test_handle_ignore_suppresses_default(self) -> None:
        """Register 'ignore' for SIGTERM, send SIGTERM, process NOT terminated."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        shell.execute(f"handle {proc.pid} SIGTERM ignore")
        shell.execute(f"signal {proc.pid} SIGTERM")
        assert proc.state is ProcessState.RUNNING

    def test_handle_uncatchable_error(self) -> None:
        """'handle <pid> SIGKILL log' should return an error."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"handle {proc.pid} SIGKILL log")
        assert "error" in result.lower()

    def test_handle_missing_args(self) -> None:
        """'handle' with no args should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("handle")
        assert "usage" in result.lower()

    def test_handle_invalid_signal(self) -> None:
        """'handle <pid> BOGUS log' should show an error."""
        kernel = _booted_kernel()
        proc = _running_process(kernel)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"handle {proc.pid} BOGUS log")
        assert "error" in result.lower()

    def test_handle_invalid_pid(self) -> None:
        """'handle abc SIGTERM log' should show an error."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("handle abc SIGTERM log")
        assert "error" in result.lower()

    def test_help_includes_handle(self) -> None:
        """Help output should list the handle command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "handle" in result
