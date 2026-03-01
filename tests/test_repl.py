"""Tests for the REPL (Read-Eval-Print Loop) and shell exit command.

The REPL is the interactive terminal interface. Since it involves I/O,
we test the components it depends on rather than the loop itself:
- The shell's ``exit`` command signals shutdown.
- The REPL module's helper functions are testable in isolation.
"""

from unittest.mock import patch

from py_os.kernel import ExecutionMode, Kernel, KernelState
from py_os.repl import build_prompt, format_boot_log
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel, Shell(kernel=kernel)


class TestShellExit:
    """Verify the exit command."""

    def test_exit_returns_sentinel(self) -> None:
        """The exit command should return the EXIT sentinel."""
        _kernel, shell = _booted_shell()
        result = shell.execute("exit")
        assert result == Shell.EXIT_SENTINEL

    def test_exit_shuts_down_kernel(self) -> None:
        """The exit command should shut down the kernel."""
        kernel, shell = _booted_shell()
        shell.execute("exit")
        assert kernel.state is KernelState.SHUTDOWN

    def test_help_includes_exit(self) -> None:
        """Help should list the exit command."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "exit" in result


class TestREPLHelpers:
    """Verify REPL helper functions."""

    def test_build_prompt_as_root(self) -> None:
        """The prompt should show the username."""
        kernel, _shell = _booted_shell()
        prompt = build_prompt(kernel)
        assert "root" in prompt

    def test_build_prompt_as_user(self) -> None:
        """The prompt should reflect the current user."""
        kernel, _shell = _booted_shell()
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=user["uid"])
        prompt = build_prompt(kernel)
        assert "alice" in prompt

    def test_format_boot_log(self) -> None:
        """format_boot_log should produce a displayable boot banner."""
        log = ["[POST] Memory: 64 frames ... OK", "[OK] Scheduler"]
        banner = format_boot_log(log)
        assert "PyOS" in banner
        assert "[POST]" in banner
        assert "[OK] Scheduler" in banner

    def test_boot_banner_dynamic(self) -> None:
        """The boot banner built from real boot log should contain OS info."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        banner = format_boot_log(kernel.dmesg())
        assert "PyOS" in banner
        assert "[OK]" in banner

    def test_build_prompt_when_not_running(self) -> None:
        """Build prompt should return a fallback when kernel is not running."""
        kernel = Kernel()
        prompt = build_prompt(kernel)
        assert prompt == "pyos $ "

    def test_build_prompt_syscall_error_fallback(self) -> None:
        """Build prompt should return fallback when whoami syscall fails."""
        kernel, _shell = _booted_shell()
        with patch.object(kernel, "syscall", side_effect=SyscallError("whoami failed")):
            prompt = build_prompt(kernel)
        assert prompt == "pyos $ "

    def test_build_prompt_key_error_fallback(self) -> None:
        """Build prompt should return fallback when response lacks username."""
        kernel, _shell = _booted_shell()
        with patch.object(kernel, "syscall", return_value={}):
            prompt = build_prompt(kernel)
        assert prompt == "pyos $ "
