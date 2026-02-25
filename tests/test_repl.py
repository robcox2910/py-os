"""Tests for the REPL (Read-Eval-Print Loop) and shell exit command.

The REPL is the interactive terminal interface. Since it involves I/O,
we test the components it depends on rather than the loop itself:
- The shell's ``exit`` command signals shutdown.
- The REPL module's helper functions are testable in isolation.
"""

from py_os.kernel import ExecutionMode, Kernel, KernelState
from py_os.repl import boot_banner, build_prompt
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


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

    def test_boot_banner(self) -> None:
        """The boot banner should contain OS info."""
        banner = boot_banner()
        assert "py-os" in banner.lower() or "PyOS" in banner
