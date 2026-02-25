"""Tests for the environment variable system.

Environment variables are key-value string pairs that configure process
behaviour. Each process gets its own copy — changes don't leak to the
parent or siblings. The kernel maintains a global environment that new
processes inherit from.
"""

import pytest

from py_os.env import Environment
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


class TestEnvironment:
    """Verify the Environment key-value store."""

    def test_get_and_set(self) -> None:
        """Setting a variable should make it retrievable."""
        env = Environment()
        env.set("HOME", "/root")
        assert env.get("HOME") == "/root"

    def test_get_missing_returns_none(self) -> None:
        """Getting a missing key should return None."""
        env = Environment()
        assert env.get("MISSING") is None

    def test_get_missing_with_default(self) -> None:
        """Getting a missing key with a default should return the default."""
        env = Environment()
        assert env.get("MISSING", "fallback") == "fallback"

    def test_set_overwrites(self) -> None:
        """Setting an existing key should overwrite the value."""
        env = Environment()
        env.set("X", "old")
        env.set("X", "new")
        assert env.get("X") == "new"

    def test_delete(self) -> None:
        """Deleting a variable should remove it."""
        env = Environment()
        env.set("X", "val")
        env.delete("X")
        assert env.get("X") is None

    def test_delete_missing_raises(self) -> None:
        """Deleting a non-existent key should raise KeyError."""
        env = Environment()
        with pytest.raises(KeyError):
            env.delete("NOPE")

    def test_items(self) -> None:
        """Items should return all key-value pairs."""
        env = Environment()
        env.set("A", "1")
        env.set("B", "2")
        items = dict(env.items())
        assert items == {"A": "1", "B": "2"}

    def test_copy_is_independent(self) -> None:
        """A copied environment should be independent of the original."""
        env = Environment()
        env.set("X", "original")
        child = env.copy()
        child.set("X", "modified")
        assert env.get("X") == "original"
        assert child.get("X") == "modified"

    def test_copy_inherits_all_vars(self) -> None:
        """A copy should start with all parent variables."""
        env = Environment()
        env.set("A", "1")
        env.set("B", "2")
        child = env.copy()
        assert child.get("A") == "1"
        assert child.get("B") == "2"

    def test_len(self) -> None:
        """len() should return the number of variables."""
        env = Environment()
        expected_empty = 0
        assert len(env) == expected_empty
        env.set("X", "1")
        expected_one = 1
        assert len(env) == expected_one


class TestKernelEnvironment:
    """Verify kernel-level environment management."""

    def test_kernel_has_env_after_boot(self) -> None:
        """The kernel should have a global environment after booting."""
        kernel = _booted_kernel()
        assert kernel.env is not None

    def test_kernel_env_has_defaults(self) -> None:
        """The kernel environment should have default variables."""
        kernel = _booted_kernel()
        assert kernel.env is not None
        assert kernel.env.get("PATH") is not None
        assert kernel.env.get("HOME") is not None

    def test_kernel_env_none_after_shutdown(self) -> None:
        """The environment should be torn down after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.env is None


class TestSyscallEnv:
    """Verify environment-related system calls."""

    def test_get_env(self) -> None:
        """SYS_GET_ENV should return a variable value."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_GET_ENV, key="PATH")
        assert result is not None

    def test_set_env(self) -> None:
        """SYS_SET_ENV should set a variable."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_ENV, key="MY_VAR", value="hello")
        result = kernel.syscall(SyscallNumber.SYS_GET_ENV, key="MY_VAR")
        assert result == "hello"

    def test_list_env(self) -> None:
        """SYS_LIST_ENV should return all variables."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LIST_ENV)
        assert "PATH" in dict(result)

    def test_delete_env(self) -> None:
        """SYS_DELETE_ENV should remove a variable."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_ENV, key="TEMP", value="val")
        kernel.syscall(SyscallNumber.SYS_DELETE_ENV, key="TEMP")
        result = kernel.syscall(SyscallNumber.SYS_GET_ENV, key="TEMP")
        assert result is None

    def test_delete_env_missing_raises(self) -> None:
        """Deleting a non-existent variable should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_DELETE_ENV, key="NOPE")


class TestShellEnvCommands:
    """Verify the shell's environment commands."""

    def test_env_lists_variables(self) -> None:
        """The env command should list all environment variables."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("env")
        assert "PATH" in result
        assert "HOME" in result

    def test_export_sets_variable(self) -> None:
        """The export command should set an environment variable."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        shell.execute("export GREETING=hello")
        result = shell.execute("env")
        assert "GREETING=hello" in result

    def test_export_missing_args(self) -> None:
        """Export without args should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("export")
        assert "usage" in result.lower()

    def test_export_invalid_format(self) -> None:
        """Export without '=' should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("export NOEQUALS")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_unset_removes_variable(self) -> None:
        """The unset command should remove an environment variable."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        shell.execute("export TEMP=val")
        shell.execute("unset TEMP")
        result = shell.execute("env")
        assert "TEMP" not in result

    def test_help_includes_env_commands(self) -> None:
        """Help should list env, export, and unset commands."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "env" in result
        assert "export" in result
        assert "unset" in result
