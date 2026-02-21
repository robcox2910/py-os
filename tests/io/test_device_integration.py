"""Tests for device integration into the kernel, syscalls, and shell.

Verifies that:
- The kernel boots a DeviceManager with default devices.
- Device-related syscalls work (read, write, list).
- The shell exposes devices and devread/devwrite commands.
"""

import pytest

from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = _booted_kernel()
    return kernel, Shell(kernel=kernel)


class TestKernelDeviceSubsystem:
    """Verify that the kernel manages devices as a subsystem."""

    def test_device_manager_available_after_boot(self) -> None:
        """The device manager should be accessible after booting."""
        kernel = _booted_kernel()
        assert kernel.device_manager is not None

    def test_device_manager_none_before_boot(self) -> None:
        """The device manager should not be accessible before booting."""
        kernel = Kernel()
        assert kernel.device_manager is None

    def test_device_manager_none_after_shutdown(self) -> None:
        """The device manager should be torn down after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.device_manager is None

    def test_default_devices_registered(self) -> None:
        """Boot should register null, console, and random devices."""
        kernel = _booted_kernel()
        assert kernel.device_manager is not None
        names = kernel.device_manager.list_devices()
        assert "null" in names
        assert "console" in names
        assert "random" in names


class TestSyscallDeviceOps:
    """Verify device-related system calls."""

    def test_list_devices(self) -> None:
        """SYS_LIST_DEVICES should return all device names."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LIST_DEVICES)
        assert "null" in result
        assert "console" in result
        assert "random" in result

    def test_device_write_and_read_console(self) -> None:
        """Writing to console then reading should round-trip data."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_DEVICE_WRITE, device="console", data=b"hello")
        result = kernel.syscall(SyscallNumber.SYS_DEVICE_READ, device="console")
        assert result == b"hello"

    def test_device_read_null(self) -> None:
        """Reading from null should return empty bytes."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_DEVICE_READ, device="null")
        assert result == b""

    def test_device_write_null(self) -> None:
        """Writing to null should succeed silently."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_DEVICE_WRITE, device="null", data=b"gone")

    def test_device_read_random(self) -> None:
        """Reading from random should return bytes."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_DEVICE_READ, device="random")
        assert len(result) > 0

    def test_device_write_random_raises(self) -> None:
        """Writing to random should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="read-only"):
            kernel.syscall(SyscallNumber.SYS_DEVICE_WRITE, device="random", data=b"nope")

    def test_device_read_nonexistent_raises(self) -> None:
        """Reading from a non-existent device should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_DEVICE_READ, device="nope")

    def test_device_write_nonexistent_raises(self) -> None:
        """Writing to a non-existent device should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_DEVICE_WRITE, device="nope", data=b"x")


class TestShellDeviceCommands:
    """Verify the shell's device-related commands."""

    def test_devices_lists_all(self) -> None:
        """The devices command should list registered devices."""
        _kernel, shell = _booted_shell()
        result = shell.execute("devices")
        assert "null" in result
        assert "console" in result
        assert "random" in result

    def test_devwrite_and_devread(self) -> None:
        """Devwrite then devread on console should round-trip."""
        _kernel, shell = _booted_shell()
        shell.execute("devwrite console hello device!")
        result = shell.execute("devread console")
        assert "hello device!" in result

    def test_devread_missing_arg(self) -> None:
        """Devread without a device name should produce usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("devread")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_devwrite_missing_args(self) -> None:
        """Devwrite without enough args should produce usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("devwrite")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_help_includes_device_commands(self) -> None:
        """Help should list device commands."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "devices" in result
        assert "devread" in result
        assert "devwrite" in result
