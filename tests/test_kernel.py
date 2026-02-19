"""Tests for the kernel module.

The kernel is the core of the OS. It bootstraps subsystems, manages
the system lifecycle (boot → run → shutdown), and will eventually
coordinate all other modules (scheduler, memory, file system, etc.).
"""

import pytest

from py_os.kernel import Kernel, KernelState


class TestKernelInitialisation:
    """Verify that a freshly created kernel is in the correct default state."""

    def test_initial_state_is_shutdown(self) -> None:
        """A new kernel should start in the SHUTDOWN state."""
        kernel = Kernel()
        assert kernel.state is KernelState.SHUTDOWN

    def test_kernel_has_no_uptime_before_boot(self) -> None:
        """Uptime should be zero before the kernel boots."""
        kernel = Kernel()
        expected_uptime = 0.0
        assert kernel.uptime == expected_uptime


class TestKernelBoot:
    """Verify the boot sequence transitions and side-effects."""

    def test_boot_transitions_to_running(self) -> None:
        """Booting should move the kernel from SHUTDOWN to RUNNING."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.state is KernelState.RUNNING

    def test_boot_when_already_running_raises(self) -> None:
        """Booting an already-running kernel is an error."""
        kernel = Kernel()
        kernel.boot()
        with pytest.raises(RuntimeError, match="Cannot boot"):
            kernel.boot()

    def test_uptime_is_positive_after_boot(self) -> None:
        """After booting, uptime should be greater than zero."""
        kernel = Kernel()
        kernel.boot()
        min_uptime = 0.0
        assert kernel.uptime > min_uptime


class TestKernelShutdown:
    """Verify the shutdown sequence transitions and side-effects."""

    def test_shutdown_transitions_to_shutdown_state(self) -> None:
        """Shutting down should return the kernel to SHUTDOWN."""
        kernel = Kernel()
        kernel.boot()
        kernel.shutdown()
        assert kernel.state is KernelState.SHUTDOWN

    def test_shutdown_when_not_running_raises(self) -> None:
        """Shutting down a kernel that isn't running is an error."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="Cannot shutdown"):
            kernel.shutdown()

    def test_uptime_resets_after_shutdown(self) -> None:
        """Uptime should be zero after shutdown."""
        kernel = Kernel()
        kernel.boot()
        kernel.shutdown()
        expected_uptime = 0.0
        assert kernel.uptime == expected_uptime


class TestKernelReboot:
    """Verify that the kernel can be rebooted (shutdown then boot)."""

    def test_reboot_returns_to_running(self) -> None:
        """A full reboot cycle should leave the kernel RUNNING."""
        kernel = Kernel()
        kernel.boot()
        kernel.shutdown()
        kernel.boot()
        assert kernel.state is KernelState.RUNNING
