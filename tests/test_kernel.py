"""Tests for the kernel module.

The kernel is the core of the OS. It bootstraps subsystems, manages
the system lifecycle (boot → run → shutdown), and coordinates all
other modules (scheduler, memory, file system).
"""

import pytest

from py_os.kernel import Kernel, KernelState
from py_os.process.pcb import ProcessState


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


TOTAL_FRAMES = 64
NUM_MEMORY_PAGES = 4


class TestKernelSubsystems:
    """Verify that boot initialises and exposes subsystems."""

    def test_scheduler_available_after_boot(self) -> None:
        """The scheduler should be accessible after booting."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.scheduler is not None

    def test_memory_manager_available_after_boot(self) -> None:
        """The memory manager should be accessible after booting."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.memory is not None
        assert kernel.memory.total_frames == TOTAL_FRAMES

    def test_filesystem_available_after_boot(self) -> None:
        """The file system should be accessible after booting."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.filesystem is not None
        assert kernel.filesystem.exists("/")

    def test_user_manager_available_after_boot(self) -> None:
        """The user manager should be accessible after booting."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.user_manager is not None

    def test_device_manager_available_after_boot(self) -> None:
        """The device manager should be accessible after booting."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.device_manager is not None

    def test_subsystems_none_before_boot(self) -> None:
        """Subsystems should not be accessible before booting."""
        kernel = Kernel()
        assert kernel.scheduler is None
        assert kernel.memory is None
        assert kernel.filesystem is None
        assert kernel.user_manager is None
        assert kernel.device_manager is None

    def test_subsystems_none_after_shutdown(self) -> None:
        """Subsystems should be torn down after shutdown."""
        kernel = Kernel()
        kernel.boot()
        kernel.shutdown()
        assert kernel.scheduler is None
        assert kernel.memory is None
        assert kernel.filesystem is None
        assert kernel.user_manager is None
        assert kernel.device_manager is None


class TestKernelCreateProcess:
    """Verify the kernel's coordinated process creation."""

    def test_create_process_returns_process(self) -> None:
        """Creating a process should return a Process object."""
        kernel = Kernel()
        kernel.boot()
        process = kernel.create_process(name="init", num_pages=NUM_MEMORY_PAGES)
        assert process.name == "init"

    def test_created_process_is_ready(self) -> None:
        """A newly created process should be admitted and READY."""
        kernel = Kernel()
        kernel.boot()
        process = kernel.create_process(name="init", num_pages=NUM_MEMORY_PAGES)
        assert process.state is ProcessState.READY

    def test_created_process_has_memory(self) -> None:
        """The kernel should allocate memory for the new process."""
        kernel = Kernel()
        kernel.boot()
        process = kernel.create_process(name="init", num_pages=NUM_MEMORY_PAGES)
        assert kernel.memory is not None
        assert len(kernel.memory.pages_for(process.pid)) == NUM_MEMORY_PAGES

    def test_created_process_is_in_scheduler(self) -> None:
        """The new process should be added to the scheduler's ready queue."""
        kernel = Kernel()
        kernel.boot()
        kernel.create_process(name="init", num_pages=NUM_MEMORY_PAGES)
        assert kernel.scheduler is not None
        expected_count = 1
        assert kernel.scheduler.ready_count == expected_count

    def test_create_process_before_boot_raises(self) -> None:
        """Cannot create a process if the kernel hasn't booted."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            kernel.create_process(name="init", num_pages=NUM_MEMORY_PAGES)

    def test_create_multiple_processes(self) -> None:
        """Multiple processes can be created and tracked independently."""
        kernel = Kernel()
        kernel.boot()
        p1 = kernel.create_process(name="shell", num_pages=NUM_MEMORY_PAGES)
        p2 = kernel.create_process(name="daemon", num_pages=NUM_MEMORY_PAGES)
        assert p1.pid != p2.pid
        assert kernel.scheduler is not None
        expected_count = 2
        assert kernel.scheduler.ready_count == expected_count


class TestKernelTerminateProcess:
    """Verify the kernel's coordinated process termination."""

    def test_terminate_frees_memory(self) -> None:
        """Terminating a process should release its memory frames."""
        kernel = Kernel()
        kernel.boot()
        process = kernel.create_process(name="init", num_pages=NUM_MEMORY_PAGES)
        assert kernel.memory is not None
        free_before = kernel.memory.free_frames

        # Must dispatch first (only RUNNING processes can be terminated)
        assert kernel.scheduler is not None
        kernel.scheduler.dispatch()
        kernel.terminate_process(pid=process.pid)

        assert kernel.memory.free_frames == free_before + NUM_MEMORY_PAGES
        assert kernel.memory.pages_for(process.pid) == []

    def test_terminate_before_boot_raises(self) -> None:
        """Cannot terminate a process if the kernel hasn't booted."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            kernel.terminate_process(pid=1)
