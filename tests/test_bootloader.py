"""Tests for the bootloader — simulated firmware POST and boot chain.

The bootloader simulates the boot process that every real computer
follows: Firmware POST → Bootloader → Kernel → Userspace.
"""

import json
from pathlib import Path

import pytest

from py_os.bootloader import BootError, Bootloader, BootStage, KernelImage, PostResult
from py_os.kernel import ExecutionMode, Kernel, KernelState
from py_os.process.pcb import ProcessState
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber

_IMAGE_FRAMES_SMALL = 128
_IMAGE_FRAMES_LARGE = 256

# -- Cycle 1: Data types -------------------------------------------------------


class TestBootStage:
    """Verify BootStage enum members."""

    def test_boot_stage_values(self) -> None:
        """BootStage should have four members matching the boot chain."""
        assert BootStage.FIRMWARE == "firmware"
        assert BootStage.BOOTLOADER == "bootloader"
        assert BootStage.KERNEL == "kernel"
        assert BootStage.USERSPACE == "userspace"


class TestKernelImage:
    """Verify KernelImage frozen dataclass."""

    def test_kernel_image_construction(self) -> None:
        """KernelImage should store version, frames, policy, and boot args."""
        img = KernelImage(
            version="0.1.0",
            total_frames=_IMAGE_FRAMES_SMALL,
            default_policy="fcfs",
            boot_args={"quiet": "1"},
        )
        assert img.version == "0.1.0"
        assert img.total_frames == _IMAGE_FRAMES_SMALL
        assert img.default_policy == "fcfs"
        assert img.boot_args == {"quiet": "1"}

    def test_kernel_image_frozen(self) -> None:
        """KernelImage should be immutable."""
        img = KernelImage(
            version="0.1.0",
            total_frames=64,
            default_policy="fcfs",
        )
        with pytest.raises(AttributeError):
            img.version = "changed"  # type: ignore[misc]


class TestPostResult:
    """Verify PostResult frozen dataclass."""

    def test_post_result_passed_all_ok(self) -> None:
        """When all checks pass, the passed property should return True."""
        result = PostResult(
            memory_ok=True,
            disk_ok=True,
            devices_ok=True,
            messages=("Memory: OK", "Disk: OK", "Devices: OK"),
        )
        assert result.passed is True

    def test_post_result_failed_memory(self) -> None:
        """When memory fails, passed should return False."""
        result = PostResult(
            memory_ok=False,
            disk_ok=True,
            devices_ok=True,
            messages=("Memory: FAIL",),
        )
        assert result.passed is False


class TestBootError:
    """Verify BootError exception."""

    def test_boot_error_is_runtime_error(self) -> None:
        """BootError should be a RuntimeError subclass."""
        assert issubclass(BootError, RuntimeError)

    def test_boot_error_carries_message(self) -> None:
        """BootError should carry a descriptive message."""
        err = BootError("POST failed: memory check")
        assert "POST failed" in str(err)


# -- Cycle 2: POST simulation ---------------------------------------------------


class TestPost:
    """Verify firmware Power-On Self-Test simulation."""

    def test_post_succeeds_default_config(self) -> None:
        """Default 64-frame config should pass POST."""
        bl = Bootloader()
        result = bl._run_post()
        assert result.passed is True

    def test_post_fails_zero_frames(self) -> None:
        """Zero frames should cause POST to fail and boot to raise."""
        bl = Bootloader(total_frames=0)
        with pytest.raises(BootError, match="POST failed"):
            bl.boot()

    def test_post_messages_contain_checks(self) -> None:
        """POST messages should mention memory, disk, and device checks."""
        bl = Bootloader()
        result = bl._run_post()
        joined = " ".join(result.messages)
        assert "Memory" in joined
        assert "Disk" in joined
        assert "Devices" in joined

    def test_bootloader_stage_after_post(self) -> None:
        """After POST the bootloader stage should be FIRMWARE initially."""
        bl = Bootloader()
        assert bl.stage is BootStage.FIRMWARE


# -- Cycle 3: Boot chain -------------------------------------------------------


class TestBootChain:
    """Verify the full boot chain: POST → load image → kernel → userspace."""

    def test_boot_returns_running_kernel(self) -> None:
        """Boot should return a kernel in the RUNNING state."""
        bl = Bootloader()
        kernel = bl.boot()
        assert kernel.state is KernelState.RUNNING

    def test_boot_log_has_all_stages(self) -> None:
        """Boot log should contain POST, BOOT, and KERNEL entries."""
        bl = Bootloader()
        bl.boot()
        log = bl.boot_log
        assert any("[POST]" in entry for entry in log)
        assert any("[BOOT]" in entry for entry in log)

    def test_bootloader_stage_is_userspace(self) -> None:
        """After boot completes, stage should be USERSPACE."""
        bl = Bootloader()
        bl.boot()
        assert bl.stage is BootStage.USERSPACE

    def test_boot_with_custom_frames(self) -> None:
        """Custom total_frames should propagate to the kernel."""
        custom_frames = 32
        bl = Bootloader(total_frames=custom_frames)
        kernel = bl.boot()
        assert kernel._total_frames == custom_frames

    def test_load_kernel_image_from_file(self, tmp_path: object) -> None:
        """Bootloader should load kernel image config from a JSON file."""
        assert isinstance(tmp_path, Path)
        image_file = tmp_path / "kernel.json"
        image_data = {
            "version": "1.2.3",
            "total_frames": _IMAGE_FRAMES_LARGE,
            "default_policy": "rr",
            "boot_args": {"debug": "true"},
        }
        image_file.write_text(json.dumps(image_data))

        bl = Bootloader(kernel_image_path=image_file)
        kernel = bl.boot()
        assert kernel._total_frames == _IMAGE_FRAMES_LARGE
        assert any("1.2.3" in entry for entry in bl.boot_log)


# -- Cycle 4: Kernel boot log + init process -----------------------------------


def _booted_kernel() -> Kernel:
    """Create a booted kernel in KERNEL execution mode for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


class TestKernelBootLog:
    """Verify that the kernel records boot messages."""

    def test_kernel_boot_log_populated(self) -> None:
        """Boot log should be non-empty after boot."""
        kernel = _booted_kernel()
        assert len(kernel.dmesg()) > 0

    def test_kernel_boot_log_has_subsystems(self) -> None:
        """Boot log should mention key subsystems."""
        kernel = _booted_kernel()
        log_text = " ".join(kernel.dmesg())
        assert "Memory" in log_text
        assert "File system" in log_text
        assert "Scheduler" in log_text

    def test_kernel_dmesg_returns_log(self) -> None:
        """dmesg() should return the same list as the internal boot log."""
        kernel = _booted_kernel()
        log = kernel.dmesg()
        assert isinstance(log, list)
        assert all(isinstance(entry, str) for entry in log)


class TestInitProcess:
    """Verify that boot creates an init (PID 1-like) sentinel process."""

    def test_init_process_exists_after_boot(self) -> None:
        """After boot, init_pid should be set and the process in the table."""
        kernel = _booted_kernel()
        assert kernel.init_pid is not None
        assert kernel.init_pid in kernel.processes

    def test_init_process_is_ready_state(self) -> None:
        """The init process should be in the READY state."""
        kernel = _booted_kernel()
        assert kernel.init_pid is not None
        init_proc = kernel.processes[kernel.init_pid]
        assert init_proc.state is ProcessState.READY

    def test_create_process_defaults_parent_to_init(self) -> None:
        """New processes should default to init as their parent."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="test", num_pages=1)
        assert proc.parent_pid == kernel.init_pid


# -- Cycle 5: Syscalls + dmesg shell command -----------------------------------


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel, Shell(kernel=kernel)


class TestDmesgSyscalls:
    """Verify SYS_DMESG and SYS_BOOT_INFO syscalls."""

    def test_sys_dmesg_returns_list(self) -> None:
        """SYS_DMESG should return a list of boot message strings."""
        kernel = _booted_kernel()
        result: list[str] = kernel.syscall(SyscallNumber.SYS_DMESG)
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(entry, str) for entry in result)

    def test_sys_boot_info_returns_dict(self) -> None:
        """SYS_BOOT_INFO should return a dict with init_pid and uptime."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_BOOT_INFO)
        assert "init_pid" in result
        assert "uptime" in result
        assert "kernel_version" in result

    def test_dmesg_contains_ok_markers(self) -> None:
        """Dmesg output should contain [OK] markers from subsystem init."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_DMESG)
        ok_entries = [entry for entry in result if "[OK]" in entry]
        min_ok_entries = 5
        assert len(ok_entries) >= min_ok_entries


class TestDmesgShellCommand:
    """Verify the dmesg shell command."""

    def test_dmesg_command_output(self) -> None:
        """The dmesg command should show boot messages."""
        _kernel, shell = _booted_shell()
        result = shell.execute("dmesg")
        assert "[OK]" in result
        assert "Memory" in result

    def test_help_lists_dmesg(self) -> None:
        """The help command should list dmesg."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "dmesg" in result
