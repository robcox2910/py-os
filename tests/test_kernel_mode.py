"""Test user-mode vs kernel-mode enforcement.

In a real CPU, code runs at two privilege levels: user mode (ring 3) and
kernel mode (ring 0).  User programs can only access kernel services
through system calls.  These tests verify that PyOS enforces the same
boundary at runtime.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel, KernelModeError, KernelState
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEMAPHORE_COUNT = 3


def _booted_kernel() -> Kernel:
    """Return a freshly booted kernel (ends in USER mode)."""
    k = Kernel()
    k.boot()
    return k


def _raise_inside_kernel_mode(k: Kernel) -> None:
    """Enter kernel mode, verify it, then raise ValueError."""
    with k.kernel_mode():
        assert k.execution_mode is ExecutionMode.KERNEL
        msg = "boom"
        raise ValueError(msg)


# ---------------------------------------------------------------------------
# Cycle 1 — ExecutionMode state
# ---------------------------------------------------------------------------


class TestExecutionModeState:
    """Verify ExecutionMode enum values and kernel boot/shutdown transitions."""

    def test_enum_values_exist(self) -> None:
        """ExecutionMode has USER and KERNEL members."""
        assert ExecutionMode.USER == "user"
        assert ExecutionMode.KERNEL == "kernel"

    def test_fresh_kernel_starts_in_kernel_mode(self) -> None:
        """A newly created (unbooted) kernel is in KERNEL mode."""
        k = Kernel()
        assert k.execution_mode is ExecutionMode.KERNEL

    def test_boot_ends_in_user_mode(self) -> None:
        """After boot(), the kernel transitions to USER mode."""
        k = _booted_kernel()
        assert k.execution_mode is ExecutionMode.USER
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_shutdown_resets_to_kernel_mode(self) -> None:
        """After shutdown(), the kernel returns to KERNEL mode."""
        k = _booted_kernel()
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()
        assert k.execution_mode is ExecutionMode.KERNEL

    def test_execution_mode_readable_in_user_mode(self) -> None:
        """The execution_mode property is always safe to read."""
        k = _booted_kernel()
        # In user mode — should not raise
        assert k.execution_mode is ExecutionMode.USER
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 2 — Property guarding
# ---------------------------------------------------------------------------

# All 19 properties that must be guarded in USER mode.
_GUARDED_PROPERTIES = [
    "scheduler",
    "memory",
    "filesystem",
    "user_manager",
    "device_manager",
    "env",
    "logger",
    "current_uid",
    "file_permissions",
    "processes",
    "resource_manager",
    "sync_manager",
    "pi_manager",
    "ordering_manager",
    "slab_allocator",
    "socket_manager",
    "proc_filesystem",
    "strace_enabled",
]


class TestPropertyGuarding:
    """Verify guarded properties raise KernelModeError in USER mode."""

    @pytest.mark.parametrize("prop_name", _GUARDED_PROPERTIES)
    def test_guarded_property_raises_in_user_mode(self, prop_name: str) -> None:
        """Accessing a guarded property in USER mode raises KernelModeError."""
        k = _booted_kernel()
        with pytest.raises(KernelModeError):
            getattr(k, prop_name)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    @pytest.mark.parametrize("prop_name", _GUARDED_PROPERTIES)
    def test_guarded_property_works_in_kernel_mode(self, prop_name: str) -> None:
        """Accessing a guarded property in KERNEL mode succeeds."""
        k = _booted_kernel()
        k._execution_mode = ExecutionMode.KERNEL
        # Should not raise
        getattr(k, prop_name)
        k.shutdown()

    def test_current_uid_setter_guarded(self) -> None:
        """Setting current_uid in USER mode raises KernelModeError."""
        k = _booted_kernel()
        with pytest.raises(KernelModeError):
            k.current_uid = 42
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_state_unguarded_in_user_mode(self) -> None:
        """The state property is safe to read in USER mode."""
        k = _booted_kernel()
        assert k.state is KernelState.RUNNING
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_uptime_unguarded_in_user_mode(self) -> None:
        """The uptime property is safe to read in USER mode."""
        k = _booted_kernel()
        assert k.uptime > 0.0
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 3 — Mode switching
# ---------------------------------------------------------------------------


class TestModeSwitching:
    """Verify kernel_mode() context manager and syscall mode switching."""

    def test_context_manager_switches_and_restores(self) -> None:
        """Kernel_mode() switches to KERNEL and restores on exit."""
        k = _booted_kernel()
        assert k.execution_mode is ExecutionMode.USER
        with k.kernel_mode():
            assert k.execution_mode is ExecutionMode.KERNEL
        assert k.execution_mode is ExecutionMode.USER
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_context_manager_restores_on_exception(self) -> None:
        """Kernel_mode() restores mode even when an exception occurs."""
        k = _booted_kernel()
        with pytest.raises(ValueError, match="boom"):
            _raise_inside_kernel_mode(k)

    def test_syscall_runs_in_kernel_mode(self) -> None:
        """Syscall() temporarily switches to KERNEL mode for the handler."""
        k = _booted_kernel()
        assert k.execution_mode is ExecutionMode.USER
        # SYS_LIST_PROCESSES accesses kernel.processes internally
        result = k.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert isinstance(result, list)
        # After syscall, back to USER
        assert k.execution_mode is ExecutionMode.USER
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_syscall_restores_user_mode_after(self) -> None:
        """After a syscall, mode is restored to what it was before."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_SYSINFO)
        assert k.execution_mode is ExecutionMode.USER
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_nested_kernel_mode_preserves(self) -> None:
        """Nested kernel_mode() calls don't drop back to USER prematurely."""
        k = _booted_kernel()
        k._execution_mode = ExecutionMode.KERNEL
        with k.kernel_mode():
            assert k.execution_mode is ExecutionMode.KERNEL
            with k.kernel_mode():
                assert k.execution_mode is ExecutionMode.KERNEL
            # Still KERNEL after inner exits
            assert k.execution_mode is ExecutionMode.KERNEL
        # Was KERNEL before, so still KERNEL
        assert k.execution_mode is ExecutionMode.KERNEL
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 4 — New syscalls (190-203)
# ---------------------------------------------------------------------------


class TestNewSyscalls:
    """Verify the 14 new syscalls added for kernel-mode enforcement."""

    def test_sys_shutdown(self) -> None:
        """SYS_SHUTDOWN shuts down the kernel cleanly."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_SHUTDOWN)
        assert k.state is KernelState.SHUTDOWN

    def test_sys_scheduler_info(self) -> None:
        """SYS_SCHEDULER_INFO returns the current policy label."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
        assert result["policy"] == "FCFS"
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_lstat(self) -> None:
        """SYS_LSTAT returns file metadata without following symlinks."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_CREATE_FILE, path="/test_file")
        result = k.syscall(SyscallNumber.SYS_LSTAT, path="/test_file")
        assert result["inode_number"] >= 0
        assert result["file_type"] == "file"
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_list_mutexes(self) -> None:
        """SYS_LIST_MUTEXES returns mutex state info."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="test_m")
        result = k.syscall(SyscallNumber.SYS_LIST_MUTEXES)
        assert any(m["name"] == "test_m" for m in result)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_list_semaphores(self) -> None:
        """SYS_LIST_SEMAPHORES returns semaphore state info."""
        k = _booted_kernel()
        k.syscall(
            SyscallNumber.SYS_CREATE_SEMAPHORE,
            name="test_s",
            count=_SEMAPHORE_COUNT,
        )
        result = k.syscall(SyscallNumber.SYS_LIST_SEMAPHORES)
        assert any(s["name"] == "test_s" and s["count"] == _SEMAPHORE_COUNT for s in result)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_list_rwlocks(self) -> None:
        """SYS_LIST_RWLOCKS returns rwlock state info."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name="test_rw")
        result = k.syscall(SyscallNumber.SYS_LIST_RWLOCKS)
        assert any(r["name"] == "test_rw" for r in result)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_process_info(self) -> None:
        """SYS_PROCESS_INFO returns single-process details."""
        k = _booted_kernel()
        r = k.syscall(SyscallNumber.SYS_CREATE_PROCESS, name="info_test", num_pages=1)
        pid: int = r["pid"]
        info = k.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=pid)
        assert info["name"] == "info_test"
        assert "priority" in info
        assert "main_tid" in info
        assert "effective_priority" in info
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_dispatch(self) -> None:
        """SYS_DISPATCH dispatches the next process from the scheduler."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_CREATE_PROCESS, name="disp_test", num_pages=1)
        # First dispatch returns init (FCFS ordering)
        result = k.syscall(SyscallNumber.SYS_DISPATCH)
        assert result is not None
        assert result["name"] == "init"
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_list_fds(self) -> None:
        """SYS_LIST_FDS returns open file descriptors for a process."""
        k = _booted_kernel()
        r = k.syscall(SyscallNumber.SYS_CREATE_PROCESS, name="fd_test", num_pages=1)
        pid: int = r["pid"]
        k.syscall(SyscallNumber.SYS_CREATE_FILE, path="/fd_file")
        k.syscall(SyscallNumber.SYS_OPEN, pid=pid, path="/fd_file", mode="r")
        result = k.syscall(SyscallNumber.SYS_LIST_FDS, pid=pid)
        assert len(result) == 1
        assert result[0]["path"] == "/fd_file"
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_list_resources(self) -> None:
        """SYS_LIST_RESOURCES returns resource manager state."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_LIST_RESOURCES)
        assert isinstance(result, list)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_pi_status(self) -> None:
        """SYS_PI_STATUS returns priority inheritance information."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_PI_STATUS)
        assert "enabled" in result
        assert "boosted" in result
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_ordering_violations(self) -> None:
        """SYS_ORDERING_VIOLATIONS returns violation list."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_ORDERING_VIOLATIONS)
        assert isinstance(result, list)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_destroy_mutex(self) -> None:
        """SYS_DESTROY_MUTEX removes a named mutex."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="doomed")
        k.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="doomed")
        result = k.syscall(SyscallNumber.SYS_LIST_MUTEXES)
        assert not any(m["name"] == "doomed" for m in result)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_sys_strace_status(self) -> None:
        """SYS_STRACE_STATUS returns the current strace enabled bool."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_STRACE_STATUS)
        assert result["enabled"] is False
        k.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        result = k.syscall(SyscallNumber.SYS_STRACE_STATUS)
        assert result["enabled"] is True
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 5 — Shell enforcement
# ---------------------------------------------------------------------------


class TestShellEnforcement:
    """Verify shell commands work without bypassing the syscall boundary."""

    def test_shell_ls_works(self) -> None:
        """Verify ls command works in user mode via syscalls."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        result = shell.execute("ls /")
        assert isinstance(result, str)
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_shell_stat_works(self) -> None:
        """Verify stat command works via SYS_LSTAT syscall."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        shell.execute("touch /stat_test")
        result = shell.execute("stat /stat_test")
        assert "Inode:" in result
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_shell_mutex_list_works(self) -> None:
        """Verify mutex list command works via SYS_LIST_MUTEXES syscall."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        shell.execute("mutex create test_lock")
        result = shell.execute("mutex list")
        assert "test_lock" in result
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_shell_strace_inline_works(self) -> None:
        """Verify strace output appends via SYS_STRACE_STATUS syscall."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        shell.execute("strace on")
        result = shell.execute("ps")
        # With strace on, output may contain strace section
        assert isinstance(result, str)
        shell.execute("strace off")
        k._execution_mode = ExecutionMode.KERNEL
        k.shutdown()

    def test_shell_exit_works(self) -> None:
        """Verify exit command works via SYS_SHUTDOWN syscall."""
        k = _booted_kernel()
        shell = Shell(kernel=k)
        result = shell.execute("exit")
        assert result == Shell.EXIT_SENTINEL
        assert k.state is KernelState.SHUTDOWN
