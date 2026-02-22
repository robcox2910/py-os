"""Tests for wait/waitpid — parent collects terminated child.

In Unix, when a parent forks a child, it must eventually "collect" the
child after it terminates.  Until collected, the terminated child is a
**zombie** — still in the process table holding its exit code, but
consuming no CPU or memory.

``wait()`` blocks the parent until *any* child terminates.
``waitpid(pid)`` blocks until a *specific* child terminates.

Because PyOS is single-threaded, "blocking" is declarative: the parent
transitions to WAITING and records what it is waiting for (via the
``wait_target`` field).  When the child later terminates, the kernel
checks for a waiting parent and wakes it.
"""

import pytest

from py_os.kernel import Kernel
from py_os.process.pcb import Process, ProcessState
from py_os.process.signals import Signal
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


# -- TDD Cycle 1: wait_target field -------------------------------------------


class TestProcessWaitTarget:
    """Verify the wait_target field on Process."""

    def test_wait_target_defaults_to_none(self) -> None:
        """A new process should have wait_target=None."""
        process = Process(name="test")
        assert process.wait_target is None

    def test_wait_target_can_be_set_to_any_child(self) -> None:
        """Setting wait_target to -1 means 'wait for any child'."""
        process = Process(name="test")
        process.wait_target = -1
        assert process.wait_target == -1

    def test_wait_target_can_be_set_to_specific_pid(self) -> None:
        """Setting wait_target to a positive int means 'wait for that PID'."""
        process = Process(name="test")
        target_pid = 42
        process.wait_target = target_pid
        assert process.wait_target == target_pid

    def test_wait_target_can_be_cleared(self) -> None:
        """Setting wait_target back to None clears the wait."""
        process = Process(name="test")
        process.wait_target = -1
        process.wait_target = None
        assert process.wait_target is None


# -- TDD Cycle 2: wait_process immediate collection ---------------------------


class TestWaitImmediate:
    """Verify wait_process collects an already-terminated child."""

    def test_wait_collects_terminated_child(self) -> None:
        """If a child is already terminated, wait returns its info immediately."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "done")
        kernel.run_process(pid=child.pid)

        result = kernel.wait_process(parent_pid=parent.pid)
        assert result is not None
        assert result["child_pid"] == child.pid
        assert result["exit_code"] == 0
        assert result["output"] == "done"

    def test_wait_removes_zombie_from_table(self) -> None:
        """After collection, the zombie should be removed from the process table."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "bye")
        kernel.run_process(pid=child.pid)

        # Child should still be in the table as a zombie
        assert child.pid in kernel.processes

        kernel.wait_process(parent_pid=parent.pid)

        # Now it should be gone
        assert child.pid not in kernel.processes

    def test_wait_no_children_raises(self) -> None:
        """Waiting on a process with no children should raise ValueError."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="lonely", num_pages=1)

        with pytest.raises(ValueError, match="no children"):
            kernel.wait_process(parent_pid=parent.pid)

    def test_wait_nonexistent_parent_raises(self) -> None:
        """Waiting with a non-existent parent PID should raise ValueError."""
        kernel = _booted_kernel()
        nonexistent = 999

        with pytest.raises(ValueError, match="not found"):
            kernel.wait_process(parent_pid=nonexistent)


# -- TDD Cycle 3: wait_process blocking ---------------------------------------


class TestWaitBlocking:
    """Verify wait_process blocks and child termination wakes parent."""

    def test_wait_blocks_parent_when_child_alive(self) -> None:
        """If no child is terminated, the parent should block (WAITING)."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.fork_process(parent_pid=parent.pid)

        result = kernel.wait_process(parent_pid=parent.pid)
        assert result is None
        assert parent.state is ProcessState.WAITING
        assert parent.wait_target == -1

    def test_child_termination_wakes_waiting_parent(self) -> None:
        """When a child terminates, its waiting parent should be woken."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "hi")

        # Parent blocks
        kernel.wait_process(parent_pid=parent.pid)
        assert parent.state is ProcessState.WAITING

        # Child runs and terminates
        kernel.run_process(pid=child.pid)

        # Parent should be woken (READY)
        assert parent.state is ProcessState.READY
        assert parent.wait_target is None

    def test_parent_can_collect_after_wake(self) -> None:
        """After being woken, the parent can call wait again to collect."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "result")

        # Parent blocks
        kernel.wait_process(parent_pid=parent.pid)

        # Child runs (wakes parent)
        kernel.run_process(pid=child.pid)

        # Now parent collects
        result = kernel.wait_process(parent_pid=parent.pid)
        assert result is not None
        assert result["child_pid"] == child.pid
        assert result["output"] == "result"


# -- TDD Cycle 4: waitpid_process ---------------------------------------------


class TestWaitpid:
    """Verify waitpid_process targets a specific child."""

    def test_waitpid_collects_terminated_child(self) -> None:
        """Waitpid should collect a specific terminated child."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "specific")
        kernel.run_process(pid=child.pid)

        result = kernel.waitpid_process(parent_pid=parent.pid, child_pid=child.pid)
        assert result is not None
        assert result["child_pid"] == child.pid
        assert result["output"] == "specific"

    def test_waitpid_blocks_when_child_alive(self) -> None:
        """If the specific child is alive, parent should block."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)

        result = kernel.waitpid_process(parent_pid=parent.pid, child_pid=child.pid)
        assert result is None
        assert parent.state is ProcessState.WAITING
        assert parent.wait_target == child.pid

    def test_waitpid_ignores_other_terminated_children(self) -> None:
        """Waitpid should not collect a different child than requested."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child_a = kernel.fork_process(parent_pid=parent.pid)
        child_b = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child_a.pid, program=lambda: "a done")
        kernel.run_process(pid=child_a.pid)

        # Wait for child_b specifically — child_a is dead but ignored
        result = kernel.waitpid_process(parent_pid=parent.pid, child_pid=child_b.pid)
        assert result is None
        assert parent.state is ProcessState.WAITING
        assert parent.wait_target == child_b.pid

    def test_waitpid_wakes_only_for_target_child(self) -> None:
        """Parent waiting for child_b should not wake when child_a terminates."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child_a = kernel.fork_process(parent_pid=parent.pid)
        child_b = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child_a.pid, program=lambda: "a")
        kernel.exec_process(pid=child_b.pid, program=lambda: "b")

        # Wait specifically for child_b
        kernel.waitpid_process(parent_pid=parent.pid, child_pid=child_b.pid)
        assert parent.state is ProcessState.WAITING

        # child_a terminates — parent should NOT wake
        kernel.run_process(pid=child_a.pid)
        assert parent.state is ProcessState.WAITING

        # child_b terminates — NOW parent wakes
        kernel.run_process(pid=child_b.pid)
        assert parent.state is ProcessState.READY

    def test_waitpid_not_child_raises(self) -> None:
        """Waitpid should reject a PID that is not a child of the parent."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        stranger = kernel.create_process(name="stranger", num_pages=1)

        with pytest.raises(ValueError, match="not a child"):
            kernel.waitpid_process(parent_pid=parent.pid, child_pid=stranger.pid)

    def test_waitpid_nonexistent_child_raises(self) -> None:
        """Waitpid with a non-existent child PID should raise ValueError."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        nonexistent = 999

        with pytest.raises(ValueError, match="not found"):
            kernel.waitpid_process(parent_pid=parent.pid, child_pid=nonexistent)


# -- TDD Cycle 5: Zombie behavior ---------------------------------------------


class TestZombieBehavior:
    """Verify terminated children stay as zombies until collected."""

    def test_terminated_child_stays_in_table(self) -> None:
        """A child with a living parent should remain in the table after termination."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "zombie")
        kernel.run_process(pid=child.pid)

        # Child should still be in the table (zombie)
        assert child.pid in kernel.processes
        assert child.state is ProcessState.TERMINATED

    def test_orphan_is_deleted_immediately(self) -> None:
        """A process with no parent should be deleted after termination."""
        kernel = _booted_kernel()
        process = kernel.create_process(name="orphan", num_pages=1)
        kernel.exec_process(pid=process.pid, program=lambda: "bye")
        kernel.run_process(pid=process.pid)

        # No parent → deleted immediately
        assert process.pid not in kernel.processes

    def test_zombie_memory_is_freed(self) -> None:
        """A zombie's memory frames should be freed even though it stays in the table."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "x")

        free_before = kernel.memory.free_frames
        kernel.run_process(pid=child.pid)
        free_after = kernel.memory.free_frames

        # Memory should be freed even though child is a zombie
        assert free_after > free_before
        assert child.pid in kernel.processes

    def test_sigkill_creates_zombie(self) -> None:
        """SIGKILL on a child with a living parent should leave a zombie."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)

        # Move child to RUNNING so SIGKILL can force_terminate
        child.dispatch()
        kernel.send_signal(child.pid, Signal.SIGKILL)

        assert child.state is ProcessState.TERMINATED
        assert child.pid in kernel.processes  # zombie

    def test_sigkill_orphan_deleted(self) -> None:
        """SIGKILL on an orphan should delete it from the table."""
        kernel = _booted_kernel()
        process = kernel.create_process(name="orphan", num_pages=1)
        process.dispatch()
        kernel.send_signal(process.pid, Signal.SIGKILL)

        assert process.pid not in kernel.processes

    def test_collecting_zombie_removes_signal_handlers(self) -> None:
        """Collecting a zombie should clean up its signal handlers."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)

        # Register a handler on the child
        handler_called = False

        def handler() -> None:
            nonlocal handler_called
            handler_called = True

        kernel.register_signal_handler(child.pid, Signal.SIGUSR1, handler)

        # Terminate and collect
        kernel.exec_process(pid=child.pid, program=lambda: "x")
        kernel.run_process(pid=child.pid)
        kernel.wait_process(parent_pid=parent.pid)

        # Handler entry should be cleaned up
        assert (child.pid, Signal.SIGUSR1) not in kernel._signal_handlers


# -- TDD Cycle 6: Syscall wrappers --------------------------------------------


class TestWaitSyscall:
    """Verify SYS_WAIT syscall wrapper."""

    def test_sys_wait_collects_zombie(self) -> None:
        """SYS_WAIT should collect a terminated child via syscall."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "syscall")
        kernel.run_process(pid=child.pid)

        result = kernel.syscall(SyscallNumber.SYS_WAIT, parent_pid=parent.pid)
        assert result is not None
        assert result["child_pid"] == child.pid

    def test_sys_wait_no_children_raises(self) -> None:
        """SYS_WAIT with no children should raise SyscallError."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="lonely", num_pages=1)

        with pytest.raises(SyscallError, match="no children"):
            kernel.syscall(SyscallNumber.SYS_WAIT, parent_pid=parent.pid)


class TestWaitpidSyscall:
    """Verify SYS_WAITPID syscall wrapper."""

    def test_sys_waitpid_collects_zombie(self) -> None:
        """SYS_WAITPID should collect a specific terminated child."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "specific")
        kernel.run_process(pid=child.pid)

        result = kernel.syscall(
            SyscallNumber.SYS_WAITPID,
            parent_pid=parent.pid,
            child_pid=child.pid,
        )
        assert result is not None
        assert result["child_pid"] == child.pid

    def test_sys_waitpid_not_child_raises(self) -> None:
        """SYS_WAITPID for a non-child should raise SyscallError."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        stranger = kernel.create_process(name="stranger", num_pages=1)

        with pytest.raises(SyscallError, match="not a child"):
            kernel.syscall(
                SyscallNumber.SYS_WAITPID,
                parent_pid=parent.pid,
                child_pid=stranger.pid,
            )


# -- TDD Cycle 7: Shell commands ----------------------------------------------


class TestShellWaitCommand:
    """Verify the shell's wait command."""

    def test_wait_collects_child(self) -> None:
        """Shell wait should collect a terminated child and show info."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "hello")
        kernel.run_process(pid=child.pid)
        shell = Shell(kernel=kernel)

        result = shell.execute(f"wait {parent.pid}")
        assert str(child.pid) in result
        assert "exit_code" in result or "exit code" in result.lower()

    def test_wait_blocks_parent(self) -> None:
        """Shell wait should report that the parent is now waiting."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.fork_process(parent_pid=parent.pid)
        shell = Shell(kernel=kernel)

        result = shell.execute(f"wait {parent.pid}")
        assert "waiting" in result.lower()

    def test_wait_no_args_shows_usage(self) -> None:
        """Wait without arguments should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("wait")
        assert "usage" in result.lower()

    def test_wait_error_shows_message(self) -> None:
        """Wait on a process with no children should show error."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="lonely", num_pages=1)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"wait {parent.pid}")
        assert "error" in result.lower()

    def test_help_includes_wait(self) -> None:
        """Help should list the wait command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "wait" in result


class TestShellWaitpidCommand:
    """Verify the shell's waitpid command."""

    def test_waitpid_collects_child(self) -> None:
        """Shell waitpid should collect a specific terminated child."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=1)
        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.exec_process(pid=child.pid, program=lambda: "hi")
        kernel.run_process(pid=child.pid)
        shell = Shell(kernel=kernel)

        result = shell.execute(f"waitpid {parent.pid} {child.pid}")
        assert str(child.pid) in result

    def test_waitpid_no_args_shows_usage(self) -> None:
        """Waitpid without arguments should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("waitpid")
        assert "usage" in result.lower()

    def test_waitpid_one_arg_shows_usage(self) -> None:
        """Waitpid with only parent PID should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("waitpid 1")
        assert "usage" in result.lower()

    def test_help_includes_waitpid(self) -> None:
        """Help should list the waitpid command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "waitpid" in result
