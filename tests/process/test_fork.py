"""Tests for process forking (fork syscall).

In Unix, ``fork()`` creates a child process that is a near-exact copy
of the parent.  The child gets its own PID, its own memory (a copy of
the parent's data), and starts in the READY state.  This is how every
new process in Unix is born — even ``exec()`` starts with a fork.

Key properties:
    - The child gets a **new PID** but records the parent's PID.
    - Memory uses **copy-on-write** — parent and child share physical
      frames until one writes, triggering a private copy.
    - The child is admitted to the scheduler and is immediately eligible
      to run.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.process.pcb import ProcessState
from py_os.process.signals import Signal
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


# -- Kernel-level fork ---------------------------------------------------------


class TestForkProcess:
    """Verify kernel-level process forking."""

    def test_fork_creates_child(self) -> None:
        """Forking should create a new child process."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.pid != parent.pid
        assert child.parent_pid == parent.pid

    def test_fork_child_inherits_name(self) -> None:
        """Child name should indicate it was forked from the parent."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="server", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert "server" in child.name

    def test_fork_child_is_ready(self) -> None:
        """Child should be in READY state after fork."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.state is ProcessState.READY

    def test_fork_child_in_process_table(self) -> None:
        """Child should appear in the kernel's process table."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.pid in kernel.processes

    def test_fork_copies_memory_data(self) -> None:
        """Child should have a copy of the parent's memory contents."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"hello")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None
        result = child.virtual_memory.read(virtual_address=0, size=5)
        assert result == b"hello"

    def test_fork_memory_isolation(self) -> None:
        """Writing to child's memory should not affect the parent."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"parent")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None
        child.virtual_memory.write(virtual_address=0, data=b"child!")

        # Parent data must be untouched
        parent_data = parent.virtual_memory.read(virtual_address=0, size=6)
        assert parent_data == b"parent"

    def test_fork_shares_physical_frames(self) -> None:
        """After COW fork, parent and child share the same physical frames."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert kernel.memory is not None
        parent_frames = set(kernel.memory.pages_for(parent.pid))
        child_frames = set(kernel.memory.pages_for(child.pid))
        assert parent_frames == child_frames

    def test_fork_uses_zero_new_frames(self) -> None:
        """COW fork should not consume any new physical frames."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        num_pages = 4
        parent = kernel.create_process(name="parent", num_pages=num_pages)
        after_parent = kernel.memory.free_frames
        kernel.fork_process(parent_pid=parent.pid)
        after_fork = kernel.memory.free_frames
        assert after_fork == after_parent

    def test_fork_inherits_priority(self) -> None:
        """Child should inherit the parent's scheduling priority."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.priority == parent.priority

    def test_fork_nonexistent_pid_raises(self) -> None:
        """Forking a non-existent process should raise ValueError."""
        kernel = _booted_kernel()
        nonexistent = 999
        with pytest.raises(ValueError, match="not found"):
            kernel.fork_process(parent_pid=nonexistent)

    def test_fork_terminated_process_raises(self) -> None:
        """Forking a terminated process should raise ValueError."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        # Transition to TERMINATED via dispatch → terminate
        parent.dispatch()
        parent.terminate()
        with pytest.raises(ValueError, match="terminated"):
            kernel.fork_process(parent_pid=parent.pid)

    def test_fork_chain(self) -> None:
        """A forked child can itself be forked (grandchild)."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="ancestor", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        grandchild = kernel.fork_process(parent_pid=child.pid)
        assert grandchild.parent_pid == child.pid
        assert child.parent_pid == parent.pid


class TestCopyOnWriteFork:
    """Verify copy-on-write semantics in forked processes.

    After fork, parent and child share physical frames marked COW.
    A write by either side triggers a fault that copies the page,
    giving the writer its own private frame while the other side
    keeps the original.
    """

    def test_child_write_triggers_cow(self) -> None:
        """Writing in the child should give it a private frame."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"shared")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None
        child.virtual_memory.write(virtual_address=0, data=b"child!")

        # Parent still sees original data
        assert parent.virtual_memory.read(virtual_address=0, size=6) == b"shared"
        # Child sees its own data
        assert child.virtual_memory.read(virtual_address=0, size=6) == b"child!"

    def test_parent_write_triggers_cow(self) -> None:
        """Writing in the parent should give it a private frame."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"before")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None

        # Parent writes first
        parent.virtual_memory.write(virtual_address=0, data=b"parent")

        # Child still sees the original data
        assert child.virtual_memory.read(virtual_address=0, size=6) == b"before"
        assert parent.virtual_memory.read(virtual_address=0, size=6) == b"parent"

    def test_both_sides_write_both_get_private_copies(self) -> None:
        """Both parent and child writing should produce independent copies."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"orig")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None

        child.virtual_memory.write(virtual_address=0, data=b"ccc!")
        parent.virtual_memory.write(virtual_address=0, data=b"ppp!")

        assert parent.virtual_memory.read(virtual_address=0, size=4) == b"ppp!"
        assert child.virtual_memory.read(virtual_address=0, size=4) == b"ccc!"

    def test_cow_write_allocates_one_frame(self) -> None:
        """A COW fault should consume exactly one frame from the free pool."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        parent = kernel.create_process(name="parent", num_pages=2)
        kernel.fork_process(parent_pid=parent.pid)
        free_before = kernel.memory.free_frames

        child = kernel.processes[max(kernel.processes)]
        assert child.virtual_memory is not None
        child.virtual_memory.write(virtual_address=0, data=b"x")

        expected_free = free_before - 1
        assert kernel.memory.free_frames == expected_free

    def test_cow_refcount_lifecycle(self) -> None:
        """Refcounts should track sharing correctly through fork and write."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        parent = kernel.create_process(name="parent", num_pages=1)
        parent_frame = kernel.memory.pages_for(parent.pid)[0]

        # Before fork: refcount = 1
        assert kernel.memory.refcount(parent_frame) == 1

        child = kernel.fork_process(parent_pid=parent.pid)
        # After fork: refcount = 2 (shared)
        expected_shared = 2
        assert kernel.memory.refcount(parent_frame) == expected_shared

        # Child writes: gets private frame, old frame drops to 1
        assert child.virtual_memory is not None
        child.virtual_memory.write(virtual_address=0, data=b"x")
        assert kernel.memory.refcount(parent_frame) == 1

    def test_cow_pages_marked_on_both_sides(self) -> None:
        """After fork, COW flags should be set on both parent and child VMs."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert parent.virtual_memory is not None
        assert child.virtual_memory is not None

        # Both should have all pages marked COW
        expected_cow = frozenset({0, 1})
        assert parent.virtual_memory.cow_pages == expected_cow
        assert child.virtual_memory.cow_pages == expected_cow

    def test_terminate_shared_frame_process(self) -> None:
        """Terminating a process with shared frames should not corrupt the other."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"safe")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None

        # Kill child via SIGKILL (works from any state)
        kernel.send_signal(child.pid, Signal.SIGKILL)

        # Parent data intact
        assert parent.virtual_memory.read(virtual_address=0, size=4) == b"safe"

    def test_read_shared_page_no_fault(self) -> None:
        """Reading a shared COW page should work without triggering a copy."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        parent = kernel.create_process(name="parent", num_pages=2)
        assert parent.virtual_memory is not None
        parent.virtual_memory.write(virtual_address=0, data=b"read-me")

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.virtual_memory is not None
        free_before = kernel.memory.free_frames

        # Read from child — should NOT allocate a new frame
        result = child.virtual_memory.read(virtual_address=0, size=7)
        assert result == b"read-me"
        assert kernel.memory.free_frames == free_before

    def test_chain_fork_refcounts(self) -> None:
        """Forking a fork should bump refcounts to 3."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        parent = kernel.create_process(name="A", num_pages=1)
        frame = kernel.memory.pages_for(parent.pid)[0]

        child = kernel.fork_process(parent_pid=parent.pid)
        grandchild = kernel.fork_process(parent_pid=child.pid)
        expected_triple = 3
        assert kernel.memory.refcount(frame) == expected_triple

        # Grandchild writes — gets private copy, frame drops to 2
        assert grandchild.virtual_memory is not None
        grandchild.virtual_memory.write(virtual_address=0, data=b"gc")
        expected_double = 2
        assert kernel.memory.refcount(frame) == expected_double

    def test_shared_frame_count_after_fork(self) -> None:
        """shared_frame_count should reflect number of shared frames."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        num_pages = 3
        parent = kernel.create_process(name="parent", num_pages=num_pages)
        assert kernel.memory.shared_frame_count == 0

        kernel.fork_process(parent_pid=parent.pid)
        assert kernel.memory.shared_frame_count == num_pages


# -- Fork syscall --------------------------------------------------------------


class TestForkSyscall:
    """Verify fork through the syscall interface."""

    def test_sys_fork_returns_child_info(self) -> None:
        """SYS_FORK should return the child's PID and parent PID."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        result = kernel.syscall(SyscallNumber.SYS_FORK, parent_pid=parent.pid)
        assert "child_pid" in result
        assert result["parent_pid"] == parent.pid

    def test_sys_fork_invalid_pid_raises(self) -> None:
        """SYS_FORK with invalid PID should raise SyscallError."""
        kernel = _booted_kernel()
        nonexistent = 999
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_FORK, parent_pid=nonexistent)

    def test_list_processes_includes_parent_pid(self) -> None:
        """SYS_LIST_PROCESSES should include parent_pid for forked processes."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        kernel.fork_process(parent_pid=parent.pid)
        procs = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        child_entry = next(p for p in procs if p["parent_pid"] == parent.pid)
        assert child_entry is not None


# -- Shell fork and pstree commands --------------------------------------------


class TestShellForkCommand:
    """Verify the shell's fork and pstree commands."""

    def test_fork_command_creates_child(self) -> None:
        """Shell fork should create a child and report success."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="worker", num_pages=2)
        shell = Shell(kernel=kernel)
        result = shell.execute(f"fork {parent.pid}")
        assert "fork" in result.lower() or "child" in result.lower()

    def test_fork_no_args_shows_usage(self) -> None:
        """Fork without arguments should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("fork")
        assert "usage" in result.lower()

    def test_fork_invalid_pid_shows_error(self) -> None:
        """Fork with unknown PID should show error."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("fork 999")
        assert "error" in result.lower()

    def test_help_includes_fork(self) -> None:
        """Help should list the fork command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "fork" in result

    def test_pstree_shows_hierarchy(self) -> None:
        """Pstree should show parent-child relationships."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        kernel.fork_process(parent_pid=parent.pid)
        shell = Shell(kernel=kernel)
        result = shell.execute("pstree")
        assert "parent" in result

    def test_help_includes_pstree(self) -> None:
        """Help should list the pstree command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "pstree" in result
