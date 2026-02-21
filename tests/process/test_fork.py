"""Tests for process forking (fork syscall).

In Unix, ``fork()`` creates a child process that is a near-exact copy
of the parent.  The child gets its own PID, its own memory (a copy of
the parent's data), and starts in the READY state.  This is how every
new process in Unix is born — even ``exec()`` starts with a fork.

Key properties:
    - The child gets a **new PID** but records the parent's PID.
    - Memory is **copied** (not shared) — writes in the child don't
      affect the parent.  Real OSes use copy-on-write for efficiency;
      we do an eager copy for clarity.
    - The child is admitted to the scheduler and is immediately eligible
      to run.
"""

import pytest

from py_os.kernel import Kernel
from py_os.process.pcb import ProcessState
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
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

    def test_fork_allocates_new_frames(self) -> None:
        """Child should get different physical frames than the parent."""
        kernel = _booted_kernel()
        parent = kernel.create_process(name="parent", num_pages=2)
        child = kernel.fork_process(parent_pid=parent.pid)
        assert kernel.memory is not None
        parent_frames = set(kernel.memory.pages_for(parent.pid))
        child_frames = set(kernel.memory.pages_for(child.pid))
        assert parent_frames.isdisjoint(child_frames)

    def test_fork_reduces_free_memory(self) -> None:
        """Fork should allocate memory, reducing free frames."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        num_pages = 4
        parent = kernel.create_process(name="parent", num_pages=num_pages)
        after_parent = kernel.memory.free_frames
        kernel.fork_process(parent_pid=parent.pid)
        after_fork = kernel.memory.free_frames
        assert after_fork == after_parent - num_pages

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
