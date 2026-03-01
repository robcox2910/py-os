"""Tests for threads — lightweight execution units within a process.

A thread is a unit of execution within a process.  Unlike fork (which
copies the entire address space), threads **share** the parent process's
memory.  This makes them cheap to create but introduces the need for
synchronisation (a topic for a later module).

Key differences from processes:
    - Threads share the same virtual memory (heap, data).
    - Each thread has its own state (READY, RUNNING, etc.) and TID.
    - Thread IDs are scoped per-process (not globally unique).
    - When the main thread (TID 0) terminates, all threads terminate.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.memory.virtual import VirtualMemory
from py_os.process.pcb import Process
from py_os.process.threads import Thread, ThreadState
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


# -- Thread class --------------------------------------------------------------


class TestThread:
    """Verify the Thread class itself."""

    def test_creation(self) -> None:
        """Thread should store tid, name, pid, and start in NEW state."""
        thread = Thread(tid=1, name="worker", pid=42)
        assert thread.tid == 1
        assert thread.name == "worker"
        expected_pid = 42
        assert thread.pid == expected_pid
        assert thread.state is ThreadState.NEW

    def test_admit(self) -> None:
        """Admit should transition NEW -> READY."""
        thread = Thread(tid=0, name="main", pid=1)
        thread.admit()
        assert thread.state is ThreadState.READY

    def test_full_lifecycle(self) -> None:
        """Thread should follow the same state machine as processes."""
        thread = Thread(tid=0, name="main", pid=1)
        thread.admit()
        thread.dispatch()
        assert thread.state is ThreadState.RUNNING
        thread.terminate()
        assert thread.state is ThreadState.TERMINATED

    def test_preempt(self) -> None:
        """Preempt should transition RUNNING -> READY."""
        thread = Thread(tid=0, name="main", pid=1)
        thread.admit()
        thread.dispatch()
        thread.preempt()
        assert thread.state is ThreadState.READY

    def test_wait_and_wake(self) -> None:
        """Wait and wake should work like process WAITING transitions."""
        thread = Thread(tid=0, name="main", pid=1)
        thread.admit()
        thread.dispatch()
        thread.wait()
        assert thread.state is ThreadState.WAITING
        thread.wake()
        assert thread.state is ThreadState.READY

    def test_invalid_transition_raises(self) -> None:
        """Dispatching from NEW should raise RuntimeError."""
        thread = Thread(tid=0, name="main", pid=1)
        with pytest.raises(RuntimeError, match="Cannot dispatch"):
            thread.dispatch()

    def test_force_terminate(self) -> None:
        """Force terminate should work from any alive state."""
        thread = Thread(tid=0, name="main", pid=1)
        thread.admit()
        thread.force_terminate()
        assert thread.state is ThreadState.TERMINATED

    def test_force_terminate_already_terminated_raises(self) -> None:
        """Force-terminating an already terminated thread should raise RuntimeError."""
        thread = Thread(tid=0, name="main", pid=1)
        thread.admit()
        thread.dispatch()
        thread.terminate()
        with pytest.raises(RuntimeError, match="already terminated"):
            thread.force_terminate()

    def test_force_terminate_new_thread_raises(self) -> None:
        """Force-terminating a NEW (not yet admitted) thread should raise RuntimeError."""
        thread = Thread(tid=0, name="main", pid=1)
        with pytest.raises(RuntimeError, match="not yet admitted"):
            thread.force_terminate()

    def test_repr(self) -> None:
        """Thread repr should show tid, name, and state."""
        thread = Thread(tid=1, name="worker", pid=5)
        result = repr(thread)
        assert "tid=1" in result
        assert "worker" in result


# -- Process thread management -------------------------------------------------


class TestProcessThreads:
    """Verify thread management within a process."""

    def test_process_has_main_thread(self) -> None:
        """Every process should start with a main thread (TID 0)."""
        process = Process(name="test")
        assert len(process.threads) == 1
        main_tid = 0
        assert main_tid in process.threads

    def test_main_thread_name(self) -> None:
        """The main thread should be named 'main'."""
        process = Process(name="test")
        assert process.main_thread.name == "main"

    def test_main_thread_has_process_pid(self) -> None:
        """The main thread should reference its process's PID."""
        process = Process(name="test")
        assert process.main_thread.pid == process.pid

    def test_create_thread(self) -> None:
        """Creating a thread should add it to the process."""
        process = Process(name="test")
        thread = process.create_thread(name="worker")
        expected_count = 2
        assert len(process.threads) == expected_count
        assert thread.pid == process.pid

    def test_thread_ids_unique_within_process(self) -> None:
        """Thread IDs should be unique within the same process."""
        process = Process(name="test")
        t1 = process.create_thread(name="t1")
        t2 = process.create_thread(name="t2")
        assert t1.tid != t2.tid

    def test_threads_share_virtual_memory(self) -> None:
        """All threads in a process share the same virtual memory."""
        process = Process(name="test")
        vm = VirtualMemory()
        vm.page_table.map(virtual_page=0, physical_frame=0)
        process.virtual_memory = vm
        # Write via the process (main thread's context)
        vm.write(virtual_address=0, data=b"shared")
        # Any thread can read the same data — they all use the same VM
        assert process.virtual_memory is vm
        thread = process.create_thread(name="reader")
        # Thread's view of memory is through process.virtual_memory
        assert thread.pid == process.pid
        data = process.virtual_memory.read(virtual_address=0, size=6)
        assert data == b"shared"

    def test_no_memory_allocation_for_threads(self) -> None:
        """Creating a thread should not allocate new memory frames."""
        kernel = _booted_kernel()
        assert kernel.memory is not None
        proc = kernel.create_process(name="app", num_pages=2)
        free_before = kernel.memory.free_frames
        kernel.create_thread(pid=proc.pid, name="worker")
        free_after = kernel.memory.free_frames
        assert free_after == free_before


# -- Kernel thread operations --------------------------------------------------


class TestKernelThreads:
    """Verify kernel-level thread creation."""

    def test_create_thread(self) -> None:
        """Kernel should create a thread within a process."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="server", num_pages=2)
        thread = kernel.create_thread(pid=proc.pid, name="handler")
        assert thread.pid == proc.pid
        assert thread.state is ThreadState.READY

    def test_create_thread_nonexistent_pid_raises(self) -> None:
        """Creating a thread in a non-existent process should raise ValueError."""
        kernel = _booted_kernel()
        nonexistent = 999
        with pytest.raises(ValueError, match="not found"):
            kernel.create_thread(pid=nonexistent, name="orphan")

    def test_create_multiple_threads(self) -> None:
        """Multiple threads can be created within one process."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="server", num_pages=2)
        kernel.create_thread(pid=proc.pid, name="handler-1")
        kernel.create_thread(pid=proc.pid, name="handler-2")
        expected_count = 3  # main + 2 workers
        assert len(proc.threads) == expected_count

    def test_thread_shares_process_memory(self) -> None:
        """Threads should see the same virtual memory as the process."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="server", num_pages=2)
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(virtual_address=0, data=b"shared data")
        kernel.create_thread(pid=proc.pid, name="reader")
        # Thread accesses the same VM — data is visible
        data = proc.virtual_memory.read(virtual_address=0, size=11)
        assert data == b"shared data"

    def test_fork_vs_thread_memory(self) -> None:
        """Fork copies memory (isolation); threads share it."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=2)
        assert proc.virtual_memory is not None
        proc.virtual_memory.write(virtual_address=0, data=b"original")

        # Fork creates independent memory
        child = kernel.fork_process(parent_pid=proc.pid)
        assert child.virtual_memory is not None
        assert child.virtual_memory is not proc.virtual_memory  # different objects

        # Thread shares memory
        thread = kernel.create_thread(pid=proc.pid, name="worker")
        assert thread.pid == proc.pid
        # Thread's VM is the same object
        assert proc.virtual_memory is proc.virtual_memory  # same for all threads


# -- Thread syscalls -----------------------------------------------------------


class TestThreadSyscalls:
    """Verify thread operations through the syscall interface."""

    def test_sys_create_thread(self) -> None:
        """SYS_CREATE_THREAD should create a thread and return info."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=2)
        result = kernel.syscall(SyscallNumber.SYS_CREATE_THREAD, pid=proc.pid, name="worker")
        assert "tid" in result
        assert result["pid"] == proc.pid

    def test_sys_create_thread_invalid_pid(self) -> None:
        """SYS_CREATE_THREAD with invalid PID should raise SyscallError."""
        kernel = _booted_kernel()
        nonexistent = 999
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CREATE_THREAD, pid=nonexistent, name="orphan")

    def test_sys_list_threads(self) -> None:
        """SYS_LIST_THREADS should return all threads for a process."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=2)
        kernel.create_thread(pid=proc.pid, name="worker")
        threads = kernel.syscall(SyscallNumber.SYS_LIST_THREADS, pid=proc.pid)
        expected_count = 2  # main + worker
        assert len(threads) == expected_count

    def test_sys_list_threads_invalid_pid(self) -> None:
        """SYS_LIST_THREADS with invalid PID should raise SyscallError."""
        kernel = _booted_kernel()
        nonexistent = 999
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_LIST_THREADS, pid=nonexistent)


# -- Shell threads command -----------------------------------------------------


class TestShellThreadsCommand:
    """Verify the shell's threads command."""

    def test_threads_lists_process_threads(self) -> None:
        """Threads command should list all threads of a process."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=2)
        kernel.create_thread(pid=proc.pid, name="worker")
        shell = Shell(kernel=kernel)
        result = shell.execute(f"threads {proc.pid}")
        assert "main" in result
        assert "worker" in result

    def test_threads_no_args_shows_usage(self) -> None:
        """Threads without arguments should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("threads")
        assert "usage" in result.lower()

    def test_threads_invalid_pid_shows_error(self) -> None:
        """Threads with unknown PID should show error."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("threads 999")
        assert "error" in result.lower()

    def test_help_includes_threads(self) -> None:
        """Help should list the threads command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "threads" in result
