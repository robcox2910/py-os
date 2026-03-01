"""Tests for the system call interface.

System calls are the controlled gateway between user-space and
kernel-space.  Instead of reaching directly into kernel subsystems,
user programs invoke numbered operations via kernel.syscall().

The kernel validates each request, dispatches to the right subsystem,
and returns a result — just like a real OS trap handler.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.process.pcb import ProcessState
from py_os.syscalls import SyscallError, SyscallNumber

NUM_PAGES = 2
DEFAULT_TOTAL_FRAMES = 64


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


class TestSyscallProcessOps:
    """Verify process-related system calls."""

    def test_create_process(self) -> None:
        """SYS_CREATE_PROCESS should create and return a process."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="init",
            num_pages=NUM_PAGES,
        )
        assert result["pid"] > 0
        assert result["name"] == "init"
        assert result["state"] == ProcessState.READY

    def test_list_processes(self) -> None:
        """SYS_LIST_PROCESSES should return all processes including init."""
        kernel = _booted_kernel()
        kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="daemon",
            num_pages=NUM_PAGES,
        )
        result = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        expected_count = 2  # init + daemon
        assert len(result) == expected_count
        names = {p["name"] for p in result}
        assert "init" in names
        assert "daemon" in names

    def test_list_processes_only_init(self) -> None:
        """SYS_LIST_PROCESSES with no user processes returns only init."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        assert len(result) == 1
        assert result[0]["name"] == "init"

    def test_terminate_process(self) -> None:
        """SYS_TERMINATE_PROCESS should terminate by PID."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="victim",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        # Dispatch init first (FCFS), preempt it, then dispatch victim
        assert kernel.scheduler is not None
        init_proc = kernel.scheduler.dispatch()
        assert init_proc is not None
        init_proc.preempt()
        kernel.scheduler.add(init_proc)
        kernel.scheduler.dispatch()
        kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=pid)
        procs = kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        victim = next(p for p in procs if p["pid"] == pid)
        assert victim["state"] == ProcessState.TERMINATED

    def test_terminate_nonexistent_process(self) -> None:
        """Terminating a non-existent PID should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=999)


class TestSyscallFileOps:
    """Verify file-system-related system calls."""

    def test_create_file(self) -> None:
        """SYS_CREATE_FILE should create a file at the given path."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/hello.txt")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "hello.txt" in result

    def test_create_dir(self) -> None:
        """SYS_CREATE_DIR should create a directory."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/docs")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "docs" in result

    def test_write_and_read_file(self) -> None:
        """SYS_WRITE_FILE and SYS_READ_FILE round-trip data."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/msg.txt")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/msg.txt",
            data=b"hello kernel",
        )
        result = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/msg.txt")
        assert result == b"hello kernel"

    def test_delete_file(self) -> None:
        """SYS_DELETE_FILE should remove a file."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/temp.txt")
        kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/temp.txt")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "temp.txt" not in result

    def test_read_nonexistent_file(self) -> None:
        """Reading a non-existent file should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/nope.txt")

    def test_list_dir(self) -> None:
        """SYS_LIST_DIR should return directory contents."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/a.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/b.txt")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "a.txt" in result
        assert "b.txt" in result


class TestSyscallMemoryOps:
    """Verify memory-related system calls."""

    def test_memory_info(self) -> None:
        """SYS_MEMORY_INFO should return memory statistics."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
        assert "total_frames" in result
        assert "free_frames" in result
        assert result["total_frames"] == DEFAULT_TOTAL_FRAMES
        assert result["free_frames"] == DEFAULT_TOTAL_FRAMES

    def test_memory_info_after_allocation(self) -> None:
        """Free frames should decrease after process creation."""
        kernel = _booted_kernel()
        kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="hog",
            num_pages=NUM_PAGES,
        )
        result = kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
        expected_free = 62
        assert result["free_frames"] == expected_free


class TestSyscallScheduler:
    """Verify scheduler-related system calls."""

    def test_sys_set_scheduler_priority(self) -> None:
        """SYS_SET_SCHEDULER should switch to priority policy."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_SET_SCHEDULER,
            policy="priority",
        )
        assert "priority" in result.lower()

    def test_sys_set_scheduler_rr_with_quantum(self) -> None:
        """SYS_SET_SCHEDULER should switch to round robin with quantum."""
        kernel = _booted_kernel()
        rr_quantum = 4
        result = kernel.syscall(
            SyscallNumber.SYS_SET_SCHEDULER,
            policy="rr",
            quantum=rr_quantum,
        )
        assert "round robin" in result.lower()

    def test_sys_set_scheduler_unknown(self) -> None:
        """SYS_SET_SCHEDULER with unknown policy should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="Unknown"):
            kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                policy="bogus",
            )

    def test_sys_set_scheduler_mlfq(self) -> None:
        """SYS_SET_SCHEDULER should switch to MLFQ policy."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_SET_SCHEDULER,
            policy="mlfq",
        )
        assert "MLFQ" in result

    def test_sys_scheduler_boost(self) -> None:
        """SYS_SCHEDULER_BOOST should succeed with MLFQ active."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="mlfq")
        result = kernel.syscall(SyscallNumber.SYS_SCHEDULER_BOOST)
        assert "boost" in result.lower()

    def test_sys_scheduler_boost_non_mlfq_raises(self) -> None:
        """SYS_SCHEDULER_BOOST without MLFQ should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="MLFQ"):
            kernel.syscall(SyscallNumber.SYS_SCHEDULER_BOOST)

    def test_sys_set_scheduler_aging(self) -> None:
        """SYS_SET_SCHEDULER with policy='aging' should switch to Aging Priority."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_SET_SCHEDULER,
            policy="aging",
        )
        assert "aging" in result.lower()

    def test_sys_set_scheduler_cfs(self) -> None:
        """SYS_SET_SCHEDULER with policy='cfs' should switch to CFS."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_SET_SCHEDULER,
            policy="cfs",
        )
        assert "CFS" in result


class TestSyscallValidation:
    """Verify that syscalls validate inputs and kernel state."""

    def test_syscall_before_boot_raises(self) -> None:
        """Syscalls should fail if the kernel isn't running."""
        kernel = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)

    def test_unknown_syscall_raises(self) -> None:
        """An invalid syscall number should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="Unknown syscall"):
            kernel.syscall(999)  # type: ignore[arg-type]


# -- File-system error paths ---------------------------------------------------

NONEXISTENT_PID = 99999


class TestSyscallFileErrors:
    """Verify syscall exception handling for filesystem operations."""

    def test_create_file_duplicate_raises(self) -> None:
        """Creating an already-existing file should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/dup.txt")
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/dup.txt")

    def test_create_dir_duplicate_raises(self) -> None:
        """Creating an already-existing directory should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/mydir")
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/mydir")

    def test_delete_nonexistent_file_raises(self) -> None:
        """Deleting a nonexistent file should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/gone.txt")


# -- File descriptor error paths -----------------------------------------------


class TestSyscallFdErrors:
    """Verify syscall exception handling for file descriptor operations."""

    def test_read_fd_invalid_raises(self) -> None:
        """Reading from an invalid FD should raise SyscallError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=NUM_PAGES)
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_READ_FD, pid=proc.pid, fd=999, count=10)

    def test_write_fd_invalid_raises(self) -> None:
        """Writing to an invalid FD should raise SyscallError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=NUM_PAGES)
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_WRITE_FD, pid=proc.pid, fd=999, data=b"hi")

    def test_seek_fd_invalid_raises(self) -> None:
        """Seeking on an invalid FD should raise SyscallError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=NUM_PAGES)
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_SEEK,
                pid=proc.pid,
                fd=999,
                offset=0,
                whence="set",
            )


# -- Sync primitive error paths ------------------------------------------------


class TestSyscallSyncErrors:
    """Verify syscall exception handling for sync primitives."""

    def test_create_duplicate_mutex_raises(self) -> None:
        """Creating a duplicate mutex should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="m")
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="m")

    def test_acquire_nonexistent_mutex_raises(self) -> None:
        """Acquiring a nonexistent mutex should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_ACQUIRE_MUTEX, name="nope", tid=0)

    def test_release_nonexistent_mutex_raises(self) -> None:
        """Releasing a nonexistent mutex should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_RELEASE_MUTEX, name="nope", tid=0)

    def test_create_duplicate_semaphore_raises(self) -> None:
        """Creating a duplicate semaphore should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_SEMAPHORE, name="s", count=1)
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CREATE_SEMAPHORE, name="s", count=1)

    def test_acquire_nonexistent_semaphore_raises(self) -> None:
        """Acquiring a nonexistent semaphore should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_ACQUIRE_SEMAPHORE, name="nope", tid=0)

    def test_release_nonexistent_semaphore_raises(self) -> None:
        """Releasing a nonexistent semaphore should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_RELEASE_SEMAPHORE, name="nope")

    def test_create_condition_bad_mutex_raises(self) -> None:
        """Creating a condition with nonexistent mutex should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_CREATE_CONDITION,
                name="c",
                mutex_name="nope",
            )

    def test_condition_wait_nonexistent_raises(self) -> None:
        """Waiting on nonexistent condition should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CONDITION_WAIT, name="nope", tid=0)

    def test_condition_notify_nonexistent_raises(self) -> None:
        """Notifying nonexistent condition should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CONDITION_NOTIFY, name="nope")

    def test_condition_notify_all(self) -> None:
        """Notify-all on an existing condition should succeed."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="m")
        kernel.syscall(SyscallNumber.SYS_CREATE_CONDITION, name="c", mutex_name="m")
        result = kernel.syscall(SyscallNumber.SYS_CONDITION_NOTIFY, name="c", notify_all=True)
        assert "notified" in result

    def test_create_duplicate_rwlock_raises(self) -> None:
        """Creating a duplicate rwlock should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name="rw")
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name="rw")

    def test_acquire_nonexistent_read_lock_raises(self) -> None:
        """Acquiring read lock on nonexistent rwlock should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_ACQUIRE_READ_LOCK, name="nope", tid=0)

    def test_acquire_nonexistent_write_lock_raises(self) -> None:
        """Acquiring write lock on nonexistent rwlock should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_ACQUIRE_WRITE_LOCK, name="nope", tid=0)

    def test_release_nonexistent_read_lock_raises(self) -> None:
        """Releasing read lock on nonexistent rwlock should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_RELEASE_READ_LOCK, name="nope", tid=0)

    def test_release_nonexistent_write_lock_raises(self) -> None:
        """Releasing write lock on nonexistent rwlock should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_RELEASE_WRITE_LOCK, name="nope", tid=0)


# -- DNS error paths -----------------------------------------------------------


class TestSyscallDnsErrors:
    """Verify syscall exception handling for DNS operations."""

    def test_dns_register_duplicate_raises(self) -> None:
        """Registering a duplicate hostname should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_DNS_REGISTER, hostname="a.com", address="1.1.1.1")
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname="a.com",
                address="2.2.2.2",
            )

    def test_dns_lookup_nonexistent_raises(self) -> None:
        """Looking up a nonexistent hostname should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_DNS_LOOKUP, hostname="nope.com")

    def test_dns_remove_nonexistent_raises(self) -> None:
        """Removing a nonexistent hostname should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname="nope.com")


# -- Socket error paths --------------------------------------------------------


class TestSyscallSocketErrors:
    """Verify syscall exception handling for socket operations."""

    def test_socket_bind_invalid_raises(self) -> None:
        """Binding an invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_SOCKET_BIND,
                sock_id=999,
                address="127.0.0.1",
                port=80,
            )

    def test_socket_listen_invalid_raises(self) -> None:
        """Listening on invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=999)

    def test_socket_connect_invalid_raises(self) -> None:
        """Connecting an invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_SOCKET_CONNECT,
                sock_id=999,
                address="1.1.1.1",
                port=80,
            )

    def test_socket_accept_invalid_raises(self) -> None:
        """Accepting on invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=999)

    def test_socket_send_invalid_raises(self) -> None:
        """Sending on invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SOCKET_SEND, sock_id=999, data=b"hi")

    def test_socket_recv_invalid_raises(self) -> None:
        """Receiving from invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SOCKET_RECV, sock_id=999)

    def test_socket_close_invalid_raises(self) -> None:
        """Closing an invalid socket should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=999)


# -- SHM error paths ----------------------------------------------------------


class TestSyscallShmErrors:
    """Verify syscall exception handling for shared memory operations."""

    def test_shm_detach_nonexistent_raises(self) -> None:
        """Detaching from nonexistent segment should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SHM_DETACH, name="nope", pid=1)

    def test_shm_destroy_nonexistent_raises(self) -> None:
        """Destroying nonexistent segment should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_SHM_DESTROY, name="nope")

    def test_shm_write_nonexistent_raises(self) -> None:
        """Writing to nonexistent segment should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_SHM_WRITE,
                name="nope",
                pid=1,
                data=b"hi",
            )

    def test_shm_read_nonexistent_raises(self) -> None:
        """Reading from nonexistent segment should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(
                SyscallNumber.SYS_SHM_READ,
                name="nope",
                pid=1,
            )


# -- Mmap error paths ---------------------------------------------------------


class TestSyscallMmapErrors:
    """Verify syscall exception handling for mmap operations."""

    def test_munmap_invalid_raises(self) -> None:
        """Unmapping an invalid address should raise SyscallError."""
        kernel = _booted_kernel()
        proc = kernel.create_process(name="app", num_pages=NUM_PAGES)
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_MUNMAP, pid=proc.pid, virtual_address=9999)


# -- Scheduler info paths -----------------------------------------------------


class TestSyscallSchedulerInfo:
    """Verify scheduler info syscall covers all policy types."""

    def test_scheduler_info_rr(self) -> None:
        """Scheduler info should show Round Robin details."""
        kernel = _booted_kernel()
        rr_quantum = 3
        kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="rr", quantum=rr_quantum)
        result = kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
        assert "Round Robin" in result["policy"]

    def test_scheduler_info_priority(self) -> None:
        """Scheduler info should show Priority."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="priority")
        result = kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
        assert "Priority" in result["policy"]

    def test_rr_without_quantum_raises(self) -> None:
        """Setting RR scheduler without quantum should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="quantum"):
            kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="rr")


# -- TCP error paths -----------------------------------------------------------


class TestSyscallTcpErrors:
    """Verify syscall exception handling for TCP operations."""

    def test_tcp_listen_invalid_raises(self) -> None:
        """TCP listen on invalid port should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_TCP_LISTEN, port=80)
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_TCP_LISTEN, port=80)

    def test_tcp_accept_invalid_raises(self) -> None:
        """TCP accept on invalid listener should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_TCP_ACCEPT, listener_id=999)

    def test_tcp_connect_returns_info(self) -> None:
        """TCP connect should return connection info."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_TCP_CONNECT,
            client_port=5000,
            server_port=80,
        )
        assert "conn_id" in result

    def test_tcp_send_invalid_raises(self) -> None:
        """TCP send on invalid connection should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_TCP_SEND, conn_id=999, data=b"hi")

    def test_tcp_recv_invalid_raises(self) -> None:
        """TCP recv on invalid connection should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_TCP_RECV, conn_id=999)

    def test_tcp_close_invalid_raises(self) -> None:
        """TCP close on invalid connection should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_TCP_CLOSE, conn_id=999)

    def test_tcp_info_invalid_raises(self) -> None:
        """TCP info on invalid connection should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError):
            kernel.syscall(SyscallNumber.SYS_TCP_INFO, conn_id=999)
