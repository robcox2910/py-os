"""System call interface — the gateway between user-space and kernel-space.

In a real OS, user programs cannot directly access kernel memory or
hardware.  Instead they trigger a **trap** (software interrupt) that
switches the CPU to kernel mode, where a dispatcher examines the
syscall number and arguments and routes to the right handler.

Our simulation mirrors this pattern:

1. ``SyscallNumber`` — an enum of every operation the kernel supports.
   In Linux these are integers in a table (``__NR_read``, ``__NR_write``,
   etc.).  We use an IntEnum so they're also valid ints.

2. ``SyscallError`` — a user-facing exception for syscall failures.
   The kernel catches internal exceptions (``FileNotFoundError``,
   ``OutOfMemoryError``) and re-raises them as ``SyscallError`` so
   user-space never sees raw kernel internals.

3. ``dispatch_syscall()`` — the trap handler.  It receives the syscall
   number and keyword arguments, validates, and calls the appropriate
   kernel subsystem.  This is the *only* entry point from user-space
   into the kernel.

Why bother with this layer?
    - **Security**: every request is validated before touching internals.
    - **Abstraction**: user code never imports filesystem, scheduler, etc.
    - **Stability**: kernel internals can change without breaking callers.
    - **Auditability**: one choke-point for logging, rate-limiting, etc.
"""

import contextlib
from enum import IntEnum
from typing import Any

from py_os.fs.fd import FdError, FileMode, SeekWhence
from py_os.io.dns import DnsError
from py_os.io.networking import SocketError
from py_os.io.shm import SharedMemoryError
from py_os.memory.mmap import MmapError
from py_os.memory.slab import SlabError
from py_os.process.scheduler import (
    AgingPriorityPolicy,
    CFSPolicy,
    FCFSPolicy,
    MLFQPolicy,
    PriorityPolicy,
    RoundRobinPolicy,
)
from py_os.process.signals import SignalError
from py_os.sync.ordering import OrderingMode
from py_os.users import FilePermissions
from py_os.users import PermissionError as OsPermissionError


class SyscallNumber(IntEnum):
    """Enumerate every system call the kernel supports.

    Using IntEnum means each syscall is also a plain int — matching
    how real kernels identify syscalls by number in a lookup table.
    """

    # Process operations
    SYS_CREATE_PROCESS = 1
    SYS_TERMINATE_PROCESS = 2
    SYS_LIST_PROCESSES = 3
    SYS_FORK = 4
    SYS_CREATE_THREAD = 5
    SYS_LIST_THREADS = 6
    SYS_WAIT = 7
    SYS_WAITPID = 8

    # File-system operations
    SYS_CREATE_FILE = 10
    SYS_CREATE_DIR = 11
    SYS_READ_FILE = 12
    SYS_WRITE_FILE = 13
    SYS_DELETE_FILE = 14
    SYS_LIST_DIR = 15
    SYS_OPEN = 16
    SYS_CLOSE = 17
    SYS_READ_FD = 18
    SYS_WRITE_FD = 19

    # Memory operations
    SYS_MEMORY_INFO = 20
    SYS_MMAP = 21
    SYS_MUNMAP = 22
    SYS_MSYNC = 23
    SYS_SLAB_CREATE = 24
    SYS_SLAB_ALLOC = 25
    SYS_SLAB_FREE = 26
    SYS_SLAB_INFO = 27
    SYS_SEEK = 28

    # User operations
    SYS_WHOAMI = 30
    SYS_CREATE_USER = 31
    SYS_LIST_USERS = 32
    SYS_SWITCH_USER = 33

    # Link operations
    SYS_LINK = 34
    SYS_SYMLINK = 35
    SYS_READLINK = 36

    # Device operations
    SYS_DEVICE_READ = 40
    SYS_DEVICE_WRITE = 41
    SYS_LIST_DEVICES = 42

    # Logging operations
    SYS_READ_LOG = 50

    # Signal operations
    SYS_SEND_SIGNAL = 60
    SYS_REGISTER_HANDLER = 61

    # System info
    SYS_SYSINFO = 80

    # Deadlock operations
    SYS_DETECT_DEADLOCK = 90
    SYS_CHECK_ORDERING = 91
    SYS_SET_ORDERING_MODE = 92
    SYS_REGISTER_RANK = 93

    # Execution operations
    SYS_EXEC = 100
    SYS_RUN = 101

    # Environment operations
    SYS_GET_ENV = 70
    SYS_SET_ENV = 71
    SYS_LIST_ENV = 72
    SYS_DELETE_ENV = 73

    # Synchronization operations
    SYS_CREATE_MUTEX = 110
    SYS_ACQUIRE_MUTEX = 111
    SYS_RELEASE_MUTEX = 112
    SYS_CREATE_SEMAPHORE = 113
    SYS_ACQUIRE_SEMAPHORE = 114
    SYS_RELEASE_SEMAPHORE = 115
    SYS_CREATE_CONDITION = 116
    SYS_CONDITION_WAIT = 117
    SYS_CONDITION_NOTIFY = 118
    SYS_CREATE_RWLOCK = 119

    # Scheduler operations
    SYS_SET_SCHEDULER = 120
    SYS_SCHEDULER_BOOST = 121

    # Reader-writer lock operations (continues sync block after scheduler gap)
    SYS_ACQUIRE_READ_LOCK = 122
    SYS_ACQUIRE_WRITE_LOCK = 123
    SYS_RELEASE_READ_LOCK = 124
    SYS_RELEASE_WRITE_LOCK = 125

    # Journal operations
    SYS_JOURNAL_STATUS = 130
    SYS_JOURNAL_CHECKPOINT = 131
    SYS_JOURNAL_RECOVER = 132
    SYS_JOURNAL_CRASH = 133

    # Shared memory operations
    SYS_SHM_CREATE = 140
    SYS_SHM_ATTACH = 141
    SYS_SHM_DETACH = 142
    SYS_SHM_DESTROY = 143
    SYS_SHM_WRITE = 144
    SYS_SHM_READ = 145
    SYS_SHM_LIST = 146

    # DNS operations
    SYS_DNS_REGISTER = 150
    SYS_DNS_LOOKUP = 151
    SYS_DNS_REMOVE = 152
    SYS_DNS_LIST = 153
    SYS_DNS_FLUSH = 154

    # Socket operations
    SYS_SOCKET_CREATE = 160
    SYS_SOCKET_BIND = 161
    SYS_SOCKET_LISTEN = 162
    SYS_SOCKET_CONNECT = 163
    SYS_SOCKET_ACCEPT = 164
    SYS_SOCKET_SEND = 165
    SYS_SOCKET_RECV = 166
    SYS_SOCKET_CLOSE = 167
    SYS_SOCKET_LIST = 168

    # /proc virtual filesystem operations
    SYS_PROC_READ = 170
    SYS_PROC_LIST = 171

    # Performance metrics
    SYS_PERF_METRICS = 172

    # Strace operations
    SYS_STRACE_ENABLE = 180
    SYS_STRACE_DISABLE = 181
    SYS_STRACE_LOG = 182
    SYS_STRACE_CLEAR = 183

    # Kernel-mode enforcement operations
    SYS_SHUTDOWN = 190
    SYS_SCHEDULER_INFO = 191
    SYS_LSTAT = 192
    SYS_LIST_MUTEXES = 193
    SYS_LIST_SEMAPHORES = 194
    SYS_LIST_RWLOCKS = 195
    SYS_LIST_FDS = 196
    SYS_LIST_RESOURCES = 197
    SYS_PI_STATUS = 198
    SYS_ORDERING_VIOLATIONS = 199
    SYS_DESTROY_MUTEX = 200
    SYS_DISPATCH = 201
    SYS_PROCESS_INFO = 202
    SYS_STRACE_STATUS = 203


class SyscallError(Exception):
    """Raised when a system call fails.

    This is the only exception user-space should ever see from a
    syscall.  Internal kernel exceptions are caught and wrapped.
    """


def dispatch_syscall(
    kernel: Any,
    number: SyscallNumber,
    **kwargs: Any,
) -> Any:
    """Dispatch a system call to the appropriate kernel subsystem.

    This is the trap handler — the single entry point from user-space
    into the kernel.  It validates the syscall number, calls the right
    handler, and wraps internal errors in SyscallError.

    Args:
        kernel: The running kernel instance.
        number: The syscall number identifying the operation.
        **kwargs: Arguments specific to the syscall.

    Returns:
        The syscall result (type depends on the operation).

    Raises:
        SyscallError: If the syscall fails or the number is unknown.

    """
    handlers: dict[SyscallNumber, Any] = {
        SyscallNumber.SYS_CREATE_PROCESS: _sys_create_process,
        SyscallNumber.SYS_TERMINATE_PROCESS: _sys_terminate_process,
        SyscallNumber.SYS_LIST_PROCESSES: _sys_list_processes,
        SyscallNumber.SYS_FORK: _sys_fork,
        SyscallNumber.SYS_CREATE_THREAD: _sys_create_thread,
        SyscallNumber.SYS_LIST_THREADS: _sys_list_threads,
        SyscallNumber.SYS_WAIT: _sys_wait,
        SyscallNumber.SYS_WAITPID: _sys_waitpid,
        SyscallNumber.SYS_CREATE_FILE: _sys_create_file,
        SyscallNumber.SYS_CREATE_DIR: _sys_create_dir,
        SyscallNumber.SYS_READ_FILE: _sys_read_file,
        SyscallNumber.SYS_WRITE_FILE: _sys_write_file,
        SyscallNumber.SYS_DELETE_FILE: _sys_delete_file,
        SyscallNumber.SYS_LIST_DIR: _sys_list_dir,
        SyscallNumber.SYS_OPEN: _sys_open,
        SyscallNumber.SYS_CLOSE: _sys_close,
        SyscallNumber.SYS_READ_FD: _sys_read_fd,
        SyscallNumber.SYS_WRITE_FD: _sys_write_fd,
        SyscallNumber.SYS_SEEK: _sys_seek,
        SyscallNumber.SYS_MEMORY_INFO: _sys_memory_info,
        SyscallNumber.SYS_MMAP: _sys_mmap,
        SyscallNumber.SYS_MUNMAP: _sys_munmap,
        SyscallNumber.SYS_MSYNC: _sys_msync,
        SyscallNumber.SYS_SLAB_CREATE: _sys_slab_create,
        SyscallNumber.SYS_SLAB_ALLOC: _sys_slab_alloc,
        SyscallNumber.SYS_SLAB_FREE: _sys_slab_free,
        SyscallNumber.SYS_SLAB_INFO: _sys_slab_info,
        SyscallNumber.SYS_WHOAMI: _sys_whoami,
        SyscallNumber.SYS_CREATE_USER: _sys_create_user,
        SyscallNumber.SYS_LIST_USERS: _sys_list_users,
        SyscallNumber.SYS_SWITCH_USER: _sys_switch_user,
        SyscallNumber.SYS_LINK: _sys_link,
        SyscallNumber.SYS_SYMLINK: _sys_symlink,
        SyscallNumber.SYS_READLINK: _sys_readlink,
        SyscallNumber.SYS_DEVICE_READ: _sys_device_read,
        SyscallNumber.SYS_DEVICE_WRITE: _sys_device_write,
        SyscallNumber.SYS_LIST_DEVICES: _sys_list_devices,
        SyscallNumber.SYS_READ_LOG: _sys_read_log,
        SyscallNumber.SYS_SEND_SIGNAL: _sys_send_signal,
        SyscallNumber.SYS_REGISTER_HANDLER: _sys_register_handler,
        SyscallNumber.SYS_GET_ENV: _sys_get_env,
        SyscallNumber.SYS_SET_ENV: _sys_set_env,
        SyscallNumber.SYS_LIST_ENV: _sys_list_env,
        SyscallNumber.SYS_DELETE_ENV: _sys_delete_env,
        SyscallNumber.SYS_SYSINFO: _sys_sysinfo,
        SyscallNumber.SYS_DETECT_DEADLOCK: _sys_detect_deadlock,
        SyscallNumber.SYS_CHECK_ORDERING: _sys_check_ordering,
        SyscallNumber.SYS_SET_ORDERING_MODE: _sys_set_ordering_mode,
        SyscallNumber.SYS_REGISTER_RANK: _sys_register_rank,
        SyscallNumber.SYS_EXEC: _sys_exec,
        SyscallNumber.SYS_RUN: _sys_run,
        SyscallNumber.SYS_CREATE_MUTEX: _sys_create_mutex,
        SyscallNumber.SYS_ACQUIRE_MUTEX: _sys_acquire_mutex,
        SyscallNumber.SYS_RELEASE_MUTEX: _sys_release_mutex,
        SyscallNumber.SYS_CREATE_SEMAPHORE: _sys_create_semaphore,
        SyscallNumber.SYS_ACQUIRE_SEMAPHORE: _sys_acquire_semaphore,
        SyscallNumber.SYS_RELEASE_SEMAPHORE: _sys_release_semaphore,
        SyscallNumber.SYS_CREATE_CONDITION: _sys_create_condition,
        SyscallNumber.SYS_CONDITION_WAIT: _sys_condition_wait,
        SyscallNumber.SYS_CONDITION_NOTIFY: _sys_condition_notify,
        SyscallNumber.SYS_CREATE_RWLOCK: _sys_create_rwlock,
        SyscallNumber.SYS_ACQUIRE_READ_LOCK: _sys_acquire_read_lock,
        SyscallNumber.SYS_ACQUIRE_WRITE_LOCK: _sys_acquire_write_lock,
        SyscallNumber.SYS_RELEASE_READ_LOCK: _sys_release_read_lock,
        SyscallNumber.SYS_RELEASE_WRITE_LOCK: _sys_release_write_lock,
        SyscallNumber.SYS_SET_SCHEDULER: _sys_set_scheduler,
        SyscallNumber.SYS_SCHEDULER_BOOST: _sys_scheduler_boost,
        SyscallNumber.SYS_JOURNAL_STATUS: _sys_journal_status,
        SyscallNumber.SYS_JOURNAL_CHECKPOINT: _sys_journal_checkpoint,
        SyscallNumber.SYS_JOURNAL_RECOVER: _sys_journal_recover,
        SyscallNumber.SYS_JOURNAL_CRASH: _sys_journal_crash,
        SyscallNumber.SYS_SHM_CREATE: _sys_shm_create,
        SyscallNumber.SYS_SHM_ATTACH: _sys_shm_attach,
        SyscallNumber.SYS_SHM_DETACH: _sys_shm_detach,
        SyscallNumber.SYS_SHM_DESTROY: _sys_shm_destroy,
        SyscallNumber.SYS_SHM_WRITE: _sys_shm_write,
        SyscallNumber.SYS_SHM_READ: _sys_shm_read,
        SyscallNumber.SYS_SHM_LIST: _sys_shm_list,
        SyscallNumber.SYS_DNS_REGISTER: _sys_dns_register,
        SyscallNumber.SYS_DNS_LOOKUP: _sys_dns_lookup,
        SyscallNumber.SYS_DNS_REMOVE: _sys_dns_remove,
        SyscallNumber.SYS_DNS_LIST: _sys_dns_list,
        SyscallNumber.SYS_DNS_FLUSH: _sys_dns_flush,
        SyscallNumber.SYS_SOCKET_CREATE: _sys_socket_create,
        SyscallNumber.SYS_SOCKET_BIND: _sys_socket_bind,
        SyscallNumber.SYS_SOCKET_LISTEN: _sys_socket_listen,
        SyscallNumber.SYS_SOCKET_CONNECT: _sys_socket_connect,
        SyscallNumber.SYS_SOCKET_ACCEPT: _sys_socket_accept,
        SyscallNumber.SYS_SOCKET_SEND: _sys_socket_send,
        SyscallNumber.SYS_SOCKET_RECV: _sys_socket_recv,
        SyscallNumber.SYS_SOCKET_CLOSE: _sys_socket_close,
        SyscallNumber.SYS_SOCKET_LIST: _sys_socket_list,
        SyscallNumber.SYS_PROC_READ: _sys_proc_read,
        SyscallNumber.SYS_PROC_LIST: _sys_proc_list,
        SyscallNumber.SYS_PERF_METRICS: _sys_perf_metrics,
        SyscallNumber.SYS_STRACE_ENABLE: _sys_strace_enable,
        SyscallNumber.SYS_STRACE_DISABLE: _sys_strace_disable,
        SyscallNumber.SYS_STRACE_LOG: _sys_strace_log,
        SyscallNumber.SYS_STRACE_CLEAR: _sys_strace_clear,
        SyscallNumber.SYS_SHUTDOWN: _sys_shutdown,
        SyscallNumber.SYS_SCHEDULER_INFO: _sys_scheduler_info,
        SyscallNumber.SYS_LSTAT: _sys_lstat,
        SyscallNumber.SYS_LIST_MUTEXES: _sys_list_mutexes,
        SyscallNumber.SYS_LIST_SEMAPHORES: _sys_list_semaphores,
        SyscallNumber.SYS_LIST_RWLOCKS: _sys_list_rwlocks,
        SyscallNumber.SYS_LIST_FDS: _sys_list_fds,
        SyscallNumber.SYS_LIST_RESOURCES: _sys_list_resources,
        SyscallNumber.SYS_PI_STATUS: _sys_pi_status,
        SyscallNumber.SYS_ORDERING_VIOLATIONS: _sys_ordering_violations,
        SyscallNumber.SYS_DESTROY_MUTEX: _sys_destroy_mutex,
        SyscallNumber.SYS_DISPATCH: _sys_dispatch,
        SyscallNumber.SYS_PROCESS_INFO: _sys_process_info,
        SyscallNumber.SYS_STRACE_STATUS: _sys_strace_status,
    }

    handler = handlers.get(number)
    if handler is None:
        msg = f"Unknown syscall: {number}"
        raise SyscallError(msg)

    return handler(kernel, **kwargs)


# -- Process syscall handlers ------------------------------------------------


def _sys_create_process(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Create a new process."""
    name: str = kwargs["name"]
    num_pages: int = kwargs["num_pages"]
    priority: int = kwargs.get("priority", 0)
    process = kernel.create_process(name=name, num_pages=num_pages, priority=priority)
    return {"pid": process.pid, "name": process.name, "state": process.state}


def _sys_terminate_process(kernel: Any, **kwargs: Any) -> None:
    """Terminate a process by PID."""
    pid: int = kwargs["pid"]
    if pid not in kernel.processes:
        msg = f"Process {pid} not found"
        raise SyscallError(msg)
    kernel.terminate_process(pid=pid)


def _sys_list_processes(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """List all processes."""
    return [
        {
            "pid": p.pid,
            "name": p.name,
            "state": p.state,
            "parent_pid": p.parent_pid,
        }
        for p in kernel.processes.values()
    ]


def _sys_fork(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Fork a process, creating a child copy."""
    parent_pid: int = kwargs["parent_pid"]
    try:
        child = kernel.fork_process(parent_pid=parent_pid)
    except (ValueError, MemoryError) as e:
        raise SyscallError(str(e)) from e
    return {
        "child_pid": child.pid,
        "parent_pid": parent_pid,
        "name": child.name,
        "state": child.state,
    }


def _sys_create_thread(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Create a thread within a process."""
    pid: int = kwargs["pid"]
    name: str = kwargs["name"]
    try:
        thread = kernel.create_thread(pid=pid, name=name)
    except ValueError as e:
        raise SyscallError(str(e)) from e
    return {
        "tid": thread.tid,
        "pid": thread.pid,
        "name": thread.name,
        "state": thread.state,
    }


def _sys_list_threads(kernel: Any, **kwargs: Any) -> list[dict[str, Any]]:
    """List all threads for a process."""
    pid: int = kwargs["pid"]
    if pid not in kernel.processes:
        msg = f"Process {pid} not found"
        raise SyscallError(msg)
    process = kernel.processes[pid]
    return [{"tid": t.tid, "name": t.name, "state": t.state} for t in process.threads.values()]


def _sys_wait(kernel: Any, **kwargs: Any) -> dict[str, Any] | None:
    """Wait for any child of the parent to terminate."""
    parent_pid: int = kwargs["parent_pid"]
    try:
        return kernel.wait_process(parent_pid=parent_pid)
    except ValueError as e:
        raise SyscallError(str(e)) from e


def _sys_waitpid(kernel: Any, **kwargs: Any) -> dict[str, Any] | None:
    """Wait for a specific child to terminate."""
    parent_pid: int = kwargs["parent_pid"]
    child_pid: int = kwargs["child_pid"]
    try:
        return kernel.waitpid_process(parent_pid=parent_pid, child_pid=child_pid)
    except ValueError as e:
        raise SyscallError(str(e)) from e


# -- File-system syscall handlers --------------------------------------------


def _sys_create_file(kernel: Any, **kwargs: Any) -> None:
    """Create a file and assign ownership to the current user."""
    assert kernel.filesystem is not None  # noqa: S101
    path: str = kwargs["path"]
    try:
        kernel.filesystem.create_file(path)
    except (FileNotFoundError, FileExistsError) as e:
        raise SyscallError(str(e)) from e
    kernel.file_permissions[path] = FilePermissions(owner_uid=kernel.current_uid)


def _sys_create_dir(kernel: Any, **kwargs: Any) -> None:
    """Create a directory."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        kernel.filesystem.create_dir(kwargs["path"])
    except (FileNotFoundError, FileExistsError) as e:
        raise SyscallError(str(e)) from e


def _sys_read_file(kernel: Any, **kwargs: Any) -> bytes:
    """Read file contents (with permission check)."""
    assert kernel.filesystem is not None  # noqa: S101
    path: str = kwargs["path"]
    perms = kernel.file_permissions.get(path)
    if perms is not None:
        try:
            perms.check_read(uid=kernel.current_uid)
        except OsPermissionError as e:
            raise SyscallError(str(e)) from e
    try:
        return kernel.filesystem.read(path)
    except FileNotFoundError as e:
        msg = f"File not found: {path}"
        raise SyscallError(msg) from e


def _sys_write_file(kernel: Any, **kwargs: Any) -> None:
    """Write data to a file (with permission check)."""
    assert kernel.filesystem is not None  # noqa: S101
    path: str = kwargs["path"]
    perms = kernel.file_permissions.get(path)
    if perms is not None:
        try:
            perms.check_write(uid=kernel.current_uid)
        except OsPermissionError as e:
            raise SyscallError(str(e)) from e
    try:
        kernel.filesystem.write(path, kwargs["data"])
    except FileNotFoundError as e:
        raise SyscallError(str(e)) from e


def _sys_delete_file(kernel: Any, **kwargs: Any) -> None:
    """Delete a file or directory and clean up permissions."""
    assert kernel.filesystem is not None  # noqa: S101
    path: str = kwargs["path"]
    try:
        kernel.filesystem.delete(path)
    except FileNotFoundError as e:
        raise SyscallError(str(e)) from e
    kernel.file_permissions.pop(path, None)


def _sys_list_dir(kernel: Any, **kwargs: Any) -> list[str]:
    """List directory contents."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        return kernel.filesystem.list_dir(kwargs["path"])
    except FileNotFoundError as e:
        raise SyscallError(str(e)) from e


# -- Link syscall handlers ---------------------------------------------------


def _sys_link(kernel: Any, **kwargs: Any) -> None:
    """Create a hard link."""
    target: str = kwargs["target"]
    link_path: str = kwargs["link_path"]
    try:
        kernel.link_file(target, link_path)
    except (FileNotFoundError, FileExistsError, OSError) as e:
        raise SyscallError(str(e)) from e


def _sys_symlink(kernel: Any, **kwargs: Any) -> None:
    """Create a symbolic link."""
    target: str = kwargs["target"]
    link_path: str = kwargs["link_path"]
    try:
        kernel.symlink_file(target, link_path)
    except (FileNotFoundError, FileExistsError) as e:
        raise SyscallError(str(e)) from e


def _sys_readlink(kernel: Any, **kwargs: Any) -> str:
    """Read the target of a symbolic link."""
    path: str = kwargs["path"]
    try:
        return kernel.readlink_file(path)
    except (FileNotFoundError, OSError) as e:
        raise SyscallError(str(e)) from e


# -- File descriptor syscall handlers ----------------------------------------


def _sys_open(kernel: Any, **kwargs: Any) -> dict[str, int]:
    """Open a file and return a file descriptor."""
    pid: int = kwargs["pid"]
    path: str = kwargs["path"]
    mode = FileMode(kwargs["mode"])
    try:
        fd = kernel.open_file(pid, path, mode)
    except FdError as e:
        raise SyscallError(str(e)) from e
    return {"fd": fd}


def _sys_close(kernel: Any, **kwargs: Any) -> None:
    """Close a file descriptor."""
    try:
        kernel.close_file(kwargs["pid"], kwargs["fd"])
    except FdError as e:
        raise SyscallError(str(e)) from e


def _sys_read_fd(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Read bytes from a file descriptor."""
    pid: int = kwargs["pid"]
    fd: int = kwargs["fd"]
    count: int = kwargs["count"]
    try:
        data = kernel.read_fd(pid, fd, count=count)
    except FdError as e:
        raise SyscallError(str(e)) from e
    return {"data": data, "count": len(data)}


def _sys_write_fd(kernel: Any, **kwargs: Any) -> dict[str, int]:
    """Write bytes to a file descriptor."""
    pid: int = kwargs["pid"]
    fd: int = kwargs["fd"]
    data: bytes = kwargs["data"]
    try:
        bytes_written = kernel.write_fd(pid, fd, data)
    except FdError as e:
        raise SyscallError(str(e)) from e
    return {"bytes_written": bytes_written}


def _sys_seek(kernel: Any, **kwargs: Any) -> dict[str, int]:
    """Reposition a file descriptor's offset."""
    pid: int = kwargs["pid"]
    fd: int = kwargs["fd"]
    offset: int = kwargs["offset"]
    whence = SeekWhence(kwargs["whence"])
    try:
        new_offset = kernel.seek_fd(pid, fd, offset=offset, whence=whence)
    except FdError as e:
        raise SyscallError(str(e)) from e
    return {"offset": new_offset}


# -- Memory syscall handlers -------------------------------------------------


def _sys_memory_info(kernel: Any, **_kwargs: Any) -> dict[str, int]:
    """Return memory statistics."""
    assert kernel.memory is not None  # noqa: S101
    return {
        "total_frames": kernel.memory.total_frames,
        "free_frames": kernel.memory.free_frames,
    }


def _sys_mmap(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Map a file into a process's virtual address space."""
    pid: int = kwargs["pid"]
    path: str = kwargs["path"]
    offset: int = kwargs.get("offset", 0)
    length: int | None = kwargs.get("length")
    shared: bool = kwargs.get("shared", False)
    try:
        virtual_address = kernel.mmap_file(
            pid=pid,
            path=path,
            offset=offset,
            length=length,
            shared=shared,
        )
    except MmapError as e:
        raise SyscallError(str(e)) from e
    process = kernel.processes.get(pid)
    assert process is not None  # noqa: S101
    assert process.virtual_memory is not None  # noqa: S101
    start_vpn = virtual_address // process.virtual_memory.page_size
    region = kernel.mmap_regions(pid)[start_vpn]
    return {"virtual_address": virtual_address, "num_pages": region.num_pages}


def _sys_munmap(kernel: Any, **kwargs: Any) -> None:
    """Unmap a memory-mapped region."""
    try:
        kernel.munmap_file(pid=kwargs["pid"], virtual_address=kwargs["virtual_address"])
    except MmapError as e:
        raise SyscallError(str(e)) from e


def _sys_msync(kernel: Any, **kwargs: Any) -> None:
    """Sync a shared mapping's data back to the file."""
    try:
        kernel.msync_file(pid=kwargs["pid"], virtual_address=kwargs["virtual_address"])
    except MmapError as e:
        raise SyscallError(str(e)) from e


# -- Slab allocator syscall handlers -----------------------------------------


def _sys_slab_create(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Create a named slab cache."""
    name: str = kwargs["name"]
    obj_size: int = kwargs["obj_size"]
    try:
        cache = kernel.slab_create_cache(name, obj_size=obj_size)
    except SlabError as e:
        raise SyscallError(str(e)) from e
    return {
        "name": cache.name,
        "obj_size": cache.obj_size,
        "capacity_per_slab": cache.stats()["total_slots"] if cache.slab_count > 0 else 0,
    }


def _sys_slab_alloc(kernel: Any, **kwargs: Any) -> dict[str, int | str]:
    """Allocate an object from a slab cache."""
    cache_name: str = kwargs["cache"]
    try:
        name, slab_index, slot_index = kernel.slab_alloc(cache_name)
    except SlabError as e:
        raise SyscallError(str(e)) from e
    return {"cache": name, "slab_index": slab_index, "slot_index": slot_index}


def _sys_slab_free(kernel: Any, **kwargs: Any) -> None:
    """Free an object back to a slab cache."""
    try:
        kernel.slab_free(kwargs["cache"], kwargs["slab_index"], kwargs["slot_index"])
    except SlabError as e:
        raise SyscallError(str(e)) from e


def _sys_slab_info(kernel: Any, **_kwargs: Any) -> dict[str, dict[str, Any]]:
    """Return stats for all slab caches."""
    return kernel.slab_info()


# -- User syscall handlers ---------------------------------------------------


def _sys_whoami(kernel: Any, **_kwargs: Any) -> dict[str, Any]:
    """Return the current user's info."""
    assert kernel.user_manager is not None  # noqa: S101
    user = kernel.user_manager.get_user(kernel.current_uid)
    assert user is not None  # noqa: S101
    return {"uid": user.uid, "username": user.username}


def _sys_create_user(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Create a new user."""
    assert kernel.user_manager is not None  # noqa: S101
    username: str = kwargs["username"]
    try:
        user = kernel.user_manager.create_user(username)
    except ValueError as e:
        raise SyscallError(str(e)) from e
    return {"uid": user.uid, "username": user.username}


def _sys_list_users(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """List all users."""
    assert kernel.user_manager is not None  # noqa: S101
    return [{"uid": u.uid, "username": u.username} for u in kernel.user_manager.list_users()]


def _sys_switch_user(kernel: Any, **kwargs: Any) -> None:
    """Switch the current user."""
    assert kernel.user_manager is not None  # noqa: S101
    uid: int = kwargs["uid"]
    user = kernel.user_manager.get_user(uid)
    if user is None:
        msg = f"User {uid} not found"
        raise SyscallError(msg)
    kernel.current_uid = uid


# -- Device syscall handlers -------------------------------------------------


def _sys_device_read(kernel: Any, **kwargs: Any) -> bytes:
    """Read from a named device."""
    assert kernel.device_manager is not None  # noqa: S101
    name: str = kwargs["device"]
    device = kernel.device_manager.get(name)
    if device is None:
        msg = f"Device '{name}' not found"
        raise SyscallError(msg)
    return device.read()


def _sys_device_write(kernel: Any, **kwargs: Any) -> None:
    """Write to a named device."""
    assert kernel.device_manager is not None  # noqa: S101
    name: str = kwargs["device"]
    data: bytes = kwargs["data"]
    device = kernel.device_manager.get(name)
    if device is None:
        msg = f"Device '{name}' not found"
        raise SyscallError(msg)
    try:
        device.write(data)
    except OSError as e:
        raise SyscallError(str(e)) from e


def _sys_list_devices(kernel: Any, **_kwargs: Any) -> list[str]:
    """List all registered device names."""
    assert kernel.device_manager is not None  # noqa: S101
    return kernel.device_manager.list_devices()


# -- Logging syscall handlers --------------------------------------------------


def _sys_read_log(kernel: Any, **_kwargs: Any) -> list[str]:
    """Return recent log entries as formatted strings."""
    assert kernel.logger is not None  # noqa: S101
    return [str(entry) for entry in kernel.logger.entries]


# -- Signal syscall handlers ---------------------------------------------------


def _sys_send_signal(kernel: Any, **kwargs: Any) -> None:
    """Send a signal to a process."""
    try:
        kernel.send_signal(kwargs["pid"], kwargs["signal"])
    except SignalError as e:
        raise SyscallError(str(e)) from e


def _sys_register_handler(kernel: Any, **kwargs: Any) -> str:
    """Register a signal handler for a process."""
    try:
        kernel.register_signal_handler(kwargs["pid"], kwargs["signal"], kwargs["handler"])
    except SignalError as e:
        raise SyscallError(str(e)) from e
    return f"Handler registered for {kwargs['signal'].name} on pid {kwargs['pid']}"


# -- Environment syscall handlers ----------------------------------------------


def _sys_get_env(kernel: Any, **kwargs: Any) -> str | None:
    """Get an environment variable."""
    assert kernel.env is not None  # noqa: S101
    return kernel.env.get(kwargs["key"])


def _sys_set_env(kernel: Any, **kwargs: Any) -> None:
    """Set an environment variable."""
    assert kernel.env is not None  # noqa: S101
    kernel.env.set(kwargs["key"], kwargs["value"])


def _sys_list_env(kernel: Any, **_kwargs: Any) -> list[tuple[str, str]]:
    """List all environment variables."""
    assert kernel.env is not None  # noqa: S101
    return kernel.env.items()


def _sys_delete_env(kernel: Any, **kwargs: Any) -> None:
    """Delete an environment variable."""
    assert kernel.env is not None  # noqa: S101
    try:
        kernel.env.delete(kwargs["key"])
    except KeyError as e:
        raise SyscallError(str(e)) from e


# -- System info syscall handlers ----------------------------------------------


def _sys_sysinfo(kernel: Any, **_kwargs: Any) -> dict[str, Any]:
    """Aggregate system status from all subsystems."""
    assert kernel.memory is not None  # noqa: S101
    assert kernel.device_manager is not None  # noqa: S101
    assert kernel.user_manager is not None  # noqa: S101
    assert kernel.env is not None  # noqa: S101
    assert kernel.logger is not None  # noqa: S101

    user = kernel.user_manager.get_user(kernel.current_uid)
    return {
        "uptime": kernel.uptime,
        "memory_total": kernel.memory.total_frames,
        "memory_free": kernel.memory.free_frames,
        "process_count": len(kernel.processes),
        "device_count": len(kernel.device_manager.list_devices()),
        "current_user": user.username if user else "unknown",
        "env_count": len(kernel.env),
        "log_count": len(kernel.logger.entries),
    }


# -- Deadlock syscall handlers -------------------------------------------------


def _sys_detect_deadlock(kernel: Any, **_kwargs: Any) -> dict[str, Any]:
    """Run deadlock detection and return results."""
    assert kernel.resource_manager is not None  # noqa: S101
    deadlocked = kernel.resource_manager.detect_deadlock()
    return {"deadlocked": deadlocked}


# -- Execution syscall handlers ------------------------------------------------


def _sys_exec(kernel: Any, **kwargs: Any) -> None:
    """Load a program into a process."""
    try:
        kernel.exec_process(pid=kwargs["pid"], program=kwargs["program"])
    except ValueError as e:
        raise SyscallError(str(e)) from e


def _sys_run(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Run a process and return its output and exit code."""
    try:
        return kernel.run_process(pid=kwargs["pid"])
    except ValueError as e:
        raise SyscallError(str(e)) from e


# -- Synchronization syscall handlers -----------------------------------------


def _sys_create_mutex(kernel: Any, **kwargs: Any) -> str:
    """Create a named mutex."""
    name: str = kwargs["name"]
    try:
        kernel.create_mutex(name)
    except ValueError as e:
        raise SyscallError(str(e)) from e
    return f"mutex '{name}' created"


def _sys_acquire_mutex(kernel: Any, **kwargs: Any) -> str:
    """Acquire a named mutex."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        acquired = kernel.acquire_mutex(name, tid=tid, pid=pid)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    if acquired:
        return f"mutex '{name}' acquired by thread {tid}"
    return f"thread {tid} queued for mutex '{name}'"


def _sys_release_mutex(kernel: Any, **kwargs: Any) -> str:
    """Release a named mutex."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        kernel.release_mutex(name, tid=tid, pid=pid)
    except (KeyError, ValueError) as e:
        raise SyscallError(str(e)) from e
    return f"mutex '{name}' released by thread {tid}"


def _sys_create_semaphore(kernel: Any, **kwargs: Any) -> str:
    """Create a named semaphore."""
    name: str = kwargs["name"]
    count: int = kwargs["count"]
    try:
        kernel.create_semaphore(name, count=count)
    except ValueError as e:
        raise SyscallError(str(e)) from e
    return f"semaphore '{name}' created (count={count})"


def _sys_acquire_semaphore(kernel: Any, **kwargs: Any) -> str:
    """Acquire a named semaphore."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        acquired = kernel.acquire_semaphore(name, tid=tid, pid=pid)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    if acquired:
        return f"semaphore '{name}' acquired by thread {tid}"
    return f"thread {tid} queued for semaphore '{name}'"


def _sys_release_semaphore(kernel: Any, **kwargs: Any) -> str:
    """Release a named semaphore."""
    name: str = kwargs["name"]
    pid: int | None = kwargs.get("pid")
    try:
        kernel.release_semaphore(name, pid=pid)
    except (KeyError, ValueError) as e:
        raise SyscallError(str(e)) from e
    return f"semaphore '{name}' released"


def _sys_create_condition(kernel: Any, **kwargs: Any) -> str:
    """Create a named condition variable."""
    name: str = kwargs["name"]
    mutex_name: str = kwargs["mutex_name"]
    try:
        kernel.create_condition(name, mutex_name=mutex_name)
    except (KeyError, ValueError) as e:
        raise SyscallError(str(e)) from e
    return f"condition '{name}' created"


def _sys_condition_wait(kernel: Any, **kwargs: Any) -> str:
    """Wait on a named condition variable."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    try:
        kernel.condition_wait(name, tid=tid)
    except (KeyError, ValueError) as e:
        raise SyscallError(str(e)) from e
    return f"thread {tid} waiting on '{name}'"


def _sys_condition_notify(kernel: Any, **kwargs: Any) -> str:
    """Notify waiters on a named condition variable."""
    name: str = kwargs["name"]
    notify_all: bool = kwargs.get("notify_all", False)
    try:
        if notify_all:
            kernel.condition_notify_all(name)
        else:
            kernel.condition_notify(name)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    return f"condition '{name}' notified"


# -- Reader-writer lock syscall handlers ---------------------------------------


def _sys_create_rwlock(kernel: Any, **kwargs: Any) -> str:
    """Create a named reader-writer lock."""
    name: str = kwargs["name"]
    try:
        kernel.create_rwlock(name)
    except ValueError as e:
        raise SyscallError(str(e)) from e
    return f"rwlock '{name}' created"


def _sys_acquire_read_lock(kernel: Any, **kwargs: Any) -> str:
    """Acquire read access on a named reader-writer lock."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        acquired = kernel.acquire_read_lock(name, tid=tid, pid=pid)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    if acquired:
        return f"rwlock '{name}' read-acquired by thread {tid}"
    return f"thread {tid} queued for rwlock '{name}' (read)"


def _sys_acquire_write_lock(kernel: Any, **kwargs: Any) -> str:
    """Acquire write access on a named reader-writer lock."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        acquired = kernel.acquire_write_lock(name, tid=tid, pid=pid)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    if acquired:
        return f"rwlock '{name}' write-acquired by thread {tid}"
    return f"thread {tid} queued for rwlock '{name}' (write)"


def _sys_release_read_lock(kernel: Any, **kwargs: Any) -> str:
    """Release read access on a named reader-writer lock."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        kernel.release_read_lock(name, tid=tid, pid=pid)
    except (KeyError, ValueError) as e:
        raise SyscallError(str(e)) from e
    return f"rwlock '{name}' read-released by thread {tid}"


def _sys_release_write_lock(kernel: Any, **kwargs: Any) -> str:
    """Release write access on a named reader-writer lock."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    pid: int | None = kwargs.get("pid")
    try:
        kernel.release_write_lock(name, tid=tid, pid=pid)
    except (KeyError, ValueError) as e:
        raise SyscallError(str(e)) from e
    return f"rwlock '{name}' write-released by thread {tid}"


# -- Scheduler syscall handlers ------------------------------------------------


def _sys_set_scheduler(kernel: Any, **kwargs: Any) -> str:
    """Switch the active scheduling policy."""
    policy_name: str = kwargs["policy"]
    quantum: int | None = kwargs.get("quantum")

    match policy_name:
        case "fcfs":
            kernel.set_scheduler_policy(FCFSPolicy())
            return "Scheduler set to FCFS"
        case "rr":
            if quantum is None:
                msg = "Round Robin requires a quantum"
                raise SyscallError(msg)
            kernel.set_scheduler_policy(RoundRobinPolicy(quantum=quantum))
            return f"Scheduler set to Round Robin (quantum={quantum})"
        case "priority":
            kernel.set_scheduler_policy(PriorityPolicy())
            return "Scheduler set to Priority"
        case "aging":
            aging_boost: int = kwargs.get("aging_boost", 1)
            max_age: int = kwargs.get("max_age", 10)
            policy = AgingPriorityPolicy(aging_boost=aging_boost, max_age=max_age)
            kernel.set_scheduler_policy(policy)
            return f"Scheduler set to Aging Priority (boost={aging_boost}, max_age={max_age})"
        case "mlfq":
            num_levels: int = kwargs.get("num_levels", 3)
            base_quantum: int = kwargs.get("base_quantum", 2)
            mlfq_policy = MLFQPolicy(num_levels=num_levels, base_quantum=base_quantum)
            kernel.set_scheduler_policy(mlfq_policy)
            return f"Scheduler set to MLFQ ({num_levels} levels, base_quantum={base_quantum})"
        case "cfs":
            base_slice: int = kwargs.get("base_slice", 1)
            cfs_policy = CFSPolicy(base_slice=base_slice)
            kernel.set_scheduler_policy(cfs_policy)
            return f"Scheduler set to CFS (base_slice={base_slice})"
        case _:
            msg = f"Unknown scheduling policy: {policy_name}"
            raise SyscallError(msg)


def _sys_scheduler_boost(kernel: Any, **_kwargs: Any) -> str:
    """Trigger an MLFQ priority boost — reset all processes to level 0."""
    assert kernel.scheduler is not None  # noqa: S101
    policy = kernel.scheduler.policy
    if not isinstance(policy, MLFQPolicy):
        msg = "Boost requires MLFQ policy"
        raise SyscallError(msg)
    policy.boost()
    return "MLFQ boost: all processes reset to level 0"


# -- Journal syscall handlers ------------------------------------------------


def _sys_journal_status(kernel: Any, **_kwargs: Any) -> dict[str, int]:
    """Return journal transaction status counts."""
    return kernel.journal_status()


def _sys_journal_checkpoint(kernel: Any, **_kwargs: Any) -> None:
    """Take a journal checkpoint."""
    kernel.journal_checkpoint()


def _sys_journal_recover(kernel: Any, **_kwargs: Any) -> dict[str, int]:
    """Recover from a crash by replaying committed transactions."""
    count = kernel.journal_recover()
    return {"replayed": count}


def _sys_journal_crash(kernel: Any, **_kwargs: Any) -> None:
    """Simulate a crash for educational purposes."""
    kernel.journal_crash()


# -- Ordering syscall handlers -----------------------------------------------


def _sys_check_ordering(kernel: Any, **_kwargs: Any) -> dict[str, Any]:
    """Return ordering status — mode, registered ranks, violations."""
    om = kernel.ordering_manager
    if om is None:
        msg = "Ordering manager not available"
        raise SyscallError(msg)
    return {
        "mode": str(om.mode),
        "enabled": om.enabled,
        "ranks": om.ranks(),
        "violations": len(om.violations()),
    }


def _sys_set_ordering_mode(kernel: Any, **kwargs: Any) -> str:
    """Set the ordering enforcement mode (strict/warn/off)."""
    om = kernel.ordering_manager
    if om is None:
        msg = "Ordering manager not available"
        raise SyscallError(msg)
    mode_str: str = kwargs["mode"]
    try:
        om.mode = OrderingMode(mode_str)
    except ValueError:
        msg = f"Unknown ordering mode: {mode_str}"
        raise SyscallError(msg) from None
    return f"Ordering mode set to {om.mode}"


def _sys_register_rank(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Register a resource with a rank in the ordering manager."""
    om = kernel.ordering_manager
    if om is None:
        msg = "Ordering manager not available"
        raise SyscallError(msg)
    name: str = kwargs["name"]
    rank: int | None = kwargs.get("rank")
    assigned = om.register(name, rank=rank)
    return {"name": name, "rank": assigned}


# -- Shared memory syscall handlers -----------------------------------------


def _sys_shm_create(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Create a named shared memory segment."""
    name: str = kwargs["name"]
    size: int = kwargs["size"]
    pid: int = kwargs["pid"]
    try:
        seg = kernel.shm_create(name=name, size=size, pid=pid)
    except SharedMemoryError as e:
        raise SyscallError(str(e)) from e
    return {"name": seg.name, "size": seg.size, "num_pages": seg.num_pages}


def _sys_shm_attach(kernel: Any, **kwargs: Any) -> dict[str, int]:
    """Attach a process to a shared memory segment."""
    name: str = kwargs["name"]
    pid: int = kwargs["pid"]
    try:
        address = kernel.shm_attach(name=name, pid=pid)
    except SharedMemoryError as e:
        raise SyscallError(str(e)) from e
    return {"virtual_address": address}


def _sys_shm_detach(kernel: Any, **kwargs: Any) -> None:
    """Detach a process from a shared memory segment."""
    try:
        kernel.shm_detach(name=kwargs["name"], pid=kwargs["pid"])
    except SharedMemoryError as e:
        raise SyscallError(str(e)) from e


def _sys_shm_destroy(kernel: Any, **kwargs: Any) -> None:
    """Destroy a shared memory segment."""
    try:
        kernel.shm_destroy(name=kwargs["name"])
    except SharedMemoryError as e:
        raise SyscallError(str(e)) from e


def _sys_shm_write(kernel: Any, **kwargs: Any) -> None:
    """Write data to a shared memory segment."""
    name: str = kwargs["name"]
    pid: int = kwargs["pid"]
    data: bytes = kwargs["data"]
    offset: int = kwargs.get("offset", 0)
    try:
        kernel.shm_write(name=name, pid=pid, data=data, offset=offset)
    except SharedMemoryError as e:
        raise SyscallError(str(e)) from e


def _sys_shm_read(kernel: Any, **kwargs: Any) -> dict[str, object]:
    """Read data from a shared memory segment."""
    name: str = kwargs["name"]
    pid: int = kwargs["pid"]
    offset: int = kwargs.get("offset", 0)
    size: int | None = kwargs.get("size")
    try:
        data = kernel.shm_read(name=name, pid=pid, offset=offset, size=size)
    except SharedMemoryError as e:
        raise SyscallError(str(e)) from e
    return {"data": data, "count": len(data)}


def _sys_shm_list(kernel: Any, **_kwargs: Any) -> list[dict[str, object]]:
    """List all shared memory segments."""
    return kernel.shm_list()


# -- DNS syscall handlers ---------------------------------------------------


def _sys_dns_register(kernel: Any, **kwargs: Any) -> dict[str, str]:
    """Register a DNS A record."""
    hostname: str = kwargs["hostname"]
    address: str = kwargs["address"]
    try:
        record = kernel.dns_register(hostname, address)
    except DnsError as e:
        raise SyscallError(str(e)) from e
    return {"hostname": record.hostname, "address": record.address}


def _sys_dns_lookup(kernel: Any, **kwargs: Any) -> str:
    """Look up a hostname via DNS."""
    hostname: str = kwargs["hostname"]
    try:
        return kernel.dns_lookup(hostname)
    except DnsError as e:
        raise SyscallError(str(e)) from e


def _sys_dns_remove(kernel: Any, **kwargs: Any) -> None:
    """Remove a DNS record."""
    hostname: str = kwargs["hostname"]
    try:
        kernel.dns_remove(hostname)
    except DnsError as e:
        raise SyscallError(str(e)) from e


def _sys_dns_list(kernel: Any, **_kwargs: Any) -> list[dict[str, str]]:
    """List all DNS records."""
    return kernel.dns_list()


def _sys_dns_flush(kernel: Any, **_kwargs: Any) -> int:
    """Flush all DNS records."""
    return kernel.dns_flush()


# -- Socket syscall handlers ------------------------------------------------


def _sys_socket_create(kernel: Any, **_kwargs: Any) -> dict[str, int | str]:
    """Create a new socket."""
    try:
        return kernel.socket_create()
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_bind(kernel: Any, **kwargs: Any) -> None:
    """Bind a socket to an address and port."""
    try:
        kernel.socket_bind(kwargs["sock_id"], kwargs["address"], kwargs["port"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_listen(kernel: Any, **kwargs: Any) -> None:
    """Mark a socket as listening."""
    try:
        kernel.socket_listen(kwargs["sock_id"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_connect(kernel: Any, **kwargs: Any) -> None:
    """Connect a socket to a listener."""
    try:
        kernel.socket_connect(kwargs["sock_id"], kwargs["address"], kwargs["port"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_accept(kernel: Any, **kwargs: Any) -> dict[str, int | str] | None:
    """Accept a pending connection."""
    try:
        return kernel.socket_accept(kwargs["sock_id"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_send(kernel: Any, **kwargs: Any) -> None:
    """Send data over a socket."""
    try:
        kernel.socket_send(kwargs["sock_id"], kwargs["data"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_recv(kernel: Any, **kwargs: Any) -> bytes:
    """Receive data from a socket."""
    try:
        return kernel.socket_recv(kwargs["sock_id"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_close(kernel: Any, **kwargs: Any) -> None:
    """Close a socket."""
    try:
        kernel.socket_close(kwargs["sock_id"])
    except SocketError as e:
        raise SyscallError(str(e)) from e


def _sys_socket_list(kernel: Any, **_kwargs: Any) -> list[dict[str, object]]:
    """List all sockets."""
    return kernel.socket_list()


# -- /proc virtual filesystem syscall handlers --------------------------------


def _sys_proc_read(kernel: Any, **kwargs: Any) -> str:
    """Read a virtual /proc file."""
    try:
        return kernel.proc_read(kwargs["path"])
    except ValueError as e:
        raise SyscallError(str(e)) from e


def _sys_proc_list(kernel: Any, **kwargs: Any) -> list[str]:
    """List a virtual /proc directory."""
    try:
        return kernel.proc_list(kwargs["path"])
    except ValueError as e:
        raise SyscallError(str(e)) from e


# -- Performance metrics syscall handler -------------------------------------


def _sys_perf_metrics(kernel: Any, **_kwargs: Any) -> dict[str, float | int]:
    """Read aggregate performance metrics."""
    try:
        return kernel.perf_metrics()
    except (ValueError, RuntimeError) as e:
        raise SyscallError(str(e)) from e


# -- Strace syscall handlers ------------------------------------------------


def _sys_strace_enable(kernel: Any, **_kwargs: Any) -> None:
    """Enable syscall tracing."""
    kernel.strace_enable()


def _sys_strace_disable(kernel: Any, **_kwargs: Any) -> None:
    """Disable syscall tracing."""
    kernel.strace_disable()


def _sys_strace_log(kernel: Any, **_kwargs: Any) -> list[str]:
    """Return the current strace log entries."""
    return kernel.strace_log()


def _sys_strace_clear(kernel: Any, **_kwargs: Any) -> None:
    """Clear the strace log and reset the sequence counter."""
    kernel.strace_clear()


# -- Kernel-mode enforcement syscall handlers --------------------------------


def _sys_shutdown(kernel: Any, **_kwargs: Any) -> None:
    """Shut down the kernel."""
    kernel.shutdown()


def _sys_scheduler_info(kernel: Any, **_kwargs: Any) -> dict[str, str]:
    """Return scheduler policy name and parameters."""
    assert kernel.scheduler is not None  # noqa: S101
    policy = kernel.scheduler.policy
    match policy:
        case FCFSPolicy():
            label = "FCFS"
        case RoundRobinPolicy():
            label = f"Round Robin (quantum={policy.quantum})"
        case PriorityPolicy():
            label = "Priority"
        case AgingPriorityPolicy():
            label = f"Aging Priority (boost={policy.aging_boost}, max_age={policy.max_age})"
        case MLFQPolicy():
            label = f"MLFQ ({policy.num_levels} levels, quanta={list(policy.quantums)})"
        case CFSPolicy():
            label = f"CFS (base_slice={policy.base_slice})"
        case _:
            label = type(policy).__name__
    return {"policy": label}


def _sys_lstat(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Return file metadata without following symlinks."""
    assert kernel.filesystem is not None  # noqa: S101
    path: str = kwargs["path"]
    try:
        info = kernel.filesystem.lstat(path)
    except FileNotFoundError as e:
        raise SyscallError(str(e)) from e
    result: dict[str, Any] = {
        "inode_number": info.inode_number,
        "file_type": str(info.file_type),
        "size": info.size,
        "link_count": info.link_count,
    }
    if str(info.file_type) == "symlink":
        with contextlib.suppress(FileNotFoundError, OSError):
            result["target"] = kernel.filesystem.readlink(path)
    return result


def _sys_list_mutexes(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """List all mutexes with their state."""
    sm = kernel.sync_manager
    if sm is None:
        return []
    result: list[dict[str, Any]] = []
    for name in sorted(sm.list_mutexes()):
        mutex = sm.get_mutex(name)
        result.append(
            {
                "name": name,
                "locked": mutex.is_locked,
                "owner": mutex.owner,
            }
        )
    return result


def _sys_list_semaphores(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """List all semaphores with their counts."""
    sm = kernel.sync_manager
    if sm is None:
        return []
    result: list[dict[str, Any]] = []
    for name in sorted(sm.list_semaphores()):
        sem = sm.get_semaphore(name)
        result.append({"name": name, "count": sem.count})
    return result


def _sys_list_rwlocks(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """List all reader-writer locks with their state."""
    sm = kernel.sync_manager
    if sm is None:
        return []
    result: list[dict[str, Any]] = []
    for name in sorted(sm.list_rwlocks()):
        rwl = sm.get_rwlock(name)
        result.append(
            {
                "name": name,
                "reader_count": rwl.reader_count,
                "writer_tid": rwl.writer_tid,
                "wait_queue_size": rwl.wait_queue_size,
            }
        )
    return result


def _sys_list_fds(kernel: Any, **kwargs: Any) -> list[dict[str, Any]]:
    """List open file descriptors for a process."""
    pid: int = kwargs["pid"]
    fds = kernel.list_fds(pid)
    return [
        {"fd": fd_num, "path": ofd.path, "mode": str(ofd.mode), "offset": ofd.offset}
        for fd_num, ofd in sorted(fds.items())
    ]


def _sys_list_resources(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """List resources and their availability."""
    rm = kernel.resource_manager
    if rm is None:
        return []
    return [{"name": r, "available": rm.available(r)} for r in rm.resources()]


def _sys_pi_status(kernel: Any, **_kwargs: Any) -> dict[str, Any]:
    """Return priority inheritance status and boosted processes."""
    pi_mgr = kernel.pi_manager
    if pi_mgr is None:
        return {"enabled": False, "boosted": []}
    boosted: list[dict[str, Any]] = []
    for pid, proc in kernel.processes.items():
        if proc.effective_priority != proc.priority:
            boosted.append(
                {
                    "pid": pid,
                    "name": proc.name,
                    "base_priority": proc.priority,
                    "effective_priority": proc.effective_priority,
                }
            )
    return {"enabled": pi_mgr.enabled, "boosted": boosted}


def _sys_ordering_violations(kernel: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """Return ordering violations."""
    om = kernel.ordering_manager
    if om is None:
        return []
    return [
        {
            "resource_requested": v.resource_requested,
            "requested_rank": v.requested_rank,
            "max_held_rank": v.max_held_rank,
            "pid": v.pid,
        }
        for v in om.violations()
    ]


def _sys_destroy_mutex(kernel: Any, **kwargs: Any) -> None:
    """Destroy a named mutex."""
    name: str = kwargs["name"]
    sm = kernel.sync_manager
    if sm is None:
        msg = "Sync manager not available"
        raise SyscallError(msg)
    try:
        sm.destroy_mutex(name)
    except KeyError as e:
        raise SyscallError(str(e)) from e


def _sys_dispatch(kernel: Any, **_kwargs: Any) -> dict[str, Any] | None:
    """Dispatch the next process from the scheduler."""
    assert kernel.scheduler is not None  # noqa: S101
    process = kernel.scheduler.dispatch()
    if process is None:
        return None
    return {
        "pid": process.pid,
        "name": process.name,
        "state": str(process.state),
    }


def _sys_process_info(kernel: Any, **kwargs: Any) -> dict[str, Any]:
    """Return detailed info about a single process."""
    pid: int = kwargs["pid"]
    processes = kernel.processes
    if pid not in processes:
        msg = f"Process {pid} not found"
        raise SyscallError(msg)
    proc = processes[pid]
    return {
        "pid": proc.pid,
        "name": proc.name,
        "state": str(proc.state),
        "priority": proc.priority,
        "effective_priority": proc.effective_priority,
        "main_tid": proc.main_thread.tid,
    }


def _sys_strace_status(kernel: Any, **_kwargs: Any) -> dict[str, bool]:
    """Return whether strace is enabled."""
    return {"enabled": kernel.strace_enabled}
