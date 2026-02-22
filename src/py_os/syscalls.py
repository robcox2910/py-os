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

from enum import IntEnum
from typing import Any

from py_os.process.scheduler import (
    AgingPriorityPolicy,
    CFSPolicy,
    FCFSPolicy,
    MLFQPolicy,
    PriorityPolicy,
    RoundRobinPolicy,
)
from py_os.process.signals import SignalError
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

    # Memory operations
    SYS_MEMORY_INFO = 20

    # User operations
    SYS_WHOAMI = 30
    SYS_CREATE_USER = 31
    SYS_LIST_USERS = 32
    SYS_SWITCH_USER = 33

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

    # Scheduler operations
    SYS_SET_SCHEDULER = 120
    SYS_SCHEDULER_BOOST = 121


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
        SyscallNumber.SYS_MEMORY_INFO: _sys_memory_info,
        SyscallNumber.SYS_WHOAMI: _sys_whoami,
        SyscallNumber.SYS_CREATE_USER: _sys_create_user,
        SyscallNumber.SYS_LIST_USERS: _sys_list_users,
        SyscallNumber.SYS_SWITCH_USER: _sys_switch_user,
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
        SyscallNumber.SYS_SET_SCHEDULER: _sys_set_scheduler,
        SyscallNumber.SYS_SCHEDULER_BOOST: _sys_scheduler_boost,
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


# -- Memory syscall handlers -------------------------------------------------


def _sys_memory_info(kernel: Any, **_kwargs: Any) -> dict[str, int]:
    """Return memory statistics."""
    assert kernel.memory is not None  # noqa: S101
    return {
        "total_frames": kernel.memory.total_frames,
        "free_frames": kernel.memory.free_frames,
    }


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
    try:
        acquired = kernel.acquire_mutex(name, tid=tid)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    if acquired:
        return f"mutex '{name}' acquired by thread {tid}"
    return f"thread {tid} queued for mutex '{name}'"


def _sys_release_mutex(kernel: Any, **kwargs: Any) -> str:
    """Release a named mutex."""
    name: str = kwargs["name"]
    tid: int = kwargs["tid"]
    try:
        kernel.release_mutex(name, tid=tid)
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
    try:
        acquired = kernel.acquire_semaphore(name, tid=tid)
    except KeyError as e:
        raise SyscallError(str(e)) from e
    if acquired:
        return f"semaphore '{name}' acquired by thread {tid}"
    return f"thread {tid} queued for semaphore '{name}'"


def _sys_release_semaphore(kernel: Any, **kwargs: Any) -> str:
    """Release a named semaphore."""
    name: str = kwargs["name"]
    try:
        kernel.release_semaphore(name)
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
