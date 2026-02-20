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
    process = kernel.create_process(name=name, num_pages=num_pages)
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
    return [{"pid": p.pid, "name": p.name, "state": p.state} for p in kernel.processes.values()]


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
