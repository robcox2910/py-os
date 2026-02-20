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
    """Create a file."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        kernel.filesystem.create_file(kwargs["path"])
    except (FileNotFoundError, FileExistsError) as e:
        raise SyscallError(str(e)) from e


def _sys_create_dir(kernel: Any, **kwargs: Any) -> None:
    """Create a directory."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        kernel.filesystem.create_dir(kwargs["path"])
    except (FileNotFoundError, FileExistsError) as e:
        raise SyscallError(str(e)) from e


def _sys_read_file(kernel: Any, **kwargs: Any) -> bytes:
    """Read file contents."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        return kernel.filesystem.read(kwargs["path"])
    except FileNotFoundError as e:
        msg = f"File not found: {kwargs['path']}"
        raise SyscallError(msg) from e


def _sys_write_file(kernel: Any, **kwargs: Any) -> None:
    """Write data to a file."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        kernel.filesystem.write(kwargs["path"], kwargs["data"])
    except FileNotFoundError as e:
        raise SyscallError(str(e)) from e


def _sys_delete_file(kernel: Any, **kwargs: Any) -> None:
    """Delete a file or directory."""
    assert kernel.filesystem is not None  # noqa: S101
    try:
        kernel.filesystem.delete(kwargs["path"])
    except FileNotFoundError as e:
        raise SyscallError(str(e)) from e


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
