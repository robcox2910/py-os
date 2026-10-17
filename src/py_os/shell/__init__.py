"""The shell — command interpreter for the operating system.

The shell is the user's interface to the kernel.  It reads a command
string, parses it into a command name and arguments, dispatches to the
appropriate handler, and returns a string result.

In a real OS the shell is a user-space process that communicates with
the kernel exclusively through **system calls**.  Our shell mirrors
this: every command handler invokes ``kernel.syscall()`` rather than
reaching directly into kernel subsystems.

Design choices:
    - **Returns strings, not prints.**  This keeps the shell fully
      testable and separates concerns (the caller decides how to
      display output).
    - **Command dispatch via a dict.**  Clean, extensible, O(1) lookup.
      Each topic (files, processes, memory, ...) lives in its own module
      under ``py_os.shell.commands`` with a small ``COMMANDS`` table;
      the shell builds its dispatch dict from those tables.
    - **All kernel interaction goes through syscalls.**  The shell
      never touches ``kernel.filesystem``, ``kernel.memory``, or
      ``kernel.scheduler`` directly — it uses the official gateway.
"""

from py_os.shell.base import MAX_LOOP_ITERATIONS, Redirections, ShellBase
from py_os.shell.commands import (
    BasicCommands,
    DeviceCommands,
    FileCommands,
    IsolationCommands,
    LearnCommands,
    MemoryCommands,
    NetworkCommands,
    ProcessCommands,
    SyncCommands,
    UserCommands,
)


class Shell(
    BasicCommands,
    FileCommands,
    UserCommands,
    ProcessCommands,
    MemoryCommands,
    SyncCommands,
    DeviceCommands,
    NetworkCommands,
    IsolationCommands,
    LearnCommands,
    ShellBase,
):
    """Command interpreter that operates on a booted kernel.

    The shell requires a running kernel — it makes no sense to interpret
    commands when subsystems aren't available.  The constructor enforces
    this invariant.

    Each command group (files, processes, memory, ...) is a separate
    class in ``py_os.shell.commands``; ``Shell`` simply combines them all.
    """


__all__ = ["MAX_LOOP_ITERATIONS", "Redirections", "Shell", "ShellBase"]
