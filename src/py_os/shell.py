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
      Adding a new command means writing a method and adding one dict
      entry — no cascading if/elif chains.
    - **All kernel interaction goes through syscalls.**  The shell
      never touches ``kernel.filesystem``, ``kernel.memory``, or
      ``kernel.scheduler`` directly — it uses the official gateway.
"""

from collections.abc import Callable

from py_os.kernel import Kernel, KernelState
from py_os.syscalls import SyscallError, SyscallNumber

# Type alias for a command handler: takes a list of args, returns output.
type _Handler = Callable[[list[str]], str]


class Shell:
    """Command interpreter that operates on a booted kernel.

    The shell requires a running kernel — it makes no sense to interpret
    commands when subsystems aren't available.  The constructor enforces
    this invariant.
    """

    def __init__(self, *, kernel: Kernel) -> None:
        """Create a shell attached to a running kernel.

        Args:
            kernel: A booted kernel instance.

        Raises:
            RuntimeError: If the kernel is not in the RUNNING state.

        """
        if kernel.state is not KernelState.RUNNING:
            msg = f"Shell requires a running kernel (state: {kernel.state}, not running)"
            raise RuntimeError(msg)

        self._kernel = kernel

        # Command dispatch table — maps command names to handler methods.
        self._commands: dict[str, _Handler] = {
            "help": self._cmd_help,
            "ps": self._cmd_ps,
            "ls": self._cmd_ls,
            "mkdir": self._cmd_mkdir,
            "touch": self._cmd_touch,
            "write": self._cmd_write,
            "cat": self._cmd_cat,
            "rm": self._cmd_rm,
            "kill": self._cmd_kill,
            "whoami": self._cmd_whoami,
            "adduser": self._cmd_adduser,
            "su": self._cmd_su,
        }

    def execute(self, command: str) -> str:
        """Parse and execute a shell command.

        Args:
            command: The raw command string (e.g. "ls /docs").

        Returns:
            The command output as a string, or an error message.

        """
        parts = command.strip().split()
        if not parts:
            return ""

        name = parts[0]
        args = parts[1:]

        handler = self._commands.get(name)
        if handler is None:
            return f"Unknown command: {name}"

        return handler(args)

    # -- Command handlers ------------------------------------------------

    def _cmd_help(self, _args: list[str]) -> str:
        """List available commands."""
        return "Available commands: " + ", ".join(sorted(self._commands))

    def _cmd_ps(self, _args: list[str]) -> str:
        """Show running processes."""
        procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        lines = ["PID    STATE       NAME"]
        lines.extend(f"{p['pid']:<6} {p['state']!s:<11} {p['name']}" for p in procs)
        return "\n".join(lines)

    def _cmd_ls(self, args: list[str]) -> str:
        """List directory contents."""
        path = args[0] if args else "/"
        try:
            entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path=path)
        except SyscallError as e:
            return f"Error: {e}"
        return "\n".join(entries) if entries else ""

    def _cmd_mkdir(self, args: list[str]) -> str:
        """Create a directory."""
        if not args:
            return "Usage: mkdir <path>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_touch(self, args: list[str]) -> str:
        """Create an empty file."""
        if not args:
            return "Usage: touch <path>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_write(self, args: list[str]) -> str:
        """Write content to a file."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: write <path> <content...>"

        path = args[0]
        content = " ".join(args[1:])
        try:
            self._kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path=path, data=content.encode())
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_cat(self, args: list[str]) -> str:
        """Read file contents."""
        if not args:
            return "Usage: cat <path>"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=args[0])
            return data.decode()
        except SyscallError as e:
            return f"Error: not found — {e}"

    def _cmd_rm(self, args: list[str]) -> str:
        """Remove a file or directory."""
        if not args:
            return "Usage: rm <path>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_kill(self, args: list[str]) -> str:
        """Terminate a process by PID."""
        if not args:
            return "Usage: kill <pid>"

        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"

        try:
            self._kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=pid)
        except SyscallError as e:
            return f"Error: {e}"
        return f"Process {pid} terminated."

    def _cmd_whoami(self, _args: list[str]) -> str:
        """Show the current user."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_WHOAMI)
        return f"{result['username']} (uid={result['uid']})"

    def _cmd_adduser(self, args: list[str]) -> str:
        """Create a new user."""
        if not args:
            return "Usage: adduser <username>"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_USER, username=args[0]
            )
            return f"User '{result['username']}' created (uid={result['uid']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_su(self, args: list[str]) -> str:
        """Switch to another user by uid."""
        if not args:
            return "Usage: su <uid>"
        try:
            uid = int(args[0])
        except ValueError:
            return f"Error: invalid uid '{args[0]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=uid)
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_WHOAMI)
            return f"Switched to {result['username']} (uid={result['uid']})"
        except SyscallError as e:
            return f"Error: {e}"
