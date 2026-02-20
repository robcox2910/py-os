"""The shell — command interpreter for the operating system.

The shell is the user's interface to the kernel.  It reads a command
string, parses it into a command name and arguments, dispatches to the
appropriate handler, and returns a string result.

In a real OS the shell is itself a user-space process, but here we keep
it simple: the shell holds a reference to a **booted** kernel and calls
its subsystems directly.  Every command handler is a pure function of
its arguments and the kernel state, returning a string — making the
shell trivially testable without any I/O.

Design choices:
    - **Returns strings, not prints.**  This keeps the shell fully
      testable and separates concerns (the caller decides how to
      display output).
    - **Command dispatch via a dict.**  Clean, extensible, O(1) lookup.
      Adding a new command means writing a method and adding one dict
      entry — no cascading if/elif chains.
    - **All commands are methods on Shell.**  Keeps related state
      (the kernel reference) close and avoids a separate "commands"
      module for a handful of functions.
"""

from collections.abc import Callable

from py_os.kernel import Kernel, KernelState

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
        lines = ["PID    STATE       NAME"]
        lines.extend(
            f"{p.pid:<6} {p.state.value:<11} {p.name}" for p in self._kernel.processes.values()
        )
        return "\n".join(lines)

    def _cmd_ls(self, args: list[str]) -> str:
        """List directory contents."""
        path = args[0] if args else "/"
        fs = self._kernel.filesystem
        assert fs is not None  # noqa: S101

        try:
            entries = fs.list_dir(path)
        except FileNotFoundError as e:
            return f"Error: {e}"

        return "\n".join(entries) if entries else ""

    def _cmd_mkdir(self, args: list[str]) -> str:
        """Create a directory."""
        if not args:
            return "Usage: mkdir <path>"

        fs = self._kernel.filesystem
        assert fs is not None  # noqa: S101

        try:
            fs.create_dir(args[0])
        except (FileNotFoundError, FileExistsError) as e:
            return f"Error: {e}"
        return ""

    def _cmd_touch(self, args: list[str]) -> str:
        """Create an empty file."""
        if not args:
            return "Usage: touch <path>"

        fs = self._kernel.filesystem
        assert fs is not None  # noqa: S101

        try:
            fs.create_file(args[0])
        except (FileNotFoundError, FileExistsError) as e:
            return f"Error: {e}"
        return ""

    def _cmd_write(self, args: list[str]) -> str:
        """Write content to a file."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: write <path> <content...>"

        path = args[0]
        content = " ".join(args[1:])
        fs = self._kernel.filesystem
        assert fs is not None  # noqa: S101

        try:
            fs.write(path, content.encode())
        except FileNotFoundError as e:
            return f"Error: {e}"
        return ""

    def _cmd_cat(self, args: list[str]) -> str:
        """Read file contents."""
        if not args:
            return "Usage: cat <path>"

        fs = self._kernel.filesystem
        assert fs is not None  # noqa: S101

        try:
            return fs.read(args[0]).decode()
        except FileNotFoundError as e:
            return f"Error: not found — {e}"

    def _cmd_rm(self, args: list[str]) -> str:
        """Remove a file or directory."""
        if not args:
            return "Usage: rm <path>"

        fs = self._kernel.filesystem
        assert fs is not None  # noqa: S101

        try:
            fs.delete(args[0])
        except FileNotFoundError as e:
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
            self._kernel.terminate_process(pid=pid)
        except (RuntimeError, KeyError) as e:
            return f"Error: {e}"
        return f"Process {pid} terminated."
