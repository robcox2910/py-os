"""Shell basics commands -- the everyday helpers: help, variables, echo, history, aliases and scripts."""

from py_os.shell.base import ShellBase
from py_os.syscalls import SyscallError, SyscallNumber


class BasicCommands(ShellBase):
    """Shell commands for the everyday helpers: help, variables, echo, history, aliases and scripts."""

    def _cmd_help(self, _args: list[str]) -> str:
        """List available commands."""
        return "Available commands: " + ", ".join(sorted(self._commands))

    def _cmd_env(self, _args: list[str]) -> str:
        """List all environment variables."""
        items: list[tuple[str, str]] = self._kernel.syscall(SyscallNumber.SYS_LIST_ENV)
        return "\n".join(f"{k}={v}" for k, v in sorted(items)) if items else "No variables set."

    def _cmd_export(self, args: list[str]) -> str:
        """Set an environment variable (KEY=VALUE)."""
        if not args:
            return "Usage: export KEY=VALUE"
        pair = args[0]
        if "=" not in pair:
            return "Usage: export KEY=VALUE"
        key, value = pair.split("=", 1)
        self._kernel.syscall(SyscallNumber.SYS_SET_ENV, key=key, value=value)
        return ""

    def _cmd_unset(self, args: list[str]) -> str:
        """Remove an environment variable."""
        if not args:
            return "Usage: unset KEY"
        try:
            self._kernel.syscall(SyscallNumber.SYS_DELETE_ENV, key=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_log(self, _args: list[str]) -> str:
        """Show recent log entries."""
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_READ_LOG)
        return "\n".join(entries) if entries else "No log entries."

    def _cmd_exit(self, _args: list[str]) -> str:
        """Shut down the kernel and signal the REPL to stop."""
        self._kernel.syscall(SyscallNumber.SYS_SHUTDOWN)
        return self.EXIT_SENTINEL

    def _cmd_history(self, _args: list[str]) -> str:
        """Show command history."""
        if not self._history:
            return "No history."
        lines = [f"  {i + 1}  {cmd}" for i, cmd in enumerate(self._history)]
        return "\n".join(lines)

    def _cmd_alias(self, args: list[str]) -> str:
        """Create or list command aliases."""
        if not args:
            if not self._aliases:
                return "No aliases defined."
            return "\n".join(f"{name}={cmd}" for name, cmd in sorted(self._aliases.items()))
        pair = " ".join(args)
        if "=" not in pair:
            return "Usage: alias NAME=COMMAND"
        name, cmd = pair.split("=", 1)
        self._aliases[name.strip()] = cmd.strip()
        return ""

    def _cmd_unalias(self, args: list[str]) -> str:
        """Remove a command alias."""
        if not args:
            return "Usage: unalias <name>"
        self._aliases.pop(args[0], None)
        return ""

    def _cmd_echo(self, args: list[str]) -> str:
        """Echo arguments back as output."""
        return " ".join(args)

    def _cmd_source(self, args: list[str]) -> str:
        """Load and execute a script from a file."""
        if not args:
            return "Usage: source <path>"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=args[0])
            script = data.decode()
        except SyscallError as e:
            return f"Error: {e}"
        results = self.run_script(script)
        return "\n".join(r for r in results if r)

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("help", _cmd_help),
        ("exit", _cmd_exit),
        ("log", _cmd_log),
        ("env", _cmd_env),
        ("export", _cmd_export),
        ("unset", _cmd_unset),
        ("echo", _cmd_echo),
        ("source", _cmd_source),
        ("history", _cmd_history),
        ("alias", _cmd_alias),
        ("unalias", _cmd_unalias),
    )
