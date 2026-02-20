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

from py_os.jobs import JobManager
from py_os.kernel import Kernel, KernelState
from py_os.signals import Signal
from py_os.syscalls import SyscallError, SyscallNumber

# Type alias for a command handler: takes a list of args, returns output.
type _Handler = Callable[[list[str]], str]


class Shell:
    """Command interpreter that operates on a booted kernel.

    The shell requires a running kernel — it makes no sense to interpret
    commands when subsystems aren't available.  The constructor enforces
    this invariant.
    """

    EXIT_SENTINEL = "__EXIT__"

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
        self._pipe_input: str = ""
        self._jobs = JobManager()
        self._history: list[str] = []
        self._aliases: dict[str, str] = {}

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
            "exit": self._cmd_exit,
            "log": self._cmd_log,
            "signal": self._cmd_signal,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "unset": self._cmd_unset,
            "top": self._cmd_top,
            "grep": self._cmd_grep,
            "wc": self._cmd_wc,
            "jobs": self._cmd_jobs,
            "bg": self._cmd_bg,
            "fg": self._cmd_fg,
            "history": self._cmd_history,
            "alias": self._cmd_alias,
            "unalias": self._cmd_unalias,
            "fork": self._cmd_fork,
            "pstree": self._cmd_pstree,
            "devices": self._cmd_devices,
            "devread": self._cmd_devread,
            "devwrite": self._cmd_devwrite,
        }

    def execute(self, command: str) -> str:
        """Parse and execute a shell command, with pipe support.

        Commands can be chained with ``|``.  The output of each stage
        becomes the piped input for the next.  For example::

            ls / | grep txt | wc

        Args:
            command: The raw command string (e.g. "ls / | grep txt").

        Returns:
            The command output as a string, or an error message.

        """
        # Record in history
        stripped = command.strip()
        if stripped:
            self._history.append(stripped)

        # Expand aliases in each pipeline stage
        stages = [s.strip() for s in command.split("|")]
        output = ""
        for i, stage in enumerate(stages):
            self._pipe_input = output if i > 0 else ""
            expanded = self._expand_alias(stage)
            output = self._execute_single(expanded)
            # Stop the pipeline if a command produces an error
            if output.startswith(("Unknown command:", "Error:")):
                break
        self._pipe_input = ""
        return output

    def _expand_alias(self, command: str) -> str:
        """Expand an alias if the first word matches."""
        parts = command.strip().split()
        if parts and parts[0] in self._aliases:
            return self._aliases[parts[0]]
        return command

    def _execute_single(self, command: str) -> str:
        """Execute a single (non-piped) command."""
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

    def _cmd_signal(self, args: list[str]) -> str:
        """Send a signal to a process."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: signal <pid> <SIGNAL>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            sig = Signal[args[1]]
        except KeyError:
            return f"Error: unknown signal '{args[1]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SEND_SIGNAL, pid=pid, signal=sig)
        except SyscallError as e:
            return f"Error: {e}"
        return f"Signal {sig.name} delivered to pid {pid}."

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

    def _cmd_top(self, _args: list[str]) -> str:
        """Show system status dashboard."""
        info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SYSINFO)
        uptime = float(str(info["uptime"]))
        lines = [
            "=== PyOS System Monitor ===",
            f"Uptime:      {uptime:.2f}s",
            f"Memory:      {info['memory_free']}/{info['memory_total']} frames free",
            f"Processes:   {info['process_count']}",
            f"Devices:     {info['device_count']}",
            f"User:        {info['current_user']}",
            f"Env vars:    {info['env_count']}",
            f"Log entries: {info['log_count']}",
        ]
        return "\n".join(lines)

    def _cmd_grep(self, args: list[str]) -> str:
        """Filter piped input lines matching a pattern."""
        if not args:
            return "Usage: grep <pattern>"
        pattern = args[0]
        lines = self._pipe_input.splitlines() if self._pipe_input else []
        matched = [line for line in lines if pattern in line]
        return "\n".join(matched)

    def _cmd_wc(self, _args: list[str]) -> str:
        """Count lines in piped input."""
        if not self._pipe_input:
            return "Usage: wc (pipe input required)"
        lines = self._pipe_input.splitlines()
        return f"{len(lines)} lines"

    def _cmd_jobs(self, _args: list[str]) -> str:
        """List background jobs."""
        jobs = self._jobs.list_jobs()
        if not jobs:
            return "No background jobs."
        return "\n".join(str(j) for j in jobs)

    def _cmd_bg(self, args: list[str]) -> str:
        """Add a process as a background job."""
        if not args:
            return "Usage: bg <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        # Verify the process exists
        procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        proc = next((p for p in procs if p["pid"] == pid), None)
        if proc is None:
            return f"Error: process {pid} not found"
        name = str(proc["name"])
        job = self._jobs.add(pid=pid, name=name)
        return str(job)

    def _cmd_fg(self, args: list[str]) -> str:
        """Bring a background job to the foreground."""
        if not args:
            return "Usage: fg <job_id>"
        try:
            job_id = int(args[0])
        except ValueError:
            return f"Error: invalid job id '{args[0]}'"
        job = self._jobs.get(job_id)
        if job is None:
            return f"Error: job {job_id} not found"
        self._jobs.remove(job_id)
        return f"{job.name} (pid={job.pid}) moved to foreground."

    def _cmd_log(self, _args: list[str]) -> str:
        """Show recent log entries."""
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_READ_LOG)
        return "\n".join(entries) if entries else "No log entries."

    def _cmd_exit(self, _args: list[str]) -> str:
        """Shut down the kernel and signal the REPL to stop."""
        self._kernel.shutdown()
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

    def _cmd_fork(self, args: list[str]) -> str:
        """Fork a process, creating a child copy."""
        if not args:
            return "Usage: fork <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_FORK, parent_pid=pid)
            return f"Forked pid {pid} → child pid {result['child_pid']} ({result['name']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_pstree(self, _args: list[str]) -> str:
        """Show the process tree (parent-child hierarchy)."""
        procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        if not procs:
            return "No processes."
        # Build parent → children mapping
        by_pid: dict[int, dict[str, object]] = {int(str(p["pid"])): p for p in procs}
        children: dict[int | None, list[int]] = {}
        for p in procs:
            parent_pid = p["parent_pid"]
            parent_key: int | None = int(str(parent_pid)) if parent_pid is not None else None
            children.setdefault(parent_key, []).append(int(str(p["pid"])))

        lines: list[str] = []

        def _walk(pid: int, prefix: str, *, is_last: bool) -> None:
            proc = by_pid[pid]
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{proc['name']} (pid={pid})")
            kids = children.get(pid, [])
            for i, child_pid in enumerate(kids):
                extension = "    " if is_last else "│   "
                _walk(child_pid, prefix + extension, is_last=i == len(kids) - 1)

        # Start from root processes (no parent)
        roots = children.get(None, [])
        for i, root_pid in enumerate(roots):
            _walk(root_pid, "", is_last=i == len(roots) - 1)

        return "\n".join(lines) if lines else "No processes."

    def _cmd_devices(self, _args: list[str]) -> str:
        """List all registered devices."""
        names: list[str] = self._kernel.syscall(SyscallNumber.SYS_LIST_DEVICES)
        return "\n".join(names) if names else "No devices registered."

    def _cmd_devread(self, args: list[str]) -> str:
        """Read from a device."""
        if not args:
            return "Usage: devread <device>"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_DEVICE_READ, device=args[0])
            return data.decode() if data else "(empty)"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_devwrite(self, args: list[str]) -> str:
        """Write to a device."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: devwrite <device> <data...>"
        device = args[0]
        data = " ".join(args[1:])
        try:
            self._kernel.syscall(SyscallNumber.SYS_DEVICE_WRITE, device=device, data=data.encode())
        except SyscallError as e:
            return f"Error: {e}"
        return ""
