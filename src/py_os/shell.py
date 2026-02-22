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

import re
from collections.abc import Callable

from py_os.jobs import JobManager
from py_os.kernel import Kernel, KernelState
from py_os.process.scheduler import (
    AgingPriorityPolicy,
    CFSPolicy,
    FCFSPolicy,
    MLFQPolicy,
    PriorityPolicy,
    RoundRobinPolicy,
)
from py_os.process.signals import Signal
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
            "threads": self._cmd_threads,
            "resources": self._cmd_resources,
            "deadlock": self._cmd_deadlock,
            "devices": self._cmd_devices,
            "devread": self._cmd_devread,
            "devwrite": self._cmd_devwrite,
            "echo": self._cmd_echo,
            "source": self._cmd_source,
            "run": self._cmd_run,
            "scheduler": self._cmd_scheduler,
            "mutex": self._cmd_mutex,
            "semaphore": self._cmd_semaphore,
            "handle": self._cmd_handle,
            "wait": self._cmd_wait,
            "waitpid": self._cmd_waitpid,
            "mmap": self._cmd_mmap,
            "munmap": self._cmd_munmap,
            "msync": self._cmd_msync,
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

    def run_script(self, script: str) -> list[str]:
        """Execute a multi-line script, returning output from each command.

        Supports comments (``#``), variable substitution (``$VAR``),
        and conditionals (``if``/``then``/``else``/``fi``).

        In real shells, scripts are the foundation of system automation.
        Boot scripts, cron jobs, and ``.bashrc`` are all shell scripts.

        Args:
            script: Multi-line string of commands.

        Returns:
            List of output strings, one per executed command.

        """
        lines = script.splitlines()
        results: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            i += 1

            # Skip blanks and comments
            if not line or line.startswith("#"):
                continue

            # Handle if/then/else/fi blocks
            if line.startswith("if "):
                condition_cmd = self._expand_variables(line[3:])
                then_block: list[str] = []
                else_block: list[str] = []
                in_else = False
                # Collect lines until fi
                while i < len(lines):
                    block_line = lines[i].strip()
                    i += 1
                    if block_line == "fi":
                        break
                    if block_line == "then":
                        continue
                    if block_line == "else":
                        in_else = True
                        continue
                    if in_else:
                        else_block.append(block_line)
                    else:
                        then_block.append(block_line)

                # Evaluate condition: success = no error prefix
                cond_result = self.execute(condition_cmd)
                condition_passed = not cond_result.startswith("Error:")
                block = then_block if condition_passed else else_block
                for cmd in block:
                    expanded = self._expand_variables(cmd)
                    result = self.execute(expanded)
                    results.append(result)
                continue

            # Regular command — expand variables, then execute
            expanded = self._expand_variables(line)
            result = self.execute(expanded)
            results.append(result)

        return results

    def _expand_variables(self, command: str) -> str:
        """Replace $VAR references with environment variable values.

        In real shells, ``$HOME`` becomes ``/home/user``, ``$PATH``
        becomes the search path, etc.  Undefined variables expand
        to empty string (like bash with unset variables).
        """

        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            value = self._kernel.syscall(SyscallNumber.SYS_GET_ENV, key=var_name)
            return value if value is not None else ""

        return re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", _replace, command)

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

    def _cmd_threads(self, args: list[str]) -> str:
        """List threads of a process."""
        if not args:
            return "Usage: threads <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            threads: list[dict[str, object]] = self._kernel.syscall(
                SyscallNumber.SYS_LIST_THREADS, pid=pid
            )
        except SyscallError as e:
            return f"Error: {e}"
        lines = [f"Threads for pid {pid}:"]
        lines.extend(f"  TID {t['tid']:<4} {t['state']!s:<11} {t['name']}" for t in threads)
        return "\n".join(lines)

    def _cmd_resources(self, _args: list[str]) -> str:
        """Show resource allocation status."""
        rm = self._kernel.resource_manager
        if rm is None:
            return "Resource manager not available."
        resources = rm.resources()
        if not resources:
            return "No resources registered."
        lines = ["RESOURCE   AVAIL"]
        lines.extend(f"{r:<10} {rm.available(r)}" for r in resources)
        return "\n".join(lines)

    def _cmd_deadlock(self, _args: list[str]) -> str:
        """Run deadlock detection and report results."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_DETECT_DEADLOCK)
        deadlocked: set[int] = result["deadlocked"]  # type: ignore[assignment]
        if not deadlocked:
            return "No deadlock detected — system is safe."
        pids = sorted(deadlocked)
        return f"DEADLOCK detected! Stuck processes: {pids}"

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

    def _cmd_run(self, args: list[str]) -> str:
        """Create a process, load a built-in program, and run it."""
        if not args:
            return "Usage: run <program> [priority]"
        program_name = args[0]
        priority = 0
        if len(args) >= 2:  # noqa: PLR2004
            try:
                priority = int(args[1])
            except ValueError:
                return f"Error: invalid priority '{args[1]}'"
        programs: dict[str, Callable[[], str]] = {
            "hello": lambda: "Hello from PyOS!",
            "counter": lambda: "\n".join(str(i) for i in range(1, 6)),
        }
        program = programs.get(program_name)
        if program is None:
            return f"Unknown program: {program_name}"
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS,
                name=program_name,
                num_pages=1,
                priority=priority,
            )
            pid = result["pid"]
            self._kernel.syscall(SyscallNumber.SYS_EXEC, pid=pid, program=program)
            run_result = self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
            output = run_result["output"]
            exit_code = run_result["exit_code"]
            return f"{output}\n[exit code: {exit_code}]"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_scheduler(self, args: list[str]) -> str:
        """Show or switch the scheduling policy."""
        if not args:
            return self._cmd_scheduler_show()
        match args[0]:
            case "fcfs" | "rr" | "priority" | "aging":
                return self._cmd_scheduler_switch(args[0], args[1:])
            case "mlfq":
                return self._cmd_scheduler_mlfq(args[1:])
            case "cfs":
                return self._cmd_scheduler_cfs(args[1:])
            case "boost":
                return self._cmd_scheduler_boost()
            case _:
                return (
                    f"Error: unknown policy '{args[0]}'."
                    " Use fcfs, rr, priority, aging, mlfq, or cfs."
                )

    def _cmd_scheduler_show(self) -> str:
        """Display the current scheduling policy name."""
        scheduler = self._kernel.scheduler
        if scheduler is None:
            return "Scheduler not available."
        policy = scheduler.policy
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
                label = f"MLFQ ({policy.num_levels} levels, quanta={policy.quantums})"
            case CFSPolicy():
                label = f"CFS (base_slice={policy.base_slice})"
            case _:
                label = type(policy).__name__
        return f"Current policy: {label}"

    def _cmd_scheduler_switch(self, name: str, args: list[str]) -> str:
        """Switch the scheduling policy via syscall."""
        if name == "rr":
            if not args:
                return "Usage: scheduler rr <quantum>"
            try:
                quantum = int(args[0])
            except ValueError:
                return f"Error: invalid quantum '{args[0]}'"
            try:
                result: str = self._kernel.syscall(
                    SyscallNumber.SYS_SET_SCHEDULER,
                    policy=name,
                    quantum=quantum,
                )
            except SyscallError as e:
                return f"Error: {e}"
            return result
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                policy=name,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_scheduler_mlfq(self, args: list[str]) -> str:
        """Switch to MLFQ with optional num_levels and base_quantum."""
        kwargs: dict[str, int | str] = {"policy": "mlfq"}
        if args:
            try:
                kwargs["num_levels"] = int(args[0])
            except ValueError:
                return f"Error: invalid num_levels '{args[0]}'"
        if len(args) >= 2:  # noqa: PLR2004
            try:
                kwargs["base_quantum"] = int(args[1])
            except ValueError:
                return f"Error: invalid base_quantum '{args[1]}'"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                **kwargs,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_scheduler_cfs(self, args: list[str]) -> str:
        """Switch to CFS with optional base_slice."""
        kwargs: dict[str, int | str] = {"policy": "cfs"}
        if args:
            try:
                kwargs["base_slice"] = int(args[0])
            except ValueError:
                return f"Error: invalid base_slice '{args[0]}'"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                **kwargs,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_scheduler_boost(self) -> str:
        """Trigger an MLFQ priority boost via syscall."""
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_SCHEDULER_BOOST)
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_mutex(self, args: list[str]) -> str:
        """Manage mutexes — create or list."""
        if not args or args[0] not in {"create", "list"}:
            return "Usage: mutex <create|list> [args...]"
        if args[0] == "create":
            return self._cmd_mutex_create(args[1:])
        return self._cmd_mutex_list()

    def _cmd_mutex_create(self, args: list[str]) -> str:
        """Create a named mutex."""
        if not args:
            return "Usage: mutex create <name>"
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_mutex_list(self) -> str:
        """List all mutexes and their state."""
        sm = self._kernel.sync_manager
        if sm is None:
            return "Sync manager not available."
        names = sm.list_mutexes()
        if not names:
            return "No mutexes."
        lines: list[str] = ["NAME       STATE       OWNER"]
        for name in sorted(names):
            mutex = sm.get_mutex(name)
            state = "locked" if mutex.is_locked else "unlocked"
            owner = str(mutex.owner) if mutex.owner is not None else "-"
            lines.append(f"{name:<10} {state:<11} {owner}")
        return "\n".join(lines)

    def _cmd_semaphore(self, args: list[str]) -> str:
        """Manage semaphores — create or list."""
        if not args or args[0] not in {"create", "list"}:
            return "Usage: semaphore <create|list> [args...]"
        if args[0] == "create":
            return self._cmd_semaphore_create(args[1:])
        return self._cmd_semaphore_list()

    def _cmd_semaphore_create(self, args: list[str]) -> str:
        """Create a named semaphore with a given count."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: semaphore create <name> <count>"
        try:
            count = int(args[1])
        except ValueError:
            return f"Error: invalid count '{args[1]}'"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_SEMAPHORE,
                name=args[0],
                count=count,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_semaphore_list(self) -> str:
        """List all semaphores and their counts."""
        sm = self._kernel.sync_manager
        if sm is None:
            return "Sync manager not available."
        names = sm.list_semaphores()
        if not names:
            return "No semaphores."
        lines: list[str] = ["NAME       COUNT"]
        for name in sorted(names):
            sem = sm.get_semaphore(name)
            lines.append(f"{name:<10} {sem.count}")
        return "\n".join(lines)

    def _cmd_handle(self, args: list[str]) -> str:
        """Register a signal handler for a process.

        Built-in actions:
            - ``log`` — store the signal name in env var
              ``_LAST_SIGNAL_{pid}``.
            - ``ignore`` — suppress the signal's default action.
        """
        min_args = 3
        if len(args) < min_args:
            return "Usage: handle <pid> <SIGNAL> <log|ignore>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            sig = Signal[args[1]]
        except KeyError:
            return f"Error: unknown signal '{args[1]}'"

        action_name = args[2]
        match action_name:
            case "log":

                def _log_handler(_pid: int = pid, _sig: Signal = sig) -> None:
                    self._kernel.syscall(
                        SyscallNumber.SYS_SET_ENV,
                        key=f"_LAST_SIGNAL_{_pid}",
                        value=_sig.name,
                    )

                handler: Callable[[], None] = _log_handler
            case "ignore":

                def _ignore_handler() -> None:
                    pass

                handler = _ignore_handler
            case _:
                return f"Error: unknown action '{action_name}'. Use log or ignore."

        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_REGISTER_HANDLER,
                pid=pid,
                signal=sig,
                handler=handler,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_wait(self, args: list[str]) -> str:
        """Wait for any child of a parent process to terminate."""
        if not args:
            return "Usage: wait <parent_pid>"
        try:
            parent_pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            result_wait: dict[str, object] | None = self._kernel.syscall(
                SyscallNumber.SYS_WAIT, parent_pid=parent_pid
            )
        except SyscallError as e:
            return f"Error: {e}"
        if result_wait is None:
            return f"Process {parent_pid} is now waiting for a child."
        return (
            f"Collected child pid {result_wait['child_pid']}"
            f" (exit_code={result_wait['exit_code']}"
            f", output={result_wait['output']!r})"
        )

    def _cmd_waitpid(self, args: list[str]) -> str:
        """Wait for a specific child process to terminate."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: waitpid <parent_pid> <child_pid>"
        try:
            parent_pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            child_pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        try:
            result_waitpid: dict[str, object] | None = self._kernel.syscall(
                SyscallNumber.SYS_WAITPID,
                parent_pid=parent_pid,
                child_pid=child_pid,
            )
        except SyscallError as e:
            return f"Error: {e}"
        if result_waitpid is None:
            return f"Process {parent_pid} is now waiting for child {child_pid}."
        return (
            f"Collected child pid {result_waitpid['child_pid']}"
            f" (exit_code={result_waitpid['exit_code']}"
            f", output={result_waitpid['output']!r})"
        )

    def _cmd_mmap(self, args: list[str]) -> str:
        """Map a file into a process's virtual address space."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: mmap <pid> <path> [--shared]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        path = args[1]
        shared = "--shared" in args
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_MMAP,
                pid=pid,
                path=path,
                shared=shared,
            )
            return (
                f"Mapped {path} at address {result['virtual_address']}"
                f" ({result['num_pages']} pages)"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_munmap(self, args: list[str]) -> str:
        """Unmap a memory-mapped region."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: munmap <pid> <address>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            address = int(args[1])
        except ValueError:
            return f"Error: invalid address '{args[1]}'"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_MUNMAP,
                pid=pid,
                virtual_address=address,
            )
            return f"Unmapped address {address}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_msync(self, args: list[str]) -> str:
        """Sync a shared mapping's data back to the file."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: msync <pid> <address>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            address = int(args[1])
        except ValueError:
            return f"Error: invalid address '{args[1]}'"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_MSYNC,
                pid=pid,
                virtual_address=address,
            )
            # Look up region path for the output message
            regions = self._kernel.mmap_regions(pid)
            vpn = address // 256  # default page size
            region = regions.get(vpn)
            path_info = f" to {region.path}" if region else ""
            return f"Synced address {address}{path_info}"
        except SyscallError as e:
            return f"Error: {e}"
