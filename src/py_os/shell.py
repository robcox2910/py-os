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

import contextlib
import re
from collections.abc import Callable
from dataclasses import dataclass

from py_os.fs.filesystem import FileType
from py_os.jobs import JobManager, JobStatus
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

# Safety limit for while/for loops — prevents infinite loops in scripts.
_MAX_LOOP_ITERATIONS = 1000


@dataclass
class _Redirections:
    """Parsed I/O redirection operators from a command string."""

    stdin: str | None = None  # < file
    stdout: str | None = None  # > file or >> file
    stderr: str | None = None  # 2> file
    append: bool = False  # >> vs >


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
            "slabcreate": self._cmd_slabcreate,
            "slaballoc": self._cmd_slaballoc,
            "slabfree": self._cmd_slabfree,
            "slabinfo": self._cmd_slabinfo,
            "open": self._cmd_open,
            "close": self._cmd_close,
            "readfd": self._cmd_readfd,
            "writefd": self._cmd_writefd,
            "seek": self._cmd_seek,
            "lsfd": self._cmd_lsfd,
            "ln": self._cmd_ln,
            "readlink": self._cmd_readlink,
            "stat": self._cmd_stat,
            "journal": self._cmd_journal,
            "waitjob": self._cmd_waitjob,
        }

    def execute(self, command: str) -> str:
        """Parse and execute a shell command, with pipe and ``&`` support.

        Commands can be chained with ``|``.  The output of each stage
        becomes the piped input for the next.  A trailing ``&`` runs the
        command in the background (only meaningful for ``run``).

        Args:
            command: The raw command string (e.g. "ls / | grep txt").

        Returns:
            The command output as a string, or an error message.

        """
        # Record in history
        stripped = command.strip()
        if stripped:
            self._history.append(stripped)

        # Detect trailing &
        background = stripped.endswith("&")
        if background:
            stripped = stripped[:-1].rstrip()
            if not stripped:
                return ""
            if "|" in stripped:
                return "Error: background execution with pipes is not supported"
            if re.search(r"2?>|>>|<", stripped):
                return "Error: background execution with redirection is not supported"

        # Expand aliases in each pipeline stage
        stages = [s.strip() for s in stripped.split("|")]
        output = ""
        for i, stage in enumerate(stages):
            self._pipe_input = output if i > 0 else ""
            expanded = self._expand_alias(stage)
            cmd, redirects = self._parse_redirections(expanded)

            # Input redirection: load file into _pipe_input
            if redirects.stdin is not None:
                input_result = self._apply_input_redirect(redirects.stdin)
                if input_result.startswith("Error:"):
                    output = input_result
                    break
                self._pipe_input = input_result

            output = self._execute_single(cmd, background=background)

            # Output/error redirection
            output = self._apply_output_redirect(output, redirects)

            # Stop the pipeline if a command produces an error
            if output.startswith(("Unknown command:", "Error:")):
                break
        self._pipe_input = ""
        return output

    def run_script(self, script: str) -> list[str]:
        """Execute a multi-line script, returning output from each command.

        Supports comments (``#``), variable substitution (``$VAR``),
        conditionals (``if``/``then``/``else``/``fi``), and loops
        (``while``/``do``/``done``, ``for``/``in``/``do``/``done``).

        Loop bodies and conditional blocks are executed via recursive
        ``run_script()`` calls, so arbitrary nesting is supported.

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

            if line.startswith("if "):
                i = self._run_if_block(line, lines, i, results)
            elif line.startswith("while "):
                i = self._run_while_block(line, lines, i, results)
            elif line.startswith("for "):
                i = self._run_for_block(line, lines, i, results)
            else:
                expanded = self._expand_variables(line)
                results.append(self.execute(expanded))

        return results

    def _run_if_block(self, header: str, lines: list[str], i: int, results: list[str]) -> int:
        """Handle an if/then/else/fi block inside run_script().

        Collect the block, split into then/else branches respecting
        nested if depth, evaluate the condition, and execute the
        chosen branch via recursive ``run_script()``.
        """
        condition_cmd = header[3:]
        try:
            block, i = self._collect_block(lines, i, ("if",), "fi")
        except ValueError as exc:
            results.append(f"Error: {exc}")
            return i

        then_lines: list[str] = []
        else_lines: list[str] = []
        in_else = False
        depth = 0
        for bl in block:
            if bl.startswith("if ") or bl == "if":
                depth += 1
            elif bl == "fi":
                depth -= 1
            if depth == 0 and bl == "then":
                continue
            if depth == 0 and bl == "else":
                in_else = True
                continue
            if in_else:
                else_lines.append(bl)
            else:
                then_lines.append(bl)

        cond_result = self.execute(self._expand_variables(condition_cmd))
        chosen = then_lines if not cond_result.startswith("Error:") else else_lines
        results.extend(self.run_script("\n".join(chosen)))
        return i

    def _run_while_block(self, header: str, lines: list[str], i: int, results: list[str]) -> int:
        """Handle a while/do/done block inside run_script().

        Collect the body, then repeatedly evaluate the condition and
        execute the body until the condition fails or the iteration
        limit is reached.
        """
        condition_raw = header[6:]
        try:
            body, i = self._collect_block(lines, i, ("while", "for"), "done")
        except ValueError as exc:
            results.append(f"Error: {exc}")
            return i

        body = [bl for bl in body if bl != "do"]
        body_script = "\n".join(body)
        iterations = 0
        while iterations < _MAX_LOOP_ITERATIONS:
            cond_expanded = self._expand_variables(condition_raw)
            cond_result = self.execute(cond_expanded)
            if cond_result.startswith("Error:"):
                break
            results.extend(self.run_script(body_script))
            iterations += 1
        if iterations >= _MAX_LOOP_ITERATIONS:
            results.append(f"Error: loop exceeded {_MAX_LOOP_ITERATIONS} iterations limit")
        return i

    def _run_for_block(self, header: str, lines: list[str], i: int, results: list[str]) -> int:
        """Handle a for/in/do/done block inside run_script().

        Parse the variable name and item list, collect the body, then
        iterate: set the variable via SYS_SET_ENV and execute the body
        via recursive ``run_script()``.
        """
        parts = header[4:].split()
        min_parts = 2
        if len(parts) < min_parts or parts[1] != "in":
            results.append("Error: syntax error — expected 'for VAR in items...'")
            with contextlib.suppress(ValueError):
                _body, i = self._collect_block(lines, i, ("while", "for"), "done")
            return i

        var_name = parts[0]
        items_expanded = self._expand_variables(" ".join(parts[2:]))
        items = items_expanded.split()

        try:
            body, i = self._collect_block(lines, i, ("while", "for"), "done")
        except ValueError as exc:
            results.append(f"Error: {exc}")
            return i

        body = [bl for bl in body if bl != "do"]
        body_script = "\n".join(body)
        for iteration, item in enumerate(items):
            if iteration >= _MAX_LOOP_ITERATIONS:
                results.append(f"Error: loop exceeded {_MAX_LOOP_ITERATIONS} iterations limit")
                break
            self._kernel.syscall(SyscallNumber.SYS_SET_ENV, key=var_name, value=item)
            results.extend(self.run_script(body_script))
        return i

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

    @staticmethod
    def _collect_block(
        lines: list[str],
        start: int,
        open_keywords: tuple[str, ...],
        close_keyword: str,
    ) -> tuple[list[str], int]:
        """Collect lines from a block until the matching close keyword.

        Track nesting depth so that inner blocks with the same keywords
        don't cause premature termination.

        Args:
            lines: All script lines.
            start: Index to begin scanning from.
            open_keywords: Keywords that open a nested block.
            close_keyword: Keyword that closes the block.

        Returns:
            Tuple of (body lines, next index after close keyword).

        Raises:
            ValueError: If the close keyword is never found.

        """
        body: list[str] = []
        depth = 1
        i = start
        while i < len(lines):
            line = lines[i].strip()
            i += 1
            if any(line.startswith(kw + " ") or line == kw for kw in open_keywords):
                depth += 1
            elif line == close_keyword:
                depth -= 1
                if depth == 0:
                    return body, i
            body.append(line)
        msg = f"missing '{close_keyword}'"
        raise ValueError(msg)

    def _expand_alias(self, command: str) -> str:
        """Expand an alias if the first word matches."""
        parts = command.strip().split()
        if parts and parts[0] in self._aliases:
            return self._aliases[parts[0]]
        return command

    def _parse_redirections(self, command: str) -> tuple[str, _Redirections]:
        """Extract redirection operators from a command string.

        Processing order: ``2>`` before ``>>`` before ``>`` before ``<``
        to avoid ambiguity (e.g. ``2>`` must not leave a stray ``2``).
        """
        redirects = _Redirections()
        remaining = command

        # 2> (must check before > to avoid 2 being left as an arg)
        if match := re.search(r"2>\s*(\S+)", remaining):
            redirects.stderr = match.group(1)
            remaining = remaining[: match.start()] + remaining[match.end() :]

        # >> (must check before >)
        if match := re.search(r">>\s*(\S+)", remaining):
            redirects.stdout = match.group(1)
            redirects.append = True
            remaining = remaining[: match.start()] + remaining[match.end() :]

        # >
        elif match := re.search(r">\s*(\S+)", remaining):
            redirects.stdout = match.group(1)
            remaining = remaining[: match.start()] + remaining[match.end() :]

        # <
        if match := re.search(r"<\s*(\S+)", remaining):
            redirects.stdin = match.group(1)
            remaining = remaining[: match.start()] + remaining[match.end() :]

        return remaining.strip(), redirects

    def _apply_input_redirect(self, path: str) -> str:
        """Read a file for input redirection (``<``)."""
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=path)
            return data.decode()
        except SyscallError as e:
            return f"Error: {e}"

    def _apply_output_redirect(self, output: str, redirects: _Redirections) -> str:
        """Apply output and error redirection after command execution."""
        is_error = output.startswith(("Error:", "Unknown command:"))

        # Error redirection (2>)
        if is_error and redirects.stderr is not None:
            return self._write_redirect(redirects.stderr, output, append=False)

        # Stdout redirection (> or >>)
        if not is_error and redirects.stdout is not None:
            return self._write_redirect(redirects.stdout, output, append=redirects.append)

        return output

    def _write_redirect(self, path: str, content: str, *, append: bool) -> str:
        """Write content to a file for redirection. Create file if needed."""
        try:
            if append:
                try:
                    existing: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=path)
                    combined = existing.decode() + content
                except SyscallError:
                    # File doesn't exist — create it, start fresh
                    self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=path)
                    combined = content
                self._kernel.syscall(
                    SyscallNumber.SYS_WRITE_FILE, path=path, data=combined.encode()
                )
            else:
                try:
                    self._kernel.syscall(
                        SyscallNumber.SYS_WRITE_FILE, path=path, data=content.encode()
                    )
                except SyscallError:
                    # File doesn't exist — create then write
                    self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=path)
                    self._kernel.syscall(
                        SyscallNumber.SYS_WRITE_FILE, path=path, data=content.encode()
                    )
            return ""  # Output was redirected; return empty
        except SyscallError as e:
            return f"Error: {e}"

    def _execute_single(self, command: str, *, background: bool = False) -> str:
        """Execute a single (non-piped) command."""
        parts = command.strip().split()
        if not parts:
            return ""

        name = parts[0]
        args = parts[1:]

        # Only `run` has meaningful background semantics
        if background and name == "run":
            return self._run_background(args)

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
        """Bring a background job to the foreground.

        If the job has captured output (from ``run ... &``), display it.
        Otherwise fall back to the standard "moved to foreground" message
        (for jobs created via ``bg``).
        """
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
        if job.output is not None:
            return job.output
        return f"{job.name} (pid={job.pid}) moved to foreground."

    def _cmd_waitjob(self, args: list[str]) -> str:
        """Collect output from background jobs.

        ``waitjob``         — collect all jobs
        ``waitjob <job_id>`` — collect a specific job

        Unlike ``wait`` (kernel-level parent-child semantics), ``waitjob``
        is a shell-level concept for retrieving background job output.
        """
        if not args:
            jobs = self._jobs.list_jobs()
            if not jobs:
                return "No background jobs."
            outputs: list[str] = []
            for job in jobs:
                header = f"[{job.job_id}] {job.name}:"
                body = job.output if job.output is not None else "(no output)"
                outputs.append(f"{header}\n{body}")
                self._jobs.remove(job.job_id)
            return "\n".join(outputs)
        try:
            job_id = int(args[0])
        except ValueError:
            return f"Error: invalid job id '{args[0]}'"
        job = self._jobs.get(job_id)
        if job is None:
            return f"Error: job {job_id} not found"
        self._jobs.remove(job_id)
        if job.output is not None:
            return job.output
        return f"{job.name} (pid={job.pid}) — no captured output."

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

    @staticmethod
    def _builtin_programs() -> dict[str, Callable[[], str]]:
        """Return the registry of built-in programs.

        Both ``_cmd_run`` and ``_run_background`` need the same set of
        programs, so this single source of truth avoids duplication.
        """
        return {
            "hello": lambda: "Hello from PyOS!",
            "counter": lambda: "\n".join(str(i) for i in range(1, 6)),
        }

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
        program = self._builtin_programs().get(program_name)
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

    def _run_background(self, args: list[str]) -> str:
        """Run a program in the background, capturing output into a job.

        Same create/exec/run flow as ``_cmd_run``, but output is stored
        in a job instead of returned directly.  The user gets a
        ``[job_id] pid`` notification and retrieves output via ``fg``
        or ``waitjob``.
        """
        if not args:
            return "Usage: run <program> [priority]"
        program_name = args[0]
        priority = 0
        if len(args) >= 2:  # noqa: PLR2004
            try:
                priority = int(args[1])
            except ValueError:
                return f"Error: invalid priority '{args[1]}'"
        program = self._builtin_programs().get(program_name)
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
        except SyscallError as e:
            return f"Error: {e}"
        job = self._jobs.add(pid=pid, name=program_name)
        job.status = JobStatus.DONE
        job.output = f"{output}\n[exit code: {exit_code}]"
        job.exit_code = exit_code
        return f"[{job.job_id}] {pid}"

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

    # -- Slab allocator commands ---------------------------------------------

    def _cmd_slabcreate(self, args: list[str]) -> str:
        """Create a named slab cache with a given object size."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: slabcreate <name> <obj_size>"
        name = args[0]
        try:
            obj_size = int(args[1])
        except ValueError:
            return f"Error: invalid obj_size '{args[1]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SLAB_CREATE,
                name=name,
                obj_size=obj_size,
            )
            return (
                f"Created cache '{result['name']}'"
                f" ({result['obj_size']} bytes,"
                f" {result['capacity_per_slab']} per slab)"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slaballoc(self, args: list[str]) -> str:
        """Allocate an object from a slab cache."""
        if not args:
            return "Usage: slaballoc <cache>"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SLAB_ALLOC,
                cache=args[0],
            )
            return (
                f"Allocated from '{result['cache']}':"
                f" slab {result['slab_index']}, slot {result['slot_index']}"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slabfree(self, args: list[str]) -> str:
        """Free an object back to a slab cache."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: slabfree <cache> <slab_index> <slot_index>"
        name = args[0]
        try:
            slab_index = int(args[1])
        except ValueError:
            return f"Error: invalid slab_index '{args[1]}'"
        try:
            slot_index = int(args[2])
        except ValueError:
            return f"Error: invalid slot_index '{args[2]}'"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SLAB_FREE,
                cache=name,
                slab_index=slab_index,
                slot_index=slot_index,
            )
            return f"Freed '{name}' slab {slab_index}, slot {slot_index}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slabinfo(self, _args: list[str]) -> str:
        """Show slab cache statistics."""
        info: dict[str, dict[str, object]] = self._kernel.syscall(
            SyscallNumber.SYS_SLAB_INFO,
        )
        if not info:
            return "No slab caches."
        lines = ["CACHE      OBJ_SIZE  SLABS  USED  FREE"]
        for name in sorted(info):
            stats = info[name]
            lines.append(
                f"{name:<10} {stats['obj_size']!s:>8}"
                f"  {stats['total_slabs']!s:>5}"
                f"  {stats['used_slots']!s:>4}"
                f"  {stats['free_slots']!s:>4}"
            )
        return "\n".join(lines)

    # -- File descriptor commands --------------------------------------------

    def _cmd_open(self, args: list[str]) -> str:
        """Open a file and get a file descriptor."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: open <pid> <path> [r|w|rw]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        path = args[1]
        mode = args[2] if len(args) > 2 else "r"  # noqa: PLR2004
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_OPEN, pid=pid, path=path, mode=mode
            )
            return f"Opened '{path}' as fd {result['fd']} for pid {pid}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_close(self, args: list[str]) -> str:
        """Close a file descriptor."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: close <pid> <fd>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CLOSE, pid=pid, fd=fd)
            return f"Closed fd {fd} for pid {pid}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_readfd(self, args: list[str]) -> str:
        """Read bytes from a file descriptor."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: readfd <pid> <fd> <count>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        try:
            count = int(args[2])
        except ValueError:
            return f"Error: invalid count '{args[2]}'"
        try:
            result_read: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_READ_FD, pid=pid, fd=fd, count=count
            )
            data: bytes = result_read["data"]  # type: ignore[assignment]
            return data.decode(errors="replace")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_writefd(self, args: list[str]) -> str:
        """Write data to a file descriptor."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: writefd <pid> <fd> <data...>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        content = " ".join(args[2:])
        try:
            result_write: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FD, pid=pid, fd=fd, data=content.encode()
            )
            return f"Wrote {result_write['bytes_written']} bytes to fd {fd}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_seek(self, args: list[str]) -> str:
        """Reposition a file descriptor's offset."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: seek <pid> <fd> <offset> [set|cur|end]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        try:
            offset = int(args[2])
        except ValueError:
            return f"Error: invalid offset '{args[2]}'"
        whence = args[3] if len(args) > 3 else "set"  # noqa: PLR2004
        try:
            result_seek: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SEEK, pid=pid, fd=fd, offset=offset, whence=whence
            )
            return f"Seeked fd {fd} to offset {result_seek['offset']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_lsfd(self, args: list[str]) -> str:
        """List open file descriptors for a process."""
        if not args:
            return "Usage: lsfd <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        fds = self._kernel.list_fds(pid)
        if not fds:
            return f"No open file descriptors for pid {pid}."
        lines = ["FD  MODE  OFFSET  PATH"]
        for fd_num in sorted(fds):
            ofd = fds[fd_num]
            lines.append(f"{fd_num:<3} {ofd.mode!s:<5} {ofd.offset:<7} {ofd.path}")
        return "\n".join(lines)

    # -- Link commands -------------------------------------------------------

    def _cmd_ln(self, args: list[str]) -> str:
        """Create a hard or symbolic link.

        ``ln <target> <link>``     → hard link
        ``ln -s <target> <link>``  → symbolic link
        """
        symbolic = args[0] == "-s" if args else False
        actual_args = args[1:] if symbolic else args

        min_args = 2
        if len(actual_args) < min_args:
            return "Usage: ln [-s] <target> <link_name>"

        target = actual_args[0]
        link_path = actual_args[1]
        syscall = SyscallNumber.SYS_SYMLINK if symbolic else SyscallNumber.SYS_LINK
        try:
            self._kernel.syscall(syscall, target=target, link_path=link_path)
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_readlink(self, args: list[str]) -> str:
        """Print the target of a symbolic link."""
        if not args:
            return "Usage: readlink <path>"
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_READLINK, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_stat(self, args: list[str]) -> str:
        """Display file metadata (inode, type, size, links).

        Uses lstat internally so symlinks show their own metadata.
        """
        if not args:
            return "Usage: stat <path>"
        path = args[0]
        assert self._kernel.filesystem is not None  # noqa: S101
        try:
            info = self._kernel.filesystem.lstat(path)
        except FileNotFoundError as e:
            return f"Error: {e}"

        if info.file_type is FileType.SYMLINK:
            target = self._kernel.filesystem.readlink(path)
            file_line = f"  File: {path} -> {target}"
        else:
            file_line = f"  File: {path}"

        lines = [
            file_line,
            f"  Inode: {info.inode_number}",
            f"  Type: {info.file_type}",
            f"  Size: {info.size}",
            f"  Links: {info.link_count}",
        ]
        return "\n".join(lines)

    # -- Journal commands ---------------------------------------------------

    def _cmd_journal(self, args: list[str]) -> str:
        """Manage the filesystem journal — status, checkpoint, recover, crash."""
        if not args:
            return "Usage: journal <status|checkpoint|recover|crash>"
        match args[0]:
            case "status":
                return self._cmd_journal_status()
            case "checkpoint":
                return self._cmd_journal_checkpoint()
            case "recover":
                return self._cmd_journal_recover()
            case "crash":
                return self._cmd_journal_crash()
            case _:
                return "Usage: journal <status|checkpoint|recover|crash>"

    def _cmd_journal_status(self) -> str:
        """Show journal transaction status."""
        status: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_JOURNAL_STATUS)
        return (
            f"Transactions: {status['total']} total"
            f" ({status['active']} active,"
            f" {status['committed']} committed,"
            f" {status['aborted']} aborted)"
        )

    def _cmd_journal_checkpoint(self) -> str:
        """Create a journal checkpoint."""
        self._kernel.syscall(SyscallNumber.SYS_JOURNAL_CHECKPOINT)
        return "Checkpoint created"

    def _cmd_journal_recover(self) -> str:
        """Recover from a crash by replaying committed transactions."""
        result: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_JOURNAL_RECOVER)
        count = result["replayed"]
        return f"Recovery complete: replayed {count} transactions"

    def _cmd_journal_crash(self) -> str:
        """Simulate a crash for educational purposes."""
        self._kernel.syscall(SyscallNumber.SYS_JOURNAL_CRASH)
        return "Crash simulated \u2014 uncommitted work lost"
