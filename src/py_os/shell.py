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

from py_os.io.http import (
    HttpMethod,
    HttpRequest,
    HttpResponse,
    HttpStatus,
    format_request,
    format_response,
    parse_request,
    parse_response,
    status_reason,
)
from py_os.io.networking import SocketManager
from py_os.jobs import JobManager, JobStatus
from py_os.kernel import Kernel, KernelState
from py_os.process.signals import Signal
from py_os.syscalls import SyscallError, SyscallNumber
from py_os.tutorials import TutorialRunner

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
            "rwlock": self._cmd_rwlock,
            "pi": self._cmd_pi,
            "ordering": self._cmd_ordering,
            "waitjob": self._cmd_waitjob,
            "shm": self._cmd_shm,
            "dns": self._cmd_dns,
            "socket": self._cmd_socket,
            "http": self._cmd_http,
            "proc": self._cmd_proc,
            "perf": self._cmd_perf,
            "strace": self._cmd_strace,
            "dmesg": self._cmd_dmesg,
            "cpu": self._cmd_cpu,
            "taskset": self._cmd_taskset,
            "learn": self._cmd_learn,
        }

    @property
    def kernel(self) -> Kernel:
        """Return the kernel this shell is attached to."""
        return self._kernel

    @property
    def command_names(self) -> list[str]:
        """Return sorted list of available command names."""
        return sorted(self._commands)

    @property
    def builtin_program_names(self) -> list[str]:
        """Return sorted list of built-in program names."""
        return sorted(self._builtin_programs())

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
        return self._append_strace_output(output)

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
        lines = ["PID    CPU  STATE       NAME"]
        for p in procs:
            cpu = str(p["cpu_id"]) if p["cpu_id"] is not None else "-"
            lines.append(f"{p['pid']:<6} {cpu:<4} {p['state']!s:<11} {p['name']}")
        return "\n".join(lines)

    def _cmd_ls(self, args: list[str]) -> str:
        """List directory contents."""
        path = args[0] if args else "/"
        if path.startswith("/proc"):
            try:
                entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_PROC_LIST, path=path)
            except SyscallError as e:
                return f"Error: {e}"
            return "\n".join(entries) if entries else ""
        try:
            entries = self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path=path)
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
        if args[0].startswith("/proc"):
            try:
                return self._kernel.syscall(SyscallNumber.SYS_PROC_READ, path=args[0])
            except SyscallError as e:
                return f"Error: not found — {e}"
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
        resources: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_RESOURCES)
        if not resources:
            return "No resources registered."
        lines = ["RESOURCE   AVAIL"]
        lines.extend(f"{r['name']!s:<10} {r['available']}" for r in resources)
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

    def _cmd_scheduler(self, args: list[str]) -> str:  # noqa: PLR0911
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
            case "balance":
                return self._cmd_scheduler_balance()
            case _:
                return (
                    f"Error: unknown policy '{args[0]}'."
                    " Use fcfs, rr, priority, aging, mlfq, cfs, or balance."
                )

    def _cmd_scheduler_show(self) -> str:
        """Display the current scheduling policy name."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
        num_cpus = result.get("num_cpus", 1)
        cpu_info = f" ({num_cpus} CPUs)" if int(str(num_cpus)) > 1 else ""
        return f"Current policy: {result['policy']}{cpu_info}"

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
        mutexes: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_MUTEXES)
        if not mutexes:
            return "No mutexes."
        lines: list[str] = ["NAME       STATE       OWNER"]
        for m in mutexes:
            state = "locked" if m["locked"] else "unlocked"
            owner = str(m["owner"]) if m["owner"] is not None else "-"
            lines.append(f"{m['name']!s:<10} {state:<11} {owner}")
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
        sems: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_SEMAPHORES)
        if not sems:
            return "No semaphores."
        lines: list[str] = ["NAME       COUNT"]
        lines.extend(f"{s['name']!s:<10} {s['count']}" for s in sems)
        return "\n".join(lines)

    def _cmd_rwlock(self, args: list[str]) -> str:
        """Manage reader-writer locks — create or list."""
        if not args or args[0] not in {"create", "list"}:
            return "Usage: rwlock <create|list> [args...]"
        if args[0] == "create":
            return self._cmd_rwlock_create(args[1:])
        return self._cmd_rwlock_list()

    def _cmd_rwlock_create(self, args: list[str]) -> str:
        """Create a named reader-writer lock."""
        if not args:
            return "Usage: rwlock create <name>"
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_rwlock_list(self) -> str:
        """List all reader-writer locks and their state."""
        rwlocks: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_RWLOCKS)
        if not rwlocks:
            return "No reader-writer locks."
        lines: list[str] = ["NAME       READERS  WRITER  WAITING"]
        for r in rwlocks:
            readers = str(r["reader_count"])
            writer = str(r["writer_tid"]) if r["writer_tid"] is not None else "-"
            waiting = str(r["wait_queue_size"])
            lines.append(f"{r['name']!s:<10} {readers:<8} {writer:<7} {waiting}")
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
        fds: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_FDS, pid=pid)
        if not fds:
            return f"No open file descriptors for pid {pid}."
        lines = ["FD  MODE  OFFSET  PATH"]
        lines.extend(
            f"{fd_info['fd']!s:<3} {fd_info['mode']!s:<5}"
            f" {fd_info['offset']!s:<7} {fd_info['path']}"
            for fd_info in fds
        )
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

        Use lstat internally so symlinks show their own metadata.
        """
        if not args:
            return "Usage: stat <path>"
        path = args[0]
        try:
            info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_LSTAT, path=path)
        except SyscallError as e:
            return f"Error: {e}"

        if str(info["file_type"]) == "symlink" and "target" in info:
            file_line = f"  File: {path} -> {info['target']}"
        else:
            file_line = f"  File: {path}"

        lines = [
            file_line,
            f"  Inode: {info['inode_number']}",
            f"  Type: {info['file_type']}",
            f"  Size: {info['size']}",
            f"  Links: {info['link_count']}",
        ]
        return "\n".join(lines)

    # -- Priority inheritance commands --------------------------------------

    def _cmd_pi(self, args: list[str]) -> str:
        """Priority inheritance demo and status.

        Subcommands:
            demo   — walk through the Mars Pathfinder scenario
            status — show which processes are currently boosted
        """
        if not args or args[0] not in {"demo", "status"}:
            return "Usage: pi <demo|status>"
        if args[0] == "demo":
            return self._cmd_pi_demo()
        return self._cmd_pi_status()

    def _cmd_pi_demo(self) -> str:
        """Walk through the Mars Pathfinder priority inversion scenario."""
        lines: list[str] = [
            "=== Mars Pathfinder Priority Inversion Demo ===",
            "",
            "In 1997, NASA's Mars Pathfinder rover kept rebooting on Mars.",
            "A low-priority task held a shared mutex, a high-priority task",
            "blocked waiting for it, and a medium-priority task kept running.",
            "",
            "Let's recreate this with three processes and a mutex:",
        ]

        try:
            # Create demo processes
            low_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="low_task", num_pages=1, priority=1
            )
            med_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="med_task", num_pages=1, priority=5
            )
            high_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="high_task", num_pages=1, priority=10
            )
            low_pid: int = low_r["pid"]
            med_pid: int = med_r["pid"]
            high_pid: int = high_r["pid"]

            low_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=low_pid
            )
            med_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=med_pid
            )
            high_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=high_pid
            )

            lines.append(f"  low_task  (pid={low_pid}, priority=1)")
            lines.append(f"  med_task  (pid={med_pid}, priority=5)")
            lines.append(f"  high_task (pid={high_pid}, priority=10)")

            # Create a mutex
            self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="_pi_demo_lock")

            # Low acquires the mutex
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX,
                name="_pi_demo_lock",
                tid=int(str(low_info["main_tid"])),
                pid=low_pid,
            )
            low_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=low_pid)
            lines.append("")
            lines.append("Step 1: low_task acquires the mutex.")
            lines.append(f"  low_task effective_priority = {low_info['effective_priority']}")

            # High tries to acquire — blocked, triggers PI
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX,
                name="_pi_demo_lock",
                tid=int(str(high_info["main_tid"])),
                pid=high_pid,
            )
            low_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=low_pid)
            med_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=med_pid)
            lines.append("")
            lines.append("Step 2: high_task tries to acquire — blocked!")
            lines.append("  Priority inheritance kicks in:")
            lines.append(
                f"  low_task effective_priority = {low_info['effective_priority']} (boosted!)"
            )
            lines.append(f"  med_task effective_priority = {med_info['effective_priority']}")
            lines.append("")
            lines.append("  Now low_task runs at priority 10, so the scheduler picks it")
            lines.append("  over med_task (priority 5). low_task finishes and releases.")

            # Low releases
            self._kernel.syscall(
                SyscallNumber.SYS_RELEASE_MUTEX,
                name="_pi_demo_lock",
                tid=int(str(low_info["main_tid"])),
                pid=low_pid,
            )
            low_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=low_pid)
            lines.append("")
            lines.append("Step 3: low_task releases the mutex.")
            lines.append(
                f"  low_task effective_priority = {low_info['effective_priority']} (restored)"
            )
            lines.append("  high_task can now acquire and proceed.")

            lines.append("")
            lines.append("Without priority inheritance, med_task would have starved high_task.")
            lines.append("This is exactly what happened on Mars until engineers uploaded a fix!")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up demo resources
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="_pi_demo_lock")

        return "\n".join(lines)

    def _cmd_pi_status(self) -> str:
        """Show priority inheritance status."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PI_STATUS)

        lines = ["=== Priority Inheritance Status ==="]
        lines.append(f"Enabled: {result['enabled']}")

        boosted_list: list[dict[str, object]] = result["boosted"]  # type: ignore[assignment]
        if boosted_list:
            lines.append("Boosted processes:")
            lines.extend(
                f"  pid {b['pid']} ({b['name']}):"
                f" base={b['base_priority']}, effective={b['effective_priority']}"
                for b in boosted_list
            )
        else:
            lines.append("No processes currently boosted.")

        return "\n".join(lines)

    # -- Resource ordering commands -----------------------------------------

    def _cmd_ordering(self, args: list[str]) -> str:
        """Manage resource ordering — register, status, mode, violations, demo."""
        subs = {"register", "status", "mode", "violations", "demo"}
        if not args or args[0] not in subs:
            return "Usage: ordering <register|status|mode|violations|demo>"
        sub = args[0]
        if sub == "register":
            return self._cmd_ordering_register(args[1:])
        if sub == "mode":
            return self._cmd_ordering_mode(args[1:])
        if sub == "status":
            return self._cmd_ordering_status()
        if sub == "violations":
            return self._cmd_ordering_violations()
        return self._cmd_ordering_demo()

    def _cmd_ordering_register(self, args: list[str]) -> str:
        """Register a resource with a rank."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: ordering register <resource> <rank>"
        name = args[0]
        try:
            rank = int(args[1])
        except ValueError:
            return f"Error: invalid rank '{args[1]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_REGISTER_RANK,
                name=name,
                rank=rank,
            )
            return f"Registered '{result['name']}' with rank {result['rank']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_ordering_status(self) -> str:
        """Show ordering table and held resources."""
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_CHECK_ORDERING)
        except SyscallError as e:
            return f"Error: {e}"
        lines = [
            "=== Resource Ordering Status ===",
            f"Mode: {result['mode']}",
            f"Violations: {result['violations']}",
        ]
        ranks: dict[str, int] = result["ranks"]  # type: ignore[assignment]
        if ranks:
            lines.append("")
            lines.append("RESOURCE                     RANK")
            lines.extend(
                f"  {name:<26} {ranks[name]}" for name in sorted(ranks, key=lambda n: ranks[n])
            )
        else:
            lines.append("No resources registered.")
        return "\n".join(lines)

    def _cmd_ordering_mode(self, args: list[str]) -> str:
        """Set the ordering enforcement mode."""
        if not args:
            return "Usage: ordering mode <strict|warn|off>"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_SET_ORDERING_MODE,
                mode=args[0],
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_ordering_violations(self) -> str:
        """Show recorded ordering violations."""
        violations: list[dict[str, object]] = self._kernel.syscall(
            SyscallNumber.SYS_ORDERING_VIOLATIONS
        )
        if not violations:
            return "No ordering violations recorded."
        lines = ["RESOURCE                     REQ_RANK  MAX_HELD  PID"]
        lines.extend(
            f"  {v['resource_requested']!s:<26}"
            f" {v['requested_rank']!s:<9}"
            f" {v['max_held_rank']!s:<9}"
            f" {v['pid']}"
            for v in violations
        )
        return "\n".join(lines)

    def _cmd_ordering_demo(self) -> str:
        """Walk through the numbered-lockers resource ordering scenario."""
        lines: list[str] = [
            "=== Resource Ordering Demo ===",
            "",
            "Imagine numbered lockers in a school hallway.",
            "The rule: you can only walk forward (ascending locker numbers).",
            "If you need locker 3 and locker 7, open 3 first, then 7.",
            "You can never go backwards. Nobody ever gets stuck in a circle.",
            "",
            "Let's see this in action with two mutexes:",
        ]

        # Remember the current ordering mode so we can restore it
        ordering_status: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_CHECK_ORDERING)
        old_mode = str(ordering_status["mode"])

        try:
            # Create demo mutexes with explicit ranks
            self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="_demo_lock_a")
            self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="_demo_lock_b")
            self._kernel.syscall(SyscallNumber.SYS_REGISTER_RANK, name="mutex:_demo_lock_a", rank=1)
            self._kernel.syscall(SyscallNumber.SYS_REGISTER_RANK, name="mutex:_demo_lock_b", rank=2)

            # Create two processes
            p1_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="walker_1", num_pages=1
            )
            p2_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="walker_2", num_pages=1
            )
            p1_pid: int = p1_r["pid"]
            p2_pid: int = p2_r["pid"]

            p1_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=p1_pid
            )
            p2_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=p2_pid
            )
            p1_tid = int(str(p1_info["main_tid"]))
            p2_tid = int(str(p2_info["main_tid"]))

            lines.append("  mutex:_demo_lock_a  rank=1")
            lines.append("  mutex:_demo_lock_b  rank=2")
            lines.append(f"  walker_1 (pid={p1_pid})")
            lines.append(f"  walker_2 (pid={p2_pid})")

            # Set warn mode for the demo
            self._kernel.syscall(SyscallNumber.SYS_SET_ORDERING_MODE, mode="warn")

            # Process 1: ascending order (correct)
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_a", tid=p1_tid, pid=p1_pid
            )
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_b", tid=p1_tid, pid=p1_pid
            )
            lines.append("")
            lines.append("Step 1: walker_1 acquires lock_a (rank 1) then lock_b (rank 2)")
            lines.append("  Ascending order -- ALLOWED (walking forward)")

            # Release p1's locks
            self._kernel.syscall(
                SyscallNumber.SYS_RELEASE_MUTEX, name="_demo_lock_b", tid=p1_tid, pid=p1_pid
            )
            self._kernel.syscall(
                SyscallNumber.SYS_RELEASE_MUTEX, name="_demo_lock_a", tid=p1_tid, pid=p1_pid
            )

            # Process 2: descending order (violation!)
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_b", tid=p2_tid, pid=p2_pid
            )
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_a", tid=p2_tid, pid=p2_pid
            )
            lines.append("")
            lines.append("Step 2: walker_2 acquires lock_b (rank 2) then lock_a (rank 1)")
            lines.append("  Descending order -- VIOLATION! (walking backwards)")
            lines.append("  In strict mode, this would be rejected.")

            lines.append("")
            lines.append("This simple rule -- always go forward -- prevents circular wait,")
            lines.append("one of the four conditions required for deadlock.")
            lines.append("No circle can form because nobody ever goes backwards.")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up demo resources
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="_demo_lock_a")
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="_demo_lock_b")
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_SET_ORDERING_MODE, mode=old_mode)

        return "\n".join(lines)

    # -- Shared memory commands ---------------------------------------------

    def _cmd_shm(self, args: list[str]) -> str:
        """Manage shared memory segments."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "create": self._cmd_shm_create,
            "attach": self._cmd_shm_attach,
            "detach": self._cmd_shm_detach,
            "write": self._cmd_shm_write,
            "read": self._cmd_shm_read,
            "list": lambda _a: self._cmd_shm_list(),
            "destroy": self._cmd_shm_destroy,
            "demo": lambda _a: self._cmd_shm_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: shm <create|attach|detach|write|read|list|destroy|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_shm_create(self, args: list[str]) -> str:
        """Create a named shared memory segment."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: shm create <name> <size> <pid>"
        name = args[0]
        try:
            size = int(args[1])
        except ValueError:
            return f"Error: invalid size '{args[1]}'"
        try:
            pid = int(args[2])
        except ValueError:
            return f"Error: invalid PID '{args[2]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_CREATE, name=name, size=size, pid=pid
            )
            return (
                f"Created shared memory '{result['name']}'"
                f" ({result['size']} bytes, {result['num_pages']} pages)"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_attach(self, args: list[str]) -> str:
        """Attach a process to a shared memory segment."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: shm attach <name> <pid>"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_ATTACH, name=name, pid=pid
            )
            return f"Attached pid {pid} to '{name}' at address {result['virtual_address']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_detach(self, args: list[str]) -> str:
        """Detach a process from a shared memory segment."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: shm detach <name> <pid>"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SHM_DETACH, name=name, pid=pid)
            return f"Detached pid {pid} from '{name}'"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_write(self, args: list[str]) -> str:
        """Write data to a shared memory segment."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: shm write <name> <pid> <data> [offset]"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        offset = 0
        if len(args) > min_args:
            try:
                offset = int(args[-1])
                data = " ".join(args[2:-1])
            except ValueError:
                data = " ".join(args[2:])
        else:
            data = args[2]
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SHM_WRITE,
                name=name,
                pid=pid,
                data=data.encode(),
                offset=offset,
            )
            return f"Wrote {len(data)} bytes to '{name}'"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_read(self, args: list[str]) -> str:
        """Read data from a shared memory segment."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: shm read <name> <pid> [offset] [size]"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        kwargs: dict[str, object] = {"name": name, "pid": pid}
        if len(args) > min_args:
            try:
                kwargs["offset"] = int(args[2])
            except ValueError:
                return f"Error: invalid offset '{args[2]}'"
        min_args_with_size = 4
        if len(args) >= min_args_with_size:
            try:
                kwargs["size"] = int(args[3])
            except ValueError:
                return f"Error: invalid size '{args[3]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SHM_READ, **kwargs)
            data: bytes = result["data"]  # type: ignore[assignment]
            return data.decode(errors="replace").rstrip("\x00")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_list(self) -> str:
        """List all shared memory segments."""
        segments: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_SHM_LIST)
        if not segments:
            return "No shared memory segments."
        lines = ["NAME       SIZE  PAGES  CREATOR  ATTACHED  MARKED"]
        for seg in segments:
            marked = "yes" if seg["marked_for_deletion"] else "no"
            lines.append(
                f"{seg['name']:<10} {seg['size']!s:>5}"
                f"  {seg['num_pages']!s:>5}"
                f"  {seg['creator_pid']!s:>7}"
                f"  {seg['attached']!s:>8}"
                f"  {marked}"
            )
        return "\n".join(lines)

    def _cmd_shm_destroy(self, args: list[str]) -> str:
        """Destroy a shared memory segment."""
        if not args:
            return "Usage: shm destroy <name>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SHM_DESTROY, name=args[0])
            return f"Destroyed shared memory '{args[0]}'"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_demo(self) -> str:
        """Walk through a shared memory demo — the shared whiteboard."""
        lines: list[str] = [
            "=== Shared Memory Demo ===",
            "",
            "Imagine a shared whiteboard in the school hallway.",
            "Any student can walk up and write on it, and everyone",
            "else can see what's there instantly.",
            "",
        ]

        try:
            # Create two processes
            writer_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="writer", num_pages=1
            )
            reader_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="reader", num_pages=1
            )
            writer_pid: int = writer_r["pid"]
            reader_pid: int = reader_r["pid"]

            lines.append(
                f"Step 1: Create two processes: writer (pid={writer_pid})"
                f" and reader (pid={reader_pid})"
            )

            # Create a shared memory segment
            seg_r: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_CREATE, name="_demo_board", size=64, pid=writer_pid
            )
            lines.append(
                f"Step 2: Create shared memory 'board'"
                f" ({seg_r['size']} bytes, {seg_r['num_pages']} pages)"
            )

            # Attach both processes
            self._kernel.syscall(SyscallNumber.SYS_SHM_ATTACH, name="_demo_board", pid=writer_pid)
            self._kernel.syscall(SyscallNumber.SYS_SHM_ATTACH, name="_demo_board", pid=reader_pid)
            lines.append("Step 3: Both processes attach to the shared memory")

            # Writer writes
            message = "Hello from Process A!"
            self._kernel.syscall(
                SyscallNumber.SYS_SHM_WRITE,
                name="_demo_board",
                pid=writer_pid,
                data=message.encode(),
            )
            lines.append(f'Step 4: Writer writes "{message}"')

            # Reader reads
            read_r: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_READ,
                name="_demo_board",
                pid=reader_pid,
                size=len(message),
            )
            data: bytes = read_r["data"]  # type: ignore[assignment]
            lines.append(f'Step 5: Reader reads: "{data.decode()}"')
            lines.append("  The data appeared instantly -- shared whiteboard!")

            lines.append("")
            lines.append("Note: Without synchronization (like a semaphore), two")
            lines.append("processes writing at the same time could corrupt data.")
            lines.append("Always use a lock or semaphore to protect shared memory!")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_SHM_DESTROY, name="_demo_board")

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

    # -- DNS commands -------------------------------------------------------

    def _cmd_dns(self, args: list[str]) -> str:
        """Manage DNS records — the phone book for hostname → IP resolution."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "register": self._cmd_dns_register,
            "lookup": self._cmd_dns_lookup,
            "remove": self._cmd_dns_remove,
            "list": lambda _a: self._cmd_dns_list(),
            "flush": lambda _a: self._cmd_dns_flush(),
            "demo": lambda _a: self._cmd_dns_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: dns <register|lookup|remove|list|flush|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_dns_register(self, args: list[str]) -> str:
        """Register a DNS A record."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: dns register <hostname> <ip>"
        hostname = args[0]
        address = args[1]
        try:
            result: dict[str, str] = self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER, hostname=hostname, address=address
            )
            return f"Registered {result['hostname']} -> {result['address']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_dns_lookup(self, args: list[str]) -> str:
        """Look up a hostname."""
        if not args:
            return "Usage: dns lookup <hostname>"
        hostname = args[0]
        try:
            address: str = self._kernel.syscall(SyscallNumber.SYS_DNS_LOOKUP, hostname=hostname)
            return f"{hostname} -> {address}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_dns_remove(self, args: list[str]) -> str:
        """Remove a DNS record."""
        if not args:
            return "Usage: dns remove <hostname>"
        hostname = args[0]
        try:
            self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=hostname)
            return f"Removed {hostname}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_dns_list(self) -> str:
        """List all DNS records."""
        records: list[dict[str, str]] = self._kernel.syscall(SyscallNumber.SYS_DNS_LIST)
        if not records:
            return "No DNS records."
        lines = ["HOSTNAME                 ADDRESS"]
        lines.extend(f"{rec['hostname']:<24} {rec['address']}" for rec in records)
        return "\n".join(lines)

    def _cmd_dns_flush(self) -> str:
        """Flush all DNS records."""
        count: int = self._kernel.syscall(SyscallNumber.SYS_DNS_FLUSH)
        return f"Flushed {count} DNS records"

    def _cmd_dns_demo(self) -> str:
        """Walk through a DNS demo — name resolution over sockets."""
        lines: list[str] = [
            "=== DNS Demo: Name Resolution Over Sockets ===",
            "",
            "DNS is like a phone book. You know your friend's name",
            "but not their phone number. You open the phone book,",
            "look up the name, and find the number.",
            "",
        ]

        demo_host_1 = "_demo.example.com"
        demo_ip_1 = "93.184.216.34"
        demo_host_2 = "_demo.pyos.local"
        demo_ip_2 = "10.0.0.42"
        dns_port = 53

        try:
            # Step 1: Register demo records
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname=demo_host_1,
                address=demo_ip_1,
            )
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname=demo_host_2,
                address=demo_ip_2,
            )
            lines.append(
                f"Step 1: Register demo records:"
                f"\n  {demo_host_1} -> {demo_ip_1}"
                f"\n  {demo_host_2} -> {demo_ip_2}"
            )
            lines.append("")

            # Step 2: Set up sockets (used directly — not kernel-integrated yet)
            sm = SocketManager()
            server = sm.create_socket()
            server.bind(address="localhost", port=dns_port)
            server.listen()
            lines.append(f"Step 2: DNS server socket bound to localhost:{dns_port}, listening")

            # Step 3: Client connects
            client = sm.create_socket()
            sm.connect(client, address="localhost", port=dns_port)
            peer = sm.accept(server)
            assert peer is not None  # noqa: S101
            lines.append("Step 3: Client connects to the DNS server")
            lines.append("")

            # Step 4: Client sends a query
            query = f"QUERY A {demo_host_1}"
            sm.send(client, query.encode())
            lines.append(f'Step 4: Client sends: "{query}"')

            # Step 5: Server receives and resolves
            raw = sm.recv(peer)
            query_text = raw.decode()
            parts = query_text.split()
            queried_host = parts[2]
            resolved_ip: str = self._kernel.syscall(
                SyscallNumber.SYS_DNS_LOOKUP, hostname=queried_host
            )
            answer = f"ANSWER {queried_host} {resolved_ip}"
            sm.send(peer, answer.encode())
            lines.append(
                f"Step 5: Server receives query, looks up '{queried_host}',"
                f'\n  resolves to {resolved_ip}, sends: "{answer}"'
            )

            # Step 6: Client receives the answer
            response = sm.recv(client).decode()
            lines.append(f'Step 6: Client receives: "{response}"')
            lines.append("")

            # Teaching summary
            lines.append("How it works:")
            lines.append("  - DNS queries travel over sockets (real DNS uses port 53)")
            lines.append("  - The query/answer is just text (real DNS uses a binary format)")
            lines.append("  - This is protocol layering: DNS runs ON TOP of sockets")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up demo records
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=demo_host_1)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=demo_host_2)

        return "\n".join(lines)

    # -- Socket commands ---------------------------------------------------

    def _cmd_socket(self, args: list[str]) -> str:
        """Manage raw sockets — create, bind, listen, connect, accept, send, recv, close, list."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "create": lambda _a: self._cmd_socket_create(),
            "bind": self._cmd_socket_bind,
            "listen": self._cmd_socket_listen,
            "connect": self._cmd_socket_connect,
            "accept": self._cmd_socket_accept,
            "send": self._cmd_socket_send,
            "recv": self._cmd_socket_recv,
            "close": self._cmd_socket_close,
            "list": lambda _a: self._cmd_socket_list(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: socket <create|bind|listen|connect|accept|send|recv|close|list>"
        return dispatch[args[0]](args[1:])

    def _cmd_socket_create(self) -> str:
        """Create a new socket."""
        try:
            result: dict[str, int | str] = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            return f"Socket {result['sock_id']} created (state: {result['state']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_bind(self, args: list[str]) -> str:
        """Bind a socket to an address and port."""
        expected_args = 3
        if len(args) < expected_args:
            return "Usage: socket bind <id> <address> <port>"
        try:
            sock_id = int(args[0])
            port = int(args[2])
        except ValueError:
            return "Error: id and port must be integers"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_BIND, sock_id=sock_id, address=args[1], port=port
            )
            return f"Socket {sock_id} bound to {args[1]}:{port}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_listen(self, args: list[str]) -> str:
        """Mark a socket as listening."""
        if not args:
            return "Usage: socket listen <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=sock_id)
            return f"Socket {sock_id} listening"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_connect(self, args: list[str]) -> str:
        """Connect a socket to a listener."""
        expected_args = 3
        if len(args) < expected_args:
            return "Usage: socket connect <id> <address> <port>"
        try:
            sock_id = int(args[0])
            port = int(args[2])
        except ValueError:
            return "Error: id and port must be integers"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_CONNECT, sock_id=sock_id, address=args[1], port=port
            )
            return f"Socket {sock_id} connected to {args[1]}:{port}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_accept(self, args: list[str]) -> str:
        """Accept a pending connection."""
        if not args:
            return "Usage: socket accept <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=sock_id)
            if result is None:
                return "No pending connections"
            return f"Accepted connection: peer socket {result['sock_id']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_send(self, args: list[str]) -> str:
        """Send data over a socket."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: socket send <id> <data>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        data = " ".join(args[1:])
        try:
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_SEND, sock_id=sock_id, data=data.encode())
            return f"Sent {len(data)} bytes on socket {sock_id}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_recv(self, args: list[str]) -> str:
        """Receive data from a socket."""
        if not args:
            return "Usage: socket recv <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_SOCKET_RECV, sock_id=sock_id)
            if not data:
                return "(no data)"
            return data.decode(errors="replace")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_close(self, args: list[str]) -> str:
        """Close a socket."""
        if not args:
            return "Usage: socket close <id>"
        try:
            sock_id = int(args[0])
        except ValueError:
            return "Error: id must be an integer"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=sock_id)
            return f"Socket {sock_id} closed"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_socket_list(self) -> str:
        """List all sockets."""
        sockets: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_SOCKET_LIST)
        if not sockets:
            return "No sockets."
        lines = ["ID     STATE        ADDRESS          PORT"]
        for s in sockets:
            sid = s["sock_id"]
            state = s["state"]
            addr = s.get("address") or "-"
            port = s.get("port") or "-"
            lines.append(f"{sid:<6} {state:<12} {addr:<16} {port}")
        return "\n".join(lines)

    # -- HTTP commands -----------------------------------------------------

    def _cmd_http(self, args: list[str]) -> str:
        """HTTP protocol demo — request/response over sockets."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "demo": lambda _a: self._cmd_http_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: http <demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_http_demo(self) -> str:  # noqa: PLR0915
        """Walk through an HTTP demo — serve a file over sockets."""
        lines: list[str] = [
            "=== HTTP Demo: Request/Response Over Sockets ===",
            "",
            "HTTP is like a restaurant. The customer (client) fills out an",
            "order form (request), the waiter (socket) carries it to the",
            "kitchen (server), and the kitchen sends back a receipt (response).",
            "",
        ]

        demo_host = "_demo.webserver"
        demo_ip = "10.0.0.80"
        demo_port = 80
        demo_path = "/www/index.html"
        demo_content = "<h1>Welcome to PyOS!</h1>"
        missing_path = "/www/missing.html"

        # Track socket IDs for cleanup
        sock_ids: list[int] = []

        try:
            # Step 1: Create file in filesystem
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/www")
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=demo_path)
            self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FILE,
                path=demo_path,
                data=demo_content.encode(),
            )
            lines.append(f'Step 1: Created {demo_path} with "{demo_content}"')
            lines.append("")

            # Step 2: Register DNS
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname=demo_host,
                address=demo_ip,
            )
            lines.append(f"Step 2: Registered DNS: {demo_host} -> {demo_ip}")
            lines.append("")

            # Step 3: Server socket — create, bind, listen (via syscalls)
            srv = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            srv_id = srv["sock_id"]
            sock_ids.append(srv_id)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_BIND,
                sock_id=srv_id,
                address=demo_ip,
                port=demo_port,
            )
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=srv_id)
            lines.append(f"Step 3: Server socket {srv_id} listening on {demo_ip}:{demo_port}")

            # Step 4: Client socket — create and connect
            cli = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            cli_id = cli["sock_id"]
            sock_ids.append(cli_id)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_CONNECT,
                sock_id=cli_id,
                address=demo_ip,
                port=demo_port,
            )
            lines.append(f"Step 4: Client socket {cli_id} connected to {demo_ip}:{demo_port}")
            lines.append("")

            # Step 5: Server accepts
            peer = self._kernel.syscall(SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=srv_id)
            assert peer is not None  # noqa: S101
            peer_id = peer["sock_id"]
            sock_ids.append(peer_id)
            lines.append(f"Step 5: Server accepted connection (peer socket {peer_id})")
            lines.append("")

            # Step 6: Client sends HTTP GET request
            request = HttpRequest(
                method=HttpMethod.GET,
                path=demo_path,
                headers={"Host": demo_host},
            )
            request_bytes = format_request(request)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=cli_id,
                data=request_bytes,
            )
            lines.append(f"Step 6: Client sends: GET {demo_path} HTTP/1.0")

            # Step 7: Server receives and parses
            raw_request: bytes = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_RECV, sock_id=peer_id
            )
            parsed = parse_request(raw_request)
            lines.append(f"Step 7: Server receives request: {parsed.method} {parsed.path}")

            # Step 8: Server reads file and builds response
            file_data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=parsed.path)
            response = HttpResponse(
                status=HttpStatus.OK,
                headers={"Content-Type": "text/html"},
                body=file_data,
            )
            response_bytes = format_response(response)
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=peer_id,
                data=response_bytes,
            )
            lines.append(
                f"Step 8: Server reads file, sends: HTTP/1.0 {response.status}"
                f" {status_reason(response.status)}"
            )
            lines.append("")

            # Step 9: Client receives and parses response
            raw_response: bytes = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_RECV, sock_id=cli_id
            )
            parsed_resp = parse_response(raw_response)
            lines.append(
                f"Step 9: Client receives: {parsed_resp.status} {status_reason(parsed_resp.status)}"
            )
            lines.append(f"  Body: {parsed_resp.body.decode()}")
            lines.append("")

            # Step 10: Show 404 — request a missing file
            lines.append("--- Now requesting a file that doesn't exist ---")
            lines.append("")
            request_404 = HttpRequest(
                method=HttpMethod.GET,
                path=missing_path,
                headers={"Host": demo_host},
            )
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=cli_id,
                data=format_request(request_404),
            )
            raw_404: bytes = self._kernel.syscall(SyscallNumber.SYS_SOCKET_RECV, sock_id=peer_id)
            parsed_404 = parse_request(raw_404)

            # Server tries to read the file — it won't exist
            try:
                self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=parsed_404.path)
                # If we somehow get here, send 200 (shouldn't happen)
                resp_404 = HttpResponse(status=HttpStatus.OK, headers={})
            except SyscallError:
                resp_404 = HttpResponse(
                    status=HttpStatus.NOT_FOUND,
                    headers={},
                    body=b"404 Not Found",
                )

            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND,
                sock_id=peer_id,
                data=format_response(resp_404),
            )
            raw_404_resp: bytes = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_RECV, sock_id=cli_id
            )
            parsed_404_resp = parse_response(raw_404_resp)
            lines.append(
                f"Step 10: GET {missing_path} -> {parsed_404_resp.status}"
                f" {status_reason(parsed_404_resp.status)}"
            )
            lines.append(f"  Body: {parsed_404_resp.body.decode()}")
            lines.append("")

            # Teaching summary
            lines.append("How it works:")
            lines.append("  - HTTP is a request/response protocol (client asks, server answers)")
            lines.append("  - Requests have a method (GET, POST) and a path (/index.html)")
            lines.append("  - Responses have a status code (200 OK, 404 Not Found)")
            lines.append("  - HTTP runs ON TOP of sockets — protocol layering!")
            lines.append("  - All socket operations go through syscalls (kernel integration)")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up: close sockets, remove DNS, delete files
            for sid in sock_ids:
                with contextlib.suppress(SyscallError):
                    self._kernel.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=sid)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname=demo_host)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path=demo_path)
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/www")

        return "\n".join(lines)

    # -- /proc virtual filesystem command ------------------------------------

    def _cmd_proc(self, args: list[str]) -> str:
        """/proc virtual filesystem — inspect live kernel state."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "demo": lambda _a: self._cmd_proc_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: proc <demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_proc_demo(self) -> str:
        """Walk through the /proc virtual filesystem."""
        lines: list[str] = [
            "=== /proc Virtual Filesystem Demo ===",
            "",
            "/proc is like a magic bulletin board. Nobody writes real papers and",
            "pins them there. When you look at a section, the information appears",
            "automatically from the school's current records.",
            "",
        ]

        # Step 1: List /proc root
        try:
            entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_PROC_LIST, path="/proc")
            lines.append("Step 1: ls /proc — what's on the bulletin board?")
            lines.append(f"  {', '.join(entries)}")
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 1 failed: {e}")
            return "\n".join(lines)

        # Step 2: Read global files
        lines.append("Step 2: Reading global /proc files...")
        for name in ("meminfo", "uptime", "cpuinfo"):
            try:
                content: str = self._kernel.syscall(
                    SyscallNumber.SYS_PROC_READ, path=f"/proc/{name}"
                )
                lines.append(f"  cat /proc/{name}:")
                lines.extend(f"    {line}" for line in content.splitlines())
                lines.append("")
            except SyscallError as e:
                lines.append(f"  /proc/{name} failed: {e}")

        # Step 3: Create a demo process and explore its /proc entry
        demo_pid: int | None = None
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="demo_proc", num_pages=2
            )
            demo_pid = int(str(result["pid"]))
            lines.append(f"Step 3: Created process 'demo_proc' (pid {demo_pid})")
            lines.append("")

            # List the process directory
            proc_entries: list[str] = self._kernel.syscall(
                SyscallNumber.SYS_PROC_LIST, path=f"/proc/{demo_pid}"
            )
            lines.append(f"  ls /proc/{demo_pid}: {', '.join(proc_entries)}")
            lines.append("")

            # Read each file
            for fname in proc_entries:
                content = self._kernel.syscall(
                    SyscallNumber.SYS_PROC_READ, path=f"/proc/{demo_pid}/{fname}"
                )
                lines.append(f"  cat /proc/{demo_pid}/{fname}:")
                lines.extend(f"    {line}" for line in content.splitlines())
                lines.append("")
        except SyscallError as e:
            lines.append(f"Step 3 failed: {e}")

        # Cleanup — dispatch then terminate (process must be RUNNING to terminate)
        if demo_pid is not None:
            try:
                dispatched = self._kernel.syscall(SyscallNumber.SYS_DISPATCH)
                if dispatched is not None:
                    self._kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=demo_pid)
            except (SyscallError, RuntimeError):
                pass

        lines.append("Virtual files are generated live — no disk storage needed!")
        return "\n".join(lines)

    # -- perf command -----------------------------------------------------------

    def _cmd_perf(self, args: list[str]) -> str:
        """Show performance metrics or run a guided demo."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "demo": lambda _a: self._cmd_perf_demo(),
        }
        if args and args[0] in dispatch:
            return dispatch[args[0]](args[1:])
        return self._cmd_perf_summary()

    def _cmd_perf_summary(self) -> str:
        """Format a performance metrics summary."""
        try:
            metrics: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
        except SyscallError as e:
            return f"Error: {e}"
        return (
            "=== PyOS Performance Metrics ===\n"
            f"Context switches:    {metrics['context_switches']}\n"
            f"Processes created:   {metrics['total_created']}\n"
            f"Processes completed: {metrics['total_completed']}\n"
            f"Avg wait time:       {float(str(metrics['avg_wait_time'])):.2f}s\n"
            f"Avg turnaround:      {float(str(metrics['avg_turnaround_time'])):.2f}s\n"
            f"Avg response:        {float(str(metrics['avg_response_time'])):.2f}s\n"
            f"Throughput:          {float(str(metrics['throughput'])):.2f} procs/sec\n"
            f"Migrations:          {metrics['migrations']}"
        )

    def _cmd_perf_demo(self) -> str:
        """Walk through performance metrics with a guided demo."""
        lines: list[str] = [
            "=== Performance Metrics Demo ===",
            "",
            "Imagine a sports day. Every time a runner steps up to the start line,",
            "a helper clicks a stopwatch. When the runner starts, the helper notes",
            "how long they waited. When they finish, we record the total race time.",
            "",
        ]

        # Step 1: Show initial metrics
        try:
            metrics: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append("Step 1: Initial metrics (before any work)")
            lines.append(f"  Context switches:    {metrics['context_switches']}")
            lines.append(f"  Processes created:   {metrics['total_created']}")
            lines.append(f"  Processes completed: {metrics['total_completed']}")
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 1 failed: {e}")
            return "\n".join(lines)

        # Step 2: Create and run a process
        demo_pid: int | None = None
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="perf_demo", num_pages=1
            )
            demo_pid = int(str(result["pid"]))
            self._kernel.syscall(
                SyscallNumber.SYS_EXEC,
                pid=demo_pid,
                program=lambda: "demo output",
            )
            self._kernel.syscall(SyscallNumber.SYS_RUN, pid=demo_pid)

            metrics = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append("Step 2: After creating and running one process")
            lines.append(f"  Context switches:    {metrics['context_switches']}")
            lines.append(f"  Processes completed: {metrics['total_completed']}")
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 2 failed: {e}")

        # Step 3: Create and run multiple processes
        try:
            for name in ("worker_a", "worker_b", "worker_c"):
                r: dict[str, object] = self._kernel.syscall(
                    SyscallNumber.SYS_CREATE_PROCESS, name=name, num_pages=1
                )
                pid = int(str(r["pid"]))
                self._kernel.syscall(
                    SyscallNumber.SYS_EXEC,
                    pid=pid,
                    program=lambda: "batch output",
                )
                self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)

            lines.append("Step 3: After running 3 more processes")
            metrics = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append(f"  Processes created:   {metrics['total_created']}")
            lines.append(f"  Processes completed: {metrics['total_completed']}")
            lines.append(f"  Avg wait time:       {float(str(metrics['avg_wait_time'])):.4f}s")
            lines.append(
                f"  Avg turnaround:      {float(str(metrics['avg_turnaround_time'])):.4f}s"
            )
            lines.append(f"  Avg response:        {float(str(metrics['avg_response_time'])):.4f}s")
            lines.append(
                f"  Throughput:          {float(str(metrics['throughput'])):.2f} procs/sec"
            )
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 3 failed: {e}")

        # Step 4: Explain each metric
        lines.extend(
            [
                "Step 4: What each metric means",
                "  Wait time:       How long a process sat in the READY queue",
                "  Turnaround time: Total time from creation to termination",
                "  Response time:   Time from creation to first CPU dispatch",
                "  Context switches: How many times the CPU switched processes",
                "  Throughput:      Processes completed per second of uptime",
            ]
        )

        return "\n".join(lines)

    # -- strace command ---------------------------------------------------------

    def _append_strace_output(self, output: str) -> str:
        """Append strace entries to output if strace is enabled."""
        if self._kernel.state is not KernelState.RUNNING:
            return output
        status: dict[str, bool] = self._kernel.syscall(SyscallNumber.SYS_STRACE_STATUS)
        if not status["enabled"]:
            return output
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_STRACE_LOG)
        if not entries:
            return output
        self._kernel.syscall(SyscallNumber.SYS_STRACE_CLEAR)
        strace_section = "\n--- strace ---\n" + "\n".join(entries)
        return output + strace_section

    def _cmd_strace(self, args: list[str]) -> str:
        """Syscall tracing — see every request the kernel handles."""
        dispatch: dict[str, Callable[[list[str]], str]] = {
            "on": lambda _a: self._cmd_strace_on(),
            "off": lambda _a: self._cmd_strace_off(),
            "show": lambda _a: self._cmd_strace_show(),
            "clear": lambda _a: self._cmd_strace_clear(),
            "demo": lambda _a: self._cmd_strace_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: strace <on|off|show|clear|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_strace_on(self) -> str:
        """Enable syscall tracing."""
        self._kernel.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        return "Strace enabled."

    def _cmd_strace_off(self) -> str:
        """Disable syscall tracing."""
        self._kernel.syscall(SyscallNumber.SYS_STRACE_DISABLE)
        return "Strace disabled."

    def _cmd_strace_show(self) -> str:
        """Display the current strace log."""
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_STRACE_LOG)
        if not entries:
            return "(strace log is empty)"
        return "\n".join(entries)

    def _cmd_strace_clear(self) -> str:
        """Clear the strace log."""
        self._kernel.syscall(SyscallNumber.SYS_STRACE_CLEAR)
        return "Strace log cleared."

    def _cmd_strace_demo(self) -> str:
        """Walk through strace with a guided demo."""
        lines: list[str] = [
            "=== Strace Demo ===",
            "",
            "Strace is like standing in a kitchen with a clipboard. Normally",
            "you sit in the dining room and just see the food appear. But strace",
            "lets you write down every order the chef (program) makes to the",
            "assistants (kernel): 'Get me flour' -> 'Here's the flour.'",
            "You see every request and every response.",
            "",
        ]

        # Step 1: Enable strace
        self._kernel.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        lines.append("Step 1: Strace enabled — now every syscall is recorded.")
        lines.append("")

        # Step 2: Run some syscalls
        lines.append("Step 2: Making some syscalls...")
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/strace_demo")
            lines.append("  mkdir /strace_demo")
        except SyscallError:
            lines.append("  mkdir /strace_demo (already exists)")

        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/strace_demo/hello.txt")
            self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FILE,
                path="/strace_demo/hello.txt",
                data=b"Hello from strace!",
            )
            lines.append("  write /strace_demo/hello.txt")
        except SyscallError:
            lines.append("  write /strace_demo/hello.txt (error)")

        try:
            self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/strace_demo")
            lines.append("  ls /strace_demo")
        except SyscallError:
            pass

        lines.append("")

        # Step 3: Show the captured trace
        lines.append("Step 3: Here's what strace captured:")
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_STRACE_LOG)
        lines.extend(f"  {entry}" for entry in entries)
        lines.append("")

        # Step 4: Disable and cleanup
        self._kernel.syscall(SyscallNumber.SYS_STRACE_DISABLE)
        lines.append("Step 4: Strace disabled. The log is preserved for review.")

        # Cleanup demo files
        try:
            self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/strace_demo/hello.txt")
            self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/strace_demo")
        except SyscallError:
            pass

        return "\n".join(lines)

    # -- Boot info commands ---------------------------------------------------

    def _cmd_dmesg(self, _args: list[str]) -> str:
        """Show kernel boot messages."""
        messages: list[str] = self._kernel.syscall(SyscallNumber.SYS_DMESG)
        return "\n".join(messages) if messages else "No boot messages."

    # -- Multi-CPU commands ---------------------------------------------------

    def _cmd_cpu(self, _args: list[str]) -> str:
        """Show per-CPU status."""
        try:
            cpu_info: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_CPU_INFO)
        except SyscallError as e:
            return f"Error: {e}"
        lines: list[str] = [f"=== {len(cpu_info)} CPU(s) ==="]
        for info in cpu_info:
            current = info["current"]
            current_str = f"pid {current}" if current is not None else "idle"
            lines.append(
                f"CPU {info['cpu_id']}: policy={info['policy']}"
                f"  ready={info['ready_count']}  current={current_str}"
            )
        return "\n".join(lines)

    def _cmd_taskset(self, args: list[str]) -> str:
        """Show or set CPU affinity for a process."""
        if not args:
            return "Usage: taskset <pid> [cpu_list]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        if len(args) == 1:
            return self._cmd_taskset_show(pid)
        return self._cmd_taskset_set(pid, args[1:])

    def _cmd_taskset_show(self, pid: int) -> str:
        """Display CPU affinity for a process."""
        try:
            affinity: list[int] = self._kernel.syscall(SyscallNumber.SYS_GET_AFFINITY, pid=pid)
        except SyscallError as e:
            return f"Error: {e}"
        return f"PID {pid} affinity: {affinity}"

    def _cmd_taskset_set(self, pid: int, cpu_args: list[str]) -> str:
        """Set CPU affinity for a process."""
        try:
            cpus = [int(c) for c in cpu_args]
        except ValueError:
            return "Error: CPU IDs must be integers"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SET_AFFINITY, pid=pid, cpus=cpus)
        except SyscallError as e:
            return f"Error: {e}"
        return f"PID {pid} affinity set to {cpus}"

    def _cmd_scheduler_balance(self) -> str:
        """Trigger load balancing across CPUs."""
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_BALANCE)
        except SyscallError as e:
            return f"Error: {e}"
        count = result["count"]
        migrations = result["migrations"]
        if not migrations:
            return "Load balanced: 0 migrations (already balanced)"
        lines = [f"Load balanced: {count} migration(s)"]
        for pid, from_cpu, to_cpu in migrations:  # type: ignore[union-attr]
            lines.append(f"  PID {pid}: CPU {from_cpu} → CPU {to_cpu}")
        return "\n".join(lines)

    # -- learn command ----------------------------------------------------------

    def _cmd_learn(self, args: list[str]) -> str:
        """Run an interactive tutorial lesson."""
        runner = TutorialRunner(self._kernel)

        if not args:
            lessons = runner.list_lessons()
            lines = ["Available lessons:"]
            lines.extend(f"  {name}" for name in lessons)
            lines.append("")
            lines.append("Usage: learn <lesson> or learn all")
            return "\n".join(lines)

        if args[0] == "all":
            return runner.run_all()

        try:
            return runner.run(args[0])
        except KeyError:
            return f"Error: unknown lesson '{args[0]}'. Run 'learn' to see available lessons."
