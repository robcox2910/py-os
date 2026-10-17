"""The shell's engine -- everything except the commands themselves.

``ShellBase`` reads a command line, expands variables and aliases, handles
pipes, redirections and background jobs, runs little scripts (``if``,
``while``, ``for``), and finally looks the command up in its dispatch table.
The commands live in :mod:`py_os.shell.commands`, one module per topic --
like a toolbox with a separate drawer for each kind of tool.
"""

import contextlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from py_os.jobs import JobManager, JobStatus
from py_os.kernel import Kernel, KernelState
from py_os.syscalls import SyscallError, SyscallNumber

# Type alias for a command handler: takes a list of args, returns output.
type _Handler = Callable[[list[str]], str]

# Safety limit for while/for loops — prevents infinite loops in scripts.
MAX_LOOP_ITERATIONS = 1000
DEFAULT_PAGE_SIZE = 256
ASCII_PRINTABLE_MIN = 32
ASCII_PRINTABLE_MAX = 127
MIN_CONTAINER_EXEC_ARGS = 2


@dataclass
class Redirections:
    """Parsed I/O redirection operators from a command string."""

    stdin: str | None = None  # < file
    stdout: str | None = None  # > file or >> file
    stderr: str | None = None  # 2> file
    append: bool = False  # >> vs >


class ShellBase:
    """The shell engine shared by every command group (see :class:`py_os.shell.Shell`)."""

    # Each command group fills this in: command name -> handler method.
    COMMANDS: ClassVar[tuple[tuple[str, Callable[..., str]], ...]] = ()

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

        # Command dispatch table -- built from every command group's
        # COMMANDS registry, so adding a command means writing a method and
        # adding one entry to its group's table.
        self._commands: dict[str, _Handler] = {}
        for group in reversed(type(self).__mro__):
            for name, handler in vars(group).get("COMMANDS", ()):
                self._commands[name] = getattr(self, handler.__name__)

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
        if len(stages) > 1 and any(stage == "" for stage in stages):
            return "Error: empty pipe segment"
        output = ""
        for i, stage in enumerate(stages):
            self._pipe_input = output if i > 0 else ""
            expanded = self._expand_alias(stage)
            try:
                cmd, redirects = self._parse_redirections(expanded)
            except ValueError as e:
                output = f"Error: {e}"
                break

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
        while iterations < MAX_LOOP_ITERATIONS:
            cond_expanded = self._expand_variables(condition_raw)
            cond_result = self.execute(cond_expanded)
            if cond_result.startswith("Error:"):
                break
            results.extend(self.run_script(body_script))
            iterations += 1
        if iterations >= MAX_LOOP_ITERATIONS:
            results.append(f"Error: loop exceeded {MAX_LOOP_ITERATIONS} iterations limit")
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
            if iteration >= MAX_LOOP_ITERATIONS:
                results.append(f"Error: loop exceeded {MAX_LOOP_ITERATIONS} iterations limit")
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
            expanded = self._aliases[parts[0]]
            if len(parts) > 1:
                expanded += " " + " ".join(parts[1:])
            return expanded
        return command

    def _parse_redirections(self, command: str) -> tuple[str, Redirections]:
        """Extract redirection operators from a command string.

        Processing order: ``2>`` before ``>>`` before ``>`` before ``<``
        to avoid ambiguity (e.g. ``2>`` must not leave a stray ``2``).

        Raises:
            ValueError: If a redirect operator has no filename.

        """
        redirects = Redirections()
        remaining = command

        # 2> (must check before > to avoid 2 being left as an arg)
        if match := re.search(r"2>\s*(\S+)", remaining):
            redirects.stderr = match.group(1)
            remaining = remaining[: match.start()] + remaining[match.end() :]
        elif re.search(r"2>\s*$", remaining):
            msg = "missing filename after 2>"
            raise ValueError(msg)

        # >> (must check before >)
        if match := re.search(r">>\s*(\S+)", remaining):
            redirects.stdout = match.group(1)
            redirects.append = True
            remaining = remaining[: match.start()] + remaining[match.end() :]

        # >
        elif match := re.search(r">\s*(\S+)", remaining):
            redirects.stdout = match.group(1)
            remaining = remaining[: match.start()] + remaining[match.end() :]

        elif re.search(r">>?\s*$", remaining):
            msg = "missing filename after >"
            raise ValueError(msg)

        # <
        if match := re.search(r"<\s*(\S+)", remaining):
            redirects.stdin = match.group(1)
            remaining = remaining[: match.start()] + remaining[match.end() :]
        elif re.search(r"<\s*$", remaining):
            msg = "missing filename after <"
            raise ValueError(msg)

        return remaining.strip(), redirects

    def _apply_input_redirect(self, path: str) -> str:
        """Read a file for input redirection (``<``)."""
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=path)
            return data.decode()
        except SyscallError as e:
            return f"Error: {e}"

    def _apply_output_redirect(self, output: str, redirects: Redirections) -> str:
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

    def _create_and_run_program(self, args: list[str]) -> tuple[int, str, int] | str:
        """Parse args, look up built-in program, create/exec/run via syscalls.

        Returns:
            ``(pid, output, exit_code)`` on success, or an error string.

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
            pid: int = result["pid"]
            self._kernel.syscall(SyscallNumber.SYS_EXEC, pid=pid, program=program)
            run_result = self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
            output: str = run_result["output"]
            exit_code: int = run_result["exit_code"]
            return (pid, output, exit_code)
        except SyscallError as e:
            return f"Error: {e}"

    def _run_background(self, args: list[str]) -> str:
        """Run a program in the background, capturing output into a job.

        Same create/exec/run flow as ``_cmd_run``, but output is stored
        in a job instead of returned directly.  The user gets a
        ``[job_id] pid`` notification and retrieves output via ``fg``
        or ``waitjob``.
        """
        result = self._create_and_run_program(args)
        if isinstance(result, str):
            return result
        pid, output, exit_code = result
        job = self._jobs.add(pid=pid, name=args[0])
        job.status = JobStatus.DONE
        job.output = f"{output}\n[exit code: {exit_code}]"
        job.exit_code = exit_code
        return f"[{job.job_id}] {pid}"

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

    _DASHBOARD_BAR_WIDTH = 30
