"""Context-aware tab completer for the PyOS shell.

The completer separates **what to complete** (pure logic, fully
testable) from **how to wire it** (readline integration in the REPL).

The ``complete(text, state)`` method is the readline callback.  It
delegates to ``completions(text, line)`` which analyses the input
context and returns a list of candidate strings.
"""

from __future__ import annotations

import readline
from typing import TYPE_CHECKING

from py_os.process.signals import Signal
from py_os.syscalls import SyscallError, SyscallNumber

if TYPE_CHECKING:
    from py_os.kernel import Kernel
    from py_os.shell import Shell

# Commands whose argument is a filesystem path.
_PATH_COMMANDS: frozenset[str] = frozenset(
    ["ls", "cat", "rm", "mkdir", "touch", "write", "source", "stat", "readlink", "ln", "open", "cd"]
)

# Commands that accept subcommands as a second word.
_SUBCOMMANDS: dict[str, list[str]] = {
    "scheduler": ["fcfs", "rr", "priority", "aging", "mlfq", "cfs", "boost", "balance"],
    "mutex": ["create", "list"],
    "semaphore": ["create", "list"],
    "journal": ["status", "checkpoint", "recover", "crash"],
    "rwlock": ["create", "list"],
    "pi": ["demo", "status"],
    "ordering": ["register", "status", "mode", "violations", "demo"],
    "shm": ["create", "attach", "detach", "write", "read", "list", "destroy", "demo"],
    "dns": ["register", "lookup", "remove", "list", "flush", "demo"],
    "socket": ["create", "bind", "listen", "connect", "accept", "send", "recv", "close", "list"],
    "http": ["demo"],
    "tcp": ["listen", "connect", "send", "recv", "close", "info", "list", "demo"],
    "proc": ["demo"],
    "perf": ["demo"],
    "strace": ["on", "off", "show", "clear", "demo"],
    "learn": [
        "processes",
        "memory",
        "filesystem",
        "scheduling",
        "signals",
        "ipc",
        "networking",
        "tcp",
        "all",
    ],
}

# Minimum number of words needed before signal name completion kicks in.
_MIN_WORDS_FOR_SIGNAL = 2


class Completer:
    """Context-aware tab completer for the PyOS shell."""

    def __init__(self, shell: Shell) -> None:
        """Create a completer attached to a shell instance.

        Args:
            shell: The shell whose commands, kernel, and programs
                   are used to generate completion candidates.

        """
        self._shell = shell
        self._kernel: Kernel = shell.kernel

    def complete(self, text: str, state: int) -> str | None:
        """Readline callback — return the *state*-th candidate for *text*.

        Args:
            text: The partial word being completed.
            state: Index into the candidate list (0, 1, 2, …).

        Returns:
            The candidate at *state*, or ``None`` when exhausted.

        """
        line = readline.get_line_buffer()
        candidates = self.completions(text, line)
        if state < len(candidates):
            return candidates[state]
        return None

    def completions(self, text: str, line: str) -> list[str]:
        """Return completion candidates based on context.

        Args:
            text: The partial word under the cursor.
            line: The full input line so far.

        Returns:
            Sorted list of matching candidates.

        """
        words = line.lstrip().split()

        # No words yet, or still typing the first word → command completion
        if not words or (len(words) == 1 and not line.endswith(" ")):
            return self._complete_commands(text)

        return self._complete_argument(words, text, line)

    # -- private completers ------------------------------------------------

    def _complete_argument(  # noqa: PLR0911
        self, words: list[str], text: str, line: str
    ) -> list[str]:
        """Dispatch argument completion based on the command and context."""
        cmd = words[0]

        # Second word for commands that have subcommands
        if cmd in _SUBCOMMANDS and (
            len(words) == 1 or (len(words) == _MIN_WORDS_FOR_SIGNAL and not line.endswith(" "))
        ):
            return self._complete_subcommands(cmd, text)

        # After 'run' → program names
        if cmd == "run":
            return self._complete_programs(text)

        # After 'unset' → env var names
        if cmd == "unset":
            return self._complete_env_vars(text)

        # After 'signal'/'handle' with pid already given → signal names
        if cmd in ("signal", "handle") and len(words) >= _MIN_WORDS_FOR_SIGNAL:
            return self._complete_signals(text)

        # Dollar-prefix in any position → env var names with $ prefix
        if text.startswith("$"):
            return self._complete_dollar_vars(text)

        # Text starts with / or command takes paths → path completion
        if text.startswith("/") or cmd in _PATH_COMMANDS:
            return self._complete_paths(text)

        return []

    def _complete_commands(self, text: str) -> list[str]:
        """Complete command names from the shell's dispatch table."""
        return [cmd for cmd in self._shell.command_names if cmd.startswith(text)]

    @staticmethod
    def _complete_subcommands(cmd: str, text: str) -> list[str]:
        """Complete subcommands for a command that has them."""
        return sorted(sub for sub in _SUBCOMMANDS[cmd] if sub.startswith(text))

    def _complete_paths(self, text: str) -> list[str]:
        """Complete filesystem paths.

        Split the partial path into a directory and a name prefix,
        list the directory via SYS_LIST_DIR, and filter by prefix.
        Directories get a trailing ``/`` suffix.

        For /proc paths, use SYS_PROC_LIST instead of SYS_LIST_DIR.
        """
        if "/" not in text:
            return []

        # Split "/foo/ba" into dir="/foo" prefix="ba"
        last_slash = text.rfind("/")
        directory = text[: last_slash + 1] or "/"
        prefix = text[last_slash + 1 :]

        syscall = (
            SyscallNumber.SYS_PROC_LIST
            if directory.startswith("/proc")
            else SyscallNumber.SYS_LIST_DIR
        )
        try:
            entries: list[str] = self._kernel.syscall(syscall, path=directory)
        except SyscallError:
            return []

        candidates: list[str] = []
        for entry in entries:
            if entry.startswith(prefix):
                full = f"{directory.rstrip('/')}/{entry}"
                # Check if this entry is itself a directory
                if self._is_directory(full):
                    full += "/"
                candidates.append(full)

        return sorted(candidates)

    def _is_directory(self, path: str) -> bool:
        """Return True if *path* is a directory in the filesystem."""
        syscall = (
            SyscallNumber.SYS_PROC_LIST if path.startswith("/proc") else SyscallNumber.SYS_LIST_DIR
        )
        try:
            self._kernel.syscall(syscall, path=path)
        except (SyscallError, NotADirectoryError):
            return False
        return True

    def _complete_programs(self, text: str) -> list[str]:
        """Complete built-in program names after 'run'."""
        return [name for name in self._shell.builtin_program_names if name.startswith(text)]

    def _complete_env_vars(self, text: str) -> list[str]:
        """Complete environment variable names (without $ prefix)."""
        try:
            items: list[tuple[str, str]] = self._kernel.syscall(SyscallNumber.SYS_LIST_ENV)
        except SyscallError:
            return []
        return sorted(key for key, _val in items if key.startswith(text))

    def _complete_dollar_vars(self, text: str) -> list[str]:
        """Complete $VAR references with the dollar prefix."""
        prefix = text[1:]  # strip leading $
        try:
            items: list[tuple[str, str]] = self._kernel.syscall(SyscallNumber.SYS_LIST_ENV)
        except SyscallError:
            return []
        return sorted(f"${key}" for key, _val in items if key.startswith(prefix))

    @staticmethod
    def _complete_signals(text: str) -> list[str]:
        """Complete signal names from the Signal enum."""
        return sorted(sig.name for sig in Signal if sig.name.startswith(text))
