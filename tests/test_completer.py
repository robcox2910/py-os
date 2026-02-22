"""Tests for the tab-completion engine.

The Completer class provides context-aware completion for the PyOS
shell.  Its logic is pure (no I/O) — it analyses the input line and
returns candidate strings, making it fully testable without readline.
"""

from unittest.mock import patch

from py_os.completer import Completer
from py_os.kernel import Kernel
from py_os.shell import Shell


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# ---------------------------------------------------------------------------
# Cycle 1 — command name completion
# ---------------------------------------------------------------------------


class TestCommandCompletion:
    """Verify completion of command names (first word on the line)."""

    def test_empty_line_returns_all_commands(self) -> None:
        """Pressing Tab on a blank line should list every command."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "")
        assert set(candidates) == set(shell.command_names)

    def test_partial_match(self) -> None:
        """A partial prefix should return only matching commands."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("ls", "ls")
        assert "ls" in candidates
        assert "lsfd" in candidates
        # Commands that don't start with "ls" should be absent.
        assert "cat" not in candidates

    def test_unique_prefix(self) -> None:
        """A prefix matching exactly one command should return just that."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("hel", "hel")
        assert candidates == ["help"]

    def test_no_match_returns_empty(self) -> None:
        """An unrecognised prefix should return no candidates."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("zzz", "zzz")
        assert candidates == []

    def test_second_word_not_confused_for_command(self) -> None:
        """Typing after a space should not offer command completions."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        # "echo " + text "he" — should NOT complete to "help"
        candidates = completer.completions("he", "echo he")
        assert "help" not in candidates


# ---------------------------------------------------------------------------
# Cycle 2 — subcommand completion
# ---------------------------------------------------------------------------


class TestSubcommandCompletion:
    """Verify completion of subcommands for commands that have them."""

    def test_scheduler_subcommands(self) -> None:
        """'scheduler ' should offer scheduler policy names."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "scheduler ")
        assert "fcfs" in candidates
        assert "cfs" in candidates
        assert "boost" in candidates

    def test_mutex_subcommands(self) -> None:
        """'mutex ' should offer create and list."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "mutex ")
        assert sorted(candidates) == ["create", "list"]

    def test_journal_subcommands(self) -> None:
        """'journal ' should offer status, checkpoint, recover, crash."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "journal ")
        assert sorted(candidates) == ["checkpoint", "crash", "recover", "status"]

    def test_partial_subcommand(self) -> None:
        """A partial prefix should filter subcommands."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("cr", "mutex cr")
        assert candidates == ["create"]

    def test_unknown_command_no_subcommands(self) -> None:
        """A command without subcommands should not offer them."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "echo ")
        assert candidates == []


# ---------------------------------------------------------------------------
# Cycle 3 — path completion
# ---------------------------------------------------------------------------


class TestPathCompletion:
    """Verify completion of filesystem paths."""

    def test_root_entries(self) -> None:
        """'ls /' should list root directory entries with '/' prefix."""
        _kernel, shell = _booted_shell()
        # Create some files so there are entries to complete
        shell.execute("mkdir /data")
        shell.execute("touch /hello.txt")

        completer = Completer(shell)
        candidates = completer.completions("/", "ls /")
        assert "/data/" in candidates
        assert "/hello.txt" in candidates

    def test_partial_path_match(self) -> None:
        """A partial name should filter to matching entries."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /alpha.txt")
        shell.execute("touch /beta.txt")

        completer = Completer(shell)
        candidates = completer.completions("/al", "cat /al")
        assert "/alpha.txt" in candidates
        assert "/beta.txt" not in candidates

    def test_subdirectory_completion(self) -> None:
        """Paths within a subdirectory should complete."""
        _kernel, shell = _booted_shell()
        shell.execute("mkdir /docs")
        shell.execute("touch /docs/readme.txt")

        completer = Completer(shell)
        candidates = completer.completions("/docs/r", "cat /docs/r")
        assert "/docs/readme.txt" in candidates

    def test_directory_gets_slash_suffix(self) -> None:
        """Completed directories should have a trailing '/'."""
        _kernel, shell = _booted_shell()
        shell.execute("mkdir /mydir")

        completer = Completer(shell)
        candidates = completer.completions("/my", "ls /my")
        assert "/mydir/" in candidates

    def test_no_matches_returns_empty(self) -> None:
        """Nonexistent path prefix should return no candidates."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("/zzz", "ls /zzz")
        assert candidates == []


# ---------------------------------------------------------------------------
# Cycle 4 — program name completion
# ---------------------------------------------------------------------------


class TestProgramCompletion:
    """Verify completion of program names after 'run'."""

    def test_run_lists_programs(self) -> None:
        """'run ' should list all built-in program names."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "run ")
        assert "hello" in candidates
        assert "counter" in candidates

    def test_run_partial_match(self) -> None:
        """A partial prefix after 'run' should filter programs."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("he", "run he")
        assert candidates == ["hello"]

    def test_run_no_match(self) -> None:
        """An unrecognised program prefix should return nothing."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("zzz", "run zzz")
        assert candidates == []


# ---------------------------------------------------------------------------
# Cycle 5 — env vars, signals, readline state interface
# ---------------------------------------------------------------------------


class TestSpecialCompletion:
    """Verify environment variable, signal, and readline state completion."""

    def test_unset_completes_env_vars(self) -> None:
        """'unset ' should offer environment variable names."""
        _kernel, shell = _booted_shell()
        shell.execute("export GREETING=hello")
        shell.execute("export COLOR=blue")

        completer = Completer(shell)
        candidates = completer.completions("", "unset ")
        assert "GREETING" in candidates
        assert "COLOR" in candidates

    def test_signal_names_after_pid(self) -> None:
        """'signal 1 ' should offer signal names."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("SIG", "signal 1 SIG")
        assert "SIGTERM" in candidates
        assert "SIGKILL" in candidates

    def test_dollar_prefix_completes_env_vars(self) -> None:
        """'$' prefix in any position should complete env var names."""
        _kernel, shell = _booted_shell()
        shell.execute("export MY_VAR=test")

        completer = Completer(shell)
        candidates = completer.completions("$MY", "echo $MY")
        assert "$MY_VAR" in candidates

    def test_readline_complete_state_interface(self) -> None:
        """complete() should return candidates by state index and None when done."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)

        with patch("readline.get_line_buffer", return_value="hel"):
            result_0 = completer.complete("hel", 0)
            result_1 = completer.complete("hel", 1)
            assert result_0 == "help"
            assert result_1 is None

    def test_handle_completes_signals(self) -> None:
        """'handle 1 ' should offer signal names."""
        _kernel, shell = _booted_shell()
        completer = Completer(shell)
        candidates = completer.completions("", "handle 1 ")
        assert "SIGTERM" in candidates
        assert "SIGUSR1" in candidates
