"""Tests for shell pipe support and the grep command.

Pipes let users chain commands: the output of one becomes the input
of the next. ``ls | grep foo`` runs ``ls``, then filters its output
through ``grep foo``.
"""

from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


class TestPipeParsing:
    """Verify that the shell correctly splits pipes."""

    def test_single_command_no_pipe(self) -> None:
        """A command without pipes should work as before."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "help" in result

    def test_two_command_pipe(self) -> None:
        """Output of first command should feed into second."""
        _kernel, shell = _booted_shell()
        # help lists commands; grep for "ps"
        result = shell.execute("help | grep ps")
        assert "ps" in result

    def test_pipe_filters_output(self) -> None:
        """Grep should filter lines that don't match."""
        kernel, shell = _booted_shell()
        # Create some files so ls has multiple entries
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/alpha.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/beta.txt")
        result = shell.execute("ls / | grep alpha")
        assert "alpha" in result
        assert "beta" not in result

    def test_three_command_pipe(self) -> None:
        """Pipes should chain through three commands."""
        _kernel, shell = _booted_shell()
        # help | grep ps | grep ps — should still find ps
        result = shell.execute("help | grep ps | grep ps")
        assert "ps" in result

    def test_pipe_with_empty_output(self) -> None:
        """If first command returns empty, second gets empty input."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help | grep ZZZZNOTFOUND")
        assert result == ""

    def test_pipe_preserves_error(self) -> None:
        """If a piped command fails, the error should propagate."""
        _kernel, shell = _booted_shell()
        result = shell.execute("notacommand | grep foo")
        assert "unknown" in result.lower()


class TestGrepCommand:
    """Verify the built-in grep command."""

    def test_grep_filters_matching_lines(self) -> None:
        """Grep should only return lines containing the pattern."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help | grep ps")
        assert "ps" in result

    def test_grep_no_match_returns_empty(self) -> None:
        """Grep with no matching lines should return empty."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help | grep ZZZZNOTFOUND")
        assert result == ""

    def test_grep_without_pipe_shows_usage(self) -> None:
        """Grep without piped input and no args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("grep")
        assert "usage" in result.lower()

    def test_grep_case_sensitive(self) -> None:
        """Grep should be case-sensitive by default."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help | grep PS")
        # "PS" uppercase should NOT match "ps" lowercase
        assert "ps" not in result.lower() or result == ""

    def test_help_includes_grep(self) -> None:
        """Help should list the grep command."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "grep" in result


class TestWcCommand:
    """Verify the built-in wc (word count) command."""

    def test_wc_counts_lines(self) -> None:
        """Wc should count lines from piped input."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help | wc")
        # help produces 1 line of output, wc should report it
        assert "1" in result

    def test_wc_with_multiple_lines(self) -> None:
        """Wc should count multiple piped lines."""
        kernel, shell = _booted_shell()
        # Create files so ls has entries
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/a.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/b.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/c.txt")
        result = shell.execute("ls / | wc")
        # At least 3 lines
        count = int(result.strip().split()[0])
        min_lines = 3
        assert count >= min_lines

    def test_wc_no_input(self) -> None:
        """Wc without piped input should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("wc")
        assert "usage" in result.lower()

    def test_help_includes_wc(self) -> None:
        """Help should list the wc command."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "wc" in result
