"""Tests for I/O redirection (>, >>, <, 2>).

Redirection lets users route command output to files and read command
input from files, just like a real Unix shell.  It's a shell-only
feature that reuses existing file I/O syscalls.
"""

from py_os.kernel import Kernel
from py_os.shell import Shell, _Redirections
from py_os.syscalls import SyscallNumber


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# ---------------------------------------------------------------------------
# Cycle 1 — Parsing
# ---------------------------------------------------------------------------


class TestRedirectionParsing:
    """Verify _parse_redirections() extracts operators and cleans the command."""

    def test_no_redirections(self) -> None:
        """A plain command returns unchanged with empty redirections."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("echo hello world")
        assert cmd == "echo hello world"
        assert redir == _Redirections()

    def test_stdout_redirect(self) -> None:
        """``>`` extracts the stdout target file."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("echo hello > /out.txt")
        assert cmd == "echo hello"
        assert redir.stdout == "/out.txt"
        assert redir.append is False

    def test_append_redirect(self) -> None:
        """``>>`` extracts the stdout target with append=True."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("echo hello >> /out.txt")
        assert cmd == "echo hello"
        assert redir.stdout == "/out.txt"
        assert redir.append is True

    def test_stdin_redirect(self) -> None:
        """``<`` extracts the stdin source file."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("grep pattern < /input.txt")
        assert cmd == "grep pattern"
        assert redir.stdin == "/input.txt"

    def test_stderr_redirect(self) -> None:
        """``2>`` extracts the stderr target file."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("ls /nope 2> /err.txt")
        assert cmd == "ls /nope"
        assert redir.stderr == "/err.txt"

    def test_combined_stdout_and_stderr(self) -> None:
        """``>`` and ``2>`` can appear in the same command."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("ls / > /out.txt 2> /err.txt")
        assert cmd == "ls /"
        assert redir.stdout == "/out.txt"
        assert redir.stderr == "/err.txt"

    def test_combined_stdin_and_stdout(self) -> None:
        """``<`` and ``>`` can appear in the same command."""
        _kernel, shell = _booted_shell()
        cmd, redir = shell._parse_redirections("grep txt < /in.txt > /out.txt")
        assert cmd == "grep txt"
        assert redir.stdin == "/in.txt"
        assert redir.stdout == "/out.txt"


# ---------------------------------------------------------------------------
# Cycle 2 — Output redirection (>)
# ---------------------------------------------------------------------------


class TestOutputRedirection:
    """Verify ``>`` writes command output to a file."""

    def test_echo_to_file(self) -> None:
        """``echo hello > /out.txt`` write 'hello' into the file."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/out.txt")
        result = shell.execute("echo hello > /out.txt")
        assert result == ""  # output redirected, nothing displayed
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/out.txt")
        assert data.decode() == "hello"

    def test_creates_file_if_missing(self) -> None:
        """``>`` create the file when it doesn't already exist."""
        kernel, shell = _booted_shell()
        result = shell.execute("echo new > /created.txt")
        assert result == ""
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/created.txt")
        assert data.decode() == "new"

    def test_overwrites_existing_content(self) -> None:
        """``>`` overwrite whatever was in the file before."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/out.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/out.txt", data=b"old")
        shell.execute("echo new > /out.txt")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/out.txt")
        assert data.decode() == "new"

    def test_ls_to_file(self) -> None:
        """``ls / > /listing.txt`` capture directory listing in a file."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/hello.txt")
        result = shell.execute("ls / > /listing.txt")
        assert result == ""
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/listing.txt")
        assert "hello.txt" in data.decode()

    def test_empty_output_writes_empty_file(self) -> None:
        """Redirecting a command with empty output write an empty string."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/empty")
        result = shell.execute("ls /empty > /out.txt")
        assert result == ""
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/out.txt")
        assert data.decode() == ""

    def test_redirect_returns_empty(self) -> None:
        """When output is redirected, the shell return empty string."""
        _kernel, shell = _booted_shell()
        result = shell.execute("echo hello > /out.txt")
        assert result == ""


# ---------------------------------------------------------------------------
# Cycle 3 — Append redirection (>>)
# ---------------------------------------------------------------------------


class TestAppendRedirection:
    """Verify ``>>`` appends command output to a file."""

    def test_append_to_existing_file(self) -> None:
        """``>>`` append to the end of an existing file."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/log.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/log.txt", data=b"line1\n")
        shell.execute("echo line2 >> /log.txt")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/log.txt")
        assert data.decode() == "line1\nline2"

    def test_append_creates_file_if_missing(self) -> None:
        """``>>`` create the file if it doesn't exist."""
        kernel, shell = _booted_shell()
        shell.execute("echo first >> /new.txt")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/new.txt")
        assert data.decode() == "first"

    def test_multiple_appends_accumulate(self) -> None:
        """Multiple ``>>`` commands build up the file content."""
        kernel, shell = _booted_shell()
        shell.execute("echo a >> /acc.txt")
        shell.execute("echo b >> /acc.txt")
        shell.execute("echo c >> /acc.txt")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/acc.txt")
        assert data.decode() == "abc"

    def test_append_returns_empty(self) -> None:
        """``>>`` return empty string (output redirected)."""
        _kernel, shell = _booted_shell()
        result = shell.execute("echo hello >> /out.txt")
        assert result == ""


# ---------------------------------------------------------------------------
# Cycle 4 — Input redirection (<)
# ---------------------------------------------------------------------------


class TestInputRedirection:
    """Verify ``<`` feeds file content into pipe-aware commands."""

    def test_grep_with_input_redirect(self) -> None:
        """``grep pattern < /file.txt`` filter lines from the file."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/data.txt")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/data.txt",
            data=b"apple\nbanana\napricot",
        )
        result = shell.execute("grep ap < /data.txt")
        assert "apple" in result
        assert "apricot" in result
        assert "banana" not in result

    def test_wc_with_input_redirect(self) -> None:
        """``wc < /file.txt`` count lines in the file."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/data.txt")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/data.txt",
            data=b"one\ntwo\nthree",
        )
        result = shell.execute("wc < /data.txt")
        assert "3 lines" in result

    def test_input_redirect_file_not_found(self) -> None:
        """``< /missing.txt`` produce an error when the file doesn't exist."""
        _kernel, shell = _booted_shell()
        result = shell.execute("grep x < /missing.txt")
        assert result.startswith("Error:")

    def test_cat_ignores_input_redirect(self) -> None:
        """``cat`` reads its arg, so ``<`` loads into _pipe_input which cat ignores."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/a.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/a.txt", data=b"aaa")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/b.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/b.txt", data=b"bbb")
        # cat reads /a.txt from its arg; < /b.txt populates _pipe_input
        result = shell.execute("cat /a.txt < /b.txt")
        assert result == "aaa"

    def test_input_redirect_with_output_redirect(self) -> None:
        """``< /in.txt > /out.txt`` combine input and output redirection."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/in.txt")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/in.txt",
            data=b"hello\nworld\nhello again",
        )
        result = shell.execute("grep hello < /in.txt > /out.txt")
        assert result == ""
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/out.txt")
        assert "hello" in data.decode()
        assert "world" not in data.decode()


# ---------------------------------------------------------------------------
# Cycle 5 — Error redirection (2>)
# ---------------------------------------------------------------------------


class TestErrorRedirection:
    """Verify ``2>`` captures error output to a file."""

    def test_error_captured_to_file(self) -> None:
        """An error from a failing command is written to the 2> file."""
        kernel, shell = _booted_shell()
        result = shell.execute("cat /nope 2> /err.txt")
        assert result == ""  # error was redirected
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/err.txt")
        assert "Error:" in data.decode()

    def test_non_error_ignores_stderr_redirect(self) -> None:
        """Successful output is NOT captured by 2>."""
        _kernel, shell = _booted_shell()
        result = shell.execute("echo hello 2> /err.txt")
        assert result == "hello"  # normal output returned

    def test_unknown_command_captured_by_stderr(self) -> None:
        """``Unknown command:`` messages are captured by 2>."""
        kernel, shell = _booted_shell()
        result = shell.execute("nosuchcmd 2> /err.txt")
        assert result == ""
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/err.txt")
        assert "Unknown command:" in data.decode()

    def test_combined_stdout_and_stderr_redirect(self) -> None:
        """``> /out.txt 2> /err.txt`` route success and errors separately."""
        kernel, shell = _booted_shell()
        # Successful command — output goes to stdout file
        shell.execute("echo ok > /out.txt 2> /err.txt")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/out.txt")
        assert data.decode() == "ok"

    def test_error_redirect_creates_file(self) -> None:
        """``2>`` create the target file if it doesn't exist."""
        kernel, shell = _booted_shell()
        shell.execute("cat /nope 2> /newerr.txt")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/newerr.txt")
        assert "Error:" in data.decode()


# ---------------------------------------------------------------------------
# Cycle 6 — Interactions
# ---------------------------------------------------------------------------


class TestRedirectionInteractions:
    """Verify redirection works with pipes, scripts, ``&``, and history."""

    def test_pipe_then_redirect(self) -> None:
        """Redirect the last stage of a pipeline to a file."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/a.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/b.txt")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/c.log")
        result = shell.execute("ls / | grep txt > /matches.txt")
        assert result == ""
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/matches.txt")
        content = data.decode()
        assert "a.txt" in content
        assert "b.txt" in content
        assert "c.log" not in content

    def test_script_with_redirect(self) -> None:
        """Redirection work inside scripts executed via run_script."""
        kernel, shell = _booted_shell()
        script = "echo hello > /out.txt\necho world >> /out.txt"
        shell.run_script(script)
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/out.txt")
        assert data.decode() == "helloworld"

    def test_background_with_redirect_is_error(self) -> None:
        """Combining ``&`` with redirection produce an error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("echo hello > /out.txt &")
        assert "Error:" in result
        assert "redirection" in result

    def test_history_records_full_command(self) -> None:
        """History record the complete command including redirection operators."""
        _kernel, shell = _booted_shell()
        shell.execute("echo hello > /out.txt")
        result = shell.execute("history")
        assert "> /out.txt" in result

    def test_source_with_redirect(self) -> None:
        """Redirection work inside scripts loaded via ``source``."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/setup.sh")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/setup.sh",
            data=b"echo line1 > /result.txt\necho line2 >> /result.txt",
        )
        shell.execute("source /setup.sh")
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/result.txt")
        assert data.decode() == "line1line2"
