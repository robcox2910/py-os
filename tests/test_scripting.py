"""Tests for shell scripting.

Real shells can execute **scripts** — files containing a sequence of
commands.  This is how system administration, automation, and boot-up
scripts work (``/etc/init.d/*``, ``.bashrc``, cron jobs, etc.).

Our scripting support includes:
    - **Multi-line execution** — run a sequence of commands from a string.
    - **Comments** — lines starting with ``#`` are ignored.
    - **Variable substitution** — ``$VAR`` is replaced with the env value.
    - **Conditionals** — ``if``/``then``/``else``/``fi`` blocks.
    - **source command** — load and execute a script from a file.
"""

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    shell = Shell(kernel=kernel)
    return kernel, shell


# -- Basic script execution ----------------------------------------------------


class TestScriptExecution:
    """Verify running a sequence of commands as a script."""

    def test_run_multiple_commands(self) -> None:
        """A script with multiple lines should execute each in order."""
        _kernel, shell = _booted_shell()
        script = "mkdir /data\ntouch /data/file.txt"
        results = shell.run_script(script)
        result_count = 2
        assert len(results) == result_count

    def test_results_collected(self) -> None:
        """Each command's output should be captured."""
        _kernel, shell = _booted_shell()
        script = "whoami"
        results = shell.run_script(script)
        assert "root" in results[0]

    def test_empty_script(self) -> None:
        """An empty script should produce no results."""
        _kernel, shell = _booted_shell()
        assert shell.run_script("") == []

    def test_blank_lines_skipped(self) -> None:
        """Blank lines should be ignored."""
        _kernel, shell = _booted_shell()
        script = "whoami\n\n\nwhoami"
        results = shell.run_script(script)
        result_count = 2
        assert len(results) == result_count

    def test_commands_execute_in_order(self) -> None:
        """Later commands should see effects of earlier ones."""
        _kernel, shell = _booted_shell()
        script = "mkdir /data\ntouch /data/hello.txt\nls /data"
        results = shell.run_script(script)
        assert "hello.txt" in results[-1]

    def test_error_in_script_continues(self) -> None:
        """Errors in one command should not stop the script."""
        _kernel, shell = _booted_shell()
        script = "cat /nonexistent\nwhoami"
        results = shell.run_script(script)
        result_count = 2
        assert len(results) == result_count
        assert "root" in results[1]


# -- Comments ------------------------------------------------------------------


class TestComments:
    """Lines starting with # should be ignored."""

    def test_comment_line(self) -> None:
        """A comment line should be skipped entirely."""
        _kernel, shell = _booted_shell()
        script = "# This is a comment\nwhoami"
        results = shell.run_script(script)
        assert len(results) == 1
        assert "root" in results[0]

    def test_all_comments(self) -> None:
        """A script of only comments produces no output."""
        _kernel, shell = _booted_shell()
        script = "# comment 1\n# comment 2"
        results = shell.run_script(script)
        assert results == []

    def test_inline_comment_not_stripped(self) -> None:
        """Inline comments are not supported (consistent with simple shells)."""
        _kernel, shell = _booted_shell()
        # "whoami # comment" is treated as command "whoami" with args "# comment"
        script = "whoami # this is not stripped"
        results = shell.run_script(script)
        # The command still runs (whoami ignores extra args)
        assert len(results) == 1


# -- Variable substitution ----------------------------------------------------


class TestVariableSubstitution:
    """$VAR in commands should be replaced with env values."""

    def test_simple_substitution(self) -> None:
        """$HOME should be replaced with its env value."""
        _kernel, shell = _booted_shell()
        script = "export GREETING=hello\necho $GREETING"
        results = shell.run_script(script)
        assert "hello" in results[-1]

    def test_path_substitution(self) -> None:
        """$HOME should expand to /root (boot default)."""
        _kernel, shell = _booted_shell()
        results = shell.run_script("echo $HOME")
        assert "/root" in results[0]

    def test_undefined_var_becomes_empty(self) -> None:
        """An undefined variable should expand to empty string."""
        _kernel, shell = _booted_shell()
        results = shell.run_script("echo $UNDEFINED_VAR")
        # echo with empty arg just returns empty or the remaining text
        assert len(results) == 1

    def test_multiple_vars_in_one_line(self) -> None:
        """Multiple variables on one line should all be expanded."""
        _kernel, shell = _booted_shell()
        results = shell.run_script("echo $USER $HOME")
        assert "root" in results[0]
        assert "/root" in results[0]


# -- Conditionals (if/then/else/fi) -------------------------------------------


class TestConditionals:
    """if/then/else/fi blocks for branching logic."""

    def test_if_true_branch(self) -> None:
        """When condition succeeds, the then-block should execute."""
        _kernel, shell = _booted_shell()
        script = "mkdir /data\nif ls /data\nthen\ntouch /data/ok.txt\nfi"
        shell.run_script(script)
        kernel = shell._kernel
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/data")
        assert "ok.txt" in result

    def test_if_false_else_branch(self) -> None:
        """When condition fails, the else-block should execute."""
        _kernel, shell = _booted_shell()
        script = "if ls /nonexistent\nthen\ntouch /yes.txt\nelse\ntouch /no.txt\nfi"
        shell.run_script(script)
        kernel = shell._kernel
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "no.txt" in result

    def test_if_true_skips_else(self) -> None:
        """When condition succeeds, else-block should NOT execute."""
        _kernel, shell = _booted_shell()
        script = "mkdir /data\nif ls /data\nthen\ntouch /yes.txt\nelse\ntouch /no.txt\nfi"
        shell.run_script(script)
        kernel = shell._kernel
        root_contents = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "yes.txt" in root_contents
        assert "no.txt" not in root_contents

    def test_if_without_else(self) -> None:
        """if/then/fi without else should work when condition is true."""
        _kernel, shell = _booted_shell()
        script = "mkdir /test\nif ls /test\nthen\ntouch /test/ok.txt\nfi"
        shell.run_script(script)
        kernel = shell._kernel
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/test")
        assert "ok.txt" in result

    def test_if_false_without_else(self) -> None:
        """if/then/fi without else should do nothing when condition fails."""
        _kernel, shell = _booted_shell()
        script = "if ls /nonexistent\nthen\ntouch /shouldnt_exist.txt\nfi"
        shell.run_script(script)
        kernel = shell._kernel
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/")
        assert "shouldnt_exist.txt" not in result


# -- Source command (run script from file) -------------------------------------


class TestSourceCommand:
    """The source command loads and runs a script from a file."""

    def test_source_from_file(self) -> None:
        """Source should execute commands stored in a file."""
        kernel, shell = _booted_shell()
        # Write a script to a file
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/setup.sh")
        kernel.syscall(
            SyscallNumber.SYS_WRITE_FILE,
            path="/setup.sh",
            data=b"mkdir /data\ntouch /data/readme.txt",
        )
        shell.execute("source /setup.sh")
        result = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/data")
        assert "readme.txt" in result

    def test_source_missing_file(self) -> None:
        """Source of a missing file should report an error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("source /nonexistent.sh")
        assert "Error" in result

    def test_source_usage(self) -> None:
        """Source without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("source")
        assert "Usage" in result


# -- Echo command (needed for variable substitution) ---------------------------


class TestEcho:
    """Echo command outputs its arguments."""

    def test_echo_simple(self) -> None:
        """Echo should return its arguments joined by spaces."""
        _kernel, shell = _booted_shell()
        result = shell.execute("echo hello world")
        assert result == "hello world"

    def test_echo_empty(self) -> None:
        """Echo with no args should return empty string."""
        _kernel, shell = _booted_shell()
        result = shell.execute("echo")
        assert result == ""

    def test_help_includes_echo(self) -> None:
        """Help should list the echo command."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "echo" in result

    def test_help_includes_source(self) -> None:
        """Help should list the source command."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "source" in result
