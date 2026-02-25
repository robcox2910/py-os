"""Tests for command history and aliases.

The shell records every command for recall, and supports aliases
that expand shorthand names into full commands.
"""

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel, Shell(kernel=kernel)


class TestCommandHistory:
    """Verify command history tracking."""

    def test_history_records_itself(self) -> None:
        """The first history call should show itself (like real shells)."""
        _kernel, shell = _booted_shell()
        result = shell.execute("history")
        # The history command records itself before running
        assert "history" in result

    def test_commands_are_recorded(self) -> None:
        """Executed commands should appear in history."""
        _kernel, shell = _booted_shell()
        shell.execute("whoami")
        result = shell.execute("history")
        assert "whoami" in result

    def test_history_preserves_order(self) -> None:
        """Commands should appear in chronological order."""
        _kernel, shell = _booted_shell()
        shell.execute("whoami")
        shell.execute("ps")
        result = shell.execute("history")
        whoami_pos = result.index("whoami")
        ps_pos = result.index("ps")
        assert whoami_pos < ps_pos

    def test_history_includes_numbers(self) -> None:
        """History entries should be numbered."""
        _kernel, shell = _booted_shell()
        shell.execute("whoami")
        result = shell.execute("history")
        assert "1" in result

    def test_history_command_itself_is_recorded(self) -> None:
        """The history command should appear in subsequent history."""
        _kernel, shell = _booted_shell()
        shell.execute("history")
        result = shell.execute("history")
        assert "history" in result

    def test_help_includes_history(self) -> None:
        """Help should list the history command."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "history" in result


class TestAliases:
    """Verify command alias support."""

    def test_alias_creates_shortcut(self) -> None:
        """An alias should expand to the original command."""
        _kernel, shell = _booted_shell()
        shell.execute("alias ll=ls /")
        result = shell.execute("ll")
        # ll should behave like "ls /"
        # At minimum, it shouldn't be "Unknown command"
        assert "unknown" not in result.lower()

    def test_alias_list(self) -> None:
        """Running alias with no args should list aliases."""
        _kernel, shell = _booted_shell()
        shell.execute("alias ll=ls /")
        result = shell.execute("alias")
        assert "ll" in result
        assert "ls /" in result

    def test_alias_no_aliases(self) -> None:
        """Listing aliases when none exist should show a message."""
        _kernel, shell = _booted_shell()
        result = shell.execute("alias")
        assert "no aliases" in result.lower() or result.strip() == ""

    def test_unalias_removes(self) -> None:
        """Unalias should remove an alias."""
        _kernel, shell = _booted_shell()
        shell.execute("alias ll=ls /")
        shell.execute("unalias ll")
        result = shell.execute("ll")
        assert "unknown" in result.lower()

    def test_unalias_missing_args(self) -> None:
        """Unalias without args should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("unalias")
        assert "usage" in result.lower()

    def test_alias_overwrite(self) -> None:
        """Setting an alias again should overwrite it."""
        _kernel, shell = _booted_shell()
        shell.execute("alias g=ps")
        shell.execute("alias g=whoami")
        result = shell.execute("g")
        # Should act like whoami, not ps
        assert "root" in result.lower()

    def test_help_includes_alias(self) -> None:
        """Help should list alias and unalias commands."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "alias" in result
        assert "unalias" in result
