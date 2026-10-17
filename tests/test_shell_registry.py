"""The shell's commands are organised into topic modules, each with a COMMANDS table.

Like a toolbox with one drawer per kind of tool: every command lives in
exactly one drawer, and the shell builds its full list from the drawers.
"""

import inspect

import pytest

from py_os.kernel import Kernel
from py_os.shell import Shell, ShellBase

EXPECTED_COMMAND_COUNT = 93


def _command_groups() -> list[type[ShellBase]]:
    """Return every command-group class the Shell is built from."""
    return [cls for cls in Shell.__mro__ if "COMMANDS" in vars(cls) and cls is not ShellBase]


@pytest.fixture
def shell() -> Shell:
    """Return a shell on a freshly booted kernel."""
    kernel = Kernel()
    kernel.boot()
    return Shell(kernel=kernel)


def test_every_command_lives_in_exactly_one_group() -> None:
    """No two groups claim the same command name (one would silently win)."""
    names = [name for group in _command_groups() for name, _ in group.COMMANDS]
    assert len(names) == len(set(names))


def test_shell_offers_every_registered_command(shell: Shell) -> None:
    """The dispatch table is exactly the union of the groups' tables -- nothing lost."""
    registered = {name for group in _command_groups() for name, _ in group.COMMANDS}
    assert set(shell.command_names) == registered
    assert len(registered) == EXPECTED_COMMAND_COUNT


def test_each_command_is_handled_by_its_own_group() -> None:
    """A group's table only points at methods defined in that same group."""
    for group in _command_groups():
        own_methods = set(vars(group))
        for name, handler in group.COMMANDS:
            assert handler.__name__ in own_methods, f"{group.__name__} lists {name!r}"


def test_each_group_lives_in_its_own_module() -> None:
    """Each topic is its own small module, not one giant file."""
    modules = {inspect.getmodule(group).__name__ for group in _command_groups()}  # pyright: ignore[reportOptionalMemberAccess]
    assert len(modules) == len(_command_groups())
    assert all(m.startswith("py_os.shell.commands.") for m in modules)
