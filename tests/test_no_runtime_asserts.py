"""The kernel must never rely on ``assert`` for checks that matter at runtime.

Python throws every ``assert`` away when run with ``python -O`` ("optimise").
A check that only exists as an ``assert`` silently disappears, and a missing
subsystem then shows up later as a baffling ``'NoneType' object has no
attribute ...``. So the source code uses real ``if ... raise`` checks instead.
"""

import ast
from pathlib import Path

import pytest

from py_os.kernel import Kernel
from py_os.process.scheduler import FCFSPolicy
from py_os.syscalls import SyscallError, SyscallNumber

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "py_os"


def test_source_has_no_assert_statements() -> None:
    """Regression: 115 runtime checks used to be asserts that ``python -O`` removes."""
    offenders = [
        f"{path.relative_to(SOURCE_ROOT)}:{node.lineno}"
        for path in sorted(SOURCE_ROOT.rglob("*.py"))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Assert)
    ]
    assert offenders == []


def test_missing_kernel_subsystem_raises_a_clear_error() -> None:
    """A subsystem that's gone missing is reported by name, not as an AssertionError."""
    kernel = Kernel()
    kernel.boot()
    kernel._scheduler = None  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(RuntimeError, match="scheduler"):
        kernel.set_scheduler_policy(FCFSPolicy)


def test_missing_subsystem_in_a_syscall_is_a_syscall_error() -> None:
    """User programs only ever see SyscallError -- even for a missing subsystem."""
    kernel = Kernel()
    kernel.boot()
    kernel._env = None  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(SyscallError, match="env"):
        kernel.syscall(SyscallNumber.SYS_SYSINFO)
