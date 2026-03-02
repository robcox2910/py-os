"""Shared test fixtures for the PyOS test suite.

Provides ``booted_kernel`` and ``booted_shell`` pytest fixtures
so individual test modules don't need to duplicate boot helpers.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell


@pytest.fixture
def booted_kernel() -> Kernel:
    """Return a booted kernel in kernel mode, ready for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


@pytest.fixture
def booted_shell(booted_kernel: Kernel) -> tuple[Kernel, Shell]:
    """Return a booted kernel and shell pair for testing."""
    return booted_kernel, Shell(kernel=booted_kernel)
