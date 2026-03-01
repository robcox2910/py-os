"""Integration tests for swap space wired into kernel, syscalls, and shell.

The Pager, SwapSpace, and replacement policies (FIFO, LRU, Clock) are
unit-tested in ``test_page_replacement.py``.  These tests verify that
the pager is properly integrated into the kernel lifecycle and
accessible through syscalls and shell commands.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# -- Kernel boot integration --------------------------------------------------


class TestKernelSwapBoot:
    """Verify the pager is created at boot and torn down at shutdown."""

    def test_pager_available_after_boot(self) -> None:
        """Pager should be initialised after kernel boot."""
        kernel = _booted_kernel()
        assert kernel.pager is not None

    def test_pager_none_before_boot(self) -> None:
        """Pager should be None before boot."""
        kernel = Kernel()
        kernel._execution_mode = ExecutionMode.KERNEL
        assert kernel.pager is None

    def test_pager_none_after_shutdown(self) -> None:
        """Pager should be None after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        kernel._execution_mode = ExecutionMode.KERNEL
        assert kernel.pager is None

    def test_swap_in_dmesg(self) -> None:
        """Boot log should mention swap space."""
        kernel = _booted_kernel()
        assert any("Swap space" in line for line in kernel.dmesg())

    def test_default_policy_is_lru(self) -> None:
        """Default swap policy should be LRU."""
        kernel = _booted_kernel()
        assert kernel.swap_policy_name == "lru"


# -- Syscall: SYS_SWAP_INFO ---------------------------------------------------


class TestSyscallSwapInfo:
    """Verify the swap info syscall returns correct data."""

    def test_returns_dict_with_expected_keys(self) -> None:
        """Swap info should contain all required keys."""
        kernel = _booted_kernel()
        info: dict[str, object] = kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
        expected_keys = {
            "swap_total",
            "swap_used",
            "swap_free",
            "page_faults",
            "resident_count",
            "policy",
        }
        assert set(info.keys()) == expected_keys

    def test_initial_zero_faults(self) -> None:
        """A fresh pager should have zero page faults."""
        kernel = _booted_kernel()
        info: dict[str, object] = kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
        assert info["page_faults"] == 0

    def test_policy_name_matches(self) -> None:
        """Swap info policy should match the kernel's swap_policy_name."""
        kernel = _booted_kernel()
        info: dict[str, object] = kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
        assert info["policy"] == "lru"


# -- Syscall: SYS_SET_SWAP_POLICY ---------------------------------------------


class TestSyscallSetSwapPolicy:
    """Verify swapping the replacement policy via syscall."""

    def test_fifo_succeeds(self) -> None:
        """Setting FIFO policy should succeed."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_SWAP_POLICY, name="fifo")
        assert kernel.swap_policy_name == "fifo"

    def test_lru_succeeds(self) -> None:
        """Setting LRU policy should succeed."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_SWAP_POLICY, name="lru")
        assert kernel.swap_policy_name == "lru"

    def test_clock_succeeds(self) -> None:
        """Setting Clock policy should succeed."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_SET_SWAP_POLICY, name="clock")
        assert kernel.swap_policy_name == "clock"

    def test_unknown_policy_raises(self) -> None:
        """An unknown policy name should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="Unknown swap policy"):
            kernel.syscall(SyscallNumber.SYS_SET_SWAP_POLICY, name="optimal")


# -- Syscall: SYS_SWAP_EXERCISE -----------------------------------------------


class TestSyscallSwapExercise:
    """Verify the swap exercise syscall forces page faults."""

    def test_page_faults_increase(self) -> None:
        """Exercise should cause page faults when pages exceed frames."""
        kernel = _booted_kernel()
        info_before: dict[str, object] = kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
        faults_before = info_before["page_faults"]
        result: dict[str, object] = kernel.syscall(SyscallNumber.SYS_SWAP_EXERCISE)
        assert isinstance(result["new_faults"], int)
        assert result["faults_after"] > faults_before  # type: ignore[operator]


# -- Shell: swap command -------------------------------------------------------


class TestShellSwap:
    """Verify the shell swap command."""

    def test_status_output(self) -> None:
        """Command 'swap' (no args) should show status info."""
        _kernel, shell = _booted_shell()
        output = shell.execute("swap")
        assert "Swap Status" in output
        assert "Policy" in output
        assert "lru" in output

    def test_policy_change(self) -> None:
        """Command 'swap policy fifo' should change the policy."""
        _kernel, shell = _booted_shell()
        output = shell.execute("swap policy fifo")
        assert "fifo" in output

    def test_bad_policy_error(self) -> None:
        """Command 'swap policy unknown' should show an error."""
        _kernel, shell = _booted_shell()
        output = shell.execute("swap policy banana")
        assert "Error" in output

    def test_demo_output(self) -> None:
        """Command 'swap demo' should show fault statistics."""
        _kernel, shell = _booted_shell()
        output = shell.execute("swap demo")
        assert "Swap Demo" in output
        assert "faults" in output.lower()

    def test_help_listing(self) -> None:
        """Command 'swap' should appear in the help listing."""
        _kernel, shell = _booted_shell()
        output = shell.execute("help")
        assert "swap" in output
