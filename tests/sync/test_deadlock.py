"""Tests for deadlock detection and Banker's algorithm.

Deadlock occurs when processes are stuck waiting for each other's
resources in a circular chain — none can proceed.  Four conditions
must ALL hold simultaneously:

    1. **Mutual exclusion** — resources can't be shared.
    2. **Hold and wait** — processes hold resources while waiting.
    3. **No preemption** — resources can't be forcibly taken.
    4. **Circular wait** — a circular chain of waiting processes.

Two strategies address deadlock:
    - **Detection** — find deadlocked processes after the fact.
    - **Avoidance (Banker's)** — deny requests that would create
      an unsafe state (no guaranteed completion sequence).
"""

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.sync.deadlock import ResourceManager
from py_os.syscalls import SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


# -- ResourceManager basics ----------------------------------------------------


class TestResourceManagerBasics:
    """Verify resource tracking fundamentals."""

    def test_add_resource(self) -> None:
        """Adding a resource should track its total instances."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        available = 4
        assert rm.available("CPU") == available

    def test_add_multiple_resources(self) -> None:
        """Multiple resource types should be tracked independently."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.add_resource("Disk", total=2)
        cpu_total = 4
        disk_total = 2
        assert rm.available("CPU") == cpu_total
        assert rm.available("Disk") == disk_total

    def test_declare_max(self) -> None:
        """Processes must declare their maximum resource needs upfront."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.declare_max(pid=1, resource="CPU", maximum=3)
        need = 3
        assert rm.need(pid=1, resource="CPU") == need

    def test_request_reduces_available(self) -> None:
        """A granted request should reduce available instances."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.declare_max(pid=1, resource="CPU", maximum=3)
        rm.request(pid=1, resource="CPU", amount=2)
        expected_available = 2
        assert rm.available("CPU") == expected_available

    def test_release_increases_available(self) -> None:
        """Releasing resources should increase available instances."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.declare_max(pid=1, resource="CPU", maximum=3)
        rm.request(pid=1, resource="CPU", amount=2)
        rm.release(pid=1, resource="CPU", amount=2)
        full = 4
        assert rm.available("CPU") == full

    def test_allocation_tracking(self) -> None:
        """Allocation should track how many each process holds."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.declare_max(pid=1, resource="CPU", maximum=3)
        rm.request(pid=1, resource="CPU", amount=2)
        held = 2
        assert rm.allocation(pid=1, resource="CPU") == held

    def test_need_decreases_after_request(self) -> None:
        """Need should decrease as resources are allocated."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.declare_max(pid=1, resource="CPU", maximum=3)
        rm.request(pid=1, resource="CPU", amount=2)
        remaining_need = 1
        assert rm.need(pid=1, resource="CPU") == remaining_need

    def test_remove_process(self) -> None:
        """Removing a process should release all its resources."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.declare_max(pid=1, resource="CPU", maximum=3)
        rm.request(pid=1, resource="CPU", amount=2)
        rm.remove_process(pid=1)
        full = 4
        assert rm.available("CPU") == full

    def test_resource_list(self) -> None:
        """Should list all registered resources."""
        rm = ResourceManager()
        rm.add_resource("CPU", total=4)
        rm.add_resource("Disk", total=2)
        resources = rm.resources()
        assert "CPU" in resources
        assert "Disk" in resources


# -- Banker's Algorithm (Safety Check) -----------------------------------------


class TestBankersAlgorithm:
    """Verify the Banker's algorithm for deadlock avoidance.

    The algorithm checks if granting a request leaves the system in
    a 'safe state' — one where there exists an ordering (safe sequence)
    in which all processes can complete.  If no safe sequence exists,
    the request is denied.
    """

    def _classic_setup(self) -> ResourceManager:
        """Set up the classic textbook Banker's example.

        Resources: A=10, B=5, C=7
        5 processes with declared maximums and current allocations.

        Process  Alloc(A,B,C)  Max(A,B,C)  Need(A,B,C)
        P0       0,1,0         7,5,3       7,4,3
        P1       2,0,0         3,2,2       1,2,2
        P2       3,0,2         9,0,2       6,0,0
        P3       2,1,1         2,2,2       0,1,1
        P4       0,0,2         4,3,3       4,3,1

        Available: A=3, B=3, C=2
        Safe sequence exists: <P1, P3, P4, P2, P0>
        """
        rm = ResourceManager()
        rm.add_resource("A", total=10)
        rm.add_resource("B", total=5)
        rm.add_resource("C", total=7)

        # P0: alloc(0,1,0), max(7,5,3)
        rm.declare_max(pid=0, resource="A", maximum=7)
        rm.declare_max(pid=0, resource="B", maximum=5)
        rm.declare_max(pid=0, resource="C", maximum=3)
        rm.request(pid=0, resource="B", amount=1)

        # P1: alloc(2,0,0), max(3,2,2)
        rm.declare_max(pid=1, resource="A", maximum=3)
        rm.declare_max(pid=1, resource="B", maximum=2)
        rm.declare_max(pid=1, resource="C", maximum=2)
        rm.request(pid=1, resource="A", amount=2)

        # P2: alloc(3,0,2), max(9,0,2)
        rm.declare_max(pid=2, resource="A", maximum=9)
        rm.declare_max(pid=2, resource="B", maximum=0)
        rm.declare_max(pid=2, resource="C", maximum=2)
        rm.request(pid=2, resource="A", amount=3)
        rm.request(pid=2, resource="C", amount=2)

        # P3: alloc(2,1,1), max(2,2,2)
        rm.declare_max(pid=3, resource="A", maximum=2)
        rm.declare_max(pid=3, resource="B", maximum=2)
        rm.declare_max(pid=3, resource="C", maximum=2)
        rm.request(pid=3, resource="A", amount=2)
        rm.request(pid=3, resource="B", amount=1)
        rm.request(pid=3, resource="C", amount=1)

        # P4: alloc(0,0,2), max(4,3,3)
        rm.declare_max(pid=4, resource="A", maximum=4)
        rm.declare_max(pid=4, resource="B", maximum=3)
        rm.declare_max(pid=4, resource="C", maximum=3)
        rm.request(pid=4, resource="C", amount=2)

        return rm

    def test_classic_example_is_safe(self) -> None:
        """The classic textbook state should be safe."""
        rm = self._classic_setup()
        assert rm.is_safe()

    def test_safe_sequence_exists(self) -> None:
        """A safe sequence should be found for the classic example."""
        rm = self._classic_setup()
        seq = rm.find_safe_sequence()
        assert seq is not None
        expected_len = 5
        assert len(seq) == expected_len

    def test_safe_sequence_starts_correctly(self) -> None:
        """P1 should be first in the safe sequence (lowest need)."""
        rm = self._classic_setup()
        seq = rm.find_safe_sequence()
        assert seq is not None
        assert seq[0] == 1  # P1 can finish first

    def test_request_granted_when_safe(self) -> None:
        """Banker's should grant a request that keeps state safe."""
        rm = ResourceManager()
        rm.add_resource("R", total=10)
        rm.declare_max(pid=1, resource="R", maximum=5)
        granted = rm.request_safe(pid=1, resource="R", amount=3)
        assert granted

    def test_request_denied_when_unsafe(self) -> None:
        """Banker's should deny a request that makes state unsafe."""
        rm = ResourceManager()
        rm.add_resource("R", total=4)
        rm.declare_max(pid=1, resource="R", maximum=4)
        rm.declare_max(pid=2, resource="R", maximum=4)
        # Give 2 to each — now available=0, but each still needs 2
        rm.request(pid=1, resource="R", amount=2)
        rm.request(pid=2, resource="R", amount=1)
        # Granting 1 more to pid=2 would leave available=0 with pid=1 needing 2
        granted = rm.request_safe(pid=2, resource="R", amount=1)
        assert not granted

    def test_simple_safe_state(self) -> None:
        """A state with plenty of resources should be safe."""
        rm = ResourceManager()
        rm.add_resource("R", total=10)
        rm.declare_max(pid=1, resource="R", maximum=3)
        rm.request(pid=1, resource="R", amount=1)
        assert rm.is_safe()

    def test_unsafe_state_no_sequence(self) -> None:
        """An unsafe state should return None for safe sequence."""
        rm = ResourceManager()
        rm.add_resource("R", total=2)
        rm.declare_max(pid=1, resource="R", maximum=2)
        rm.declare_max(pid=2, resource="R", maximum=2)
        rm.request(pid=1, resource="R", amount=1)
        rm.request(pid=2, resource="R", amount=1)
        # Available=0, both need 1 more — neither can finish
        assert not rm.is_safe()
        assert rm.find_safe_sequence() is None


# -- Deadlock Detection --------------------------------------------------------


class TestDeadlockDetection:
    """Verify deadlock detection (finding stuck processes)."""

    def test_no_deadlock(self) -> None:
        """No deadlock when resources are available."""
        rm = ResourceManager()
        rm.add_resource("R", total=5)
        rm.declare_max(pid=1, resource="R", maximum=3)
        rm.request(pid=1, resource="R", amount=1)
        deadlocked = rm.detect_deadlock()
        assert len(deadlocked) == 0

    def test_deadlock_detected(self) -> None:
        """Deadlock should be detected when processes can't proceed."""
        rm = ResourceManager()
        rm.add_resource("R", total=2)
        rm.declare_max(pid=1, resource="R", maximum=2)
        rm.declare_max(pid=2, resource="R", maximum=2)
        rm.request(pid=1, resource="R", amount=1)
        rm.request(pid=2, resource="R", amount=1)
        # Available=0, both need 1 more — deadlock
        deadlocked = rm.detect_deadlock()
        pid_a, pid_b = 1, 2
        assert pid_a in deadlocked
        assert pid_b in deadlocked

    def test_partial_deadlock(self) -> None:
        """Only deadlocked processes should be reported, not all."""
        rm = ResourceManager()
        rm.add_resource("R", total=3)
        rm.declare_max(pid=1, resource="R", maximum=2)
        rm.declare_max(pid=2, resource="R", maximum=2)
        rm.declare_max(pid=3, resource="R", maximum=1)
        rm.request(pid=1, resource="R", amount=1)
        rm.request(pid=2, resource="R", amount=1)
        rm.request(pid=3, resource="R", amount=1)
        # Available=0. P3 needs 0 more (can finish, releasing 1).
        # Then P1 or P2 can finish. So no deadlock.
        deadlocked = rm.detect_deadlock()
        assert len(deadlocked) == 0

    def test_deadlock_with_multiple_resources(self) -> None:
        """Deadlock detection should work across resource types."""
        rm = ResourceManager()
        rm.add_resource("A", total=1)
        rm.add_resource("B", total=1)
        # P1 holds A, needs B.  P2 holds B, needs A.  Classic circular wait.
        rm.declare_max(pid=1, resource="A", maximum=1)
        rm.declare_max(pid=1, resource="B", maximum=1)
        rm.declare_max(pid=2, resource="A", maximum=1)
        rm.declare_max(pid=2, resource="B", maximum=1)
        rm.request(pid=1, resource="A", amount=1)
        rm.request(pid=2, resource="B", amount=1)
        # Available: A=0, B=0.  P1 needs B, P2 needs A — deadlock.
        deadlocked = rm.detect_deadlock()
        pid_a, pid_b = 1, 2
        assert pid_a in deadlocked
        assert pid_b in deadlocked


# -- Kernel integration --------------------------------------------------------


class TestKernelDeadlock:
    """Verify deadlock management through the kernel."""

    def test_kernel_has_resource_manager(self) -> None:
        """Booted kernel should have a resource manager."""
        kernel = _booted_kernel()
        assert kernel.resource_manager is not None

    def test_add_resource_via_kernel(self) -> None:
        """Resources can be added through the kernel."""
        kernel = _booted_kernel()
        assert kernel.resource_manager is not None
        kernel.resource_manager.add_resource("Printer", total=2)
        expected = 2
        assert kernel.resource_manager.available("Printer") == expected

    def test_terminate_cleans_resources(self) -> None:
        """Terminating a process should release its resources."""
        kernel = _booted_kernel()
        assert kernel.resource_manager is not None
        kernel.resource_manager.add_resource("R", total=5)
        proc = kernel.create_process(name="app", num_pages=2)
        proc.dispatch()  # READY → RUNNING (terminate requires RUNNING)
        kernel.resource_manager.declare_max(pid=proc.pid, resource="R", maximum=3)
        kernel.resource_manager.request(pid=proc.pid, resource="R", amount=2)
        expected_before = 3
        assert kernel.resource_manager.available("R") == expected_before
        kernel.terminate_process(pid=proc.pid)
        expected_after = 5
        assert kernel.resource_manager.available("R") == expected_after


# -- Syscalls ------------------------------------------------------------------


class TestDeadlockSyscalls:
    """Verify deadlock operations through syscalls."""

    def test_sys_detect_deadlock(self) -> None:
        """SYS_DETECT_DEADLOCK should return deadlocked PIDs."""
        kernel = _booted_kernel()
        assert kernel.resource_manager is not None
        kernel.resource_manager.add_resource("R", total=2)
        p1 = kernel.create_process(name="p1", num_pages=1)
        p2 = kernel.create_process(name="p2", num_pages=1)
        kernel.resource_manager.declare_max(pid=p1.pid, resource="R", maximum=2)
        kernel.resource_manager.declare_max(pid=p2.pid, resource="R", maximum=2)
        kernel.resource_manager.request(pid=p1.pid, resource="R", amount=1)
        kernel.resource_manager.request(pid=p2.pid, resource="R", amount=1)
        result = kernel.syscall(SyscallNumber.SYS_DETECT_DEADLOCK)
        assert p1.pid in result["deadlocked"]
        assert p2.pid in result["deadlocked"]

    def test_sys_detect_no_deadlock(self) -> None:
        """No deadlock should return empty set."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_DETECT_DEADLOCK)
        assert len(result["deadlocked"]) == 0


# -- Shell commands ------------------------------------------------------------


class TestShellDeadlockCommands:
    """Verify shell commands for resource and deadlock management."""

    def test_resources_command(self) -> None:
        """Resources command should show allocation info."""
        kernel = _booted_kernel()
        assert kernel.resource_manager is not None
        kernel.resource_manager.add_resource("Printer", total=2)
        shell = Shell(kernel=kernel)
        result = shell.execute("resources")
        assert "Printer" in result

    def test_deadlock_command_no_deadlock(self) -> None:
        """Deadlock command should report no deadlocks when safe."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("deadlock")
        assert "no deadlock" in result.lower() or "safe" in result.lower()

    def test_deadlock_command_detects(self) -> None:
        """Deadlock command should report deadlocked processes."""
        kernel = _booted_kernel()
        assert kernel.resource_manager is not None
        kernel.resource_manager.add_resource("R", total=2)
        p1 = kernel.create_process(name="p1", num_pages=1)
        p2 = kernel.create_process(name="p2", num_pages=1)
        kernel.resource_manager.declare_max(pid=p1.pid, resource="R", maximum=2)
        kernel.resource_manager.declare_max(pid=p2.pid, resource="R", maximum=2)
        kernel.resource_manager.request(pid=p1.pid, resource="R", amount=1)
        kernel.resource_manager.request(pid=p2.pid, resource="R", amount=1)
        shell = Shell(kernel=kernel)
        result = shell.execute("deadlock")
        assert "deadlock" in result.lower()

    def test_help_includes_resources(self) -> None:
        """Help should list the resources command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "resources" in result

    def test_help_includes_deadlock(self) -> None:
        """Help should list the deadlock command."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "deadlock" in result
