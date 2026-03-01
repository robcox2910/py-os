"""Tests for priority inversion detection and priority inheritance protocol.

Priority inversion is one of the most famous bugs in computing history.
In 1997, NASA's Mars Pathfinder rover kept rebooting on Mars because a
low-priority task held a shared mutex, a high-priority task blocked
waiting for it, and a medium-priority task -- which didn't need the
mutex at all -- kept running instead.  The high-priority task starved.

The fix is **priority inheritance**: when a high-priority thread blocks
on a mutex held by a lower-priority thread, the kernel temporarily
boosts the holder's priority to match the waiter's.  This lets the
holder run, release the lock, and restore normal scheduling.

Real-world analogy: three students share one textbook.  The slow
student (low priority) has the textbook.  The fast student (high
priority) needs it but can't get it.  Meanwhile a normal student
(medium priority) keeps getting called on by the teacher because
they're higher priority than the slow student.  The fix: the teacher
temporarily bumps the slow student up so they can finish quickly,
return the textbook, and the fast student can proceed.
"""

from collections import deque

from py_os.kernel import ExecutionMode, Kernel
from py_os.process.pcb import Process
from py_os.process.scheduler import AgingPriorityPolicy, CFSPolicy, PriorityPolicy
from py_os.shell import Shell
from py_os.sync.inheritance import PriorityInheritanceManager

# Named constants to satisfy PLR2004
PRIORITY_LOW = 1
PRIORITY_MEDIUM = 5
PRIORITY_HIGH = 10
PRIORITY_VERY_HIGH = 15
NUM_PAGES = 1


# -- Helpers -----------------------------------------------------------------


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return kernel, Shell(kernel=kernel)


# -- Cycle 1: Process.effective_priority ------------------------------------


class TestProcessEffectivePriority:
    """Verify that effective_priority defaults to base and can be boosted."""

    def test_effective_priority_defaults_to_base(self) -> None:
        """A new process's effective priority equals its base priority."""
        process = Process(name="test", priority=PRIORITY_MEDIUM)
        assert process.effective_priority == PRIORITY_MEDIUM

    def test_effective_priority_can_be_set(self) -> None:
        """Setting effective_priority changes the value the scheduler sees."""
        process = Process(name="test", priority=PRIORITY_LOW)
        process.effective_priority = PRIORITY_HIGH
        assert process.effective_priority == PRIORITY_HIGH

    def test_base_priority_unchanged_after_boost(self) -> None:
        """Boosting effective_priority does not alter the base priority."""
        process = Process(name="test", priority=PRIORITY_LOW)
        process.effective_priority = PRIORITY_HIGH
        assert process.priority == PRIORITY_LOW


# -- Cycle 2: PriorityInheritanceManager basics ----------------------------


class TestPriorityInheritanceManager:
    """Verify core PI manager operations: acquire, block, release, clear."""

    def test_on_acquire_records_holder(self) -> None:
        """After on_acquire, the manager knows which PID holds the mutex."""
        mgr = PriorityInheritanceManager()
        mgr.on_acquire("m1", pid=1)
        assert mgr.holder("m1") == 1

    def test_on_block_no_inversion_is_noop(self) -> None:
        """Blocking by a lower-priority waiter does not boost the holder."""
        mgr = PriorityInheritanceManager()
        low = Process(name="low", priority=PRIORITY_LOW)
        high = Process(name="high", priority=PRIORITY_HIGH)
        processes = {low.pid: low, high.pid: high}

        mgr.on_acquire("m1", pid=high.pid)
        mgr.on_block("m1", waiter_pid=low.pid, processes=processes)

        # High-priority holder should NOT be boosted by low-priority waiter
        assert high.effective_priority == PRIORITY_HIGH

    def test_on_block_boosts_holder(self) -> None:
        """A high-priority waiter boosts the lower-priority holder."""
        mgr = PriorityInheritanceManager()
        low = Process(name="low", priority=PRIORITY_LOW)
        high = Process(name="high", priority=PRIORITY_HIGH)
        processes = {low.pid: low, high.pid: high}

        mgr.on_acquire("m1", pid=low.pid)
        mgr.on_block("m1", waiter_pid=high.pid, processes=processes)

        assert low.effective_priority == PRIORITY_HIGH

    def test_on_release_restores_base_priority(self) -> None:
        """Releasing a mutex restores the holder's effective priority to base."""
        mgr = PriorityInheritanceManager()
        low = Process(name="low", priority=PRIORITY_LOW)
        high = Process(name="high", priority=PRIORITY_HIGH)
        processes = {low.pid: low, high.pid: high}

        mgr.on_acquire("m1", pid=low.pid)
        mgr.on_block("m1", waiter_pid=high.pid, processes=processes)
        assert low.effective_priority == PRIORITY_HIGH

        mgr.on_release("m1", pid=low.pid, new_holder_pid=high.pid, processes=processes)
        assert low.effective_priority == PRIORITY_LOW

    def test_clear_resets_all_state(self) -> None:
        """After clear(), all tracking state is gone."""
        mgr = PriorityInheritanceManager()
        mgr.on_acquire("m1", pid=1)
        mgr.clear()
        assert mgr.holder("m1") is None

    def test_on_block_no_holder_is_noop(self) -> None:
        """Blocking on a mutex with no holder should not raise."""
        mgr = PriorityInheritanceManager()
        waiter = Process(name="w", priority=PRIORITY_HIGH)
        processes = {waiter.pid: waiter}
        # No on_acquire → no holder for "m1"
        mgr.on_block("m1", waiter_pid=waiter.pid, processes=processes)
        assert waiter.effective_priority == PRIORITY_HIGH

    def test_on_block_missing_process_is_noop(self) -> None:
        """Blocking when waiter/holder PID is not in process table should not raise."""
        mgr = PriorityInheritanceManager()
        holder = Process(name="h", priority=PRIORITY_LOW)
        mgr.on_acquire("m1", pid=holder.pid)
        # Pass empty process table — waiter/holder not found
        nonexistent_pid = 9999
        mgr.on_block("m1", waiter_pid=nonexistent_pid, processes={})

    def test_on_release_missing_process_returns_early(self) -> None:
        """Releasing when process is not in the table should not raise."""
        mgr = PriorityInheritanceManager()
        mgr.on_acquire("m1", pid=1)
        # Process not in table
        mgr.on_release("m1", pid=1, new_holder_pid=None, processes={})


# -- Cycle 3: Transitive inheritance ---------------------------------------


class TestTransitiveInheritance:
    """Verify priority inheritance propagates through mutex chains."""

    def test_chain_of_two_mutexes(self) -> None:
        """A → M1 → B → M2 → C: boost propagates C to A's priority."""
        mgr = PriorityInheritanceManager()
        a = Process(name="A", priority=PRIORITY_HIGH)
        b = Process(name="B", priority=PRIORITY_MEDIUM)
        c = Process(name="C", priority=PRIORITY_LOW)
        processes = {a.pid: a, b.pid: b, c.pid: c}

        # C holds M2, B holds M1
        mgr.on_acquire("m2", pid=c.pid)
        mgr.on_acquire("m1", pid=b.pid)

        # B blocks on M2 → C boosted to MEDIUM
        mgr.on_block("m2", waiter_pid=b.pid, processes=processes)
        assert c.effective_priority == PRIORITY_MEDIUM

        # A blocks on M1 → B boosted to HIGH, and transitively C boosted to HIGH
        mgr.on_block("m1", waiter_pid=a.pid, processes=processes)
        assert b.effective_priority == PRIORITY_HIGH
        assert c.effective_priority == PRIORITY_HIGH

    def test_chain_of_three_mutexes(self) -> None:
        """A → M1 → B → M2 → C → M3 → D: boost reaches D."""
        mgr = PriorityInheritanceManager()
        a = Process(name="A", priority=PRIORITY_VERY_HIGH)
        b = Process(name="B", priority=PRIORITY_HIGH)
        c = Process(name="C", priority=PRIORITY_MEDIUM)
        d = Process(name="D", priority=PRIORITY_LOW)
        processes = {a.pid: a, b.pid: b, c.pid: c, d.pid: d}

        mgr.on_acquire("m3", pid=d.pid)
        mgr.on_acquire("m2", pid=c.pid)
        mgr.on_acquire("m1", pid=b.pid)

        mgr.on_block("m3", waiter_pid=c.pid, processes=processes)
        mgr.on_block("m2", waiter_pid=b.pid, processes=processes)
        mgr.on_block("m1", waiter_pid=a.pid, processes=processes)

        assert b.effective_priority == PRIORITY_VERY_HIGH
        assert c.effective_priority == PRIORITY_VERY_HIGH
        assert d.effective_priority == PRIORITY_VERY_HIGH

    def test_propagation_stops_on_missing_holder(self) -> None:
        """Propagation should stop when a holder in the chain is missing from processes."""
        mgr = PriorityInheritanceManager()
        a = Process(name="A", priority=PRIORITY_HIGH)
        b = Process(name="B", priority=PRIORITY_LOW)
        # B holds M1, but B is blocked on M2 whose holder is not in processes
        mgr.on_acquire("m1", pid=b.pid)
        mgr.on_acquire("m2", pid=999)  # holder PID 999 not in process table
        # Record B as blocked on M2 (manually, to set up chain)
        mgr._blocked_on[b.pid] = "m2"
        # A blocks on M1 → B boosted, propagation tries 999 but stops
        processes = {a.pid: a, b.pid: b}
        mgr.on_block("m1", waiter_pid=a.pid, processes=processes)
        assert b.effective_priority == PRIORITY_HIGH

    def test_multiple_waiters_highest_wins(self) -> None:
        """When multiple threads wait on the same mutex, the holder gets the highest."""
        mgr = PriorityInheritanceManager()
        holder = Process(name="holder", priority=PRIORITY_LOW)
        waiter_med = Process(name="med", priority=PRIORITY_MEDIUM)
        waiter_high = Process(name="high", priority=PRIORITY_HIGH)
        processes = {holder.pid: holder, waiter_med.pid: waiter_med, waiter_high.pid: waiter_high}

        mgr.on_acquire("m1", pid=holder.pid)
        mgr.on_block("m1", waiter_pid=waiter_med.pid, processes=processes)
        assert holder.effective_priority == PRIORITY_MEDIUM

        mgr.on_block("m1", waiter_pid=waiter_high.pid, processes=processes)
        assert holder.effective_priority == PRIORITY_HIGH

    def test_release_with_remaining_held_mutexes_keeps_boost(self) -> None:
        """If a process holds two mutexes and releases one, the boost from the other persists."""
        mgr = PriorityInheritanceManager()
        holder = Process(name="holder", priority=PRIORITY_LOW)
        waiter_a = Process(name="A", priority=PRIORITY_HIGH)
        waiter_b = Process(name="B", priority=PRIORITY_MEDIUM)
        processes = {holder.pid: holder, waiter_a.pid: waiter_a, waiter_b.pid: waiter_b}

        mgr.on_acquire("m1", pid=holder.pid)
        mgr.on_acquire("m2", pid=holder.pid)
        mgr.on_block("m1", waiter_pid=waiter_a.pid, processes=processes)
        mgr.on_block("m2", waiter_pid=waiter_b.pid, processes=processes)
        assert holder.effective_priority == PRIORITY_HIGH

        # Release m1 (waiter_a gets it), but m2 still has waiter_b
        mgr.on_release("m1", pid=holder.pid, new_holder_pid=waiter_a.pid, processes=processes)
        assert holder.effective_priority == PRIORITY_MEDIUM


# -- Cycle 4: Scheduler uses effective_priority ----------------------------


class TestSchedulerEffectivePriority:
    """Verify that priority-aware schedulers use effective_priority."""

    def test_priority_policy_uses_effective(self) -> None:
        """PriorityPolicy selects the process with highest effective_priority."""
        low = Process(name="low", priority=PRIORITY_LOW)
        high = Process(name="high", priority=PRIORITY_HIGH)
        # Boost low's effective above high's base
        low.effective_priority = PRIORITY_VERY_HIGH

        low.admit()
        high.admit()
        queue: deque[Process] = deque([high, low])
        policy = PriorityPolicy()
        selected = policy.select(queue)

        assert selected is not None
        assert selected.pid == low.pid

    def test_aging_policy_combines_effective_and_aging(self) -> None:
        """AgingPriorityPolicy adds aging bonus to effective_priority."""
        process = Process(name="test", priority=PRIORITY_LOW)
        process.effective_priority = PRIORITY_MEDIUM

        policy = AgingPriorityPolicy()
        eff = policy.effective_priority(process)
        assert eff == PRIORITY_MEDIUM  # effective_priority + 0 age

    def test_cfs_weight_uses_effective(self) -> None:
        """CFSPolicy.weight uses effective_priority, not base."""
        process = Process(name="test", priority=PRIORITY_LOW)
        process.effective_priority = PRIORITY_HIGH

        weight = CFSPolicy.weight(process)
        assert weight == PRIORITY_HIGH + 1

    def test_disabled_pi_has_no_effect(self) -> None:
        """When PI is disabled, on_block does not boost the holder."""
        mgr = PriorityInheritanceManager()
        mgr.enabled = False

        low = Process(name="low", priority=PRIORITY_LOW)
        high = Process(name="high", priority=PRIORITY_HIGH)
        processes = {low.pid: low, high.pid: high}

        mgr.on_acquire("m1", pid=low.pid)
        mgr.on_block("m1", waiter_pid=high.pid, processes=processes)

        assert low.effective_priority == PRIORITY_LOW


# -- Cycle 5: Integration tests -------------------------------------------


class TestPriorityInversionIntegration:
    """End-to-end tests: kernel, syscalls, and shell work with PI."""

    def test_kernel_creates_pi_manager_on_boot(self) -> None:
        """The kernel creates a PriorityInheritanceManager during boot."""
        kernel = _booted_kernel()
        assert kernel.pi_manager is not None
        kernel.shutdown()

    def test_acquire_mutex_with_pid_triggers_boost(self) -> None:
        """Acquiring a mutex with pid param records in PI manager."""
        kernel = _booted_kernel()
        kernel.create_mutex("test_lock")

        low = kernel.create_process(name="low", num_pages=NUM_PAGES, priority=PRIORITY_LOW)
        high = kernel.create_process(name="high", num_pages=NUM_PAGES, priority=PRIORITY_HIGH)

        # Low acquires the lock
        kernel.acquire_mutex("test_lock", tid=low.main_thread.tid, pid=low.pid)
        # High tries to acquire — blocks, low gets boosted
        kernel.acquire_mutex("test_lock", tid=high.main_thread.tid, pid=high.pid)

        assert low.effective_priority == PRIORITY_HIGH
        kernel.shutdown()

    def test_release_mutex_with_pid_restores(self) -> None:
        """Releasing a mutex with pid param restores the holder's priority."""
        kernel = _booted_kernel()
        kernel.create_mutex("test_lock")

        low = kernel.create_process(name="low", num_pages=NUM_PAGES, priority=PRIORITY_LOW)
        high = kernel.create_process(name="high", num_pages=NUM_PAGES, priority=PRIORITY_HIGH)

        kernel.acquire_mutex("test_lock", tid=low.main_thread.tid, pid=low.pid)
        kernel.acquire_mutex("test_lock", tid=high.main_thread.tid, pid=high.pid)
        assert low.effective_priority == PRIORITY_HIGH

        kernel.release_mutex("test_lock", tid=low.main_thread.tid, pid=low.pid)
        assert low.effective_priority == PRIORITY_LOW
        kernel.shutdown()

    def test_shell_pi_demo_and_status_commands(self) -> None:
        """The shell pi demo and pi status commands produce output."""
        kernel, shell = _booted_shell()
        demo_output = shell.execute("pi demo")
        assert "Mars Pathfinder" in demo_output or "priority" in demo_output.lower()

        status_output = shell.execute("pi status")
        assert "enabled" in status_output.lower() or "Priority Inheritance" in status_output
        kernel.shutdown()
