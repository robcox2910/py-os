"""Tests for deadlock prevention via resource ordering.

**Deadlock** occurs when processes are stuck in a circular wait — each
holds a resource the next one needs, and none can proceed.  One way to
*prevent* deadlock (as opposed to *detecting* it after the fact) is
**resource ordering**: assign every resource a numeric rank, and require
processes to always acquire in ascending rank order.  A cycle becomes
structurally impossible because it would require someone to go "down"
in rank.

**Analogy:** Numbered lockers in a school hallway.  The rule: you can
only walk forward.  If you need locker 3 and locker 7, open 3 first,
then walk forward to 7.  You can never go backwards.  Nobody ever gets
stuck in a circle.
"""

from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.sync.ordering import OrderingMode, OrderingViolation, ResourceOrderingManager

# Named constants to satisfy PLR2004
RANK_1 = 1
RANK_2 = 2
RANK_3 = 3
RANK_5 = 5
RANK_10 = 10
PID_1 = 100
PID_2 = 200
NUM_PAGES = 1


# -- Helpers -----------------------------------------------------------------


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# -- Cycle 1: ResourceOrderingManager basics --------------------------------


class TestResourceOrderingBasics:
    """Verify register, rank lookup, auto-increment, and clear."""

    def test_register_assigns_explicit_rank(self) -> None:
        """Register a resource with an explicit rank."""
        mgr = ResourceOrderingManager()
        rank = mgr.register("mutex:lock_a", rank=RANK_5)
        assert rank == RANK_5
        assert mgr.rank("mutex:lock_a") == RANK_5

    def test_register_auto_increments(self) -> None:
        """Register without explicit rank uses auto-increment."""
        mgr = ResourceOrderingManager()
        r1 = mgr.register("mutex:first")
        r2 = mgr.register("mutex:second")
        assert r1 == RANK_1
        assert r2 == RANK_2

    def test_rank_returns_none_for_unknown(self) -> None:
        """Querying an unregistered resource returns None."""
        mgr = ResourceOrderingManager()
        assert mgr.rank("nonexistent") is None

    def test_clear_resets_all_state(self) -> None:
        """After clear(), ranks, held resources, and violations are gone."""
        mgr = ResourceOrderingManager()
        mgr.register("mutex:a", rank=RANK_1)
        mgr.on_acquire(PID_1, "mutex:a")
        mgr.clear()
        assert mgr.rank("mutex:a") is None
        assert mgr.held_by(PID_1) == {}
        assert mgr.violations() == []


# -- Cycle 2: Ordering enforcement ------------------------------------------


class TestOrderingEnforcement:
    """Verify ascending-order enforcement across strict, warn, and off modes."""

    def test_ascending_order_allowed(self) -> None:
        """Acquiring resources in ascending rank order is always allowed."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.STRICT
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_2)

        assert mgr.check_acquire(PID_1, "mutex:a") is True
        mgr.on_acquire(PID_1, "mutex:a")
        assert mgr.check_acquire(PID_1, "mutex:b") is True

    def test_descending_rejected_in_strict(self) -> None:
        """Descending order is rejected in strict mode."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.STRICT
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_2)

        mgr.on_acquire(PID_1, "mutex:b")  # rank 2
        assert mgr.check_acquire(PID_1, "mutex:a") is False  # rank 1 < 2

    def test_descending_warned_in_warn_mode(self) -> None:
        """Descending order is allowed but recorded in warn mode."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.WARN
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_2)

        mgr.on_acquire(PID_1, "mutex:b")
        result = mgr.check_acquire(PID_1, "mutex:a")
        assert result is True  # allowed
        assert len(mgr.violations()) == RANK_1  # but violation recorded

    def test_off_mode_skips_all_checks(self) -> None:
        """OFF mode never rejects and never records violations."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.OFF
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_2)

        mgr.on_acquire(PID_1, "mutex:b")
        assert mgr.check_acquire(PID_1, "mutex:a") is True
        assert mgr.violations() == []

    def test_equal_rank_is_violation(self) -> None:
        """Acquiring a resource with rank equal to max held is a violation."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.STRICT
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_1)

        mgr.on_acquire(PID_1, "mutex:a")
        assert mgr.check_acquire(PID_1, "mutex:b") is False


# -- Cycle 3: Process tracking ----------------------------------------------


class TestOrderingProcessTracking:
    """Verify on_acquire, on_release, remove_process, and violation details."""

    def test_on_acquire_tracks_held_resources(self) -> None:
        """After on_acquire, held_by returns the resource and rank."""
        mgr = ResourceOrderingManager()
        mgr.register("mutex:a", rank=RANK_3)
        mgr.on_acquire(PID_1, "mutex:a")
        held = mgr.held_by(PID_1)
        assert held == {"mutex:a": RANK_3}

    def test_on_release_removes_resource(self) -> None:
        """After on_release, the resource is no longer in held_by."""
        mgr = ResourceOrderingManager()
        mgr.register("mutex:a", rank=RANK_1)
        mgr.on_acquire(PID_1, "mutex:a")
        mgr.on_release(PID_1, "mutex:a")
        assert mgr.held_by(PID_1) == {}

    def test_remove_process_clears_all_held(self) -> None:
        """remove_process removes all tracking for a PID."""
        mgr = ResourceOrderingManager()
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_2)
        mgr.on_acquire(PID_1, "mutex:a")
        mgr.on_acquire(PID_1, "mutex:b")
        mgr.remove_process(PID_1)
        assert mgr.held_by(PID_1) == {}

    def test_violation_records_details(self) -> None:
        """Violation contains resource, requested rank, max held rank, and pid."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.WARN
        mgr.register("mutex:a", rank=RANK_1)
        mgr.register("mutex:b", rank=RANK_5)

        mgr.on_acquire(PID_2, "mutex:b")
        mgr.check_acquire(PID_2, "mutex:a")

        violations = mgr.violations()
        assert len(violations) == RANK_1
        v = violations[0]
        assert v == OrderingViolation(
            resource_requested="mutex:a",
            requested_rank=RANK_1,
            max_held_rank=RANK_5,
            pid=PID_2,
        )


# -- Cycle 4: Kernel integration -------------------------------------------


class TestKernelOrderingIntegration:
    """Verify kernel creates, uses, and cleans up the ordering manager."""

    def test_kernel_creates_manager_on_boot(self) -> None:
        """The kernel creates a ResourceOrderingManager during boot."""
        kernel = _booted_kernel()
        assert kernel.ordering_manager is not None
        kernel.shutdown()

    def test_acquire_mutex_checks_ordering(self) -> None:
        """Mutex acquire in ascending order is tracked by the ordering manager."""
        kernel = _booted_kernel()
        kernel.create_mutex("lock_a")
        kernel.create_mutex("lock_b")

        assert kernel.ordering_manager is not None
        kernel.ordering_manager.register("mutex:lock_a", rank=RANK_1)
        kernel.ordering_manager.register("mutex:lock_b", rank=RANK_2)

        proc = kernel.create_process(name="test", num_pages=NUM_PAGES)
        tid = proc.main_thread.tid

        kernel.acquire_mutex("lock_a", tid=tid, pid=proc.pid)
        kernel.acquire_mutex("lock_b", tid=tid, pid=proc.pid)

        held = kernel.ordering_manager.held_by(proc.pid)
        assert "mutex:lock_a" in held
        assert "mutex:lock_b" in held
        kernel.shutdown()

    def test_strict_mode_rejects_descending(self) -> None:
        """In strict mode, descending acquire returns False."""
        kernel = _booted_kernel()
        kernel.create_mutex("lock_a")
        kernel.create_mutex("lock_b")

        assert kernel.ordering_manager is not None
        kernel.ordering_manager.mode = OrderingMode.STRICT
        kernel.ordering_manager.register("mutex:lock_a", rank=RANK_1)
        kernel.ordering_manager.register("mutex:lock_b", rank=RANK_2)

        proc = kernel.create_process(name="test", num_pages=NUM_PAGES)
        tid = proc.main_thread.tid

        kernel.acquire_mutex("lock_b", tid=tid, pid=proc.pid)
        result = kernel.acquire_mutex("lock_a", tid=tid, pid=proc.pid)
        assert result is False
        kernel.shutdown()

    def test_terminate_cleans_ordering_state(self) -> None:
        """Terminating a process cleans up its ordering manager state."""
        kernel = _booted_kernel()
        kernel.create_mutex("lock_x")

        assert kernel.ordering_manager is not None
        kernel.ordering_manager.register("mutex:lock_x", rank=RANK_1)

        proc = kernel.create_process(name="test", num_pages=NUM_PAGES)
        pid = proc.pid
        tid = proc.main_thread.tid

        kernel.acquire_mutex("lock_x", tid=tid, pid=pid)
        assert kernel.ordering_manager.held_by(pid) != {}

        # Move to RUNNING so terminate_process can transition to TERMINATED
        proc.dispatch()
        kernel.terminate_process(pid=pid)
        assert kernel.ordering_manager.held_by(pid) == {}
        kernel.shutdown()


# -- Cycle 5: Shell commands ------------------------------------------------


class TestShellOrderingCommands:
    """Verify shell ordering command outputs."""

    def test_status_shows_ordering_table(self) -> None:
        """The status subcommand shows the ordering table and mode."""
        kernel, shell = _booted_shell()
        output = shell.execute("ordering status")
        assert "Mode:" in output
        assert "warn" in output.lower()
        kernel.shutdown()

    def test_mode_command_changes_mode(self) -> None:
        """The mode subcommand changes the enforcement mode."""
        kernel, shell = _booted_shell()
        output = shell.execute("ordering mode strict")
        assert "strict" in output.lower()
        assert kernel.ordering_manager is not None
        assert kernel.ordering_manager.mode is OrderingMode.STRICT
        kernel.shutdown()

    def test_demo_produces_output(self) -> None:
        """The demo subcommand produces educational output."""
        kernel, shell = _booted_shell()
        output = shell.execute("ordering demo")
        assert "locker" in output.lower() or "ordering" in output.lower()
        assert "violation" in output.lower() or "ascending" in output.lower()
        kernel.shutdown()

    def test_help_includes_ordering(self) -> None:
        """The help command lists the ordering command."""
        kernel, shell = _booted_shell()
        output = shell.execute("help")
        assert "ordering" in output
        kernel.shutdown()


# -- Extra: Auto-registration and enabled property --------------------------


class TestOrderingMiscellaneous:
    """Verify auto-registration and the enabled property."""

    def test_check_acquire_auto_registers(self) -> None:
        """check_acquire auto-registers unknown resources."""
        mgr = ResourceOrderingManager()
        mgr.check_acquire(PID_1, "mutex:new_one")
        assert mgr.rank("mutex:new_one") is not None

    def test_enabled_property(self) -> None:
        """Enabled is True for STRICT and WARN, False for OFF."""
        mgr = ResourceOrderingManager()
        mgr.mode = OrderingMode.STRICT
        assert mgr.enabled is True
        mgr.mode = OrderingMode.WARN
        assert mgr.enabled is True
        mgr.mode = OrderingMode.OFF
        assert mgr.enabled is False

    def test_ranks_returns_copy(self) -> None:
        """ranks() returns a copy, not the internal dict."""
        mgr = ResourceOrderingManager()
        mgr.register("mutex:a", rank=RANK_1)
        result = mgr.ranks()
        result["mutex:b"] = RANK_2
        assert mgr.rank("mutex:b") is None
