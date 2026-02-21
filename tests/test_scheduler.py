"""Tests for the scheduler module.

The scheduler decides which READY process gets the CPU next. We test
six algorithms:

- FCFS (First Come, First Served): processes run in arrival order.
- Round Robin: each process gets a fixed time quantum, then yields.
- Priority: highest priority process runs first, FIFO tiebreaker.
- Aging Priority: like Priority, but waiting processes earn bonus priority
  over time to prevent starvation.
- MLFQ (Multilevel Feedback Queue): adaptive demotion with boost.
- CFS (Completely Fair Scheduler): weighted virtual runtime fairness.

All implementations share the same interface (SchedulingPolicy protocol)
so they can be swapped without changing the scheduler.
"""

import pytest

from py_os.process import Process, ProcessState
from py_os.scheduler import (
    AgingPriorityPolicy,
    CFSPolicy,
    FCFSPolicy,
    MLFQPolicy,
    PriorityPolicy,
    RoundRobinPolicy,
    Scheduler,
)

DEFAULT_QUANTUM = 2


class TestSchedulerCreation:
    """Verify scheduler initialisation."""

    def test_scheduler_starts_with_no_processes(self) -> None:
        """A new scheduler should have an empty ready queue."""
        scheduler = Scheduler(policy=FCFSPolicy())
        assert scheduler.ready_count == 0

    def test_scheduler_has_no_current_process(self) -> None:
        """No process should be running before the first dispatch."""
        scheduler = Scheduler(policy=FCFSPolicy())
        assert scheduler.current is None


class TestSchedulerAddAndDispatch:
    """Verify adding processes and dispatching them to the CPU."""

    def test_add_process_increases_ready_count(self) -> None:
        """Adding a READY process should increase the ready count."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        expected_count = 1
        assert scheduler.ready_count == expected_count

    def test_add_non_ready_process_raises(self) -> None:
        """Only READY processes can be added to the scheduler."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        with pytest.raises(RuntimeError, match="Cannot add"):
            scheduler.add(process)

    def test_dispatch_selects_a_process(self) -> None:
        """Dispatching should select a process and make it RUNNING."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        dispatched = scheduler.dispatch()
        assert dispatched is process
        assert process.state is ProcessState.RUNNING

    def test_dispatch_empty_queue_returns_none(self) -> None:
        """Dispatching with no READY processes should return None."""
        scheduler = Scheduler(policy=FCFSPolicy())
        assert scheduler.dispatch() is None

    def test_dispatch_decreases_ready_count(self) -> None:
        """Dispatching removes the process from the ready queue."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        scheduler.dispatch()
        assert scheduler.ready_count == 0

    def test_dispatch_sets_current(self) -> None:
        """After dispatch, the scheduler tracks the current process."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        scheduler.dispatch()
        assert scheduler.current is process


class TestSchedulerPreemptAndTerminate:
    """Verify preemption and termination of the current process."""

    def test_preempt_returns_process_to_ready_queue(self) -> None:
        """Preempting the current process should make it READY again."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        scheduler.dispatch()
        scheduler.preempt()
        assert process.state is ProcessState.READY
        expected_count = 1
        assert scheduler.ready_count == expected_count

    def test_preempt_clears_current(self) -> None:
        """After preemption, no process should be current."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        scheduler.dispatch()
        scheduler.preempt()
        assert scheduler.current is None

    def test_preempt_with_no_current_raises(self) -> None:
        """Cannot preempt when nothing is running."""
        scheduler = Scheduler(policy=FCFSPolicy())
        with pytest.raises(RuntimeError, match="No process"):
            scheduler.preempt()

    def test_terminate_current_process(self) -> None:
        """Terminating the current process should mark it TERMINATED."""
        scheduler = Scheduler(policy=FCFSPolicy())
        process = Process(name="init")
        process.admit()
        scheduler.add(process)
        scheduler.dispatch()
        scheduler.terminate_current()
        assert process.state is ProcessState.TERMINATED
        assert scheduler.current is None

    def test_terminate_with_no_current_raises(self) -> None:
        """Cannot terminate when nothing is running."""
        scheduler = Scheduler(policy=FCFSPolicy())
        with pytest.raises(RuntimeError, match="No process"):
            scheduler.terminate_current()


class TestFCFSPolicy:
    """Verify First Come, First Served scheduling order."""

    def test_fcfs_dispatches_in_arrival_order(self) -> None:
        """Processes should be dispatched in the order they were added."""
        scheduler = Scheduler(policy=FCFSPolicy())
        p1 = Process(name="first")
        p2 = Process(name="second")
        p3 = Process(name="third")
        for p in (p1, p2, p3):
            p.admit()
            scheduler.add(p)

        assert scheduler.dispatch() is p1
        scheduler.terminate_current()
        assert scheduler.dispatch() is p2
        scheduler.terminate_current()
        assert scheduler.dispatch() is p3


class TestRoundRobinPolicy:
    """Verify Round Robin scheduling with time quantum."""

    def test_round_robin_dispatches_in_order(self) -> None:
        """First dispatch should pick the first process added."""
        scheduler = Scheduler(policy=RoundRobinPolicy(quantum=DEFAULT_QUANTUM))
        p1 = Process(name="first")
        p2 = Process(name="second")
        for p in (p1, p2):
            p.admit()
            scheduler.add(p)

        assert scheduler.dispatch() is p1

    def test_round_robin_cycles_after_preemption(self) -> None:
        """After preemption, the next process should get the CPU."""
        scheduler = Scheduler(policy=RoundRobinPolicy(quantum=DEFAULT_QUANTUM))
        p1 = Process(name="first")
        p2 = Process(name="second")
        for p in (p1, p2):
            p.admit()
            scheduler.add(p)

        scheduler.dispatch()
        scheduler.preempt()
        assert scheduler.dispatch() is p2

    def test_round_robin_wraps_around(self) -> None:
        """After all processes have run, it should cycle back to the first."""
        scheduler = Scheduler(policy=RoundRobinPolicy(quantum=DEFAULT_QUANTUM))
        p1 = Process(name="first")
        p2 = Process(name="second")
        for p in (p1, p2):
            p.admit()
            scheduler.add(p)

        # p1 runs, preempted → p2 runs, preempted → back to p1
        scheduler.dispatch()
        scheduler.preempt()
        scheduler.dispatch()
        scheduler.preempt()
        assert scheduler.dispatch() is p1

    def test_round_robin_quantum_is_accessible(self) -> None:
        """The time quantum should be readable for tick-based simulation."""
        policy = RoundRobinPolicy(quantum=DEFAULT_QUANTUM)
        assert policy.quantum == DEFAULT_QUANTUM


# Named constants for priority test values.
HIGH_PRIORITY = 10
MEDIUM_PRIORITY = 5
LOW_PRIORITY = 1


def _ready(name: str, priority: int = 0) -> Process:
    """Create a READY process with the given name and priority."""
    p = Process(name=name, priority=priority)
    p.admit()
    return p


class TestPriorityPolicy:
    """Verify priority-based scheduling — highest priority runs first."""

    def test_selects_highest_priority(self) -> None:
        """Dispatch should pick the highest-priority process."""
        scheduler = Scheduler(policy=PriorityPolicy())
        p_low = _ready("low", LOW_PRIORITY)
        p_high = _ready("high", MEDIUM_PRIORITY)
        p_mid = _ready("mid", 3)
        for p in (p_low, p_high, p_mid):
            scheduler.add(p)

        assert scheduler.dispatch() is p_high

    def test_equal_priority_uses_fifo(self) -> None:
        """Equal-priority processes should dispatch in arrival order."""
        scheduler = Scheduler(policy=PriorityPolicy())
        p1 = _ready("first", MEDIUM_PRIORITY)
        p2 = _ready("second", MEDIUM_PRIORITY)
        p3 = _ready("third", MEDIUM_PRIORITY)
        for p in (p1, p2, p3):
            scheduler.add(p)

        assert scheduler.dispatch() is p1

    def test_across_multiple_dispatches(self) -> None:
        """Successive dispatches should follow descending priority."""
        scheduler = Scheduler(policy=PriorityPolicy())
        p_low = _ready("low", LOW_PRIORITY)
        p_mid = _ready("mid", 3)
        p_high = _ready("high", MEDIUM_PRIORITY)
        for p in (p_low, p_mid, p_high):
            scheduler.add(p)

        dispatched = scheduler.dispatch()
        assert dispatched is p_high
        scheduler.terminate_current()

        dispatched = scheduler.dispatch()
        assert dispatched is p_mid
        scheduler.terminate_current()

        dispatched = scheduler.dispatch()
        assert dispatched is p_low

    def test_preempted_process_competes_by_priority(self) -> None:
        """A preempted process re-enters and competes by priority."""
        scheduler = Scheduler(policy=PriorityPolicy())
        p_med = _ready("med", MEDIUM_PRIORITY)
        scheduler.add(p_med)
        scheduler.dispatch()  # med is RUNNING

        p_high = _ready("high", HIGH_PRIORITY)
        scheduler.add(p_high)
        scheduler.preempt()  # med back to queue

        assert scheduler.dispatch() is p_high

    def test_empty_queue_returns_none(self) -> None:
        """Dispatching from an empty queue should return None."""
        scheduler = Scheduler(policy=PriorityPolicy())
        assert scheduler.dispatch() is None

    def test_single_process(self) -> None:
        """A lone process should be dispatched regardless of priority."""
        scheduler = Scheduler(policy=PriorityPolicy())
        p = _ready("only", LOW_PRIORITY)
        scheduler.add(p)
        assert scheduler.dispatch() is p

    def test_integration_add_dispatch_preempt(self) -> None:
        """Full lifecycle: add → dispatch → preempt → re-dispatch by priority."""
        scheduler = Scheduler(policy=PriorityPolicy())
        p1 = _ready("a", LOW_PRIORITY)
        p2 = _ready("b", MEDIUM_PRIORITY)
        scheduler.add(p1)
        scheduler.add(p2)

        # Dispatch highest priority first
        assert scheduler.dispatch() is p2
        scheduler.preempt()

        # After preemption, p2 (prio 5) still beats p1 (prio 1)
        assert scheduler.dispatch() is p2
        scheduler.terminate_current()

        # Now only p1 remains
        assert scheduler.dispatch() is p1


# Named constants for aging priority tests.
DEFAULT_AGING_BOOST = 1
DEFAULT_MAX_AGE = 10


class TestAgingPriorityPolicy:
    """Verify priority scheduling with aging — prevents starvation."""

    def test_empty_queue_returns_none(self) -> None:
        """An empty queue should produce None."""
        policy = AgingPriorityPolicy()
        scheduler = Scheduler(policy=policy)
        assert scheduler.dispatch() is None

    def test_selects_highest_base_priority(self) -> None:
        """Without aging, behave like PriorityPolicy — highest priority wins."""
        scheduler = Scheduler(policy=AgingPriorityPolicy())
        p_low = _ready("low", LOW_PRIORITY)
        p_high = _ready("high", HIGH_PRIORITY)
        for p in (p_low, p_high):
            scheduler.add(p)

        assert scheduler.dispatch() is p_high

    def test_age_increments_on_each_dispatch(self) -> None:
        """After dispatch, non-selected processes' age should increase."""
        policy = AgingPriorityPolicy()
        scheduler = Scheduler(policy=policy)
        p_high = _ready("high", HIGH_PRIORITY)
        p_low = _ready("low", LOW_PRIORITY)
        for p in (p_high, p_low):
            scheduler.add(p)

        # Dispatch picks p_high; p_low should gain an age bonus
        scheduler.dispatch()
        assert policy.effective_priority(p_low) == LOW_PRIORITY + DEFAULT_AGING_BOOST

    def test_aging_overcomes_priority_gap(self) -> None:
        """A low-priority process eventually beats a high-priority one."""
        policy = AgingPriorityPolicy()
        scheduler = Scheduler(policy=policy)
        # Priority gap of 5 — with boost=1, low needs 6 rounds to overtake
        p_high = _ready("high", MEDIUM_PRIORITY)
        p_low = _ready("low", 0)
        for p in (p_high, p_low):
            scheduler.add(p)

        # Keep dispatching and preempting; p_high always wins at first
        dispatched_names: list[str] = []
        dispatch_limit = 20
        for _ in range(dispatch_limit):
            result = scheduler.dispatch()
            assert result is not None
            dispatched_names.append(result.name)
            scheduler.preempt()

        # p_low should eventually appear
        assert "low" in dispatched_names

    def test_age_resets_on_dispatch(self) -> None:
        """The dispatched process's age bonus should reset to 0."""
        policy = AgingPriorityPolicy()
        scheduler = Scheduler(policy=policy)
        p_high = _ready("high", HIGH_PRIORITY)
        p_low = _ready("low", LOW_PRIORITY)
        for p in (p_high, p_low):
            scheduler.add(p)

        scheduler.dispatch()  # p_high selected
        # p_high was dispatched, its age resets
        assert policy.effective_priority(p_high) == HIGH_PRIORITY

    def test_age_resets_on_preempt(self) -> None:
        """A preempted process's age should reset (it just ran)."""
        policy = AgingPriorityPolicy()
        scheduler = Scheduler(policy=policy)
        p = _ready("worker", MEDIUM_PRIORITY)
        scheduler.add(p)
        scheduler.dispatch()

        # Artificially check: after preempt, age resets
        scheduler.preempt()
        assert policy.effective_priority(p) == MEDIUM_PRIORITY

    def test_age_capped_at_max(self) -> None:
        """Age bonus should never exceed max_age."""
        max_age = 3
        policy = AgingPriorityPolicy(max_age=max_age)
        scheduler = Scheduler(policy=policy)
        p_high = _ready("high", HIGH_PRIORITY)
        p_low = _ready("low", LOW_PRIORITY)
        for p in (p_high, p_low):
            scheduler.add(p)

        # Dispatch many times — p_low ages but should be capped
        cap_rounds = 10
        for _ in range(cap_rounds):
            scheduler.dispatch()
            scheduler.preempt()

        # p_low's effective priority should not exceed base + max_age
        assert policy.effective_priority(p_low) <= LOW_PRIORITY + max_age

    def test_custom_boost_and_max(self) -> None:
        """Custom aging_boost and max_age should be stored correctly."""
        custom_boost = 2
        custom_max = 20
        policy = AgingPriorityPolicy(aging_boost=custom_boost, max_age=custom_max)
        assert policy.aging_boost == custom_boost
        assert policy.max_age == custom_max

    def test_equal_effective_priority_uses_fifo(self) -> None:
        """Tied effective priority should use FIFO (arrival order)."""
        scheduler = Scheduler(policy=AgingPriorityPolicy())
        p1 = _ready("first", MEDIUM_PRIORITY)
        p2 = _ready("second", MEDIUM_PRIORITY)
        p3 = _ready("third", MEDIUM_PRIORITY)
        for p in (p1, p2, p3):
            scheduler.add(p)

        assert scheduler.dispatch() is p1


# Named constants for MLFQ tests.
DEFAULT_MLFQ_LEVELS = 3
DEFAULT_MLFQ_BASE_QUANTUM = 2


class TestMLFQPolicy:
    """Verify Multilevel Feedback Queue scheduling with demotion and boost."""

    def test_empty_queue_returns_none(self) -> None:
        """An empty queue should produce None."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)
        assert scheduler.dispatch() is None

    def test_new_process_starts_at_top(self) -> None:
        """Unknown PIDs should be at level 0 (highest priority queue)."""
        policy = MLFQPolicy()
        assert policy.level(pid=42) == 0

    def test_quantum_doubles_per_level(self) -> None:
        """Default quanta should double each level: (2, 4, 8)."""
        policy = MLFQPolicy()
        expected = (DEFAULT_MLFQ_BASE_QUANTUM, 4, 8)
        assert policy.quantums == expected

    def test_custom_levels_and_quantum(self) -> None:
        """Custom levels and base quantum should produce correct quanta."""
        custom_levels = 4
        custom_base = 3
        policy = MLFQPolicy(num_levels=custom_levels, base_quantum=custom_base)
        expected = (3, 6, 12, 24)
        assert policy.quantums == expected
        assert policy.num_levels == custom_levels

    def test_selects_from_highest_queue(self) -> None:
        """A level-0 process should be selected before a level-2 process."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)

        # p1 will be demoted twice (to level 2)
        p1 = _ready("demoted")
        scheduler.add(p1)
        scheduler.dispatch()
        scheduler.preempt()  # p1 → level 1
        scheduler.dispatch()
        scheduler.preempt()  # p1 → level 2

        # p2 is new, so it starts at level 0
        p2 = _ready("fresh")
        scheduler.add(p2)

        # p2 at level 0 should beat p1 at level 2
        assert scheduler.dispatch() is p2

    def test_same_level_uses_fifo(self) -> None:
        """Processes at the same level should dispatch in arrival order."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("first")
        p2 = _ready("second")
        p3 = _ready("third")
        for p in (p1, p2, p3):
            scheduler.add(p)

        assert scheduler.dispatch() is p1

    def test_preemption_demotes(self) -> None:
        """After preemption, the process should move down one level."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)
        p = _ready("worker")
        scheduler.add(p)
        scheduler.dispatch()
        scheduler.preempt()

        expected_level = 1
        assert policy.level(pid=p.pid) == expected_level

    def test_bottom_level_stays_at_bottom(self) -> None:
        """Preemption at the bottom level should not go lower."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)
        p = _ready("heavy")
        scheduler.add(p)

        # Demote through all levels
        for _ in range(DEFAULT_MLFQ_LEVELS + 1):
            scheduler.dispatch()
            scheduler.preempt()

        bottom = DEFAULT_MLFQ_LEVELS - 1
        assert policy.level(pid=p.pid) == bottom

    def test_boost_resets_all_levels(self) -> None:
        """Boosting should reset all tracked processes to level 0."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("a")
        p2 = _ready("b")
        scheduler.add(p1)
        scheduler.add(p2)

        # Demote both
        scheduler.dispatch()
        scheduler.preempt()
        scheduler.dispatch()
        scheduler.preempt()

        policy.boost()
        assert policy.level(pid=p1.pid) == 0
        assert policy.level(pid=p2.pid) == 0

    def test_multi_level_dispatch_order_after_demotions(self) -> None:
        """Full scenario: add 3 procs, demote via preemption, verify order."""
        policy = MLFQPolicy()
        scheduler = Scheduler(policy=policy)

        p1 = _ready("a")
        p2 = _ready("b")
        p3 = _ready("c")
        for p in (p1, p2, p3):
            scheduler.add(p)

        # Dispatch p1 and demote it (level 0 → 1)
        assert scheduler.dispatch() is p1
        scheduler.preempt()

        # Dispatch p2 and demote it (level 0 → 1)
        assert scheduler.dispatch() is p2
        scheduler.preempt()

        # p3 still at level 0, should go next
        assert scheduler.dispatch() is p3
        scheduler.preempt()

        # Now p1 and p2 are both at level 1, p3 at level 1 too
        # FIFO within level 1: p1 was added first after demotion
        assert scheduler.dispatch() is p1


# Named constant for CFS tests.
DEFAULT_CFS_BASE_SLICE = 1
CFS_ROUNDS = 20


class TestCFSPolicy:
    """Verify Completely Fair Scheduler — weighted virtual runtime fairness."""

    def test_empty_queue_returns_none(self) -> None:
        """An empty queue should produce None."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        assert scheduler.dispatch() is None

    def test_single_process_selected(self) -> None:
        """A lone process should be selected."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p = _ready("only")
        scheduler.add(p)
        assert scheduler.dispatch() is p

    def test_equal_priority_round_robins(self) -> None:
        """Two equal-priority processes should alternate fairly."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("a")
        p2 = _ready("b")
        for p in (p1, p2):
            scheduler.add(p)

        names: list[str] = []
        for _ in range(CFS_ROUNDS):
            result = scheduler.dispatch()
            assert result is not None
            names.append(result.name)
            scheduler.preempt()

        # Both should appear roughly equally
        assert names.count("a") == names.count("b")

    def test_lowest_vruntime_wins(self) -> None:
        """After vruntime accumulation, the lower-vruntime process wins."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("a")
        p2 = _ready("b")
        for p in (p1, p2):
            scheduler.add(p)

        # Dispatch and preempt p1 — its vruntime increases
        scheduler.dispatch()  # picks p1 (FIFO tiebreak, both at 0)
        scheduler.preempt()  # p1's vruntime goes up

        # Now p2 has lower vruntime, should be picked
        assert scheduler.dispatch() is p2

    def test_higher_priority_gets_more_cpu(self) -> None:
        """A high-priority process should be selected more often over 20 rounds."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p_high = _ready("high", MEDIUM_PRIORITY)
        p_low = _ready("low", 0)
        for p in (p_high, p_low):
            scheduler.add(p)

        counts: dict[str, int] = {"high": 0, "low": 0}
        for _ in range(CFS_ROUNDS):
            result = scheduler.dispatch()
            assert result is not None
            counts[result.name] += 1
            scheduler.preempt()

        assert counts["high"] > counts["low"]

    def test_vruntime_increases_on_preempt(self) -> None:
        """After preempt, the process's vruntime should have increased."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p = _ready("worker")
        scheduler.add(p)
        scheduler.dispatch()

        vruntime_before = policy.vruntime(pid=p.pid)
        scheduler.preempt()
        vruntime_after = policy.vruntime(pid=p.pid)

        assert vruntime_after > vruntime_before

    def test_weight_from_priority(self) -> None:
        """Weight should equal max(1, priority + 1)."""
        p_zero = _ready("zero", 0)
        p_five = _ready("five", MEDIUM_PRIORITY)

        expected_weight_zero = 1
        expected_weight_five = MEDIUM_PRIORITY + 1
        assert CFSPolicy.weight(p_zero) == expected_weight_zero
        assert CFSPolicy.weight(p_five) == expected_weight_five

    def test_new_process_starts_at_min_vruntime(self) -> None:
        """A newly added process should get min_vruntime, not 0.

        Vruntime is assigned when select() first encounters an untracked
        PID, so we verify after dispatch.
        """
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("first")
        scheduler.add(p1)

        # Run p1 a few times to build up vruntime
        advance_rounds = 5
        for _ in range(advance_rounds):
            scheduler.dispatch()
            scheduler.preempt()

        # p1's vruntime should be > 0 now
        min_vr = policy.min_vruntime
        assert min_vr > 0.0

        # Add a new process — it should get min_vruntime on first select()
        p2 = _ready("second")
        scheduler.add(p2)

        # Trigger select() to assign vruntime, then preempt both back
        dispatched = scheduler.dispatch()
        assert dispatched is not None
        scheduler.preempt()

        # p2's base vruntime (before any preempt increment) should be min_vr
        # If p2 was dispatched, it now has min_vr; if p1 was dispatched,
        # p2 still got assigned min_vr during select's scan.
        # Either way, p2's pre-increment vruntime was min_vr.
        # After one preempt of the winner, check p2 is close to min_vr.
        assert policy.vruntime(pid=p2.pid) == pytest.approx(min_vr, abs=1.0)  # pyright: ignore[reportUnknownMemberType]

    def test_equal_vruntime_uses_fifo(self) -> None:
        """Tied vruntime should use FIFO order (left-to-right scan)."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("first")
        p2 = _ready("second")
        p3 = _ready("third")
        for p in (p1, p2, p3):
            scheduler.add(p)

        # All start at vruntime=0, so FIFO picks p1
        assert scheduler.dispatch() is p1

    def test_base_slice_property(self) -> None:
        """The base_slice property should return the configured value."""
        policy = CFSPolicy()
        assert policy.base_slice == DEFAULT_CFS_BASE_SLICE

    def test_min_vruntime_empty(self) -> None:
        """min_vruntime should be 0.0 when nothing is tracked."""
        policy = CFSPolicy()
        assert policy.min_vruntime == 0.0

    def test_custom_base_slice(self) -> None:
        """A non-default base_slice should change the accumulation rate."""
        custom_slice = 3
        policy = CFSPolicy(base_slice=custom_slice)
        scheduler = Scheduler(policy=policy)
        p = _ready("worker")
        scheduler.add(p)
        scheduler.dispatch()
        scheduler.preempt()

        # weight(priority=0) = 1, so vruntime += custom_slice / 1 = 3.0
        assert policy.vruntime(pid=p.pid) == pytest.approx(float(custom_slice))  # pyright: ignore[reportUnknownMemberType]

    def test_vruntime_query(self) -> None:
        """policy.vruntime(pid=X) should return the tracked value."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p = _ready("worker")
        scheduler.add(p)
        scheduler.dispatch()
        scheduler.preempt()

        # weight(priority=0) = 1, vruntime += 1/1 = 1.0
        assert policy.vruntime(pid=p.pid) == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]

    def test_fairness_over_many_rounds(self) -> None:
        """Over 20 cycles, equal-priority processes should have similar vruntime."""
        policy = CFSPolicy()
        scheduler = Scheduler(policy=policy)
        p1 = _ready("a")
        p2 = _ready("b")
        for p in (p1, p2):
            scheduler.add(p)

        for _ in range(CFS_ROUNDS):
            scheduler.dispatch()
            scheduler.preempt()

        vr1 = policy.vruntime(pid=p1.pid)
        vr2 = policy.vruntime(pid=p2.pid)
        assert vr1 == pytest.approx(vr2, abs=1.0)  # pyright: ignore[reportUnknownMemberType]
