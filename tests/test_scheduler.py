"""Tests for the scheduler module.

The scheduler decides which READY process gets the CPU next. We test
three algorithms:

- FCFS (First Come, First Served): processes run in arrival order.
- Round Robin: each process gets a fixed time quantum, then yields.
- Priority: highest priority process runs first, FIFO tiebreaker.

All implementations share the same interface (SchedulingPolicy protocol)
so they can be swapped without changing the scheduler.
"""

import pytest

from py_os.process import Process, ProcessState
from py_os.scheduler import FCFSPolicy, PriorityPolicy, RoundRobinPolicy, Scheduler

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
