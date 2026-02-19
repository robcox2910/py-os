"""Tests for the scheduler module.

The scheduler decides which READY process gets the CPU next. We test
two algorithms:

- FCFS (First Come, First Served): processes run in arrival order.
- Round Robin: each process gets a fixed time quantum, then yields.

Both implementations share the same interface (SchedulingPolicy protocol)
so they can be swapped without changing the scheduler.
"""

import pytest

from py_os.process import Process, ProcessState
from py_os.scheduler import FCFSPolicy, RoundRobinPolicy, Scheduler

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
