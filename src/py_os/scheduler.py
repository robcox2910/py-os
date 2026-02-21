"""CPU scheduler — decides which READY process gets the CPU next.

The scheduler owns the ready queue and delegates the *ordering* decision
to a pluggable SchedulingPolicy.  Three policies ship out of the box:

- **FCFSPolicy** (First Come, First Served): pure FIFO — simple, but a
  long-running process starves everyone behind it (convoy effect).
- **RoundRobinPolicy**: each process gets a fixed time quantum, then is
  preempted so the next process can run.  Fairer, but more context-switch
  overhead.
- **PriorityPolicy**: highest-priority process runs first.  Ties are
  broken by arrival order (FIFO).  Simple but susceptible to starvation
  of low-priority processes.

Design: Strategy pattern
    The Scheduler is the *context*; SchedulingPolicy is the *strategy*.
    Adding a new algorithm means writing a new policy class — existing
    code is never touched.
"""

from __future__ import annotations

from collections import deque
from typing import Protocol

from py_os.process import Process, ProcessState


class SchedulingPolicy(Protocol):
    """Interface that every scheduling algorithm must satisfy.

    The protocol defines two operations the scheduler needs:
    - select: pick the next process from the ready queue.
    - on_preempt: decide where to re-insert a preempted process.
    """

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Remove and return the next process to run, or None if empty."""
        ...  # pragma: no cover

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Re-insert a preempted process into the ready queue."""
        ...  # pragma: no cover


class FCFSPolicy:
    """First Come, First Served — processes run in arrival order.

    The simplest possible policy: a plain FIFO queue.  Whatever was
    added first gets dispatched first.  No preemption logic needed
    beyond appending to the back.
    """

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Pop the front of the queue (oldest arrival)."""
        if not ready_queue:
            return None
        return ready_queue.popleft()

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Append the preempted process to the back of the queue."""
        ready_queue.append(process)


class RoundRobinPolicy:
    """Round Robin — each process gets a fixed time quantum.

    Behaves like FCFS for ordering, but the scheduler is expected to
    preempt the running process after `quantum` ticks.  The quantum
    value is stored here so the scheduler (or a future clock module)
    can read it.
    """

    def __init__(self, *, quantum: int) -> None:
        """Create a Round Robin policy with the given time quantum.

        Args:
            quantum: Number of ticks before forced preemption.

        """
        self._quantum = quantum

    @property
    def quantum(self) -> int:
        """Return the time quantum (ticks per slice)."""
        return self._quantum

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Pop the front of the queue — same as FCFS for selection."""
        if not ready_queue:
            return None
        return ready_queue.popleft()

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Append the preempted process to the back — round-robin cycle."""
        ready_queue.append(process)


class PriorityPolicy:
    """Priority scheduling — highest priority process runs first.

    Non-preemptive: once dispatched, a process runs until termination or
    explicit preemption.  Higher priority values = more important.

    Starvation risk: low-priority processes can wait forever if high-
    priority work keeps arriving.  Real systems use aging to solve this.

    Tiebreaker: equal-priority processes use FIFO (first-added wins),
    since we scan left-to-right and the deque preserves insertion order.
    """

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Remove and return the highest-priority process, or None."""
        if not ready_queue:
            return None
        best_idx = 0
        for i in range(1, len(ready_queue)):
            if ready_queue[i].priority > ready_queue[best_idx].priority:
                best_idx = i
        # Remove the winner from the deque (O(n), fine for a learning sim)
        process = ready_queue[best_idx]
        del ready_queue[best_idx]
        return process

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Append the preempted process to the back of the queue."""
        ready_queue.append(process)


class Scheduler:
    """The CPU scheduler — manages the ready queue and current process.

    The scheduler does not *decide* the ordering — that's the policy's
    job.  The scheduler orchestrates: it validates states, calls the
    policy, and tracks which process currently owns the CPU.
    """

    def __init__(self, *, policy: SchedulingPolicy) -> None:
        """Create a scheduler with the given scheduling policy.

        Args:
            policy: The algorithm that determines dispatch order.

        """
        self._policy = policy
        self._ready_queue: deque[Process] = deque()
        self._current: Process | None = None

    @property
    def policy(self) -> SchedulingPolicy:
        """Return the current scheduling policy."""
        return self._policy

    @property
    def ready_count(self) -> int:
        """Return the number of processes in the ready queue."""
        return len(self._ready_queue)

    @property
    def current(self) -> Process | None:
        """Return the currently running process, or None."""
        return self._current

    def add(self, process: Process) -> None:
        """Add a READY process to the ready queue.

        Args:
            process: A process that has already been admitted (state=READY).

        Raises:
            RuntimeError: If the process is not in the READY state.

        """
        if process.state is not ProcessState.READY:
            msg = f"Cannot add process {process.pid}: state is {process.state}, expected ready"
            raise RuntimeError(msg)
        self._ready_queue.append(process)

    def dispatch(self) -> Process | None:
        """Select the next process and give it the CPU.

        Returns:
            The dispatched process, or None if the ready queue is empty.

        """
        process = self._policy.select(self._ready_queue)
        if process is None:
            return None
        process.dispatch()
        self._current = process
        return process

    def preempt(self) -> None:
        """Preempt the current process and return it to the ready queue.

        Raises:
            RuntimeError: If no process is currently running.

        """
        if self._current is None:
            msg = "No process is currently running"
            raise RuntimeError(msg)
        self._current.preempt()
        self._policy.on_preempt(self._ready_queue, self._current)
        self._current = None

    def terminate_current(self) -> None:
        """Terminate the currently running process.

        Raises:
            RuntimeError: If no process is currently running.

        """
        if self._current is None:
            msg = "No process is currently running"
            raise RuntimeError(msg)
        self._current.terminate()
        self._current = None
