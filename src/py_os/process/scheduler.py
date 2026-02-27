"""CPU scheduler — decides which READY process gets the CPU next.

The scheduler owns the ready queue and delegates the *ordering* decision
to a pluggable SchedulingPolicy.  Six policies ship out of the box:

- **FCFSPolicy** (First Come, First Served): pure FIFO — simple, but a
  long-running process starves everyone behind it (convoy effect).
- **RoundRobinPolicy**: each process gets a fixed time quantum, then is
  preempted so the next process can run.  Fairer, but more context-switch
  overhead.
- **PriorityPolicy**: highest-priority process runs first.  Ties are
  broken by arrival order (FIFO).  Simple but susceptible to starvation
  of low-priority processes.
- **AgingPriorityPolicy**: like PriorityPolicy, but waiting processes
  earn a small priority bonus each scheduling round.  This prevents
  starvation — even a low-priority process eventually gets selected.
- **MLFQPolicy** (Multilevel Feedback Queue): adaptive scheduling with
  demotion.  New processes start at the highest-priority queue (shortest
  quantum).  Preempted processes are demoted to a lower queue with a
  longer quantum.  A periodic boost resets everyone to prevent starvation.
- **CFSPolicy** (Completely Fair Scheduler): tracks virtual runtime
  (vruntime) for each process, weighted by priority.  Always picks the
  process with the lowest vruntime, guaranteeing fair CPU share.

Design: Strategy pattern
    The Scheduler is the *context*; SchedulingPolicy is the *strategy*.
    Adding a new algorithm means writing a new policy class — existing
    code is never touched.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Protocol

from py_os.process.pcb import Process, ProcessState

if TYPE_CHECKING:
    from collections.abc import Callable


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
            if ready_queue[i].effective_priority > ready_queue[best_idx].effective_priority:
                best_idx = i
        # Remove the winner from the deque (O(n), fine for a learning sim)
        process = ready_queue[best_idx]
        del ready_queue[best_idx]
        return process

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Append the preempted process to the back of the queue."""
        ready_queue.append(process)


class AgingPriorityPolicy:
    """Priority scheduling with aging — prevent starvation.

    Like PriorityPolicy, the highest effective priority wins.  But each
    time the scheduler runs, every waiting process earns a small bonus.
    This means even a low-priority process will eventually collect enough
    bonus to be selected.  Once dispatched, the bonus resets to zero.
    """

    def __init__(self, *, aging_boost: int = 1, max_age: int = 10) -> None:
        """Create an aging priority policy.

        Args:
            aging_boost: Priority bonus awarded each scheduling round.
            max_age: Maximum accumulated age bonus.

        """
        self._aging_boost = aging_boost
        self._max_age = max_age
        self._ages: dict[int, int] = {}  # PID → accumulated age bonus

    @property
    def aging_boost(self) -> int:
        """Return the per-round priority bonus."""
        return self._aging_boost

    @property
    def max_age(self) -> int:
        """Return the maximum age bonus."""
        return self._max_age

    def effective_priority(self, process: Process) -> int:
        """Return effective priority plus accumulated age bonus."""
        return process.effective_priority + self._ages.get(process.pid, 0)

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Age all waiting processes, then pick the highest effective priority."""
        if not ready_queue:
            return None

        # Age every process in the queue
        for proc in ready_queue:
            current_age = self._ages.get(proc.pid, 0)
            self._ages[proc.pid] = min(current_age + self._aging_boost, self._max_age)

        # Find the highest effective priority (FIFO tiebreak via left-to-right scan)
        best_idx = 0
        best_eff = self.effective_priority(ready_queue[0])
        for i in range(1, len(ready_queue)):
            eff = self.effective_priority(ready_queue[i])
            if eff > best_eff:
                best_eff = eff
                best_idx = i

        process = ready_queue[best_idx]
        del ready_queue[best_idx]

        # Reset winner's age
        self._ages[process.pid] = 0
        return process

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Reset the preempted process's age and re-insert at back."""
        self._ages[process.pid] = 0
        ready_queue.append(process)


class MLFQPolicy:
    """Multilevel Feedback Queue — adaptive scheduling with demotion.

    New processes start at level 0 (shortest quantum).  If preempted,
    they are demoted to the next level (longer quantum).  A periodic
    boost resets everyone to level 0 to prevent starvation.

    Levels are tracked externally in a PID → level dict so the policy
    works with the scheduler's single ``deque[Process]`` ready queue.
    """

    def __init__(self, *, num_levels: int = 3, base_quantum: int = 2) -> None:
        """Create an MLFQ policy with the given number of levels.

        Quanta double each level: ``[base, base*2, base*4, ...]``.

        Args:
            num_levels: Number of priority queues (default 3).
            base_quantum: Time quantum for the top-level queue (default 2).

        """
        self._num_levels = num_levels
        self._quantums = tuple(base_quantum * (2**i) for i in range(num_levels))
        self._levels: dict[int, int] = {}

    @property
    def num_levels(self) -> int:
        """Return the number of priority levels."""
        return self._num_levels

    @property
    def quantums(self) -> tuple[int, ...]:
        """Return the quanta for each level."""
        return self._quantums

    def level(self, *, pid: int) -> int:
        """Return the current level for *pid* (0 if unknown)."""
        return self._levels.get(pid, 0)

    def quantum_for(self, *, pid: int) -> int:
        """Return the time quantum for *pid*'s current level."""
        return self._quantums[self.level(pid=pid)]

    def boost(self) -> None:
        """Reset all tracked processes to level 0 (anti-starvation)."""
        self._levels.clear()

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Select the highest-level (lowest number) process, FIFO tiebreak."""
        if not ready_queue:
            return None
        best_idx = 0
        best_level = self.level(pid=ready_queue[0].pid)
        for i in range(1, len(ready_queue)):
            proc_level = self.level(pid=ready_queue[i].pid)
            if proc_level < best_level:
                best_level = proc_level
                best_idx = i
        process = ready_queue[best_idx]
        del ready_queue[best_idx]
        return process

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Demote the preempted process one level and re-insert at back."""
        current = self.level(pid=process.pid)
        self._levels[process.pid] = min(current + 1, self._num_levels - 1)
        ready_queue.append(process)


class CFSPolicy:
    """Completely Fair Scheduler — weighted virtual runtime fairness.

    CFS guarantees every process gets a fair share of CPU time
    proportional to its weight (derived from priority).  It tracks
    virtual runtime (vruntime) — how much weighted CPU time each
    process has consumed — and always picks the process with the
    lowest vruntime.

    Think of a pizza party where the host keeps a notebook tracking
    how many slices each person has eaten.  The person who has eaten
    the fewest goes next.  Kids with extra toppings (higher priority)
    have their count go up more slowly, so they eat more total slices
    before their number catches up.
    """

    def __init__(self, *, base_slice: int = 1) -> None:
        """Create a CFS policy with the given base slice.

        Args:
            base_slice: Base vruntime increment per scheduling round.

        """
        self._base_slice = base_slice
        self._vruntimes: dict[int, float] = {}

    @property
    def base_slice(self) -> int:
        """Return the base vruntime increment."""
        return self._base_slice

    @property
    def min_vruntime(self) -> float:
        """Return the minimum vruntime across all tracked processes, or 0.0."""
        if not self._vruntimes:
            return 0.0
        return min(self._vruntimes.values())

    def vruntime(self, *, pid: int) -> float:
        """Return the tracked vruntime for *pid* (0.0 if unknown)."""
        return self._vruntimes.get(pid, 0.0)

    @staticmethod
    def weight(process: Process) -> int:
        """Return the scheduling weight for *process*.

        Higher priority → higher weight → slower vruntime growth → more CPU.
        """
        return max(1, process.effective_priority + 1)

    def select(self, ready_queue: deque[Process]) -> Process | None:
        """Pick the process with the lowest vruntime (FIFO tiebreak).

        New PIDs that aren't yet tracked get assigned ``min_vruntime``
        so they don't jump ahead or fall behind unfairly.
        """
        if not ready_queue:
            return None

        # Assign min_vruntime to any untracked processes
        min_vr = self.min_vruntime
        for proc in ready_queue:
            if proc.pid not in self._vruntimes:
                self._vruntimes[proc.pid] = min_vr

        # Find the lowest vruntime (left-to-right scan for FIFO tiebreak)
        best_idx = 0
        best_vr = self._vruntimes[ready_queue[0].pid]
        for i in range(1, len(ready_queue)):
            vr = self._vruntimes[ready_queue[i].pid]
            if vr < best_vr:
                best_vr = vr
                best_idx = i

        process = ready_queue[best_idx]
        del ready_queue[best_idx]
        return process

    def on_preempt(self, ready_queue: deque[Process], process: Process) -> None:
        """Increment vruntime by ``base_slice / weight`` and re-insert at back."""
        w = self.weight(process)
        self._vruntimes[process.pid] = self._vruntimes.get(process.pid, 0.0) + (
            self._base_slice / w
        )
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
        self._context_switches: int = 0

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

    @property
    def context_switches(self) -> int:
        """Return the total number of context switches (dispatches)."""
        return self._context_switches

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
        self._context_switches += 1
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

    def reset_counters(self) -> None:
        """Reset the context switch counter to zero."""
        self._context_switches = 0

    @property
    def ready_processes(self) -> list[Process]:
        """Return a snapshot of the ready queue as a list."""
        return list(self._ready_queue)

    def purge_terminated(self) -> int:
        """Remove all terminated processes from the ready queue.

        Returns:
            Number of processes removed.

        """
        before = len(self._ready_queue)
        self._ready_queue = deque(
            p for p in self._ready_queue if p.state is not ProcessState.TERMINATED
        )
        return before - len(self._ready_queue)

    def extract_from_ready(self, pid: int) -> Process | None:
        """Remove a process by PID from the ready queue.

        Args:
            pid: The PID to search for and remove.

        Returns:
            The removed process, or None if not found.

        """
        for i, proc in enumerate(self._ready_queue):
            if proc.pid == pid:
                del self._ready_queue[i]
                return proc
        return None


class MultiCPUScheduler:
    """Coordinate N per-CPU schedulers with load balancing.

    Wraps N ``Scheduler`` instances — one per CPU.  Each CPU has its
    own ready queue and current process.  The wrapper provides:

    - **Backward-compatible interface** — ``add()``, ``dispatch()``,
      ``preempt()``, ``current``, ``ready_count`` all default to CPU 0,
      so existing kernel code works unchanged for ``num_cpus=1``.
    - **Per-CPU access** — ``cpu_scheduler()``, ``cpu_current()``,
      ``cpu_ready_count()`` for inspecting individual CPUs.
    - **Load balancing** — ``balance()`` moves processes from overloaded
      CPUs to underloaded ones, respecting affinity constraints.
    - **CPU affinity** — ``set_affinity()`` / ``get_affinity()`` pin
      processes to specific CPUs.

    Think of it like a school with multiple whiteboards.  Each whiteboard
    has its own queue of students.  The teacher (scheduler) can move
    students between queues when one gets too long.
    """

    def __init__(
        self,
        *,
        num_cpus: int = 1,
        policy_factory: Callable[[], SchedulingPolicy],
    ) -> None:
        """Create a multi-CPU scheduler with N per-CPU schedulers.

        Args:
            num_cpus: Number of CPUs (each gets its own Scheduler).
            policy_factory: Callable that creates a fresh policy instance
                for each CPU (e.g. ``FCFSPolicy`` or
                ``lambda: RoundRobinPolicy(quantum=4)``).

        """
        if num_cpus < 1:
            msg = "num_cpus must be at least 1"
            raise ValueError(msg)
        self._num_cpus = num_cpus
        self._policy_factory = policy_factory
        self._schedulers: list[Scheduler] = [
            Scheduler(policy=policy_factory()) for _ in range(num_cpus)
        ]
        self._affinities: dict[int, frozenset[int]] = {}
        self._migrations: int = 0

    # -- Backward-compatible interface (defaults to CPU 0) --------------------

    def add(self, process: Process, *, cpu_id: int | None = None) -> None:
        """Add a READY process to a CPU's ready queue.

        When ``cpu_id`` is None, the process is placed on the
        least-loaded CPU that is allowed by its affinity mask.

        Args:
            process: A process that has been admitted (state=READY).
            cpu_id: Explicit CPU, or None for auto-assignment.

        """
        if cpu_id is not None:
            self._schedulers[cpu_id].add(process)
            process.cpu_id = cpu_id
            return
        # Auto-assign: pick the least-loaded allowed CPU
        target = self._least_loaded_cpu(process.pid)
        self._schedulers[target].add(process)
        process.cpu_id = target

    def dispatch(self, *, cpu_id: int = 0) -> Process | None:
        """Select the next process on *cpu_id* and give it the CPU.

        Returns:
            The dispatched process, or None if the queue is empty.

        """
        proc = self._schedulers[cpu_id].dispatch()
        if proc is not None:
            proc.cpu_id = cpu_id
        return proc

    def preempt(self, *, cpu_id: int = 0) -> None:
        """Preempt the current process on *cpu_id*."""
        self._schedulers[cpu_id].preempt()

    def terminate_current(self, *, cpu_id: int = 0) -> None:
        """Terminate the current process on *cpu_id*."""
        self._schedulers[cpu_id].terminate_current()

    # -- Aggregate properties (backward compat) -------------------------------

    @property
    def current(self) -> Process | None:
        """Return CPU 0's current process (backward compat)."""
        return self._schedulers[0].current

    @property
    def ready_count(self) -> int:
        """Return total ready processes across all CPUs."""
        return sum(s.ready_count for s in self._schedulers)

    @property
    def context_switches(self) -> int:
        """Return total context switches across all CPUs."""
        return sum(s.context_switches for s in self._schedulers)

    @property
    def policy(self) -> SchedulingPolicy:
        """Return CPU 0's policy (backward compat)."""
        return self._schedulers[0].policy

    # -- Multi-CPU specific ---------------------------------------------------

    @property
    def num_cpus(self) -> int:
        """Return the number of CPUs."""
        return self._num_cpus

    @property
    def migrations(self) -> int:
        """Return the total number of process migrations."""
        return self._migrations

    def reset_counters(self) -> None:
        """Reset all context switch counters and migration count to zero."""
        for s in self._schedulers:
            s.reset_counters()
        self._migrations = 0

    def purge_terminated(self) -> int:
        """Remove terminated processes from all CPU ready queues.

        Returns:
            Total number of processes removed.

        """
        return sum(s.purge_terminated() for s in self._schedulers)

    def cpu_scheduler(self, cpu_id: int) -> Scheduler:
        """Return the per-CPU scheduler for *cpu_id*."""
        return self._schedulers[cpu_id]

    def cpu_current(self, cpu_id: int) -> Process | None:
        """Return the current process on *cpu_id*."""
        return self._schedulers[cpu_id].current

    def cpu_ready_count(self, cpu_id: int) -> int:
        """Return the ready queue length for *cpu_id*."""
        return self._schedulers[cpu_id].ready_count

    def dispatch_all(self) -> dict[int, Process | None]:
        """Dispatch on every CPU and return the results.

        Returns:
            Dict mapping cpu_id to the dispatched process (or None).

        """
        return {i: self.dispatch(cpu_id=i) for i in range(self._num_cpus)}

    def balance(self) -> list[tuple[int, int, int]]:
        """Balance load across CPUs by migrating processes.

        Move processes from the busiest CPU to the least busy until
        the difference is at most 1.  Respects affinity — pinned
        processes are never moved.

        Returns:
            List of (pid, from_cpu, to_cpu) tuples for each migration.

        """
        moved: list[tuple[int, int, int]] = []
        while True:
            loads = [s.ready_count for s in self._schedulers]
            max_cpu = loads.index(max(loads))
            min_cpu = loads.index(min(loads))
            threshold = 2
            if loads[max_cpu] - loads[min_cpu] < threshold:
                break
            migrated = self._migrate_one(max_cpu, min_cpu)
            if migrated is None:
                break
            moved.append(migrated)
        return moved

    def migrate(self, pid: int, from_cpu: int, to_cpu: int) -> bool:
        """Migrate a specific process between CPUs.

        Args:
            pid: The process ID to migrate.
            from_cpu: Source CPU.
            to_cpu: Destination CPU.

        Returns:
            True if migration succeeded, False otherwise.

        """
        allowed = self._affinities.get(pid, frozenset(range(self._num_cpus)))
        if to_cpu not in allowed:
            return False
        sched = self._schedulers[from_cpu]
        proc = sched.extract_from_ready(pid)
        if proc is None:
            return False
        proc.cpu_id = to_cpu
        self._schedulers[to_cpu].add(proc)
        self._migrations += 1
        return True

    def set_affinity(self, pid: int, cpus: frozenset[int]) -> None:
        """Set the CPU affinity mask for a process.

        Args:
            pid: The process ID.
            cpus: Frozenset of allowed CPU IDs.

        """
        self._affinities[pid] = cpus

    def get_affinity(self, pid: int) -> frozenset[int]:
        """Return the CPU affinity mask for a process.

        Defaults to all CPUs if no affinity has been set.
        """
        return self._affinities.get(pid, frozenset(range(self._num_cpus)))

    # -- Private helpers ------------------------------------------------------

    def _least_loaded_cpu(self, pid: int) -> int:
        """Return the CPU with the fewest ready processes allowed by affinity."""
        allowed = self._affinities.get(pid, frozenset(range(self._num_cpus)))
        return min(allowed, key=lambda c: self._schedulers[c].ready_count)

    def _migrate_one(self, from_cpu: int, to_cpu: int) -> tuple[int, int, int] | None:
        """Move one migratable process from *from_cpu* to *to_cpu*.

        Returns:
            ``(pid, from_cpu, to_cpu)`` on success, or None if nothing
            can be moved (all processes are pinned).

        """
        sched = self._schedulers[from_cpu]
        for proc in sched.ready_processes:
            allowed = self._affinities.get(proc.pid, frozenset(range(self._num_cpus)))
            if to_cpu in allowed:
                extracted = sched.extract_from_ready(proc.pid)
                if extracted is not None:
                    extracted.cpu_id = to_cpu
                    self._schedulers[to_cpu].add(extracted)
                    self._migrations += 1
                    return (extracted.pid, from_cpu, to_cpu)
        return None
