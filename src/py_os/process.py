"""Process and Process Control Block (PCB).

A process is a program in execution. The OS tracks each one via a PCB
containing its PID, state, priority, name, and parent relationship.

Processes follow a strict state machine — each transition method
(admit, dispatch, preempt, wait, wake, terminate) enforces that the
process is in the correct source state before moving it.

State machine::

    NEW → READY ⇄ RUNNING → TERMINATED
                    ↓  ↑
                  WAITING
"""

from enum import StrEnum
from itertools import count


class ProcessState(StrEnum):
    """Lifecycle states of a process.

    These mirror the classic five-state process model found in every
    OS textbook. Each state describes what the process is doing:

    - NEW: just created, not yet admitted to the scheduler.
    - READY: waiting in the ready queue for CPU time.
    - RUNNING: currently executing on the CPU.
    - WAITING: blocked on I/O or an event.
    - TERMINATED: finished, awaiting cleanup.
    """

    NEW = "new"
    READY = "ready"
    RUNNING = "running"
    WAITING = "waiting"
    TERMINATED = "terminated"


# Module-level PID counter. Using itertools.count gives us a thread-safe,
# monotonically increasing sequence without any global mutable state to
# manage manually. Each call to next(_pid_counter) yields the next int.
_pid_counter = count(start=1)


class Process:
    """A simulated process (the Process Control Block).

    The PCB is the data structure the OS uses to track everything about
    a process. In a real OS this lives in kernel memory and is never
    directly accessible to user-space code.

    State transitions are enforced: calling dispatch() on a NEW process
    raises RuntimeError, because the scheduler must admit it first.
    """

    def __init__(
        self,
        *,
        name: str,
        priority: int = 0,
        parent_pid: int | None = None,
    ) -> None:
        """Create a new process in the NEW state.

        Args:
            name: Human-readable label (e.g. "shell", "ls").
            priority: Scheduling priority (higher = more important).
            parent_pid: PID of the parent process, if any.

        """
        self._pid: int = next(_pid_counter)
        self._name: str = name
        self._state: ProcessState = ProcessState.NEW
        self._priority: int = priority
        self._parent_pid: int | None = parent_pid

    @property
    def pid(self) -> int:
        """Return the unique process identifier."""
        return self._pid

    @property
    def name(self) -> str:
        """Return the process name."""
        return self._name

    @property
    def state(self) -> ProcessState:
        """Return the current process state."""
        return self._state

    @property
    def priority(self) -> int:
        """Return the scheduling priority."""
        return self._priority

    @property
    def parent_pid(self) -> int | None:
        """Return the parent's PID, or None for root processes."""
        return self._parent_pid

    def _transition(self, action: str, expected: ProcessState, target: ProcessState) -> None:
        """Enforce a state transition.

        Args:
            action: Name of the transition (for error messages).
            expected: The state the process must be in.
            target: The state to move to.

        Raises:
            RuntimeError: If the process is not in the expected state.

        """
        if self._state is not expected:
            msg = f"Cannot {action}: process {self._pid} is {self._state}, expected {expected}"
            raise RuntimeError(msg)
        self._state = target

    def admit(self) -> None:
        """Transition NEW → READY. Admit the process to the ready queue."""
        self._transition("admit", ProcessState.NEW, ProcessState.READY)

    def dispatch(self) -> None:
        """Transition READY → RUNNING. Give the process the CPU."""
        self._transition("dispatch", ProcessState.READY, ProcessState.RUNNING)

    def preempt(self) -> None:
        """Transition RUNNING → READY. Yield the CPU back to the scheduler."""
        self._transition("preempt", ProcessState.RUNNING, ProcessState.READY)

    def wait(self) -> None:
        """Transition RUNNING → WAITING. Block on I/O or an event."""
        self._transition("wait", ProcessState.RUNNING, ProcessState.WAITING)

    def wake(self) -> None:
        """Transition WAITING → READY. I/O or event completed."""
        self._transition("wake", ProcessState.WAITING, ProcessState.READY)

    def terminate(self) -> None:
        """Transition RUNNING → TERMINATED. End the process."""
        self._transition("terminate", ProcessState.RUNNING, ProcessState.TERMINATED)

    def __repr__(self) -> str:
        """Return a debug-friendly representation."""
        return f"Process(pid={self._pid}, name={self._name!r}, state={self._state})"
