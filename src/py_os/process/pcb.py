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

from __future__ import annotations

from enum import StrEnum
from itertools import count
from typing import TYPE_CHECKING

from py_os.process.threads import Thread

if TYPE_CHECKING:
    from collections.abc import Callable

    from py_os.memory.virtual import VirtualMemory


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
        self._effective_priority: int = priority
        self._parent_pid: int | None = parent_pid
        self._virtual_memory: VirtualMemory | None = None
        self._program: Callable[[], str] | None = None
        self._output: str | None = None
        self._exit_code: int | None = None
        self._wait_target: int | None = None

        # Thread management — every process has at least one thread
        self._next_tid = count(start=1)
        self._threads: dict[int, Thread] = {
            0: Thread(tid=0, name="main", pid=self._pid),
        }

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
        """Return the base scheduling priority (immutable)."""
        return self._priority

    @property
    def effective_priority(self) -> int:
        """Return the effective scheduling priority (may be boosted by inheritance)."""
        return self._effective_priority

    @effective_priority.setter
    def effective_priority(self, value: int) -> None:
        """Set the effective priority (used by priority inheritance)."""
        self._effective_priority = value

    @property
    def virtual_memory(self) -> VirtualMemory | None:
        """Return the process's virtual memory, or None if not assigned."""
        return self._virtual_memory

    @virtual_memory.setter
    def virtual_memory(self, vm: VirtualMemory | None) -> None:
        """Set the process's virtual memory."""
        self._virtual_memory = vm

    @property
    def parent_pid(self) -> int | None:
        """Return the parent's PID, or None for root processes."""
        return self._parent_pid

    @property
    def program(self) -> Callable[[], str] | None:
        """Return the loaded program, or None if no program is set."""
        return self._program

    @program.setter
    def program(self, prog: Callable[[], str] | None) -> None:
        """Load a program (callable) into this process."""
        self._program = prog

    @property
    def output(self) -> str | None:
        """Return the program's output, or None if not yet executed."""
        return self._output

    @property
    def exit_code(self) -> int | None:
        """Return the exit code, or None if not yet executed."""
        return self._exit_code

    @property
    def wait_target(self) -> int | None:
        """Return the PID this process is waiting to collect.

        None means not waiting, -1 means any child, positive int means
        a specific child PID.
        """
        return self._wait_target

    @wait_target.setter
    def wait_target(self, target: int | None) -> None:
        """Set the child PID this process is waiting for."""
        self._wait_target = target

    def execute(self) -> None:
        """Run the loaded program and capture its output and exit code.

        The process must be in RUNNING state with a program loaded.
        On success, exit_code is 0 and output is the return value.
        On failure (exception), exit_code is 1 and output is the error message.

        Raises:
            RuntimeError: If the process is not running or has no program.

        """
        if self._state is not ProcessState.RUNNING:
            msg = f"Cannot execute: process {self._pid} is not running"
            raise RuntimeError(msg)
        if self._program is None:
            msg = f"No program loaded in process {self._pid}"
            raise RuntimeError(msg)
        try:
            self._output = self._program()
            self._exit_code = 0
        except Exception as e:
            self._output = str(e)
            self._exit_code = 1

    @property
    def threads(self) -> dict[int, Thread]:
        """Return the thread table (TID → Thread mapping)."""
        return dict(self._threads)

    @property
    def main_thread(self) -> Thread:
        """Return the main thread (TID 0)."""
        return self._threads[0]

    def create_thread(self, name: str) -> Thread:
        """Create a new thread within this process.

        The thread shares this process's virtual memory — no new
        memory is allocated.  Thread IDs are assigned sequentially
        starting from 1 (TID 0 is reserved for the main thread).

        Args:
            name: Human-readable label for the thread.

        Returns:
            The newly created thread (in NEW state).

        """
        tid = next(self._next_tid)
        thread = Thread(tid=tid, name=name, pid=self._pid)
        self._threads[tid] = thread
        return thread

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

    def force_terminate(self) -> None:
        """Force termination from any non-terminated state.

        This is the SIGKILL path — the process is killed unconditionally.
        Unlike terminate(), this works from READY, RUNNING, or WAITING.

        Raises:
            RuntimeError: If the process is already TERMINATED or NEW.

        """
        if self._state is ProcessState.TERMINATED:
            msg = f"Cannot force_terminate: process {self._pid} is already terminated"
            raise RuntimeError(msg)
        if self._state is ProcessState.NEW:
            msg = f"Cannot force_terminate: process {self._pid} is not yet admitted"
            raise RuntimeError(msg)
        self._state = ProcessState.TERMINATED

    def __repr__(self) -> str:
        """Return a debug-friendly representation."""
        return f"Process(pid={self._pid}, name={self._name!r}, state={self._state})"
