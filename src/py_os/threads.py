"""Threads — lightweight execution units within a process.

A **thread** is the smallest unit of execution that the OS schedules.
Every process has at least one thread (the "main thread").  Additional
threads share the process's resources — most importantly, its virtual
memory (address space).

Threads vs Processes:
    - **Process** = resource container (memory, open files, PID).
    - **Thread** = execution context (state, program counter, stack).
    - Multiple threads within a process share the same memory.
    - Creating a thread is cheap — no memory is copied or allocated.
    - This sharing is powerful but dangerous: concurrent writes to
      shared memory can cause **race conditions** (a topic for later).

Thread lifecycle (same five-state model as processes)::

    NEW → READY ⇄ RUNNING → TERMINATED
                    ↓  ↑
                  WAITING

Thread IDs (TIDs) are scoped per-process — TID 0 is always the main
thread.  In Linux, threads actually have globally-unique task IDs, but
per-process TIDs are clearer for learning.
"""

from enum import StrEnum


class ThreadState(StrEnum):
    """Lifecycle states of a thread.

    These mirror ProcessState exactly — threads follow the same
    state machine.  We define a separate enum to make clear that
    thread state is conceptually independent from process state,
    even though the values are identical.
    """

    NEW = "new"
    READY = "ready"
    RUNNING = "running"
    WAITING = "waiting"
    TERMINATED = "terminated"


class Thread:
    """A lightweight execution unit within a process.

    Each thread has its own TID, name, and lifecycle state.  All
    threads within a process share the same virtual memory — they
    access it through the parent process, not through their own copy.
    """

    def __init__(self, *, tid: int, name: str, pid: int) -> None:
        """Create a thread in the NEW state.

        Args:
            tid: Thread ID (unique within the parent process).
            name: Human-readable label (e.g. "main", "worker-1").
            pid: PID of the parent process.

        """
        self._tid = tid
        self._name = name
        self._pid = pid
        self._state = ThreadState.NEW

    @property
    def tid(self) -> int:
        """Return the thread ID (unique within the process)."""
        return self._tid

    @property
    def name(self) -> str:
        """Return the thread name."""
        return self._name

    @property
    def pid(self) -> int:
        """Return the PID of the parent process."""
        return self._pid

    @property
    def state(self) -> ThreadState:
        """Return the current thread state."""
        return self._state

    def _transition(self, action: str, expected: ThreadState, target: ThreadState) -> None:
        """Enforce a state transition.

        Args:
            action: Name of the transition (for error messages).
            expected: The state the thread must be in.
            target: The state to move to.

        Raises:
            RuntimeError: If the thread is not in the expected state.

        """
        if self._state is not expected:
            msg = f"Cannot {action}: thread {self._tid} is {self._state}, expected {expected}"
            raise RuntimeError(msg)
        self._state = target

    def admit(self) -> None:
        """Transition NEW → READY."""
        self._transition("admit", ThreadState.NEW, ThreadState.READY)

    def dispatch(self) -> None:
        """Transition READY → RUNNING."""
        self._transition("dispatch", ThreadState.READY, ThreadState.RUNNING)

    def preempt(self) -> None:
        """Transition RUNNING → READY."""
        self._transition("preempt", ThreadState.RUNNING, ThreadState.READY)

    def wait(self) -> None:
        """Transition RUNNING → WAITING."""
        self._transition("wait", ThreadState.RUNNING, ThreadState.WAITING)

    def wake(self) -> None:
        """Transition WAITING → READY."""
        self._transition("wake", ThreadState.WAITING, ThreadState.READY)

    def terminate(self) -> None:
        """Transition RUNNING → TERMINATED."""
        self._transition("terminate", ThreadState.RUNNING, ThreadState.TERMINATED)

    def force_terminate(self) -> None:
        """Force termination from any non-terminated state.

        Raises:
            RuntimeError: If the thread is already TERMINATED or NEW.

        """
        if self._state is ThreadState.TERMINATED:
            msg = f"Cannot force_terminate: thread {self._tid} is already terminated"
            raise RuntimeError(msg)
        if self._state is ThreadState.NEW:
            msg = f"Cannot force_terminate: thread {self._tid} is not yet admitted"
            raise RuntimeError(msg)
        self._state = ThreadState.TERMINATED

    def __repr__(self) -> str:
        """Return a debug-friendly representation."""
        return f"Thread(tid={self._tid}, name={self._name!r}, state={self._state})"
