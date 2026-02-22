"""Priority inheritance protocol — prevent priority inversion.

Priority inversion happens when a high-priority thread blocks on a mutex
held by a low-priority thread, while a medium-priority thread (which
doesn't need the mutex) keeps running instead.  The high-priority thread
starves because the scheduler never gives the low-priority holder enough
CPU time to finish and release the lock.

The fix is **priority inheritance**: when a high-priority thread blocks
on a mutex held by a lower-priority thread, the kernel temporarily
boosts the holder's effective priority to match the waiter's.  This
lets the holder run, release the lock, and restore normal scheduling.

The ``PriorityInheritanceManager`` coordinates this at the kernel level.
The Mutex itself stays simple — all coordination logic lives here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py_os.process.pcb import Process


class PriorityInheritanceManager:
    """Coordinate priority inheritance across mutexes and processes.

    Track which process holds each mutex, which processes are blocked
    waiting, and boost effective priorities as needed.  Supports
    transitive inheritance (chains of blocked processes) and
    recalculation on release.
    """

    def __init__(self) -> None:
        """Create a PI manager with empty state."""
        self._holder: dict[str, int] = {}  # mutex name → holder PID
        self._held_mutexes: dict[int, set[str]] = {}  # PID → mutex names held
        self._blocked_on: dict[int, str] = {}  # PID → mutex name blocked on
        self._enabled: bool = True

    @property
    def enabled(self) -> bool:
        """Return whether priority inheritance is active."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable priority inheritance."""
        self._enabled = value

    def holder(self, mutex_name: str) -> int | None:
        """Return the PID of the process holding *mutex_name*, or None."""
        return self._holder.get(mutex_name)

    def is_boosted(self, pid: int, base_priority: int) -> bool:
        """Return True if *pid*'s effective priority exceeds its base."""
        # External callers pass the base; we just compare.
        return (
            pid in self._held_mutexes
            and any(self._holder.get(m) == pid for m in self._held_mutexes.get(pid, set()))
            and base_priority < self._max_waiter_priority(pid, {})
        )

    def on_acquire(self, mutex_name: str, pid: int) -> None:
        """Record that *pid* now holds *mutex_name*."""
        self._holder[mutex_name] = pid
        self._held_mutexes.setdefault(pid, set()).add(mutex_name)

    def on_block(
        self,
        mutex_name: str,
        waiter_pid: int,
        processes: dict[int, Process],
    ) -> None:
        """Record that *waiter_pid* is blocked on *mutex_name* and boost if needed.

        If the waiter's effective priority exceeds the holder's, the
        holder is boosted.  Transitive inheritance propagates through
        any chain of blocked holders (with loop detection).

        Args:
            mutex_name: The mutex the waiter tried to acquire.
            waiter_pid: PID of the blocked process.
            processes: The kernel's process table for priority lookups.

        """
        self._blocked_on[waiter_pid] = mutex_name

        if not self._enabled:
            return

        holder_pid = self._holder.get(mutex_name)
        if holder_pid is None:
            return

        waiter = processes.get(waiter_pid)
        holder = processes.get(holder_pid)
        if waiter is None or holder is None:
            return

        if waiter.effective_priority > holder.effective_priority:
            holder.effective_priority = waiter.effective_priority

            # Transitive: if holder is itself blocked, propagate up
            self._propagate(holder_pid, waiter.effective_priority, processes)

    def _propagate(
        self,
        pid: int,
        priority: int,
        processes: dict[int, Process],
    ) -> None:
        """Walk the blocked-on chain and boost each holder transitively.

        Args:
            pid: Starting PID (just boosted).
            priority: The priority to propagate.
            processes: The kernel's process table.

        """
        visited: set[int] = {pid}
        current = pid

        while current in self._blocked_on:
            mutex_name = self._blocked_on[current]
            next_holder_pid = self._holder.get(mutex_name)
            if next_holder_pid is None or next_holder_pid in visited:
                break

            next_holder = processes.get(next_holder_pid)
            if next_holder is None:
                break

            next_holder.effective_priority = max(next_holder.effective_priority, priority)

            visited.add(next_holder_pid)
            current = next_holder_pid

    def on_release(
        self,
        mutex_name: str,
        pid: int,
        new_holder_pid: int | None,
        processes: dict[int, Process],
    ) -> None:
        """Record that *pid* released *mutex_name* and recalculate priority.

        Remove the mutex from the holder's set, optionally record the
        new holder, clear blocked_on for the new holder, and recalculate
        the releaser's effective priority based on remaining held mutexes.

        Args:
            mutex_name: The released mutex.
            pid: PID of the releasing process.
            new_holder_pid: PID of the next holder (from wait queue), or None.
            processes: The kernel's process table.

        """
        # Remove holder tracking
        self._holder.pop(mutex_name, None)
        held = self._held_mutexes.get(pid)
        if held is not None:
            held.discard(mutex_name)
            if not held:
                del self._held_mutexes[pid]

        # Record new holder
        if new_holder_pid is not None:
            self._holder[mutex_name] = new_holder_pid
            self._held_mutexes.setdefault(new_holder_pid, set()).add(mutex_name)
            self._blocked_on.pop(new_holder_pid, None)

        # Recalculate releaser's effective priority
        process = processes.get(pid)
        if process is None:
            return

        max_waiter = self._max_waiter_priority(pid, processes)
        process.effective_priority = max(process.priority, max_waiter)

    def _max_waiter_priority(self, pid: int, processes: dict[int, Process]) -> int:
        """Return the maximum effective_priority of all waiters on mutexes held by *pid*."""
        held = self._held_mutexes.get(pid, set())
        max_pri = 0
        for mutex_name in held:
            for waiter_pid, blocked_mutex in self._blocked_on.items():
                if blocked_mutex == mutex_name:
                    waiter = processes.get(waiter_pid)
                    if waiter is not None and waiter.effective_priority > max_pri:
                        max_pri = waiter.effective_priority
        return max_pri

    def clear(self) -> None:
        """Reset all tracking state (for shutdown and tests)."""
        self._holder.clear()
        self._held_mutexes.clear()
        self._blocked_on.clear()
