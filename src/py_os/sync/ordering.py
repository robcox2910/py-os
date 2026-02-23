"""Deadlock prevention via resource ordering.

**Deadlock** requires four conditions (the Coffman conditions):
    1. **Mutual exclusion** — resources can't be shared.
    2. **Hold and wait** — hold resources while waiting for more.
    3. **No preemption** — resources can't be forcibly taken.
    4. **Circular wait** — A waits for B, B waits for A.

Break *any one* of these and deadlock becomes impossible.  Resource
ordering targets **circular wait**: assign every resource a numeric
rank, and require processes to acquire resources in ascending rank
order.  A cycle is then impossible — it would require someone to go
"down" in rank, which the ordering rule forbids.

**Analogy:** Numbered lockers in a school hallway.  The rule: you can
only walk forward.  If you need locker 3 and locker 7, open 3 first,
then walk forward to 7.  You can never go backwards.  Nobody ever
gets stuck in a circle.

Three enforcement modes:
    - **strict** — reject the acquire attempt (prevents deadlock).
    - **warn** — log the violation but allow it (for debugging).
    - **off** — no checking (maximum performance).

This module is separate from ``deadlock.py`` because detection
(Banker's algorithm) is *reactive* — it finds deadlocks after they
happen.  Prevention (ordering) is *proactive* — it makes deadlocks
structurally impossible.
"""

from dataclasses import dataclass
from enum import StrEnum


class OrderingMode(StrEnum):
    """Enforcement mode for resource ordering checks.

    STRICT rejects violations outright; WARN logs but allows; OFF skips.
    """

    STRICT = "strict"
    WARN = "warn"
    OFF = "off"


@dataclass(frozen=True)
class OrderingViolation:
    """Record of a single ordering violation.

    Captured when a process attempts to acquire a resource whose rank
    is <= the highest rank it already holds.
    """

    resource_requested: str
    requested_rank: int
    max_held_rank: int
    pid: int


class ResourceOrderingManager:
    """Enforce resource acquisition ordering to prevent circular wait.

    Every resource gets a numeric rank (either explicit or auto-assigned).
    Before acquiring a resource, ``check_acquire`` verifies that the
    requested rank is strictly greater than the highest rank the process
    currently holds.  If not, the behaviour depends on the mode:

    - **strict**: return False (reject the acquire).
    - **warn**: record the violation, return True (allow but log).
    - **off**: return True (no checking).

    The kernel calls ``on_acquire`` after a successful acquire and
    ``on_release`` when releasing, so the manager always knows what
    each process holds.
    """

    def __init__(self) -> None:
        """Create an empty ordering manager in WARN mode."""
        self._ranks: dict[str, int] = {}
        self._next_rank: int = 1
        self._held: dict[int, dict[str, int]] = {}
        self._mode: OrderingMode = OrderingMode.WARN
        self._violations: list[OrderingViolation] = []

    @property
    def mode(self) -> OrderingMode:
        """Return the current enforcement mode."""
        return self._mode

    @mode.setter
    def mode(self, value: OrderingMode) -> None:
        """Set the enforcement mode."""
        self._mode = value

    @property
    def enabled(self) -> bool:
        """Return True if ordering checks are active (not OFF)."""
        return self._mode is not OrderingMode.OFF

    def register(self, name: str, *, rank: int | None = None) -> int:
        """Register a resource with an explicit or auto-assigned rank.

        If the resource is already registered, update its rank.

        Args:
            name: Resource name (e.g. ``"mutex:lock1"``).
            rank: Explicit rank, or None for auto-increment.

        Returns:
            The assigned rank.

        """
        if rank is None:
            rank = self._next_rank
        self._ranks[name] = rank
        if rank >= self._next_rank:
            self._next_rank = rank + 1
        return rank

    def rank(self, name: str) -> int | None:
        """Return the rank for a resource, or None if unregistered."""
        return self._ranks.get(name)

    def ranks(self) -> dict[str, int]:
        """Return a copy of the full resource → rank mapping."""
        return dict(self._ranks)

    def check_acquire(self, pid: int, resource: str) -> bool:
        """Check whether acquiring *resource* would violate ordering.

        Auto-registers unknown resources with the next available rank.
        A violation occurs when the process already holds a resource
        whose rank is >= the requested resource's rank.

        Args:
            pid: The process attempting the acquire.
            resource: The resource name (e.g. ``"mutex:lock1"``).

        Returns:
            True if the acquire is allowed, False if rejected (strict).

        """
        if self._mode is OrderingMode.OFF:
            return True

        # Auto-register unknown resources
        if resource not in self._ranks:
            self.register(resource)

        requested_rank = self._ranks[resource]
        held = self._held.get(pid, {})

        if held:
            max_held_rank = max(held.values())
            if requested_rank <= max_held_rank:
                violation = OrderingViolation(
                    resource_requested=resource,
                    requested_rank=requested_rank,
                    max_held_rank=max_held_rank,
                    pid=pid,
                )
                self._violations.append(violation)
                if self._mode is OrderingMode.STRICT:
                    return False

        return True

    def on_acquire(self, pid: int, resource: str) -> None:
        """Record that a process has acquired a resource.

        Args:
            pid: The process that acquired.
            resource: The resource name.

        """
        if resource not in self._ranks:
            self.register(resource)
        rank = self._ranks[resource]
        self._held.setdefault(pid, {})[resource] = rank

    def on_release(self, pid: int, resource: str) -> None:
        """Record that a process has released a resource.

        Args:
            pid: The process that released.
            resource: The resource name.

        """
        held = self._held.get(pid)
        if held is not None:
            held.pop(resource, None)
            if not held:
                del self._held[pid]

    def held_by(self, pid: int) -> dict[str, int]:
        """Return the resources held by a process {name: rank}.

        Args:
            pid: The process to query.

        Returns:
            Dict mapping resource name to rank (empty if none).

        """
        return dict(self._held.get(pid, {}))

    def violations(self) -> list[OrderingViolation]:
        """Return all recorded ordering violations."""
        return list(self._violations)

    def remove_process(self, pid: int) -> None:
        """Remove all tracking state for a process.

        Called during process termination to clean up.

        Args:
            pid: The process to remove.

        """
        self._held.pop(pid, None)

    def clear(self) -> None:
        """Reset all state — ranks, held resources, violations."""
        self._ranks.clear()
        self._next_rank = 1
        self._held.clear()
        self._violations.clear()
