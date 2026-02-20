"""Disk scheduling algorithms — minimising seek time for I/O requests.

When multiple processes request disk I/O, the disk arm must move
between tracks (cylinders) to service them.  The dominant cost is
**seek time** — how far the arm travels.  Disk scheduling algorithms
decide the *order* in which requests are serviced to minimise this.

Think of a disk arm like an elevator in a building:
    - **FCFS** — stop at every floor in the order people pressed buttons.
    - **SSTF** — always go to the nearest requested floor (greedy).
    - **SCAN** — go all the way up, then all the way down (elevator).
    - **C-SCAN** — go all the way up, jump back to bottom, go up again.

Algorithms:
    - ``FCFSPolicy`` — simple, fair, but high total seek time.
    - ``SSTFPolicy`` — lowest immediate cost, but can starve distant
      requests (the arm hovers near popular regions).
    - ``SCANPolicy`` — bounded wait, no starvation, predictable sweep.
    - ``CSCANPolicy`` — uniform wait times (no favouring middle tracks).

All policies implement the ``DiskPolicy`` protocol — the Strategy
pattern, same as scheduler and page replacement.
"""

from typing import Protocol


class DiskPolicy(Protocol):
    """Protocol for disk scheduling policies (Strategy pattern)."""

    def schedule(self, requests: list[int], *, head: int) -> list[int]:
        """Return the order in which requests should be serviced.

        Args:
            requests: List of cylinder numbers to visit.
            head: Current position of the disk head.

        Returns:
            Ordered list of cylinder numbers.

        """
        ...


class FCFSPolicy:
    """First Come, First Served — service in arrival order.

    The simplest policy.  Fair (no starvation), but the arm zigzags
    wildly across the disk, producing high total seek time.

    Real-world analogy: an elevator that visits floors in the order
    buttons were pressed, regardless of direction.  You'd ride past
    your floor and come back later.
    """

    def schedule(self, requests: list[int], *, head: int) -> list[int]:  # noqa: ARG002
        """Return requests in their original order."""
        return list(requests)


class SSTFPolicy:
    """Shortest Seek Time First — always go to the nearest request.

    A greedy algorithm that minimises immediate seek time.  Produces
    better total movement than FCFS, but can **starve** distant
    requests if new requests keep arriving near the head.

    Real-world analogy: an elevator that always goes to the nearest
    floor with a waiting passenger.  Floors far from the action
    might wait a very long time.
    """

    def schedule(self, requests: list[int], *, head: int) -> list[int]:
        """Return requests ordered by nearest-first from current head."""
        remaining = list(requests)
        order: list[int] = []
        current = head
        while remaining:
            nearest = min(remaining, key=lambda r: abs(r - current))
            order.append(nearest)
            remaining.remove(nearest)
            current = nearest
        return order


class SCANPolicy:
    """SCAN (Elevator algorithm) — sweep one direction, then reverse.

    The arm moves in one direction, servicing all requests along the
    way, then reverses and services requests in the other direction.
    This guarantees bounded wait times — no request waits more than
    two full sweeps.

    Named "elevator" because it works exactly like a building elevator:
    go up servicing all floors, then go down servicing all floors.

    Args:
        direction: Initial sweep direction ("up" or "down").
        max_cylinder: Highest cylinder number on the disk.

    """

    def __init__(self, *, direction: str = "up", max_cylinder: int = 199) -> None:
        """Create a SCAN policy with an initial direction."""
        self._direction = direction
        self._max_cylinder = max_cylinder

    def schedule(self, requests: list[int], *, head: int) -> list[int]:
        """Return requests in SCAN (elevator) order."""
        if not requests:
            return []

        if self._direction == "up":
            # Service requests >= head in ascending order, then < head descending
            up = sorted(r for r in requests if r >= head)
            down = sorted((r for r in requests if r < head), reverse=True)
            return up + down

        # Sweep down then reverse

        down = sorted((r for r in requests if r <= head), reverse=True)
        up = sorted(r for r in requests if r > head)
        return down + up


class CSCANPolicy:
    """Circular SCAN — sweep one direction, jump back, sweep again.

    Unlike SCAN, C-SCAN only services requests in one direction.
    After reaching the end, the arm jumps back to the beginning
    and sweeps the same direction again.  This provides more
    **uniform wait times** — requests near the beginning and end
    of the disk are treated equally.

    With regular SCAN, requests in the middle of the disk are
    favoured (the arm passes them twice per cycle).  C-SCAN
    eliminates this bias.

    Args:
        direction: Sweep direction ("up" or "down").
        max_cylinder: Highest cylinder number on the disk.

    """

    def __init__(self, *, direction: str = "up", max_cylinder: int = 199) -> None:
        """Create a C-SCAN policy with sweep direction."""
        self._direction = direction
        self._max_cylinder = max_cylinder

    def schedule(self, requests: list[int], *, head: int) -> list[int]:
        """Return requests in C-SCAN order."""
        if not requests:
            return []

        if self._direction == "up":
            # Sweep up from head, then wrap to lowest and sweep up again
            up = sorted(r for r in requests if r >= head)
            wrapped = sorted(r for r in requests if r < head)
            return up + wrapped

        # Sweep down then reverse

        down = sorted((r for r in requests if r <= head), reverse=True)
        wrapped = sorted((r for r in requests if r > head), reverse=True)
        return down + wrapped


class DiskScheduler:
    """Disk scheduler — ties a policy to a request queue.

    Analogous to how ``Scheduler`` ties a ``SchedulingPolicy`` to
    a ready queue.  The disk scheduler accepts I/O requests, then
    runs the selected policy to determine service order.
    """

    def __init__(self, *, policy: DiskPolicy, head: int = 0) -> None:
        """Create a disk scheduler with a policy and initial head position."""
        self._policy = policy
        self._head = head
        self._queue: list[int] = []

    @property
    def head(self) -> int:
        """Return current head position."""
        return self._head

    @property
    def policy(self) -> DiskPolicy:
        """Return the current scheduling policy."""
        return self._policy

    @policy.setter
    def policy(self, value: DiskPolicy) -> None:
        """Swap the scheduling policy (Strategy pattern)."""
        self._policy = value

    @property
    def pending(self) -> list[int]:
        """Return the current request queue."""
        return list(self._queue)

    def add_request(self, cylinder: int) -> None:
        """Add an I/O request for a cylinder."""
        self._queue.append(cylinder)

    def run(self) -> list[int]:
        """Run the scheduling policy on queued requests.

        Returns the service order and updates the head position
        to the last serviced cylinder.  Clears the queue.

        Returns:
            Ordered list of cylinders as serviced.

        """
        if not self._queue:
            return []
        order = self._policy.schedule(self._queue, head=self._head)
        if order:
            self._head = order[-1]
        self._queue.clear()
        return order
