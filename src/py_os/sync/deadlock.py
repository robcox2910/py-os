"""Deadlock detection and avoidance (Banker's algorithm).

**Deadlock** occurs when processes are stuck in a circular wait — each
holds a resource the next one needs, and none can proceed.  Four
conditions must ALL hold simultaneously:

    1. **Mutual exclusion** — resources can't be shared.
    2. **Hold and wait** — hold resources while waiting for more.
    3. **No preemption** — resources can't be forcibly taken.
    4. **Circular wait** — A waits for B, B waits for A.

Two strategies:

**Detection** (``detect_deadlock``):
    Find processes that are stuck *right now*.  Run the safety algorithm
    on the current state — any process that can't finish is deadlocked.

**Avoidance** (``request_safe`` — Banker's algorithm):
    Before granting a request, *simulate* granting it and check if the
    resulting state is safe.  If not, deny the request.  This prevents
    deadlock from ever occurring, at the cost of reduced concurrency.

The Banker's algorithm is named after a banker who must decide whether
to grant loans: if granting a loan might make it impossible to satisfy
all customers, the banker refuses.  The key insight is the concept of
a **safe state** — one where there exists an ordering (safe sequence)
in which every process can finish.

Data structures (per the textbook):
    - **Available[r]** — free instances of resource r.
    - **Maximum[p][r]** — max instances process p might ever need.
    - **Allocation[p][r]** — instances process p currently holds.
    - **Need[p][r]** — Maximum - Allocation (remaining need).
"""

from collections import defaultdict


class ResourceManager:
    """Track resource allocation and detect/avoid deadlocks.

    Maintains the four matrices needed by Banker's algorithm:
    available, maximum, allocation, and need.
    """

    def __init__(self) -> None:
        """Create an empty resource manager."""
        self._total: dict[str, int] = {}
        self._allocation: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._maximum: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def add_resource(self, name: str, *, total: int) -> None:
        """Register a resource type with a fixed number of instances.

        Args:
            name: Resource name (e.g. "CPU", "Printer").
            total: Total instances available system-wide.

        """
        self._total[name] = total

    def resources(self) -> list[str]:
        """Return all registered resource names."""
        return list(self._total)

    def available(self, resource: str) -> int:
        """Return the number of free instances of a resource."""
        total = self._total.get(resource, 0)
        allocated = sum(proc[resource] for proc in self._allocation.values())
        return total - allocated

    def allocation(self, pid: int, resource: str) -> int:
        """Return how many instances process pid currently holds."""
        return self._allocation[pid][resource]

    def need(self, pid: int, resource: str) -> int:
        """Return how many more instances process pid might request."""
        return self._maximum[pid][resource] - self._allocation[pid][resource]

    def declare_max(self, *, pid: int, resource: str, maximum: int) -> None:
        """Declare the maximum instances a process might need.

        This must be called before the process can request resources.
        The Banker's algorithm uses this to determine if future requests
        can be safely satisfied.

        Args:
            pid: The process identifier.
            resource: The resource name.
            maximum: Maximum instances this process might ever need.

        """
        self._maximum[pid][resource] = maximum

    def request(self, pid: int, resource: str, amount: int) -> None:
        """Grant a resource request (no safety check).

        Use ``request_safe`` for Banker's algorithm safety checking.

        Args:
            pid: The requesting process.
            resource: The resource name.
            amount: Number of instances requested.

        Raises:
            ValueError: If insufficient resources are available.

        """
        if amount > self.available(resource):
            msg = f"Cannot allocate {amount} {resource}: only {self.available(resource)} available"
            raise ValueError(msg)
        self._allocation[pid][resource] += amount

    def release(self, pid: int, resource: str, amount: int) -> None:
        """Release resource instances back to the pool.

        Args:
            pid: The process releasing resources.
            resource: The resource name.
            amount: Number of instances to release.

        Raises:
            ValueError: If *amount* exceeds the current allocation.

        """
        current = self._allocation[pid][resource]
        if amount > current:
            msg = f"Cannot release {amount} {resource}: only {current} allocated"
            raise ValueError(msg)
        self._allocation[pid][resource] -= amount

    def remove_process(self, pid: int) -> None:
        """Remove a process and release all its resources."""
        self._allocation.pop(pid, None)
        self._maximum.pop(pid, None)

    def _get_pids(self) -> list[int]:
        """Return all PIDs that have declared maximums."""
        return list(self._maximum)

    def is_safe(self) -> bool:
        """Check whether the current state is safe.

        A state is safe if there exists a sequence in which all
        processes can finish.

        Returns:
            True if a safe sequence exists, False otherwise.

        """
        return self.find_safe_sequence() is not None

    def find_safe_sequence(self) -> list[int] | None:
        """Find a safe sequence using the Banker's safety algorithm.

        Algorithm:
            1. work = copy of available resources
            2. finish = {pid: False} for all processes
            3. Find an unfinished process whose need <= work
            4. Pretend it finishes: work += its allocation
            5. Repeat until no more can be found
            6. If all finished → return the sequence
            7. Otherwise → return None (unsafe)

        Returns:
            A safe sequence of PIDs, or None if unsafe.

        """
        pids = self._get_pids()
        if not pids:
            return []

        # work = current available for each resource
        work = {r: self.available(r) for r in self._total}
        finish = dict.fromkeys(pids, False)
        sequence: list[int] = []

        changed = True
        while changed:
            changed = False
            for pid in pids:
                if finish[pid]:
                    continue
                # Check if this process's need can be satisfied
                can_finish = all(self.need(pid, r) <= work[r] for r in self._total)
                if can_finish:
                    # Pretend it finishes: release its allocation
                    for r in self._total:
                        work[r] += self._allocation[pid][r]
                    finish[pid] = True
                    sequence.append(pid)
                    changed = True

        if all(finish.values()):
            return sequence
        return None

    def request_safe(self, pid: int, resource: str, amount: int) -> bool:
        """Request resources with Banker's safety check.

        Simulates granting the request, then checks if the resulting
        state is safe.  If safe, the request is committed.  If unsafe,
        it is rolled back and denied.

        Args:
            pid: The requesting process.
            resource: The resource name.
            amount: Number of instances requested.

        Returns:
            True if the request was granted, False if denied.

        """
        if amount > self.available(resource):
            return False

        # Tentatively grant
        self._allocation[pid][resource] += amount

        if self.is_safe():
            return True

        # Unsafe — rollback
        self._allocation[pid][resource] -= amount
        return False

    def detect_deadlock(self) -> set[int]:
        """Detect deadlocked processes.

        Uses the safety algorithm on the current state.  Any process
        that cannot finish with current available resources is
        considered deadlocked.

        Returns:
            Set of PIDs that are deadlocked (empty if none).

        """
        pids = self._get_pids()
        if not pids:
            return set()

        work = {r: self.available(r) for r in self._total}
        finish = dict.fromkeys(pids, False)

        changed = True
        while changed:
            changed = False
            for pid in pids:
                if finish[pid]:
                    continue
                can_finish = all(self.need(pid, r) <= work[r] for r in self._total)
                if can_finish:
                    for r in self._total:
                        work[r] += self._allocation[pid][r]
                    finish[pid] = True
                    changed = True

        return {pid for pid, done in finish.items() if not done}
