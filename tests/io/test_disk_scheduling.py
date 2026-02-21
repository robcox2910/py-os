"""Tests for disk scheduling algorithms.

When multiple processes request disk I/O, the OS must decide the order
in which to service those requests.  The disk arm moves across tracks
(cylinders), and the time is dominated by **seek time** — how far the
arm must travel.  Disk scheduling algorithms aim to minimise total
head movement.

Algorithms tested:
    - **FCFS** — First Come, First Served.  Service in arrival order.
    - **SSTF** — Shortest Seek Time First.  Service nearest request.
    - **SCAN** — Elevator algorithm.  Sweep one direction, then reverse.
    - **C-SCAN** — Circular SCAN.  Sweep one direction, jump back to start.
"""

from py_os.io.disk import (
    CSCANPolicy,
    DiskScheduler,
    FCFSPolicy,
    SCANPolicy,
    SSTFPolicy,
)

# -- Textbook example constants -----------------------------------------------
# Classic disk scheduling example: 8 requests with head at cylinder 53.
_TEXTBOOK_REQUESTS = [98, 183, 37, 122, 14, 124, 65, 67]
_TEXTBOOK_HEAD = 53
_NEAREST_TO_53 = 65  # cylinder closest to head position 53


# -- FCFS (First Come, First Served) ------------------------------------------


class TestFCFS:
    """FCFS services requests in the order they arrive — no reordering."""

    def test_preserves_order(self) -> None:
        """Requests should be serviced in submission order."""
        policy = FCFSPolicy()
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        assert order == _TEXTBOOK_REQUESTS

    def test_empty_queue(self) -> None:
        """Empty request queue should return empty schedule."""
        policy = FCFSPolicy()
        assert policy.schedule([], head=50) == []

    def test_single_request(self) -> None:
        """Single request should return as-is."""
        policy = FCFSPolicy()
        assert policy.schedule([100], head=50) == [100]

    def test_head_movement(self) -> None:
        """Total head movement should be the sum of absolute differences."""
        policy = FCFSPolicy()
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        total = _total_movement(order, head=_TEXTBOOK_HEAD)
        expected = 640
        assert total == expected


# -- SSTF (Shortest Seek Time First) ------------------------------------------


class TestSSTF:
    """SSTF always services the request nearest to the current head."""

    def test_nearest_first(self) -> None:
        """The first serviced request should be closest to the head."""
        policy = SSTFPolicy()
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        assert order[0] == _NEAREST_TO_53

    def test_reduces_movement(self) -> None:
        """SSTF should produce less movement than FCFS for this example."""
        fcfs_movement = _total_movement(
            FCFSPolicy().schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD),
            head=_TEXTBOOK_HEAD,
        )
        sstf_movement = _total_movement(
            SSTFPolicy().schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD),
            head=_TEXTBOOK_HEAD,
        )
        assert sstf_movement < fcfs_movement

    def test_all_requests_serviced(self) -> None:
        """All requests must be serviced exactly once."""
        policy = SSTFPolicy()
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        assert sorted(order) == sorted(_TEXTBOOK_REQUESTS)

    def test_empty_queue(self) -> None:
        """Empty request queue should return empty schedule."""
        policy = SSTFPolicy()
        assert policy.schedule([], head=50) == []

    def test_tie_breaking(self) -> None:
        """When two requests are equidistant, either is acceptable."""
        policy = SSTFPolicy()
        requests = [40, 60]
        order = policy.schedule(requests, head=50)
        request_count = 2
        assert len(order) == request_count
        assert sorted(order) == [40, 60]


# -- SCAN (Elevator Algorithm) ------------------------------------------------


class TestSCAN:
    """SCAN moves in one direction, servicing all requests, then reverses.

    Like an elevator.
    """

    def test_sweep_direction(self) -> None:
        """SCAN moving up should service higher requests first."""
        policy = SCANPolicy(direction="up", max_cylinder=199)
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        up_portion = [r for r in order if r >= _TEXTBOOK_HEAD]
        down_portion = [r for r in order if r < _TEXTBOOK_HEAD]
        assert up_portion == sorted(up_portion)
        assert down_portion == sorted(down_portion, reverse=True)

    def test_all_requests_serviced(self) -> None:
        """All requests must appear exactly once."""
        policy = SCANPolicy(direction="up", max_cylinder=199)
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        assert sorted(order) == sorted(_TEXTBOOK_REQUESTS)

    def test_scan_down(self) -> None:
        """SCAN moving down should service lower requests first."""
        policy = SCANPolicy(direction="down", max_cylinder=199)
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        down_portion = [r for r in order if r <= _TEXTBOOK_HEAD]
        up_portion = [r for r in order if r > _TEXTBOOK_HEAD]
        assert down_portion == sorted(down_portion, reverse=True)
        assert up_portion == sorted(up_portion)

    def test_empty_queue(self) -> None:
        """Empty request queue should return empty schedule."""
        policy = SCANPolicy(direction="up", max_cylinder=199)
        assert policy.schedule([], head=50) == []

    def test_no_reversal_needed(self) -> None:
        """If all requests are in the sweep direction, no reversal."""
        policy = SCANPolicy(direction="up", max_cylinder=199)
        requests = [60, 80, 100]
        order = policy.schedule(requests, head=50)
        assert order == [60, 80, 100]


# -- C-SCAN (Circular SCAN) ---------------------------------------------------


class TestCSCAN:
    """C-SCAN sweeps in one direction only, then jumps back to start.

    This gives more uniform wait times than SCAN.
    """

    def test_uniform_direction(self) -> None:
        """C-SCAN (up) should service all requests in ascending order."""
        policy = CSCANPolicy(direction="up", max_cylinder=199)
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        up_first = [r for r in order if r >= _TEXTBOOK_HEAD]
        wrapped = [r for r in order if r < _TEXTBOOK_HEAD]
        assert up_first == sorted(up_first)
        assert wrapped == sorted(wrapped)
        # Wrapped portion should come after the up portion
        up_end = 0
        for i, r in enumerate(order):
            if r >= _TEXTBOOK_HEAD:
                up_end = i
        for i, r in enumerate(order):
            if r < _TEXTBOOK_HEAD:
                assert i > up_end

    def test_all_requests_serviced(self) -> None:
        """All requests must appear exactly once."""
        policy = CSCANPolicy(direction="up", max_cylinder=199)
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        assert sorted(order) == sorted(_TEXTBOOK_REQUESTS)

    def test_cscan_down(self) -> None:
        """C-SCAN (down) should sweep down then wrap to highest."""
        policy = CSCANPolicy(direction="down", max_cylinder=199)
        order = policy.schedule(_TEXTBOOK_REQUESTS, head=_TEXTBOOK_HEAD)
        down_first = [r for r in order if r <= _TEXTBOOK_HEAD]
        wrapped = [r for r in order if r > _TEXTBOOK_HEAD]
        assert down_first == sorted(down_first, reverse=True)
        assert wrapped == sorted(wrapped, reverse=True)

    def test_empty_queue(self) -> None:
        """Empty request queue should return empty schedule."""
        policy = CSCANPolicy(direction="up", max_cylinder=199)
        assert policy.schedule([], head=50) == []


# -- DiskScheduler (integration) -----------------------------------------------


class TestDiskScheduler:
    """The DiskScheduler ties policy to a request queue."""

    def test_add_and_run(self) -> None:
        """Adding requests and running should schedule them."""
        ds = DiskScheduler(policy=FCFSPolicy(), head=50)
        ds.add_request(100)
        ds.add_request(25)
        order = ds.run()
        assert order == [100, 25]

    def test_head_updates_after_run(self) -> None:
        """After running, head should be at the last serviced position."""
        ds = DiskScheduler(policy=FCFSPolicy(), head=50)
        ds.add_request(100)
        ds.add_request(25)
        ds.run()
        last_cylinder = 25
        assert ds.head == last_cylinder

    def test_queue_clears_after_run(self) -> None:
        """Queue should be empty after running."""
        ds = DiskScheduler(policy=FCFSPolicy(), head=50)
        ds.add_request(100)
        ds.run()
        assert ds.run() == []

    def test_total_movement(self) -> None:
        """Total head movement should be computed correctly."""
        ds = DiskScheduler(policy=FCFSPolicy(), head=50)
        ds.add_request(100)
        ds.add_request(25)
        order = ds.run()
        expected = 125  # |50-100| + |100-25| = 50 + 75
        assert _total_movement(order, head=50) == expected

    def test_swap_policy(self) -> None:
        """Policy can be swapped (Strategy pattern)."""
        ds = DiskScheduler(policy=FCFSPolicy(), head=50)
        ds.policy = SSTFPolicy()
        ds.add_request(100)
        ds.add_request(60)
        order = ds.run()
        nearest = 60
        assert order[0] == nearest  # SSTF picks nearest first

    def test_pending_requests(self) -> None:
        """Pending requests should reflect what's queued."""
        ds = DiskScheduler(policy=FCFSPolicy(), head=50)
        ds.add_request(100)
        ds.add_request(25)
        assert ds.pending == [100, 25]


# -- Helper --------------------------------------------------------------------


def _total_movement(order: list[int], *, head: int) -> int:
    """Compute total head movement for a schedule."""
    total = 0
    current = head
    for pos in order:
        total += abs(pos - current)
        current = pos
    return total
