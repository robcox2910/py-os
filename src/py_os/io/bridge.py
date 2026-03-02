"""Network bridge — connect multiple kernel instances.

In a real network, computers communicate by sending **packets** through
cables, switches, and routers.  A **bridge** is the simplest connector:
it receives a packet from one machine and delivers it to another.

Think of it like a computer lab where every machine is connected by a
cable to a central switch.  When Machine A wants to talk to Machine B,
it sends a message to the switch, and the switch forwards it to B.

Our ``NetworkBridge`` connects multiple PyOS kernel instances the same
way.  Each kernel registers with the bridge and gets an ID.  Packets
flow through the bridge from one kernel to another — enabling
cross-machine messaging, ping, and DNS lookups.

The ``Cluster`` class is a higher-level manager that creates and
connects multiple kernels, providing a friendly API for inter-machine
communication.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py_os.kernel import Kernel


class BridgeError(Exception):
    """Raise when a bridge operation fails."""


class PacketType(StrEnum):
    """Type of packet flowing through the bridge."""

    DATA = "data"
    DNS_QUERY = "dns_query"
    DNS_RESPONSE = "dns_response"
    PING = "ping"
    PONG = "pong"


@dataclass(frozen=True)
class Packet:
    """A single network packet between two kernels."""

    src_kernel_id: int
    dst_kernel_id: int
    payload: bytes
    packet_type: PacketType


class NetworkBridge:
    """Connect multiple kernels via in-memory packet queues.

    Each kernel gets its own incoming queue.  Sending a packet
    places it in the destination kernel's queue; receiving pops
    the next packet from your own queue.
    """

    def __init__(self) -> None:
        """Create an empty bridge with no connected kernels."""
        self._queues: dict[int, deque[Packet]] = {}
        self._kernels: dict[int, Kernel] = {}
        self._next_id = 1

    def register_kernel(self, kernel: Kernel) -> int:
        """Register a kernel and return its bridge ID."""
        kid = self._next_id
        self._next_id += 1
        self._queues[kid] = deque()
        self._kernels[kid] = kernel
        return kid

    def unregister_kernel(self, kernel_id: int) -> None:
        """Remove a kernel from the bridge."""
        self._queues.pop(kernel_id, None)
        self._kernels.pop(kernel_id, None)

    def send(self, packet: Packet) -> None:
        """Deliver a packet to the destination kernel's queue.

        Raises:
            BridgeError: If the destination kernel is not registered.

        """
        if packet.dst_kernel_id not in self._queues:
            msg = f"Destination kernel {packet.dst_kernel_id} not registered"
            raise BridgeError(msg)
        self._queues[packet.dst_kernel_id].append(packet)

    def receive(self, kernel_id: int) -> Packet | None:
        """Pop the next incoming packet for a kernel, or None if empty."""
        queue = self._queues.get(kernel_id)
        if queue is None:
            msg = f"Kernel {kernel_id} not registered"
            raise BridgeError(msg)
        return queue.popleft() if queue else None

    def pending_count(self, kernel_id: int) -> int:
        """Return the number of pending packets for a kernel."""
        queue = self._queues.get(kernel_id)
        if queue is None:
            return 0
        return len(queue)

    @property
    def kernel_count(self) -> int:
        """Return the number of connected kernels."""
        return len(self._kernels)

    def list_kernels(self) -> list[int]:
        """Return all registered kernel IDs."""
        return sorted(self._kernels.keys())


_DEFAULT_CLUSTER_FRAMES = 64


class Cluster:
    """Manage multiple booted kernels connected via a bridge.

    The cluster is the highest-level abstraction: it creates kernels,
    connects them to a shared bridge, and provides methods for
    inter-machine communication.
    """

    def __init__(self) -> None:
        """Create an empty cluster with a bridge."""
        self._bridge = NetworkBridge()
        self._kernels: dict[int, Kernel] = {}

    @property
    def bridge(self) -> NetworkBridge:
        """Return the underlying network bridge."""
        return self._bridge

    def add_kernel(self, *, total_frames: int = _DEFAULT_CLUSTER_FRAMES) -> tuple[int, Kernel]:
        """Create a new kernel, boot it, and connect to the bridge.

        Args:
            total_frames: Memory frames for the new kernel.

        Returns:
            A tuple of (kernel_id, kernel).

        """
        # Import here to avoid circular dependency at module level
        from py_os.kernel import Kernel as KernelClass  # noqa: PLC0415

        kernel = KernelClass(total_frames=total_frames)
        kernel.boot()
        kid = self._bridge.register_kernel(kernel)
        self._kernels[kid] = kernel
        return kid, kernel

    def register_existing(self, kernel: Kernel) -> int:
        """Register an already-booted kernel (e.g., the creating kernel).

        Args:
            kernel: An existing booted kernel instance.

        Returns:
            The kernel's cluster ID.

        """
        kid = self._bridge.register_kernel(kernel)
        self._kernels[kid] = kernel
        return kid

    def remove_kernel(self, kernel_id: int) -> None:
        """Shut down and remove a kernel from the cluster.

        Raises:
            BridgeError: If the kernel ID is not in the cluster.

        """
        kernel = self._kernels.pop(kernel_id, None)
        if kernel is None:
            msg = f"Kernel {kernel_id} not in cluster"
            raise BridgeError(msg)
        self._bridge.unregister_kernel(kernel_id)
        kernel.shutdown()

    def send_message(self, from_id: int, to_id: int, data: bytes) -> None:
        """Send a data message from one kernel to another."""
        packet = Packet(
            src_kernel_id=from_id,
            dst_kernel_id=to_id,
            payload=data,
            packet_type=PacketType.DATA,
        )
        self._bridge.send(packet)

    def receive_message(self, kernel_id: int) -> bytes | None:
        """Receive the next data message for a kernel."""
        packet = self._bridge.receive(kernel_id)
        if packet is None:
            return None
        return packet.payload

    def ping(self, from_id: int, to_id: int) -> bool:
        """Send a PING and check for a PONG response.

        This is a simplified simulation — in a real network, ping
        would measure round-trip time.  Here we just verify the
        destination kernel is reachable.
        """
        if to_id not in self._kernels:
            return False
        # Send PING
        ping_packet = Packet(
            src_kernel_id=from_id,
            dst_kernel_id=to_id,
            payload=b"ping",
            packet_type=PacketType.PING,
        )
        self._bridge.send(ping_packet)
        # Auto-respond with PONG (simulated)
        pong_packet = Packet(
            src_kernel_id=to_id,
            dst_kernel_id=from_id,
            payload=b"pong",
            packet_type=PacketType.PONG,
        )
        self._bridge.send(pong_packet)
        # Consume the PING from target's queue
        self._bridge.receive(to_id)
        # Consume the PONG from sender's queue
        response = self._bridge.receive(from_id)
        return response is not None and response.packet_type is PacketType.PONG

    def dns_query(self, _from_id: int, to_id: int, hostname: str) -> str | None:
        """Look up a hostname using another kernel's DNS resolver.

        Args:
            from_id: The requesting kernel.
            to_id: The kernel whose DNS we query.
            hostname: The hostname to look up.

        Returns:
            The resolved IP address, or None if not found.

        """
        target = self._kernels.get(to_id)
        if target is None:
            return None
        dns = target.dns_resolver
        if dns is None:
            return None
        try:
            return dns.lookup(hostname)
        except Exception:
            return None

    def list_kernels(self) -> list[dict[str, object]]:
        """Return a summary of all kernels in the cluster."""
        return [
            {
                "id": kid,
                "state": str(kernel.state),
                "pending": self._bridge.pending_count(kid),
            }
            for kid, kernel in sorted(self._kernels.items())
        ]

    def demo(self) -> str:
        """Run a demonstration of inter-machine networking.

        Returns:
            A string describing what happened.

        """
        lines = ["=== Cluster Demo ===", ""]

        # Create two kernels
        id1, _k1 = self.add_kernel()
        id2, _k2 = self.add_kernel()
        lines.append(f"Created kernel {id1} and kernel {id2}")

        # Send a message
        self.send_message(id1, id2, b"Hello from kernel 1!")
        lines.append(f"Kernel {id1} -> Kernel {id2}: 'Hello from kernel 1!'")

        # Receive it
        msg = self.receive_message(id2)
        if msg is not None:
            lines.append(f"Kernel {id2} received: {msg.decode()}")

        # Ping
        reachable = self.ping(id1, id2)
        lines.append(f"Ping {id1} -> {id2}: {'OK' if reachable else 'FAIL'}")

        # List
        kernels = self.list_kernels()
        lines.append(f"\n{len(kernels)} kernel(s) in cluster")

        # Cleanup
        self.remove_kernel(id2)
        self.remove_kernel(id1)
        lines.append("Cluster cleaned up.")

        return "\n".join(lines)
