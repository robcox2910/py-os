"""Tests for inter-machine networking — bridge, packets, and clusters."""

import re

import pytest

from py_os.io.bridge import (
    BridgeError,
    Cluster,
    NetworkBridge,
    Packet,
    PacketType,
)
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

_DEFAULT_FRAMES = 64
_DST_KERNEL_ID = 2


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create booted kernel + shell for testing."""
    kernel = _booted_kernel()
    return kernel, Shell(kernel=kernel)


# -- Packet tests -------------------------------------------------------------


class TestPacket:
    """Verify Packet dataclass."""

    def test_creation(self) -> None:
        """Packet stores all fields correctly."""
        p = Packet(
            src_kernel_id=1,
            dst_kernel_id=2,
            payload=b"hello",
            packet_type=PacketType.DATA,
        )
        assert p.src_kernel_id == 1
        assert p.dst_kernel_id == _DST_KERNEL_ID
        assert p.payload == b"hello"
        assert p.packet_type is PacketType.DATA

    def test_frozen(self) -> None:
        """Packet is immutable."""
        p = Packet(1, 2, b"data", PacketType.DATA)
        with pytest.raises(AttributeError):
            p.payload = b"changed"  # type: ignore[misc]

    def test_all_packet_types(self) -> None:
        """All expected packet types are defined."""
        expected = {"data", "dns_query", "dns_response", "ping", "pong"}
        actual = {pt.value for pt in PacketType}
        assert expected == actual


# -- NetworkBridge tests -------------------------------------------------------


class TestNetworkBridge:
    """Verify the network bridge."""

    def test_register_kernel(self) -> None:
        """Registering a kernel returns an ID."""
        bridge = NetworkBridge()
        kernel = _booted_kernel()
        kid = bridge.register_kernel(kernel)
        assert kid >= 1

    def test_kernel_count(self) -> None:
        """Kernel count reflects registrations."""
        bridge = NetworkBridge()
        k1 = _booted_kernel()
        k2 = _booted_kernel()
        bridge.register_kernel(k1)
        bridge.register_kernel(k2)
        assert bridge.kernel_count == 2  # noqa: PLR2004

    def test_send_and_receive(self) -> None:
        """Send a packet and receive it at the destination."""
        bridge = NetworkBridge()
        k1 = _booted_kernel()
        k2 = _booted_kernel()
        id1 = bridge.register_kernel(k1)
        id2 = bridge.register_kernel(k2)
        packet = Packet(id1, id2, b"hello", PacketType.DATA)
        bridge.send(packet)
        received = bridge.receive(id2)
        assert received is not None
        assert received.payload == b"hello"

    def test_receive_empty_returns_none(self) -> None:
        """Receiving from an empty queue returns None."""
        bridge = NetworkBridge()
        kernel = _booted_kernel()
        kid = bridge.register_kernel(kernel)
        assert bridge.receive(kid) is None

    def test_send_to_nonexistent_raises(self) -> None:
        """Sending to an unregistered kernel raises BridgeError."""
        bridge = NetworkBridge()
        packet = Packet(1, 99, b"data", PacketType.DATA)
        with pytest.raises(BridgeError, match="not registered"):
            bridge.send(packet)

    def test_receive_from_nonexistent_raises(self) -> None:
        """Receiving from an unregistered kernel raises BridgeError."""
        bridge = NetworkBridge()
        with pytest.raises(BridgeError, match="not registered"):
            bridge.receive(99)

    def test_pending_count(self) -> None:
        """Pending count reflects queued packets."""
        bridge = NetworkBridge()
        k1 = _booted_kernel()
        k2 = _booted_kernel()
        id1 = bridge.register_kernel(k1)
        id2 = bridge.register_kernel(k2)
        assert bridge.pending_count(id2) == 0
        bridge.send(Packet(id1, id2, b"a", PacketType.DATA))
        bridge.send(Packet(id1, id2, b"b", PacketType.DATA))
        assert bridge.pending_count(id2) == 2  # noqa: PLR2004

    def test_unregister_kernel(self) -> None:
        """Unregistering removes the kernel and its queue."""
        bridge = NetworkBridge()
        kernel = _booted_kernel()
        kid = bridge.register_kernel(kernel)
        bridge.unregister_kernel(kid)
        assert bridge.kernel_count == 0

    def test_list_kernels(self) -> None:
        """List kernels returns sorted IDs."""
        bridge = NetworkBridge()
        k1 = _booted_kernel()
        k2 = _booted_kernel()
        id1 = bridge.register_kernel(k1)
        id2 = bridge.register_kernel(k2)
        assert bridge.list_kernels() == sorted([id1, id2])


# -- Cluster tests -------------------------------------------------------------

_TWO_KERNELS = 2


class TestCluster:
    """Verify the cluster manager."""

    def test_add_kernel(self) -> None:
        """Adding a kernel returns an ID and a booted kernel."""
        cluster = Cluster()
        kid, kernel = cluster.add_kernel()
        assert kid >= 1
        assert kernel.state.value == "running"
        # Cleanup
        cluster.remove_kernel(kid)

    def test_remove_kernel(self) -> None:
        """Removing a kernel shuts it down."""
        cluster = Cluster()
        kid, kernel = cluster.add_kernel()
        cluster.remove_kernel(kid)
        assert kernel.state.value == "shutdown"

    def test_remove_nonexistent_raises(self) -> None:
        """Removing a nonexistent kernel raises BridgeError."""
        cluster = Cluster()
        with pytest.raises(BridgeError, match="not in cluster"):
            cluster.remove_kernel(99)

    def test_send_receive_message(self) -> None:
        """Send and receive a data message between kernels."""
        cluster = Cluster()
        id1, _k1 = cluster.add_kernel()
        id2, _k2 = cluster.add_kernel()
        cluster.send_message(id1, id2, b"hello cluster")
        msg = cluster.receive_message(id2)
        assert msg == b"hello cluster"
        # Cleanup
        cluster.remove_kernel(id2)
        cluster.remove_kernel(id1)

    def test_receive_empty(self) -> None:
        """Receiving when no messages returns None."""
        cluster = Cluster()
        kid, _kernel = cluster.add_kernel()
        assert cluster.receive_message(kid) is None
        cluster.remove_kernel(kid)

    def test_ping(self) -> None:
        """Ping between kernels returns True."""
        cluster = Cluster()
        id1, _k1 = cluster.add_kernel()
        id2, _k2 = cluster.add_kernel()
        assert cluster.ping(id1, id2) is True
        cluster.remove_kernel(id2)
        cluster.remove_kernel(id1)

    def test_ping_nonexistent(self) -> None:
        """Ping to nonexistent kernel returns False."""
        cluster = Cluster()
        kid, _kernel = cluster.add_kernel()
        assert cluster.ping(kid, 99) is False
        cluster.remove_kernel(kid)

    def test_dns_query(self) -> None:
        """Cross-kernel DNS query resolves a hostname."""
        cluster = Cluster()
        id1, _k1 = cluster.add_kernel()
        id2, k2 = cluster.add_kernel()
        # Register a DNS record on kernel 2
        k2._execution_mode = ExecutionMode.KERNEL
        assert k2._dns_resolver is not None
        k2._dns_resolver.register("myhost", "10.0.0.1")
        result = cluster.dns_query(id1, id2, "myhost")
        assert result == "10.0.0.1"
        cluster.remove_kernel(id2)
        cluster.remove_kernel(id1)

    def test_dns_query_not_found(self) -> None:
        """Cross-kernel DNS query for unknown host returns None."""
        cluster = Cluster()
        id1, _k1 = cluster.add_kernel()
        id2, _k2 = cluster.add_kernel()
        result = cluster.dns_query(id1, id2, "unknown")
        assert result is None
        cluster.remove_kernel(id2)
        cluster.remove_kernel(id1)

    def test_list_kernels(self) -> None:
        """List returns all kernels with state and pending count."""
        cluster = Cluster()
        id1, _k1 = cluster.add_kernel()
        id2, _k2 = cluster.add_kernel()
        result = cluster.list_kernels()
        assert len(result) == _TWO_KERNELS
        ids = {k["id"] for k in result}
        assert ids == {id1, id2}
        cluster.remove_kernel(id2)
        cluster.remove_kernel(id1)


class TestClusterDemo:
    """Verify the cluster demo."""

    def test_demo_returns_output(self) -> None:
        """Demo produces non-empty output."""
        cluster = Cluster()
        output = cluster.demo()
        assert len(output) > 0
        assert "Cluster Demo" in output


# -- Syscall cluster tests -----------------------------------------------------


class TestSyscallClusterOps:
    """Verify cluster-related syscalls."""

    def test_sys_cluster_create(self) -> None:
        """SYS_CLUSTER_CREATE initializes a cluster."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_CLUSTER_CREATE)
        assert result["kernel_id"] >= 1
        kernel.shutdown()

    def test_sys_cluster_add(self) -> None:
        """SYS_CLUSTER_ADD adds a kernel to the cluster."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CLUSTER_CREATE)
        result = kernel.syscall(SyscallNumber.SYS_CLUSTER_ADD)
        assert result["kernel_id"] >= 1
        kernel.shutdown()

    def test_sys_cluster_list(self) -> None:
        """SYS_CLUSTER_LIST lists cluster kernels."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CLUSTER_CREATE)
        result = kernel.syscall(SyscallNumber.SYS_CLUSTER_LIST)
        assert len(result) >= 1
        kernel.shutdown()

    def test_sys_cluster_ping(self) -> None:
        """SYS_CLUSTER_PING pings another kernel."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CLUSTER_CREATE)
        add_result = kernel.syscall(SyscallNumber.SYS_CLUSTER_ADD)
        target_id = add_result["kernel_id"]
        result = kernel.syscall(SyscallNumber.SYS_CLUSTER_PING, target_id=target_id)
        assert result["reachable"] is True
        kernel.shutdown()

    def test_sys_cluster_send_recv(self) -> None:
        """SYS_CLUSTER_SEND and SYS_CLUSTER_RECV transfer data."""
        kernel = _booted_kernel()
        create_result = kernel.syscall(SyscallNumber.SYS_CLUSTER_CREATE)
        my_id = create_result["kernel_id"]
        kernel.syscall(SyscallNumber.SYS_CLUSTER_ADD)
        # Send to self (via cluster)
        kernel.syscall(
            SyscallNumber.SYS_CLUSTER_SEND,
            to_id=my_id,
            data=b"test message",
        )
        result = kernel.syscall(SyscallNumber.SYS_CLUSTER_RECV)
        assert result["data"] == b"test message"
        kernel.shutdown()

    def test_sys_cluster_no_cluster_raises(self) -> None:
        """Cluster operations without init raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="No cluster"):
            kernel.syscall(SyscallNumber.SYS_CLUSTER_LIST)


# -- Shell cluster command tests -----------------------------------------------


class TestShellClusterCommands:
    """Verify shell cluster commands."""

    def test_cluster_create(self) -> None:
        """Shell 'cluster create' initializes a cluster."""
        _kernel, shell = _booted_shell()
        output = shell.execute("cluster create")
        assert "Cluster created" in output or "kernel" in output.lower()

    def test_cluster_list(self) -> None:
        """Shell 'cluster list' shows kernels."""
        _kernel, shell = _booted_shell()
        shell.execute("cluster create")
        output = shell.execute("cluster list")
        assert "ID" in output or "running" in output

    def test_cluster_add(self) -> None:
        """Shell 'cluster add' adds a kernel."""
        _kernel, shell = _booted_shell()
        shell.execute("cluster create")
        output = shell.execute("cluster add")
        assert "Added" in output or "kernel" in output.lower()

    def test_cluster_ping(self) -> None:
        """Shell 'cluster ping' pings a kernel."""
        _kernel, shell = _booted_shell()
        shell.execute("cluster create")
        add_output = shell.execute("cluster add")
        # Extract kernel ID from output
        match = re.search(r"\d+", add_output)
        assert match is not None
        kid = match.group()
        output = shell.execute(f"cluster ping {kid}")
        assert "reachable" in output.lower() or "OK" in output

    def test_cluster_no_args_shows_usage(self) -> None:
        """Shell 'cluster' without args shows usage."""
        _kernel, shell = _booted_shell()
        output = shell.execute("cluster")
        assert "Usage:" in output

    def test_cluster_demo(self) -> None:
        """Shell 'cluster demo' runs a demonstration."""
        _kernel, shell = _booted_shell()
        output = shell.execute("cluster demo")
        assert "Cluster Demo" in output or "cluster" in output.lower()
