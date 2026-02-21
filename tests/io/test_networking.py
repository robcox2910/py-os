"""Tests for simulated networking (sockets).

Real networking lets processes communicate across machines (or locally)
using **sockets** — endpoints identified by an address and port.  The
standard workflow is:

    Server: socket() → bind(addr) → listen() → accept() → recv/send
    Client: socket() → connect(addr) → send/recv

Our simulation mirrors this lifecycle with in-memory message passing,
teaching the socket abstraction without actual network I/O.
"""

from py_os.io.networking import Socket, SocketManager, SocketState

# -- Socket basics -------------------------------------------------------------


class TestSocketBasics:
    """Verify socket creation and properties."""

    def test_create_socket(self) -> None:
        """A new socket should be in CREATED state."""
        sock = Socket()
        assert sock.state is SocketState.CREATED

    def test_socket_has_id(self) -> None:
        """Each socket should have a unique integer ID."""
        s1 = Socket()
        s2 = Socket()
        assert s1.sock_id != s2.sock_id

    def test_socket_state_created(self) -> None:
        """New sockets start unbound."""
        sock = Socket()
        assert sock.address is None
        assert sock.port is None


# -- Bind and listen -----------------------------------------------------------


class TestBindAndListen:
    """Verify server-side socket setup."""

    def test_bind(self) -> None:
        """Binding assigns an address and port to the socket."""
        sock = Socket()
        sock.bind(address="localhost", port=8080)
        assert sock.address == "localhost"
        port = 8080
        assert sock.port == port
        assert sock.state is SocketState.BOUND

    def test_listen(self) -> None:
        """Listening transitions to LISTENING state."""
        sock = Socket()
        sock.bind(address="localhost", port=8080)
        sock.listen()
        assert sock.state is SocketState.LISTENING

    def test_listen_without_bind_raises(self) -> None:
        """Cannot listen on an unbound socket."""
        sock = Socket()
        try:
            sock.listen()
            raised = False
        except RuntimeError:
            raised = True
        assert raised

    def test_bind_twice_raises(self) -> None:
        """Cannot bind an already-bound socket."""
        sock = Socket()
        sock.bind(address="localhost", port=8080)
        try:
            sock.bind(address="localhost", port=9090)
            raised = False
        except RuntimeError:
            raised = True
        assert raised


# -- Connect and data transfer -------------------------------------------------


class TestConnectAndTransfer:
    """Verify client connection and data exchange."""

    def test_connect(self) -> None:
        """Connecting should transition to CONNECTED state."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        client = mgr.create_socket()
        mgr.connect(client, address="localhost", port=8080)
        assert client.state is SocketState.CONNECTED

    def test_send_and_receive(self) -> None:
        """Data sent on one side should be receivable on the other."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        client = mgr.create_socket()
        mgr.connect(client, address="localhost", port=8080)

        peer = mgr.accept(server)
        assert peer is not None

        mgr.send(client, b"hello")
        data = mgr.recv(peer)
        assert data == b"hello"

    def test_bidirectional(self) -> None:
        """Both sides should be able to send and receive."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        client = mgr.create_socket()
        mgr.connect(client, address="localhost", port=8080)
        peer = mgr.accept(server)
        assert peer is not None

        mgr.send(client, b"ping")
        assert mgr.recv(peer) == b"ping"

        mgr.send(peer, b"pong")
        assert mgr.recv(client) == b"pong"

    def test_recv_empty_when_no_data(self) -> None:
        """Receiving when no data has been sent returns empty bytes."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        client = mgr.create_socket()
        mgr.connect(client, address="localhost", port=8080)
        peer = mgr.accept(server)
        assert peer is not None

        data = mgr.recv(peer)
        assert data == b""


# -- Accept (server-side) -----------------------------------------------------


class TestAccept:
    """Verify server accepting incoming connections."""

    def test_accept_returns_peer(self) -> None:
        """Accept should return a connected peer socket."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        client = mgr.create_socket()
        mgr.connect(client, address="localhost", port=8080)

        peer = mgr.accept(server)
        assert peer is not None
        assert peer.state is SocketState.CONNECTED

    def test_accept_no_pending(self) -> None:
        """Accept with no pending connections returns None."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        peer = mgr.accept(server)
        assert peer is None

    def test_multiple_clients(self) -> None:
        """Server should accept multiple clients independently."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        c1 = mgr.create_socket()
        mgr.connect(c1, address="localhost", port=8080)
        c2 = mgr.create_socket()
        mgr.connect(c2, address="localhost", port=8080)

        p1 = mgr.accept(server)
        p2 = mgr.accept(server)
        assert p1 is not None
        assert p2 is not None
        assert p1.sock_id != p2.sock_id

        # Data isolation: c1's data doesn't leak to c2's peer
        mgr.send(c1, b"from-c1")
        mgr.send(c2, b"from-c2")
        assert mgr.recv(p1) == b"from-c1"
        assert mgr.recv(p2) == b"from-c2"


# -- Close ---------------------------------------------------------------------


class TestClose:
    """Verify socket closing."""

    def test_close_socket(self) -> None:
        """Closing a socket should transition to CLOSED state."""
        sock = Socket()
        sock.close()
        assert sock.state is SocketState.CLOSED

    def test_send_on_closed_raises(self) -> None:
        """Sending on a closed socket should raise."""
        mgr = SocketManager()
        server = mgr.create_socket()
        server.bind(address="localhost", port=8080)
        server.listen()

        client = mgr.create_socket()
        mgr.connect(client, address="localhost", port=8080)
        client.close()
        try:
            mgr.send(client, b"data")
            raised = False
        except RuntimeError:
            raised = True
        assert raised


# -- SocketManager -------------------------------------------------------------


class TestSocketManager:
    """Verify the socket manager registry."""

    def test_create_socket(self) -> None:
        """Manager should create and track sockets."""
        mgr = SocketManager()
        sock = mgr.create_socket()
        assert sock.state is SocketState.CREATED

    def test_list_sockets(self) -> None:
        """Manager should list all created sockets."""
        mgr = SocketManager()
        mgr.create_socket()
        mgr.create_socket()
        socket_count = 2
        assert len(mgr.list_sockets()) == socket_count

    def test_connect_to_nonexistent_raises(self) -> None:
        """Connecting to an address with no listener should raise."""
        mgr = SocketManager()
        client = mgr.create_socket()
        try:
            mgr.connect(client, address="localhost", port=9999)
            raised = False
        except ConnectionError:
            raised = True
        assert raised

    def test_get_socket_by_id(self) -> None:
        """Manager should look up sockets by ID."""
        mgr = SocketManager()
        sock = mgr.create_socket()
        found = mgr.get_socket(sock.sock_id)
        assert found is sock

    def test_get_nonexistent_returns_none(self) -> None:
        """Looking up a nonexistent ID should return None."""
        mgr = SocketManager()
        assert mgr.get_socket(999) is None
