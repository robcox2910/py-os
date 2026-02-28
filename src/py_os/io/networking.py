"""Simulated networking — sockets for inter-process communication.

In real operating systems, **sockets** are the standard API for network
communication.  A socket is an endpoint identified by an address and port.
Two processes communicate by each holding one end of a connection.

The standard lifecycle is:

    Server: socket() → bind(addr, port) → listen() → accept() → recv/send
    Client: socket() → connect(addr, port) → send/recv

Key concepts:
    - **Socket** — an endpoint for sending/receiving data.
    - **Bind** — associate a socket with an address and port.
    - **Listen** — mark a socket as passive (accepting connections).
    - **Connect** — establish a connection to a listening socket.
    - **Accept** — dequeue a pending connection on a listening socket.
    - **Send/Recv** — transfer data over an established connection.

Our simulation uses in-memory buffers instead of actual network I/O,
teaching the socket abstraction and protocol without needing a network
stack or TCP/IP implementation.
"""

from collections import deque
from enum import StrEnum
from itertools import count


class SocketError(Exception):
    """Raise when a socket operation fails."""


class SocketState(StrEnum):
    """Lifecycle states of a socket.

    Mirrors the real socket state machine:
    CREATED → BOUND → LISTENING → CONNECTED → CLOSED
    """

    CREATED = "created"
    BOUND = "bound"
    LISTENING = "listening"
    CONNECTED = "connected"
    CLOSED = "closed"


# Module-level counter for unique socket IDs
_next_sock_id = count(start=1)


class Socket:
    """A network socket — an endpoint for communication.

    Each socket has a unique ID, an optional address/port binding,
    and a state that tracks its position in the lifecycle.
    """

    def __init__(self) -> None:
        """Create a new socket in the CREATED state."""
        self._sock_id = next(_next_sock_id)
        self._state = SocketState.CREATED
        self._address: str | None = None
        self._port: int | None = None

    @property
    def sock_id(self) -> int:
        """Return the unique socket identifier."""
        return self._sock_id

    @property
    def state(self) -> SocketState:
        """Return the current socket state."""
        return self._state

    @property
    def address(self) -> str | None:
        """Return the bound address, or None if unbound."""
        return self._address

    @property
    def port(self) -> int | None:
        """Return the bound port, or None if unbound."""
        return self._port

    def bind(self, *, address: str, port: int) -> None:
        """Bind the socket to an address and port.

        In real networking, bind() associates the socket with a local
        address so that clients know where to connect.  A port can only
        be bound by one socket at a time (enforced by the OS).

        Args:
            address: The address to bind to (e.g. "localhost").
            port: The port number.

        Raises:
            RuntimeError: If the socket is already bound.

        """
        if self._state is not SocketState.CREATED:
            msg = f"Cannot bind: socket {self._sock_id} is {self._state}"
            raise RuntimeError(msg)
        self._address = address
        self._port = port
        self._state = SocketState.BOUND

    def listen(self) -> None:
        """Mark the socket as listening for incoming connections.

        In real networking, listen() puts the socket in passive mode
        and creates a backlog queue for pending connections.

        Raises:
            RuntimeError: If the socket is not bound.

        """
        if self._state is not SocketState.BOUND:
            msg = f"Cannot listen: socket {self._sock_id} is {self._state}, expected bound"
            raise RuntimeError(msg)
        self._state = SocketState.LISTENING

    def set_connected(self) -> None:
        """Transition to CONNECTED state (used by SocketManager).

        Raises:
            RuntimeError: If the socket is already CLOSED or CONNECTED.

        """
        if self._state in {SocketState.CLOSED, SocketState.CONNECTED}:
            msg = f"Cannot connect: socket {self._sock_id} is {self._state}"
            raise RuntimeError(msg)
        self._state = SocketState.CONNECTED

    def close(self) -> None:
        """Close the socket, releasing its resources."""
        self._state = SocketState.CLOSED

    def __repr__(self) -> str:
        """Return a debug-friendly representation."""
        return f"Socket(id={self._sock_id}, state={self._state})"


class SocketManager:
    """Manage sockets and route connections between them.

    In a real OS, the kernel's network stack handles connection
    routing, buffer management, and multiplexing.  Our SocketManager
    is the simplified equivalent — it tracks all sockets, matches
    connect() calls to listening sockets, and manages data buffers.
    """

    def __init__(self) -> None:
        """Create an empty socket manager."""
        self._sockets: dict[int, Socket] = {}
        # Pending connections waiting for accept()
        self._pending: dict[int, deque[Socket]] = {}
        # Data buffers: connection_id → deque of bytes
        # Each connection has two buffers (one per direction)
        self._buffers: dict[tuple[int, int], deque[bytes]] = {}

    def create_socket(self) -> Socket:
        """Create and register a new socket."""
        sock = Socket()
        self._sockets[sock.sock_id] = sock
        return sock

    def get_socket(self, sock_id: int) -> Socket | None:
        """Look up a socket by ID."""
        return self._sockets.get(sock_id)

    def list_sockets(self) -> list[Socket]:
        """Return all registered sockets."""
        return list(self._sockets.values())

    def connect(self, client: Socket, *, address: str, port: int) -> None:
        """Connect a client socket to a listening server.

        In real networking, connect() initiates TCP's three-way
        handshake.  Our simulation immediately establishes the
        connection if a matching listener exists.

        Args:
            client: The client socket.
            address: The server address.
            port: The server port.

        Raises:
            ConnectionError: If no server is listening on that address.

        """
        if client.state is not SocketState.CREATED:
            msg = f"Cannot connect: socket {client.sock_id} is {client.state}, expected created"
            raise ConnectionError(msg)
        server = self._find_listener(address, port)
        if server is None:
            msg = f"Connection refused: no listener on {address}:{port}"
            raise ConnectionError(msg)
        client.set_connected()
        # Queue this client for the server to accept
        self._pending.setdefault(server.sock_id, deque()).append(client)

    def accept(self, server: Socket) -> Socket | None:
        """Accept the next pending connection on a listening socket.

        Returns a new **peer socket** that the server uses to
        communicate with the client.  The original listening socket
        stays in LISTENING state to accept more connections.

        In real networking, accept() dequeues from the backlog
        and returns a new connected socket (file descriptor).

        Args:
            server: The listening socket.

        Returns:
            A connected peer socket, or None if no pending connections.

        """
        pending = self._pending.get(server.sock_id)
        if not pending:
            return None
        client = pending.popleft()

        # Create a peer socket for the server side of this connection
        peer = self.create_socket()
        peer.set_connected()

        # Set up bidirectional buffers: client→peer and peer→client
        self._buffers[(client.sock_id, peer.sock_id)] = deque()
        self._buffers[(peer.sock_id, client.sock_id)] = deque()

        return peer

    def send(self, sender: Socket, data: bytes) -> None:
        """Send data from one socket to its connected peer.

        Args:
            sender: The sending socket.
            data: The bytes to send.

        Raises:
            RuntimeError: If the socket is not connected or is closed.

        """
        if sender.state is SocketState.CLOSED:
            msg = f"Cannot send: socket {sender.sock_id} is closed"
            raise RuntimeError(msg)
        # Find the buffer where this sender writes
        for (src, _dst), buf in self._buffers.items():
            if src == sender.sock_id:
                buf.append(data)
                return
        msg = f"Socket {sender.sock_id} is not connected"
        raise RuntimeError(msg)

    def recv(self, receiver: Socket) -> bytes:
        """Receive data from the connected peer.

        Returns data that was sent to this socket.  If no data
        is available, returns empty bytes (non-blocking).

        Args:
            receiver: The receiving socket.

        Returns:
            The next chunk of data, or empty bytes.

        Raises:
            RuntimeError: If the socket is closed.

        """
        if receiver.state is SocketState.CLOSED:
            msg = f"Cannot recv: socket {receiver.sock_id} is closed"
            raise RuntimeError(msg)
        # Find the buffer where data is written *to* this receiver
        for (_src, dst), buf in self._buffers.items():
            if dst == receiver.sock_id and buf:
                return buf.popleft()
        return b""

    def _find_listener(self, address: str, port: int) -> Socket | None:
        """Find a listening socket matching the address and port."""
        for sock in self._sockets.values():
            if (
                sock.state is SocketState.LISTENING
                and sock.address == address
                and sock.port == port
            ):
                return sock
        return None
