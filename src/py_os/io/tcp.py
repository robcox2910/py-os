"""TCP transport layer — reliable, ordered, byte-stream delivery.

In real networking, TCP sits between the application layer (HTTP, DNS)
and the network layer (IP).  It provides:

    1. **Reliable delivery** — lost segments are retransmitted.
    2. **Ordered delivery** — segments arrive in sequence.
    3. **Flow control** — the receiver limits how fast the sender sends.
    4. **Congestion control** — the network limits how fast everyone sends.

Think of TCP like sending a numbered set of postcards.  You number each
one, and the receiver tells you which ones arrived.  If one goes missing,
you send it again.  The receiver also says "I have room for 5 more
postcards" (flow control), and if the post office is busy, you slow
down (congestion control).

Our simulation implements the core TCP state machine, three-way
handshake, sliding window, and a simplified congestion controller
(slow start + AIMD) — all driven by ``kernel.tick()`` for timeouts.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum

# -- Constants (no magic numbers) -------------------------------------------

INITIAL_CWND = 1
INITIAL_SSTHRESH = 16
DEFAULT_RECV_WINDOW = 8
DEFAULT_RETRANSMIT_TIMEOUT = 10  # ticks
INITIAL_SEQ_NUMBER = 0
MAX_SEGMENT_PAYLOAD = 256


# -- Enums and data classes -------------------------------------------------


class TcpState(StrEnum):
    """The 11 states of a TCP connection.

    A real TCP connection moves through these states during its
    lifetime: setup (handshake), data transfer, and teardown (close).
    """

    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    CLOSING = "CLOSING"


class TcpFlag(StrEnum):
    """TCP control flags present in each segment header."""

    SYN = "SYN"
    ACK = "ACK"
    FIN = "FIN"
    RST = "RST"


@dataclass(frozen=True)
class TcpSegment:
    """A single TCP segment (the packet unit of TCP).

    Each segment carries a sequence number, acknowledgement number,
    control flags, the receiver's advertised window, and an optional
    data payload.
    """

    src_port: int
    dst_port: int
    seq_number: int
    ack_number: int
    flags: frozenset[TcpFlag]
    window_size: int
    payload: bytes = b""

    def has_flag(self, flag: TcpFlag) -> bool:
        """Check whether this segment carries a specific flag."""
        return flag in self.flags


# -- TcpConnection ----------------------------------------------------------


class TcpConnection:
    """One endpoint of a TCP connection.

    Manages the state machine, sequence numbers, send/receive buffers,
    flow control (sliding window), and congestion control (slow start
    plus AIMD).
    """

    def __init__(
        self,
        *,
        local_port: int,
        remote_port: int,
    ) -> None:
        """Create a new TCP connection endpoint.

        Args:
            local_port: This endpoint's port number.
            remote_port: The remote endpoint's port number.

        """
        self._local_port = local_port
        self._remote_port = remote_port
        self._state = TcpState.CLOSED

        # Sequence tracking
        self._send_next = INITIAL_SEQ_NUMBER
        self._send_unacked = INITIAL_SEQ_NUMBER
        self._recv_next = INITIAL_SEQ_NUMBER

        # Flow control
        self._recv_window = DEFAULT_RECV_WINDOW
        self._send_window = DEFAULT_RECV_WINDOW

        # Congestion control
        self._cwnd = INITIAL_CWND
        self._ssthresh = INITIAL_SSTHRESH

        # Buffers
        self._send_buffer: deque[bytes] = deque()
        self._recv_buffer: deque[bytes] = deque()
        self._unacked_segments: list[TcpSegment] = []

        # Retransmission
        self._retransmit_timer = 0
        self._retransmit_timeout = DEFAULT_RETRANSMIT_TIMEOUT

    # -- Properties ----------------------------------------------------------

    @property
    def state(self) -> TcpState:
        """Return the current TCP state."""
        return self._state

    @property
    def local_port(self) -> int:
        """Return the local port number."""
        return self._local_port

    @property
    def remote_port(self) -> int:
        """Return the remote port number."""
        return self._remote_port

    @property
    def send_next(self) -> int:
        """Return the next sequence number to send."""
        return self._send_next

    @property
    def send_unacked(self) -> int:
        """Return the oldest unacknowledged sequence number."""
        return self._send_unacked

    @property
    def recv_next(self) -> int:
        """Return the next expected sequence number from the peer."""
        return self._recv_next

    @property
    def recv_window(self) -> int:
        """Return the receive window size (flow control)."""
        return self._recv_window

    @property
    def send_window(self) -> int:
        """Return the peer's advertised window size."""
        return self._send_window

    @property
    def cwnd(self) -> int:
        """Return the congestion window size."""
        return self._cwnd

    @property
    def ssthresh(self) -> int:
        """Return the slow-start threshold."""
        return self._ssthresh

    @property
    def effective_window(self) -> int:
        """Return the effective send window: min(cwnd, peer window)."""
        return min(self._cwnd, self._send_window)

    @property
    def unacked_count(self) -> int:
        """Return the number of unacknowledged segments in flight."""
        return len(self._unacked_segments)

    # -- Segment creation ----------------------------------------------------

    def create_segment(
        self,
        *,
        flags: frozenset[TcpFlag],
        payload: bytes = b"",
    ) -> TcpSegment:
        """Create a segment from this endpoint.

        Args:
            flags: Control flags for the segment.
            payload: Optional data payload.

        Returns:
            A new TcpSegment ready to send.

        """
        seg = TcpSegment(
            src_port=self._local_port,
            dst_port=self._remote_port,
            seq_number=self._send_next,
            ack_number=self._recv_next,
            flags=flags,
            window_size=self._recv_window,
            payload=payload,
        )
        # SYN and FIN consume one sequence number
        if seg.has_flag(TcpFlag.SYN) or seg.has_flag(TcpFlag.FIN):
            self._send_next += 1
        # Data consumes sequence numbers equal to payload length
        if payload:
            self._send_next += len(payload)
        return seg

    # -- State machine: process incoming segment -----------------------------

    def process_segment(self, segment: TcpSegment) -> list[TcpSegment]:
        """Process an incoming segment and return response segments.

        This implements the TCP state machine. Each state handles
        specific flags and transitions to the next state.

        Args:
            segment: The incoming TCP segment.

        Returns:
            A list of response segments to send back.

        """
        responses: list[TcpSegment] = []

        # RST handling — immediate close from any state
        if segment.has_flag(TcpFlag.RST):
            self._state = TcpState.CLOSED
            return responses

        # Update peer's advertised window
        self._send_window = segment.window_size

        match self._state:
            case TcpState.LISTEN:
                responses = self._handle_listen(segment)
            case TcpState.SYN_SENT:
                responses = self._handle_syn_sent(segment)
            case TcpState.SYN_RECEIVED:
                responses = self._handle_syn_received(segment)
            case TcpState.ESTABLISHED:
                responses = self._handle_established(segment)
            case TcpState.FIN_WAIT_1:
                responses = self._handle_fin_wait_1(segment)
            case TcpState.FIN_WAIT_2:
                responses = self._handle_fin_wait_2(segment)
            case TcpState.CLOSE_WAIT:
                pass  # Waiting for application to close
            case TcpState.LAST_ACK:
                responses = self._handle_last_ack(segment)
            case TcpState.CLOSING:
                responses = self._handle_closing(segment)
            case TcpState.TIME_WAIT:
                pass  # Waiting for timeout, ignore segments
            case _:
                pass

        return responses

    def _handle_listen(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in LISTEN state — expect SYN."""
        if segment.has_flag(TcpFlag.SYN):
            self._recv_next = segment.seq_number + 1
            self._state = TcpState.SYN_RECEIVED
            syn_ack = self.create_segment(
                flags=frozenset({TcpFlag.SYN, TcpFlag.ACK}),
            )
            self._unacked_segments.append(syn_ack)
            self._retransmit_timer = 0
            return [syn_ack]
        return []

    def _handle_syn_sent(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in SYN_SENT state — expect SYN+ACK."""
        if segment.has_flag(TcpFlag.SYN) and segment.has_flag(TcpFlag.ACK):
            self._recv_next = segment.seq_number + 1
            self._send_unacked = segment.ack_number
            self._unacked_segments.clear()
            self._state = TcpState.ESTABLISHED
            ack = self.create_segment(flags=frozenset({TcpFlag.ACK}))
            return [ack]
        return []

    def _handle_syn_received(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in SYN_RECEIVED — expect ACK to complete handshake."""
        if segment.has_flag(TcpFlag.ACK):
            self._send_unacked = segment.ack_number
            self._unacked_segments.clear()
            self._state = TcpState.ESTABLISHED
        return []

    def _handle_established(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in ESTABLISHED — data transfer or FIN."""
        responses: list[TcpSegment] = []

        # Process ACK for our sent data
        if segment.has_flag(TcpFlag.ACK):
            self._process_ack(segment.ack_number)

        # Process incoming data
        if segment.payload:
            self._recv_buffer.append(segment.payload)
            self._recv_next = segment.seq_number + len(segment.payload)
            ack = self.create_segment(flags=frozenset({TcpFlag.ACK}))
            responses.append(ack)

        # FIN received — start graceful close (passive side)
        if segment.has_flag(TcpFlag.FIN):
            self._recv_next = segment.seq_number + 1
            self._state = TcpState.CLOSE_WAIT
            ack = self.create_segment(flags=frozenset({TcpFlag.ACK}))
            responses.append(ack)

        return responses

    def _handle_fin_wait_1(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in FIN_WAIT_1 — waiting for ACK of our FIN."""
        responses: list[TcpSegment] = []

        if segment.has_flag(TcpFlag.ACK):
            self._send_unacked = segment.ack_number
            self._unacked_segments.clear()
            if segment.has_flag(TcpFlag.FIN):
                # Simultaneous close
                self._recv_next = segment.seq_number + 1
                self._state = TcpState.TIME_WAIT
                ack = self.create_segment(flags=frozenset({TcpFlag.ACK}))
                responses.append(ack)
            else:
                self._state = TcpState.FIN_WAIT_2

        elif segment.has_flag(TcpFlag.FIN):
            # FIN without ACK — enter CLOSING
            self._recv_next = segment.seq_number + 1
            self._state = TcpState.CLOSING
            ack = self.create_segment(flags=frozenset({TcpFlag.ACK}))
            responses.append(ack)

        return responses

    def _handle_fin_wait_2(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in FIN_WAIT_2 — waiting for peer's FIN."""
        if segment.has_flag(TcpFlag.FIN):
            self._recv_next = segment.seq_number + 1
            self._state = TcpState.TIME_WAIT
            ack = self.create_segment(flags=frozenset({TcpFlag.ACK}))
            return [ack]
        return []

    def _handle_last_ack(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in LAST_ACK — waiting for ACK of our FIN."""
        if segment.has_flag(TcpFlag.ACK):
            self._send_unacked = segment.ack_number
            self._unacked_segments.clear()
            self._state = TcpState.CLOSED
        return []

    def _handle_closing(self, segment: TcpSegment) -> list[TcpSegment]:
        """Handle segment in CLOSING — waiting for ACK of our FIN."""
        if segment.has_flag(TcpFlag.ACK):
            self._send_unacked = segment.ack_number
            self._unacked_segments.clear()
            self._state = TcpState.TIME_WAIT
        return []

    # -- Connection setup / teardown -----------------------------------------

    def initiate_open(self) -> TcpSegment:
        """Start an active open (client side) — send SYN.

        Returns:
            The SYN segment to send.

        """
        self._state = TcpState.SYN_SENT
        syn = self.create_segment(flags=frozenset({TcpFlag.SYN}))
        self._unacked_segments.append(syn)
        self._retransmit_timer = 0
        return syn

    def start_listen(self) -> None:
        """Start a passive open (server side) — enter LISTEN state."""
        self._state = TcpState.LISTEN

    def initiate_close(self) -> TcpSegment:
        """Start a graceful close — send FIN.

        Returns:
            The FIN segment to send.

        """
        fin = self.create_segment(flags=frozenset({TcpFlag.FIN, TcpFlag.ACK}))
        self._unacked_segments.append(fin)
        self._retransmit_timer = 0
        if self._state is TcpState.ESTABLISHED:
            self._state = TcpState.FIN_WAIT_1
        elif self._state is TcpState.CLOSE_WAIT:
            self._state = TcpState.LAST_ACK
        return fin

    # -- Data transfer -------------------------------------------------------

    def send(self, data: bytes) -> list[TcpSegment]:
        """Queue data for sending and create segments within the window.

        Data is split into segments respecting MAX_SEGMENT_PAYLOAD
        and the effective send window.

        Args:
            data: The data bytes to send.

        Returns:
            A list of data segments ready to transmit.

        """
        if self._state is not TcpState.ESTABLISHED:
            return []

        # Split data into chunks
        offset = 0
        while offset < len(data):
            chunk_size = min(MAX_SEGMENT_PAYLOAD, len(data) - offset)
            self._send_buffer.append(data[offset : offset + chunk_size])
            offset += chunk_size

        return self._flush_send_buffer()

    def _flush_send_buffer(self) -> list[TcpSegment]:
        """Send buffered data within the effective window."""
        segments: list[TcpSegment] = []
        while self._send_buffer and self.unacked_count < self.effective_window:
            chunk = self._send_buffer.popleft()
            seg = self.create_segment(
                flags=frozenset({TcpFlag.ACK}),
                payload=chunk,
            )
            self._unacked_segments.append(seg)
            self._retransmit_timer = 0
            segments.append(seg)
        return segments

    def recv(self) -> bytes:
        """Read received data from the buffer.

        Returns:
            All buffered data concatenated, or empty bytes.

        """
        if not self._recv_buffer:
            return b""
        result = b"".join(self._recv_buffer)
        self._recv_buffer.clear()
        return result

    # -- Congestion control --------------------------------------------------

    def _process_ack(self, ack_number: int) -> None:
        """Process an ACK: advance send_unacked and update cwnd.

        Implements slow start and congestion avoidance (AIMD).

        Args:
            ack_number: The acknowledgement number from the peer.

        """
        if ack_number <= self._send_unacked:
            return  # Duplicate ACK — ignore for now

        # Remove acknowledged segments
        self._unacked_segments = [
            seg
            for seg in self._unacked_segments
            if seg.seq_number
            + len(seg.payload)
            + (1 if seg.has_flag(TcpFlag.SYN) or seg.has_flag(TcpFlag.FIN) else 0)
            > ack_number
        ]
        self._send_unacked = ack_number

        # Congestion control: slow start or congestion avoidance
        if self._cwnd < self._ssthresh:
            # Slow start: cwnd doubles per RTT (increment by 1 per ACK)
            self._cwnd += 1
        else:
            # Congestion avoidance: additive increase (1/cwnd per ACK)
            # We use integer arithmetic: increment when enough ACKs received
            self._cwnd_fractional = getattr(self, "_cwnd_fractional", 0) + 1
            if self._cwnd_fractional >= self._cwnd:
                self._cwnd += 1
                self._cwnd_fractional = 0

        # Reset retransmit timer on new ACK
        self._retransmit_timer = 0

    def on_timeout(self) -> list[TcpSegment]:
        """Handle a retransmission timeout.

        Retransmit the oldest unacknowledged segment, apply
        multiplicative decrease to the congestion window.

        Returns:
            A list of segments to retransmit (at most one).

        """
        if not self._unacked_segments:
            return []

        # Multiplicative decrease
        self._ssthresh = max(self._cwnd // 2, 1)
        self._cwnd = INITIAL_CWND

        # Retransmit oldest unacked segment
        oldest = self._unacked_segments[0]
        self._retransmit_timer = 0
        return [oldest]

    # -- Timer integration ---------------------------------------------------

    def tick(self) -> list[TcpSegment]:
        """Advance the retransmission timer by one tick.

        Returns:
            Segments to retransmit if a timeout occurred, else empty.

        """
        if not self._unacked_segments:
            return []

        self._retransmit_timer += 1
        if self._retransmit_timer >= self._retransmit_timeout:
            return self.on_timeout()
        return []

    # -- Info ----------------------------------------------------------------

    def info(self) -> dict[str, object]:
        """Return connection info as a dict."""
        return {
            "state": str(self._state),
            "local_port": self._local_port,
            "remote_port": self._remote_port,
            "send_next": self._send_next,
            "send_unacked": self._send_unacked,
            "recv_next": self._recv_next,
            "cwnd": self._cwnd,
            "ssthresh": self._ssthresh,
            "send_window": self._send_window,
            "recv_window": self._recv_window,
            "effective_window": self.effective_window,
            "unacked": self.unacked_count,
        }


# -- TcpStack ---------------------------------------------------------------


class TcpStack:
    """Manage multiple TCP connections.

    The stack acts as the TCP layer of the OS network stack,
    routing segments between connections and managing the
    connection lifecycle.
    """

    def __init__(self) -> None:
        """Create an empty TCP stack."""
        self._connections: dict[int, TcpConnection] = {}
        self._listeners: dict[int, TcpConnection] = {}
        self._accept_queue: dict[int, deque[int]] = {}
        self._next_conn_id = 1

    def _alloc_id(self) -> int:
        """Allocate a unique connection ID."""
        conn_id = self._next_conn_id
        self._next_conn_id += 1
        return conn_id

    def open_connection(
        self,
        *,
        client_port: int,
        server_port: int,
    ) -> tuple[int, list[TcpSegment]]:
        """Initiate a TCP connection (active open).

        Args:
            client_port: The client's port number.
            server_port: The server's port number.

        Returns:
            A tuple of (connection_id, segments_to_send).

        """
        conn_id = self._alloc_id()
        conn = TcpConnection(local_port=client_port, remote_port=server_port)
        self._connections[conn_id] = conn
        syn = conn.initiate_open()
        return conn_id, [syn]

    def listen(self, *, port: int) -> int:
        """Start listening on a port (passive open).

        Args:
            port: The port number to listen on.

        Returns:
            The listener connection ID.

        Raises:
            ValueError: If the port is already in use.

        """
        for conn in self._listeners.values():
            if conn.local_port == port:
                msg = f"Port {port} already in use"
                raise ValueError(msg)

        conn_id = self._alloc_id()
        conn = TcpConnection(local_port=port, remote_port=0)
        conn.start_listen()
        self._listeners[conn_id] = conn
        self._accept_queue[conn_id] = deque()
        return conn_id

    def accept(self, *, listener_id: int) -> int | None:
        """Accept a pending connection on a listener.

        Args:
            listener_id: The listener's connection ID.

        Returns:
            The new connection ID, or None if no pending connections.

        Raises:
            KeyError: If the listener ID is not found.

        """
        queue = self._accept_queue.get(listener_id)
        if queue is None:
            msg = f"Listener {listener_id} not found"
            raise KeyError(msg)
        if not queue:
            return None
        return queue.popleft()

    def close_connection(self, *, conn_id: int) -> list[TcpSegment]:
        """Initiate a graceful close.

        Args:
            conn_id: The connection ID to close.

        Returns:
            Segments to send (the FIN).

        Raises:
            KeyError: If the connection ID is not found.

        """
        conn = self._connections.get(conn_id)
        if conn is None:
            # Check if it's a listener
            listener = self._listeners.pop(conn_id, None)
            if listener is not None:
                self._accept_queue.pop(conn_id, None)
                return []
            msg = f"Connection {conn_id} not found"
            raise KeyError(msg)

        if conn.state in {TcpState.CLOSED, TcpState.TIME_WAIT}:
            self._connections.pop(conn_id, None)
            return []

        fin = conn.initiate_close()
        return [fin]

    def send(self, *, conn_id: int, data: bytes) -> list[TcpSegment]:
        """Send data on a connection.

        Args:
            conn_id: The connection ID.
            data: The data to send.

        Returns:
            Data segments to transmit.

        Raises:
            KeyError: If the connection ID is not found.

        """
        conn = self._get_connection(conn_id)
        return conn.send(data)

    def recv(self, *, conn_id: int) -> bytes:
        """Receive data from a connection.

        Args:
            conn_id: The connection ID.

        Returns:
            Buffered data, or empty bytes.

        Raises:
            KeyError: If the connection ID is not found.

        """
        conn = self._get_connection(conn_id)
        return conn.recv()

    def deliver_segment(self, segment: TcpSegment) -> list[TcpSegment]:
        """Deliver an incoming segment to the correct connection.

        Finds the matching connection by port numbers and delegates
        processing to it.

        Args:
            segment: The incoming TCP segment.

        Returns:
            Response segments to send back.

        """
        # Try active connections first
        for conn in self._connections.values():
            if conn.local_port == segment.dst_port and conn.remote_port == segment.src_port:
                return conn.process_segment(segment)

        # Try listeners (for SYN on listening port)
        for listener_id, listener in self._listeners.items():
            if listener.local_port == segment.dst_port and segment.has_flag(TcpFlag.SYN):
                # Create a new server-side connection
                server_id = self._alloc_id()
                server_conn = TcpConnection(
                    local_port=listener.local_port,
                    remote_port=segment.src_port,
                )
                server_conn.start_listen()
                self._connections[server_id] = server_conn
                self._accept_queue[listener_id].append(server_id)
                return server_conn.process_segment(segment)

        return []

    def tick(self) -> list[TcpSegment]:
        """Advance all connection retransmission timers.

        Returns:
            Any segments that need retransmission.

        """
        retransmissions: list[TcpSegment] = []
        for conn in self._connections.values():
            retransmissions.extend(conn.tick())
        return retransmissions

    def get_connection_info(self, conn_id: int) -> dict[str, object]:
        """Return info about a specific connection.

        Args:
            conn_id: The connection ID.

        Returns:
            A dict of connection details.

        Raises:
            KeyError: If the connection ID is not found.

        """
        conn = self._get_connection(conn_id)
        return {"conn_id": conn_id, **conn.info()}

    def list_connections(self) -> list[dict[str, object]]:
        """Return info about all connections and listeners."""
        result: list[dict[str, object]] = []
        for conn_id, conn in self._connections.items():
            result.append({"conn_id": conn_id, **conn.info()})
        for listener_id, listener in self._listeners.items():
            result.append(
                {
                    "conn_id": listener_id,
                    "state": str(listener.state),
                    "local_port": listener.local_port,
                    "remote_port": 0,
                    "pending_accepts": len(self._accept_queue.get(listener_id, deque())),
                }
            )
        return result

    def _get_connection(self, conn_id: int) -> TcpConnection:
        """Look up a connection by ID.

        Raises:
            KeyError: If not found.

        """
        conn = self._connections.get(conn_id)
        if conn is None:
            msg = f"Connection {conn_id} not found"
            raise KeyError(msg)
        return conn
