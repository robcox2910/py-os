"""Unit tests for the TCP transport layer."""

import pytest

from py_os.io.tcp import (
    DEFAULT_RECV_WINDOW,
    DEFAULT_RETRANSMIT_TIMEOUT,
    INITIAL_CWND,
    INITIAL_SEQ_NUMBER,
    INITIAL_SSTHRESH,
    MAX_SEGMENT_PAYLOAD,
    TcpConnection,
    TcpFlag,
    TcpSegment,
    TcpStack,
    TcpState,
)

CLIENT_PORT = 5000
SERVER_PORT = 80
CUSTOM_PORT = 9090
EXPECTED_SSTHRESH_AFTER_TIMEOUT = 4  # cwnd=8 → ssthresh = 8 // 2


# -- Segment tests ----------------------------------------------------------


class TestTcpSegment:
    """Test TCP segment creation and flag checks."""

    def test_segment_fields(self) -> None:
        """Segment stores all header fields."""
        seg = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.SYN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        assert seg.src_port == CLIENT_PORT
        assert seg.dst_port == SERVER_PORT
        assert seg.payload == b""

    def test_has_flag(self) -> None:
        """has_flag returns True for present flags."""
        seg = TcpSegment(
            src_port=0,
            dst_port=0,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.SYN, TcpFlag.ACK}),
            window_size=0,
        )
        assert seg.has_flag(TcpFlag.SYN) is True
        assert seg.has_flag(TcpFlag.ACK) is True
        assert seg.has_flag(TcpFlag.FIN) is False

    def test_segment_is_frozen(self) -> None:
        """Segments are immutable."""
        seg = TcpSegment(
            src_port=0,
            dst_port=0,
            seq_number=0,
            ack_number=0,
            flags=frozenset(),
            window_size=0,
        )
        with pytest.raises(AttributeError):
            seg.src_port = 1  # type: ignore[misc]


# -- Connection state machine tests -----------------------------------------


class TestTcpHandshake:
    """Test the three-way handshake (SYN, SYN+ACK, ACK)."""

    def test_active_open_sends_syn(self) -> None:
        """Client initiates with SYN and enters SYN_SENT."""
        client = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        syn = client.initiate_open()
        assert client.state is TcpState.SYN_SENT
        assert syn.has_flag(TcpFlag.SYN)
        assert syn.src_port == CLIENT_PORT
        assert syn.dst_port == SERVER_PORT

    def test_passive_open_listens(self) -> None:
        """Server enters LISTEN state."""
        server = TcpConnection(local_port=SERVER_PORT, remote_port=0)
        server.start_listen()
        assert server.state is TcpState.LISTEN

    def test_server_responds_syn_ack(self) -> None:
        """Server responds to SYN with SYN+ACK."""
        server = TcpConnection(local_port=SERVER_PORT, remote_port=CLIENT_PORT)
        server.start_listen()
        syn = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=INITIAL_SEQ_NUMBER,
            ack_number=0,
            flags=frozenset({TcpFlag.SYN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        responses = server.process_segment(syn)
        assert server.state is TcpState.SYN_RECEIVED
        assert len(responses) == 1
        assert responses[0].has_flag(TcpFlag.SYN)
        assert responses[0].has_flag(TcpFlag.ACK)

    def test_client_completes_handshake(self) -> None:
        """Client processes SYN+ACK and enters ESTABLISHED."""
        client = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        client.initiate_open()
        syn_ack = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=INITIAL_SEQ_NUMBER,
            ack_number=1,
            flags=frozenset({TcpFlag.SYN, TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        responses = client.process_segment(syn_ack)
        assert client.state is TcpState.ESTABLISHED
        assert len(responses) == 1
        assert responses[0].has_flag(TcpFlag.ACK)

    def test_server_completes_handshake(self) -> None:
        """Server processes final ACK and enters ESTABLISHED."""
        server = TcpConnection(local_port=SERVER_PORT, remote_port=CLIENT_PORT)
        server.start_listen()
        # Process SYN
        syn = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.SYN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        server.process_segment(syn)
        # Process ACK
        ack = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=1,
            ack_number=1,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        server.process_segment(ack)
        assert server.state is TcpState.ESTABLISHED


def _established_pair() -> tuple[TcpConnection, TcpConnection]:
    """Create a pair of connections in ESTABLISHED state."""
    client = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
    server = TcpConnection(local_port=SERVER_PORT, remote_port=CLIENT_PORT)
    server.start_listen()

    # Three-way handshake
    syn = client.initiate_open()
    syn_ack_responses = server.process_segment(syn)
    client.process_segment(syn_ack_responses[0])
    ack = TcpSegment(
        src_port=CLIENT_PORT,
        dst_port=SERVER_PORT,
        seq_number=1,
        ack_number=1,
        flags=frozenset({TcpFlag.ACK}),
        window_size=DEFAULT_RECV_WINDOW,
    )
    server.process_segment(ack)

    assert client.state is TcpState.ESTABLISHED
    assert server.state is TcpState.ESTABLISHED
    return client, server


# -- Data transfer tests -----------------------------------------------------


class TestDataTransfer:
    """Test sending and receiving data."""

    def test_send_creates_segments(self) -> None:
        """Sending data creates data segments."""
        client, _server = _established_pair()
        segments = client.send(b"hello")
        assert len(segments) == 1
        assert segments[0].payload == b"hello"
        assert segments[0].has_flag(TcpFlag.ACK)

    def test_recv_returns_data(self) -> None:
        """Receiving a data segment makes data available."""
        client, server = _established_pair()
        segments = client.send(b"hello")
        server.process_segment(segments[0])
        data = server.recv()
        assert data == b"hello"

    def test_recv_empty_when_no_data(self) -> None:
        """Recv returns empty bytes when no data available."""
        client, _server = _established_pair()
        assert client.recv() == b""

    def test_data_segment_triggers_ack(self) -> None:
        """Receiving data sends back an ACK."""
        client, server = _established_pair()
        segments = client.send(b"hi")
        responses = server.process_segment(segments[0])
        assert len(responses) >= 1
        assert any(r.has_flag(TcpFlag.ACK) for r in responses)

    def test_large_data_split_into_segments(self) -> None:
        """Data larger than MAX_SEGMENT_PAYLOAD is split."""
        client, _server = _established_pair()
        # Set cwnd high enough to send multiple segments
        client._cwnd = MAX_SEGMENT_PAYLOAD
        data = b"x" * (MAX_SEGMENT_PAYLOAD + 1)
        segments = client.send(data)
        assert len(segments) >= 2  # noqa: PLR2004

    def test_send_on_closed_returns_empty(self) -> None:
        """Sending on a non-ESTABLISHED connection returns empty."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        assert conn.send(b"data") == []


# -- Flow control tests ----------------------------------------------------


class TestFlowControl:
    """Test sliding window flow control."""

    def test_effective_window(self) -> None:
        """Effective window is min(cwnd, peer window)."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        assert conn.effective_window == min(conn.cwnd, conn.send_window)

    def test_send_window_limits_segments(self) -> None:
        """Send window limits how many segments can be in flight."""
        client, _server = _established_pair()
        # cwnd starts at 1, so only 1 segment can be in flight
        assert client.cwnd == INITIAL_CWND
        data = b"x" * MAX_SEGMENT_PAYLOAD * 3
        segments = client.send(data)
        assert len(segments) == INITIAL_CWND

    def test_recv_window_advertised(self) -> None:
        """Segments carry the receiver's advertised window."""
        client, _server = _established_pair()
        segments = client.send(b"test")
        assert segments[0].window_size == DEFAULT_RECV_WINDOW


# -- Congestion control tests -----------------------------------------------


class TestCongestionControl:
    """Test slow start and AIMD congestion control."""

    def test_initial_cwnd(self) -> None:
        """Connection starts with cwnd=1."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        assert conn.cwnd == INITIAL_CWND

    def test_initial_ssthresh(self) -> None:
        """Connection starts with ssthresh=16."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        assert conn.ssthresh == INITIAL_SSTHRESH

    def test_slow_start_increases_cwnd(self) -> None:
        """ACK in slow start increases cwnd by 1."""
        client, server = _established_pair()
        segments = client.send(b"data")
        # ACK from server
        ack = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=server.send_next,
            ack_number=client.send_next,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        client.process_segment(ack)
        expected_cwnd = INITIAL_CWND + 1
        assert client.cwnd == expected_cwnd
        assert len(segments) == 1  # Used segments var

    def test_timeout_reduces_cwnd(self) -> None:
        """Timeout sets cwnd=1 and halves ssthresh."""
        client, _server = _established_pair()
        client._cwnd = 8
        client.send(b"data")
        retransmissions = client.on_timeout()
        assert client.cwnd == INITIAL_CWND
        assert client.ssthresh == EXPECTED_SSTHRESH_AFTER_TIMEOUT
        assert len(retransmissions) == 1


# -- Retransmission tests --------------------------------------------------


class TestRetransmission:
    """Test retransmission timer and timeout."""

    def test_tick_advances_timer(self) -> None:
        """Each tick advances the retransmission timer."""
        client, _server = _established_pair()
        client.send(b"data")
        # Tick but don't reach timeout
        for _ in range(DEFAULT_RETRANSMIT_TIMEOUT - 1):
            result = client.tick()
            assert result == []

    def test_timeout_triggers_retransmission(self) -> None:
        """Timer reaching timeout retransmits oldest segment."""
        client, _server = _established_pair()
        segments = client.send(b"data")
        original = segments[0]
        retransmissions: list[TcpSegment] = []
        for _ in range(DEFAULT_RETRANSMIT_TIMEOUT):
            retransmissions.extend(client.tick())
        assert len(retransmissions) == 1
        assert retransmissions[0].seq_number == original.seq_number

    def test_no_timeout_when_no_unacked(self) -> None:
        """No retransmission when nothing is unacked."""
        client, _server = _established_pair()
        for _ in range(DEFAULT_RETRANSMIT_TIMEOUT * 2):
            assert client.tick() == []


# -- Graceful close tests ---------------------------------------------------


class TestGracefulClose:
    """Test the four-way close sequence."""

    def test_active_close_sends_fin(self) -> None:
        """Initiating close sends FIN and enters FIN_WAIT_1."""
        client, _server = _established_pair()
        fin = client.initiate_close()
        assert client.state is TcpState.FIN_WAIT_1
        assert fin.has_flag(TcpFlag.FIN)

    def test_passive_close_sequence(self) -> None:
        """Receiving FIN transitions to CLOSE_WAIT, then LAST_ACK."""
        client, server = _established_pair()
        fin = client.initiate_close()
        responses = server.process_segment(fin)
        assert server.state is TcpState.CLOSE_WAIT
        assert any(r.has_flag(TcpFlag.ACK) for r in responses)

        # Server closes its side
        server_fin = server.initiate_close()
        assert server.state is TcpState.LAST_ACK
        assert server_fin.has_flag(TcpFlag.FIN)

    def test_full_close_sequence(self) -> None:
        """Complete four-way close: FIN → ACK → FIN → ACK."""
        client, server = _established_pair()

        # Client sends FIN
        fin1 = client.initiate_close()
        assert client.state is TcpState.FIN_WAIT_1

        # Server receives FIN, sends ACK
        responses = server.process_segment(fin1)
        assert server.state is TcpState.CLOSE_WAIT

        # Client receives ACK, enters FIN_WAIT_2
        for resp in responses:
            client.process_segment(resp)
        assert client.state is TcpState.FIN_WAIT_2

        # Server sends FIN
        fin2 = server.initiate_close()
        assert server.state is TcpState.LAST_ACK

        # Client receives FIN, sends ACK, enters TIME_WAIT
        responses2 = client.process_segment(fin2)
        assert client.state is TcpState.TIME_WAIT

        # Server receives ACK, enters CLOSED
        for resp in responses2:
            server.process_segment(resp)
        assert server.state is TcpState.CLOSED

    def test_rst_closes_immediately(self) -> None:
        """RST immediately closes the connection."""
        client, _server = _established_pair()
        rst = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.RST}),
            window_size=0,
        )
        client.process_segment(rst)
        assert client.state is TcpState.CLOSED


# -- Connection info --------------------------------------------------------


class TestConnectionInfo:
    """Test connection info reporting."""

    def test_info_dict(self) -> None:
        """Connection info contains expected keys."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        info = conn.info()
        assert info["state"] == str(TcpState.CLOSED)
        assert info["local_port"] == CLIENT_PORT
        assert info["remote_port"] == SERVER_PORT
        assert "cwnd" in info
        assert "ssthresh" in info


# -- TcpStack tests ---------------------------------------------------------


class TestTcpStack:
    """Test the TcpStack connection manager."""

    def test_open_connection(self) -> None:
        """Opening a connection returns an ID and SYN segment."""
        stack = TcpStack()
        conn_id, segments = stack.open_connection(
            client_port=CLIENT_PORT,
            server_port=SERVER_PORT,
        )
        assert conn_id >= 1
        assert len(segments) == 1
        assert segments[0].has_flag(TcpFlag.SYN)

    def test_listen(self) -> None:
        """Listening returns a listener ID."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)
        assert listener_id >= 1

    def test_listen_duplicate_port_raises(self) -> None:
        """Listening on an already-used port raises ValueError."""
        stack = TcpStack()
        stack.listen(port=SERVER_PORT)
        with pytest.raises(ValueError, match="already in use"):
            stack.listen(port=SERVER_PORT)

    def test_deliver_syn_creates_server_connection(self) -> None:
        """Delivering a SYN to a listener creates a server connection."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)
        syn = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.SYN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        responses = stack.deliver_segment(syn)
        assert len(responses) == 1
        assert responses[0].has_flag(TcpFlag.SYN)
        assert responses[0].has_flag(TcpFlag.ACK)

        # Server connection should be in accept queue
        server_id = stack.accept(listener_id=listener_id)
        assert server_id is not None

    def test_accept_empty_returns_none(self) -> None:
        """Accept with no pending connections returns None."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)
        assert stack.accept(listener_id=listener_id) is None

    def test_accept_unknown_listener_raises(self) -> None:
        """Accept on unknown listener raises KeyError."""
        stack = TcpStack()
        with pytest.raises(KeyError, match="not found"):
            stack.accept(listener_id=999)

    def test_full_handshake_via_stack(self) -> None:
        """Complete handshake through the stack."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)

        # Client sends SYN
        client_id, syn_segs = stack.open_connection(
            client_port=CLIENT_PORT,
            server_port=SERVER_PORT,
        )
        # Deliver SYN to server
        syn_ack_segs = stack.deliver_segment(syn_segs[0])
        # Deliver SYN+ACK to client
        ack_segs = stack.deliver_segment(syn_ack_segs[0])
        # Accept server-side connection
        server_id = stack.accept(listener_id=listener_id)
        assert server_id is not None
        # Deliver final ACK to server
        if ack_segs:
            stack.deliver_segment(ack_segs[0])

        client_info = stack.get_connection_info(client_id)
        assert client_info["state"] == str(TcpState.ESTABLISHED)

    def test_send_recv_via_stack(self) -> None:
        """Send and receive data through the stack."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)

        # Handshake
        client_id, syn_segs = stack.open_connection(
            client_port=CLIENT_PORT,
            server_port=SERVER_PORT,
        )
        syn_ack_segs = stack.deliver_segment(syn_segs[0])
        ack_segs = stack.deliver_segment(syn_ack_segs[0])
        server_id = stack.accept(listener_id=listener_id)
        assert server_id is not None
        if ack_segs:
            stack.deliver_segment(ack_segs[0])

        # Send data
        data_segs = stack.send(conn_id=client_id, data=b"hello")
        assert len(data_segs) >= 1

        # Deliver data to server
        for seg in data_segs:
            stack.deliver_segment(seg)

        # Receive on server
        received = stack.recv(conn_id=server_id)
        assert received == b"hello"

    def test_close_connection(self) -> None:
        """Closing a connection sends FIN."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)
        client_id, syn_segs = stack.open_connection(
            client_port=CLIENT_PORT,
            server_port=SERVER_PORT,
        )
        syn_ack_segs = stack.deliver_segment(syn_segs[0])
        stack.deliver_segment(syn_ack_segs[0])
        stack.accept(listener_id=listener_id)

        fin_segs = stack.close_connection(conn_id=client_id)
        assert len(fin_segs) == 1
        assert fin_segs[0].has_flag(TcpFlag.FIN)

    def test_close_listener(self) -> None:
        """Closing a listener returns empty segments."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)
        segs = stack.close_connection(conn_id=listener_id)
        assert segs == []

    def test_close_unknown_raises(self) -> None:
        """Closing unknown connection raises KeyError."""
        stack = TcpStack()
        with pytest.raises(KeyError, match="not found"):
            stack.close_connection(conn_id=999)

    def test_list_connections(self) -> None:
        """List connections shows all connections and listeners."""
        stack = TcpStack()
        stack.listen(port=SERVER_PORT)
        stack.open_connection(client_port=CLIENT_PORT, server_port=SERVER_PORT)
        connections = stack.list_connections()
        assert len(connections) >= 2  # noqa: PLR2004

    def test_tick_advances_all_connections(self) -> None:
        """Stack tick advances retransmission timers for all connections."""
        stack = TcpStack()
        stack.listen(port=SERVER_PORT)
        stack.open_connection(client_port=CLIENT_PORT, server_port=SERVER_PORT)
        # Should not raise
        retransmissions = stack.tick()
        assert isinstance(retransmissions, list)

    def test_get_connection_info_unknown_raises(self) -> None:
        """Getting info for unknown connection raises KeyError."""
        stack = TcpStack()
        with pytest.raises(KeyError, match="not found"):
            stack.get_connection_info(999)

    def test_send_unknown_raises(self) -> None:
        """Sending on unknown connection raises KeyError."""
        stack = TcpStack()
        with pytest.raises(KeyError, match="not found"):
            stack.send(conn_id=999, data=b"test")

    def test_recv_unknown_raises(self) -> None:
        """Receiving from unknown connection raises KeyError."""
        stack = TcpStack()
        with pytest.raises(KeyError, match="not found"):
            stack.recv(conn_id=999)

    def test_close_already_closed_connection(self) -> None:
        """Closing a CLOSED connection should remove it and return empty."""
        stack = TcpStack()
        listener_id = stack.listen(port=SERVER_PORT)
        client_id, syn_segs = stack.open_connection(
            client_port=CLIENT_PORT,
            server_port=SERVER_PORT,
        )
        syn_ack = stack.deliver_segment(syn_segs[0])
        stack.deliver_segment(syn_ack[0])
        stack.accept(listener_id=listener_id)
        # Force connection to CLOSED state
        conn = stack._connections[client_id]
        conn._state = TcpState.CLOSED
        result = stack.close_connection(conn_id=client_id)
        assert result == []

    def test_deliver_segment_no_match(self) -> None:
        """Delivering a segment to a port with no matching connection returns empty."""
        stack = TcpStack()
        unmatched = TcpSegment(
            src_port=9999,
            dst_port=8888,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.ACK}),
            window_size=0,
        )
        assert stack.deliver_segment(unmatched) == []


# -- Connection edge cases --------------------------------------------------


class TestConnectionEdgeCases:
    """Test TCP connection edge cases and state transitions."""

    def test_property_accessors(self) -> None:
        """Connection properties send_unacked, recv_next, recv_window are accessible."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        assert conn.send_unacked == INITIAL_SEQ_NUMBER
        assert conn.recv_next == 0
        assert conn.recv_window == DEFAULT_RECV_WINDOW

    def test_listen_ignores_non_syn(self) -> None:
        """LISTEN state ignores non-SYN segments."""
        server = TcpConnection(local_port=SERVER_PORT, remote_port=CLIENT_PORT)
        server.start_listen()
        ack = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.ACK}),
            window_size=0,
        )
        responses = server.process_segment(ack)
        assert responses == []
        assert server.state is TcpState.LISTEN

    def test_syn_sent_ignores_non_syn_ack(self) -> None:
        """SYN_SENT state ignores segments without both SYN and ACK."""
        client = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        client.initiate_open()
        ack_only = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.ACK}),
            window_size=0,
        )
        responses = client.process_segment(ack_only)
        assert responses == []
        assert client.state is TcpState.SYN_SENT

    def test_syn_received_ack_completes(self) -> None:
        """ACK in SYN_RECEIVED transitions to ESTABLISHED."""
        server = TcpConnection(local_port=SERVER_PORT, remote_port=CLIENT_PORT)
        server.start_listen()
        syn = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.SYN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        server.process_segment(syn)
        assert server.state is TcpState.SYN_RECEIVED
        ack = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=1,
            ack_number=1,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        server.process_segment(ack)
        assert server.state is TcpState.ESTABLISHED

    def test_close_wait_ignores_segments(self) -> None:
        """CLOSE_WAIT connection ignores incoming segments."""
        client, server = _established_pair()
        fin = client.initiate_close()
        server.process_segment(fin)
        assert server.state is TcpState.CLOSE_WAIT
        # Send another segment — should be ignored
        extra = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.ACK}),
            window_size=0,
        )
        responses = server.process_segment(extra)
        assert responses == []

    def test_close_wait_to_last_ack(self) -> None:
        """Initiating close from CLOSE_WAIT transitions to LAST_ACK."""
        client, server = _established_pair()
        fin = client.initiate_close()
        server.process_segment(fin)
        assert server.state is TcpState.CLOSE_WAIT
        server_fin = server.initiate_close()
        assert server.state is TcpState.LAST_ACK
        assert server_fin.has_flag(TcpFlag.FIN)

    def test_simultaneous_close(self) -> None:
        """Simultaneous close: FIN_WAIT_1 receives ACK+FIN → TIME_WAIT."""
        client, server = _established_pair()
        client_fin = client.initiate_close()
        assert client.state is TcpState.FIN_WAIT_1
        # Simulate simultaneous close: server also sends FIN
        server_fin = server.initiate_close()
        # Client receives server's FIN+ACK while in FIN_WAIT_1
        ack_fin = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=server.send_next - 1,
            ack_number=client.send_next,
            flags=frozenset({TcpFlag.ACK, TcpFlag.FIN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        responses = client.process_segment(ack_fin)
        assert client.state is TcpState.TIME_WAIT
        assert any(r.has_flag(TcpFlag.ACK) for r in responses)
        assert client_fin.has_flag(TcpFlag.FIN)  # use client_fin
        assert server_fin.has_flag(TcpFlag.FIN)  # use server_fin

    def test_fin_wait_1_receives_fin_only(self) -> None:
        """FIN without ACK in FIN_WAIT_1 enters CLOSING state."""
        client, _server = _established_pair()
        client.initiate_close()
        assert client.state is TcpState.FIN_WAIT_1
        fin_only = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=1,
            ack_number=0,
            flags=frozenset({TcpFlag.FIN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        responses = client.process_segment(fin_only)
        assert client.state is TcpState.CLOSING
        assert any(r.has_flag(TcpFlag.ACK) for r in responses)

    def test_fin_wait_2_ignores_non_fin(self) -> None:
        """FIN_WAIT_2 ignores segments without FIN flag."""
        client, server = _established_pair()
        fin = client.initiate_close()
        # Deliver FIN to server, get ACK back
        responses = server.process_segment(fin)
        for resp in responses:
            client.process_segment(resp)
        assert client.state is TcpState.FIN_WAIT_2
        # Send ACK-only — should be ignored
        ack = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=1,
            ack_number=client.send_next,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        responses = client.process_segment(ack)
        assert responses == []
        assert client.state is TcpState.FIN_WAIT_2

    def test_last_ack_receives_ack(self) -> None:
        """ACK in LAST_ACK transitions to CLOSED."""
        client, server = _established_pair()
        fin = client.initiate_close()
        server.process_segment(fin)
        server.initiate_close()
        assert server.state is TcpState.LAST_ACK
        final_ack = TcpSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq_number=client.send_next,
            ack_number=server.send_next,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        server.process_segment(final_ack)
        assert server.state is TcpState.CLOSED

    def test_closing_receives_ack(self) -> None:
        """ACK in CLOSING state transitions to TIME_WAIT."""
        client, _server = _established_pair()
        client.initiate_close()
        # Force into CLOSING state
        fin_only = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=1,
            ack_number=0,
            flags=frozenset({TcpFlag.FIN}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        client.process_segment(fin_only)
        assert client.state is TcpState.CLOSING
        # Now send ACK
        ack = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=2,
            ack_number=client.send_next,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        client.process_segment(ack)
        assert client.state is TcpState.TIME_WAIT

    def test_time_wait_ignores_segments(self) -> None:
        """TIME_WAIT connection ignores incoming segments."""
        conn = TcpConnection(local_port=CLIENT_PORT, remote_port=SERVER_PORT)
        conn._state = TcpState.TIME_WAIT
        seg = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=0,
            ack_number=0,
            flags=frozenset({TcpFlag.ACK}),
            window_size=0,
        )
        assert conn.process_segment(seg) == []

    def test_timeout_no_unacked_returns_empty(self) -> None:
        """Timeout with no unacked segments returns empty list."""
        client, _server = _established_pair()
        assert client.on_timeout() == []

    def test_congestion_avoidance_increment(self) -> None:
        """In congestion avoidance, cwnd increments by 1 after cwnd ACKs."""
        client, server = _established_pair()
        # Set cwnd = ssthresh to enter congestion avoidance
        client._cwnd = 2
        client._ssthresh = 2
        initial_cwnd = client.cwnd
        # Send data and get ACKed
        segments = client.send(b"data")
        ack1 = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=server.send_next,
            ack_number=client.send_next,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        client.process_segment(ack1)
        # First ACK → fractional increment (not enough for full +1)
        assert client.cwnd == initial_cwnd  # not yet incremented
        # Need cwnd more ACKs to increment — send more data
        segments = client.send(b"more")
        ack2 = TcpSegment(
            src_port=SERVER_PORT,
            dst_port=CLIENT_PORT,
            seq_number=server.send_next,
            ack_number=client.send_next,
            flags=frozenset({TcpFlag.ACK}),
            window_size=DEFAULT_RECV_WINDOW,
        )
        client.process_segment(ack2)
        # After 2 ACKs with cwnd=2, should increment
        expected_cwnd = initial_cwnd + 1
        assert client.cwnd == expected_cwnd
        assert len(segments) >= 1  # use segments var
