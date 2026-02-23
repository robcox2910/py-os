"""Tests for the HTTP simulation module.

HTTP (Hypertext Transfer Protocol) is like ordering food at a restaurant.
The customer (client) fills out an order form (request), the waiter (socket)
carries it to the kitchen (server), and the kitchen sends back a receipt
(response).  These tests verify the order forms, receipts, and the whole
restaurant workflow.
"""

import dataclasses

import pytest

from py_os.completer import Completer
from py_os.io.http import (
    HttpError,
    HttpMethod,
    HttpRequest,
    HttpResponse,
    HttpStatus,
    format_request,
    format_response,
    parse_request,
    parse_response,
    status_reason,
)
from py_os.io.networking import SocketError
from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# Magic-number constants for test assertions (PLR2004)
STATUS_OK = 200
STATUS_BAD_REQUEST = 400
STATUS_NOT_FOUND = 404
STATUS_INTERNAL_SERVER_ERROR = 500


# ---------------------------------------------------------------------------
# Cycle 1: HttpMethod, HttpStatus, HttpRequest, HttpResponse, HttpError
# ---------------------------------------------------------------------------


class TestHttpEnumsAndDataclasses:
    """Verify HTTP enums, frozen dataclasses, and the HttpError exception."""

    def test_http_method_values(self) -> None:
        """HttpMethod has GET and POST members with correct string values."""
        assert HttpMethod.GET == "GET"
        assert HttpMethod.POST == "POST"

    def test_http_status_values(self) -> None:
        """HttpStatus has correct integer values for common status codes."""
        assert HttpStatus.OK == STATUS_OK
        assert HttpStatus.BAD_REQUEST == STATUS_BAD_REQUEST
        assert HttpStatus.NOT_FOUND == STATUS_NOT_FOUND
        assert HttpStatus.INTERNAL_SERVER_ERROR == STATUS_INTERNAL_SERVER_ERROR

    def test_http_request_fields(self) -> None:
        """HttpRequest stores method, path, headers, and optional body."""
        req = HttpRequest(method=HttpMethod.GET, path="/index.html", headers={"Host": "localhost"})
        assert req.method is HttpMethod.GET
        assert req.path == "/index.html"
        assert req.headers == {"Host": "localhost"}
        assert req.body == b""

    def test_http_request_is_frozen(self) -> None:
        """HttpRequest is immutable."""
        req = HttpRequest(method=HttpMethod.GET, path="/", headers={})
        with pytest.raises(dataclasses.FrozenInstanceError):
            req.path = "/other"  # type: ignore[misc]

    def test_http_response_fields(self) -> None:
        """HttpResponse stores status, headers, and optional body."""
        resp = HttpResponse(
            status=HttpStatus.OK,
            headers={"Content-Length": "5"},
            body=b"hello",
        )
        assert resp.status is HttpStatus.OK
        assert resp.headers == {"Content-Length": "5"}
        assert resp.body == b"hello"

    def test_http_response_is_frozen(self) -> None:
        """HttpResponse is immutable."""
        resp = HttpResponse(status=HttpStatus.OK, headers={})
        with pytest.raises(dataclasses.FrozenInstanceError):
            resp.status = HttpStatus.NOT_FOUND  # type: ignore[misc]

    def test_http_error_is_exception(self) -> None:
        """HttpError is a standard Exception subclass."""
        err = HttpError("bad request")
        assert isinstance(err, Exception)
        assert str(err) == "bad request"

    def test_status_reason_phrases(self) -> None:
        """status_reason returns standard reason phrases."""
        assert status_reason(HttpStatus.OK) == "OK"
        assert status_reason(HttpStatus.BAD_REQUEST) == "Bad Request"
        assert status_reason(HttpStatus.NOT_FOUND) == "Not Found"
        assert status_reason(HttpStatus.INTERNAL_SERVER_ERROR) == "Internal Server Error"


# ---------------------------------------------------------------------------
# Cycle 2: format_request / parse_request
# ---------------------------------------------------------------------------


class TestFormatParseRequest:
    """Verify HTTP request serialization and parsing."""

    def test_format_get_request(self) -> None:
        """format_request produces correct wire format for a GET request."""
        req = HttpRequest(method=HttpMethod.GET, path="/index.html", headers={"Host": "localhost"})
        data = format_request(req)
        assert data == b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n"

    def test_parse_get_request(self) -> None:
        """parse_request reconstructs an HttpRequest from wire bytes."""
        raw = b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n"
        req = parse_request(raw)
        assert req.method is HttpMethod.GET
        assert req.path == "/index.html"
        assert req.headers["Host"] == "localhost"
        assert req.body == b""

    def test_format_post_with_body(self) -> None:
        """format_request includes Content-Length and body for POST."""
        req = HttpRequest(
            method=HttpMethod.POST,
            path="/data",
            headers={"Host": "localhost"},
            body=b"payload",
        )
        data = format_request(req)
        assert b"POST /data HTTP/1.0\r\n" in data
        assert b"Content-Length: 7\r\n" in data
        assert data.endswith(b"\r\n\r\npayload")

    def test_parse_post_with_body(self) -> None:
        """parse_request handles POST with Content-Length and body."""
        raw = b"POST /data HTTP/1.0\r\nHost: localhost\r\nContent-Length: 7\r\n\r\npayload"
        req = parse_request(raw)
        assert req.method is HttpMethod.POST
        assert req.path == "/data"
        assert req.body == b"payload"

    def test_malformed_request_raises(self) -> None:
        """parse_request raises HttpError for garbage input."""
        with pytest.raises(HttpError):
            parse_request(b"not a valid request")

    def test_roundtrip_request(self) -> None:
        """Format then parse produces an equivalent request."""
        original = HttpRequest(
            method=HttpMethod.GET,
            path="/test",
            headers={"Host": "example.com"},
        )
        reconstructed = parse_request(format_request(original))
        assert reconstructed.method == original.method
        assert reconstructed.path == original.path
        assert reconstructed.headers["Host"] == original.headers["Host"]


# ---------------------------------------------------------------------------
# Cycle 3: format_response / parse_response
# ---------------------------------------------------------------------------


class TestFormatParseResponse:
    """Verify HTTP response serialization and parsing."""

    def test_format_200_response(self) -> None:
        """format_response produces correct wire format for 200 OK."""
        resp = HttpResponse(
            status=HttpStatus.OK,
            headers={"Content-Type": "text/html"},
            body=b"<h1>Hello</h1>",
        )
        data = format_response(resp)
        assert data.startswith(b"HTTP/1.0 200 OK\r\n")
        assert b"Content-Type: text/html\r\n" in data
        assert b"Content-Length: 14\r\n" in data
        assert data.endswith(b"\r\n\r\n<h1>Hello</h1>")

    def test_format_404_response(self) -> None:
        """format_response produces correct wire format for 404 Not Found."""
        resp = HttpResponse(
            status=HttpStatus.NOT_FOUND,
            headers={},
            body=b"Not Found",
        )
        data = format_response(resp)
        assert data.startswith(b"HTTP/1.0 404 Not Found\r\n")

    def test_parse_response(self) -> None:
        """parse_response reconstructs an HttpResponse from wire bytes."""
        raw = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        resp = parse_response(raw)
        assert resp.status is HttpStatus.OK
        assert resp.body == b"hello"

    def test_malformed_response_raises(self) -> None:
        """parse_response raises HttpError for garbage input."""
        with pytest.raises(HttpError):
            parse_response(b"not a valid response")

    def test_roundtrip_response(self) -> None:
        """Format then parse produces an equivalent response."""
        original = HttpResponse(
            status=HttpStatus.OK,
            headers={"Content-Type": "text/plain"},
            body=b"body content",
        )
        reconstructed = parse_response(format_response(original))
        assert reconstructed.status == original.status
        assert reconstructed.body == original.body

    def test_empty_body_response(self) -> None:
        """format_response handles empty body correctly."""
        resp = HttpResponse(status=HttpStatus.NOT_FOUND, headers={})
        data = format_response(resp)
        assert b"Content-Length: 0\r\n" in data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_INITIAL_SOCKET_COUNT = 0
EXPECTED_SINGLE_SOCKET = 1
EXPECTED_THREE_SOCKETS = 3
HTTP_DEMO_PORT = 80


def _booted_kernel() -> Kernel:
    """Return a booted kernel for integration tests."""
    k = Kernel()
    k.boot()
    return k


# ---------------------------------------------------------------------------
# Cycle 4: Kernel socket integration
# ---------------------------------------------------------------------------


class TestKernelSockets:
    """Verify kernel-level socket management methods."""

    def test_boot_creates_socket_manager(self) -> None:
        """Booting the kernel creates a SocketManager."""
        k = _booted_kernel()
        assert k.socket_manager is not None
        k.shutdown()

    def test_shutdown_clears_socket_manager(self) -> None:
        """Shutdown sets socket_manager to None."""
        k = _booted_kernel()
        k.shutdown()
        assert k.socket_manager is None

    def test_socket_create_and_list(self) -> None:
        """socket_create returns an info dict, socket_list shows it."""
        k = _booted_kernel()
        info = k.socket_create()
        assert "sock_id" in info
        assert "state" in info
        sockets = k.socket_list()
        assert len(sockets) >= EXPECTED_SINGLE_SOCKET
        k.shutdown()

    def test_full_socket_lifecycle(self) -> None:
        """Create, bind, listen, connect, accept, send, recv, close."""
        k = _booted_kernel()

        # Server side
        server = k.socket_create()
        sid = server["sock_id"]
        assert isinstance(sid, int)
        k.socket_bind(sid, "localhost", HTTP_DEMO_PORT)
        k.socket_listen(sid)

        # Client side
        client = k.socket_create()
        cid = client["sock_id"]
        assert isinstance(cid, int)
        k.socket_connect(cid, "localhost", HTTP_DEMO_PORT)

        # Accept connection
        peer = k.socket_accept(sid)
        assert peer is not None
        peer_id = peer["sock_id"]
        assert isinstance(peer_id, int)

        # Send/recv
        k.socket_send(cid, b"hello")
        data = k.socket_recv(peer_id)
        assert data == b"hello"

        # Close
        k.socket_close(cid)
        k.socket_close(peer_id)
        k.socket_close(sid)

        k.shutdown()

    def test_invalid_socket_id_raises(self) -> None:
        """Operating on a nonexistent socket raises SocketError."""
        k = _booted_kernel()
        invalid_id = 9999
        with pytest.raises(SocketError, match="not found"):
            k.socket_bind(invalid_id, "localhost", HTTP_DEMO_PORT)
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 5: Socket syscalls
# ---------------------------------------------------------------------------


class TestSocketSyscalls:
    """Verify socket syscall wrappers."""

    def test_create_syscall(self) -> None:
        """SYS_SOCKET_CREATE returns a dict with sock_id."""
        k = _booted_kernel()
        result = k.syscall(SyscallNumber.SYS_SOCKET_CREATE)
        assert "sock_id" in result
        assert isinstance(result["sock_id"], int)
        k.shutdown()

    def test_full_roundtrip_via_syscalls(self) -> None:
        """End-to-end socket communication through syscalls."""
        k = _booted_kernel()

        # Server
        srv = k.syscall(SyscallNumber.SYS_SOCKET_CREATE)
        sid = srv["sock_id"]
        k.syscall(
            SyscallNumber.SYS_SOCKET_BIND, sock_id=sid, address="127.0.0.1", port=HTTP_DEMO_PORT
        )
        k.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=sid)

        # Client
        cli = k.syscall(SyscallNumber.SYS_SOCKET_CREATE)
        cid = cli["sock_id"]
        k.syscall(
            SyscallNumber.SYS_SOCKET_CONNECT, sock_id=cid, address="127.0.0.1", port=HTTP_DEMO_PORT
        )

        # Accept
        peer = k.syscall(SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=sid)
        assert peer is not None
        pid = peer["sock_id"]

        # Data exchange
        k.syscall(SyscallNumber.SYS_SOCKET_SEND, sock_id=cid, data=b"ping")
        result = k.syscall(SyscallNumber.SYS_SOCKET_RECV, sock_id=pid)
        assert result == b"ping"

        # Cleanup
        k.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=cid)
        k.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=pid)
        k.syscall(SyscallNumber.SYS_SOCKET_CLOSE, sock_id=sid)
        k.shutdown()

    def test_list_syscall(self) -> None:
        """SYS_SOCKET_LIST returns all sockets."""
        k = _booted_kernel()
        k.syscall(SyscallNumber.SYS_SOCKET_CREATE)
        k.syscall(SyscallNumber.SYS_SOCKET_CREATE)
        sockets = k.syscall(SyscallNumber.SYS_SOCKET_LIST)
        assert len(sockets) >= 2  # noqa: PLR2004
        k.shutdown()

    def test_error_wrapping(self) -> None:
        """Socket errors are wrapped in SyscallError."""
        k = _booted_kernel()
        invalid_id = 9999
        with pytest.raises(SyscallError, match="not found"):
            k.syscall(SyscallNumber.SYS_SOCKET_BIND, sock_id=invalid_id, address="x", port=1)
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 6: Shell commands (socket + http)
# ---------------------------------------------------------------------------


class TestShellCommands:
    """Verify socket and http shell commands."""

    def test_socket_create_and_list(self) -> None:
        """'socket create' and 'socket list' produce expected output."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("socket create")
        assert "Socket" in result
        result = sh.execute("socket list")
        assert "created" in result.lower() or "ID" in result
        k.shutdown()

    def test_socket_bad_subcommand(self) -> None:
        """'socket badcmd' returns usage info."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("socket badcmd")
        assert "Usage" in result or "usage" in result.lower()
        k.shutdown()

    def test_http_demo_runs(self) -> None:
        """'http demo' runs without error and mentions HTTP concepts."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("http demo")
        assert "HTTP" in result
        assert "200" in result or "OK" in result
        assert "404" in result or "Not Found" in result
        k.shutdown()

    def test_http_bad_subcommand(self) -> None:
        """'http badcmd' returns usage info."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        result = sh.execute("http badcmd")
        assert "Usage" in result or "usage" in result.lower()
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 7: Completer
# ---------------------------------------------------------------------------


class TestCompleter:
    """Verify tab completion for socket and http commands."""

    def test_socket_subcommand_completion(self) -> None:
        """Typing 'socket ' and pressing tab offers subcommands."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        comp = Completer(sh)
        candidates = comp.completions("cr", "socket cr")
        assert "create" in candidates
        k.shutdown()

    def test_http_subcommand_completion(self) -> None:
        """Typing 'http ' and pressing tab offers 'demo'."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        comp = Completer(sh)
        candidates = comp.completions("", "http ")
        assert "demo" in candidates
        k.shutdown()
