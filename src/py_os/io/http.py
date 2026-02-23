r"""Simulated HTTP/1.0 — request/response protocol on top of sockets.

In real operating systems, HTTP is an **application-layer protocol** that
runs on top of TCP sockets.  The kernel owns sockets (transport), but HTTP
lives in user-space — just like a web browser or web server is a regular
program, not part of the kernel.

HTTP is a **request/response** protocol:

    Client sends:   GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n
    Server replies:  HTTP/1.0 200 OK\r\nContent-Length: 42\r\n\r\n<body>

Key concepts:
    - **Method** — what the client wants (GET = "give me this", POST = "here's data").
    - **Status code** — server's answer (200 = OK, 404 = not found, etc.).
    - **Headers** — metadata key-value pairs (Host, Content-Length, Content-Type).
    - **Body** — optional payload (the actual content being sent/received).

Our simulation uses pure functions for formatting and parsing.  This mirrors
the real-world split: the kernel provides sockets, user-space code builds
HTTP on top.
"""

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class HttpError(Exception):
    """Raise when an HTTP operation fails."""


class HttpMethod(StrEnum):
    """HTTP request methods.

    GET asks the server for a resource.  POST sends data to the server.
    """

    GET = "GET"
    POST = "POST"


class HttpStatus(IntEnum):
    """HTTP response status codes.

    Each code tells the client what happened:
    - 200 OK — success, here's your data.
    - 400 Bad Request — the request was malformed.
    - 404 Not Found — the requested resource doesn't exist.
    - 500 Internal Server Error — something went wrong on the server.
    """

    OK = 200
    BAD_REQUEST = 400
    NOT_FOUND = 404
    INTERNAL_SERVER_ERROR = 500


_REASON_PHRASES: dict[HttpStatus, str] = {
    HttpStatus.OK: "OK",
    HttpStatus.BAD_REQUEST: "Bad Request",
    HttpStatus.NOT_FOUND: "Not Found",
    HttpStatus.INTERNAL_SERVER_ERROR: "Internal Server Error",
}


def status_reason(status: HttpStatus) -> str:
    """Return the standard reason phrase for a status code."""
    return _REASON_PHRASES[status]


def _empty_headers() -> dict[str, str]:
    """Return an empty headers dict (typed factory for dataclass fields)."""
    return {}


@dataclass(frozen=True)
class HttpRequest:
    """An HTTP request — the order form a client sends to a server.

    Attributes:
        method: GET or POST.
        path: The resource being requested (e.g. "/index.html").
        headers: Key-value metadata pairs.
        body: Optional payload bytes (default empty).

    """

    method: HttpMethod
    path: str
    headers: dict[str, str] = field(default_factory=_empty_headers)
    body: bytes = b""


@dataclass(frozen=True)
class HttpResponse:
    """An HTTP response — the receipt a server sends back to a client.

    Attributes:
        status: Status code (200, 404, etc.).
        headers: Key-value metadata pairs.
        body: Optional payload bytes (default empty).

    """

    status: HttpStatus
    headers: dict[str, str] = field(default_factory=_empty_headers)
    body: bytes = b""


# ---------------------------------------------------------------------------
# Serialization — Python objects → wire-format bytes
# ---------------------------------------------------------------------------

_CRLF = b"\r\n"
_HTTP_VERSION = b"HTTP/1.0"
_MIN_REQUEST_LINE_PARTS = 3
_MIN_STATUS_LINE_PARTS = 3


def format_request(request: HttpRequest) -> bytes:
    r"""Serialize an HttpRequest to wire-format bytes.

    Wire format::

        METHOD /path HTTP/1.0\r\n
        Header-Name: value\r\n
        ...\r\n
        \r\n
        [body]
    """
    parts: list[bytes] = []

    # Request line
    parts.append(f"{request.method} {request.path} HTTP/1.0".encode())
    parts.append(_CRLF)

    # Headers
    headers = dict(request.headers)
    if request.body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(request.body))

    for name, value in headers.items():
        parts.append(f"{name}: {value}".encode())
        parts.append(_CRLF)

    # Blank line separates headers from body
    parts.append(_CRLF)

    # Body
    if request.body:
        parts.append(request.body)

    return b"".join(parts)


def parse_request(data: bytes) -> HttpRequest:
    """Parse raw bytes into an HttpRequest.

    Raises:
        HttpError: If the data is malformed.

    """
    try:
        # Split headers from body
        header_end = data.index(b"\r\n\r\n")
        header_section = data[:header_end]
        body = data[header_end + 4 :]

        lines = header_section.split(b"\r\n")
        request_line = lines[0].decode()
        parts = request_line.split(" ", maxsplit=2)
        if len(parts) < _MIN_REQUEST_LINE_PARTS:
            msg = f"Malformed request line: {request_line}"
            raise HttpError(msg)

        method = HttpMethod(parts[0])
        path = parts[1]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            decoded = line.decode()
            colon = decoded.index(":")
            name = decoded[:colon].strip()
            value = decoded[colon + 1 :].strip()
            headers[name] = value

        return HttpRequest(method=method, path=path, headers=headers, body=body)
    except HttpError:
        raise
    except Exception as e:
        msg = f"Failed to parse HTTP request: {e}"
        raise HttpError(msg) from e


def format_response(response: HttpResponse) -> bytes:
    r"""Serialize an HttpResponse to wire-format bytes.

    Wire format::

        HTTP/1.0 200 OK\r\n
        Header-Name: value\r\n
        Content-Length: N\r\n
        ...\r\n
        \r\n
        [body]
    """
    parts: list[bytes] = []

    # Status line
    reason = status_reason(response.status)
    parts.append(f"HTTP/1.0 {response.status} {reason}".encode())
    parts.append(_CRLF)

    # Headers
    headers = dict(response.headers)
    headers["Content-Length"] = str(len(response.body))

    for name, value in headers.items():
        parts.append(f"{name}: {value}".encode())
        parts.append(_CRLF)

    # Blank line separates headers from body
    parts.append(_CRLF)

    # Body
    if response.body:
        parts.append(response.body)

    return b"".join(parts)


def parse_response(data: bytes) -> HttpResponse:
    """Parse raw bytes into an HttpResponse.

    Raises:
        HttpError: If the data is malformed.

    """
    try:
        # Split headers from body
        header_end = data.index(b"\r\n\r\n")
        header_section = data[:header_end]
        body = data[header_end + 4 :]

        lines = header_section.split(b"\r\n")
        status_line = lines[0].decode()
        parts = status_line.split(" ", maxsplit=2)
        if len(parts) < _MIN_STATUS_LINE_PARTS:
            msg = f"Malformed status line: {status_line}"
            raise HttpError(msg)

        status = HttpStatus(int(parts[1]))

        headers: dict[str, str] = {}
        for line in lines[1:]:
            decoded = line.decode()
            colon = decoded.index(":")
            name = decoded[:colon].strip()
            value = decoded[colon + 1 :].strip()
            headers[name] = value

        return HttpResponse(status=status, headers=headers, body=body)
    except HttpError:
        raise
    except Exception as e:
        msg = f"Failed to parse HTTP response: {e}"
        raise HttpError(msg) from e
