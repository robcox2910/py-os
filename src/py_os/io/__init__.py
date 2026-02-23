"""I/O subsystem — devices, IPC, and networking.

Re-exports public symbols so callers can write::

    from py_os.io import DeviceManager, Pipe

Note: Disk scheduling policies (FCFSPolicy, etc.) are NOT re-exported
here to avoid name collisions with scheduler policies.  Import them
directly from ``py_os.io.disk``.
"""

from py_os.io.devices import (
    ConsoleDevice,
    Device,
    DeviceManager,
    DeviceState,
    NullDevice,
    RandomDevice,
)
from py_os.io.dns import DnsError, DnsRecord, DnsResolver
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
from py_os.io.ipc import MessageQueue, Pipe
from py_os.io.networking import Socket, SocketError, SocketManager, SocketState
from py_os.io.shm import SharedMemoryError, SharedMemorySegment

__all__ = [
    "ConsoleDevice",
    "Device",
    "DeviceManager",
    "DeviceState",
    "DnsError",
    "DnsRecord",
    "DnsResolver",
    "HttpError",
    "HttpMethod",
    "HttpRequest",
    "HttpResponse",
    "HttpStatus",
    "MessageQueue",
    "NullDevice",
    "Pipe",
    "RandomDevice",
    "SharedMemoryError",
    "SharedMemorySegment",
    "Socket",
    "SocketError",
    "SocketManager",
    "SocketState",
    "format_request",
    "format_response",
    "parse_request",
    "parse_response",
    "status_reason",
]
