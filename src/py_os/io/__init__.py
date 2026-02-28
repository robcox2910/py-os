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
from py_os.io.interrupts import (
    VECTOR_IO_BASE,
    VECTOR_TIMER,
    InterruptController,
    InterruptPriority,
    InterruptRequest,
    InterruptType,
    InterruptVector,
)
from py_os.io.ipc import MessageQueue, Pipe
from py_os.io.networking import Socket, SocketError, SocketManager, SocketState
from py_os.io.shm import SharedMemoryError, SharedMemorySegment
from py_os.io.tcp import TcpConnection, TcpFlag, TcpSegment, TcpStack, TcpState
from py_os.io.timer import TimerDevice

__all__ = [
    "VECTOR_IO_BASE",
    "VECTOR_TIMER",
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
    "InterruptController",
    "InterruptPriority",
    "InterruptRequest",
    "InterruptType",
    "InterruptVector",
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
    "TcpConnection",
    "TcpFlag",
    "TcpSegment",
    "TcpStack",
    "TcpState",
    "TimerDevice",
    "format_request",
    "format_response",
    "parse_request",
    "parse_response",
    "status_reason",
]
