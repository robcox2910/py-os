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
from py_os.io.ipc import MessageQueue, Pipe
from py_os.io.networking import Socket, SocketManager, SocketState

__all__ = [
    "ConsoleDevice",
    "Device",
    "DeviceManager",
    "DeviceState",
    "MessageQueue",
    "NullDevice",
    "Pipe",
    "RandomDevice",
    "Socket",
    "SocketManager",
    "SocketState",
]
