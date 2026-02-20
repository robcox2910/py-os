"""Device manager and device implementations.

In Unix, **everything is a file** — hardware devices are accessed
through the same ``read()``/``write()`` interface as regular files.
The ``/dev`` directory contains special files that map to devices:
``/dev/null`` (black hole), ``/dev/random`` (random bytes),
``/dev/tty`` (terminal), etc.

This module provides:

**Device** (Protocol) — the interface every device must implement.
    ``name``: unique identifier (like the filename in ``/dev``).
    ``read()``: produce bytes from the device.
    ``write()``: send bytes to the device.
    ``status``: the device's current state.

**DeviceManager** — a registry that tracks named devices, like the
    kernel's device table.  Register a device, look it up by name.

**Concrete devices**:
    - ``NullDevice``: absorbs writes, reads return empty (``/dev/null``).
    - ``ConsoleDevice``: buffered terminal I/O (``/dev/console``).
    - ``RandomDevice``: produces random bytes (``/dev/random``).

Why a Protocol instead of an ABC?
    Structural typing — any class that has the right methods is a
    valid device, without needing to inherit from a base class.
    This matches Python's duck-typing philosophy.
"""

from collections import deque
from enum import StrEnum
from os import urandom
from typing import Protocol


class DeviceState(StrEnum):
    """The operational state of a device."""

    READY = "ready"
    BUSY = "busy"
    OFFLINE = "offline"


DEFAULT_RANDOM_SIZE = 32


class Device(Protocol):
    """Interface that every device must satisfy."""

    @property
    def name(self) -> str:
        """Return the device name (unique identifier)."""
        ...  # pragma: no cover

    @property
    def status(self) -> DeviceState:
        """Return the current device state."""
        ...  # pragma: no cover

    def read(self, **kwargs: int) -> bytes:
        """Read bytes from the device."""
        ...  # pragma: no cover

    def write(self, data: bytes) -> None:
        """Write bytes to the device."""
        ...  # pragma: no cover


class NullDevice:
    """The black hole — absorbs all writes, reads return empty.

    This is ``/dev/null``.  Useful for discarding output or as a
    no-op data sink.  Always ready, never fails.
    """

    @property
    def name(self) -> str:
        """Return 'null'."""
        return "null"

    @property
    def status(self) -> DeviceState:
        """Null device is always ready."""
        return DeviceState.READY

    def read(self, **_kwargs: int) -> bytes:
        """Return empty bytes (nothing to read)."""
        return b""

    def write(self, data: bytes) -> None:
        """Absorb data silently (black hole)."""


class ConsoleDevice:
    """Buffered terminal I/O device.

    Models ``/dev/console`` — a FIFO buffer where writes enqueue
    data and reads dequeue it.  In a real OS this would be backed
    by a UART or framebuffer driver.
    """

    def __init__(self) -> None:
        """Create a console with an empty buffer."""
        self._buffer: deque[bytes] = deque()

    @property
    def name(self) -> str:
        """Return 'console'."""
        return "console"

    @property
    def status(self) -> DeviceState:
        """Console is always ready."""
        return DeviceState.READY

    def read(self, **_kwargs: int) -> bytes:
        """Read the next chunk from the buffer, or empty if none."""
        if not self._buffer:
            return b""
        return self._buffer.popleft()

    def write(self, data: bytes) -> None:
        """Write data to the console buffer."""
        self._buffer.append(data)


class RandomDevice:
    """Random byte generator — ``/dev/random``.

    Produces cryptographically random bytes using ``os.urandom()``.
    Read-only: writing raises ``OSError``.
    """

    @property
    def name(self) -> str:
        """Return 'random'."""
        return "random"

    @property
    def status(self) -> DeviceState:
        """Random device is always ready."""
        return DeviceState.READY

    def read(self, *, size: int = DEFAULT_RANDOM_SIZE) -> bytes:
        """Return ``size`` random bytes."""
        return urandom(size)

    def write(self, _data: bytes) -> None:
        """Raise — random is a read-only device."""
        msg = "Cannot write to read-only device 'random'"
        raise OSError(msg)


class DeviceManager:
    """Registry of named devices — the kernel's device table.

    Devices are registered by name and looked up by name, mirroring
    how ``/dev`` entries map to drivers in a real kernel.
    """

    def __init__(self) -> None:
        """Create an empty device registry."""
        self._devices: dict[str, Device] = {}

    def register(self, device: Device) -> None:
        """Register a device.

        Args:
            device: The device to register.

        Raises:
            ValueError: If a device with the same name is already registered.

        """
        if device.name in self._devices:
            msg = f"Device '{device.name}' already registered"
            raise ValueError(msg)
        self._devices[device.name] = device

    def get(self, name: str) -> Device | None:
        """Look up a device by name.

        Returns:
            The device, or None if not found.

        """
        return self._devices.get(name)

    def list_devices(self) -> list[str]:
        """Return the names of all registered devices."""
        return list(self._devices.keys())
