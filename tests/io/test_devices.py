"""Tests for the device manager and device implementations.

Devices provide a uniform read/write interface to hardware resources.
The device manager registers and looks up devices by name, mirroring
how /dev works on Unix.
"""

import pytest

from py_os.io.devices import ConsoleDevice, DeviceManager, DeviceState, NullDevice, RandomDevice


class TestNullDevice:
    """Verify /dev/null behaviour — absorbs writes, reads empty."""

    def test_write_succeeds(self) -> None:
        """Writing to null should succeed silently."""
        dev = NullDevice()
        dev.write(b"anything")  # should not raise

    def test_read_returns_empty(self) -> None:
        """Reading from null should return empty bytes."""
        dev = NullDevice()
        assert dev.read() == b""

    def test_name(self) -> None:
        """The device name should be 'null'."""
        dev = NullDevice()
        assert dev.name == "null"

    def test_status_is_ready(self) -> None:
        """Null device is always ready."""
        dev = NullDevice()
        assert dev.status is DeviceState.READY


class TestConsoleDevice:
    """Verify console (terminal) buffer device."""

    def test_write_then_read(self) -> None:
        """Data written to console should be readable."""
        dev = ConsoleDevice()
        dev.write(b"hello")
        assert dev.read() == b"hello"

    def test_read_empty_returns_empty(self) -> None:
        """Reading with nothing in the buffer returns empty bytes."""
        dev = ConsoleDevice()
        assert dev.read() == b""

    def test_fifo_order(self) -> None:
        """Multiple writes should be read back in order."""
        dev = ConsoleDevice()
        dev.write(b"first")
        dev.write(b"second")
        assert dev.read() == b"first"
        assert dev.read() == b"second"

    def test_name(self) -> None:
        """The device name should be 'console'."""
        dev = ConsoleDevice()
        assert dev.name == "console"

    def test_status_is_ready(self) -> None:
        """Console device should be ready."""
        dev = ConsoleDevice()
        assert dev.status is DeviceState.READY


class TestRandomDevice:
    """Verify /dev/random — produces random bytes."""

    def test_read_returns_bytes(self) -> None:
        """Reading should return bytes of the requested size."""
        dev = RandomDevice()
        data = dev.read(size=16)
        expected_len = 16
        assert len(data) == expected_len

    def test_read_default_size(self) -> None:
        """Default read should return some bytes."""
        dev = RandomDevice()
        data = dev.read()
        assert len(data) > 0

    def test_reads_are_not_identical(self) -> None:
        """Two reads should (almost certainly) differ."""
        dev = RandomDevice()
        a = dev.read(size=32)
        b = dev.read(size=32)
        assert a != b

    def test_write_raises(self) -> None:
        """Writing to random should raise (read-only device)."""
        dev = RandomDevice()
        with pytest.raises(OSError, match="read-only"):
            dev.write(b"data")

    def test_name(self) -> None:
        """The device name should be 'random'."""
        dev = RandomDevice()
        assert dev.name == "random"


class TestDeviceManager:
    """Verify device registration and lookup."""

    def test_register_and_get(self) -> None:
        """A registered device should be retrievable by name."""
        mgr = DeviceManager()
        dev = NullDevice()
        mgr.register(dev)
        assert mgr.get("null") is dev

    def test_get_nonexistent_returns_none(self) -> None:
        """Getting a non-existent device should return None."""
        mgr = DeviceManager()
        assert mgr.get("nope") is None

    def test_register_duplicate_raises(self) -> None:
        """Registering a device with a duplicate name should raise."""
        mgr = DeviceManager()
        mgr.register(NullDevice())
        with pytest.raises(ValueError, match="already registered"):
            mgr.register(NullDevice())

    def test_list_devices(self) -> None:
        """All registered devices should be listable."""
        mgr = DeviceManager()
        mgr.register(NullDevice())
        mgr.register(ConsoleDevice())
        names = mgr.list_devices()
        assert "null" in names
        assert "console" in names

    def test_list_devices_empty(self) -> None:
        """An empty manager should return an empty list."""
        mgr = DeviceManager()
        assert mgr.list_devices() == []
