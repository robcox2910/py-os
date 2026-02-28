"""Tests for the timer device."""

import pytest

from py_os.io.devices import DeviceState
from py_os.io.interrupts import (
    VECTOR_TIMER,
    InterruptController,
    InterruptPriority,
    InterruptRequest,
    InterruptType,
)
from py_os.io.timer import DEFAULT_TIMER_INTERVAL, TimerDevice

CUSTOM_INTERVAL = 10
NEW_INTERVAL = 3
EXPECTED_FIRES = 5
TOTAL_TICKS = 10


class TestTimerCreation:
    """Test timer device construction."""

    def test_default_interval(self) -> None:
        """Timer uses DEFAULT_TIMER_INTERVAL by default."""
        ic = InterruptController()
        timer = TimerDevice(ic)
        assert timer.interval == DEFAULT_TIMER_INTERVAL

    def test_custom_interval(self) -> None:
        """Timer accepts a custom interval."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=CUSTOM_INTERVAL)
        assert timer.interval == CUSTOM_INTERVAL

    def test_initial_state(self) -> None:
        """Timer starts with zero ticks and fires."""
        ic = InterruptController()
        timer = TimerDevice(ic)
        assert timer.current_tick == 0
        assert timer.total_ticks == 0
        assert timer.fires == 0

    def test_device_properties(self) -> None:
        """Timer satisfies the Device protocol properties."""
        ic = InterruptController()
        timer = TimerDevice(ic)
        assert timer.name == "timer"
        assert timer.status is DeviceState.READY


class TestTimerTick:
    """Test tick counting and interrupt firing."""

    def test_tick_increments_counter(self) -> None:
        """Each tick increments both counters."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=10)
        timer.tick()
        assert timer.current_tick == 1
        assert timer.total_ticks == 1

    def test_tick_returns_false_before_interval(self) -> None:
        """Tick returns False when the interval hasn't been reached."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=5)
        for _ in range(4):
            assert timer.tick() is False

    def test_tick_fires_at_interval(self) -> None:
        """Tick returns True and fires when counter reaches interval."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=3)
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)

        assert timer.tick() is False  # 1
        assert timer.tick() is False  # 2
        assert timer.tick() is True  # 3 — fire!
        assert timer.fires == 1
        assert timer.current_tick == 0  # reset

    def test_periodic_firing(self) -> None:
        """Timer fires repeatedly at the interval."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=2)
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)

        fire_ticks = [i + 1 for i in range(TOTAL_TICKS) if timer.tick()]

        assert fire_ticks == [2, 4, 6, 8, TOTAL_TICKS]
        assert timer.fires == EXPECTED_FIRES
        assert timer.total_ticks == TOTAL_TICKS

    def test_tick_raises_interrupt(self) -> None:
        """Tick raises a VECTOR_TIMER interrupt when it fires."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=1)
        received: list[InterruptRequest] = []
        ic.register_handler(VECTOR_TIMER, received.append)

        timer.tick()
        ic.service_pending()

        assert len(received) == 1
        assert received[0].vector == VECTOR_TIMER


class TestTimerInterval:
    """Test interval property and modification."""

    def test_set_interval(self) -> None:
        """Setting interval changes the fire period."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=5)
        timer.interval = NEW_INTERVAL
        assert timer.interval == NEW_INTERVAL

    def test_set_invalid_interval_raises(self) -> None:
        """Setting interval to zero or negative raises ValueError."""
        ic = InterruptController()
        timer = TimerDevice(ic)
        with pytest.raises(ValueError, match="positive"):
            timer.interval = 0
        with pytest.raises(ValueError, match="positive"):
            timer.interval = -1


class TestTimerDeviceProtocol:
    """Test Device protocol read/write methods."""

    def test_read_returns_status(self) -> None:
        """Read returns timer status as bytes."""
        ic = InterruptController()
        timer = TimerDevice(ic, interval=5)
        timer.tick()
        timer.tick()
        data = timer.read()
        assert b"ticks=2" in data
        assert b"fires=0" in data
        assert b"interval=5" in data

    def test_write_sets_interval(self) -> None:
        """Write sets the timer interval from bytes."""
        ic = InterruptController()
        timer = TimerDevice(ic)
        timer.write(b"10")
        assert timer.interval == CUSTOM_INTERVAL

    def test_write_invalid_raises(self) -> None:
        """Write with non-integer data raises ValueError."""
        ic = InterruptController()
        timer = TimerDevice(ic)
        with pytest.raises(ValueError, match="invalid literal"):
            timer.write(b"not-a-number")


class TestTimerWithExistingVector:
    """Test timer when VECTOR_TIMER is pre-registered."""

    def test_timer_with_preregistered_vector(self) -> None:
        """Timer handles a pre-registered VECTOR_TIMER gracefully."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        # This should not raise
        timer = TimerDevice(ic, interval=1)
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)
        assert timer.tick() is True
