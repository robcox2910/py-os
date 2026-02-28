"""Programmable interval timer — generates periodic interrupts.

In a real computer, the **timer** (or PIT — Programmable Interval Timer)
is a chip that ticks at a fixed rate and fires an interrupt every N
ticks.  The OS uses this to:

    1. **Preempt** processes — give each one a time slice, then switch.
    2. **Keep time** — track wall-clock time and schedule delayed work.
    3. **Drive retransmission** — networking protocols use timers for
       timeouts and retransmits.

Our timer implements the ``Device`` protocol so it appears in the
device manager alongside null, console, and random devices.  Its
``tick()`` method is called by ``kernel.tick()`` — each call advances
the counter by one.  When the counter reaches the configured interval,
the timer fires by raising VECTOR_TIMER on the interrupt controller.
"""

from contextlib import suppress

from py_os.io.devices import DeviceState
from py_os.io.interrupts import VECTOR_TIMER, InterruptController, InterruptPriority, InterruptType

DEFAULT_TIMER_INTERVAL = 5


class TimerDevice:
    """A programmable interval timer that fires interrupts.

    The timer counts ticks.  Every ``interval`` ticks it raises a
    VECTOR_TIMER interrupt on the interrupt controller and resets.
    """

    def __init__(
        self,
        controller: InterruptController,
        *,
        interval: int = DEFAULT_TIMER_INTERVAL,
    ) -> None:
        """Create a timer device and register its interrupt vector.

        Args:
            controller: The interrupt controller to raise IRQs on.
            interval: Number of ticks between timer fires.

        """
        self._controller = controller
        self._interval = interval
        self._counter = 0
        self._total_ticks = 0
        self._fires = 0

        # Register the timer vector if not already registered
        with suppress(ValueError):
            controller.register_vector(
                VECTOR_TIMER,
                interrupt_type=InterruptType.TIMER,
                priority=InterruptPriority.HIGH,
            )

    @property
    def name(self) -> str:
        """Return the device name."""
        return "timer"

    @property
    def status(self) -> DeviceState:
        """Return the device state (always READY)."""
        return DeviceState.READY

    @property
    def interval(self) -> int:
        """Return the current tick interval between fires."""
        return self._interval

    @interval.setter
    def interval(self, value: int) -> None:
        """Set the tick interval between fires.

        Args:
            value: New interval (must be > 0).

        Raises:
            ValueError: If the interval is not positive.

        """
        if value <= 0:
            msg = f"Interval must be positive, got {value}"
            raise ValueError(msg)
        self._interval = value

    @property
    def current_tick(self) -> int:
        """Return ticks since last fire (resets each interval)."""
        return self._counter

    @property
    def total_ticks(self) -> int:
        """Return total ticks since creation."""
        return self._total_ticks

    @property
    def fires(self) -> int:
        """Return total number of times the timer has fired."""
        return self._fires

    def tick(self) -> bool:
        """Advance the timer by one tick.

        If the counter reaches the interval, the timer fires: it
        raises a VECTOR_TIMER interrupt and resets the counter.

        Returns:
            True if the timer fired this tick, False otherwise.

        """
        self._counter += 1
        self._total_ticks += 1

        if self._counter >= self._interval:
            self._counter = 0
            self._fires += 1
            self._controller.raise_interrupt(VECTOR_TIMER)
            return True
        return False

    def read(self, **_kwargs: int) -> bytes:
        """Read timer status as bytes (Device protocol).

        Returns:
            UTF-8 encoded string with timer info.

        """
        return f"ticks={self._total_ticks} fires={self._fires} interval={self._interval}".encode()

    def write(self, data: bytes) -> None:
        """Write to the timer to set the interval (Device protocol).

        The data should be a UTF-8 string of an integer.

        Args:
            data: UTF-8 encoded integer for the new interval.

        Raises:
            ValueError: If the data is not a valid positive integer.

        """
        self.interval = int(data.decode().strip())
