"""Interrupt controller — hardware event dispatching.

In a real computer, **interrupts** are signals from hardware devices
that tell the CPU: "Stop what you're doing — something needs attention!"
Think of them as doorbells: each device has its own bell (vector number),
and when it rings the CPU looks up a handler function to run.

Key concepts:
    - **Vector** — a numbered slot in the interrupt table.  Each device
      is assigned a unique vector.  The CPU uses the vector to find the
      right handler.
    - **IRQ (Interrupt Request)** — a pending interrupt waiting to be
      serviced.  Hardware raises an IRQ; the controller queues it.
    - **Masking** — disabling a specific vector so its IRQs are held
      (but not lost) until unmasked.  Like putting your doorbell on
      silent — the visitors still queue at the door.
    - **Priority** — when multiple IRQs are pending at once, the
      controller services the highest-priority one first.

Our simulation mirrors a simplified programmable interrupt controller
(PIC).  It doesn't actually preempt Python code — instead, the kernel
calls ``service_pending()`` at each tick to process queued IRQs.
"""

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class InterruptType(StrEnum):
    """Classify interrupts by source."""

    TIMER = "timer"
    IO = "io"
    SOFTWARE = "software"


class InterruptPriority(IntEnum):
    """Priority levels for interrupts (higher number = higher priority)."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


# Well-known vector numbers — like IRQ lines on a real PIC
VECTOR_TIMER = 0
VECTOR_IO_BASE = 16


@dataclass(frozen=True)
class InterruptVector:
    """A slot in the interrupt descriptor table.

    Each vector maps a number to a type and priority.  Handlers are
    registered separately so vectors can exist before handlers are
    attached.
    """

    number: int
    interrupt_type: InterruptType
    priority: InterruptPriority


@dataclass(frozen=True)
class InterruptRequest:
    """A pending interrupt waiting to be serviced.

    When hardware raises an interrupt, an IRQ is created and queued.
    The controller processes them in priority order.
    """

    vector: int
    data: object = None


@dataclass
class _VectorEntry:
    """Internal bookkeeping for a registered vector."""

    vector: InterruptVector
    handler: Callable[[InterruptRequest], None] | None = None
    masked: bool = False
    pending: deque[InterruptRequest] = field(
        default_factory=lambda: deque[InterruptRequest](),
    )


class InterruptController:
    """Manage interrupt vectors, handlers, and pending IRQs.

    The controller is the central hub for all hardware interrupts.
    Devices raise IRQs, the controller queues them, and
    ``service_pending()`` dispatches them to registered handlers.
    """

    def __init__(self) -> None:
        """Create an interrupt controller with no registered vectors."""
        self._vectors: dict[int, _VectorEntry] = {}
        self._total_serviced: int = 0

    @property
    def total_serviced(self) -> int:
        """Return the total number of interrupts serviced."""
        return self._total_serviced

    def register_vector(
        self,
        vector: int,
        *,
        interrupt_type: InterruptType,
        priority: InterruptPriority,
    ) -> InterruptVector:
        """Register an interrupt vector in the descriptor table.

        Args:
            vector: The vector number (must be unique).
            interrupt_type: Classification of this interrupt.
            priority: How urgently this interrupt should be serviced.

        Returns:
            The newly registered InterruptVector.

        Raises:
            ValueError: If the vector number is already registered.

        """
        if vector in self._vectors:
            msg = f"Vector {vector} already registered"
            raise ValueError(msg)
        iv = InterruptVector(
            number=vector,
            interrupt_type=interrupt_type,
            priority=priority,
        )
        self._vectors[vector] = _VectorEntry(vector=iv)
        return iv

    def register_handler(
        self,
        vector: int,
        handler: Callable[[InterruptRequest], None],
    ) -> None:
        """Attach a handler function to an interrupt vector.

        The handler is called each time an IRQ on this vector is
        serviced.  Only one handler per vector — a new registration
        replaces the previous one.

        Args:
            vector: The vector number.
            handler: Callable that receives an InterruptRequest.

        Raises:
            KeyError: If the vector is not registered.

        """
        entry = self._vectors.get(vector)
        if entry is None:
            msg = f"Vector {vector} not registered"
            raise KeyError(msg)
        entry.handler = handler

    def raise_interrupt(self, vector: int, *, data: object = None) -> None:
        """Queue an interrupt request on the given vector.

        This is what hardware does when it needs attention — it raises
        an IRQ.  The request is queued and processed on the next call
        to ``service_pending()``.

        Args:
            vector: The vector number.
            data: Optional data payload for the handler.

        Raises:
            KeyError: If the vector is not registered.

        """
        entry = self._vectors.get(vector)
        if entry is None:
            msg = f"Vector {vector} not registered"
            raise KeyError(msg)
        entry.pending.append(InterruptRequest(vector=vector, data=data))

    def service_pending(self) -> int:
        """Process all unmasked pending IRQs in priority order.

        Iterates through vectors sorted by priority (highest first).
        For each unmasked vector with pending IRQs, calls the handler.
        Masked vectors keep their IRQs queued for later.

        Returns:
            The number of interrupts serviced in this call.

        """
        serviced = 0
        # Sort by priority descending — highest priority serviced first
        sorted_entries = sorted(
            self._vectors.values(),
            key=lambda e: e.vector.priority,
            reverse=True,
        )
        for entry in sorted_entries:
            if entry.masked or entry.handler is None:
                continue
            while entry.pending:
                irq = entry.pending.popleft()
                entry.handler(irq)
                serviced += 1
                self._total_serviced += 1
        return serviced

    def mask(self, vector: int) -> None:
        """Disable (mask) an interrupt vector.

        Masked vectors accumulate pending IRQs but don't service them
        until unmasked.

        Args:
            vector: The vector number to mask.

        Raises:
            KeyError: If the vector is not registered.

        """
        entry = self._vectors.get(vector)
        if entry is None:
            msg = f"Vector {vector} not registered"
            raise KeyError(msg)
        entry.masked = True

    def unmask(self, vector: int) -> None:
        """Re-enable (unmask) an interrupt vector.

        Args:
            vector: The vector number to unmask.

        Raises:
            KeyError: If the vector is not registered.

        """
        entry = self._vectors.get(vector)
        if entry is None:
            msg = f"Vector {vector} not registered"
            raise KeyError(msg)
        entry.masked = False

    def is_masked(self, vector: int) -> bool:
        """Return whether a vector is currently masked.

        Args:
            vector: The vector number.

        Raises:
            KeyError: If the vector is not registered.

        """
        entry = self._vectors.get(vector)
        if entry is None:
            msg = f"Vector {vector} not registered"
            raise KeyError(msg)
        return entry.masked

    def pending_count(self, vector: int) -> int:
        """Return the number of pending IRQs on a vector.

        Args:
            vector: The vector number.

        Raises:
            KeyError: If the vector is not registered.

        """
        entry = self._vectors.get(vector)
        if entry is None:
            msg = f"Vector {vector} not registered"
            raise KeyError(msg)
        return len(entry.pending)

    def list_vectors(self) -> list[dict[str, object]]:
        """Return info about all registered vectors.

        Returns:
            List of dicts with vector details.

        """
        return [
            {
                "vector": e.vector.number,
                "type": str(e.vector.interrupt_type),
                "priority": int(e.vector.priority),
                "masked": e.masked,
                "pending": len(e.pending),
                "has_handler": e.handler is not None,
            }
            for e in sorted(self._vectors.values(), key=lambda e: e.vector.number)
        ]
