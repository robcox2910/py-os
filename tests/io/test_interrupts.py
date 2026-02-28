"""Tests for the interrupt controller."""

import pytest

from py_os.io.interrupts import (
    VECTOR_IO_BASE,
    VECTOR_TIMER,
    InterruptController,
    InterruptPriority,
    InterruptRequest,
    InterruptType,
)

EXPECTED_VECTOR_COUNT = 2
EXPECTED_PENDING = 2
EXPECTED_SERVICED = 3


class TestInterruptVector:
    """Test interrupt vector registration."""

    def test_register_vector(self) -> None:
        """Register a vector and verify its properties."""
        ic = InterruptController()
        vec = ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        assert vec.number == VECTOR_TIMER
        assert vec.interrupt_type is InterruptType.TIMER
        assert vec.priority is InterruptPriority.HIGH

    def test_register_duplicate_vector_raises(self) -> None:
        """Registering the same vector twice raises ValueError."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        with pytest.raises(ValueError, match="already registered"):
            ic.register_vector(
                VECTOR_TIMER,
                interrupt_type=InterruptType.TIMER,
                priority=InterruptPriority.HIGH,
            )

    def test_register_multiple_vectors(self) -> None:
        """Register multiple vectors with different numbers."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        ic.register_vector(
            VECTOR_IO_BASE,
            interrupt_type=InterruptType.IO,
            priority=InterruptPriority.NORMAL,
        )
        vectors = ic.list_vectors()
        assert len(vectors) == EXPECTED_VECTOR_COUNT


class TestInterruptHandler:
    """Test handler registration and dispatch."""

    def test_register_handler(self) -> None:
        """Register a handler and verify it gets called."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        received: list[InterruptRequest] = []
        ic.register_handler(VECTOR_TIMER, received.append)

        ic.raise_interrupt(VECTOR_TIMER)
        serviced = ic.service_pending()

        assert serviced == 1
        assert len(received) == 1
        assert received[0].vector == VECTOR_TIMER

    def test_handler_not_registered_raises(self) -> None:
        """Registering a handler for an unknown vector raises KeyError."""
        ic = InterruptController()
        with pytest.raises(KeyError, match="not registered"):
            ic.register_handler(999, lambda _irq: None)

    def test_handler_replaces_previous(self) -> None:
        """A new handler replaces the old one."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        first_calls: list[InterruptRequest] = []
        second_calls: list[InterruptRequest] = []

        ic.register_handler(VECTOR_TIMER, first_calls.append)
        ic.register_handler(VECTOR_TIMER, second_calls.append)

        ic.raise_interrupt(VECTOR_TIMER)
        ic.service_pending()

        assert len(first_calls) == 0
        assert len(second_calls) == 1


class TestRaiseInterrupt:
    """Test raising interrupts."""

    def test_raise_unknown_vector_raises(self) -> None:
        """Raising an interrupt on an unknown vector raises KeyError."""
        ic = InterruptController()
        with pytest.raises(KeyError, match="not registered"):
            ic.raise_interrupt(999)

    def test_raise_with_data(self) -> None:
        """Interrupt data is passed through to the handler."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_IO_BASE,
            interrupt_type=InterruptType.IO,
            priority=InterruptPriority.NORMAL,
        )
        received: list[InterruptRequest] = []
        ic.register_handler(VECTOR_IO_BASE, received.append)

        ic.raise_interrupt(VECTOR_IO_BASE, data={"device": "disk0"})
        ic.service_pending()

        assert received[0].data == {"device": "disk0"}

    def test_pending_count(self) -> None:
        """Pending count reflects queued IRQs."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)

        assert ic.pending_count(VECTOR_TIMER) == 0
        ic.raise_interrupt(VECTOR_TIMER)
        assert ic.pending_count(VECTOR_TIMER) == 1
        ic.raise_interrupt(VECTOR_TIMER)
        assert ic.pending_count(VECTOR_TIMER) == EXPECTED_PENDING

        ic.service_pending()
        assert ic.pending_count(VECTOR_TIMER) == 0

    def test_pending_count_unknown_vector_raises(self) -> None:
        """Querying pending count on an unknown vector raises KeyError."""
        ic = InterruptController()
        with pytest.raises(KeyError, match="not registered"):
            ic.pending_count(999)


class TestServicePending:
    """Test interrupt servicing."""

    def test_service_no_pending(self) -> None:
        """Service returns 0 when nothing is pending."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        assert ic.service_pending() == 0

    def test_service_multiple_pending(self) -> None:
        """Service all pending IRQs in one call."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        count = 0

        def _count(_irq: InterruptRequest) -> None:
            nonlocal count
            count += 1

        ic.register_handler(VECTOR_TIMER, _count)
        ic.raise_interrupt(VECTOR_TIMER)
        ic.raise_interrupt(VECTOR_TIMER)
        ic.raise_interrupt(VECTOR_TIMER)

        serviced = ic.service_pending()
        assert serviced == EXPECTED_SERVICED
        assert count == EXPECTED_SERVICED

    def test_priority_ordering(self) -> None:
        """Higher-priority vectors are serviced before lower-priority ones."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_IO_BASE,
            interrupt_type=InterruptType.IO,
            priority=InterruptPriority.LOW,
        )
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )

        order: list[int] = []
        ic.register_handler(VECTOR_IO_BASE, lambda _irq: order.append(VECTOR_IO_BASE))
        ic.register_handler(VECTOR_TIMER, lambda _irq: order.append(VECTOR_TIMER))

        # Raise IO first, then timer — but timer has higher priority
        ic.raise_interrupt(VECTOR_IO_BASE)
        ic.raise_interrupt(VECTOR_TIMER)

        ic.service_pending()
        assert order == [VECTOR_TIMER, VECTOR_IO_BASE]

    def test_no_handler_skips(self) -> None:
        """Vectors without handlers are skipped (IRQs stay pending)."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        ic.raise_interrupt(VECTOR_TIMER)

        serviced = ic.service_pending()
        assert serviced == 0
        assert ic.pending_count(VECTOR_TIMER) == 1

    def test_total_serviced_accumulates(self) -> None:
        """Total serviced count accumulates across calls."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)

        assert ic.total_serviced == 0
        ic.raise_interrupt(VECTOR_TIMER)
        ic.service_pending()
        assert ic.total_serviced == 1

        ic.raise_interrupt(VECTOR_TIMER)
        ic.raise_interrupt(VECTOR_TIMER)
        ic.service_pending()
        assert ic.total_serviced == EXPECTED_SERVICED


class TestMasking:
    """Test interrupt masking and unmasking."""

    def test_mask_prevents_service(self) -> None:
        """Masked vectors accumulate IRQs but don't service them."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)

        ic.mask(VECTOR_TIMER)
        ic.raise_interrupt(VECTOR_TIMER)

        serviced = ic.service_pending()
        assert serviced == 0
        assert ic.pending_count(VECTOR_TIMER) == 1

    def test_unmask_allows_service(self) -> None:
        """Unmasking processes previously queued IRQs."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        received: list[InterruptRequest] = []
        ic.register_handler(VECTOR_TIMER, received.append)

        ic.mask(VECTOR_TIMER)
        ic.raise_interrupt(VECTOR_TIMER)
        ic.service_pending()
        assert len(received) == 0

        ic.unmask(VECTOR_TIMER)
        serviced = ic.service_pending()
        assert serviced == 1
        assert len(received) == 1

    def test_is_masked(self) -> None:
        """Verify masking state queries."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        assert ic.is_masked(VECTOR_TIMER) is False
        ic.mask(VECTOR_TIMER)
        assert ic.is_masked(VECTOR_TIMER) is True
        ic.unmask(VECTOR_TIMER)
        assert ic.is_masked(VECTOR_TIMER) is False

    def test_mask_unknown_vector_raises(self) -> None:
        """Masking an unknown vector raises KeyError."""
        ic = InterruptController()
        with pytest.raises(KeyError, match="not registered"):
            ic.mask(999)

    def test_unmask_unknown_vector_raises(self) -> None:
        """Unmasking an unknown vector raises KeyError."""
        ic = InterruptController()
        with pytest.raises(KeyError, match="not registered"):
            ic.unmask(999)

    def test_is_masked_unknown_vector_raises(self) -> None:
        """Querying mask state on an unknown vector raises KeyError."""
        ic = InterruptController()
        with pytest.raises(KeyError, match="not registered"):
            ic.is_masked(999)


class TestListVectors:
    """Test vector listing."""

    def test_list_empty(self) -> None:
        """Empty controller returns empty list."""
        ic = InterruptController()
        assert ic.list_vectors() == []

    def test_list_shows_all_info(self) -> None:
        """Listed vectors contain all expected fields."""
        ic = InterruptController()
        ic.register_vector(
            VECTOR_TIMER,
            interrupt_type=InterruptType.TIMER,
            priority=InterruptPriority.HIGH,
        )
        ic.register_handler(VECTOR_TIMER, lambda _irq: None)
        ic.raise_interrupt(VECTOR_TIMER)
        ic.mask(VECTOR_TIMER)

        vectors = ic.list_vectors()
        assert len(vectors) == 1
        v = vectors[0]
        assert v["vector"] == VECTOR_TIMER
        assert v["type"] == "timer"
        assert v["priority"] == int(InterruptPriority.HIGH)
        assert v["masked"] is True
        assert v["pending"] == 1
        assert v["has_handler"] is True
