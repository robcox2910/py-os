"""Integration tests for kernel.tick(), timer-driven preemption, and I/O interrupts."""

from py_os.io.interrupts import VECTOR_IO_BASE, VECTOR_TIMER, InterruptRequest
from py_os.kernel import Kernel
from py_os.syscalls import SyscallNumber

MULTI_TICK_COUNT = 10
EXPECTED_FIRES = 3
NEW_INTERVAL = 3


class TestKernelTick:
    """Test the kernel tick mechanism."""

    def test_tick_increments_count(self) -> None:
        """Each tick increments the kernel tick count."""
        kernel = Kernel()
        kernel.boot()
        assert kernel.tick_count == 0

        with kernel.kernel_mode():
            result = kernel.tick()
        assert kernel.tick_count == 1
        assert result["tick"] == 1

    def test_tick_returns_dict(self) -> None:
        """Tick returns a dict with expected keys."""
        kernel = Kernel()
        kernel.boot()
        with kernel.kernel_mode():
            result = kernel.tick()
        assert "tick" in result
        assert "interrupts_serviced" in result
        assert "preempted" in result

    def test_multiple_ticks(self) -> None:
        """Multiple ticks increment the count correctly."""
        kernel = Kernel()
        kernel.boot()
        with kernel.kernel_mode():
            for i in range(10):
                result = kernel.tick()
                assert result["tick"] == i + 1
        assert kernel.tick_count == MULTI_TICK_COUNT


class TestTimerFiring:
    """Test timer-driven interrupt firing via tick."""

    def test_timer_fires_at_interval(self) -> None:
        """Timer fires after the configured interval of ticks."""
        kernel = Kernel()
        kernel.boot()
        with kernel.kernel_mode():
            assert kernel.timer is not None
            interval = kernel.timer.interval

            # Tick until just before the interval
            for _ in range(interval - 1):
                result = kernel.tick()
                assert result["interrupts_serviced"] == 0

            # The interval-th tick should fire the timer
            result = kernel.tick()
            assert result["interrupts_serviced"] == 1

    def test_timer_fires_periodically(self) -> None:
        """Timer fires repeatedly at the interval."""
        kernel = Kernel()
        kernel.boot()
        with kernel.kernel_mode():
            assert kernel.timer is not None
            interval = kernel.timer.interval
            fire_count = 0
            total_ticks = interval * 3

            for _ in range(total_ticks):
                result = kernel.tick()
                fire_count += result["interrupts_serviced"]

            assert fire_count == EXPECTED_FIRES


class TestTickSyscall:
    """Test the SYS_TICK syscall."""

    def test_tick_syscall_single(self) -> None:
        """SYS_TICK with count=1 advances one tick."""
        kernel = Kernel()
        kernel.boot()
        result = kernel.syscall(SyscallNumber.SYS_TICK, count=1)
        assert result["ticks"] == 1
        assert result["final_tick"] == 1

    def test_tick_syscall_multiple(self) -> None:
        """SYS_TICK with count=N advances N ticks."""
        kernel = Kernel()
        kernel.boot()
        result = kernel.syscall(SyscallNumber.SYS_TICK, count=MULTI_TICK_COUNT)
        assert result["ticks"] == MULTI_TICK_COUNT
        assert result["final_tick"] == MULTI_TICK_COUNT


class TestInterruptSyscalls:
    """Test interrupt-related syscalls."""

    def test_interrupt_list(self) -> None:
        """SYS_INTERRUPT_LIST returns registered vectors."""
        kernel = Kernel()
        kernel.boot()
        vectors = kernel.syscall(SyscallNumber.SYS_INTERRUPT_LIST)
        assert len(vectors) >= 1
        # Timer vector should always be present
        timer_vec = next(v for v in vectors if v["vector"] == VECTOR_TIMER)
        assert timer_vec["type"] == "timer"

    def test_interrupt_mask_unmask(self) -> None:
        """Masking prevents timer fires, unmasking resumes them."""
        kernel = Kernel()
        kernel.boot()

        # Mask the timer
        kernel.syscall(SyscallNumber.SYS_INTERRUPT_MASK, vector=VECTOR_TIMER)

        # Tick past the interval — no interrupts should fire
        with kernel.kernel_mode():
            assert kernel.timer is not None
            interval = kernel.timer.interval
        result = kernel.syscall(SyscallNumber.SYS_TICK, count=interval)
        assert result["total_interrupts_serviced"] == 0

        # Unmask and service
        kernel.syscall(SyscallNumber.SYS_INTERRUPT_UNMASK, vector=VECTOR_TIMER)
        # One more tick to service queued interrupt
        result = kernel.syscall(SyscallNumber.SYS_TICK, count=1)
        assert result["total_interrupts_serviced"] == 1


class TestTimerSyscalls:
    """Test timer-related syscalls."""

    def test_timer_info(self) -> None:
        """SYS_TIMER_INFO returns timer status."""
        kernel = Kernel()
        kernel.boot()
        info = kernel.syscall(SyscallNumber.SYS_TIMER_INFO)
        assert "interval" in info
        assert "current_tick" in info
        assert "total_ticks" in info
        assert "fires" in info

    def test_timer_set_interval(self) -> None:
        """SYS_TIMER_SET_INTERVAL changes the timer period."""
        kernel = Kernel()
        kernel.boot()
        kernel.syscall(SyscallNumber.SYS_TIMER_SET_INTERVAL, interval=NEW_INTERVAL)
        info = kernel.syscall(SyscallNumber.SYS_TIMER_INFO)
        assert info["interval"] == NEW_INTERVAL


class TestIOInterrupts:
    """Test I/O completion interrupts."""

    def test_raise_io_interrupt(self) -> None:
        """Kernel can raise I/O interrupts and service them."""
        kernel = Kernel()
        kernel.boot()

        received: list[InterruptRequest] = []

        with kernel.kernel_mode():
            ic = kernel.interrupt_controller
            assert ic is not None
            kernel.raise_io_interrupt(data={"device": "disk0"})
            ic.register_handler(VECTOR_IO_BASE, received.append)
            kernel.raise_io_interrupt(data={"device": "disk1"})

        # Tick to service
        result = kernel.syscall(SyscallNumber.SYS_TICK, count=1)
        assert result["total_interrupts_serviced"] >= 1
        assert len(received) >= 1


class TestBootIntegration:
    """Test that interrupt subsystem integrates with boot/shutdown."""

    def test_boot_creates_controller_and_timer(self) -> None:
        """Booting creates interrupt controller and timer."""
        kernel = Kernel()
        kernel.boot()
        with kernel.kernel_mode():
            assert kernel.interrupt_controller is not None
            assert kernel.timer is not None
            assert kernel.timer.name == "timer"

    def test_dmesg_includes_interrupt_init(self) -> None:
        """Boot log includes interrupt controller initialization."""
        kernel = Kernel()
        kernel.boot()
        log = kernel.dmesg()
        assert any("Interrupt controller" in msg for msg in log)

    def test_shutdown_clears_interrupt_state(self) -> None:
        """Shutdown clears interrupt controller and timer."""
        kernel = Kernel()
        kernel.boot()
        kernel.shutdown()
        assert kernel._interrupt_controller is None
        assert kernel._timer is None
        assert kernel._tick_count == 0

    def test_timer_in_device_list(self) -> None:
        """Timer appears in the device manager after boot."""
        kernel = Kernel()
        kernel.boot()
        with kernel.kernel_mode():
            assert kernel.device_manager is not None
            device_names = kernel.device_manager.list_devices()
        assert "timer" in device_names
