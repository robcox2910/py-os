"""The kernel — core of the operating system.

The kernel manages the system lifecycle and will eventually coordinate
all subsystems: scheduler, memory manager, file system, and more.

A real kernel is the first code that runs after the bootloader. It sets
up hardware, initialises data structures, and enters a main loop. Our
simulated kernel mirrors these phases with an explicit state machine:

    SHUTDOWN  →  BOOTING  →  RUNNING  →  SHUTTING_DOWN  →  SHUTDOWN
"""

from enum import StrEnum
from time import monotonic


class KernelState(StrEnum):
    """Represent the lifecycle phases of the kernel.

    Why a StrEnum?
    - Type safety: the type checker catches typos at edit-time.
    - Exhaustiveness: a match/case on the enum is verifiably complete.
    - Self-documenting: you can list all valid states in one place.
    - String-native: usable directly in f-strings and logs without .value.
    """

    SHUTDOWN = "shutdown"
    BOOTING = "booting"
    RUNNING = "running"
    SHUTTING_DOWN = "shutting_down"


class Kernel:
    """The central coordinator of the operating system.

    Responsibilities (current):
    - Manage boot / shutdown lifecycle via an explicit state machine.
    - Track uptime.

    Responsibilities (future modules will add):
    - Initialise and own the Scheduler, MemoryManager, FileSystem, etc.
    - Dispatch system calls from user-space processes.
    """

    def __init__(self) -> None:
        """Create a kernel in the SHUTDOWN state."""
        self._state: KernelState = KernelState.SHUTDOWN
        self._boot_time: float | None = None

    @property
    def state(self) -> KernelState:
        """Return the current kernel state."""
        return self._state

    @property
    def uptime(self) -> float:
        """Return seconds elapsed since boot, or 0.0 if not running."""
        if self._boot_time is None:
            return 0.0
        return monotonic() - self._boot_time

    def boot(self) -> None:
        """Transition the kernel from SHUTDOWN → RUNNING.

        Raises:
            RuntimeError: If the kernel is not in the SHUTDOWN state.

        """
        if self._state is not KernelState.SHUTDOWN:
            msg = f"Cannot boot: kernel is {self._state}, expected shutdown"
            raise RuntimeError(msg)

        self._state = KernelState.BOOTING
        self._boot_time = monotonic()
        # Future: initialise subsystems here (scheduler, memory, fs…)
        self._state = KernelState.RUNNING

    def shutdown(self) -> None:
        """Transition the kernel from RUNNING → SHUTDOWN.

        Raises:
            RuntimeError: If the kernel is not in the RUNNING state.

        """
        if self._state is not KernelState.RUNNING:
            msg = f"Cannot shutdown: kernel is {self._state}, expected running"
            raise RuntimeError(msg)

        self._state = KernelState.SHUTTING_DOWN
        # Future: tear down subsystems in reverse order
        self._boot_time = None
        self._state = KernelState.SHUTDOWN
