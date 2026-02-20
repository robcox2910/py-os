"""The kernel — core of the operating system.

The kernel manages the system lifecycle and coordinates all subsystems:
scheduler, memory manager, and file system.

A real kernel is the first code that runs after the bootloader. It sets
up hardware, initialises data structures, and enters a main loop. Our
simulated kernel mirrors these phases with an explicit state machine:

    SHUTDOWN  →  BOOTING  →  RUNNING  →  SHUTTING_DOWN  →  SHUTDOWN

Boot sequence (order matters):
    1. Memory manager — everything else needs memory.
    2. File system — processes may need file access.
    3. Scheduler — ready to accept processes.

Shutdown sequence (reverse order):
    3. Scheduler — stop scheduling.
    2. File system — unmount.
    1. Memory manager — release all frames.
"""

from enum import StrEnum
from time import monotonic

from py_os.filesystem import FileSystem
from py_os.memory import MemoryManager
from py_os.process import Process
from py_os.scheduler import FCFSPolicy, Scheduler

DEFAULT_TOTAL_FRAMES = 64


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

    The kernel owns and manages the lifecycle of all subsystems.
    Subsystem references are None when the kernel is not running,
    and are initialised during boot.
    """

    def __init__(self) -> None:
        """Create a kernel in the SHUTDOWN state."""
        self._state: KernelState = KernelState.SHUTDOWN
        self._boot_time: float | None = None
        self._scheduler: Scheduler | None = None
        self._memory: MemoryManager | None = None
        self._filesystem: FileSystem | None = None
        self._processes: dict[int, Process] = {}

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

    @property
    def scheduler(self) -> Scheduler | None:
        """Return the scheduler, or None if not booted."""
        return self._scheduler

    @property
    def memory(self) -> MemoryManager | None:
        """Return the memory manager, or None if not booted."""
        return self._memory

    @property
    def filesystem(self) -> FileSystem | None:
        """Return the file system, or None if not booted."""
        return self._filesystem

    def _require_running(self) -> None:
        """Raise if the kernel is not in the RUNNING state."""
        if self._state is not KernelState.RUNNING:
            msg = f"Kernel is not running (state: {self._state})"
            raise RuntimeError(msg)

    def boot(self) -> None:
        """Transition the kernel from SHUTDOWN → RUNNING.

        Initialise subsystems in dependency order:
        memory → file system → scheduler.

        Raises:
            RuntimeError: If the kernel is not in the SHUTDOWN state.

        """
        if self._state is not KernelState.SHUTDOWN:
            msg = f"Cannot boot: kernel is {self._state}, expected shutdown"
            raise RuntimeError(msg)

        self._state = KernelState.BOOTING
        self._boot_time = monotonic()

        # 1. Memory — everything else needs it
        self._memory = MemoryManager(total_frames=DEFAULT_TOTAL_FRAMES)

        # 2. File system — processes may need files
        self._filesystem = FileSystem()

        # 3. Scheduler — ready to accept processes
        self._scheduler = Scheduler(policy=FCFSPolicy())

        self._state = KernelState.RUNNING

    def shutdown(self) -> None:
        """Transition the kernel from RUNNING → SHUTDOWN.

        Tear down subsystems in reverse order.

        Raises:
            RuntimeError: If the kernel is not in the RUNNING state.

        """
        if self._state is not KernelState.RUNNING:
            msg = f"Cannot shutdown: kernel is {self._state}, expected running"
            raise RuntimeError(msg)

        self._state = KernelState.SHUTTING_DOWN

        # Tear down in reverse order
        self._scheduler = None
        self._filesystem = None
        self._memory = None
        self._processes.clear()

        self._boot_time = None
        self._state = KernelState.SHUTDOWN

    def create_process(self, *, name: str, num_pages: int) -> Process:
        """Create a new process, allocate memory, and register with scheduler.

        This is the coordinated act of process creation — the kernel is
        the only entity that can do this because it spans all subsystems:

        1. Create the PCB (Process object).
        2. Allocate memory frames.
        3. Admit the process (NEW → READY).
        4. Add to the scheduler's ready queue.

        Args:
            name: Human-readable process name.
            num_pages: Number of memory frames to allocate.

        Returns:
            The newly created process.

        Raises:
            RuntimeError: If the kernel is not running.
            OutOfMemoryError: If insufficient memory frames are available.

        """
        self._require_running()
        assert self._memory is not None  # guaranteed by _require_running  # noqa: S101
        assert self._scheduler is not None  # noqa: S101

        process = Process(name=name)
        self._memory.allocate(process.pid, num_pages=num_pages)
        process.admit()
        self._scheduler.add(process)
        self._processes[process.pid] = process
        return process

    def terminate_process(self, *, pid: int) -> None:
        """Terminate a process and free its resources.

        The kernel coordinates cleanup across subsystems:
        1. Terminate the process (RUNNING → TERMINATED).
        2. Free its memory frames.
        3. Remove from the process table.

        Args:
            pid: The PID of the process to terminate.

        Raises:
            RuntimeError: If the kernel is not running.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101

        process = self._processes.get(pid)
        if process is not None:
            process.terminate()
            self._memory.free(pid)
            del self._processes[pid]
