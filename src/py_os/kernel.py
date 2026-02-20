"""The kernel — core of the operating system.

The kernel manages the system lifecycle and coordinates all subsystems:
scheduler, memory manager, file system, and user manager.

A real kernel is the first code that runs after the bootloader. It sets
up hardware, initialises data structures, and enters a main loop. Our
simulated kernel mirrors these phases with an explicit state machine:

    SHUTDOWN  →  BOOTING  →  RUNNING  →  SHUTTING_DOWN  →  SHUTDOWN

Boot sequence (order matters):
    0. Logger — capture events from the start.
    1. Memory manager — everything else needs memory.
    2. File system — processes may need file access.
    3. User manager — identity before scheduling.
    4. Device manager — register default devices.
    5. Scheduler — ready to accept processes.

Shutdown sequence (reverse order):
    5. Scheduler — stop scheduling.
    4. Device manager — unregister devices.
    3. User manager — clear users.
    2. File system — unmount.
    1. Memory manager — release all frames.
    0. Logger — last to go (captures shutdown events).
"""

from collections.abc import Callable
from enum import StrEnum
from time import monotonic
from typing import Any

from py_os.devices import ConsoleDevice, DeviceManager, NullDevice, RandomDevice
from py_os.env import Environment
from py_os.filesystem import FileSystem
from py_os.logging import Logger, LogLevel
from py_os.memory import MemoryManager
from py_os.process import Process, ProcessState
from py_os.scheduler import FCFSPolicy, Scheduler
from py_os.signals import Signal, SignalError
from py_os.syscalls import SyscallNumber, dispatch_syscall
from py_os.threads import Thread
from py_os.users import FilePermissions, UserManager
from py_os.virtual_memory import VirtualMemory

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
        self._user_manager: UserManager | None = None
        self._device_manager: DeviceManager | None = None
        self._env: Environment | None = None
        self._logger: Logger | None = None
        self._current_uid: int = 0
        self._file_permissions: dict[str, FilePermissions] = {}
        self._processes: dict[int, Process] = {}
        self._signal_handlers: dict[tuple[int, Signal], Callable[[], None]] = {}

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

    @property
    def user_manager(self) -> UserManager | None:
        """Return the user manager, or None if not booted."""
        return self._user_manager

    @property
    def device_manager(self) -> DeviceManager | None:
        """Return the device manager, or None if not booted."""
        return self._device_manager

    @property
    def env(self) -> Environment | None:
        """Return the global environment, or None if not booted."""
        return self._env

    @property
    def logger(self) -> Logger | None:
        """Return the logger, or None if not booted."""
        return self._logger

    @property
    def current_uid(self) -> int:
        """Return the uid of the current user."""
        return self._current_uid

    @current_uid.setter
    def current_uid(self, uid: int) -> None:
        """Set the current user uid."""
        self._current_uid = uid

    @property
    def file_permissions(self) -> dict[str, FilePermissions]:
        """Return the file permissions table (path → permissions)."""
        return self._file_permissions

    @property
    def processes(self) -> dict[int, Process]:
        """Return the process table (PID → Process mapping)."""
        return dict(self._processes)

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

        # 0. Logger — capture events from the start
        self._logger = Logger()

        # 1. Memory — everything else needs it
        self._memory = MemoryManager(total_frames=DEFAULT_TOTAL_FRAMES)

        # 2. File system — processes may need files
        self._filesystem = FileSystem()

        # 3. User manager — identity before scheduling
        self._user_manager = UserManager()
        self._current_uid = 0  # root

        # 5. Environment — default variables
        self._env = Environment(
            initial={
                "PATH": "/bin:/usr/bin",
                "HOME": "/root",
                "USER": "root",
            }
        )

        # 6. Device manager — register default devices
        self._device_manager = DeviceManager()
        self._device_manager.register(NullDevice())
        self._device_manager.register(ConsoleDevice())
        self._device_manager.register(RandomDevice())

        # 7. Scheduler — ready to accept processes
        self._scheduler = Scheduler(policy=FCFSPolicy())

        self._state = KernelState.RUNNING
        self._logger.log(LogLevel.INFO, "Kernel boot complete", source="kernel")

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
        self._device_manager = None
        self._env = None
        self._user_manager = None
        self._current_uid = 0
        self._file_permissions.clear()
        self._filesystem = None
        self._memory = None
        self._processes.clear()
        self._signal_handlers.clear()

        self._logger = None
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
        frames = self._memory.allocate(process.pid, num_pages=num_pages)

        # Set up virtual memory: map virtual pages 0..N-1 to physical frames
        vm = VirtualMemory()
        for vpn, frame in enumerate(frames):
            vm.page_table.map(virtual_page=vpn, physical_frame=frame)
        process.virtual_memory = vm

        process.admit()
        self._scheduler.add(process)
        self._processes[process.pid] = process
        return process

    def fork_process(self, *, parent_pid: int) -> Process:
        """Fork a process — create a child that is a copy of the parent.

        In Unix, fork() is how every new process is born.  The child gets:
        - A new unique PID with parent_pid set to the parent's PID.
        - A copy of the parent's virtual memory (new physical frames,
          same data — eager copy, not copy-on-write).
        - The same name (suffixed with " (fork)") and priority.
        - READY state — admitted to the scheduler immediately.

        Args:
            parent_pid: PID of the process to fork.

        Returns:
            The newly created child process.

        Raises:
            ValueError: If the parent doesn't exist or is terminated.
            OutOfMemoryError: If insufficient memory for the copy.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101
        assert self._scheduler is not None  # noqa: S101

        parent = self._processes.get(parent_pid)
        if parent is None:
            msg = f"Process {parent_pid} not found"
            raise ValueError(msg)
        if parent.state is ProcessState.TERMINATED:
            msg = f"Cannot fork: process {parent_pid} is terminated"
            raise ValueError(msg)

        # Determine how many pages the parent has
        parent_frames = self._memory.pages_for(parent_pid)
        num_pages = len(parent_frames)

        # Create the child process
        child = Process(
            name=f"{parent.name} (fork)",
            priority=parent.priority,
            parent_pid=parent_pid,
        )

        # Allocate new physical frames for the child
        child_frames = self._memory.allocate(child.pid, num_pages=num_pages)

        # Set up virtual memory: copy page table structure and data
        child_vm = VirtualMemory()
        parent_vm = parent.virtual_memory
        if parent_vm is not None:
            parent_mappings = parent_vm.page_table.mappings()
            for vpn, _parent_frame in sorted(parent_mappings.items()):
                child_frame = child_frames[vpn] if vpn < len(child_frames) else child_frames[0]
                child_vm.page_table.map(virtual_page=vpn, physical_frame=child_frame)

                # Copy the page data from parent to child
                addr = vpn * parent_vm.page_size
                data = parent_vm.read(virtual_address=addr, size=parent_vm.page_size)
                child_vm.write(virtual_address=addr, data=data)

        child.virtual_memory = child_vm

        # Admit to scheduler and register in process table
        child.admit()
        self._scheduler.add(child)
        self._processes[child.pid] = child
        return child

    def create_thread(self, *, pid: int, name: str) -> Thread:
        """Create a new thread within a process.

        Unlike fork, creating a thread is cheap — no memory is
        allocated.  The thread shares the process's virtual memory.

        Args:
            pid: PID of the process to create the thread in.
            name: Human-readable label for the thread.

        Returns:
            The newly created thread (in READY state).

        Raises:
            ValueError: If the process doesn't exist.

        """
        self._require_running()
        process = self._processes.get(pid)
        if process is None:
            msg = f"Process {pid} not found"
            raise ValueError(msg)
        thread = process.create_thread(name)
        thread.admit()
        return thread

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

    def register_signal_handler(
        self,
        pid: int,
        signal: Signal,
        handler: Callable[[], None],
    ) -> None:
        """Register a handler to be called when a signal is delivered.

        Args:
            pid: The target process.
            signal: The signal to handle.
            handler: A callable invoked before the signal's default action.

        Raises:
            SignalError: If the process does not exist.

        """
        self._require_running()
        if pid not in self._processes:
            msg = f"Process {pid} not found"
            raise SignalError(msg)
        self._signal_handlers[(pid, signal)] = handler

    def send_signal(self, pid: int, signal: Signal) -> None:
        """Deliver a signal to a process.

        Signal behaviour:
            - SIGKILL: force-terminate (uncatchable, no handler).
            - SIGTERM: invoke handler if registered, then terminate.
            - SIGSTOP: pause (RUNNING → WAITING).
            - SIGCONT: resume (WAITING → READY), no-op otherwise.

        Args:
            pid: The target process.
            signal: The signal to deliver.

        Raises:
            SignalError: If the process doesn't exist or is terminated.

        """
        self._require_running()
        process = self._processes.get(pid)
        if process is None:
            msg = f"Process {pid} not found"
            raise SignalError(msg)
        if process.state is ProcessState.TERMINATED:
            msg = f"Process {pid} is already terminated"
            raise SignalError(msg)

        if self._logger is not None:
            self._logger.log(
                LogLevel.INFO,
                f"Signal {signal.name} → pid {pid}",
                source="signal",
                uid=self._current_uid,
            )

        if signal is Signal.SIGKILL:
            process.force_terminate()
        elif signal is Signal.SIGTERM:
            handler = self._signal_handlers.get((pid, signal))
            if handler is not None:
                handler()
            process.force_terminate()
        elif signal is Signal.SIGSTOP:
            process.wait()
        elif signal is Signal.SIGCONT and process.state is ProcessState.WAITING:
            process.wake()

    def syscall(self, number: SyscallNumber, **kwargs: Any) -> Any:
        """Execute a system call — the user-space → kernel-space gateway.

        This is the single entry point for all user-space requests.
        It validates that the kernel is running, then dispatches to
        the appropriate handler via the syscall dispatch table.

        Args:
            number: The syscall number identifying the operation.
            **kwargs: Arguments specific to the syscall.

        Returns:
            The syscall result (type depends on the operation).

        Raises:
            RuntimeError: If the kernel is not running.
            SyscallError: If the syscall fails.

        """
        self._require_running()
        if self._logger is not None:
            label = number.name if hasattr(number, "name") else str(number)
            self._logger.log(
                LogLevel.DEBUG,
                f"syscall {label}",
                source="syscall",
                uid=self._current_uid,
            )
        return dispatch_syscall(self, number, **kwargs)
