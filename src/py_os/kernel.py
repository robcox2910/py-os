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

from py_os.env import Environment
from py_os.fs.fd import FdError, FdTable, FileMode, OpenFileDescription, SeekWhence
from py_os.fs.filesystem import FileType
from py_os.fs.journal import JournaledFileSystem
from py_os.fs.procfs import ProcError, ProcFilesystem
from py_os.io.devices import ConsoleDevice, DeviceManager, NullDevice, RandomDevice
from py_os.io.dns import DnsRecord, DnsResolver
from py_os.io.networking import SocketError, SocketManager
from py_os.io.shm import SharedMemoryError, SharedMemorySegment
from py_os.logging import Logger, LogLevel
from py_os.memory.manager import MemoryManager
from py_os.memory.mmap import MmapError, MmapRegion
from py_os.memory.slab import SlabAllocator, SlabCache
from py_os.memory.virtual import VirtualMemory
from py_os.process.pcb import Process, ProcessState
from py_os.process.scheduler import FCFSPolicy, Scheduler, SchedulingPolicy
from py_os.process.signals import DEFAULT_ACTIONS, UNCATCHABLE, Signal, SignalAction, SignalError
from py_os.process.threads import Thread
from py_os.sync.deadlock import ResourceManager
from py_os.sync.inheritance import PriorityInheritanceManager
from py_os.sync.ordering import ResourceOrderingManager
from py_os.sync.primitives import Condition, Mutex, ReadWriteLock, Semaphore, SyncManager
from py_os.syscalls import SyscallNumber, dispatch_syscall
from py_os.users import FilePermissions, UserManager

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
        self._filesystem: JournaledFileSystem | None = None
        self._user_manager: UserManager | None = None
        self._device_manager: DeviceManager | None = None
        self._env: Environment | None = None
        self._logger: Logger | None = None
        self._current_uid: int = 0
        self._file_permissions: dict[str, FilePermissions] = {}
        self._processes: dict[int, Process] = {}
        self._signal_handlers: dict[tuple[int, Signal], Callable[[], None]] = {}
        self._resource_manager: ResourceManager | None = None
        self._sync_manager: SyncManager | None = None
        self._pi_manager: PriorityInheritanceManager | None = None
        self._ordering_manager: ResourceOrderingManager | None = None
        self._slab_allocator: SlabAllocator | None = None
        # Per-process mmap regions: pid → {start_vpn → MmapRegion}
        self._mmap_regions: dict[int, dict[int, MmapRegion]] = {}
        # Shared frame cache: (inode_number, page_index) → (frame, bytearray)
        self._shared_file_frames: dict[tuple[int, int], tuple[int, bytearray]] = {}
        # Per-process file descriptor tables: pid → FdTable
        self._fd_tables: dict[int, FdTable] = {}
        # Named shared memory segments: name → SharedMemorySegment
        self._shared_memory: dict[str, SharedMemorySegment] = {}
        # DNS resolver — phone book for hostname → IP resolution
        self._dns_resolver: DnsResolver | None = None
        # Socket manager — in-memory network stack
        self._socket_manager: SocketManager | None = None
        # Virtual /proc filesystem — generates content from live kernel state
        self._proc_fs: ProcFilesystem | None = None

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
    def filesystem(self) -> JournaledFileSystem | None:
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

    @property
    def resource_manager(self) -> ResourceManager | None:
        """Return the resource manager, or None if not booted."""
        return self._resource_manager

    @property
    def sync_manager(self) -> SyncManager | None:
        """Return the sync manager, or None if not booted."""
        return self._sync_manager

    @property
    def pi_manager(self) -> PriorityInheritanceManager | None:
        """Return the priority inheritance manager, or None if not booted."""
        return self._pi_manager

    @property
    def ordering_manager(self) -> ResourceOrderingManager | None:
        """Return the resource ordering manager, or None if not booted."""
        return self._ordering_manager

    @property
    def slab_allocator(self) -> SlabAllocator | None:
        """Return the slab allocator, or None if not booted."""
        return self._slab_allocator

    @property
    def socket_manager(self) -> SocketManager | None:
        """Return the socket manager, or None if not booted."""
        return self._socket_manager

    @property
    def proc_filesystem(self) -> ProcFilesystem | None:
        """Return the /proc virtual filesystem, or None if not booted."""
        return self._proc_fs

    def set_scheduler_policy(self, policy: SchedulingPolicy) -> None:
        """Replace the scheduler's policy, preserving the ready queue.

        Creates a new Scheduler with the given policy and re-adds every
        process that was in the old ready queue.

        Args:
            policy: The new scheduling policy to use.

        """
        self._require_running()
        assert self._scheduler is not None  # noqa: S101

        old = self._scheduler
        new = Scheduler(policy=policy)

        # Drain the old ready queue into the new scheduler
        while old.ready_count > 0:
            process = old.dispatch()
            if process is not None:
                process.preempt()  # RUNNING → READY
                new.add(process)

        self._scheduler = new

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

        # 1b. Slab allocator — kernel-level fixed-size object pools
        self._slab_allocator = SlabAllocator(
            memory=self._memory,
            page_size=VirtualMemory().page_size,
            kernel_pid=0,
        )
        self._slab_allocator.create_cache("pcb", obj_size=64)
        self._slab_allocator.create_cache("inode", obj_size=48)

        # 2. File system — processes may need files (with journaling for crash recovery)
        self._filesystem = JournaledFileSystem()

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

        # 6b. DNS resolver — pre-seed with localhost
        self._dns_resolver = DnsResolver()
        self._dns_resolver.register("localhost", "127.0.0.1")

        # 6c. Socket manager — in-memory network stack
        self._socket_manager = SocketManager()

        # 7. Resource manager — deadlock detection and avoidance
        self._resource_manager = ResourceManager()

        # 8. Sync manager — mutexes, semaphores, condition variables
        self._sync_manager = SyncManager()

        # 8b. Priority inheritance manager — prevent priority inversion
        self._pi_manager = PriorityInheritanceManager()

        # 8c. Resource ordering manager — prevent deadlock via ordering
        self._ordering_manager = ResourceOrderingManager()

        # 9. Scheduler — ready to accept processes
        self._scheduler = Scheduler(policy=FCFSPolicy())

        # 10. /proc virtual filesystem — reads live state from all subsystems
        self._proc_fs = ProcFilesystem(kernel=self)

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
        self._proc_fs = None
        self._scheduler = None
        if self._ordering_manager is not None:
            self._ordering_manager.clear()
        self._ordering_manager = None
        if self._pi_manager is not None:
            self._pi_manager.clear()
        self._pi_manager = None
        self._sync_manager = None
        self._resource_manager = None
        self._device_manager = None
        self._env = None
        self._user_manager = None
        self._current_uid = 0
        self._file_permissions.clear()
        self._filesystem = None
        self._slab_allocator = None
        self._memory = None
        self._processes.clear()
        self._signal_handlers.clear()
        self._fd_tables.clear()
        self._mmap_regions.clear()
        self._shared_file_frames.clear()
        self._shared_memory.clear()
        self._socket_manager = None
        self._dns_resolver = None

        self._logger = None
        self._boot_time = None
        self._state = KernelState.SHUTDOWN

    def create_process(self, *, name: str, num_pages: int, priority: int = 0) -> Process:
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
            priority: Scheduling priority (higher = more important, default 0).

        Returns:
            The newly created process.

        Raises:
            RuntimeError: If the kernel is not running.
            OutOfMemoryError: If insufficient memory frames are available.

        """
        self._require_running()
        assert self._memory is not None  # guaranteed by _require_running  # noqa: S101
        assert self._scheduler is not None  # noqa: S101

        process = Process(name=name, priority=priority)
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
        - **Copy-on-write** virtual memory: parent and child share the
          same physical frames, marked read-only.  The first write by
          either side triggers a fault that copies the page, giving the
          writer a private frame while the other keeps the original.
        - The same name (suffixed with " (fork)") and priority.
        - READY state — admitted to the scheduler immediately.

        Args:
            parent_pid: PID of the process to fork.

        Returns:
            The newly created child process.

        Raises:
            ValueError: If the parent doesn't exist or is terminated.

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

        # Create the child process
        child = Process(
            name=f"{parent.name} (fork)",
            priority=parent.priority,
            parent_pid=parent_pid,
        )

        # COW fork: share physical frames instead of copying
        child_vm = VirtualMemory()
        parent_vm = parent.virtual_memory

        # Build set of vpns that are shared (skip COW for these)
        shared_vpns = self._shared_vpns_for(parent_pid)

        if parent_vm is not None:
            parent_mappings = parent_vm.page_table.mappings()
            for vpn, frame in sorted(parent_mappings.items()):
                # Point child to the same physical frame
                child_vm.page_table.map(virtual_page=vpn, physical_frame=frame)
                child_vm.share_physical(
                    frame=frame,
                    storage=parent_vm.physical_storage(frame),
                )
                self._memory.increment_refcount(frame)
                self._memory.share_frame(pid=child.pid, frame=frame)

                if vpn not in shared_vpns:
                    # Mark COW on both sides (private pages)
                    parent_vm.mark_cow(virtual_page=vpn)
                    child_vm.mark_cow(virtual_page=vpn)

            # Install COW fault handlers
            self._install_cow_handler(child.pid, child_vm)
            self._install_cow_handler(parent_pid, parent_vm)

        child.virtual_memory = child_vm

        # Copy mmap regions from parent to child
        parent_regions = self._mmap_regions.get(parent_pid, {})
        if parent_regions:
            self._mmap_regions[child.pid] = dict(parent_regions)

        # Copy shm attachments from parent to child
        for seg in self._shared_memory.values():
            if parent_pid in seg.attachments:
                seg.attachments[child.pid] = seg.attachments[parent_pid]

        # Copy fd table from parent to child (independent offsets)
        parent_fd_table = self._fd_tables.get(parent_pid)
        if parent_fd_table is not None:
            self._fd_tables[child.pid] = parent_fd_table.duplicate()

        # Admit to scheduler and register in process table
        child.admit()
        self._scheduler.add(child)
        self._processes[child.pid] = child
        return child

    def _shared_vpns_for(self, pid: int) -> set[int]:
        """Return VPNs that are shared (mmap MAP_SHARED + shm) for a process.

        These pages should NOT be marked COW during fork.
        """
        vpns: set[int] = set()
        for region in self._mmap_regions.get(pid, {}).values():
            if region.shared:
                vpns.update(range(region.start_vpn, region.start_vpn + region.num_pages))
        for seg in self._shared_memory.values():
            if pid in seg.attachments:
                start = seg.attachments[pid]
                vpns.update(range(start, start + seg.num_pages))
        return vpns

    def _install_cow_handler(self, pid: int, vm: VirtualMemory) -> None:
        """Install a copy-on-write fault handler on a virtual memory space.

        The handler is a closure that captures the PID and memory manager.
        When a COW page is written, it allocates a fresh frame, copies
        the data, and decrements the old frame's refcount.

        Args:
            pid: The process ID that owns this address space.
            vm: The virtual memory to install the handler on.

        """
        memory = self._memory
        assert memory is not None  # noqa: S101

        def cow_handler(vpn: int) -> tuple[int, bytearray]:
            old_frame = vm.page_table.translate(vpn)
            new_frame = memory.allocate_one(pid)
            old_storage = vm.physical_storage(old_frame)
            new_storage = bytearray(old_storage)
            memory.decrement_refcount(old_frame)
            return (new_frame, new_storage)

        vm.cow_fault_handler = cow_handler

    # -- Link operations --------------------------------------------------------

    def link_file(self, target_path: str, link_path: str) -> None:
        """Create a hard link via the filesystem.

        Args:
            target_path: The existing file to link to.
            link_path: The new name for the file.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        self._filesystem.link(target_path, link_path)

    def symlink_file(self, target_path: str, link_path: str) -> None:
        """Create a symbolic link via the filesystem.

        Args:
            target_path: The path the symlink will point to.
            link_path: The new symlink name.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        self._filesystem.symlink(target_path, link_path)

    def readlink_file(self, path: str) -> str:
        """Return the target of a symbolic link.

        Args:
            path: Absolute path to a symlink.

        Returns:
            The target path stored in the symlink.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        return self._filesystem.readlink(path)

    # -- File descriptor operations --------------------------------------------

    def open_file(self, pid: int, path: str, mode: FileMode) -> int:
        """Open a file and return a file descriptor.

        Validates that the process exists, the file exists, and the path
        is not a directory.  Creates a per-process fd table on first use.

        Args:
            pid: The process opening the file.
            path: Absolute path to the file.
            mode: Access mode (read, write, or read-write).

        Returns:
            The newly allocated fd number (>= 3).

        Raises:
            FdError: If the process or file is not found, or path is a directory.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101

        if pid not in self._processes:
            msg = f"Process {pid} not found"
            raise FdError(msg)

        if not self._filesystem.exists(path):
            msg = f"File not found: {path}"
            raise FdError(msg)

        info = self._filesystem.stat(path)
        if info.file_type is FileType.DIRECTORY:
            msg = f"Is a directory: {path}"
            raise FdError(msg)

        ofd = OpenFileDescription(
            path=path,
            mode=mode,
            inode_number=info.inode_number,
        )
        table = self._fd_tables.setdefault(pid, FdTable())
        return table.allocate(ofd)

    def close_file(self, pid: int, fd: int) -> None:
        """Close a file descriptor for a process.

        Args:
            pid: The process that owns the fd.
            fd: The file descriptor number.

        Raises:
            FdError: If the pid has no fd table or the fd is not open.

        """
        self._require_running()
        table = self._fd_tables.get(pid)
        if table is None:
            msg = f"Bad file descriptor: {fd}"
            raise FdError(msg)
        table.close(fd)

    def read_fd(self, pid: int, fd: int, *, count: int) -> bytes:
        """Read bytes from a file through a file descriptor.

        Enforces mode — the fd must be opened for reading.  Advances
        the offset by the number of bytes actually read.

        Args:
            pid: The process that owns the fd.
            fd: The file descriptor number.
            count: Maximum number of bytes to read.

        Returns:
            The bytes read (may be fewer than *count* near EOF).

        Raises:
            FdError: If the fd is invalid or not readable.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101

        table = self._fd_tables.get(pid)
        if table is None:
            msg = f"Bad file descriptor: {fd}"
            raise FdError(msg)
        ofd = table.lookup(fd)

        if ofd.mode is FileMode.WRITE:
            msg = f"fd {fd} is not readable (opened write-only)"
            raise FdError(msg)

        data = self._filesystem.read_at(ofd.path, offset=ofd.offset, count=count)
        ofd.offset += len(data)
        return data

    def write_fd(self, pid: int, fd: int, data: bytes) -> int:
        """Write bytes to a file through a file descriptor.

        Enforces mode — the fd must be opened for writing.  Advances
        the offset by the number of bytes written.

        Args:
            pid: The process that owns the fd.
            fd: The file descriptor number.
            data: The bytes to write.

        Returns:
            The number of bytes written.

        Raises:
            FdError: If the fd is invalid or not writable.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101

        table = self._fd_tables.get(pid)
        if table is None:
            msg = f"Bad file descriptor: {fd}"
            raise FdError(msg)
        ofd = table.lookup(fd)

        if ofd.mode is FileMode.READ:
            msg = f"fd {fd} is not writable (opened read-only)"
            raise FdError(msg)

        self._filesystem.write_at(ofd.path, offset=ofd.offset, data=data)
        ofd.offset += len(data)
        return len(data)

    def seek_fd(
        self,
        pid: int,
        fd: int,
        *,
        offset: int,
        whence: SeekWhence,
    ) -> int:
        """Reposition a file descriptor's offset.

        Args:
            pid: The process that owns the fd.
            fd: The file descriptor number.
            offset: The offset value (interpretation depends on *whence*).
            whence: How to interpret *offset* (SET, CUR, or END).

        Returns:
            The new absolute offset.

        Raises:
            FdError: If the fd is invalid or the resulting offset is negative.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101

        table = self._fd_tables.get(pid)
        if table is None:
            msg = f"Bad file descriptor: {fd}"
            raise FdError(msg)
        ofd = table.lookup(fd)

        file_size = self._filesystem.stat(ofd.path).size

        match whence:
            case SeekWhence.SET:
                new_offset = offset
            case SeekWhence.CUR:
                new_offset = ofd.offset + offset
            case SeekWhence.END:
                new_offset = file_size + offset

        if new_offset < 0:
            msg = f"Negative seek offset: {new_offset}"
            raise FdError(msg)

        ofd.offset = new_offset
        return new_offset

    def list_fds(self, pid: int) -> dict[int, OpenFileDescription]:
        """Return all open file descriptors for a process.

        Args:
            pid: The process to query.

        Returns:
            Dict mapping fd numbers to open file descriptions (empty if none).

        """
        table = self._fd_tables.get(pid)
        if table is None:
            return {}
        return table.list_fds()

    # -- Slab allocator delegation ---------------------------------------------

    def slab_create_cache(self, name: str, *, obj_size: int) -> SlabCache:
        """Create a named slab cache via the slab allocator.

        Args:
            name: Unique cache name.
            obj_size: Bytes per object slot.

        Returns:
            The newly created SlabCache.

        """
        self._require_running()
        assert self._slab_allocator is not None  # noqa: S101
        return self._slab_allocator.create_cache(name, obj_size=obj_size)

    def slab_alloc(self, cache_name: str) -> tuple[str, int, int]:
        """Allocate an object slot from a named slab cache.

        Args:
            cache_name: The cache to allocate from.

        Returns:
            ``(cache_name, slab_index, slot_index)``.

        """
        self._require_running()
        assert self._slab_allocator is not None  # noqa: S101
        return self._slab_allocator.allocate(cache_name)

    def slab_free(self, cache_name: str, slab_index: int, slot_index: int) -> None:
        """Free an object slot back to a named slab cache.

        Args:
            cache_name: The cache name.
            slab_index: The slab index.
            slot_index: The slot index.

        """
        self._require_running()
        assert self._slab_allocator is not None  # noqa: S101
        self._slab_allocator.free(cache_name, slab_index, slot_index)

    def slab_info(self) -> dict[str, dict[str, object]]:
        """Return stats for all slab caches.

        Returns:
            Dict mapping cache name to its stats dict.

        """
        self._require_running()
        assert self._slab_allocator is not None  # noqa: S101
        return self._slab_allocator.info()

    # -- Memory-mapped files (mmap) -------------------------------------------

    def mmap_regions(self, pid: int) -> dict[int, MmapRegion]:
        """Return the mmap regions for a process (start_vpn → region).

        Args:
            pid: The process ID to look up.

        Returns:
            A dict mapping start_vpn to MmapRegion (empty if none).

        """
        return dict(self._mmap_regions.get(pid, {}))

    def mmap_file(
        self,
        *,
        pid: int,
        path: str,
        offset: int = 0,
        length: int | None = None,
        shared: bool = False,
    ) -> int:
        """Map a file's contents into a process's virtual address space.

        Args:
            pid: The process to map into.
            path: Filesystem path of the file.
            offset: Byte offset into the file.
            length: Bytes to map (defaults to file size minus offset).
            shared: True for MAP_SHARED, False for MAP_PRIVATE.

        Returns:
            The virtual address where the mapping starts.

        Raises:
            MmapError: If the file doesn't exist, is a directory, or
                the PID is invalid.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101
        assert self._filesystem is not None  # noqa: S101

        process = self._processes.get(pid)
        if process is None:
            msg = f"Process {pid} not found"
            raise MmapError(msg)

        # Validate the file exists and is not a directory
        try:
            info = self._filesystem.stat(path)
        except FileNotFoundError:
            msg = f"File not found: {path}"
            raise MmapError(msg) from None
        if info.file_type is FileType.DIRECTORY:
            msg = f"Cannot mmap a directory: {path}"
            raise MmapError(msg)

        # Read file data
        data = self._filesystem.read(path)
        if length is None:
            length = len(data) - offset
        mapped_data = data[offset : offset + length]

        vm = process.virtual_memory
        if vm is None:
            msg = f"Process {pid} has no virtual memory"
            raise MmapError(msg)

        page_size = vm.page_size
        num_pages = (length + page_size - 1) // page_size

        # Find the next available vpn (after all existing mappings)
        existing = vm.page_table.mappings()
        next_vpn = max(existing.keys(), default=-1) + 1

        if shared:
            self._mmap_shared(
                pid=pid,
                vm=vm,
                inode_number=info.inode_number,
                next_vpn=next_vpn,
                num_pages=num_pages,
                mapped_data=mapped_data,
                page_size=page_size,
            )
        else:
            # MAP_PRIVATE: allocate fresh frames and copy data in
            frames = self._memory.allocate(pid, num_pages=num_pages)
            for i, frame in enumerate(frames):
                vm.page_table.map(virtual_page=next_vpn + i, physical_frame=frame)
                chunk_start = i * page_size
                chunk_end = min(chunk_start + page_size, len(mapped_data))
                if chunk_start < len(mapped_data):
                    storage = vm.physical_storage(frame)
                    storage[: chunk_end - chunk_start] = mapped_data[chunk_start:chunk_end]

        # Record the region
        region = MmapRegion(
            path=path,
            inode_number=info.inode_number,
            start_vpn=next_vpn,
            num_pages=num_pages,
            offset=offset,
            length=length,
            shared=shared,
        )
        self._mmap_regions.setdefault(pid, {})[next_vpn] = region

        return next_vpn * page_size

    def _mmap_shared(
        self,
        *,
        pid: int,
        vm: VirtualMemory,
        inode_number: int,
        next_vpn: int,
        num_pages: int,
        mapped_data: bytes,
        page_size: int,
    ) -> None:
        """Set up MAP_SHARED pages — reuse cached frames or allocate new ones.

        Args:
            pid: The process ID.
            vm: The process's virtual memory.
            inode_number: Inode for the shared-frame cache key.
            next_vpn: First virtual page number for the mapping.
            num_pages: Number of pages to map.
            mapped_data: The file data to load.
            page_size: Size of each page in bytes.

        """
        assert self._memory is not None  # noqa: S101

        for i in range(num_pages):
            cache_key = (inode_number, i)
            if cache_key in self._shared_file_frames:
                # Reuse existing shared frame
                frame, storage = self._shared_file_frames[cache_key]
                vm.page_table.map(virtual_page=next_vpn + i, physical_frame=frame)
                vm.share_physical(frame=frame, storage=storage)
                self._memory.increment_refcount(frame)
                self._memory.share_frame(pid=pid, frame=frame)
            else:
                # First mapper: allocate a new frame
                frame = self._memory.allocate_one(pid)
                vm.page_table.map(virtual_page=next_vpn + i, physical_frame=frame)
                storage = vm.physical_storage(frame)
                chunk_start = i * page_size
                chunk_end = min(chunk_start + page_size, len(mapped_data))
                if chunk_start < len(mapped_data):
                    storage[: chunk_end - chunk_start] = mapped_data[chunk_start:chunk_end]
                self._shared_file_frames[cache_key] = (frame, storage)

    def munmap_file(self, *, pid: int, virtual_address: int) -> None:
        """Unmap a memory-mapped region from a process's address space.

        For shared regions, data is written back to the file (implicit
        msync).  Page table entries are removed and frames are released.

        Args:
            pid: The process that owns the mapping.
            virtual_address: The starting virtual address of the mapping.

        Raises:
            MmapError: If the PID or address is invalid.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101
        assert self._filesystem is not None  # noqa: S101

        if pid not in self._processes:
            msg = f"Process {pid} not found"
            raise MmapError(msg)

        process = self._processes[pid]
        vm = process.virtual_memory
        if vm is None:
            msg = f"Process {pid} has no virtual memory"
            raise MmapError(msg)

        page_size = vm.page_size
        start_vpn = virtual_address // page_size
        pid_regions = self._mmap_regions.get(pid, {})
        region = pid_regions.get(start_vpn)
        if region is None:
            msg = f"No mmap region at address {virtual_address} for pid {pid}"
            raise MmapError(msg)

        # For shared mappings, write back to the file before unmapping
        if region.shared:
            self._writeback_shared(region, vm)

        # Unmap pages and release frames
        for i in range(region.num_pages):
            vpn = region.start_vpn + i
            frame = vm.page_table.translate(vpn)
            vm.page_table.unmap(virtual_page=vpn)
            self._memory.decrement_refcount(frame)

            # Clean up shared frame cache if no one else references it
            if region.shared:
                cache_key = (region.inode_number, i)
                if cache_key in self._shared_file_frames and self._memory.refcount(frame) == 0:
                    del self._shared_file_frames[cache_key]

        # Remove the region from tracking
        del pid_regions[start_vpn]
        if not pid_regions:
            self._mmap_regions.pop(pid, None)

    def _writeback_shared(
        self,
        region: MmapRegion,
        vm: VirtualMemory,
    ) -> None:
        """Write shared mapping data back to the filesystem.

        Args:
            region: The mmap region to write back.
            vm: The process's virtual memory.

        """
        assert self._filesystem is not None  # noqa: S101

        # Assemble the mapped bytes from physical storage
        chunks: list[bytes] = []
        for i in range(region.num_pages):
            vpn = region.start_vpn + i
            frame = vm.page_table.translate(vpn)
            storage = vm.physical_storage(frame)
            chunks.append(bytes(storage))
        mapped_bytes = b"".join(chunks)[: region.length]

        # Splice into original file at the region's offset
        original = self._filesystem.read(region.path)
        updated = (
            original[: region.offset] + mapped_bytes + original[region.offset + region.length :]
        )
        self._filesystem.write(region.path, updated)

    def msync_file(self, *, pid: int, virtual_address: int) -> None:
        """Sync a shared mapping's data back to the underlying file.

        Only valid for MAP_SHARED regions.  The mapping remains active
        after syncing — this is a "save" operation, not an unmap.

        Args:
            pid: The process that owns the mapping.
            virtual_address: The starting virtual address of the mapping.

        Raises:
            MmapError: If the region is private, not found, or PID invalid.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101

        if pid not in self._processes:
            msg = f"Process {pid} not found"
            raise MmapError(msg)

        process = self._processes[pid]
        vm = process.virtual_memory
        if vm is None:
            msg = f"Process {pid} has no virtual memory"
            raise MmapError(msg)

        page_size = vm.page_size
        start_vpn = virtual_address // page_size
        pid_regions = self._mmap_regions.get(pid, {})
        region = pid_regions.get(start_vpn)
        if region is None:
            msg = f"No mmap region at address {virtual_address} for pid {pid}"
            raise MmapError(msg)

        if not region.shared:
            msg = "Cannot msync a private mapping"
            raise MmapError(msg)

        self._writeback_shared(region, vm)

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

    def exec_process(self, *, pid: int, program: Callable[[], str]) -> None:
        """Load a program into an existing process.

        Analogous to Unix ``execve()`` — replace the process's code with
        a new program.  In real Unix, exec replaces the entire address
        space; here we just store the callable.

        Args:
            pid: PID of the process to load the program into.
            program: A callable that returns a string (the program's output).

        Raises:
            ValueError: If the process does not exist.

        """
        self._require_running()
        process = self._processes.get(pid)
        if process is None:
            msg = f"Process {pid} not found"
            raise ValueError(msg)
        process.program = program

    def run_process(self, *, pid: int) -> dict[str, Any]:
        """Dispatch, execute, and terminate a process.

        This is the full lifecycle: READY → RUNNING → execute → TERMINATED.
        Memory is freed immediately, but the process stays in the table
        as a zombie if it has a living parent (so the parent can collect
        its exit code).  Orphans are deleted immediately.

        Args:
            pid: PID of the process to run.

        Returns:
            A dict with 'output' and 'exit_code' from the program.

        Raises:
            ValueError: If the process does not exist or has no program.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101

        process = self._processes.get(pid)
        if process is None:
            msg = f"Process {pid} not found"
            raise ValueError(msg)
        if process.program is None:
            msg = f"No program loaded in process {pid}"
            raise ValueError(msg)

        process.dispatch()
        process.execute()
        output = process.output
        exit_code = process.exit_code

        process.terminate()
        self._cleanup_fd_table(pid)
        self._cleanup_shm(pid)
        self._cleanup_mmap_regions(pid)
        self._memory.free(pid)
        if self._resource_manager is not None:
            self._resource_manager.remove_process(pid)
        if self._ordering_manager is not None:
            self._ordering_manager.remove_process(pid)

        self._zombie_or_delete(process)

        return {"output": output, "exit_code": exit_code}

    def terminate_process(self, *, pid: int) -> None:
        """Terminate a process and free its resources.

        The kernel coordinates cleanup across subsystems:
        1. Terminate the process (RUNNING → TERMINATED).
        2. Free its memory frames.
        3. Keep as zombie if a living parent exists, else delete.

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
            self._cleanup_fd_table(pid)
            self._cleanup_shm(pid)
            self._cleanup_mmap_regions(pid)
            self._memory.free(pid)
            if self._resource_manager is not None:
                self._resource_manager.remove_process(pid)
            if self._ordering_manager is not None:
                self._ordering_manager.remove_process(pid)
            self._zombie_or_delete(process)

    def register_signal_handler(
        self,
        pid: int,
        signal: Signal,
        handler: Callable[[], None],
    ) -> None:
        """Register a handler to be called when a signal is delivered.

        For catchable signals the handler *replaces* the default action
        (except SIGCONT, where the handler is additive).  Uncatchable
        signals (SIGKILL, SIGSTOP) reject handler registration outright.

        Args:
            pid: The target process.
            signal: The signal to handle.
            handler: A callable invoked instead of the default action.

        Raises:
            SignalError: If the process does not exist or the signal is
                uncatchable.

        """
        self._require_running()
        if pid not in self._processes:
            msg = f"Process {pid} not found"
            raise SignalError(msg)
        if signal in UNCATCHABLE:
            msg = f"{signal.name} is uncatchable"
            raise SignalError(msg)
        self._signal_handlers[(pid, signal)] = handler

    def send_signal(self, pid: int, signal: Signal) -> None:
        """Deliver a signal to a process.

        Delivery logic:
            1. **SIGCONT special case** — handler fires (if any), then
               the process always resumes if WAITING.
            2. **Catchable with handler** — handler fires, default
               action is *replaced* (skipped).
            3. **Uncatchable / no handler** — default action from
               ``DEFAULT_ACTIONS`` table.

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

        handler = self._signal_handlers.get((pid, signal))

        # SIGCONT special case: handler is additive (fires AND resumes)
        if signal is Signal.SIGCONT:
            if handler is not None:
                handler()
            if process.state is ProcessState.WAITING:
                process.wake()
            return

        # Catchable signal with a handler: handler replaces default action
        if signal not in UNCATCHABLE and handler is not None:
            handler()
            return

        # Uncatchable or no handler: perform the default action
        action = DEFAULT_ACTIONS[signal]
        match action:
            case SignalAction.TERMINATE:
                process.force_terminate()
                assert self._memory is not None  # noqa: S101
                self._cleanup_fd_table(pid)
                self._cleanup_shm(pid)
                self._cleanup_mmap_regions(pid)
                self._memory.free(pid)
                if self._resource_manager is not None:
                    self._resource_manager.remove_process(pid)
                if self._ordering_manager is not None:
                    self._ordering_manager.remove_process(pid)
                self._zombie_or_delete(process)
            case SignalAction.STOP:
                process.wait()
            case SignalAction.CONTINUE | SignalAction.IGNORE:
                pass

    # -- Wait / zombie helpers -------------------------------------------------

    def _zombie_or_delete(self, process: Process) -> None:
        """Keep a terminated process as a zombie or delete it.

        If the process has a living parent in the process table, it
        stays as a zombie so the parent can collect its exit code.
        Otherwise it is deleted immediately.  In either case, if the
        parent is waiting, it is woken.
        """
        parent_pid = process.parent_pid
        if parent_pid is not None and parent_pid in self._processes:
            # Stay as zombie — parent may want to collect
            self._notify_waiting_parent(process)
        else:
            # Orphan — clean up immediately
            self._cleanup_signal_handlers(process.pid)
            del self._processes[process.pid]

    def _notify_waiting_parent(self, child: Process) -> None:
        """Wake the parent if it is waiting for this child.

        The parent must be in WAITING state and its wait_target must
        match: either -1 (any child) or the child's PID.
        """
        if child.parent_pid is None:
            return
        parent = self._processes.get(child.parent_pid)
        if parent is None:
            return
        if parent.state is not ProcessState.WAITING:
            return
        target = parent.wait_target
        if target in {-1, child.pid}:
            parent.wake()
            parent.wait_target = None

    def _collect_child(self, child: Process) -> dict[str, Any]:
        """Reap a zombie child and remove it from the process table.

        Extract the child's exit info, clean up signal handlers, and
        delete the process from the table.

        Args:
            child: A terminated child process to collect.

        Returns:
            Dict with child_pid, exit_code, and output.

        """
        result: dict[str, Any] = {
            "child_pid": child.pid,
            "exit_code": child.exit_code,
            "output": child.output,
        }
        self._cleanup_signal_handlers(child.pid)
        del self._processes[child.pid]
        return result

    def _cleanup_signal_handlers(self, pid: int) -> None:
        """Remove all signal handlers registered for a process."""
        keys_to_remove = [key for key in self._signal_handlers if key[0] == pid]
        for key in keys_to_remove:
            del self._signal_handlers[key]

    def _cleanup_fd_table(self, pid: int) -> None:
        """Remove the fd table for a process (idempotent).

        Called during process termination to release all open fds.
        """
        self._fd_tables.pop(pid, None)

    def _cleanup_mmap_regions(self, pid: int) -> None:
        """Unmap all mmap regions for a process (idempotent).

        For shared regions, data is written back to the file.
        Called before freeing process memory during termination.
        """
        pid_regions = self._mmap_regions.get(pid)
        if not pid_regions:
            return

        process = self._processes.get(pid)
        if process is None:
            self._mmap_regions.pop(pid, None)
            return

        vm = process.virtual_memory
        if vm is None:
            self._mmap_regions.pop(pid, None)
            return

        # Iterate over a copy since munmap modifies the dict
        for _start_vpn, region in list(pid_regions.items()):
            if region.shared:
                self._writeback_shared(region, vm)

            for i in range(region.num_pages):
                vpn = region.start_vpn + i
                mappings = vm.page_table.mappings()
                if vpn in mappings:
                    frame = mappings[vpn]
                    vm.page_table.unmap(virtual_page=vpn)
                    self._memory.decrement_refcount(frame)  # type: ignore[union-attr]

                    if region.shared:
                        cache_key = (region.inode_number, i)
                        if (
                            cache_key in self._shared_file_frames
                            and self._memory.refcount(frame) == 0  # type: ignore[union-attr]
                        ):
                            del self._shared_file_frames[cache_key]

        self._mmap_regions.pop(pid, None)

    # -- Shared memory IPC ---------------------------------------------------

    def shm_create(self, *, name: str, size: int, pid: int) -> SharedMemorySegment:
        """Create a named shared memory segment.

        Allocate physical frames owned by the kernel (pid 0) and create
        backing storage.  The segment is registered by name but no
        process is attached yet.

        Args:
            name: Unique identifier for the segment.
            size: Requested size in bytes (must be > 0).
            pid: The process requesting creation.

        Returns:
            The newly created SharedMemorySegment.

        Raises:
            SharedMemoryError: If the name is taken, size is invalid,
                or the pid does not exist.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101

        if name in self._shared_memory:
            msg = f"Shared memory '{name}' already exists"
            raise SharedMemoryError(msg)
        if size <= 0:
            msg = f"Invalid size: {size}"
            raise SharedMemoryError(msg)
        if pid not in self._processes:
            msg = f"Process {pid} not found"
            raise SharedMemoryError(msg)

        page_size = VirtualMemory().page_size
        num_pages = (size + page_size - 1) // page_size

        # Allocate frames owned by the kernel (pid 0)
        frames: list[int] = []
        storage: list[bytearray] = []
        for _ in range(num_pages):
            frame = self._memory.allocate_one(0)
            frames.append(frame)
            storage.append(bytearray(page_size))

        segment = SharedMemorySegment(
            name=name,
            size=size,
            num_pages=num_pages,
            frames=frames,
            storage=storage,
            creator_pid=pid,
        )
        self._shared_memory[name] = segment
        return segment

    def shm_attach(self, *, name: str, pid: int) -> int:
        """Attach a process to a shared memory segment.

        Map the segment's frames into the process's virtual address
        space and increment refcounts.

        Args:
            name: Name of the segment to attach to.
            pid: The process to attach.

        Returns:
            The virtual address where the segment is mapped.

        Raises:
            SharedMemoryError: If the segment doesn't exist, is marked
                for deletion, the pid doesn't exist, or is already
                attached.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101

        segment = self._shared_memory.get(name)
        if segment is None:
            msg = f"Shared memory '{name}' not found"
            raise SharedMemoryError(msg)
        if segment.marked_for_deletion:
            msg = f"Shared memory '{name}' is marked for deletion"
            raise SharedMemoryError(msg)

        process = self._processes.get(pid)
        if process is None:
            msg = f"Process {pid} not found"
            raise SharedMemoryError(msg)
        if pid in segment.attachments:
            msg = f"Process {pid} already attached to '{name}'"
            raise SharedMemoryError(msg)

        vm = process.virtual_memory
        if vm is None:
            msg = f"Process {pid} has no virtual memory"
            raise SharedMemoryError(msg)

        # Find the next available VPN
        existing = vm.page_table.mappings()
        next_vpn = max(existing.keys(), default=-1) + 1

        for i, (frame, store) in enumerate(zip(segment.frames, segment.storage, strict=True)):
            vm.page_table.map(virtual_page=next_vpn + i, physical_frame=frame)
            vm.share_physical(frame=frame, storage=store)
            self._memory.increment_refcount(frame)
            self._memory.share_frame(pid=pid, frame=frame)

        segment.attachments[pid] = next_vpn
        page_size = vm.page_size
        return next_vpn * page_size

    def shm_detach(self, *, name: str, pid: int) -> None:
        """Detach a process from a shared memory segment.

        Unmap the segment's frames from the process's VAS and decrement
        refcounts.  If the segment is marked for deletion and no
        attachments remain, free it.

        Args:
            name: Name of the segment.
            pid: The process to detach.

        Raises:
            SharedMemoryError: If the segment doesn't exist or the pid
                is not attached.

        """
        self._require_running()
        assert self._memory is not None  # noqa: S101

        segment = self._shared_memory.get(name)
        if segment is None:
            msg = f"Shared memory '{name}' not found"
            raise SharedMemoryError(msg)
        if pid not in segment.attachments:
            msg = f"Process {pid} not attached to '{name}'"
            raise SharedMemoryError(msg)

        process = self._processes.get(pid)
        if process is not None:
            vm = process.virtual_memory
            if vm is not None:
                start_vpn = segment.attachments[pid]
                for i, frame in enumerate(segment.frames):
                    vm.page_table.unmap(virtual_page=start_vpn + i)
                    self._memory.decrement_refcount(frame)
                    self._memory.unshare_frame(pid=pid, frame=frame)

        del segment.attachments[pid]

        if segment.marked_for_deletion and not segment.attachments:
            self._shm_free_segment(name)

    def shm_write(self, *, name: str, pid: int, data: bytes, offset: int = 0) -> None:
        """Write data to a shared memory segment.

        Args:
            name: Name of the segment.
            pid: The process writing (must be attached).
            data: Bytes to write.
            offset: Byte offset within the segment.

        Raises:
            SharedMemoryError: If the segment doesn't exist, pid is not
                attached, or the write exceeds segment bounds.

        """
        self._require_running()

        segment = self._shared_memory.get(name)
        if segment is None:
            msg = f"Shared memory '{name}' not found"
            raise SharedMemoryError(msg)
        if pid not in segment.attachments:
            msg = f"Process {pid} not attached to '{name}'"
            raise SharedMemoryError(msg)
        if offset + len(data) > segment.size:
            msg = f"Write exceeds segment size ({offset + len(data)} > {segment.size})"
            raise SharedMemoryError(msg)

        process = self._processes.get(pid)
        if process is None or process.virtual_memory is None:
            msg = f"Process {pid} not found or has no virtual memory"
            raise SharedMemoryError(msg)

        vm = process.virtual_memory
        start_vpn = segment.attachments[pid]
        vm.write(virtual_address=start_vpn * vm.page_size + offset, data=data)

    def shm_read(self, *, name: str, pid: int, offset: int = 0, size: int | None = None) -> bytes:
        """Read data from a shared memory segment.

        Args:
            name: Name of the segment.
            pid: The process reading (must be attached).
            offset: Byte offset within the segment.
            size: Number of bytes to read (defaults to remaining).

        Returns:
            The bytes read from the segment.

        Raises:
            SharedMemoryError: If the segment doesn't exist, pid is not
                attached, or the read exceeds bounds.

        """
        self._require_running()

        segment = self._shared_memory.get(name)
        if segment is None:
            msg = f"Shared memory '{name}' not found"
            raise SharedMemoryError(msg)
        if pid not in segment.attachments:
            msg = f"Process {pid} not attached to '{name}'"
            raise SharedMemoryError(msg)

        if size is None:
            size = segment.size - offset
        if offset + size > segment.size:
            msg = f"Read exceeds segment size ({offset + size} > {segment.size})"
            raise SharedMemoryError(msg)

        process = self._processes.get(pid)
        if process is None or process.virtual_memory is None:
            msg = f"Process {pid} not found or has no virtual memory"
            raise SharedMemoryError(msg)

        vm = process.virtual_memory
        start_vpn = segment.attachments[pid]
        return vm.read(virtual_address=start_vpn * vm.page_size + offset, size=size)

    def shm_destroy(self, *, name: str) -> None:
        """Destroy a shared memory segment.

        If no processes are attached, free immediately.  Otherwise, mark
        for deletion — the last detach will free it.

        Args:
            name: Name of the segment.

        Raises:
            SharedMemoryError: If the segment doesn't exist.

        """
        self._require_running()

        segment = self._shared_memory.get(name)
        if segment is None:
            msg = f"Shared memory '{name}' not found"
            raise SharedMemoryError(msg)

        if not segment.attachments:
            self._shm_free_segment(name)
        else:
            segment.marked_for_deletion = True

    def shm_list(self) -> list[dict[str, object]]:
        """List all shared memory segments.

        Returns:
            List of dicts with segment info.

        """
        self._require_running()
        return [
            {
                "name": seg.name,
                "size": seg.size,
                "num_pages": seg.num_pages,
                "creator_pid": seg.creator_pid,
                "attached": len(seg.attachments),
                "marked_for_deletion": seg.marked_for_deletion,
            }
            for seg in self._shared_memory.values()
        ]

    def _shm_free_segment(self, name: str) -> None:
        """Release the kernel's base reference for a segment and delete it.

        Called when a segment has no attachments and should be freed.
        """
        assert self._memory is not None  # noqa: S101

        segment = self._shared_memory.get(name)
        if segment is None:
            return

        # Decrement kernel's base refcount for each frame
        for frame in segment.frames:
            self._memory.decrement_refcount(frame)
            self._memory.unshare_frame(pid=0, frame=frame)

        del self._shared_memory[name]

    def _cleanup_shm(self, pid: int) -> None:
        """Detach a process from all shared memory segments.

        Called during termination BEFORE ``memory.free(pid)``.  Does NOT
        decrement refcounts — ``memory.free(pid)`` handles that via
        ``_page_tables[pid]`` entries.

        If a segment is marked for deletion and this was the last
        attachment, free the segment.
        """
        for seg in list(self._shared_memory.values()):
            if pid not in seg.attachments:
                continue

            # Unmap from VAS (but don't decrement refcounts — free() will)
            process = self._processes.get(pid)
            if process is not None:
                vm = process.virtual_memory
                if vm is not None:
                    start_vpn = seg.attachments[pid]
                    for i in range(seg.num_pages):
                        vpn = start_vpn + i
                        if vpn in vm.page_table.mappings():
                            vm.page_table.unmap(virtual_page=vpn)

            del seg.attachments[pid]

            if seg.marked_for_deletion and not seg.attachments:
                self._shm_free_segment(seg.name)

    def wait_process(self, *, parent_pid: int) -> dict[str, Any] | None:
        """Wait for any child of the parent to terminate.

        If a terminated child already exists, collect it immediately
        and return the result.  Otherwise, block the parent (transition
        to WAITING) and return None — the parent will be woken when a
        child terminates later.

        Args:
            parent_pid: PID of the parent process.

        Returns:
            Dict with child info if a zombie was collected, or None if
            the parent is now blocked waiting.

        Raises:
            ValueError: If the parent does not exist or has no children.

        """
        self._require_running()
        parent = self._processes.get(parent_pid)
        if parent is None:
            msg = f"Process {parent_pid} not found"
            raise ValueError(msg)

        children = [p for p in self._processes.values() if p.parent_pid == parent_pid]
        if not children:
            msg = f"Process {parent_pid} has no children"
            raise ValueError(msg)

        # Check for an already-terminated child
        for child in children:
            if child.state is ProcessState.TERMINATED:
                return self._collect_child(child)

        # No terminated child yet — block the parent
        parent.dispatch()
        parent.wait()
        parent.wait_target = -1
        return None

    def waitpid_process(self, *, parent_pid: int, child_pid: int) -> dict[str, Any] | None:
        """Wait for a specific child to terminate.

        If the child is already terminated, collect it immediately.
        Otherwise, block the parent and return None.

        Args:
            parent_pid: PID of the parent process.
            child_pid: PID of the specific child to wait for.

        Returns:
            Dict with child info if collected, or None if blocked.

        Raises:
            ValueError: If parent or child not found, or child is not
                a child of the parent.

        """
        self._require_running()
        parent = self._processes.get(parent_pid)
        if parent is None:
            msg = f"Process {parent_pid} not found"
            raise ValueError(msg)

        child = self._processes.get(child_pid)
        if child is None:
            msg = f"Process {child_pid} not found"
            raise ValueError(msg)
        if child.parent_pid != parent_pid:
            msg = f"Process {child_pid} is not a child of {parent_pid}"
            raise ValueError(msg)

        if child.state is ProcessState.TERMINATED:
            return self._collect_child(child)

        # Block the parent until this specific child terminates
        parent.dispatch()
        parent.wait()
        parent.wait_target = child_pid
        return None

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

    # -- Synchronization delegation ------------------------------------------

    def create_mutex(self, name: str) -> Mutex:
        """Create a named mutex via the sync manager.

        Args:
            name: Unique name for the mutex.

        Returns:
            The newly created Mutex.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        return self._sync_manager.create_mutex(name)

    def acquire_mutex(self, name: str, *, tid: int, pid: int | None = None) -> bool:
        """Acquire a named mutex on behalf of a thread.

        Args:
            name: Name of the mutex.
            tid: Thread ID of the caller.
            pid: Optional process ID for priority inheritance and ordering.

        Returns:
            True if acquired, False if queued or rejected by ordering.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101

        # Ordering check before acquire
        if (
            pid is not None
            and self._ordering_manager is not None
            and not self._ordering_manager.check_acquire(pid, f"mutex:{name}")
        ):
            return False

        mutex = self._sync_manager.get_mutex(name)
        acquired = mutex.acquire(tid)

        if pid is not None and self._pi_manager is not None:
            if acquired:
                self._pi_manager.on_acquire(name, pid)
            else:
                self._pi_manager.on_block(name, pid, self._processes)

        # Track acquisition in ordering manager
        if acquired and pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_acquire(pid, f"mutex:{name}")

        return acquired

    def release_mutex(self, name: str, *, tid: int, pid: int | None = None) -> int | None:
        """Release a named mutex on behalf of a thread.

        Args:
            name: Name of the mutex.
            tid: Thread ID of the caller.
            pid: Optional process ID for priority inheritance and ordering.

        Returns:
            The TID of the next waiter, or None.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        mutex = self._sync_manager.get_mutex(name)
        next_tid = mutex.release(tid)
        if pid is not None and self._pi_manager is not None:
            self._pi_manager.on_release(name, pid, new_holder_pid=None, processes=self._processes)
        if pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_release(pid, f"mutex:{name}")
        return next_tid

    def create_semaphore(self, name: str, *, count: int) -> Semaphore:
        """Create a named semaphore via the sync manager.

        Args:
            name: Unique name for the semaphore.
            count: Initial available count.

        Returns:
            The newly created Semaphore.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        return self._sync_manager.create_semaphore(name, count=count)

    def acquire_semaphore(self, name: str, *, tid: int, pid: int | None = None) -> bool:
        """Acquire a named semaphore on behalf of a thread.

        Args:
            name: Name of the semaphore.
            tid: Thread ID of the caller.
            pid: Optional process ID for ordering checks.

        Returns:
            True if acquired, False if queued or rejected by ordering.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101

        if (
            pid is not None
            and self._ordering_manager is not None
            and not self._ordering_manager.check_acquire(pid, f"sem:{name}")
        ):
            return False

        sem = self._sync_manager.get_semaphore(name)
        acquired = sem.acquire(tid)

        if acquired and pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_acquire(pid, f"sem:{name}")

        return acquired

    def release_semaphore(self, name: str, *, pid: int | None = None) -> int | None:
        """Release a named semaphore.

        Args:
            name: Name of the semaphore.
            pid: Optional process ID for ordering tracking.

        Returns:
            The TID of the woken waiter, or None.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        sem = self._sync_manager.get_semaphore(name)
        result = sem.release()
        if pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_release(pid, f"sem:{name}")
        return result

    def create_condition(self, name: str, *, mutex_name: str) -> Condition:
        """Create a named condition variable via the sync manager.

        Args:
            name: Unique name for the condition.
            mutex_name: Name of the associated mutex.

        Returns:
            The newly created Condition.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        return self._sync_manager.create_condition(name, mutex_name=mutex_name)

    def condition_wait(self, name: str, *, tid: int) -> None:
        """Wait on a named condition variable.

        Args:
            name: Name of the condition.
            tid: Thread ID of the caller.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        cond = self._sync_manager.get_condition(name)
        cond.wait(tid)

    def condition_notify(self, name: str) -> int | None:
        """Notify one waiter on a named condition variable.

        Args:
            name: Name of the condition.

        Returns:
            The TID of the woken thread, or None.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        cond = self._sync_manager.get_condition(name)
        return cond.notify()

    def condition_notify_all(self, name: str) -> list[int]:
        """Notify all waiters on a named condition variable.

        Args:
            name: Name of the condition.

        Returns:
            List of woken TIDs.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        cond = self._sync_manager.get_condition(name)
        return cond.notify_all()

    # -- Reader-writer lock delegation ---------------------------------------

    def create_rwlock(self, name: str) -> ReadWriteLock:
        """Create a named reader-writer lock via the sync manager.

        Args:
            name: Unique name for the lock.

        Returns:
            The newly created ReadWriteLock.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        return self._sync_manager.create_rwlock(name)

    def acquire_read_lock(self, name: str, *, tid: int, pid: int | None = None) -> bool:
        """Acquire read access on a named reader-writer lock.

        Args:
            name: Name of the lock.
            tid: Thread ID of the caller.
            pid: Optional process ID for ordering checks.

        Returns:
            True if acquired, False if queued or rejected by ordering.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101

        if (
            pid is not None
            and self._ordering_manager is not None
            and not self._ordering_manager.check_acquire(pid, f"rwlock:{name}")
        ):
            return False

        rwl = self._sync_manager.get_rwlock(name)
        acquired = rwl.acquire_read(tid)

        if acquired and pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_acquire(pid, f"rwlock:{name}")

        return acquired

    def acquire_write_lock(self, name: str, *, tid: int, pid: int | None = None) -> bool:
        """Acquire write access on a named reader-writer lock.

        Args:
            name: Name of the lock.
            tid: Thread ID of the caller.
            pid: Optional process ID for ordering checks.

        Returns:
            True if acquired, False if queued or rejected by ordering.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101

        if (
            pid is not None
            and self._ordering_manager is not None
            and not self._ordering_manager.check_acquire(pid, f"rwlock:{name}")
        ):
            return False

        rwl = self._sync_manager.get_rwlock(name)
        acquired = rwl.acquire_write(tid)

        if acquired and pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_acquire(pid, f"rwlock:{name}")

        return acquired

    def release_read_lock(self, name: str, *, tid: int, pid: int | None = None) -> list[int]:
        """Release read access on a named reader-writer lock.

        Args:
            name: Name of the lock.
            tid: Thread ID of the caller.
            pid: Optional process ID for ordering tracking.

        Returns:
            List of TIDs promoted from the wait queue.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        rwl = self._sync_manager.get_rwlock(name)
        result = rwl.release_read(tid)
        if pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_release(pid, f"rwlock:{name}")
        return result

    def release_write_lock(self, name: str, *, tid: int, pid: int | None = None) -> list[int]:
        """Release write access on a named reader-writer lock.

        Args:
            name: Name of the lock.
            tid: Thread ID of the caller.
            pid: Optional process ID for ordering tracking.

        Returns:
            List of TIDs promoted from the wait queue.

        """
        self._require_running()
        assert self._sync_manager is not None  # noqa: S101
        rwl = self._sync_manager.get_rwlock(name)
        result = rwl.release_write(tid)
        if pid is not None and self._ordering_manager is not None:
            self._ordering_manager.on_release(pid, f"rwlock:{name}")
        return result

    # -- DNS operations ------------------------------------------------------

    def dns_register(self, hostname: str, address: str) -> DnsRecord:
        """Register a DNS A record (hostname → IP).

        Args:
            hostname: The human-readable name to register.
            address: The IP address to map to.

        Returns:
            The newly created DnsRecord.

        Raises:
            DnsError: If the hostname is already registered.

        """
        self._require_running()
        assert self._dns_resolver is not None  # noqa: S101
        return self._dns_resolver.register(hostname, address)

    def dns_lookup(self, hostname: str) -> str:
        """Resolve a hostname to its IP address.

        Args:
            hostname: The hostname to look up.

        Returns:
            The IP address string.

        Raises:
            DnsError: If the hostname is not found.

        """
        self._require_running()
        assert self._dns_resolver is not None  # noqa: S101
        return self._dns_resolver.lookup(hostname)

    def dns_remove(self, hostname: str) -> None:
        """Remove a DNS record.

        Args:
            hostname: The hostname to remove.

        Raises:
            DnsError: If the hostname is not found.

        """
        self._require_running()
        assert self._dns_resolver is not None  # noqa: S101
        self._dns_resolver.remove(hostname)

    def dns_list(self) -> list[dict[str, str]]:
        """Return all DNS records as dicts.

        Returns:
            List of ``{"hostname": ..., "address": ...}`` dicts,
            sorted by hostname.

        """
        self._require_running()
        assert self._dns_resolver is not None  # noqa: S101
        return [
            {"hostname": r.hostname, "address": r.address}
            for r in self._dns_resolver.list_records()
        ]

    def dns_flush(self) -> int:
        """Remove all DNS records.

        Returns:
            The number of records removed.

        """
        self._require_running()
        assert self._dns_resolver is not None  # noqa: S101
        return self._dns_resolver.flush()

    # -- Journal operations --------------------------------------------------

    def journal_status(self) -> dict[str, Any]:
        """Return a summary of journal transaction counts.

        Returns:
            Dict with total, active, committed, and aborted counts.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        return self._filesystem.journal_status()

    def journal_checkpoint(self) -> None:
        """Take a journal checkpoint — snapshot the current filesystem state."""
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        self._filesystem.checkpoint()

    def journal_crash(self) -> None:
        """Simulate a crash — abort active transactions, restore from checkpoint."""
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        self._filesystem.simulate_crash()

    def journal_recover(self) -> int:
        """Recover from a crash — replay committed transactions.

        Returns:
            The number of transactions replayed.

        """
        self._require_running()
        assert self._filesystem is not None  # noqa: S101
        return self._filesystem.recover()

    # -- Socket operations ---------------------------------------------------

    def _require_socket(self, sock_id: int) -> "SocketManager":
        """Return the socket manager after validating the socket ID exists.

        Args:
            sock_id: The socket ID to validate.

        Returns:
            The socket manager.

        Raises:
            SocketError: If the manager is None or the socket is not found.

        """
        if self._socket_manager is None:
            msg = "Socket manager not available"
            raise SocketError(msg)
        if self._socket_manager.get_socket(sock_id) is None:
            msg = f"Socket {sock_id} not found"
            raise SocketError(msg)
        return self._socket_manager

    def socket_create(self) -> dict[str, int | str]:
        """Create a new socket and return its info.

        Returns:
            Dict with ``sock_id`` and ``state``.

        """
        self._require_running()
        if self._socket_manager is None:
            msg = "Socket manager not available"
            raise SocketError(msg)
        sock = self._socket_manager.create_socket()
        return {"sock_id": sock.sock_id, "state": str(sock.state)}

    def socket_bind(self, sock_id: int, address: str, port: int) -> None:
        """Bind a socket to an address and port.

        Args:
            sock_id: The socket to bind.
            address: The address to bind to.
            port: The port number.

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        try:
            sock.bind(address=address, port=port)
        except RuntimeError as e:
            raise SocketError(str(e)) from e

    def socket_listen(self, sock_id: int) -> None:
        """Mark a socket as listening for connections.

        Args:
            sock_id: The bound socket to start listening.

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        try:
            sock.listen()
        except RuntimeError as e:
            raise SocketError(str(e)) from e

    def socket_connect(self, sock_id: int, address: str, port: int) -> None:
        """Connect a socket to a listening server.

        Args:
            sock_id: The client socket.
            address: The server address.
            port: The server port.

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        try:
            sm.connect(sock, address=address, port=port)
        except ConnectionError as e:
            raise SocketError(str(e)) from e

    def socket_accept(self, sock_id: int) -> dict[str, int | str] | None:
        """Accept a pending connection on a listening socket.

        Args:
            sock_id: The listening socket.

        Returns:
            Dict with peer ``sock_id`` and ``state``, or None.

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        peer = sm.accept(sock)
        if peer is None:
            return None
        return {"sock_id": peer.sock_id, "state": str(peer.state)}

    def socket_send(self, sock_id: int, data: bytes) -> None:
        """Send data over a connected socket.

        Args:
            sock_id: The sending socket.
            data: The bytes to send.

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        try:
            sm.send(sock, data)
        except RuntimeError as e:
            raise SocketError(str(e)) from e

    def socket_recv(self, sock_id: int) -> bytes:
        """Receive data from a connected socket.

        Args:
            sock_id: The receiving socket.

        Returns:
            The received bytes (empty if no data available).

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        return sm.recv(sock)

    def socket_close(self, sock_id: int) -> None:
        """Close a socket.

        Args:
            sock_id: The socket to close.

        """
        self._require_running()
        sm = self._require_socket(sock_id)
        sock = sm.get_socket(sock_id)
        assert sock is not None  # noqa: S101
        sock.close()

    def socket_list(self) -> list[dict[str, object]]:
        """List all sockets managed by the kernel.

        Returns:
            List of dicts with socket info.

        """
        self._require_running()
        if self._socket_manager is None:
            return []
        return [
            {
                "sock_id": s.sock_id,
                "state": str(s.state),
                "address": s.address,
                "port": s.port,
            }
            for s in self._socket_manager.list_sockets()
        ]

    # -- /proc virtual filesystem ---------------------------------------------

    def proc_read(self, path: str) -> str:
        """Read a virtual /proc file.

        Delegate to the ProcFilesystem, converting ProcError to ValueError
        so that the syscall layer can wrap it in SyscallError.

        Args:
            path: Absolute path starting with ``/proc/``.

        Returns:
            The generated file content.

        Raises:
            ValueError: If the path is invalid or the /proc fs is unavailable.

        """
        self._require_running()
        if self._proc_fs is None:
            msg = "/proc filesystem not available"
            raise ValueError(msg)
        try:
            return self._proc_fs.read(path)
        except ProcError as e:
            raise ValueError(str(e)) from e

    def proc_list(self, path: str) -> list[str]:
        """List entries in a virtual /proc directory.

        Delegate to the ProcFilesystem, converting ProcError to ValueError
        so that the syscall layer can wrap it in SyscallError.

        Args:
            path: Absolute path starting with ``/proc``.

        Returns:
            Sorted list of entry names.

        Raises:
            ValueError: If the path is invalid or the /proc fs is unavailable.

        """
        self._require_running()
        if self._proc_fs is None:
            msg = "/proc filesystem not available"
            raise ValueError(msg)
        try:
            return self._proc_fs.list_dir(path)
        except ProcError as e:
            raise ValueError(str(e)) from e
