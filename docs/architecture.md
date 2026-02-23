# PyOS Architecture

Technical reference for every module in the system. For beginner-friendly explanations with analogies, see the **[concept guides](concepts/what-is-an-os.md)**.

## Design Principles

1. **Mirror real OS architecture** -- every module corresponds to a real OS subsystem.
2. **TDD** -- tests written first, then implementation, then refactoring.
3. **Syscalls as the boundary** -- the shell never touches kernel internals directly.
4. **Returns strings, not prints** -- everything is testable, no side effects.
5. **Simplicity over performance** -- clarity wins in a learning simulator.

## Concept Guides

| Guide | Topics |
|-------|--------|
| [What Is an OS?](concepts/what-is-an-os.md) | Big picture, layered architecture, how PyOS works |
| [Processes](concepts/processes.md) | PCB, five-state model, scheduler, fork (COW), threads, execution, zombies, wait/waitpid |
| [Memory](concepts/memory.md) | Frames/pages, virtual memory, page replacement, swap, copy-on-write, mmap, slab allocator |
| [Filesystem](concepts/filesystem.md) | Inodes, path resolution, hard/symbolic links, persistence, journaling |
| [Kernel and System Calls](concepts/kernel-and-syscalls.md) | Boot sequence, lifecycle, syscall dispatch, number ranges |
| [The Shell](concepts/shell.md) | Commands, pipes, redirection, loops, scripting, jobs, history, aliases, tab completion, env |
| [Devices and Networking](concepts/devices-and-networking.md) | Device protocol, IPC, disk scheduling, sockets, DNS, HTTP |
| [Users and Safety](concepts/users-and-safety.md) | Permissions, signals, logging, deadlock |
| [Synchronization](concepts/synchronization.md) | Mutex, semaphore, condition variable, reader-writer lock, race conditions, deadlock prevention |

## Module Map

Every source file and what it implements.

### Kernel Layer

| File | Class/Function | Purpose |
|------|---------------|---------|
| `kernel.py` | `Kernel` | Central coordinator, boot/shutdown lifecycle, subsystem ownership |
| `kernel.py` | `KernelState` | SHUTDOWN / BOOTING / RUNNING / SHUTTING_DOWN state machine |
| `syscalls.py` | `dispatch_syscall()` | Trap handler -- routes syscall numbers to kernel subsystem handlers |
| `syscalls.py` | `SyscallNumber` | IntEnum of all syscall numbers (1-168) |
| `syscalls.py` | `SyscallError` | User-facing exception wrapping internal errors |

### Process Management

| File | Class/Function | Purpose |
|------|---------------|---------|
| `process/pcb.py` | `Process` | PCB with five-state model, program/output/exit_code, thread management, effective_priority for PI |
| `process/pcb.py` | `ProcessState` | NEW / READY / RUNNING / WAITING / TERMINATED |
| `process/scheduler.py` | `Scheduler` | Ready queue management, dispatch using pluggable policy |
| `process/scheduler.py` | `FCFSPolicy` | First Come, First Served scheduling |
| `process/scheduler.py` | `RoundRobinPolicy` | Time-sliced scheduling with configurable quantum |
| `process/scheduler.py` | `PriorityPolicy` | Highest-priority-first scheduling with FIFO tiebreaker |
| `process/scheduler.py` | `AgingPriorityPolicy` | Priority scheduling with aging to prevent starvation |
| `process/scheduler.py` | `MLFQPolicy` | Multilevel Feedback Queue with demotion and boost |
| `process/scheduler.py` | `CFSPolicy` | Completely Fair Scheduler with weighted virtual runtime |
| `process/threads.py` | `Thread` | Lightweight execution unit within a process |
| `process/signals.py` | `Signal` | SIGKILL / SIGUSR1 / SIGUSR2 / SIGTERM / SIGCONT / SIGSTOP |
| `process/signals.py` | `SignalAction` | TERMINATE / STOP / CONTINUE / IGNORE default actions |
| `process/signals.py` | `DEFAULT_ACTIONS` | Maps every signal to its default action |
| `process/signals.py` | `UNCATCHABLE` | frozenset of signals that cannot have handlers (SIGKILL, SIGSTOP) |

### Memory Management

| File | Class/Function | Purpose |
|------|---------------|---------|
| `memory/manager.py` | `MemoryManager` | Frame-based allocation with free set, page tables, and refcounting for COW |
| `memory/virtual.py` | `VirtualMemory` | Per-process address space with page table translation and COW fault handling |
| `memory/mmap.py` | `MmapRegion` | Frozen dataclass describing a memory-mapped file region |
| `memory/mmap.py` | `MmapError` | Exception for mmap operation failures |
| `memory/slab.py` | `SlabAllocator` | Registry of named slab caches backed by physical frames |
| `memory/slab.py` | `SlabCache` | Pool of slabs for one fixed object size, auto-grows |
| `memory/slab.py` | `Slab` | One physical frame divided into equal-sized object slots |
| `memory/slab.py` | `SlabError` | Exception for slab operation failures |
| `memory/swap.py` | `SwapSpace` | Key-value backing store for evicted pages |
| `memory/swap.py` | `FIFOPolicy` / `LRUPolicy` / `ClockPolicy` | Page replacement strategies |
| `memory/swap.py` | `Pager` | Demand paging orchestrator (page faults, eviction, swap I/O) |

### Filesystem

| File | Class/Function | Purpose |
|------|---------------|---------|
| `fs/filesystem.py` | `FileSystem` | Inode-based filesystem with path resolution, links, CRUD, and offset-based I/O |
| `fs/filesystem.py` | `_Inode` | Internal metadata record (type, size, data, children, link_count) |
| `fs/filesystem.py` | `FileType` | FILE / DIRECTORY / SYMLINK |
| `fs/filesystem.py` | `MAX_SYMLINK_DEPTH` | Loop detection limit (40, matching Linux SYMLOOP_MAX) |
| `fs/fd.py` | `FdTable` | Per-process table mapping fd numbers (>= 3) to open file descriptions |
| `fs/fd.py` | `OpenFileDescription` | Track an open file's path, mode, and current byte offset |
| `fs/fd.py` | `FileMode` | READ / WRITE / READ_WRITE access modes |
| `fs/fd.py` | `SeekWhence` | SET / CUR / END seek directions |
| `fs/fd.py` | `FdError` | Exception for file descriptor operation failures |
| `fs/journal.py` | `JournaledFileSystem` | Composition wrapper adding WAL logging to every filesystem mutation |
| `fs/journal.py` | `Journal` | Write-ahead log managing transactions (begin/append/commit/abort) |
| `fs/journal.py` | `JournalOp` | CREATE_FILE / CREATE_DIR / WRITE / WRITE_AT / DELETE / LINK / SYMLINK |
| `fs/journal.py` | `TransactionState` | ACTIVE / COMMITTED / ABORTED |
| `fs/journal.py` | `JournalEntry` | Single logged operation within a transaction |
| `fs/journal.py` | `Transaction` | Atomic unit grouping journal entries |
| `fs/persistence.py` | `dump_filesystem()` | Serialize filesystem to JSON |
| `fs/persistence.py` | `load_filesystem()` | Deserialize filesystem from JSON |
| `fs/persistence.py` | `dump_journaled_filesystem()` | Serialize journaled filesystem (fs + journal + checkpoint) to JSON |
| `fs/persistence.py` | `load_journaled_filesystem()` | Deserialize journaled filesystem from JSON |

### User Space

| File | Class/Function | Purpose |
|------|---------------|---------|
| `shell.py` | `Shell` | Command interpreter with pipes, redirection (`>`, `>>`, `<`, `2>`), scripting (if/else, while/for loops), job control, background execution (`&`) |
| `shell.py` | `_Redirections` | Parsed I/O redirection operators from a command string |
| `completer.py` | `Completer` | Context-aware tab completion for commands, subcommands, paths, programs, env vars, signals |
| `users.py` | `UserManager` | User registry with auto-incrementing UIDs |
| `users.py` | `FilePermissions` | Per-file owner/other read/write permission bits |
| `env.py` | `Environment` | KEY=VALUE store with copy semantics |
| `jobs.py` | `JobManager` | Background/foreground job tracking with output capture |

### I/O and Networking

| File | Class/Function | Purpose |
|------|---------------|---------|
| `io/devices.py` | `DeviceManager` | Device registry with uniform read/write protocol |
| `io/devices.py` | `NullDevice` / `ConsoleDevice` / `RandomDevice` | Built-in devices |
| `io/ipc.py` | `Pipe` | Byte-stream channel (FIFO) |
| `io/ipc.py` | `MessageQueue` | Typed generic message queue |
| `io/disk.py` | `DiskScheduler` | Request queue with pluggable scheduling policy |
| `io/disk.py` | `FCFSPolicy` / `SSTFPolicy` / `SCANPolicy` / `CSCANPolicy` | Disk I/O scheduling strategies |
| `io/shm.py` | `SharedMemorySegment` | Named shared memory region (dataclass with frames, storage, attachments) |
| `io/shm.py` | `SharedMemoryError` | Exception for shared memory operation failures |
| `io/dns.py` | `DnsResolver` | Local phone book — register, look up, remove, list, flush hostname records |
| `io/dns.py` | `DnsRecord` | Frozen dataclass — one hostname-to-IP (A record) mapping |
| `io/dns.py` | `DnsError` | Exception for DNS operation failures |
| `io/networking.py` | `SocketManager` | Socket lifecycle, connection routing, data buffers |
| `io/networking.py` | `Socket` / `SocketState` | Endpoint with CREATED/BOUND/LISTENING/CONNECTED/CLOSED states |
| `io/networking.py` | `SocketError` | Exception for socket operation failures |
| `io/http.py` | `HttpMethod` | GET / POST request methods (StrEnum) |
| `io/http.py` | `HttpStatus` | 200 OK / 400 / 404 / 500 status codes (IntEnum) |
| `io/http.py` | `HttpRequest` / `HttpResponse` | Frozen dataclasses for HTTP messages |
| `io/http.py` | `HttpError` | Exception for HTTP operation failures |
| `io/http.py` | `format_request()` / `parse_request()` | Serialize/deserialize HTTP requests |
| `io/http.py` | `format_response()` / `parse_response()` | Serialize/deserialize HTTP responses |

### Synchronization

| File | Class/Function | Purpose |
|------|---------------|---------|
| `sync/inheritance.py` | `PriorityInheritanceManager` | Coordinate priority inheritance across mutexes, prevent priority inversion |
| `sync/primitives.py` | `Mutex` | Mutual exclusion lock with owner tracking, FIFO wait queue, and `waiters` property |
| `sync/primitives.py` | `Semaphore` | Counting semaphore with optional max bound |
| `sync/primitives.py` | `Condition` | Condition variable (wait/notify) paired with a mutex |
| `sync/primitives.py` | `ReadWriteLock` | Reader-writer lock with writer-preference and batch reader wake |
| `sync/primitives.py` | `SyncManager` | Registry for all sync primitives (mutexes, semaphores, conditions, rwlocks) |
| `sync/ordering.py` | `OrderingMode` | STRICT / WARN / OFF enforcement modes for resource ordering |
| `sync/ordering.py` | `OrderingViolation` | Frozen dataclass recording a single ordering violation |
| `sync/ordering.py` | `ResourceOrderingManager` | Enforce resource acquisition ordering to prevent circular wait (deadlock prevention) |

### Observability

| File | Class/Function | Purpose |
|------|---------------|---------|
| `logging.py` | `Logger` | Ring buffer of structured log entries |
| `logging.py` | `LogLevel` | DEBUG / INFO / WARNING / ERROR (IntEnum) |
| `sync/deadlock.py` | `ResourceManager` | Banker's algorithm matrices, deadlock detection |
| `repl.py` | `main()` | Interactive terminal with boot banner |

## Syscall Number Ranges

| Range | Category |
|-------|----------|
| 1-8 | Process operations (create, terminate, list, fork, threads, wait, waitpid) |
| 10-19 | Filesystem operations (create, read, write, delete, list, open, close, read_fd, write_fd) |
| 20 | Memory info |
| 21-23 | Memory-mapped files (mmap, munmap, msync) |
| 24-27 | Slab allocator (create cache, alloc, free, info) |
| 28 | File descriptor seek |
| 34-36 | Link operations (link, symlink, readlink) |
| 30-33 | User operations (whoami, create, list, switch) |
| 40-42 | Device operations (read, write, list) |
| 50 | Logging |
| 60-61 | Signal operations (send, register handler) |
| 70-73 | Environment variables |
| 80 | System info |
| 90 | Deadlock detection |
| 91-93 | Deadlock prevention (resource ordering) |
| 100-101 | Process execution (exec, run) |
| 110-119, 122-125 | Synchronization (mutex, semaphore, condition, reader-writer lock) |
| 120-121 | Scheduler operations (policy switching, MLFQ boost) |
| 130-133 | Journal operations (status, checkpoint, recover, crash) |
| 140-146 | Shared memory IPC (create, attach, detach, destroy, write, read, list) |
| 150-154 | DNS operations (register, lookup, remove, list, flush) |
| 160-168 | Socket operations (create, bind, listen, connect, accept, send, recv, close, list) |

## Strategy Pattern Usage

The Strategy pattern appears in three subsystems, always with the same structure: a **mechanism** (the manager class) delegates to a **policy** (a swappable protocol implementation).

| Subsystem | Mechanism | Policies |
|-----------|-----------|----------|
| CPU Scheduling | `Scheduler` | `FCFSPolicy`, `RoundRobinPolicy`, `PriorityPolicy`, `AgingPriorityPolicy`, `MLFQPolicy`, `CFSPolicy` |
| Page Replacement | `Pager` | `FIFOPolicy`, `LRUPolicy`, `ClockPolicy` |
| Disk Scheduling | `DiskScheduler` | `FCFSPolicy`, `SSTFPolicy`, `SCANPolicy`, `CSCANPolicy` |
