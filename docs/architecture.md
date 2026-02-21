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
| [Processes](concepts/processes.md) | PCB, five-state model, scheduler, fork, threads, execution |
| [Memory](concepts/memory.md) | Frames/pages, virtual memory, page replacement, swap |
| [Filesystem](concepts/filesystem.md) | Inodes, path resolution, persistence, journaling |
| [Kernel and System Calls](concepts/kernel-and-syscalls.md) | Boot sequence, lifecycle, syscall dispatch, number ranges |
| [The Shell](concepts/shell.md) | Commands, pipes, scripting, jobs, history, aliases, env |
| [Devices and Networking](concepts/devices-and-networking.md) | Device protocol, IPC, disk scheduling, sockets |
| [Users and Safety](concepts/users-and-safety.md) | Permissions, signals, logging, deadlock |

## Module Map

Every source file and what it implements.

### Kernel Layer

| File | Class/Function | Purpose |
|------|---------------|---------|
| `kernel.py` | `Kernel` | Central coordinator, boot/shutdown lifecycle, subsystem ownership |
| `kernel.py` | `KernelState` | SHUTDOWN / BOOTING / RUNNING / SHUTTING_DOWN state machine |
| `syscalls.py` | `dispatch_syscall()` | Trap handler -- routes syscall numbers to kernel subsystem handlers |
| `syscalls.py` | `SyscallNumber` | IntEnum of all syscall numbers (1-101) |
| `syscalls.py` | `SyscallError` | User-facing exception wrapping internal errors |

### Process Management

| File | Class/Function | Purpose |
|------|---------------|---------|
| `process.py` | `Process` | PCB with five-state model, program/output/exit_code, thread management |
| `process.py` | `ProcessState` | NEW / READY / RUNNING / WAITING / TERMINATED |
| `scheduler.py` | `Scheduler` | Ready queue management, dispatch using pluggable policy |
| `scheduler.py` | `FCFSPolicy` | First Come, First Served scheduling |
| `scheduler.py` | `RoundRobinPolicy` | Time-sliced scheduling with configurable quantum |
| `threads.py` | `Thread` | Lightweight execution unit within a process |
| `signals.py` | `Signal` | SIGTERM / SIGKILL / SIGSTOP / SIGCONT |

### Memory Management

| File | Class/Function | Purpose |
|------|---------------|---------|
| `memory.py` | `MemoryManager` | Frame-based allocation with free set and page tables |
| `virtual_memory.py` | `VirtualMemory` | Per-process address space with page table translation |
| `swap.py` | `SwapSpace` | Key-value backing store for evicted pages |
| `swap.py` | `FIFOPolicy` / `LRUPolicy` / `ClockPolicy` | Page replacement strategies |
| `swap.py` | `Pager` | Demand paging orchestrator (page faults, eviction, swap I/O) |

### Filesystem

| File | Class/Function | Purpose |
|------|---------------|---------|
| `filesystem.py` | `FileSystem` | Inode-based filesystem with path resolution and CRUD |
| `filesystem.py` | `_Inode` | Internal metadata record (type, size, data, children) |
| `persistence.py` | `dump_filesystem()` | Serialize filesystem to JSON |
| `persistence.py` | `load_filesystem()` | Deserialize filesystem from JSON |

### User Space

| File | Class/Function | Purpose |
|------|---------------|---------|
| `shell.py` | `Shell` | Command interpreter with pipes, scripting, job control |
| `users.py` | `UserManager` | User registry with auto-incrementing UIDs |
| `users.py` | `FilePermissions` | Per-file owner/other read/write permission bits |
| `env.py` | `Environment` | KEY=VALUE store with copy semantics |
| `jobs.py` | `JobManager` | Background/foreground job tracking |

### I/O and Networking

| File | Class/Function | Purpose |
|------|---------------|---------|
| `devices.py` | `DeviceManager` | Device registry with uniform read/write protocol |
| `devices.py` | `NullDevice` / `ConsoleDevice` / `RandomDevice` | Built-in devices |
| `ipc.py` | `Pipe` | Byte-stream channel (FIFO) |
| `ipc.py` | `MessageQueue` | Typed generic message queue |
| `disk.py` | `DiskScheduler` | Request queue with pluggable scheduling policy |
| `disk.py` | `FCFSPolicy` / `SSTFPolicy` / `SCANPolicy` / `CSCANPolicy` | Disk I/O scheduling strategies |
| `networking.py` | `SocketManager` | Socket lifecycle, connection routing, data buffers |
| `networking.py` | `Socket` / `SocketState` | Endpoint with CREATED/BOUND/LISTENING/CONNECTED/CLOSED states |

### Observability

| File | Class/Function | Purpose |
|------|---------------|---------|
| `logging.py` | `Logger` | Ring buffer of structured log entries |
| `logging.py` | `LogLevel` | DEBUG / INFO / WARNING / ERROR (IntEnum) |
| `deadlock.py` | `ResourceManager` | Banker's algorithm matrices, deadlock detection |
| `repl.py` | `main()` | Interactive terminal with boot banner |

## Syscall Number Ranges

| Range | Category |
|-------|----------|
| 1-6 | Process operations (create, terminate, list, fork, threads) |
| 10-15 | Filesystem operations (create, read, write, delete, list) |
| 20 | Memory info |
| 30-33 | User operations (whoami, create, list, switch) |
| 40-42 | Device operations (read, write, list) |
| 50 | Logging |
| 60 | Signals |
| 70-73 | Environment variables |
| 80 | System info |
| 90 | Deadlock detection |
| 100-101 | Process execution (exec, run) |

## Strategy Pattern Usage

The Strategy pattern appears in three subsystems, always with the same structure: a **mechanism** (the manager class) delegates to a **policy** (a swappable protocol implementation).

| Subsystem | Mechanism | Policies |
|-----------|-----------|----------|
| CPU Scheduling | `Scheduler` | `FCFSPolicy`, `RoundRobinPolicy` |
| Page Replacement | `Pager` | `FIFOPolicy`, `LRUPolicy`, `ClockPolicy` |
| Disk Scheduling | `DiskScheduler` | `FCFSPolicy`, `SSTFPolicy`, `SCANPolicy`, `CSCANPolicy` |
