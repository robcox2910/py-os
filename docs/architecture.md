# PyOS Architecture

This document explains the design of each module, the OS concepts it teaches, and how the pieces fit together.

## Design Principles

1. **Mirror real OS architecture** — every module corresponds to a real OS subsystem
2. **TDD** — tests written first, then implementation, then refactoring
3. **Syscalls as the boundary** — the shell never touches kernel internals directly
4. **Returns strings, not prints** — everything is testable, no side effects
5. **Simplicity over performance** — clarity wins in a learning simulator

---

## Kernel (`kernel.py`)

The kernel is the central coordinator. It owns all subsystems and manages the system lifecycle.

### State Machine

```
SHUTDOWN → BOOTING → RUNNING → SHUTTING_DOWN → SHUTDOWN
```

Only `RUNNING` allows operations. Booting from a non-SHUTDOWN state raises `RuntimeError`.

### Boot Sequence (Order Matters)

```
0. Logger        — capture events from the start
1. Memory        — everything else needs memory
2. Filesystem    — processes may need file access
3. User Manager  — identity before scheduling
4. Environment   — default variables (PATH, HOME, USER)
5. Device Manager — null, console, random devices
6. Scheduler     — ready to accept processes
```

Shutdown reverses this order — scheduler first, logger last (so other subsystems can still log during shutdown).

### Why Boot Order Matters

In a real OS, you can't mount a filesystem without memory, and you can't schedule processes without a filesystem to load them from. Each layer depends on the ones below it. Our boot order reflects these real dependencies.

---

## Process (`process.py`)

A process is a program in execution. We track each one via a **Process Control Block (PCB)**.

### Five-State Model

```
NEW → READY ⇄ RUNNING → TERMINATED
               ↓  ↑
             WAITING
```

- **NEW** — just created, not yet admitted to the scheduler
- **READY** — waiting in the ready queue for CPU time
- **RUNNING** — currently executing on the CPU
- **WAITING** — blocked on I/O or an event (e.g. SIGSTOP)
- **TERMINATED** — finished, awaiting cleanup

Each transition method (`admit`, `dispatch`, `preempt`, `wait`, `wake`, `terminate`) enforces that the process is in the correct source state. `force_terminate()` works from any alive state (the SIGKILL path).

### PID Assignment

PIDs are assigned via `itertools.count(start=1)` — a thread-safe, monotonically increasing counter. This mirrors real OS behaviour where PIDs never repeat within a boot cycle.

---

## Scheduler (`scheduler.py`)

The scheduler decides which process gets the CPU next.

### Strategy Pattern

The scheduling **policy** is separated from the scheduling **mechanism** using the Strategy pattern:

- `SchedulingPolicy` (Protocol) — defines `select(ready_queue)` and `should_preempt()`
- `FCFSPolicy` — First Come, First Served. No preemption. Simple FIFO.
- `RoundRobinPolicy` — Time-sliced. Each process gets a quantum, then is preempted.
- `Scheduler` — the mechanism. Owns the ready queue, dispatches using the policy.

This means you can swap scheduling algorithms without changing any other code.

---

## Memory Manager (`memory.py`)

Physical memory is divided into fixed-size **frames**.

### Why Pages (Not Variable Blocks)?

Fixed-size allocation eliminates **external fragmentation** — the situation where total free memory is sufficient but no contiguous block is large enough. With pages, any free frame can satisfy any request.

### Data Structures

- **Free set** — `set[int]` of available frame numbers. O(1) pop for allocation.
- **Page tables** — `dict[int, list[int]]` mapping PID → list of allocated frames.

---

## Virtual Memory (`virtual_memory.py`)

Virtual memory gives each process its own private address space.

### Address Translation

```
virtual_address → (virtual_page_number, offset_within_page)
page_table[vpn] → physical_frame_number
physical_address → frame_number * page_size + offset
```

This happens on every memory access in a real CPU (via the MMU hardware).

### Key Properties

1. **Isolation** — processes can't access each other's memory. Both process A and B can use virtual address 0, but they map to different physical frames.
2. **Contiguity** — the process sees contiguous memory (pages 0, 1, 2...) even when physical frames are scattered.
3. **Abstraction** — the process doesn't know where its data physically lives.

### Page Faults

Accessing an unmapped virtual page raises `PageFaultError`. In a real OS, this triggers the kernel's page fault handler which might:
- Load the page from disk (demand paging)
- Extend the stack
- Kill the process with SIGSEGV

---

## Filesystem (`filesystem.py`)

An inode-based filesystem, inspired by Unix.

### Inodes

Every file and directory is represented by an **inode** — a data structure storing metadata (type, size) and content. The directory tree is a hierarchy of inodes where directories contain name→inode mappings.

### Path Resolution

`/home/user/file.txt` is resolved step by step:
1. Start at the root inode (`/`)
2. Look up `home` in root's children → get the `home` inode
3. Look up `user` in `home`'s children → get the `user` inode
4. Look up `file.txt` in `user`'s children → get the file inode

---

## System Calls (`syscalls.py`)

The syscall layer is the **only** gateway between user-space (shell) and kernel-space.

### Why This Layer Exists

In a real OS, user programs can't directly access kernel memory or hardware. They trigger a **trap** (software interrupt) that switches the CPU to kernel mode. Our `dispatch_syscall()` mirrors this:

1. Receives a syscall number and arguments
2. Validates and routes to the correct handler
3. Wraps internal exceptions in `SyscallError`

### Benefits

- **Security** — every request is validated
- **Abstraction** — user code never imports kernel internals
- **Stability** — kernel internals can change without breaking callers
- **Auditability** — one choke-point for logging

### Syscall Number Ranges

| Range | Category |
|-------|----------|
| 1–3   | Process operations |
| 10–15 | Filesystem operations |
| 20    | Memory info |
| 30–33 | User operations |
| 40–42 | Device operations |
| 50    | Logging |
| 60    | Signals |
| 70–73 | Environment variables |
| 80    | System info |
| 90    | Deadlock detection |

---

## Shell (`shell.py`)

The command interpreter — the user's interface to the kernel.

### Design

- **Dict-based dispatch** — command name → handler method. O(1) lookup, easy to extend.
- **Returns strings** — no I/O, fully testable.
- **All interaction through syscalls** — the shell never touches kernel subsystems directly.

### Pipes

Commands can be chained with `|`. The shell splits on `|`, runs each stage left-to-right, passing output as input to the next:

```
ls / | grep txt | wc
```

This is the **Unix philosophy**: small, single-purpose tools composed via text streams.

### Filter Commands

`grep` and `wc` are "filter" commands that operate on piped input. They read `_pipe_input` (set by the pipe mechanism) rather than calling syscalls.

---

## Users & Permissions (`users.py`)

### User Model

- `User` — frozen dataclass with `uid` and `username`
- `UserManager` — registry with auto-incrementing UIDs, default `root` (uid=0)
- `FilePermissions` — per-file owner/other read/write bits

### Root Bypass

Root (uid=0) bypasses all permission checks — just like real Unix. This is enforced in `FilePermissions.check_read()` and `check_write()`.

---

## Devices (`devices.py`)

Devices are hardware abstractions accessed through a uniform interface.

### Device Protocol

All devices implement the `Device` protocol: `name`, `status`, `read()`, `write()`. This is **structural typing** — any class with these methods is a valid device, no inheritance required.

### Built-in Devices

- **NullDevice** (`/dev/null`) — reads return empty bytes, writes are silently discarded
- **ConsoleDevice** — buffered FIFO terminal (write → buffer → read)
- **RandomDevice** (`/dev/random`) — returns `os.urandom()` bytes, read-only

---

## IPC (`ipc.py`)

Inter-Process Communication — how processes talk to each other.

### Pipe

A byte-stream channel (like Unix pipes). Write bytes in, read bytes out. FIFO order.

### MessageQueue

A typed generic queue: `MessageQueue[str]` only accepts strings. Uses Python 3.12+ `class Foo[T]:` syntax. This is like a typed version of Unix System V message queues.

---

## Signals (`signals.py`)

Asynchronous notifications sent to processes — modelled after Unix signals.

### Signal Behaviour

| Signal | Value | Effect | Catchable? |
|--------|-------|--------|------------|
| SIGKILL | 9 | Force terminate | No |
| SIGTERM | 15 | Polite terminate | Yes (handler runs first) |
| SIGCONT | 18 | Resume (WAITING→READY) | N/A |
| SIGSTOP | 19 | Pause (RUNNING→WAITING) | N/A |

**SIGKILL cannot be caught** — this is a fundamental Unix guarantee. A misbehaving process can always be killed, regardless of what handlers it registers.

### Signal Handlers

Handlers are stored per `(pid, signal)` pair on the kernel. When SIGTERM is delivered, the handler runs first (for cleanup), then the process is terminated.

---

## Logging (`logging.py`)

Kernel log buffer — like `dmesg` on Linux.

### Log Levels

`DEBUG < INFO < WARNING < ERROR` — using `IntEnum` so they compare naturally. Filtering to "warnings and above" is just `level >= LogLevel.WARNING`.

### Audit Trail

Every syscall is logged at DEBUG level with the caller's UID, providing accountability. Boot events are logged at INFO level.

---

## Environment Variables (`env.py`)

Key-value string pairs that configure process behaviour.

### Copy Semantics

`env.copy()` returns an independent clone. In Unix, when a process forks, the child gets a *copy* of the parent's environment — changes in the child don't leak back. This is how you can `export FOO=bar` in a script without polluting the parent shell.

### Defaults

Boot sets: `PATH=/bin:/usr/bin`, `HOME=/root`, `USER=root`.

---

## Job Control (`jobs.py`)

Shell-level process management — background/foreground tracking.

### Jobs vs Processes

This is a critical distinction:
- **Processes** are a kernel concept (PIDs, states, scheduling)
- **Jobs** are a shell concept that *wraps* a process with a user-friendly job number (`[1]`, `[2]`)

The `JobManager` lives in the shell (user-space), not the kernel. In real Unix, job control is implemented entirely by the shell process itself.

---

## System Monitoring (SYS_SYSINFO / `top`)

The `top` command aggregates data from all subsystems into a single dashboard view — uptime, memory, processes, devices, current user, env vars, and log entries. This is the equivalent of Linux `top` or reading from `/proc`.

---

## Command History & Aliases

### History

The shell records every command in an ordered list, accessible via the `history` command. This mirrors Unix `~/.bash_history` — a chronological audit trail of what the user typed. History entries are numbered for easy reference.

In real shells, history enables features like `!!` (repeat last command) and `!n` (repeat command n). Our implementation keeps it simple: record and display.

### Aliases

Aliases are user-defined shortcuts: `alias ll=ls /` makes `ll` expand to `ls /`. The shell expands aliases before executing each pipeline stage.

Key design choices:
- **Expansion happens at the pipeline stage level** — each stage in `ls | grep foo` is independently expanded
- **Aliases are shell-local** — they live in the shell instance, not the kernel (just like real Unix)
- **No recursive expansion** — if `ll` expands to `ls /`, and `ls` is also aliased, only the first level expands. This prevents infinite loops.

---

## Page Replacement & Swap Space (`swap.py`)

When physical memory is full, the OS must decide which page to evict to make room for a new one. This is the **page replacement problem**.

### Swap Space

Swap is secondary storage (disk) used to hold evicted pages. When a page is evicted from RAM, its data is written to swap. When it's needed again, it's read back. Our `SwapSpace` class is a simple key-value store — the abstraction matters more than the backing medium.

In real systems, swap can be a dedicated partition (`/dev/sda2`) or a swap file. The kernel tracks which pages are in RAM vs swap using "present" bits in the page table.

### Replacement Policies (Strategy Pattern)

Like the scheduler, page replacement uses the **Strategy pattern** — the policy is separated from the mechanism:

| Policy | How It Works | Trade-offs |
|--------|-------------|------------|
| **FIFO** | Evict the oldest loaded page | Simple (queue), but suffers **Belady's anomaly** — more frames can mean more faults |
| **LRU** | Evict the least recently accessed | Near-optimal, no Belady's anomaly, but expensive to track (OrderedDict) |
| **Clock** | Circular buffer with reference bits; gives pages a "second chance" | Nearly as good as LRU, but much cheaper — just one bit per page |

### Clock Algorithm Detail

The clock hand sweeps through a circular buffer of pages:
1. If the page's reference bit is **set** (1): clear it and move on (second chance)
2. If the reference bit is **clear** (0): evict this page

This is the most widely used algorithm in real operating systems (Linux, Windows, BSD) because it balances effectiveness with low overhead.

### Pager (Demand Paging Orchestrator)

The `Pager` ties everything together:
- Manages a **virtual address space** larger than physical memory
- Pre-maps the first N pages (up to physical frame count) at creation
- On access to a non-resident page: **page fault** → evict a victim → swap in the requested page
- Tracks page fault count for monitoring/debugging
- Data survives multiple eviction/reload cycles via swap

This mirrors how real OSes handle memory pressure: the page fault handler runs in kernel mode, invokes the replacement policy, performs the swap I/O, updates page tables, and resumes the faulting process — all transparently.

---

## Process Forking (`fork()`)

In Unix, **every process is born from `fork()`**. The parent calls `fork()`, and the kernel creates a child that is a near-exact copy of the parent. The only difference is the return value: the parent gets the child's PID, the child gets 0.

### What Gets Copied

| Resource | Copied? | Details |
|----------|---------|---------|
| PID | New | Child gets a unique PID; `parent_pid` records the parent |
| Memory | Deep copy | New physical frames with identical data — writes in child don't affect parent |
| Priority | Inherited | Same scheduling priority as the parent |
| Name | Derived | Suffixed with "(fork)" for clarity |
| State | READY | Child is immediately eligible to run |

### Eager Copy vs Copy-on-Write

Our implementation does an **eager copy** — all of the parent's memory pages are copied to new physical frames at fork time. This is simple and correct.

Real OSes use **copy-on-write (COW)**: parent and child initially *share* the same physical frames (marked read-only). Only when one of them *writes* does the kernel copy that single page. This is much more efficient — most forked children call `exec()` immediately, so they never modify most pages.

### Process Trees

Forking creates a tree structure. The `pstree` command visualises this:

```
└── server (pid=1)
    ├── server (fork) (pid=2)
    └── server (fork) (pid=3)
        └── server (fork) (fork) (pid=4)
```

Every Unix system has a process tree rooted at PID 1 (`init` or `systemd`). All other processes are descendants, created by successive `fork()` calls.

### fork() + exec() Pattern

In real Unix, `fork()` is almost always followed by `exec()` — replace the child's code with a new program. This two-step pattern separates *process creation* from *program loading*, giving the shell a window to set up redirections, pipes, and environment changes between fork and exec.

---

## Threads (`threads.py`)

Threads are **lightweight execution units within a process**. Where a process is a resource container (memory, files, PID), a thread is an execution context (state, program counter, stack).

### Threads vs Processes vs Fork

| Operation | Memory | Cost | Use Case |
|-----------|--------|------|----------|
| **fork()** | Deep copy (new frames) | Expensive | Independent child processes |
| **Thread** | Shared (same VM) | Cheap | Parallel work within one program |

### Key Properties

1. **Shared memory** — all threads in a process see the same `VirtualMemory`. A write from one thread is immediately visible to all others. This is powerful (efficient communication) but dangerous (race conditions).

2. **Independent state** — each thread has its own `ThreadState` (NEW, READY, RUNNING, WAITING, TERMINATED) and TID. Threads follow the same five-state lifecycle as processes.

3. **Main thread** — every process starts with TID 0 ("main"). In real OSes, when the main thread exits, the process terminates and all threads are cleaned up.

4. **No memory allocation** — creating a thread does not allocate new physical frames. This is why threads are called "lightweight" — the expensive part (memory setup) is already done by the process.

### Thread IDs

TIDs are scoped per-process: TID 0 is always the main thread, and additional threads get sequential IDs (1, 2, 3...). In Linux, threads actually have globally-unique task IDs (the `tid` is really a PID internally), but per-process TIDs are clearer for learning.

### Why Threads Need Synchronisation

Because threads share memory, concurrent access to shared data can cause **race conditions** — the outcome depends on the order of execution. Solutions include mutexes, semaphores, and condition variables (topics for a future module).

---

## Deadlock Detection & Avoidance (`deadlock.py`)

**Deadlock** occurs when processes are stuck in a circular wait — each holds a resource the next one needs, and none can proceed. Four conditions must ALL hold simultaneously:

1. **Mutual exclusion** — resources can't be shared
2. **Hold and wait** — processes hold resources while waiting for more
3. **No preemption** — resources can't be forcibly taken
4. **Circular wait** — a circular chain of waiting processes

### Resource Allocation Matrices

The `ResourceManager` tracks four data structures (the textbook Banker's matrices):

| Matrix | Description | Example |
|--------|-------------|---------|
| **Available[r]** | Free instances of resource r | `Available["CPU"] = 3` |
| **Maximum[p][r]** | Max instances process p might ever need | `Maximum[1]["CPU"] = 5` |
| **Allocation[p][r]** | Instances process p currently holds | `Allocation[1]["CPU"] = 2` |
| **Need[p][r]** | Maximum - Allocation (remaining need) | `Need[1]["CPU"] = 3` |

### Banker's Algorithm (Avoidance)

Named after a banker deciding whether to grant loans. Before granting a resource request, the algorithm *simulates* granting it and checks if the resulting state is **safe** — meaning there exists an ordering (safe sequence) in which all processes can complete.

**Safety algorithm:**
1. `work = copy of available resources`
2. `finish = {pid: False}` for all processes
3. Find an unfinished process whose need <= work
4. Pretend it finishes: `work += its allocation`
5. Repeat until no more can be found
6. If all finished → safe (return the sequence)
7. Otherwise → unsafe (return None)

**`request_safe(pid, resource, amount)`:**
1. Tentatively grant the request
2. Run the safety algorithm
3. If safe → commit; if unsafe → rollback and deny

This prevents deadlock from ever occurring, at the cost of reduced concurrency (some requests are denied even though they wouldn't necessarily cause deadlock).

### Detection vs Avoidance

| Strategy | When It Runs | Effect |
|----------|-------------|--------|
| **Detection** (`detect_deadlock`) | On demand, after the fact | Finds processes that are stuck *right now* — requires recovery action |
| **Avoidance** (`request_safe`) | Before granting each request | Prevents deadlock proactively — may deny safe requests conservatively |

### Classic Example

The textbook example with 3 resources (A=10, B=5, C=7) and 5 processes demonstrates a safe state where the sequence `<P1, P3, P4, P2, P0>` allows all processes to complete. Our tests reproduce this exact scenario.

### Kernel Integration

- `ResourceManager` is initialised at boot and torn down at shutdown
- `terminate_process()` calls `remove_process()` to release all held resources
- `SYS_DETECT_DEADLOCK` syscall exposes detection to user-space
- Shell commands: `resources` (show allocation) and `deadlock` (run detection)

---

## Disk Scheduling (`disk.py`)

When multiple processes request disk I/O, the OS must decide the **order** in which to service those requests. The disk arm moves across tracks (cylinders), and the dominant cost is **seek time** — how far the arm must travel. Disk scheduling algorithms aim to minimise total head movement.

### The Disk Arm Analogy

Think of a disk arm like an elevator in a building. Passengers (I/O requests) press buttons for different floors (cylinders). The scheduling algorithm decides which floor the elevator visits next.

### Algorithms

| Policy | How It Works | Trade-offs |
|--------|-------------|------------|
| **FCFS** | Service in arrival order | Fair, simple, but the arm zigzags wildly — high total seek time |
| **SSTF** | Always go to the nearest request (greedy) | Low immediate cost, but can **starve** distant requests |
| **SCAN** | Sweep one direction, then reverse (elevator) | Bounded wait, no starvation, predictable sweep pattern |
| **C-SCAN** | Sweep one direction, jump back to start | **Uniform wait times** — no favouring middle tracks |

### FCFS (First Come, First Served)

Service requests in the order they arrived. Simple and fair, but the arm might zigzag from cylinder 14 to 183 to 37 — terrible seek time.

### SSTF (Shortest Seek Time First)

Always move to the **nearest** pending request. A greedy algorithm that minimises immediate seek cost. The problem: if new requests keep arriving near the current position, requests at the far end of the disk starve indefinitely.

### SCAN (Elevator Algorithm)

The arm sweeps in one direction, servicing all requests along the way, then reverses. Named "elevator" because it works exactly like a building elevator: go all the way up, then all the way down. This guarantees **bounded wait** — no request waits more than two full sweeps.

### C-SCAN (Circular SCAN)

Like SCAN, but after reaching the end, the arm **jumps back** to the start and sweeps the same direction again (instead of reversing). This eliminates the bias that regular SCAN has towards middle tracks — the arm passes middle positions twice per cycle in SCAN, but only once in C-SCAN, giving more **uniform wait times**.

### Strategy Pattern

All policies implement the `DiskPolicy` protocol — the same Strategy pattern used in the CPU scheduler and page replacement. The `DiskScheduler` class ties a policy to a request queue, and the policy can be swapped at runtime.

### Classic Textbook Example

The standard example uses 8 requests `[98, 183, 37, 122, 14, 124, 65, 67]` with head at cylinder 53:
- **FCFS**: 640 total head movement (zigzags across the disk)
- **SSTF**: significantly less (greedy nearest-first)
- **SCAN/C-SCAN**: predictable sweep pattern with good overall performance
