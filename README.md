# PyOS

[![CI](https://github.com/robcox2910/py-os/actions/workflows/ci.yml/badge.svg)](https://github.com/robcox2910/py-os/actions/workflows/ci.yml)
[![Docs](https://github.com/robcox2910/py-os/actions/workflows/docs.yml/badge.svg)](https://robcox2910.github.io/py-os/)

A simulated operating system built in Python for learning. If you know basic Python and are curious about how computers actually work under the hood, this project is for you.

Every module mirrors a real OS subsystem -- processes, memory, filesystems, networking -- built piece by piece using test-driven development.

## What Will I Learn?

Ever wondered what happens when you open a program, save a file, or connect to the internet? An operating system makes all of that work. PyOS builds a mini version of one so you can see the pieces and how they fit together.

Start here: **[What Is an Operating System?](docs/concepts/what-is-an-os.md)**

## Quick Start

```bash
# Install dependencies
uv sync

# Run the interactive OS
python -m py_os

# Run the test suite
uv run pytest
```

## Learn the Concepts

Each guide explains one part of the OS with real-world analogies and simple language.

| Guide | What You'll Learn |
|-------|-------------------|
| [What Is an OS?](docs/concepts/what-is-an-os.md) | The big picture -- what an OS does and why you need one |
| [Processes](docs/concepts/processes.md) | Programs that are running, how they take turns, forking, and threads |
| [Memory](docs/concepts/memory.md) | How the OS manages limited memory with pages, virtual addresses, and swap |
| [Filesystem](docs/concepts/filesystem.md) | How files and folders are organised, and how they're saved to disk |
| [The Kernel](docs/concepts/kernel-and-syscalls.md) | The brain of the OS -- boot sequence and system calls |
| [The Shell](docs/concepts/shell.md) | Typing commands, pipes, scripting, and environment variables |
| [Devices and Networking](docs/concepts/devices-and-networking.md) | Hardware, inter-process communication, disk scheduling, and sockets |
| [Interrupts and Timers](docs/concepts/interrupts.md) | Interrupt controller, vectors, masking, timer, preemption |
| [TCP: Reliable Delivery](docs/concepts/tcp.md) | Three-way handshake, flow control, congestion control, retransmission |
| [Users and Safety](docs/concepts/users-and-safety.md) | Permissions, signals, logging, and deadlocks |
| [Synchronization](docs/concepts/synchronization.md) | Mutexes, semaphores, condition variables, and race conditions |
| [The Boot Chain](docs/concepts/bootloader.md) | What happens between pressing power and seeing a prompt |
| [Interactive Tutorials](docs/concepts/tutorials.md) | Guided lessons that teach OS concepts hands-on |
| [Web UI](docs/concepts/web-ui.md) | Browser-based terminal interface |

For a technical overview of every module, see [docs/architecture.md](docs/architecture.md).

## Modules

| Module | File | What It Teaches |
|--------|------|-----------------|
| Process | `process/pcb.py` | Five-state lifecycle, PID assignment |
| Scheduler | `process/scheduler.py` | CPU scheduling (FCFS, Round Robin, Priority, Aging Priority, MLFQ, CFS) |
| Memory | `memory/manager.py` | Page-based allocation, frame management |
| Virtual Memory | `memory/virtual.py` | Address translation, page tables, isolation |
| Filesystem | `fs/filesystem.py` | Inodes, path resolution, file CRUD |
| Kernel | `kernel.py` | Boot/shutdown lifecycle, subsystem coordination |
| System Calls | `syscalls.py` | User/kernel boundary, dispatch table |
| Shell | `shell.py` | Commands, pipes, scripting, job control |
| Users | `users.py` | Identity, file permissions |
| Devices | `io/devices.py` | Null, console, and random devices |
| IPC | `io/ipc.py` | Pipes and message queues |
| Signals | `process/signals.py` | SIGTERM, SIGKILL, SIGSTOP, SIGCONT, SIGUSR1, SIGUSR2, custom handlers |
| Logging | `logging.py` | Kernel log buffer, audit trail |
| Environment | `env.py` | KEY=VALUE config |
| Jobs | `jobs.py` | Background/foreground job control |
| Swap | `memory/swap.py` | Page replacement (FIFO, LRU, Clock) |
| Fork | `kernel.py` | Process forking, parent-child trees |
| Threads | `process/threads.py` | Lightweight execution within a process |
| Deadlock | `sync/deadlock.py` | Detection and Banker's algorithm |
| Disk Scheduling | `io/disk.py` | FCFS, SSTF, SCAN, C-SCAN |
| Scripting | `shell.py` | Scripts, variables, conditionals |
| Networking | `io/networking.py` | Sockets, client-server model |
| Persistence | `fs/persistence.py` | Save/load filesystem to JSON |
| Execution | `process/pcb.py` | Running programs, exit codes |
| Synchronization | `sync/primitives.py` | Mutex, semaphore, condition variable |
| Bootloader | `bootloader.py` | Firmware POST, kernel image loading, boot chain |
| Tutorials | `tutorials.py` | Guided hands-on lessons using real syscalls |
| Interrupts | `io/interrupts.py` | Interrupt controller, vectors, masking, priority-based servicing |
| Timer | `io/timer.py` | Programmable interval timer, tick-driven preemption |
| TCP | `io/tcp.py` | Reliable delivery: three-way handshake, flow control, congestion control |
| DNS | `io/dns.py` | Name resolution, A records |
| HTTP | `io/http.py` | Request/response protocol, status codes |
| Shared Memory | `io/shm.py` | Zero-copy IPC between processes |
| File Descriptors | `fs/fd.py` | Open files, seek, per-process fd tables |
| Journal | `fs/journal.py` | Write-ahead log, crash recovery |
| ProcFS | `fs/procfs.py` | Virtual /proc filesystem |
| Slab Allocator | `memory/slab.py` | Fixed-size object pools |
| mmap | `memory/mmap.py` | Memory-mapped file regions |
| Web Frontend | `web/app.py` | Browser-based terminal via Flask |
| REPL | `repl.py` | Interactive terminal |

## Shell Commands

```
help        List available commands
ps          Show running processes
ls [path]   List directory contents
mkdir path  Create a directory
touch path  Create an empty file
write path  Write content to a file
cat path    Read file contents
rm path     Remove a file or directory
kill pid    Terminate a process by PID
whoami      Show the current user
adduser     Create a new user
su uid      Switch to another user
signal pid  Send a signal (SIGTERM, SIGKILL, SIGUSR1, etc.)
handle pid  Register a signal handler (log, ignore)
env         List environment variables
export K=V  Set an environment variable
unset key   Remove an environment variable
log         Show kernel log entries
top         System status dashboard
history     Show command history
alias N=CMD Create a command alias
unalias N   Remove a command alias
jobs        List background jobs
bg pid      Move a process to background
fg job_id   Bring a job to foreground
fork pid    Fork a process (create a child copy)
wait pid    Wait for any child to terminate and collect its exit code
waitpid p c Wait for a specific child (c) of parent (p) to terminate
pstree      Show the process tree hierarchy
threads pid List threads of a process
resources   Show resource allocation status
deadlock    Run deadlock detection
devices     List registered devices
devread     Read from a device
devwrite    Write to a device
scheduler   Show or switch scheduling policy (fcfs, rr, priority, aging, mlfq, cfs)
            scheduler boost — reset MLFQ levels (anti-starvation)
            scheduler balance — balance load across CPUs
mutex       Manage mutexes (create, list)
semaphore   Manage semaphores (create, list)
echo args   Print arguments to output
source path Run a script from a file
run prog [p] Run a built-in program with optional priority
grep pat    Filter piped input (used with |)
wc          Count lines in piped input
open path   Open a file and get a file descriptor
close fd    Close a file descriptor
readfd fd   Read from a file descriptor
writefd fd  Write to a file descriptor
seek fd pos Reposition a file descriptor's offset
lsfd        List open file descriptors
ln          Create hard or symbolic links
readlink p  Read a symlink target
stat path   Show file metadata (type, size, links)
journal     Manage journaling (status, checkpoint, recover, crash)
rwlock      Manage reader-writer locks (create, list)
pi          Priority inheritance (demo, status)
ordering    Resource ordering (register, status, mode, violations, demo)
waitjob id  Wait for a background job to complete
shm         Shared memory (create, attach, detach, write, read, list, destroy, demo)
dns         DNS operations (register, lookup, remove, list, flush, demo)
socket      Socket operations (create, bind, listen, connect, accept, send, recv, close, list)
http        HTTP demo (end-to-end request/response over sockets)
tcp         TCP connections (listen, connect, send, recv, close, info, list, demo)
proc        /proc virtual filesystem demo
perf        Show performance metrics
strace      Syscall tracing (on, off, show, clear, demo)
dmesg       Show kernel boot log
cpu         Show per-CPU status and scheduling info
taskset     Show or set CPU affinity for a process
mmap        Memory-map a file
munmap      Unmap a memory-mapped region
msync       Sync a shared mapping
slabcreate  Create a slab cache
slaballoc   Allocate from a slab cache
slabfree    Free a slab allocation
slabinfo    Show slab allocator statistics
tick [N]    Advance the system clock by N ticks (default 1)
interrupt   Manage interrupts (list, mask <vector>, unmask <vector>)
timer       Manage the timer (info, set <interval>)
learn       Interactive tutorials (processes, memory, filesystem, ...)
exit        Shut down the kernel
```

Commands can be piped: `ls / | grep txt | wc`

### Scripting

The shell supports scripts -- multi-line sequences of commands with comments, variable substitution, and conditionals:

```bash
# Setup script
mkdir /data
export NAME=hello
echo $NAME
if ls /data
then
  touch /data/$NAME.txt
fi
```

Scripts can be run from files with `source /path/to/script.sh`.

## Web UI

PyOS includes an optional browser-based terminal. Install Flask and start the server:

```bash
pip install py-os[web]
py-os-web
```

Then open `http://localhost:8080` in your browser. See [docs/concepts/web-ui.md](docs/concepts/web-ui.md) for details.

## Development

```bash
# Run tests with coverage
uv run pytest --cov

# Format code
uv run ruff format src/ tests/

# Lint and type check
uv run ruff check src/ tests/
uv run pyright src/

# Pre-commit hooks (ruff, pyright, commitizen)
uv run pre-commit run --all-files
```

**Branch workflow:** `feat/`, `fix/`, `chore/` prefixes, squash merges to protected `main`.

**TDD cycle:** Write failing tests (Red) -> Implement (Green) -> Lint and refactor (Refactor).
