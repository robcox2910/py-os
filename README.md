# PyOS

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
| [Users and Safety](docs/concepts/users-and-safety.md) | Permissions, signals, logging, and deadlocks |
| [Synchronization](docs/concepts/synchronization.md) | Mutexes, semaphores, condition variables, and race conditions |

For a technical overview of every module, see [docs/architecture.md](docs/architecture.md).

## Modules

| Module | File | What It Teaches |
|--------|------|-----------------|
| Process | `process.py` | Five-state lifecycle, PID assignment |
| Scheduler | `scheduler.py` | CPU scheduling (FCFS, Round Robin, Priority) |
| Memory | `memory.py` | Page-based allocation, frame management |
| Virtual Memory | `virtual_memory.py` | Address translation, page tables, isolation |
| Filesystem | `filesystem.py` | Inodes, path resolution, file CRUD |
| Kernel | `kernel.py` | Boot/shutdown lifecycle, subsystem coordination |
| System Calls | `syscalls.py` | User/kernel boundary, dispatch table |
| Shell | `shell.py` | Commands, pipes, scripting, job control |
| Users | `users.py` | Identity, file permissions |
| Devices | `devices.py` | Null, console, and random devices |
| IPC | `ipc.py` | Pipes and message queues |
| Signals | `signals.py` | SIGTERM, SIGKILL, SIGSTOP, SIGCONT |
| Logging | `logging.py` | Kernel log buffer, audit trail |
| Environment | `env.py` | KEY=VALUE config |
| Jobs | `jobs.py` | Background/foreground job control |
| Swap | `swap.py` | Page replacement (FIFO, LRU, Clock) |
| Fork | `kernel.py` | Process forking, parent-child trees |
| Threads | `threads.py` | Lightweight execution within a process |
| Deadlock | `deadlock.py` | Detection and Banker's algorithm |
| Disk Scheduling | `disk.py` | FCFS, SSTF, SCAN, C-SCAN |
| Scripting | `shell.py` | Scripts, variables, conditionals |
| Networking | `networking.py` | Sockets, client-server model |
| Persistence | `persistence.py` | Save/load filesystem to JSON |
| Execution | `process.py` | Running programs, exit codes |
| Synchronization | `sync.py` | Mutex, semaphore, condition variable |
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
signal pid  Send a signal (SIGTERM, SIGKILL, etc.)
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
pstree      Show the process tree hierarchy
threads pid List threads of a process
resources   Show resource allocation status
deadlock    Run deadlock detection
devices     List registered devices
devread     Read from a device
devwrite    Write to a device
scheduler   Show or switch scheduling policy (fcfs, rr, priority)
mutex       Manage mutexes (create, list)
semaphore   Manage semaphores (create, list)
echo args   Print arguments to output
source path Run a script from a file
run prog [p] Run a built-in program with optional priority
grep pat    Filter piped input (used with |)
wc          Count lines in piped input
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
