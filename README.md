# PyOS

A simulated operating system built in Python for learning OS concepts. Every module mirrors a real OS subsystem — processes, memory, filesystems, syscalls, shell — built piece by piece using TDD.

## Quick Start

```bash
# Install dependencies
uv sync

# Run the interactive OS
python -m py_os

# Run the test suite
uv run pytest

# Lint and type check
uv run ruff check src/ tests/
uv run pyright src/
```

## Architecture

PyOS follows real OS architecture: a **kernel** coordinates subsystems, a **syscall layer** separates user-space from kernel-space, and a **shell** provides the user interface.

```
┌─────────────────────────────────────────────┐
│                   Shell                      │  User-space
│  (commands, pipes, job control)              │
├─────────────────────────────────────────────┤
│              System Calls                    │  User/Kernel boundary
│  (dispatch_syscall — the only gateway)       │
├─────────────────────────────────────────────┤
│                  Kernel                      │  Kernel-space
│  ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│  │Scheduler │ │ Memory   │ │Filesystem│    │
│  │(FCFS, RR)│ │(pages,VM)│ │ (inodes) │    │
│  └──────────┘ └──────────┘ └──────────┘    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│  │  Users   │ │ Devices  │ │  Logger  │    │
│  │(perms)   │ │(null,con)│ │ (audit)  │    │
│  └──────────┘ └──────────┘ └──────────┘    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│  │ Signals  │ │   Env    │ │   IPC    │    │
│  │(TERM,KILL│ │(KEY=VAL) │ │(pipe,mq) │    │
│  └──────────┘ └──────────┘ └──────────┘    │
└─────────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for detailed module descriptions and OS concepts.

## Modules

| Module | File | What It Teaches |
|--------|------|----------------|
| Process | `process.py` | PCB, five-state lifecycle (NEW→READY⇄RUNNING→TERMINATED, WAITING) |
| Scheduler | `scheduler.py` | CPU scheduling, Strategy pattern (FCFS, Round Robin) |
| Memory | `memory.py` | Page-based allocation, frame management, OutOfMemoryError |
| Virtual Memory | `virtual_memory.py` | Address translation, page tables, page faults, process isolation |
| Filesystem | `filesystem.py` | Inodes, path resolution, CRUD operations |
| Kernel | `kernel.py` | System lifecycle (boot→run→shutdown), subsystem coordination |
| System Calls | `syscalls.py` | User/kernel boundary, trap handling, dispatch table |
| Shell | `shell.py` | Command interpreter, dispatch table, pipes |
| Users | `users.py` | Identity, file permissions, root bypass |
| Devices | `devices.py` | Device protocol, null/console/random devices |
| IPC | `ipc.py` | Pipes (byte streams), message queues (typed generics) |
| Signals | `signals.py` | SIGTERM/SIGKILL/SIGSTOP/SIGCONT, handlers, async notification |
| Logging | `logging.py` | Kernel log buffer, structured entries, audit trail |
| Environment | `env.py` | KEY=VALUE config, copy-on-fork semantics |
| Jobs | `jobs.py` | Background/foreground, job control (bg, fg, jobs) |
| REPL | `repl.py` | Interactive terminal, boot banner |

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
jobs        List background jobs
bg pid      Move a process to background
fg job_id   Bring a job to foreground
devices     List registered devices
devread     Read from a device
devwrite    Write to a device
grep pat    Filter piped input (used with |)
wc          Count lines in piped input
exit        Shut down the kernel
```

Commands can be piped: `ls / | grep txt | wc`

## Development

```bash
# Run tests with coverage
uv run pytest --cov

# Format code
uv run ruff format src/ tests/

# Pre-commit hooks (ruff, pyright, commitizen)
uv run pre-commit run --all-files
```

**Branch workflow:** `feat/`, `fix/`, `chore/` prefixes, squash merges to protected `main`.

**TDD cycle:** Write failing tests (Red) → Implement (Green) → Lint and refactor (Refactor).
