# PyOS

## The School Principal of Your Computer

Imagine a busy school with hundreds of students, dozens of classrooms,
a library, a cafeteria, and a gym. Without a **principal**, it would
be chaos -- everyone fighting over rooms, no one knowing when lunch
is, books going missing.

An **operating system** is the principal of your computer. It decides
which programs get to run (scheduling), where things are stored
(memory and filesystems), and how programs talk to each other
(networking). PyOS builds a mini version of one so you can see all
the pieces and how they fit together.

## Our Building Blocks

| Concept | Analogy | What It Does |
|---------|---------|-------------|
| **Processes** | Students | Programs that are running |
| **Memory** | Lockers | Where programs store their stuff |
| **Filesystem** | The library | Where files and folders are kept |
| **Kernel** | The principal's office | The brain that runs everything |
| **Shell** | The intercom | How you talk to the OS |
| **Networking** | The phone system | How computers talk to each other |
| **Scheduling** | The class timetable | Who gets to run and when |
| **Synchronization** | Hall passes | Preventing two programs from crashing into each other |

## Let's Start!

Head to **[What Is an Operating System?](concepts/what-is-an-os.md)**
to begin your journey.

## Quick Start

```bash
pip install pyos-learn
pyos
```

Want the browser-based terminal too?

```bash
pip install pyos-learn[web]
pyos-web
```

For development, clone the repo and use [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/robcox2910/py-os.git
cd py-os
uv sync --all-extras
uv run pytest
```

## Learn the Concepts

Each guide explains one part of the OS with real-world analogies and simple language.

| Guide | What You'll Learn |
|-------|-------------------|
| [What Is an OS?](concepts/what-is-an-os.md) | The big picture -- what an OS does and why you need one |
| [Processes](concepts/processes.md) | Programs that are running, how they take turns, forking, and threads |
| [Memory](concepts/memory.md) | How the OS manages limited memory with pages, virtual addresses, and swap |
| [Filesystem](concepts/filesystem.md) | How files and folders are organised, and how they're saved to disk |
| [The Kernel](concepts/kernel-and-syscalls.md) | The brain of the OS -- boot sequence and system calls |
| [The Shell](concepts/shell.md) | Typing commands, pipes, scripting, and environment variables |
| [Devices and Networking](concepts/devices-and-networking.md) | Hardware, inter-process communication, disk scheduling, and sockets |
| [Interrupts and Timers](concepts/interrupts.md) | Interrupt controller, vectors, masking, timer, preemption |
| [TCP: Reliable Delivery](concepts/tcp.md) | Three-way handshake, flow control, congestion control, retransmission |
| [Users and Safety](concepts/users-and-safety.md) | Permissions, signals, logging, and deadlocks |
| [Synchronization](concepts/synchronization.md) | Mutexes, semaphores, condition variables, and race conditions |
| [The Boot Chain](concepts/bootloader.md) | What happens between pressing power and seeing a prompt |
| [Framebuffer](concepts/framebuffer.md) | Pixel-level graphics, drawing shapes, and displaying images |
| [TUI Dashboard](concepts/tui.md) | A live terminal dashboard that shows OS internals in real time |
| [Permissions](concepts/permissions.md) | File ownership, read/write/execute bits, groups, and ACLs |
| [Binary Loader](concepts/binary-loader.md) | Loading and running programs -- how `exec` works |
| [Containers](concepts/containers.md) | Lightweight isolation with PID, mount, and network namespaces |
| [Inter-Machine Networking](concepts/inter-machine-networking.md) | Connecting multiple kernels with bridges and clusters |
| [Interactive Tutorials](concepts/tutorials.md) | Guided lessons that teach OS concepts hands-on |
| [Web UI](concepts/web-ui.md) | Browser-based terminal interface |

For a technical overview of every module, see [Architecture](architecture.md).

For the full command listing, see [Shell Reference](shell-reference.md).

## Web UI

PyOS includes an optional browser-based terminal. Install Flask and start the server:

```bash
pip install pyos-learn[web]
pyos-web
```

Then open `http://localhost:8080` in your browser. See [Web UI](concepts/web-ui.md) for details.

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
