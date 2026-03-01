# PyOS

**Build your own operating system in Python -- then play with it.**

[![PyPI](https://img.shields.io/pypi/v/pyos-learn)](https://pypi.org/project/pyos-learn/)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue)](https://www.python.org/downloads/)
[![CI](https://github.com/robcox2910/py-os/actions/workflows/ci.yml/badge.svg)](https://github.com/robcox2910/py-os/actions/workflows/ci.yml)
[![Docs](https://github.com/robcox2910/py-os/actions/workflows/docs.yml/badge.svg)](https://robcox2910.github.io/py-os/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Ever wondered what happens when you open a program, save a file, or connect to the internet? PyOS is a complete operating system simulator that lets you see every piece -- processes, memory, filesystems, networking -- and poke at them from a real shell. Built with test-driven development and written for learners.

## What Does It Look Like?

```
  ======================================
            PyOS v0.1.0
     A simulated operating system
  ======================================

  [POST] CPU ... OK
  [POST] Memory ... OK
  [POST] Storage ... OK
  [BOOT] Loading kernel image v0.1.0 ... OK
  [OK] Logger
  [OK] Memory manager (256 frames)
  [OK] Slab allocator
  [OK] File system (journaled)
  [OK] Scheduler (FCFS)
  [OK] Init process (PID 1)

Kernel running. Type 'help' for commands, 'exit' to quit.

root@pyos $ ps
PID  State    Name
1    READY    init

root@pyos $ fork 1
Forked process 1 → child PID 2 (init)

root@pyos $ pstree
init (PID 1)
  └── init (PID 2)

root@pyos $ learn
Available tutorials:
  processes  — What is a process and how do they work?
  memory     — How does the OS manage memory?
  filesystem — How are files stored and organised?
  shell      — What is a shell and why do we need one?
  scheduling — How does the CPU decide what to run next?
Type 'learn <topic>' to start a tutorial.
```

## Features

- **Six CPU schedulers** -- FCFS, Round Robin, Priority, Aging, MLFQ, and CFS with multi-core support
- **Virtual memory** -- page tables, address translation, swap (FIFO/LRU/Clock), slab allocator, and mmap
- **Journaled filesystem** -- inodes, directories, hard/soft links, file descriptors, /proc, and crash recovery
- **Full network stack** -- sockets, DNS, HTTP, and TCP with three-way handshake, flow control, and congestion control
- **Shell scripting** -- pipes, variables, conditionals, job control, tab completion, and 80+ built-in commands
- **Interactive tutorials** -- guided lessons that teach OS concepts hands-on using real system calls

## Install

```bash
pip install pyos-learn
pyos
```

Want the browser-based terminal too?

```bash
pip install pyos-learn[web]
pyos-web
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

## Development

```bash
git clone https://github.com/robcox2910/py-os.git
cd py-os
uv sync --all-extras
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and PR workflow.

## Links

- [Documentation](https://robcox2910.github.io/py-os/)
- [Shell Reference](docs/shell-reference.md) -- all 80+ commands by category
- [Architecture](docs/architecture.md) -- technical overview of every module
- [Visual Guide](docs/diagrams.md) -- architecture diagrams
