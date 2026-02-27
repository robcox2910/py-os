# PyOS

A simulated operating system built in Python for learning. If you know basic
Python and are curious about how computers actually work under the hood, this
project is for you.

Every module mirrors a real OS subsystem -- processes, memory, filesystems,
networking -- built piece by piece using test-driven development.

## What Will I Learn?

Ever wondered what happens when you open a program, save a file, or connect to
the internet? An operating system makes all of that work. PyOS builds a mini
version of one so you can see the pieces and how they fit together.

Start here: **[What Is an Operating System?](concepts/what-is-an-os.md)**

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

Each guide explains one part of the OS with real-world analogies and simple
language.

| Guide | What You'll Learn |
|-------|-------------------|
| [What Is an OS?](concepts/what-is-an-os.md) | The big picture -- what an OS does and why you need one |
| [Processes](concepts/processes.md) | Programs that are running, how they take turns, forking, and threads |
| [Memory](concepts/memory.md) | How the OS manages limited memory with pages, virtual addresses, and swap |
| [Filesystem](concepts/filesystem.md) | How files and folders are organised, and how they're saved to disk |
| [The Kernel](concepts/kernel-and-syscalls.md) | The brain of the OS -- boot sequence and system calls |
| [The Shell](concepts/shell.md) | Typing commands, pipes, scripting, and environment variables |
| [Bootloader](concepts/bootloader.md) | How the OS starts up, step by step |
| [Devices and Networking](concepts/devices-and-networking.md) | Hardware, inter-process communication, disk scheduling, and sockets |
| [Users and Safety](concepts/users-and-safety.md) | Permissions, signals, logging, and deadlocks |
| [Synchronization](concepts/synchronization.md) | Mutexes, semaphores, condition variables, and race conditions |

For a technical overview of every module, see
[Architecture](architecture.md).
