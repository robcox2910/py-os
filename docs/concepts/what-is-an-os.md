# What Is an Operating System?

You turn on your computer, click some stuff, maybe open a game or a browser.
Everything just... works. But have you ever wondered *who* is making all of that
happen behind the scenes?

That would be the **operating system** (OS for short).

## The School Principal Analogy

Imagine a school with no principal, no schedule, and no rules. Hundreds of
students show up and try to use the same classrooms, the same art supplies, and
the same lunch tables all at once. It would be total chaos.

A principal fixes that. They make the schedule, decide who gets which classroom,
handle problems when two students fight over the same computer, and keep the
whole building running smoothly. The students don't need to worry about any of
that -- they just show up and do their work.

An operating system is the principal of your computer.

The "students" are **programs** -- your browser, your text editor, your game.
They all need to use the computer's hardware (the screen, the memory, the hard
drive), and they all need to share without stepping on each other. The OS
coordinates all of it so every program can do its job without chaos.

## Why Does a Computer Need an OS?

Without an OS, every program you write would have to know how to:

- Talk directly to the screen to draw pixels
- Find free space in memory and claim it
- Read and write raw data on the hard drive
- Share the processor with every other program running at the same time

That is a *lot* of work, and most of it has nothing to do with what your program
actually wants to accomplish. It would be like asking every student to also build
their own desk, wire their own lights, and cook their own lunch before they could
start learning.

The OS handles all of that for you. Your program just says "hey, I need some
memory" or "save this file for me," and the OS takes care of the messy details.

## The Layers: How It All Fits Together

An OS isn't one big blob of code. It's built in **layers**, kind of like a
school building.

**The Shell** is like the front desk. It's where you (the human) walk in and
make requests. You type commands, and the shell figures out what you're asking
for and passes your request along.

**System Calls** (syscalls) are like official request forms. When a program
needs something from the OS -- more memory, access to a file, permission to talk
to the network -- it fills out a syscall. This is the *only* way to ask the
kernel for help. No cutting in line, no back doors.

**The Kernel** is the principal's office. This is where the real decisions get
made. The kernel manages all the computer's resources: memory, files, running
programs, devices, the network, and users. Everything flows through here.

Here's a picture of how the layers stack up:

```
+---------------------------------------------+
|                   Shell                      |  You talk to the OS here
|  (commands, pipes, job control)              |
+---------------------------------------------+
|              System Calls                    |  The official request forms
|  (the only way to ask the kernel for help)   |
+---------------------------------------------+
|                  Kernel                      |  The brain of the OS
|  (manages everything below)                  |
|  +----------+ +----------+ +----------+     |
|  |Processes | | Memory   | |  Files   |     |
|  +----------+ +----------+ +----------+     |
|  +----------+ +----------+ +----------+     |
|  |  Users   | | Devices  | | Network  |     |
|  +----------+ +----------+ +----------+     |
+---------------------------------------------+
```

You sit at the top (the shell). Your requests travel down through syscalls into
the kernel. The kernel does the heavy lifting and sends results back up.

## What Is PyOS?

PyOS is a **simulated operating system** built entirely in Python. It's not a
"real" OS -- it won't boot up a laptop or run on bare metal hardware. Instead,
it's a miniature version of an OS that you can read, run, tinker with, and learn
from.

Think of it like a model airplane. A model airplane doesn't fly passengers
across the ocean, but building one teaches you a ton about how real airplanes
work -- wings, engines, control surfaces, all of it.

PyOS works the same way. By building and exploring it, you'll learn how real
operating systems manage processes, memory, files, and more. And because it's
written in Python (a language you already know!), you can actually read the code
and understand what's happening at every step.

## The Major Parts of PyOS

Here's a quick tour of the big pieces. Don't worry about understanding them
deeply right now -- each one has its own page where we'll dig in.

**Processes** -- A process is a program that is currently running. When you open
a calculator app, that's a process. When you open a browser, that's another
process. The OS has to keep track of all of them, decide who gets to use the
processor, and make sure they don't interfere with each other.

**Memory** -- Programs need space to store their data while they're running.
The OS hands out chunks of memory to each process and makes sure no process
accidentally (or sneakily) reads another process's data.

**Filesystem** -- This is how the OS organizes files and folders on your hard
drive. It keeps track of where every file lives, what's inside it, and who's
allowed to read or change it.

**Shell** -- The shell is your way of talking to the OS. You type commands,
and the shell interprets them and makes things happen. It can also chain
commands together using pipes and run tasks in the background.

**Devices** -- Your computer has a screen, a keyboard, a mouse, maybe a
printer. The OS needs to talk to all of them, and they all speak different
"languages." The device system translates between programs and hardware.

**Networking** -- When your computer sends a message over the internet or
talks to another computer on your Wi-Fi, the OS manages that connection. It
breaks data into packets, sends them out, and reassembles incoming packets
into something useful.

**Users** -- Most operating systems support multiple users. The user system
keeps track of who is who, what they're allowed to do, and makes sure one
user can't mess with another user's files or processes.

## Where to Go Next

Pick whatever sounds most interesting to you. There's no wrong order -- each
topic stands on its own.

- [Processes](processes.md) -- How the OS runs programs and shares the processor
- [Memory](memory.md) -- How the OS hands out and protects memory
- [Filesystem](filesystem.md) -- How files and folders are organized and stored
- [The Kernel](kernel-and-syscalls.md) -- The core of the OS and how programs talk to it
- [The Shell](shell.md) -- Your command-line interface to the OS
- [Devices and Networking](devices-and-networking.md) -- How the OS talks to hardware and the internet
- [Users and Safety](users-and-safety.md) -- How the OS keeps users and their data separate
- [Synchronization](synchronization.md) -- How threads share resources without stepping on each other
- [The Boot Chain](bootloader.md) -- What happens between pressing the power button and seeing a prompt
- [Interrupts and Timers](interrupts.md) -- How hardware devices get the CPU's attention
- [TCP: Reliable Delivery](tcp.md) -- How TCP guarantees data arrives complete and in order
- [Interactive Tutorials](tutorials.md) -- Guided lessons that teach OS concepts hands-on
- [Web UI](web-ui.md) -- Run PyOS from your browser instead of the terminal

Happy exploring!
