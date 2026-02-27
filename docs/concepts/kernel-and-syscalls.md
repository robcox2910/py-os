# The Kernel and System Calls

In the [What Is an Operating System?](what-is-an-os.md) page we said the kernel is
like the principal's office -- the place where all the real decisions get made.
Now let's open that door and look inside.

This page covers two files in the PyOS codebase:

- **kernel.py** -- the kernel itself, the brain of the OS.
- **syscalls.py** -- the front desk that sits between programs and the kernel.

---

## 1. What Is the Kernel?

The kernel is like the **principal of a school**. The principal doesn't teach
classes or do homework. Instead, they coordinate everything: they make sure
classrooms are assigned, teachers know their schedules, the building is
maintained, and the whole school runs smoothly.

In an operating system, the kernel does the same job. It coordinates every part
of the system -- memory, files, running programs, devices, users -- so that
everything works together without stepping on each other.

Here are the key things to know about the kernel:

**It owns all the subsystems.** The kernel holds references to the memory
manager, the file system, the scheduler, the user manager, and the device
manager. No other piece of code is allowed to create or destroy these. The
kernel sets them up when the OS boots and tears them down when the OS shuts
off.

**It is the ONLY thing that can directly touch hardware.** Programs (the
"students") are never allowed to reach past the kernel and poke at hardware
themselves. They have to ask the kernel, and the kernel decides whether to
grant the request. This keeps everything safe and organized.

**It has a lifecycle.** The kernel is not just "on" or "off." It moves through
a series of states, like a school that opens in the morning and closes at
night:

```
SHUTDOWN  -->  BOOTING  -->  RUNNING  -->  SHUTTING_DOWN  -->  SHUTDOWN
```

- **SHUTDOWN** -- the school is closed, the lights are off.
- **BOOTING** -- the janitor is unlocking doors and turning things on.
- **RUNNING** -- the school is open, students and teachers are doing their thing.
- **SHUTTING_DOWN** -- the day is over, everyone is packing up and heading out.

You can find the lifecycle defined as a `KernelState` enum near the top of
`kernel.py`. In Python, that looks like this:

```python
class KernelState(StrEnum):
    SHUTDOWN = "shutdown"
    BOOTING = "booting"
    RUNNING = "running"
    SHUTTING_DOWN = "shutting_down"
```

---

## 2. Before the Kernel: The Boot Chain

Before the kernel even starts, a **bootloader** does the hard work of checking
the hardware and loading the kernel from disk. Think of it as the security
guard and janitor preparing the school building before the principal arrives.
The full boot chain is covered in the [Boot Chain](bootloader.md) guide.

In short: **Firmware POST** checks the hardware, the **Bootloader** loads the
kernel image from disk, and then the kernel takes over.

## 3. The Kernel Boot Sequence

When a school opens in the morning, things happen in a specific order. You
can't let students in before the teachers arrive, and teachers can't teach
before their classrooms are set up.

Computers work the same way. When PyOS boots, the kernel initializes each
subsystem one at a time, in a careful order. If you look at the `boot()`
method in `kernel.py`, you'll see something like this:

```
0. Logger           -- Turn on the security cameras first
                       (so everything that happens is recorded)
1. Memory Manager   -- Set up the desks
                       (everything needs somewhere to sit)
2. File System      -- Unlock the filing cabinets
3. User Manager     -- Get the attendance list ready
4. Environment      -- Post the daily schedule on the board
5. Device Manager   -- Turn on the printers and projectors
5b. DNS Resolver    -- Open the phone book (hostname -> IP)
5c. Socket Manager  -- Set up the phone lines (network stack)
6. Resource Manager -- Set up the rules for sharing supplies
7. Sync Manager     -- Hand out the shared-equipment sign-out sheets
                       (mutexes, semaphores, condition variables)
7b. PI Manager      -- Turn on the "no cutting in line" rule
                       (priority inheritance to prevent priority inversion)
7c. Ordering Manager -- Post the "walk forward only" rule for lockers
                       (resource ordering to prevent deadlock)
8. Scheduler        -- Open the doors and let students in
9. /proc Filesystem -- Turn on the magic bulletin board
                       (live stats from all subsystems)
10. Init Process    -- The vice principal sits at the front desk
                       (first process, parent of all others)
```

Only after every single one of those steps is finished does the kernel
switch its state to `RUNNING` -- and it also flips the CPU from
**kernel mode** to **user mode** (more on that in section 8 below).

The init process is special: it is the **root of the process tree**. Every
process you create afterwards becomes a child of init. You can read more
about init in the [Boot Chain](bootloader.md) guide.

### Why does order matter?

Think about it: you can't unlock the filing cabinets if there aren't any desks
to put them on (the file system needs memory). You can't let students into
classrooms that haven't been set up yet (the scheduler needs everything else
to be ready first). And you want the security cameras rolling *before*
anything else happens, so you have a record of the entire boot.

### Shutdown is the reverse

When the school day ends, you don't turn off the security cameras first and
*then* try to get the students out. That would be backwards. Instead:

- Students leave first (scheduler shuts down).
- Then devices are unregistered.
- Then users, environment, file system, and memory are cleaned up.
- The logger is the very last thing to go, so it can record the entire
  shutdown.

This "last in, first out" pattern shows up everywhere in computer science.
You'll see it again when you learn about [memory](memory.md) and stacks.

---

## 4. System Calls

Now we know the kernel is in charge. But here's the problem: if a program
(like a text editor or a game) needs something -- say, "please save this
file" -- how does it ask?

Programs are not allowed to just reach into the kernel and grab things
directly. That would be like a student walking into the principal's office,
opening the filing cabinets, and taking whatever they want. Chaos.

Instead, there is a **front desk**.

### The front desk analogy

Imagine the principal's office has a front desk with a secretary. Students
can't walk past the front desk. When they need something, they fill out a
**request form** and hand it to the secretary. The secretary checks that the
form is filled out correctly, then walks it to the right person in the
office. When the work is done, the secretary brings the answer back to the
student.

In an OS, that front desk is the **system call interface** (or "syscall
interface" for short). In PyOS, it lives in `syscalls.py`.

### How it works in PyOS

Every request a program can make has a **number**. Think of it like a form
number at the front desk:

- Form #1: "Create a new process" (start a new program running)
- Form #10: "Create a new file"
- Form #12: "Read a file"
- Form #30: "Who am I?" (which user is logged in?)

When a program wants something, it calls `kernel.syscall()` with the right
number and any details. For example, to create a file:

```python
kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/homework/essay.txt")
```

Behind the scenes, the `dispatch_syscall()` function in `syscalls.py` looks up
the number in a big table, finds the right handler function, and calls it.
If something goes wrong, the program gets back a `SyscallError` -- a
friendly error message, never the raw internal details of how the kernel
works.

### The full list of syscall numbers

Here is every syscall number in PyOS, grouped by what they do:

| Numbers | What they're for |
|---------|-----------------|
| 1-8     | Processes (create, terminate, list, fork, threads, wait, waitpid) |
| 10-15   | Files (create, create directory, read, write, delete, list) |
| 20      | Memory info |
| 30-33   | Users (who am I, create user, list users, switch user) |
| 40-42   | Devices (read, write, list) |
| 50      | View logs |
| 60-61   | Signal operations (send signal, register handler) |
| 70-73   | Environment variables (get, set, list, delete) |
| 80      | System info (like the `top` command) |
| 90      | Deadlock detection |
| 91-93   | Deadlock prevention (resource ordering) |
| 100-101 | Run programs (load and execute) |
| 110-119, 122-125 | Synchronization (mutexes, semaphores, conditions, reader-writer locks) |
| 120-121 | Scheduler operations (switch policy, MLFQ boost) |
| 130-133 | Journal operations (status, checkpoint, recover, crash) |
| 140-146 | Shared memory IPC (create, attach, detach, destroy, write, read, list) |
| 150-154 | DNS operations (register, lookup, remove, list, flush) |
| 160-168 | Socket operations (create, bind, listen, connect, accept, send, recv, close, list) |
| 170-171 | /proc virtual filesystem (read, list) |
| 172       | Performance metrics (perf_metrics) |
| 180-183 | Strace operations (enable, disable, log, clear) |
| 190-203 | Kernel-mode helpers (shutdown, scheduler info, lstat, list mutexes/semaphores/rwlocks, list fds, list resources, PI status, ordering violations, destroy mutex, dispatch, process info, strace status) |
| 210-211 | Boot info (dmesg boot log, boot metadata) |
| 220-224 | Multi-CPU operations (cpu info, set/get affinity, balance, migrate) |

You don't need to memorize these. The important thing is that every single
operation a program can ask for has a number, and every single request goes
through the same front desk.

### What a syscall handler looks like

Here is a simplified version of the "who am I?" handler from `syscalls.py`:

```python
def _sys_whoami(kernel, **kwargs):
    """Return the current user's info."""
    user = kernel.user_manager.get_user(kernel.current_uid)
    return {"uid": user.uid, "username": user.username}
```

That's it. The front desk receives form #30 ("who am I?"), calls this
function, and hands the answer back to the program. The program never had
to touch the user manager directly.

---

## 5. Why Have System Calls at All?

You might be thinking: "This seems like a lot of extra work. Why not just let
programs talk to the kernel directly?"

Great question. Here's why, using our school analogy:

**Security.** If students could walk into the principal's office and grab
whatever they wanted, someone could steal test answers or change their
grades. System calls make sure every request is checked before it's granted.
A program can't read a file it doesn't have permission to read.

**Rules.** Every request goes through the same front desk, so you can check for
mistakes in one place. If a program asks to read a file that doesn't exist,
the syscall layer catches that and returns a clean error instead of crashing
the entire OS.

**Privacy.** Students don't need to know how the filing cabinets are organized
inside the office. They just fill out a form and get a result. Similarly,
programs don't need to know how the file system stores data internally. This
means the kernel team can completely rewrite the file system, and as long as
the forms (syscalls) stay the same, no program needs to change.

**Logging.** The front desk can write down every request in a logbook. In PyOS,
every syscall is recorded by the logger. This is incredibly useful for
debugging ("wait, when did that file get deleted?") and for security ("who
tried to switch users at 3am?").

---

## 6. Tying It All Together

Here is the full picture of how a request flows through the system:

```
You type a command
        |
        v
   [The Shell]          interprets what you typed
        |
        v
   [System Call]        fills out the right form (syscall number + args)
        |
        v
   [Kernel]             the principal's office does the work
   |    |    |
   v    v    v
Memory Files Scheduler  ...and all the other subsystems
```

The shell is where you talk to the OS (see [The Shell](shell.md)). System
calls are the only way the shell -- or any program -- can ask the kernel to
do something. And the kernel coordinates all the subsystems to make it
happen.

---

## 7. Tracing System Calls with strace

Imagine you're sitting in a restaurant, and your food just magically appears.
You have no idea what happened in the kitchen. What ingredients were used? What
order were the steps done in? Did anything go wrong along the way?

**strace** is like standing in the kitchen with a clipboard. Every time the
chef (your program) asks an assistant (the kernel) for something -- "Get me
flour," "Turn on the oven," "Plate the pasta" -- you write it down. You also
write down what the assistant gives back: "Here's the flour," "Oven is on,"
or "Error: we're out of pasta."

In real Linux, `strace` intercepts every system call a program makes and shows
you a log like this:

```
open("/etc/passwd", O_RDONLY) = 3
read(3, "root:x:0:0...", 4096) = 1024
close(3) = 0
```

PyOS has its own strace. When you turn it on, every syscall gets recorded:
the syscall name, the arguments, and what came back (or if there was an error).

### Using strace in the shell

```
$ strace on
Strace enabled.
$ ls /
bin  home  tmp
--- strace ---
#1 SYS_LIST_DIR(path="/") = ["bin", "home", "tmp"]
$ strace off
Strace disabled.
```

The `--- strace ---` section appears automatically after every command when
strace is on. Each entry has a sequence number (`#1`, `#2`, ...), the syscall
name, the arguments, and the return value (or `ERROR:` if it failed).

Other strace commands:
- `strace show` -- display all captured entries so far
- `strace clear` -- wipe the log and start fresh
- `strace demo` -- a guided walkthrough that shows strace in action

### Why is strace useful?

When something goes wrong and you can't figure out why, strace shows you
exactly what happened step by step. Did a file not exist? Did a permission
check fail? Was the wrong path used? The trace log tells you.

It's also a fantastic learning tool. If you're curious what `ls` actually does
behind the scenes, just turn on strace and watch. You'll see every syscall
the shell makes to produce the output.

### How it works inside the kernel

The kernel's `syscall()` method is the single gateway for all requests. When
strace is enabled, the kernel wraps each syscall dispatch: it calls the
handler, captures the result (or error), formats a log entry with the syscall
name, arguments, and return value, and appends it to a ring buffer (capped at
1,000 entries).

Strace management syscalls (enable, disable, log, clear) and the read-log
syscall are excluded from tracing to avoid infinite loops and noise.

### Strace syscall numbers

| Number | Name | What it does |
|--------|------|-------------|
| 180 | SYS_STRACE_ENABLE | Turn on syscall tracing |
| 181 | SYS_STRACE_DISABLE | Turn off tracing (log is kept) |
| 182 | SYS_STRACE_LOG | Read the current trace entries |
| 183 | SYS_STRACE_CLEAR | Clear the log and reset the counter |

---

## 8. User Mode vs Kernel Mode

Imagine your security badge at a building. Most of the time your badge is
**blue** (user mode) -- you can enter the lobby and talk to the front desk,
but you can't open the door to the server room. When you make a system call,
the badge flips to **red** (kernel mode) -- now you can enter the server room
and do whatever the request asks for. The moment the system call finishes,
your badge flips right back to blue.

In a real CPU, this protection is built into the hardware using **privilege
rings**:

```
Ring 0 (kernel mode) -- full access to hardware and memory
Ring 3 (user mode)   -- restricted, can only ask the kernel for help
```

User programs always run in ring 3. They can't read the kernel's memory,
they can't talk to hardware directly, and they can't touch the scheduler or
filesystem structures. The only way to do any of those things is to make a
**system call**, which temporarily switches the CPU to ring 0, runs the
handler, and switches back.

### How PyOS enforces this

PyOS has an `ExecutionMode` enum with two values:

```python
class ExecutionMode(StrEnum):
    USER = "user"
    KERNEL = "kernel"
```

When the kernel boots, it starts in **kernel mode** (the janitor is setting up
the building, so they need full access). At the very end of `boot()`, the mode
flips to **user mode** -- the doors are open, and normal rules apply.

Every sensitive kernel property (scheduler, memory, filesystem, processes,
etc.) has a guard at the top:

```python
@property
def scheduler(self):
    self._require_kernel_mode()   # raises KernelModeError if in USER mode
    return self._scheduler
```

If the shell (or any other user-space code) tries to reach past the front desk
and grab the scheduler directly, they'll get a `KernelModeError`. The only way
to get scheduler information is through the proper syscall:

```python
kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
```

Inside `syscall()`, the kernel temporarily switches to kernel mode (flips the
badge to red), runs the handler, and switches back (flips it to blue again).
This is done with a context manager that always restores the previous mode,
even if the handler crashes:

```python
with self._kernel_mode():
    result = dispatch_syscall(self, number, **kwargs)
```

### Why bother?

Without this enforcement, nothing stops a programmer from writing
`kernel.filesystem.create_file(...)` directly in the shell. It works, but
it's cheating -- it bypasses all the safety checks, logging, and error
wrapping that the syscall layer provides. With mode enforcement turned on:

- **Every access goes through syscalls.** No shortcuts, no backdoors.
- **Bugs are caught early.** If you accidentally access a kernel resource
  from user-space code, you get an immediate, clear error message instead of
  a subtle data corruption later.
- **The architecture matches reality.** Real operating systems enforce this
  boundary in hardware. PyOS enforces it in software, but the principle is
  the same.

### Kernel-mode helper syscalls

To replace every direct kernel access in the shell, PyOS added 14 new
syscalls in the 190-203 range:

| Number | Name | What it does |
|--------|------|-------------|
| 190 | SYS_SHUTDOWN | Shut down the kernel cleanly |
| 191 | SYS_SCHEDULER_INFO | Return the current scheduling policy name |
| 192 | SYS_LSTAT | Get file metadata (without following symlinks) |
| 193 | SYS_LIST_MUTEXES | List all mutexes with locked/owner state |
| 194 | SYS_LIST_SEMAPHORES | List all semaphores with their counts |
| 195 | SYS_LIST_RWLOCKS | List all reader-writer locks with state |
| 196 | SYS_LIST_FDS | List open file descriptors for a process |
| 197 | SYS_LIST_RESOURCES | List resources managed by the deadlock detector |
| 198 | SYS_PI_STATUS | Priority inheritance status and boosted processes |
| 199 | SYS_ORDERING_VIOLATIONS | List resource ordering violations |
| 200 | SYS_DESTROY_MUTEX | Destroy a named mutex |
| 201 | SYS_DISPATCH | Dispatch the next process from the scheduler |
| 202 | SYS_PROCESS_INFO | Get details about a single process |
| 203 | SYS_STRACE_STATUS | Check whether strace is currently enabled |

---

## Where to Go Next

- [What Is an Operating System?](what-is-an-os.md) -- Start here if you haven't already
- [Processes](processes.md) -- How the OS runs programs and shares the processor
- [Memory](memory.md) -- How the OS hands out and protects memory
- [Filesystem](filesystem.md) -- How files and folders are organized and stored
- [The Shell](shell.md) -- Your command-line interface to the OS
- [Devices and Networking](devices-and-networking.md) -- How the OS talks to hardware and the internet
- [Users and Safety](users-and-safety.md) -- How the OS keeps users and their data separate
