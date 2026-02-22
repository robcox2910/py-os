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

## 2. The Boot Sequence

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
6. Resource Manager -- Set up the rules for sharing supplies
7. Scheduler        -- Open the doors and let students in
```

Only after every single one of those steps is finished does the kernel
switch its state to `RUNNING`.

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

## 3. System Calls

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
| 100-101 | Run programs (load and execute) |
| 110-118 | Synchronization (mutexes, semaphores, conditions) |
| 120-121 | Scheduler operations (switch policy, MLFQ boost) |

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

## 4. Why Have System Calls at All?

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

## 5. Tying It All Together

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

## Where to Go Next

- [What Is an Operating System?](what-is-an-os.md) -- Start here if you haven't already
- [Processes](processes.md) -- How the OS runs programs and shares the processor
- [Memory](memory.md) -- How the OS hands out and protects memory
- [Filesystem](filesystem.md) -- How files and folders are organized and stored
- [The Shell](shell.md) -- Your command-line interface to the OS
- [Devices and Networking](devices-and-networking.md) -- How the OS talks to hardware and the internet
- [Users and Safety](users-and-safety.md) -- How the OS keeps users and their data separate
