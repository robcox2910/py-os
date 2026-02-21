# Processes

Everything your computer does -- running a game, playing music, loading a web page -- happens inside a **process**. This page explains what processes are, how they take turns using the CPU, and how they are born, run, and finish.

---

## What is a Process?

A **program** is a set of instructions sitting in a file, like a homework assignment printed on paper. It does not do anything on its own. A **process** is what happens when someone actually starts working on that assignment.

Think of it this way. The assignment sheet is the program. But a student sitting at their desk, pencil in hand, page open, halfway through question three -- that is the process. The process is a program *in action*, with all of its current progress attached.

Here is the important part: multiple students can work on the *same* assignment at the same time. Each student has their own desk, their own pencil, and their own progress. In the same way, you can launch the same program multiple times and get multiple independent processes.

### The Process Control Block (PCB)

The operating system needs to keep track of every process. It does this with a data structure called the **Process Control Block**, or PCB.

Think of it like a profile card the teacher keeps for every student:

| Field | What it tracks | Example |
|-------|---------------|---------|
| **PID** | A unique ID number | `pid=3` |
| **Name** | What the process is called | `"web_browser"` |
| **State** | What the process is doing right now | `RUNNING` |
| **Priority** | How important it is | `priority=5` |
| **Parent PID** | Which process created this one | `parent_pid=1` |

In PyOS, the `Process` class *is* the PCB. When the [kernel](kernel-and-syscalls.md) creates a process, it fills in all of these fields and keeps the Process object in a table so it can find it later.

Every process also gets its own [virtual memory](memory.md) -- a private chunk of memory that no other process can see or touch.

---

## The Five States

A process is not always running. Most of the time, it is waiting for its turn. Every process moves through up to five states during its life:

```
NEW --> READY <--> RUNNING --> TERMINATED
                    |   ^
                    v   |
                  WAITING
```

Think of a classroom where only **one student can use the whiteboard** at a time.

**NEW** -- The student just arrived at school. They are registered, but they have not joined the line for the whiteboard yet. In PyOS, a process starts in NEW and moves to READY when it is *admitted* to the scheduler.

**READY** -- The student is in line, waiting for their turn at the whiteboard. They are ready to work, but someone else is up there right now. The scheduler's ready queue holds all the READY processes.

**RUNNING** -- The student is at the whiteboard, doing their work. Only one process can be RUNNING at a time (on a single CPU). This is the process that currently "has" the CPU.

**WAITING** -- The student stepped out of the classroom to grab a book from the library. They cannot continue until they get the book back. In OS terms, the process is blocked on something -- maybe waiting for a file to be read from disk, or waiting for a network response. When the thing it is waiting for happens, the process moves back to READY and rejoins the line.

**TERMINATED** -- The student finished their work and left the classroom. The process is done. The [kernel](kernel-and-syscalls.md) cleans up its memory and removes it from the process table.

### Transitions

Each arrow in the diagram is a specific method call in PyOS:

| Transition | Method | What triggers it |
|-----------|--------|-----------------|
| NEW to READY | `admit()` | Scheduler accepts the process |
| READY to RUNNING | `dispatch()` | Scheduler picks this process to run |
| RUNNING to READY | `preempt()` | Time is up, back to the line |
| RUNNING to WAITING | `wait()` | Process needs something (I/O, event) |
| WAITING to READY | `wake()` | The thing it needed is ready |
| RUNNING to TERMINATED | `terminate()` | Process finished normally |
| Any alive state to TERMINATED | `force_terminate()` | SIGKILL -- forced shutdown |

These transitions are **strict**. You cannot dispatch a process that is not READY, and you cannot terminate a process that is not RUNNING (unless you use `force_terminate()`, which is the emergency SIGKILL path). If you try, PyOS raises a `RuntimeError`. Real operating systems enforce similar rules in their kernel code.

---

## The Scheduler

So who decides which READY process gets to be RUNNING? That is the **scheduler**. Think of the scheduler as the teacher deciding whose turn it is at the whiteboard.

The scheduler has a **ready queue** -- the line of students waiting. When the whiteboard is free, the scheduler picks the next student based on some rule. Different rules give different results.

### FCFS (First Come, First Served)

The simplest rule: whoever got in line first goes first. The scheduler picks the process at the front of the queue, and that process runs until it finishes or voluntarily gives up the CPU.

This is fair in a basic sense, but it has a problem called the **convoy effect**. Imagine one student has a 45-minute project and three students behind them each have a 30-second question. Everyone waits 45 minutes for one slow task to finish. Not great.

### Round Robin

A fairer rule: each student gets a fixed amount of time at the whiteboard (say, 2 minutes). When their time is up, they go to the back of the line, and the next student steps up. Everyone gets a turn, no one hogs the whiteboard forever.

In PyOS, the amount of time each process gets is called the **quantum**. The `RoundRobinPolicy` stores this value, and the scheduler preempts (pulls back) the running process when its quantum expires.

```python
# Round Robin with a quantum of 3 ticks
policy = RoundRobinPolicy(quantum=3)
scheduler = Scheduler(policy=policy)
```

### Priority Scheduling

What if some tasks are more important than others? In a hospital emergency room, a patient with a broken arm is seen before someone with a splinter, even if the splinter patient arrived first. Priority scheduling works the same way: every process has a **priority number**, and the scheduler always picks the highest-priority process next.

In PyOS, higher numbers mean higher priority. A process with `priority=10` runs before one with `priority=1`. When two processes have the same priority, the scheduler falls back to FIFO -- whoever arrived first goes first.

```python
# Priority scheduling -- highest priority runs first
policy = PriorityPolicy()
scheduler = Scheduler(policy=policy)
```

There is a catch: **starvation**. If high-priority processes keep arriving, the low-priority ones never get a turn -- like an emergency room where critical patients keep showing up and the person with a sprained ankle waits forever. Real operating systems solve this with a technique called **aging**, where a process's priority slowly increases the longer it waits.

### Multilevel Feedback Queue (MLFQ)

What if the scheduler could *learn* whether a process is a quick task or a long-running one, and adjust accordingly? That is what the **Multilevel Feedback Queue** does. It is the most important adaptive scheduling algorithm in real operating systems -- used by Linux (the predecessor to CFS), Windows, and macOS.

**Analogy**: Imagine a science fair with three judging stations. Station 1 (front row) gives each student 2 minutes to present. If you cannot finish in 2 minutes, you move to Station 2, where you get 4 minutes. Still not done? Station 3 gives you 8 minutes. Judges always check Station 1 first, so quick presenters get served fast. Periodically, the teacher calls "Everyone back to Station 1!" so that students stuck in the back are not ignored forever.

Here is how it works:

1. **New processes start at the top** (level 0, shortest quantum).
2. **If preempted** (used all their time), they are **demoted** one level down (longer quantum).
3. **Judges always serve the highest level first** (lowest number = highest priority).
4. **Periodic boost** resets everyone to level 0 to prevent starvation.

This means short I/O-bound processes (like typing in a text editor) stay at level 0 and get fast response times, while long CPU-bound processes (like video encoding) naturally sink to lower levels with longer quanta -- less context-switching overhead for them.

```python
# MLFQ with 3 levels, base quantum of 2
policy = MLFQPolicy(num_levels=3, base_quantum=2)
# Quanta: level 0 = 2, level 1 = 4, level 2 = 8
```

You can switch to MLFQ and trigger boosts from the shell:

```
pyos> scheduler mlfq
Scheduler set to MLFQ (3 levels, base_quantum=2)

pyos> scheduler boost
MLFQ boost: all processes reset to level 0
```

### Comparing the Four Policies

| Policy | Ordering | Preemption | Starvation risk | Best for |
|--------|---------|------------|----------------|----------|
| FCFS | Arrival order | None | Convoy effect | Batch jobs |
| Round Robin | Arrival order | After quantum | None | Time-sharing |
| Priority | Priority number | None | High | Mixed workloads |
| MLFQ | Adaptive levels | After level quantum | None (with boost) | Real-world general use |

You can switch policies at runtime using the `scheduler` shell command:

```
pyos> scheduler priority
Scheduler set to Priority
```

### The Strategy Pattern

Notice something neat about this design: the scheduler itself does not know *how* to pick the next process. It just asks the policy. You can swap `FCFSPolicy` for `RoundRobinPolicy` or `PriorityPolicy` (or write your own!) without changing a single line in the `Scheduler` class. This is a design pattern called **Strategy** -- the "rules for taking turns" are a separate, swappable piece.

---

## Forking

Imagine you could photocopy an entire student -- their desk, their notes, their pencil, the exact spot they stopped writing. Now there are TWO students, each at their own desk, each with identical notes. From that moment on, they work independently. One might erase something, the other might keep going -- they no longer affect each other.

That is `fork()`.

The original student is called the **parent**. The copy is called the **child**. The child is a brand new process with its own PID, but it starts with copies of everything the parent had.

### What gets copied

| Resource | What happens |
|----------|-------------|
| **PID** | The child gets a new, unique PID |
| **Memory** | A full copy of the parent's [memory](memory.md) pages -- separate physical frames |
| **Priority** | Inherited from the parent |
| **Name** | Parent's name with "(fork)" added |
| **State** | The child starts in READY, immediately eligible to run |

After the fork, the parent and child are independent. If the child writes to its memory, the parent's memory is not affected. They each have their own copy.

### Why is forking useful?

Forking is how an operating system creates new workers. A web server might fork a child process for every new visitor, so each visitor gets their own handler. If one child crashes, the others keep running.

### The Process Tree

Because every child remembers its parent (via `parent_pid`), processes form a **tree**. On a real Linux system, you can see this with the `pstree` command:

```
server (pid=1)
  +-- server (fork) (pid=2)
  +-- server (fork) (pid=3)
       +-- server (fork) (fork) (pid=4)
```

Every Unix system has a process tree rooted at PID 1 (called `init` or `systemd`). All other processes are descendants, created through chains of fork calls.

---

## Threads

Forking creates a full copy of a process -- new memory, new everything. But what if you want two things to happen at the same time *inside* the same process, sharing the same data?

That is what **threads** are for.

If forking is like photocopying an entire student (desk, notes, pencil, everything), creating a thread is like giving one student a **second pair of hands**. Both pairs of hands share the same desk and the same notes. They can work on two things at the same time, and they can both see everything the other is doing.

### Why threads are cheap

When you fork, the [kernel](kernel-and-syscalls.md) has to copy all of the parent's [memory](memory.md) into new physical frames. That takes time and space. When you create a thread, no new memory is allocated at all. The thread just uses the memory that the process already has. That is why threads are called "lightweight."

```python
# Creating a thread inside a process -- no memory cost
worker = process.create_thread("worker-1")
```

### Why sharing is tricky

Sharing sounds great, but it comes with a catch. If both pairs of hands try to erase and write in the same spot at the same time, you get a mess. One hand erases while the other is writing, and the result is garbled nonsense.

In programming, this is called a **race condition** -- the result depends on which thread happened to go first, and that can change every time you run the program. Race conditions are some of the hardest bugs to find because they do not happen consistently.

The solution involves tools like **mutexes** (locks that only let one thread in at a time) and **semaphores** (counters that control access). Those are topics for a future module.

### Threads vs Fork -- When to use which

| | Fork | Thread |
|---|------|--------|
| **Memory** | Full copy (expensive) | Shared (free) |
| **Independence** | Completely separate | Tied together |
| **Crash safety** | Child crash does not affect parent | Thread crash can take down the whole process |
| **Best for** | Independent workers, isolation | Parallel work within one program |

Each thread has its own TID (Thread ID), its own name, and its own state that follows the same five-state model as processes (NEW, READY, RUNNING, WAITING, TERMINATED). But all threads in a process share the same virtual memory space.

---

## Running Programs

So far we have talked about processes having states and taking turns. But what does a process actually *do*? It runs a **program**.

In PyOS, a program is a Python function that returns a string. The lifecycle goes like this:

1. **Create** -- The kernel creates a new process (an empty student shows up).
2. **Exec** -- A program is loaded into the process (the student receives their assignment sheet).
3. **Run** -- The process is dispatched and the program executes (the student does the work).
4. **Output** -- The program returns its result (the student hands in their paper).
5. **Exit code** -- The process gets a grade: `0` means everything went well, `1` means something went wrong.

This mirrors the real Unix pattern of `fork()` then `exec()`. The process is created first, and the program is loaded into it as a separate step. That separation is useful because the [kernel](kernel-and-syscalls.md) can set up things like redirections and environment variables in between.

### Exit Codes

Every process finishes with an **exit code** -- a number that tells the parent whether things went well.

- **0** means success. The program ran and returned its output normally.
- **1** (or any non-zero number) means failure. The program hit an error.

In real Unix, you can check the last command's exit code with `$?`. In PyOS, the exit code is stored on the process object after execution.

### Try it in the PyOS shell

PyOS comes with a couple of built-in programs you can run:

```
pyos> run hello
Hello from PyOS!
[exit code: 0]

pyos> run counter
1
2
3
4
5
[exit code: 0]
```

The `run` command does the full lifecycle behind the scenes: it creates a process, loads the named program, dispatches and executes it, captures the output, and cleans up -- all through [syscalls](kernel-and-syscalls.md) (`SYS_EXEC` and `SYS_RUN`).

---

## Putting It All Together

Here is the big picture. A process is a program in action, tracked by a PCB. The scheduler decides which process gets the CPU, using a pluggable policy (FCFS or Round Robin). Processes can create copies of themselves through forking, or run lightweight parallel work using threads. When a process runs a program, it goes through the full lifecycle -- create, load, execute, output, and exit.

All of these pieces work together inside the [kernel](kernel-and-syscalls.md), which coordinates the scheduler, [memory](memory.md) manager, and process table to keep everything running smoothly.

---

## Key Terms

| Term | Definition |
|------|-----------|
| **Process** | A program in execution, with its own PID, state, and memory |
| **PCB** | Process Control Block -- the data structure that tracks everything about a process |
| **PID** | Process Identifier -- a unique number assigned to each process |
| **Scheduler** | The part of the OS that decides which process runs next |
| **Ready queue** | The line of processes waiting for the CPU |
| **Quantum** | The amount of time a process gets before being preempted (Round Robin) |
| **Preemption** | Pulling a running process off the CPU so someone else can have a turn |
| **Priority** | A number that tells the scheduler how important a process is (higher = more important) |
| **Starvation** | When a low-priority process never gets to run because higher-priority work keeps arriving |
| **Fork** | Creating a copy of a process -- new PID, copied memory, independent from the original |
| **Thread** | A lightweight execution unit that shares memory with other threads in the same process |
| **Race condition** | A bug caused by two threads accessing shared data at the same time |
| **Exit code** | A number (0 = success, non-zero = failure) that a process returns when it finishes |
