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

**TERMINATED** -- The student finished their work and left the classroom. The process is done. The [kernel](kernel-and-syscalls.md) cleans up its memory. If the process has a living parent, it stays in the process table as a [zombie](#zombies-and-waiting) until the parent collects its exit code. Otherwise it is removed immediately.

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

In PyOS, the amount of time each process gets is called the **quantum**. The `RoundRobinPolicy` stores this value, and the scheduler preempts (pulls back) the running process when its quantum expires. This preemption is driven by the hardware timer -- a device that fires an [interrupt](interrupts.md) every few ticks. When the interrupt fires, the kernel checks whether the current process has used up its quantum and, if so, switches to the next one.

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

There is a catch: **starvation**. If high-priority processes keep arriving, the low-priority ones never get a turn -- like an emergency room where critical patients keep showing up and the person with a sprained ankle waits forever. The next policy solves exactly this problem.

### Aging Priority

Imagine a lunch queue where VIP students always cut in front. That is unfair -- regular students could wait all day. **Aging** is like giving every waiting student a "patience sticker" each time someone cuts ahead of them. Once you collect enough stickers, the lunch lady says "You've waited long enough -- you're next!" After you get served, your stickers are cleared and the counting starts over.

In PyOS, every time the scheduler runs, each waiting process earns a small priority bonus (the `aging_boost`, default 1). The **effective priority** is the process's base priority plus its accumulated bonus. Eventually, even a low-priority process collects enough bonus to beat the high-priority newcomers. Once selected, the bonus resets to zero. A cap (`max_age`, default 10) prevents the bonus from growing without limit.

```python
# Aging Priority with default settings (boost=1, max_age=10)
policy = AgingPriorityPolicy()
scheduler = Scheduler(policy=policy)
```

You can switch to it from the shell:

```
pyos> scheduler aging
Scheduler set to Aging Priority (boost=1, max_age=10)
```

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

### Completely Fair Scheduler (CFS)

Linux replaced its earlier O(1) scheduler with the **Completely Fair Scheduler** in 2007, and it has been the default ever since. The goal is simple: give every process exactly its fair share of CPU time.

**Analogy**: Imagine a pizza party where everyone should get equal slices, but some kids ordered extra toppings (higher priority). The host keeps a notebook tracking how many slices each person has eaten. The person who has eaten the fewest slices goes next. Kids with extra toppings have their count go up more slowly, so they get to eat more total slices before their number catches up. Eventually, everyone's count is roughly equal -- that is fairness.

The notebook number is called **virtual runtime** (vruntime). Every time a process runs for one scheduling round, its vruntime goes up by `base_slice / weight`. The **weight** comes from the process's priority: `weight = max(1, priority + 1)`. A process with priority 5 has weight 6, so its vruntime grows six times slower than a priority-0 process. That means it gets picked more often before its count catches up -- more CPU time, just like the "extra toppings" kids.

New processes start with their vruntime set to the current minimum across all processes, so they do not jump ahead or fall behind unfairly.

```python
# CFS with default base_slice of 1
policy = CFSPolicy(base_slice=1)
scheduler = Scheduler(policy=policy)
```

You can switch to CFS from the shell:

```
pyos> scheduler cfs
Scheduler set to CFS (base_slice=1)

pyos> scheduler cfs 3
Scheduler set to CFS (base_slice=3)
```

> **How would you make it faster?** Our simulator finds the lowest vruntime by scanning through all processes in the queue -- this takes O(n) time. Real Linux CFS uses a **red-black tree** (a self-balancing binary search tree) so that finding and removing the minimum takes only O(log n) time. For our small simulations this does not matter, but in a real kernel with thousands of processes, that speedup is essential.

### Comparing the Six Policies

| Policy | Ordering | Preemption | Starvation risk | Best for |
|--------|---------|------------|----------------|----------|
| FCFS | Arrival order | None | Convoy effect | Batch jobs |
| Round Robin | Arrival order | After quantum | None | Time-sharing |
| Priority | Priority number | None | High | Mixed workloads |
| Aging Priority | Priority + age bonus | None | None (aging fixes it) | Priority with fairness |
| MLFQ | Adaptive levels | After level quantum | None (with boost) | Real-world general use |
| CFS | Lowest vruntime | After base_slice | None (vruntime balances) | Modern Linux default |

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

The solution involves tools like **mutexes** (locks that only let one thread in at a time) and **semaphores** (counters that control access). Those are covered in [Synchronization](synchronization.md).

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

## Zombies and Waiting

When a child process finishes, it does not just vanish. It still has information the parent might need -- like an exit code that says whether things went well. So the child becomes a **zombie**: it is dead (TERMINATED), its memory is freed, but its entry stays in the process table, holding its exit code like a receipt.

### The milk analogy

Imagine you send your sibling to the corner shop to buy milk. They go, they buy it, they come back. But instead of putting the milk in the fridge themselves, they stand in the doorway holding the carton, waiting for you to take it from them. Until you take the milk, they are stuck in the doorway -- that is a zombie. Once you take the milk (collect the exit code), they can finally go sit down and the doorway is clear.

### `wait()` and `waitpid()`

The parent collects a zombie using `wait()` or `waitpid()`:

- **`wait()`** -- "I don't care which sibling comes back first -- just give me whoever finishes first."
- **`waitpid(pid)`** -- "I'm specifically waiting for sibling number 5."

If a child has already finished (there is already a zombie), the collection happens instantly. If no child has finished yet, the parent **blocks** -- it moves to the WAITING state and stops doing anything until a child terminates.

In PyOS, because everything is single-threaded, "blocking" means the parent transitions to WAITING and records what it is waiting for. When the child later terminates, the kernel checks if the parent is waiting and wakes it up.

### What happens to orphans?

If a process has no parent (or the parent has already been removed), it is an **orphan**. Orphans are cleaned up immediately when they terminate -- no zombie stage needed, because nobody is going to collect them.

### Try it in the PyOS shell

```
pyos> fork 1
Forked pid 1 → child pid 2 (parent (fork))

pyos> wait 1
Collected child pid 2 (exit_code=0, output='hello')
```

If the child has not finished yet, you will see:

```
pyos> wait 1
Process 1 is now waiting for a child.
```

---

## Performance Metrics

How do we know if our scheduler is doing a good job? Imagine a **sports day stopwatch station**. Every time a runner (process) steps up to the start line (READY queue), a helper clicks a stopwatch. When the runner actually starts running (dispatched to the CPU), the helper notes how long they waited. When they cross the finish line (terminate), we record their total race time. At the end of the day, we calculate averages to see how the event went.

PyOS tracks four key measurements:

| Metric | What it measures | Sports day equivalent |
|--------|-----------------|----------------------|
| **Wait time** | How long a process sits in the READY queue | How long a runner waits at the start line |
| **Turnaround time** | Total time from creation to termination | Time from a runner arriving at the field to crossing the finish line |
| **Response time** | Time from creation to first CPU dispatch | How quickly a runner gets their first turn |
| **Context switches** | How many times the CPU switches between processes | How many times the baton gets handed off |

These metrics help answer important questions:
- "Are processes waiting too long?" (high average wait time)
- "Is the system getting work done?" (throughput — completed processes per second)
- "Does the system feel responsive?" (low average response time)

### Try it in the PyOS shell

```
pyos> perf
=== PyOS Performance Metrics ===
Context switches:    0
Processes created:   0
Processes completed: 0
Avg wait time:       0.00s
Avg turnaround:      0.00s
Avg response:        0.00s
Throughput:          0.00 procs/sec
```

You can also read the raw numbers from the virtual filesystem:

```
pyos> cat /proc/stat
CtxSwitches:    42
TotalCreated:   10
TotalCompleted: 7
AvgWaitTime:    0.15 seconds
AvgTurnaround:  1.23 seconds
AvgResponse:    0.05 seconds
Throughput:     2.33 procs/sec
```

Or check individual process timing:

```
pyos> cat /proc/42/sched
WaitTime:       0.05 seconds
CpuTime:        0.10 seconds
ResponseTime:   0.02 seconds
Turnaround:     0.15 seconds
```

Run `perf demo` for a guided walkthrough that creates processes and shows how the numbers change.

---

## Multiple CPUs

So far we've talked about **one** whiteboard -- one CPU, one student at a time. But modern computers have multiple CPUs (called **cores**). That is like a classroom with **several whiteboards**, each with its own queue of students.

### How it works

Each whiteboard has its own line of waiting students and its own scheduling policy. A teacher (the `MultiCPUScheduler`) coordinates all the whiteboards:

- When a new student arrives, the teacher sends them to the whiteboard with the **shortest line**.
- Periodically, the teacher checks if one queue is much longer than the others. If so, they move a student from the crowded queue to a shorter one. This is called **load balancing**.
- Some students have a preference -- maybe they're left-handed and whiteboard 2 is easier for them. That preference is called **CPU affinity**. The teacher respects it: a student pinned to whiteboard 2 won't be moved to whiteboard 0, even during load balancing.

### Try it in the PyOS shell

PyOS supports multiple CPUs through the bootloader or kernel configuration:

```
pyos> cpu
CPU 0: FCFSPolicy  ready=2  current=pid 1 (init)
CPU 1: FCFSPolicy  ready=1  current=none

pyos> taskset 3
Process 3 affinity: CPU 0, 1

pyos> taskset 3 0
Set process 3 affinity to CPU 0

pyos> scheduler balance
Balanced: 1 migration(s)
```

The `ps` command shows which CPU each process is on:

```
pyos> ps
PID    CPU  STATE       NAME
1      0    running     init
2      1    ready       worker-a
3      0    ready       worker-b
```

### Under the hood

The `MultiCPUScheduler` wraps N `Scheduler` instances -- one per CPU. It exposes the same interface as a single-CPU scheduler (so existing code works unchanged), plus new methods for load balancing, affinity, and migration. Each per-CPU scheduler has its own ready queue, current process, and context-switch counter.

---

## Putting It All Together

Here is the big picture. A process is a program in action, tracked by a PCB. The scheduler decides which process gets the CPU, using a pluggable policy (FCFS, Round Robin, Priority, Aging Priority, MLFQ, or CFS). On multi-CPU systems, a `MultiCPUScheduler` coordinates per-CPU schedulers with load balancing and CPU affinity. Processes can create copies of themselves through forking, or run lightweight parallel work using threads. When a process runs a program, it goes through the full lifecycle -- create, load, execute, output, and exit. When a child terminates, it becomes a zombie until its parent collects the exit code with `wait()` or `waitpid()`.

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
| **Aging** | A technique that gives waiting processes a small priority boost each round, preventing starvation |
| **vruntime** | Virtual runtime -- a weighted count of how much CPU time a process has consumed (used by CFS) |
| **CFS** | Completely Fair Scheduler -- always picks the process with the lowest vruntime |
| **Fork** | Creating a copy of a process -- new PID, copied memory, independent from the original |
| **Thread** | A lightweight execution unit that shares memory with other threads in the same process |
| **Race condition** | A bug caused by two threads accessing shared data at the same time |
| **Exit code** | A number (0 = success, non-zero = failure) that a process returns when it finishes |
| **Zombie** | A terminated process that stays in the process table until its parent collects the exit code |
| **wait()** | Block until any child terminates, then collect its exit code |
| **waitpid()** | Block until a specific child terminates, then collect its exit code |
| **Orphan** | A process whose parent no longer exists -- cleaned up immediately on termination |
| **Wait time** | How long a process spends in the READY queue, waiting for the CPU |
| **Turnaround time** | Total time from process creation to termination |
| **Response time** | Time from process creation to first CPU dispatch |
| **Context switch** | When the CPU stops running one process and starts running another |
| **Throughput** | Number of processes completed per second of system uptime |
| **CPU affinity** | The set of CPUs a process is allowed to run on |
| **Load balancing** | Moving processes from busy CPUs to less busy ones to keep work even |
| **Migration** | Moving a process from one CPU's ready queue to another |
| **MultiCPUScheduler** | A wrapper that coordinates N per-CPU schedulers with load balancing and affinity |
