# Synchronization

When multiple threads share data, things can go wrong fast. Without coordination, two threads might update the same variable at the same time, creating a **race condition** -- the result depends on which thread happens to run first.

Synchronization primitives solve this. They are the traffic lights and turnstiles of concurrent programming.

## The Problem: Race Conditions

Imagine two threads both trying to increment a counter:

```
Thread A reads counter (value: 5)
Thread B reads counter (value: 5)
Thread A writes counter = 6
Thread B writes counter = 6    <-- should be 7!
```

One increment was lost. This is a **data race**: both threads read the old value before either wrote the new one.

## Mutex (Mutual Exclusion)

**Analogy: A bathroom lock.**

A mutex is the simplest synchronization tool. Only one thread can hold it at a time. If another thread tries to acquire it, they wait in a queue until the holder releases it.

```
Thread A: acquire lock  -> success, enters critical section
Thread B: acquire lock  -> blocked, added to wait queue
Thread A: release lock  -> Thread B wakes up and acquires
Thread B: release lock  -> lock is free
```

**Key rules:**
- Only the thread that locked it can unlock it (owner tracking)
- Waiters are served in FIFO order (no starvation)
- Forgetting to release causes deadlock

**Shell usage:**
```
mutex create mylock
mutex list
```

## Semaphore (Counting Lock)

**Analogy: A parking lot with limited spaces.**

A semaphore is like a mutex, but instead of allowing only 1 holder, it allows up to N concurrent holders. Each `acquire` decrements the count; each `release` increments it. When the count reaches zero, new arrivals wait.

```
Semaphore "parking" (count=3)

Car A enters  -> count=2
Car B enters  -> count=1
Car C enters  -> count=0
Car D arrives -> blocked (lot is full)
Car A leaves  -> count stays 0, Car D enters
```

**Special cases:**
- **Binary semaphore** (count=1): behaves like a mutex
- **Bounded semaphore**: enforces a maximum count to prevent accidental over-releasing

**Shell usage:**
```
semaphore create parking 3
semaphore list
```

## Condition Variable (Wait/Notify)

**Analogy: A waiting room where you sit until your name is called.**

A condition variable lets threads wait for some condition to become true. It is always paired with a mutex:

1. Thread acquires mutex
2. Checks the condition -- if not met, calls `wait`
3. `wait` atomically releases the mutex and puts the thread to sleep
4. Another thread changes the data, then calls `notify` or `notify_all`
5. The waiting thread wakes up and re-acquires the mutex

This is the standard **producer-consumer** pattern: the producer adds items and notifies; the consumer waits until items are available.

## Reader-Writer Lock (RWLock)

**Analogy: A museum exhibit.**

Imagine a famous painting in a museum. Any number of visitors (readers) can look at the painting at the same time -- they don't interfere with each other. But when a restorer (writer) needs to work on the painting, they close the room. Visitors already inside can finish looking, but no new visitors are let in until the restorer is done.

A reader-writer lock works the same way:
- **Multiple readers** can hold the lock at the same time
- **Only one writer** can hold the lock, and nobody else (no readers, no other writers)
- This is perfect for data that gets read much more often than it gets written (config files, caches, lookup tables)

```
Thread A: acquire_read   -> success (1 reader)
Thread B: acquire_read   -> success (2 readers)
Thread C: acquire_write  -> blocked, added to wait queue
Thread D: acquire_read   -> blocked behind writer (writer-preference!)
Thread A: release_read   -> nothing happens (B still reading)
Thread B: release_read   -> 0 readers, C wakes up (writer goes next)
Thread C: release_write  -> D wakes up (reader gets in)
```

### Writer-Preference

Notice that Thread D was blocked even though it was a reader. This is **writer-preference**: when a writer is waiting in line, new readers queue behind it rather than jumping ahead. Without this rule, a steady stream of readers could starve the writer forever -- the writer would never get a turn.

**Shell usage:**
```
rwlock create db_lock
rwlock list
```

## Priority Inversion

**Analogy: Three students and one textbook.**

Imagine a classroom with three students who all need the same textbook:

- **Slow Student** (low priority) -- currently has the textbook and is reading
- **Fast Student** (high priority) -- needs the textbook urgently
- **Normal Student** (medium priority) -- doesn't need the textbook at all

The teacher (scheduler) always calls on the highest-priority student who is ready to work. Here's the problem:

1. Slow Student has the textbook and is reading chapter 3
2. Fast Student raises their hand -- "I need that textbook!" But Slow Student still has it
3. Normal Student doesn't need the textbook, so they're ready to work
4. The teacher keeps calling on Normal Student (priority 5) instead of Slow Student (priority 1)
5. Slow Student never gets a turn, so they can never finish and return the textbook
6. Fast Student is stuck forever!

This is **priority inversion**: the high-priority task is effectively running at the *lowest* priority because it's blocked behind the low-priority holder, and medium-priority tasks keep jumping ahead.

### The Mars Pathfinder Bug

This exact problem happened on Mars in 1997. NASA's Pathfinder rover had three tasks:

- A **low-priority** task that collected weather data (and held a shared mutex)
- A **high-priority** task that managed the communication bus
- **Medium-priority** tasks that ran science experiments

The high-priority bus manager kept getting starved. A watchdog timer detected the failure and rebooted the rover -- over and over. Engineers on Earth diagnosed the problem and uploaded a fix: **priority inheritance**.

**Shell usage:**
```
pi demo     # Walk through the Mars Pathfinder scenario step by step
pi status   # See which processes are currently boosted
```

## Priority Inheritance

**The fix: temporarily boost the slow student.**

Priority inheritance is the kernel's solution to priority inversion. When a high-priority thread blocks on a mutex held by a lower-priority thread, the kernel temporarily **boosts** the holder's priority to match the waiter's.

Back to our classroom:

1. Fast Student says "I need the textbook"
2. The teacher sees Fast Student is blocked waiting for Slow Student
3. The teacher says "Slow Student, you're temporarily promoted to priority 10!"
4. Now the teacher calls on Slow Student (priority 10) instead of Normal Student (priority 5)
5. Slow Student finishes quickly, returns the textbook
6. Slow Student drops back to priority 1
7. Fast Student gets the textbook and proceeds

### Transitive Inheritance

What if Slow Student is *also* waiting for something? The boost propagates through the chain:

```
Fast Student (priority=10) blocked on Textbook, held by Normal Student (priority=5)
Normal Student also blocked on Calculator, held by Slow Student (priority=1)

Result: Slow Student boosted to 10, Normal Student boosted to 10
When Slow Student returns Calculator -> Normal Student gets it, Slow Student drops to 1
When Normal Student returns Textbook -> Fast Student gets it, Normal Student drops to 5
```

The kernel walks the chain of "who is blocked on what" and boosts everyone in the path. Loop detection (via a visited set) prevents infinite chains.

### How It Works

Each process has two priority values:

- **Base priority** -- the original, immutable priority set at creation
- **Effective priority** -- what the scheduler actually uses (may be boosted)

When no inheritance is active, `effective_priority == base_priority`. When a boost happens, only the effective priority changes. When the mutex is released, the kernel recalculates: it looks at all mutexes the process still holds, finds the highest-priority waiter across all of them, and sets `effective_priority = max(base_priority, max_waiter_priority)`.

## Deadlock

Deadlock is the nightmare scenario: two or more processes are stuck forever,
each holding a resource the other needs. Nobody can move. It's like two people
in a narrow hallway, each refusing to step aside.

### The Four Coffman Conditions

In 1971, computer scientists Coffman, Elphick, and Shoshani proved that
deadlock can only happen when *all four* of these conditions hold at the same
time:

1. **Mutual exclusion** -- a resource can only be used by one process at a time
   (like a bathroom with a lock).
2. **Hold and wait** -- a process can hold resources while waiting for more
   (like a student holding one textbook while asking for another).
3. **No preemption** -- you can't forcibly take a resource from someone
   (no grabbing the textbook out of their hands).
4. **Circular wait** -- A waits for B, B waits for A, forming a circle
   (like two people at a revolving door, each waiting for the other to go first).

Break *any one* of these and deadlock becomes impossible.

### Deadlock Prevention: Resource Ordering

PyOS prevents deadlock by attacking the **circular wait** condition using
**resource ordering**.

**Analogy: Numbered lockers in a school hallway.** The rule: you can only walk
forward. If you need locker 3 and locker 7, open 3 first, then walk forward
to 7. You can never go backwards. Nobody ever gets stuck in a circle.

Here's why this works: imagine you need lockers 3 and 7, and your friend needs
lockers 7 and 3. With the "always go forward" rule:

- You open locker 3 first, then walk to 7.
- Your friend also opens locker 3 first (they can't start at 7!), then walks to 7.
- No circle is possible because everyone walks the same direction.

In PyOS, every resource (mutex, semaphore, reader-writer lock) gets a numeric
**rank**. Before a process acquires a resource, the kernel checks: "Is this
rank higher than everything I already hold?" If yes, allowed. If no, it's a
violation.

### Three Modes

| Mode | What happens on violation |
|------|--------------------------|
| **strict** | Reject the acquire -- the process can't get the resource |
| **warn** | Allow it, but record the violation for debugging |
| **off** | No checking at all (maximum performance) |

**Shell usage:**
```
ordering mode strict
ordering register mutex:lock_a 1
ordering register mutex:lock_b 2
ordering status
ordering violations
ordering demo
```

### Prevention vs. Detection

PyOS has *two* complementary approaches to deadlock:

| Aspect | Prevention (ordering) | Detection (Banker's algorithm) |
|--------|----------------------|-------------------------------|
| **When** | *Before* deadlock happens | *After* deadlock happens |
| **How** | Structural rule (rank ordering) | Periodic scan (safety check) |
| **Overhead** | One comparison per acquire | Full matrix computation |
| **Guarantee** | Deadlock impossible | Deadlock found and reported |
| **Trade-off** | May reject valid acquires | Doesn't prevent deadlock |
| **Module** | `sync/ordering.py` | `sync/deadlock.py` |

Think of it this way: ordering is like a one-way street (prevents collisions),
while detection is like a traffic camera (catches collisions after they happen).
Best practice is to use both: ordering prevents most deadlocks cheaply, and
detection catches any that slip through.

## How It Works in PyOS

PyOS implements all four primitives in `sync/primitives.py`, plus priority
inheritance in `sync/inheritance.py` and deadlock prevention in
`sync/ordering.py`:

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `Mutex` | Mutual exclusion | `acquire(tid)`, `release(tid)`, `waiters` |
| `Semaphore` | Counting lock | `acquire(tid)`, `release()` |
| `Condition` | Wait/notify | `wait(tid)`, `notify()`, `notify_all()` |
| `ReadWriteLock` | Multiple readers / one writer | `acquire_read(tid)`, `acquire_write(tid)`, `release_read(tid)`, `release_write(tid)` |
| `SyncManager` | Registry | `create_mutex()`, `create_semaphore()`, `create_condition()`, `create_rwlock()` |
| `PriorityInheritanceManager` | Prevent priority inversion | `on_acquire()`, `on_block()`, `on_release()` |
| `ResourceOrderingManager` | Prevent deadlock (resource ordering) | `register()`, `check_acquire()`, `on_acquire()`, `on_release()` |

The kernel owns a `SyncManager`, a `PriorityInheritanceManager`, and a `ResourceOrderingManager`, all created during boot and torn down during shutdown. All user-space access goes through system calls (91-93, 110-125), and the shell provides `mutex`, `semaphore`, `rwlock`, `pi`, and `ordering` commands.

The `PriorityInheritanceManager` tracks which process holds each mutex, which processes are blocked waiting, and coordinates priority boosts. The Mutex itself stays simple -- all coordination logic lives in the PI manager.

## Syscall Interface

| Number | Name | What It Does |
|--------|------|--------------|
| 110 | SYS_CREATE_MUTEX | Create a named mutex |
| 111 | SYS_ACQUIRE_MUTEX | Lock a mutex (or queue if held); optional `pid` enables PI tracking |
| 112 | SYS_RELEASE_MUTEX | Unlock a mutex; optional `pid` triggers priority recalculation |
| 113 | SYS_CREATE_SEMAPHORE | Create a counting semaphore |
| 114 | SYS_ACQUIRE_SEMAPHORE | Decrement semaphore (or queue if zero) |
| 115 | SYS_RELEASE_SEMAPHORE | Increment semaphore |
| 116 | SYS_CREATE_CONDITION | Create a condition variable |
| 117 | SYS_CONDITION_WAIT | Wait on a condition |
| 118 | SYS_CONDITION_NOTIFY | Wake waiters on a condition |
| 119 | SYS_CREATE_RWLOCK | Create a reader-writer lock |
| 122 | SYS_ACQUIRE_READ_LOCK | Acquire read access (or queue) |
| 123 | SYS_ACQUIRE_WRITE_LOCK | Acquire write access (or queue) |
| 124 | SYS_RELEASE_READ_LOCK | Release read access |
| 125 | SYS_RELEASE_WRITE_LOCK | Release write access |

No new syscall numbers were added for priority inheritance -- the existing `SYS_ACQUIRE_MUTEX` (111) and `SYS_RELEASE_MUTEX` (112) accept an optional `pid` parameter that activates PI tracking.

**Deadlock prevention syscalls:**

| Number | Name | What It Does |
|--------|------|--------------|
| 91 | SYS_CHECK_ORDERING | Return ordering status (mode, ranks, violations) |
| 92 | SYS_SET_ORDERING_MODE | Set enforcement mode (strict/warn/off) |
| 93 | SYS_REGISTER_RANK | Register a resource with an explicit rank |

## Real-World Examples

- **Mutex**: Protecting a shared log file so lines don't interleave
- **Semaphore**: Limiting database connections to a pool of 10
- **Condition**: A print queue where the printer waits for jobs to arrive
- **Reader-writer lock**: A configuration file that many threads read but only one thread updates
- **Priority inheritance**: The Mars Pathfinder rover fix -- preventing high-priority tasks from starving when they need a mutex held by a low-priority task

## Where to Go Next

With synchronization in place, you have the tools to build higher-level patterns like thread-safe queues and barriers. These primitives are the building blocks of every concurrent system, from web servers to operating systems.

- [Processes](processes.md) -- How threads live inside processes, plus fork, signals, and wait/waitpid
- [Users and Safety](users-and-safety.md) -- Deadlock detection and how the OS keeps things safe
- [Devices and Networking](devices-and-networking.md) -- IPC pipes and message queues that use these primitives under the hood
- [The Shell](shell.md) -- The `mutex`, `semaphore`, and `rwlock` shell commands
