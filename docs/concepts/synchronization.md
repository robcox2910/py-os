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

## How It Works in PyOS

PyOS implements all three primitives in `sync/primitives.py`:

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `Mutex` | Mutual exclusion | `acquire(tid)`, `release(tid)` |
| `Semaphore` | Counting lock | `acquire(tid)`, `release()` |
| `Condition` | Wait/notify | `wait(tid)`, `notify()`, `notify_all()` |
| `SyncManager` | Registry | `create_mutex()`, `create_semaphore()`, `create_condition()` |

The kernel owns a `SyncManager` that is created during boot and torn down during shutdown. All user-space access goes through system calls (110-118), and the shell provides `mutex` and `semaphore` commands.

## Syscall Interface

| Number | Name | What It Does |
|--------|------|--------------|
| 110 | SYS_CREATE_MUTEX | Create a named mutex |
| 111 | SYS_ACQUIRE_MUTEX | Lock a mutex (or queue if held) |
| 112 | SYS_RELEASE_MUTEX | Unlock a mutex |
| 113 | SYS_CREATE_SEMAPHORE | Create a counting semaphore |
| 114 | SYS_ACQUIRE_SEMAPHORE | Decrement semaphore (or queue if zero) |
| 115 | SYS_RELEASE_SEMAPHORE | Increment semaphore |
| 116 | SYS_CREATE_CONDITION | Create a condition variable |
| 117 | SYS_CONDITION_WAIT | Wait on a condition |
| 118 | SYS_CONDITION_NOTIFY | Wake waiters on a condition |

## Real-World Examples

- **Mutex**: Protecting a shared log file so lines don't interleave
- **Semaphore**: Limiting database connections to a pool of 10
- **Condition**: A print queue where the printer waits for jobs to arrive

## Where to Go Next

With synchronization in place, you have the tools to build higher-level patterns like thread-safe queues, reader-writer locks, and barriers. These primitives are the building blocks of every concurrent system, from web servers to operating systems.

- [Processes](processes.md) -- How threads live inside processes, plus fork, signals, and wait/waitpid
- [Users and Safety](users-and-safety.md) -- Deadlock detection and how the OS keeps things safe
- [Devices and Networking](devices-and-networking.md) -- IPC pipes and message queues that use these primitives under the hood
- [The Shell](shell.md) -- The `mutex` and `semaphore` shell commands
