# Users and Safety

Your computer is not just for you. Even if you are the only person sitting at the keyboard, there are dozens of programs running at the same time -- a web browser, a music player, background updaters. The operating system needs to keep track of *who* is allowed to do *what*, handle emergencies when things go wrong, keep a record of everything that happened, and prevent programs from getting stuck in traffic jams. This page covers all four of those jobs.

---

## Users and Permissions

Think of a school library. Every student has a library card with a unique number printed on it. When you check out a book, the librarian stamps your card number on the back cover. Now anyone who picks up that book can see who checked it out.

An operating system works the same way.

### UIDs and Usernames

Every user gets two things when their account is created:

| Field | What it is | Example |
|-------|-----------|---------|
| **UID** | A unique ID number (like your library card number) | `0`, `1`, `1000` |
| **Username** | A human-friendly name | `"alice"`, `"bob"`, `"root"` |

The UID is what the system actually uses behind the scenes. The username is just a label so humans do not have to memorize numbers.

### File Ownership

When you create a [file](filesystem.md), your UID gets stamped on it. You are now the **owner** of that file. This is exactly like the librarian stamping your card number on a book -- the file knows who made it.

### Permissions

Owning a file is not enough on its own. The system also tracks what you are *allowed to do* with each file. Permissions answer two questions for two groups of people:

| | Can they read it? | Can they write to it? |
|---|---|---|
| **Owner** (the person who made the file) | Maybe | Maybe |
| **Everyone else** | Maybe | Maybe |

Each of those four slots is either "yes" or "no." When you create a file, you decide the initial permissions. For example, you might say "I can read and write this file, but everyone else can only read it." That way, other users can look at your homework but they cannot change your answers.

### The root User

There is one special user that exists on every system: **root**, who always has UID 0.

Root is like the school principal. The principal can walk into any classroom, open any locker, and read any file in the school office. There are no locked doors for the principal. In the same way, root can read and write *any* file on the system, regardless of what the permissions say. Root is sometimes called the **superuser** because they have super-powered access to everything.

On a real Unix system, root can do absolutely anything -- install programs, delete other users, change system settings, even break the operating system. That is why you should only use root when you truly need it. Running as root all the time is like leaving every door in the school unlocked. It works, but it is asking for trouble.

### Try it in the PyOS shell

```
pyos> whoami
alice (uid=1000)

pyos> adduser bob
User 'bob' created with uid=1001

pyos> su bob
Switched to user 'bob'

pyos> whoami
bob (uid=1001)
```

- `whoami` -- tells you which user you are right now.
- `adduser` -- creates a new user account.
- `su` -- short for "switch user." It lets you become a different user, kind of like handing your library card to someone else (except you get it back later).

---

## Signals

Imagine you are sitting in class, focused on your work. Someone taps you on the shoulder. You look up. That tap is a **signal** -- a small message sent from one [process](processes.md) to another (or from the operating system to a process) that says "hey, pay attention."

Different taps mean different things.

### The Six Signals

| Signal | What it means | Real-life version | Can you catch it? | Default action |
|--------|--------------|-------------------|-------------------|----------------|
| **SIGKILL** (9) | "STOP RIGHT NOW." | Being physically picked up and removed from the room | No | Terminate |
| **SIGUSR1** (10) | "Custom tap #1" | A secret handshake only your friend understands | Yes | Ignore |
| **SIGUSR2** (12) | "Custom tap #2" | A different secret handshake | Yes | Ignore |
| **SIGTERM** (15) | "Please stop what you're doing." | A polite tap on the shoulder | Yes | Terminate |
| **SIGCONT** (18) | "Ok, you can move again." | Someone unfreezes you in freeze tag | Yes | Continue |
| **SIGSTOP** (19) | "Freeze! Don't move." | A game of freeze tag -- you are frozen in place | No | Stop |

SIGTERM is the polite way to ask a process to stop. The process receives the signal and gets a chance to wrap up what it is doing -- save files, close connections, say goodbye. Most of the time, this is what you want.

SIGKILL is the emergency stop. It can *never* be caught, blocked, or ignored. The operating system itself handles SIGKILL by immediately yanking the process off the CPU and marking it as [TERMINATED](processes.md). The process does not get a chance to clean up. This sounds harsh, but it is necessary. If a program goes haywire and stops responding to polite requests, you need a guaranteed way to shut it down. That is why `kill -9` (SIGKILL's number is 9) always works on a real Unix system.

SIGSTOP and SIGCONT work together like a pause and play button. SIGSTOP freezes a process in place -- it is still alive, but it is not doing anything. SIGCONT unfreezes it and lets it pick up where it left off. These are useful for debugging or for temporarily suspending a process that is using too many resources. Like SIGKILL, SIGSTOP is **uncatchable** -- you cannot register a handler for it. This guarantees that you can always pause a process, no matter what.

### User-Defined Signals: SIGUSR1 and SIGUSR2

SIGUSR1 and SIGUSR2 are like **custom shoulder taps**. They have no built-in meaning -- the operating system does not do anything special when they arrive. By default, they are simply ignored.

But a process can register a handler for them, and then they become a private communication channel. Imagine you and your friend agree: "If I tap you twice on the left shoulder, it means 'check your phone.'" That tap only means something because you both agreed on it.

In real Unix, programs use SIGUSR1 and SIGUSR2 for things like telling a server to reload its configuration file or triggering a status dump. They are completely up to the programmer.

### Signal Handlers

Here is where it gets interesting. A process can set up a **signal handler** -- a function that runs automatically when a specific signal arrives. Think of it like telling a friend: "If someone taps me on the left shoulder, remind me to save my work before I turn around."

```python
# "When I receive SIGTERM, run my cleanup function first"
kernel.register_signal_handler(pid, SIGTERM, my_cleanup_function)
```

When SIGTERM arrives, instead of the default action (terminating the process), the handler runs *instead*. The process stays alive. Maybe the handler saves a file. Maybe it sends a goodbye message. Maybe it decides to keep running. The handler **replaces** the default action -- this is exactly how real Unix works.

This is *why* SIGKILL exists. If a process could catch SIGTERM and just... not stop, you would need an uncatchable signal as a last resort. SIGKILL is that last resort.

SIGCONT is special: even if you register a handler for it, the process always resumes. The handler fires *in addition to* the default resume, not instead of it. This prevents a bug where registering a SIGCONT handler accidentally makes a frozen process unresumable.

But here is the critical part: you cannot set a handler for SIGKILL or SIGSTOP. There is no negotiating with them. They do not knock -- they kick the door down. That is by design. If programs could ignore SIGKILL, a broken program could become truly unstoppable, and you would have to restart your entire computer to get rid of it.

---

## Logging

Every school has security cameras. They record what happens throughout the day -- who entered the building in the morning, who went to which classroom, whether anyone tripped the fire alarm. If something goes wrong, you can rewind the footage and figure out what happened.

The [kernel](kernel-and-syscalls.md) has its own version of security cameras: the **logger**. It records events as they happen inside the operating system. When something breaks, the log is the first place you look.

### Log Levels

Not every event is equally important. The logger uses **levels** to mark how serious each message is, from least to most important:

| Level | What it means | Example |
|-------|--------------|---------|
| **DEBUG** | Tiny details, useful for digging into problems | "System call SYS_READ executed by pid=3" |
| **INFO** | Normal events, things working as expected | "System booted successfully" |
| **WARNING** | Something unusual that might become a problem | "Memory usage at 85%" |
| **ERROR** | Something actually went wrong | "Process 7 crashed with exit code 1" |

Think of it this way. DEBUG is like the security camera footage of a student walking through the hallway -- nothing interesting, but useful if you need to retrace someone's steps. INFO is the morning announcement that school is open. WARNING is a note that the library is almost full and might need to start turning people away. ERROR is the fire alarm going off.

Every [system call](kernel-and-syscalls.md) gets logged at the DEBUG level. Boot events get logged at INFO. This means the log can get very long very quickly, which is why the levels exist -- you can filter for just WARNINGs and ERRORs when you do not need all the tiny details.

### Try it in the PyOS shell

```
pyos> log
[INFO] System booted at tick 0
[INFO] User 'root' logged in
[DEBUG] SYS_CREATE_PROCESS: pid=1 name='init'
[DEBUG] SYS_EXEC: pid=1 program='hello'
[WARNING] Memory usage at 85%
```

The `log` command shows you the kernel's log. It is like pulling up the security footage and scrolling through it. When something goes wrong and you are not sure why, the log is your best friend.

---

## Deadlock

Imagine two people walking toward each other in a narrow hallway. Each one is carrying a big cardboard box. They meet in the middle. Person A cannot move forward because Person B is in the way. Person B cannot move forward because Person A is in the way. Neither person can back up because, well, they are both stubborn. They are stuck. Forever.

That is a **deadlock**.

In operating system terms, a deadlock happens when two or more [processes](processes.md) are each waiting for something that only the other one can provide. Nobody can make progress, so everything freezes.

### The Four Conditions

A deadlock can only happen when ALL four of these conditions are true at the same time. If even one is missing, you are safe.

**1. Mutual exclusion** -- Only one process can use a resource at a time. Think of the narrow hallway: only one person fits through at once. If the hallway were wide enough for both, there would be no problem.

**2. Hold and wait** -- Each process is holding onto one resource AND waiting for another. Each person is holding their box AND waiting for the other person to move. If one of them put their box down, they could squeeze past.

**3. No preemption** -- You cannot force a process to give up its resource. Nobody can force either person to drop their box. In some systems, the OS *can* forcibly take resources away, which breaks this condition.

**4. Circular wait** -- The waiting forms a circle. A waits for B, and B waits for A. If A was waiting for B but B was not waiting for A (maybe B was waiting for C, who was free), then B could eventually finish and free things up for A.

Break any ONE of these four conditions and deadlocks become impossible.

### Prevention: The Banker's Algorithm

One approach to dealing with deadlocks is to prevent them from ever happening. The most famous prevention method is called the **Banker's Algorithm**, and the analogy is right there in the name.

Imagine a small-town banker who gives out loans. The banker has a limited amount of money in the vault. Several customers want loans, and the banker knows the maximum each customer might eventually need. Before approving any new loan, the banker asks: "If I give this loan, will I still have enough money left to make sure *everyone* can eventually pay me back?"

If the answer is yes, the loan is **safe** -- go ahead and approve it. If the answer is no, the loan is **unsafe** -- deny it, even if the customer is upset. Better to say "not right now" than to run out of money and leave everyone stuck.

The OS does the same thing with resources (like [memory](memory.md) or access to devices). Before granting a resource to a process, it checks: "If I give this out, is there still a sequence where every process can finish?" If yes, grant it. If no, make the process wait.

The downside of prevention is that it is *conservative*. Sometimes the banker says "no" even when things would have been fine. But the upside is powerful: deadlocks literally cannot happen.

### Detection: Find and Fix

The other approach is the opposite philosophy: let processes grab whatever resources they want, but periodically check whether a deadlock has actually occurred.

Detection works by looking for circular waits in the system. If Process A is waiting for Process B, and Process B is waiting for Process A, the detector spots that circle and reports it.

This approach is more permissive -- processes are never told "no" just in case. But you need a plan for what to do when a deadlock is found. Usually, the OS picks one of the stuck processes and terminates it (using [SIGKILL](#the-four-main-signals)) to break the circle. Tough luck for that process, but it frees everyone else.

### Two Philosophies

| | Prevention (Banker's) | Detection |
|---|---|---|
| **When it checks** | Before granting a resource | After the fact, periodically |
| **Can deadlocks happen?** | No, never | Yes, but they get caught |
| **Downside** | Sometimes says "no" unnecessarily | A process might get killed to break the deadlock |
| **Best for** | Systems where deadlocks are unacceptable (medical, aviation) | Systems where occasional recovery is fine |

### Try it in the PyOS shell

```
pyos> resources
Resource Allocation Table:
  Process 1 holds: [Printer]  waiting for: [Scanner]
  Process 2 holds: [Scanner]  waiting for: [Printer]

pyos> deadlock
Deadlock detected! Processes 1 and 2 are in a circular wait.
```

- `resources` -- shows you which processes are holding which resources and what they are waiting for.
- `deadlock` -- checks the current state for circular waits and tells you if any processes are stuck.

---

## Putting It All Together

These four systems work together to keep the operating system running safely and smoothly.

**Users and permissions** make sure that one person cannot mess with another person's files. The [filesystem](filesystem.md) stamps every file with an owner, and the [kernel](kernel-and-syscalls.md) checks permissions before allowing any read or write.

**Signals** give the OS a way to communicate with [processes](processes.md) -- politely asking them to stop, forcibly killing them if they refuse, or pausing and resuming them as needed.

**Logging** records everything that happens so you can figure out what went wrong after the fact. Every system call, every boot event, every error gets written down.

**Deadlock handling** prevents or detects situations where processes get permanently stuck waiting for each other, keeping the system from freezing up.

Together with [processes](processes.md), [memory management](memory.md), the [filesystem](filesystem.md), and the [kernel](kernel-and-syscalls.md), these pieces form the safety net that lets dozens of programs run at the same time without stepping on each other's toes.

---

## Key Terms

| Term | Definition |
|------|-----------|
| **UID** | User Identifier -- a unique number assigned to each user account |
| **root** | The superuser (UID 0) who can read and write any file on the system |
| **Permissions** | Rules that control who can read and write each file |
| **Signal** | A small message sent to a process to notify it of an event |
| **SIGTERM** | A polite request for a process to stop (can be caught and handled) |
| **SIGKILL** | A forced termination that cannot be caught or ignored |
| **SIGSTOP** | A forced pause that cannot be caught or ignored |
| **SIGUSR1 / SIGUSR2** | User-defined signals with no built-in meaning (ignored by default) |
| **Uncatchable** | A signal (SIGKILL, SIGSTOP) for which no handler can be registered |
| **Signal handler** | A function that runs automatically when a specific signal is received, replacing the default action |
| **Default action** | What the kernel does when a signal arrives and no handler is registered (terminate, stop, continue, or ignore) |
| **Logger** | The kernel subsystem that records events as they happen |
| **Log level** | A label (DEBUG, INFO, WARNING, ERROR) indicating how serious a log entry is |
| **Deadlock** | A situation where two or more processes are stuck waiting for each other forever |
| **Mutual exclusion** | A resource can only be used by one process at a time |
| **Banker's Algorithm** | A deadlock prevention method that checks whether granting a resource is safe |
| **Circular wait** | A cycle of processes where each is waiting for the next one in the circle |
