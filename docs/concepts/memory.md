# Memory: How the OS Hands Out and Protects Memory

When a [process](processes.md) runs, it needs somewhere to keep its stuff -- the
variables it's working with, the instructions it's executing, the data it loaded
from a file. That "somewhere" is **memory** (specifically, RAM -- the fast,
temporary storage your computer uses while it's on).

But here's the problem: lots of processes are running at the same time, and they
all need memory. Somebody has to hand it out fairly, keep everyone's stuff
separate, and deal with the situation when there's not enough to go around.

That somebody is the OS.

In PyOS, memory management is split into three files, each handling a different
piece of the puzzle. Let's walk through them one at a time.

---

## 1. Physical Memory (`memory/manager.py`)

### The Locker Analogy

Imagine a long hallway of school lockers. Every locker is exactly the same size,
and they're numbered 0, 1, 2, 3, and so on. When a new student (a
[process](processes.md)) shows up at school, the principal (the OS) assigns them
some lockers to store their stuff in.

In OS terms, each locker is called a **frame**, and the chunk of data that fits
inside one frame is called a **page**. Pages and frames are the same size --
think of a page as the stuff, and a frame as the locker it goes into.

### Why Fixed Sizes?

You might wonder: why make every locker the same size? Why not have some big
lockers and some small ones?

Here's why. Imagine a hallway where lockers come in all different sizes. Over
time, as students come and go, you end up with a bunch of tiny gaps scattered
all over the hallway. You might have 10 small gaps, but none of them is big
enough for a new student who needs a medium locker. This problem is called
**fragmentation** -- you technically have free space, but it's chopped up into
useless little pieces.

Fixed-size lockers avoid this entirely. A free locker is a free locker. Any page
fits in any frame. Simple.

### What Happens When a Process Finishes?

When a [process](processes.md) is done running, the OS takes back all of its
lockers and marks them as free. Now those frames are available for the next
process that needs them. Nothing is wasted.

### What If All the Lockers Are Full?

If every single frame is in use and a new process asks for memory, the OS has
a choice: it can either refuse (raising an **OutOfMemoryError**, which crashes
that process) or it can try to make room using swap space, which we'll get to
in a moment.

---

## 2. Virtual Memory (`memory/virtual.py`)

### The Personal Map Analogy

Here's where things get clever.

Every student gets their own personal map of the locker hallway. On this map, it
says things like:

- "My locker 0 is actually real locker #47"
- "My locker 1 is actually real locker #12"
- "My locker 2 is actually real locker #83"

The student only ever sees their own simple numbering -- 0, 1, 2, 3 -- even
though their actual lockers are scattered all over the hallway. The student
doesn't need to know or care where the real lockers are. They just say "open my
locker 2," and the OS quietly translates that into "go to real locker #83."

This personal map is called a **page table**, and the simple numbering the
student sees is called a **virtual address**. The real, physical locker number
is the **physical address**.

### Address Translation

When a process says "I want the data at my page 3, position 5," the OS does
this:

1. Look up page 3 in that process's page table.
2. The page table says: "Page 3 maps to frame #20."
3. Go to frame #20 in physical memory and find position 5.

That's it. The process said "page 3, position 5" and the OS translated it to
"frame 20, position 5." This translation happens every single time a process
touches memory, and it's fast because the hardware helps out.

### Isolation: Keeping Students Apart

Here's the really important part. Student A and Student B both think they have a
"locker 0." But Student A's locker 0 points to real locker #47, while Student
B's locker 0 points to real locker #91. They're completely different physical
lockers.

This means Student A can never accidentally (or intentionally) read or overwrite
Student B's data. Each [process](processes.md) lives in its own little world,
with its own private numbering, completely unaware of what other processes are
doing. This separation is called **isolation**, and it's one of the most
important jobs of the OS.

### Page Faults

What happens if a student tries to open a locker that isn't on their map at all?
Maybe they ask for "my locker 99" but their map only goes up to locker 5.

That's called a **page fault**. The OS catches it and says, "Hey, you don't have
a locker 99." Depending on the situation, the OS might load the missing page
from disk (more on that below), or it might just stop the process with an error
because it tried to access memory it doesn't own.

---

## 3. Page Replacement and Swap (`memory/swap.py`)

### The Basement Storage Room

OK, so what happens when *all* the lockers in the hallway are full, but a new
student still needs one?

The OS has a trick: there's a storage room in the basement. In real computers,
this "basement" is your hard drive or SSD -- it's much slower than RAM, but
there's a lot more of it. This system is called **swap space**.

Here's how it works:

1. The OS picks a locker that's currently in use.
2. It moves everything from that locker down to the basement storage room.
3. Now that locker is empty, so the OS gives it to the new student.
4. Later, when the original owner needs their stuff back, the OS finds another
   locker to free up, brings the stuff back from the basement, and the process
   continues like nothing happened.

The tricky part is step 1: **which locker do you pick?** You want to pick one
that won't be needed again soon, so you don't have to keep shuffling things back
and forth between the hallway and the basement. That shuffling is slow, and too
much of it (called **thrashing**) makes the whole computer grind to a halt.

### Three Strategies for Picking a Locker

#### FIFO -- First In, First Out

The simplest idea: empty whichever locker has had the same stuff in it the
longest. If locker #12 was filled first, it gets emptied first.

This is easy to implement -- you just keep a list in order. But it's not always
smart. Sometimes the oldest stuff is actually the stuff you use the *most*.
Imagine emptying the locker of the student who visits it every single period just
because they got it a long time ago. Not great.

#### LRU -- Least Recently Used

A smarter idea: empty the locker that nobody has opened in the longest time. If
locker #7 hasn't been touched in three hours but locker #12 was opened five
minutes ago, empty locker #7.

This usually makes better choices than FIFO, because stuff that hasn't been used
in a while probably won't be used again soon. The downside? You have to keep
track of *every single time* someone opens a locker, which takes extra work and
extra bookkeeping.

#### Clock -- Second Chance

This is the clever compromise that most real operating systems actually use.

Picture a clock hand sweeping around a circle of lockers. Each locker has a tiny
flag -- a single bit that means "I was used recently."

When the OS needs to free a locker, the clock hand starts sweeping:

1. It looks at the locker it's pointing to.
2. If the flag is **up** ("I was used recently!"), the OS puts the flag **down**
   and moves the hand to the next locker. That locker gets a second chance.
3. If the flag is **down** ("I haven't been used in a while"), the OS empties
   that locker and uses it.

The clock hand keeps going around and around, like the hand of an actual clock.
Any locker that gets used has its flag set back up. So the only lockers that get
emptied are the ones that haven't been used since the last time the hand came
around.

This is nearly as smart as LRU -- it avoids emptying recently-used lockers --
but it's *much* simpler because you only need one flag per locker instead of a
full history of every access.

### Demand Paging

There's one more idea worth knowing about: **demand paging**.

When a [process](processes.md) starts up, the OS doesn't immediately load all of
its pages into memory. That would be wasteful -- maybe the process has a ton of
data but only uses a small piece of it right away. Instead, the OS waits.

When the process actually tries to read a page that isn't in memory yet, a
**page fault** happens. But this time it's not an error -- it's expected. The OS
says, "Oh, you need that page? Hold on." It pauses the process, loads the page
from disk into a free frame (evicting another page if necessary), updates the
page table, and then lets the process continue. The process doesn't even know it
was paused.

This "load it only when you need it" approach is called demand paging, and it
means programs can start faster and use less memory overall, because they only
occupy frames for the pages they're actually using right now.

---

## Putting It All Together

Here's how these three pieces work as a team:

1. **Physical memory** (`memory/manager.py`) manages the actual frames -- the real
   lockers in the hallway. It tracks which ones are free and which ones are
   taken.

2. **Virtual memory** (`memory/virtual.py`) gives each process its own private
   map (page table) so that processes see clean, simple addresses and can't
   interfere with each other.

3. **Swap** (`memory/swap.py`) handles the overflow. When memory is full, it moves
   pages to disk and brings them back when needed, using a replacement strategy
   (FIFO, LRU, or Clock) to decide what to move.

Together, they create the illusion that every [process](processes.md) has its own
big, private chunk of memory -- even if the physical RAM is small and shared
among many processes. That illusion is one of the most powerful tricks in all of
computing.

---

## Where to Go Next

- [Processes](processes.md) -- How the OS runs programs and shares the processor
- [What Is an OS?](what-is-an-os.md) -- The big picture of how an OS works
- [Filesystem](filesystem.md) -- How files and folders are organized and stored
