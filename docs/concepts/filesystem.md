# The Filesystem

You use files every day. Your homework, your photos, your game saves -- they all
live somewhere on your computer. But have you ever wondered *how* the computer
keeps track of all of them? That is the job of the **filesystem**.

## What Is a Filesystem?

Think of a filesystem like a giant **filing cabinet**.

The cabinet has drawers, and those drawers are **directories** (also called
folders). Inside the drawers you'll find papers, and those papers are **files**.
Drawers can contain other drawers too -- a folder inside a folder inside a
folder, as deep as you want.

Now here is the interesting part. Every paper and every drawer has a little
**index card** stapled to it. That index card records important facts: is this a
file or a folder? How big is it? What's actually inside? In operating system
terms, that index card is called an **inode** (short for "index node"). We'll
dig into inodes in a moment.

But first, there is one more surprising detail. The *name* of a file doesn't
live on the file itself. It lives in the drawer (directory) that the file sits
inside. It's like how a teacher's attendance sheet has your name on it, but the
actual essay you turned in doesn't have your name written on the pages -- the
folder it's in tells the teacher whose work it is.

In our code (`fs/filesystem.py`), the `FileSystem` class manages all of this. When
you create a file or folder, the filesystem creates a new inode and then adds
the name to the parent directory's list. The name and the data live in different
places, connected by a number.

## Inodes: The Index Cards

Every file and every directory in the filesystem gets its own numbered index
card -- an **inode**. You can think of the inode number as a student ID. The
school (filesystem) uses the ID to look up everything it needs to know about
you.

Here is what an inode keeps track of:

- **Type** -- Is this a file or a directory?
- **Size** -- How many bytes of data does it hold?
- **Data** -- For a file, this is the actual contents (the text, the image, the
  bytes). For a directory, this is a list of "name to inode number" mappings --
  basically the table of contents for that drawer.

In our Python code, the `_Inode` class looks like this (simplified):

```python
@dataclass
class _Inode:
    inode_number: int
    file_type: FileType      # FILE, DIRECTORY, or SYMLINK
    data: bytes = b""        # file contents (or symlink target path)
    children: dict[str, int] # name -> inode number (for directories)
    link_count: int = 1      # how many names point to this inode
```

Notice the `children` dictionary. If this inode is a directory, `children` maps
each child's name to its inode number. That is the "attendance sheet" we talked
about -- the names live here, not on the files themselves.

Why does this matter? In real Unix systems, this separation is what makes
**hard links** possible. Two different names in two different folders can point
to the same inode number -- the same underlying file. It's like two teachers
both having your student ID on their attendance sheets, but there's only one
you.

## Path Resolution: Finding Your File

When you ask the computer for a file like `/home/rob/homework.txt`, it doesn't
magically jump straight to it. It has to **walk the path**, one step at a time,
like following directions on a treasure map.

Here's how it works:

1. **Start at the root** (`/`) -- this is the main filing cabinet, the top-level
   directory. Every path starts here.
2. **Look up "home"** in the root directory's children -- the root inode has a
   mapping that says "home" is at inode 2 (or whatever number). Follow that.
3. **Look up "rob"** in the "home" directory's children -- another mapping,
   another inode number. Follow that too.
4. **Look up "homework.txt"** in the "rob" directory's children -- this time
   it points to a file inode. You've found it.

Each step is a lookup: "does this directory have something called X?" If the
answer is yes, you follow the inode number and keep going. If the answer is no,
you get a `FileNotFoundError` -- the path is broken somewhere along the way.

In `fs/filesystem.py`, the `_resolve` method does exactly this:

```python
def _resolve(self, path: str) -> _Inode | None:
    parts = path.strip("/").split("/")
    current = self._inodes[self._root_ino]

    for part in parts:
        child_ino = current.children.get(part)
        if child_ino is None:
            return None
        current = self._inodes[child_ino]

    return current
```

It splits the path into parts (`["home", "rob", "homework.txt"]`), then loops
through them one by one, hopping from directory to directory. Simple and clean.

When [The Kernel](kernel-and-syscalls.md) receives a filesystem syscall (like
"read this file" or "list this directory"), the kernel hands the path to the
filesystem, and this resolution process kicks in before anything else happens.

## Links: Multiple Names for One File

Remember how names live in the parent directory, not on the file itself? That
separation makes something really cool possible: one file can have **more than
one name**. There are two kinds of links in Unix, and they work very
differently.

### The Phone Contacts Analogy

**Hard link** = Two entries in your phone's contacts that both reach the same
person. "Mom" and "Emergency Contact" both dial the same number. If you delete
"Mom", the person is still reachable through "Emergency Contact". The person
only truly disappears from your phone when you delete *every* contact entry for
that number.

**Symbolic link** = A sticky note on your desk that says "Call Mom's number". It
doesn't store the number itself -- it points to the contact entry. If someone
deletes "Mom" from your contacts, the sticky note is useless (a *dangling*
link). But if someone later adds "Mom" back, the sticky note works again.

### Hard Links

A hard link is a second name that points to the **same inode**. Since both
names point to the same inode number, they share everything: the same data, the
same size, the same type. Writing through one name changes the data for the
other name too, because there is only one copy of the data.

```
Directory /         Directory /docs
name → inode        name → inode
─────────────       ─────────────
hello.txt → 5      ref.txt → 5      ← same inode!
```

In PyOS:

```python
fs.create_file("/hello.txt")
fs.write("/hello.txt", b"Hi!")
fs.link("/hello.txt", "/docs/ref.txt")

# Both names read the same data:
fs.read("/docs/ref.txt")   # b"Hi!"
```

**Rules for hard links:**

- You cannot hard-link directories. If you could, the directory tree would have
  loops, and path resolution would never finish.
- The target file must already exist.
- The new name must not already exist.

### Link Count

How does the OS know when to actually delete a file's data? It uses a **link
count** -- a counter on the inode that tracks how many names point to it. Every
time you create a hard link, the count goes up. Every time you delete a name,
the count goes down. The inode (and its data) is only freed when the count hits
zero.

```
fs.stat("/hello.txt").link_count   # 1  (just created)
fs.link("/hello.txt", "/alias.txt")
fs.stat("/hello.txt").link_count   # 2  (two names now)
fs.delete("/hello.txt")
fs.stat("/alias.txt").link_count   # 1  (one name left, data still alive)
fs.delete("/alias.txt")            # link_count → 0, inode freed
```

### Symbolic Links (Symlinks)

A symbolic link is a completely different kind of inode. Instead of pointing to
the same inode number, it creates a **new inode** whose data is the *path* to
the target. It is like a shortcut file that says "go look over there".

```python
fs.create_file("/target.txt")
fs.symlink("/target.txt", "/shortcut.txt")

fs.readlink("/shortcut.txt")   # "/target.txt"
fs.read("/shortcut.txt")       # reads /target.txt's data (followed the link)
```

The filesystem follows symlinks **automatically** during path resolution. When
`_resolve()` encounters a symlink, it reads the stored target path and
continues resolving from there.

**What makes symlinks special:**

- The target **doesn't have to exist**. You can create a symlink pointing to
  `/nonexistent`, and the symlink itself is valid. It just can't be followed
  until the target exists. This is called a **dangling symlink**.
- You **can** symlink directories. This is safe because symlinks have depth
  protection (see below).
- Symlinks can be **relative** (`real.txt`) or **absolute** (`/data/real.txt`).
  Relative targets resolve from the symlink's parent directory.

### Loop Detection

What if symlink A points to B, and B points back to A? The filesystem would
follow links forever. To prevent this, `_resolve()` counts how many symlinks
it has followed. If the count exceeds `MAX_SYMLINK_DEPTH` (40, matching Linux),
it raises an error: "Too many levels of symbolic links".

```python
fs.symlink("/b", "/a")   # /a → /b
fs.symlink("/a", "/b")   # /b → /a (circular!)
fs.stat("/a")             # OSError: Too many levels of symbolic links
```

### stat vs. lstat

The `stat()` function follows symlinks -- if you stat a symlink, you get the
target's metadata. But sometimes you want to see the symlink itself. That is
what `lstat()` does: it returns the symlink's own inode info (type=SYMLINK,
size=length of the target path) without following it.

```python
fs.stat("/shortcut.txt").file_type    # FileType.FILE (the target)
fs.lstat("/shortcut.txt").file_type   # FileType.SYMLINK (the link itself)
```

### Deleting Links

- **Deleting a hard link** removes one name and decrements the link count. The
  data survives as long as at least one name remains.
- **Deleting a symlink** removes the symlink inode. The target is untouched.
- **Deleting the target of a symlink** leaves the symlink dangling -- the
  symlink still exists, but following it produces a "not found" error.

## Saving to Disk: Persistence

Here is a problem. Our filesystem lives entirely in Python's memory. That means
when you turn off the computer (or stop the program), everything vanishes. Gone.
It is like building a beautiful filing cabinet out of ice -- when the power goes
out, the whole thing melts.

To solve this, we need **persistence** -- a way to save the filing cabinet so we
can rebuild it later. That's what `fs/persistence.py` does.

### The Photograph Analogy

Imagine taking a photograph of every single drawer and every single paper in
your filing cabinet. You write down what's in each drawer, what each paper
says, and how everything is organized. Then you save all those photographs in a
safe place.

When the power comes back on, you look at the photographs and carefully rebuild
the entire cabinet from scratch. That process of taking the photograph is called
**serialization** (turning the live data into a storable format). Rebuilding the
cabinet from the photograph is called **deserialization** (turning the stored
format back into live data).

### JSON: Our "Photograph" Format

Our "photographs" are saved as **JSON** -- a simple text format that looks like
this:

```json
{
  "root_ino": 0,
  "inodes": {
    "0": {
      "inode_number": 0,
      "file_type": "directory",
      "data": "",
      "children": {"homework.txt": 1}
    },
    "1": {
      "inode_number": 1,
      "file_type": "file",
      "data": "SGVsbG8gd29ybGQ=",
      "children": {}
    }
  }
}
```

You can read it with your eyes -- it's just text. That is the whole point. JSON
is human-readable, which makes it great for learning. You can open the saved
file and see exactly what your filesystem looked like.

### Base64: Translating Pictures Into Words

Wait -- there's a catch. JSON is a *text* format, but files can contain *binary*
data (raw bytes, like images or compiled programs). You can't just shove random
bytes into a text file. It would break.

The solution is **Base64 encoding**. Think of it as translating a picture into
words so it can be written in a text file. Base64 takes any sequence of bytes
and converts it into safe text characters (letters, numbers, `+`, `/`, and `=`).
The text is about 33% bigger than the original bytes, but it fits perfectly in
JSON.

In our code, `to_dict()` encodes file data with `base64.b64encode()`, and
`from_dict()` decodes it back with `base64.b64decode()`. The data makes a round
trip without losing a single byte.

### How Real Filesystems Do It

Real operating systems (Linux, Windows, macOS) don't use JSON. Their filesystems
-- ext4, NTFS, APFS -- write directly to the hard drive in a special **binary
format**. This is much faster and more compact, but much harder to read with
human eyes. The tradeoff is speed versus understandability, and for a learning
project, understandability wins.

Here is a quick comparison:

| PyOS (our version)  | Real Filesystem           |
|---------------------|---------------------------|
| JSON text file      | Binary data on disk       |
| `dump_filesystem()` | `sync` / unmount          |
| `load_filesystem()` | `mount`                   |
| Saves everything    | Only saves what changed   |
| No crash recovery   | Journaling (see below)    |

## Journaling: The Undo-History Safety Net

Imagine you're writing an essay in a text editor. Your editor saves a backup
every 10 minutes (that's a **checkpoint**). Every keystroke you type is recorded
in the undo history (that's the **journal**).

If your computer suddenly loses power, you'd lose everything since the last
save, right? But with a journal, you can do better:

1. Open the last saved backup (restore from checkpoint).
2. Look at the undo history and replay every keystroke that was "finished"
   (committed transactions).
3. Throw away any half-typed words that weren't finished (active/aborted
   transactions).

That's exactly how filesystem journaling works! The journal is a safety net
that lets us recover from crashes without losing completed work.

### What Is a Crash?

A "crash" is anything that stops the computer without warning -- a power
outage, a frozen program, or pulling the plug. The danger is that you might be
in the middle of changing a file. If the power dies after writing half the data,
the file is *corrupted* -- not the old version, not the new version, but a
broken mix of both.

### Write-Ahead Logging: Log Before You Do

The key idea is simple: **write down what you're about to do before you
actually do it**. This is called **write-ahead logging** (WAL). Here's the
pattern every journaled operation follows:

```python
# 1. Begin a transaction
txn = journal.begin()

# 2. Log what we're about to do
journal.append(txn, entry)

# 3. Actually do it
filesystem.create_file(path)

# 4. Mark the transaction as done
journal.commit(txn)
```

If a crash happens between steps 2 and 4, the transaction stays "active"
(uncommitted). On recovery, we know it didn't finish, so we can safely ignore
it.

### Transactions: Begin, Commit, Abort

A **transaction** is a bundle of work that either *fully succeeds* or *fully
fails* -- there's no in-between. Each transaction goes through these states:

| State | Meaning |
|-------|---------|
| **active** | Work is in progress |
| **committed** | All done -- this work should be kept |
| **aborted** | Something went wrong -- throw this away |

In our PyOS code, every filesystem mutation (create, write, delete, link) is
wrapped in its own transaction. This keeps things simple: one operation = one
transaction.

### Checkpoints: The Known-Good Snapshot

A **checkpoint** is like hitting "Save" in your text editor. It takes a
photograph of the entire filesystem at that moment. We call this the
"known-good state" because we know it's consistent and correct.

After a checkpoint, we can also clean up the journal -- we don't need to keep
records of work that's already been safely saved.

```
journal checkpoint    →  "Checkpoint created"
```

### Recovery: Restore + Replay

When you recover from a crash, three things happen:

1. **Restore** the filesystem to the last checkpoint (the last known-good
   state).
2. **Replay** all committed transactions that happened after the checkpoint.
   These were finished work, so we redo them.
3. **Discard** any active or aborted transactions. These were unfinished, so
   we throw them away.

```
journal recover    →  "Recovery complete: replayed 3 transactions"
```

The result? Your filesystem is back to a consistent state, with all completed
work preserved. Only truly unfinished operations are lost.

### Why "Redo" Logging (Not Undo)?

There are two approaches to crash recovery:

- **Redo logging** (what we use): Save the checkpoint, then replay committed
  work forward. Simple and clean.
- **Undo logging**: Record how to reverse each operation. Much more complex
  because you need to figure out the "opposite" of every action.

Real filesystems like ext3 and ext4 use redo logging in "ordered" mode. It's
the simpler approach, and it works great.

### Trying It in PyOS

You can experiment with crash recovery in the PyOS shell:

```
touch /important.txt              # create a file
write /important.txt secret data  # write to it
journal checkpoint                # save a known-good state
touch /experiment.txt             # create another file
write /experiment.txt testing     # write some data
journal crash                     # simulate a power failure!
cat /important.txt                # still here (was checkpointed)
cat /experiment.txt               # Error! (but was committed...)
journal recover                   # replay committed transactions
cat /experiment.txt               # back! recovered from the journal
```

### How Real Filesystems Do It

Real filesystems like ext4 journal their metadata by default. More advanced
systems like ZFS and Btrfs use a technique called **copy-on-write** with
checksums, which gives even stronger protection against corruption.

Our PyOS journal keeps things simple for learning, but the core ideas --
write-ahead logging, transactions, checkpoints, and recovery -- are exactly
what real operating systems use every day to keep your files safe.

## File Descriptors: Bookmarks in a Library Book

So far, every time we wanted to read or write a file, we gave the full path and
got back the *entire* contents. That works fine for small operations, but real
programs need something more flexible. They need to:

- Open a file once, then read a little bit at a time.
- Write a few bytes here, a few bytes there, without replacing the whole file.
- Jump to a specific position in the file (like flipping to page 50).
- Close the file when they're done, so the OS can clean up.

This is where **file descriptors** come in.

### The Library Analogy

Imagine you go to the library and want to read a book. You can't just grab the
book off the shelf -- you have to check it out at the front desk. The librarian
gives you a numbered ticket (your **file descriptor**). You put a **bookmark**
in the book to remember where you stopped reading (the **offset**).

- `open` = check out a book from the library, get your ticket number
- `read` = read from where your bookmark is, then move it forward
- `write` = scribble on the page at your bookmark, then move it forward
- `seek` = move your bookmark to a different page
- `close` = return the book to the library

Why numbered tickets instead of holding the book directly? Because the librarian
(the OS) needs to keep track of who has what checked out. If you leave the
library without returning your books, the librarian can clean up automatically.

### How It Works in PyOS

When you call `open`, the kernel:

1. Checks that the file exists and is not a directory.
2. Creates an **open file description** -- a little record that tracks the file
   path, access mode (read, write, or both), and the current **offset** (starts
   at 0, meaning the beginning of the file).
3. Assigns the lowest available **fd number** (starting at 3) and stores it in
   the process's **fd table**.
4. Returns the fd number to you.

Why does numbering start at 3? In Unix, fds 0, 1, and 2 are reserved:

| FD | Name   | Purpose                          |
|----|--------|----------------------------------|
| 0  | stdin  | Standard input (keyboard)        |
| 1  | stdout | Standard output (screen)         |
| 2  | stderr | Standard error (error messages)  |

We reserve these slots even though PyOS doesn't implement them yet -- it teaches
the convention that every Unix programmer needs to know.

### Access Modes

When you open a file, you choose what you're allowed to do with it:

| Mode | Meaning    | Read? | Write? |
|------|------------|-------|--------|
| `r`  | Read-only  | Yes   | No     |
| `w`  | Write-only | No    | Yes    |
| `rw` | Read-write | Yes   | Yes    |

If you try to read from a write-only fd, or write to a read-only fd, you get an
error. This is **mode enforcement** -- the OS protects you from accidentally
doing something you didn't intend.

### Reading Past the End

What happens if you try to read 100 bytes from a file that only has 10 bytes
left? You just get the 10 bytes that exist. No error, no crash. And if you try
to read when you're already at the very end of the file, you get zero bytes
back (empty). This matches how real Unix works -- programs use "got zero bytes"
as the signal that they've reached the end.

### Writing Past the End

What if you seek past the end of a file and then write? The gap gets filled with
**null bytes** (`\x00`). It's like having a notebook where you skip ahead to
page 50 and start writing -- pages 1 through 49 are just blank.

### Fork and File Descriptors

When a process forks (creates a child copy), the child gets a copy of the
parent's fd table. Both parent and child have the same fd numbers pointing to
the same files. But their offsets are **independent** -- reading in the parent
doesn't move the child's bookmark.

(In real Unix, parent and child actually *share* the same offset. PyOS
simplifies this to independent copies, which is easier to understand.)

### Cleanup

When a process terminates (normally or by signal), the kernel automatically
closes all its open fds. You don't have to worry about leaked file descriptors
-- the OS cleans up after you, just like the librarian knows which books you
checked out and can return them when you leave.

## Putting It All Together

Let's trace what happens when you type `cat /home/rob/homework.txt` in the PyOS
shell:

1. The shell parses your command and sees you want to read a file.
2. The shell sends a **syscall** (system call) to
   [The Kernel](kernel-and-syscalls.md), asking to read `/home/rob/homework.txt`.
3. The kernel passes the request to the filesystem.
4. The filesystem **resolves the path**: root -> "home" -> "rob" ->
   "homework.txt", following inode numbers at each step.
5. It finds the file's inode and reads its `data` field.
6. The data travels back up: filesystem -> kernel -> shell -> your screen.

And when you shut down PyOS and save your work:

7. `dump_filesystem()` serializes every inode into JSON (with Base64 for binary
   data) and writes it to a file on your real hard drive.
8. Next time you boot PyOS, `load_filesystem()` reads that JSON file and
   reconstructs the entire filing cabinet in memory.

That is the full lifecycle of a file, from creation to storage to survival
across reboots.

## Key Vocabulary

| Term              | Plain English                                                  |
|-------------------|----------------------------------------------------------------|
| **Filesystem**    | The system that organizes and manages files and folders         |
| **Inode**         | An index card with metadata about a file or directory           |
| **Directory**     | A folder -- an inode whose "data" is a list of names and inode numbers |
| **Path resolution** | Walking a path like `/a/b/c` step by step to find the target |
| **File descriptor** | A small number (like a library ticket) that identifies an open file |
| **Offset**        | Your current position in the file (like a bookmark)            |
| **Fd table**      | Per-process table that maps fd numbers to open file descriptions |
| **Hard link**     | A second name pointing to the same inode (same data, same file) |
| **Symbolic link** | A special inode that stores a path to another file (a shortcut) |
| **Link count**    | How many names point to an inode; file is freed when it hits zero |
| **Dangling symlink** | A symlink whose target doesn't exist (yet)                  |
| **Symlink loop**  | Circular symlinks (A→B→A); caught by MAX_SYMLINK_DEPTH        |
| **Serialization** | Converting live data into a storable format (like taking a photo) |
| **Deserialization** | Rebuilding live data from a stored format (like rebuilding from a photo) |
| **Base64**        | A way to encode binary data as safe text characters            |
| **JSON**          | A human-readable text format for structured data               |
| **Journaling**    | Writing a plan before doing work, so crashes don't cause corruption |
| **Write-ahead log** | The journal itself -- a record of planned operations         |
| **Transaction**   | A unit of work that fully succeeds or fully fails              |
| **Commit**        | Mark a transaction as successfully completed                   |
| **Abort**         | Mark a transaction as failed or incomplete                     |
| **Checkpoint**    | A snapshot of the filesystem at a known-good point             |
| **Recovery**      | Restoring from checkpoint and replaying committed transactions |
| **Crash consistency** | The guarantee that the filesystem is valid after a crash   |

## Virtual Filesystems -- /proc

So far, every file we've talked about lives on "disk" (in memory, for our
simulator). But what if you could have a directory that doesn't store
anything at all -- and yet, every time you open a file inside it, you get
fresh, live information?

That's exactly what `/proc` is. Think of it as a **magic bulletin board**
in the school hallway. Nobody writes real papers and pins them there.
When you walk up and look at a section, the information appears
automatically from the school's current records. A new student arrives?
Their name instantly appears on the board. A student leaves? Their entry
vanishes.

### What's inside /proc?

```
/proc/
├── meminfo          -- Memory statistics (total, free, used, shared)
├── uptime           -- How long the system has been running
├── cpuinfo          -- Scheduler policy, ready queue size (per-CPU on multi-CPU systems)
├── stat             -- Performance metrics (context switches, throughput)
├── [pid]/           -- One directory per process
│   ├── status       -- Name, PID, parent, state, priority, threads
│   ├── maps         -- Which memory pages the process uses
│   ├── cmdline      -- The process name
│   └── sched        -- Timing info (wait time, CPU time, response time)
└── self/            -- Alias for whatever process is running right now
    ├── status
    ├── maps
    ├── cmdline
    └── sched
```

### How to use it

You use the same commands you already know! `cat` and `ls` automatically
detect `/proc` paths and route to the virtual filesystem instead of the
real one.

```
ls /proc            -- see what's on the bulletin board
cat /proc/meminfo   -- check memory usage
cat /proc/uptime    -- see how long the system has been up
cat /proc/stat      -- see performance metrics (context switches, throughput)
ls /proc/42         -- list files for process 42
cat /proc/42/status -- see process 42's details
cat /proc/42/sched  -- see process 42's timing (wait, CPU, response time)
```

### Why does this exist?

In real Linux, tools like `ps`, `top`, and `free` don't have special
access to the kernel. They're just ordinary programs that read files from
`/proc`. This is a beautiful design: instead of needing a special API for
every kind of system information, the kernel just makes it look like files.
If you know how to read a file, you know how to inspect the entire system.

### Virtual vs real files

| Property     | Real files (`/data/report.txt`) | Virtual files (`/proc/meminfo`) |
|-------------|--------------------------------|-------------------------------|
| Stored on disk? | Yes | No -- generated on every read |
| Content changes? | Only when someone writes | Every read may be different |
| Can you write? | Yes (`write` command) | No -- read-only |
| Uses inodes? | Yes | No -- separate ProcFilesystem class |

| Term | Meaning |
|------|---------|
| **Virtual filesystem** | A filesystem where files don't exist on disk -- content is generated live |
| **/proc** | The virtual filesystem that exposes kernel state as readable files |
| **/proc/self** | A shortcut that always points to whatever process is currently running |

## Where to Go Next

- [The Kernel](kernel-and-syscalls.md) -- How the kernel routes your filesystem
  requests through syscalls
- [Processes](processes.md) -- How the OS runs programs that read and write files
- [Memory](memory.md) -- How the OS gives programs space to work with file data
