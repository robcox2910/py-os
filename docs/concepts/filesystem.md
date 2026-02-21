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
    file_type: FileType      # FILE or DIRECTORY
    data: bytes = b""        # the file's contents
    children: dict[str, int] # name -> inode number (for directories)
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

## Journaling: The Sticky-Note Safety Net

This is a concept we don't implement in PyOS, but it's important enough to talk
about because every modern filesystem uses it.

Imagine you're rearranging your filing cabinet. You're moving papers from one
drawer to another, renaming things, deleting old files. Halfway through, the
power goes out. When it comes back on, your cabinet is a mess: some papers are
in the old spot, some are in the new spot, and some might be lost entirely.

**Journaling** solves this problem. Before you start rearranging anything, you
write your plan on a sticky note:

- Step 1: Move paper A from drawer X to drawer Y
- Step 2: Delete paper B from drawer Z
- Step 3: Rename paper C to "new_name"

You stick the note on the front of the cabinet. Then you start doing the work.
If the power goes out in the middle of step 2, you can look at the sticky note
when the power comes back and figure out exactly where you left off. You either
finish the plan or undo it cleanly. Either way, you don't end up with a
corrupted mess.

In OS terms, that sticky note is called a **journal** (or **write-ahead log**).
The filesystem writes what it *plans* to do before it actually does it. If the
system crashes, it replays the journal on the next boot to get back to a
consistent state.

Real filesystems like ext4 journal their metadata by default. More advanced
systems like ZFS and Btrfs use a technique called **copy-on-write** with
checksums, which gives even stronger protection against corruption.

We skip journaling in PyOS because it adds a lot of complexity, and our simple
"dump everything to JSON" approach works fine for learning. But now you know why
real operating systems need it -- computers crash, and your files need to
survive.

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
| **Serialization** | Converting live data into a storable format (like taking a photo) |
| **Deserialization** | Rebuilding live data from a stored format (like rebuilding from a photo) |
| **Base64**        | A way to encode binary data as safe text characters            |
| **JSON**          | A human-readable text format for structured data               |
| **Journaling**    | Writing a plan before doing work, so crashes don't cause corruption |

## Where to Go Next

- [The Kernel](kernel-and-syscalls.md) -- How the kernel routes your filesystem
  requests through syscalls
- [Processes](processes.md) -- How the OS runs programs that read and write files
- [Memory](memory.md) -- How the OS gives programs space to work with file data
