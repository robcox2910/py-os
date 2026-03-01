# Binary Programs and the Loader

## What Is a Binary?

When you write a program, you write it in a language that **people** can read.
But a computer doesn't understand English — it only understands numbers.

A **binary file** is a program that's been translated into a sequence of
numbers (bytes) that the computer can decode and run. It's the final form of
every program on your machine — from your web browser to a simple calculator.

Think of it like this:

- A **recipe book** is written in English so a person can follow it.
- A **barcode** encodes that same recipe as numbers so a machine can scan it.

The binary file is the barcode. The **loader** is the scanner that reads it,
checks it makes sense, and tells the kitchen (CPU) what to cook.

## Real Binary Formats

Real operating systems use specific binary formats:

| OS | Format | Magic Bytes |
|----|--------|-------------|
| Linux | ELF | `\x7fELF` |
| Windows | PE | `MZ` |
| macOS | Mach-O | `\xfe\xed\xfa\xce` |

The **magic bytes** are the first few bytes of the file. They're like a
name tag that says "I'm a valid program!" — if the loader doesn't see the
right magic, it refuses to load the file.

## Our Format: PyBin

PyOS uses a simplified format called **PyBin**. It works the same way as
ELF or PE, just much simpler:

```
┌─────────────────────────────────────────────────┐
│                  PyBin File                      │
├──────────┬──────────────────────────────────────┤
│  Header  │  Magic: PYBN  │  Version: 1          │
│          │  Name length  │  Program name (UTF-8) │
│          │  Instruction count                    │
├──────────┼──────────────────────────────────────┤
│  Code    │  Instruction 1 (opcode + arguments)  │
│          │  Instruction 2 (opcode + arguments)  │
│          │  ...                                  │
│          │  HALT                                 │
└──────────┴──────────────────────────────────────┘
```

### The Header

Every PyBin file starts with a **header** — metadata about the program:

1. **Magic number** (`PYBN`) — 4 bytes that identify it as a PyBin file
2. **Version** — so the loader knows which format to expect
3. **Name** — the program's name (like "hello" or "counter")
4. **Instruction count** — how many instructions follow

### Instructions (Bytecode)

After the header come the instructions — the actual steps the program
follows. Each instruction has:

- An **opcode** — a number that says *what* to do
- **Arguments** — extra information the instruction needs

Here are all the opcodes:

| Opcode | Name | What It Does | Example |
|--------|------|-------------|---------|
| 1 | PRINT | Display a value | `PRINT "Hello!"` |
| 2 | SET | Store a number in a variable | `SET x 42` |
| 3 | ADD | Add two variables | `ADD result a b` |
| 4 | SUB | Subtract two variables | `SUB result a b` |
| 5 | LOAD | Store a string in a variable | `LOAD msg "hi"` |
| 6 | CONCAT | Join two strings | `CONCAT full first last` |
| 7 | LOOP | Repeat the next N instructions | `LOOP 3` |
| 8 | HALT | Stop the program | `HALT` |

Think of opcodes like action words in a recipe:
"**Chop** the onion" — *chop* is the opcode, *onion* is the argument.

## How the Loader Works

Loading a binary is like opening a recipe card and cooking:

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Read    │ ──> │  Check   │ ──> │  Parse   │ ──> │ Execute  │
│  file    │     │  magic   │     │  header  │     │  code    │
│  bytes   │     │  number  │     │  + code  │     │          │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
```

1. **Read** the file from disk as raw bytes
2. **Check** the magic number — is it really `PYBN`?
3. **Parse** the header to learn the program's name and size
4. **Execute** each instruction in order, until `HALT`

If anything goes wrong (wrong magic, file too short, unknown opcode),
the loader raises an error instead of crashing.

## The Builder

The `BinaryBuilder` lets you create PyBin programs using a friendly API
instead of crafting raw bytes by hand:

```python
from py_os.process.binary import BinaryBuilder

data = (
    BinaryBuilder("hello")
    .print("Hello from PyBin!")
    .halt()
    .build()
)
```

Don't worry if the Python code looks complex -- the important thing is the
*idea*: the builder creates instructions step by step, then packs them into
a binary file.

This produces the exact same bytes as if you'd written them manually --
but it's much easier to read and get right!

## Permission Check

Before the loader executes a binary, it checks that the file has
**execute permission** (the `x` bit). Without it, the OS refuses to
run the program — even if the file contains valid bytecode.

This is an important security feature. Just because a file *contains*
instructions doesn't mean you should be allowed to *run* them. Think of
it like a locked door: the key (execute permission) decides who can enter.

See [Permissions](permissions.md) for more about how permissions work.

## Try It in the Shell

```
PyOS> compile list           # See available demo programs
PyOS> compile hello          # Build the hello binary in /bin
PyOS> run /bin/hello         # Load and execute it
Hello from PyBin!

PyOS> hexdump /bin/hello     # See the raw bytes
PyBin binary (33 bytes)
  Magic: b'PYBN'
0000  50 59 42 4e 01 00 05 00 ...  PYBN....

PyOS> compile counter        # Build the counter program
PyOS> run /bin/counter       # Run it
1
2
3
4
5
```

## Why Does This Matter?

Every program you've ever used — games, browsers, editors — went through
this process:

1. Someone wrote **source code** (human-readable)
2. A **compiler** turned it into **binary** (machine-readable)
3. The OS **loader** read the binary, checked it, and ran it

Our PyBin format is a miniature version of the same idea. By understanding
it, you're learning the fundamentals of how *all* programs get loaded and
executed on *every* operating system.
