# Interactive Tutorials

## What Are Tutorials?

Imagine you just got a brand-new video game. You *could* read the
manual, but most games start with a **tutorial level** that teaches you
the controls while you play. PyOS tutorials work the same way -- they
teach you OS concepts by running real commands and showing you what
happens, step by step.

## How They Work

Each tutorial is a **lesson** that:

1. **Introduces** a concept with a friendly analogy (like comparing
   processes to recipes in a kitchen).
2. **Runs real syscalls** so you can see the OS doing actual work --
   creating processes, allocating memory, writing files, and more.
3. **Explains what happened** after each step, so you understand *why*
   the OS did what it did.
4. **Summarises** what you learned and suggests the next lesson.

Behind the scenes, the `TutorialRunner` class in `tutorials.py` calls
the same kernel syscalls that the shell uses. Nothing is faked -- you
are watching the real operating system in action.

## Available Lessons

| Lesson | Analogy | What You Learn |
|--------|---------|----------------|
| `processes` | Recipes and cooks | How the OS creates, runs, and tracks programs |
| `memory` | Warehouse with shelves | How the OS divides RAM into frames and pages |
| `filesystem` | A library | How files and directories are organised on disk |
| `scheduling` | Sports-day coaches | How the OS decides which process runs next |
| `signals` | School bells | How processes send notifications to each other |
| `ipc` | A shared mailbox | How processes share data through shared memory |
| `networking` | A phone system | How DNS and sockets let programs talk over a network |

## Running Tutorials

From the PyOS shell, use the `learn` command:

```
PyOS> learn              # list all available lessons
PyOS> learn processes    # run the processes lesson
PyOS> learn all          # run every lesson in order
```

Tab completion works too -- type `learn p` and press Tab to complete
`processes`.

## Why Tutorials Matter

Reading about an operating system is one thing. *Watching* one work is
another. Tutorials bridge that gap by letting you see concepts in
action without needing to write any code yourself. They are a great
starting point before you explore the shell commands on your own.
