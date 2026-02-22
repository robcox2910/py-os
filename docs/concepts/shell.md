# The Shell

You know how when you walk into a hotel, you don't just wander into the back
office, open filing cabinets, and flip light switches yourself? You go to the
front desk and tell the receptionist what you need. "I'd like to check in."
"Can I get extra towels?" The receptionist listens, translates your request
into whatever the hotel's internal system requires, and comes back with an
answer.

The **shell** is the receptionist of your operating system.

You type commands. The shell reads what you typed, figures out what you're
asking for, and passes the request to the [kernel](kernel-and-syscalls.md)
through system calls. The kernel does the real work, and the shell hands the
result back to you as text.

Here's the important rule: the shell *never* touches the kernel's internals
directly. It doesn't reach into the filesystem, it doesn't poke the scheduler,
it doesn't fiddle with memory. It always goes through the official front door
-- system calls. This keeps things clean and safe, just like how the
receptionist uses the hotel's booking system instead of personally moving
furniture between rooms.

One more thing to know: everything the shell gives back to you is a **string**
(text). Even a list of processes or a count of files comes back as plain text.
That turns out to be really powerful, as you'll see when we get to pipes.

## Commands

So how does the shell know what `ls` or `mkdir` means? It uses something
called a **dispatch table**. That's a fancy name for a Python dictionary that
maps command names to functions.

It looks something like this:

```python
commands = {
    "ls":    self._cmd_ls,
    "mkdir": self._cmd_mkdir,
    "cat":   self._cmd_cat,
    # ... and so on
}
```

When you type `ls /`, the shell splits that into the command name (`ls`) and
the arguments (`/`). It looks up `"ls"` in the dictionary, finds the matching
function, and calls it with the arguments. Done.

Want to add a brand new command to PyOS? Write a function that does the thing,
then add one line to the dictionary. That's it. No long chain of
`if`/`elif`/`else` -- just a clean dictionary lookup.

Here are the commands grouped by what they do. You don't need to memorize them
-- just know they exist so you can come back and look them up.

**Files** -- working with files and directories:

| Command | What it does |
|---------|-------------|
| `ls`    | List the contents of a directory |
| `mkdir` | Create a new directory |
| `touch` | Create an empty file |
| `cat`   | Read and display a file's contents |
| `write` | Write text into a file |
| `rm`    | Remove (delete) a file or directory |

**Processes** -- managing running programs:

| Command | What it does |
|---------|-------------|
| `ps`      | List all running processes |
| `kill`    | Terminate a process by its PID |
| `fork`    | Create a copy of an existing process |
| `pstree`  | Show the parent-child process tree |
| `threads` | List the threads inside a process |
| `run`     | Create a process and run a built-in program |
| `wait`    | Wait for any child process to finish and collect its exit code |
| `waitpid` | Wait for a specific child process to finish |
| `signal`  | Send a signal (like SIGTERM or SIGKILL) to a process |
| `handle`  | Register a custom signal handler for a process |

**Users** -- who's using the system:

| Command  | What it does |
|----------|-------------|
| `whoami`  | Show the current user |
| `adduser` | Create a new user |
| `su`      | Switch to a different user |

**System** -- checking on the OS itself:

| Command   | What it does |
|-----------|-------------|
| `top`     | Show a system status dashboard (memory, processes, uptime) |
| `log`     | Display recent log entries |
| `env`     | List all environment variables |
| `export`  | Set an environment variable |
| `history` | Show every command you've typed this session |
| `exit`    | Shut down the kernel and leave the shell |

## Pipes

Imagine an assembly line in a factory. The first worker makes a part, then
slides it down the conveyor belt to the second worker, who modifies it, who
slides it to the third worker, who counts the results. Each worker does one
small job, and together they produce the final product.

Pipes work exactly like that. The `|` character connects commands so that the
output of one becomes the input of the next.

```
ls / | grep txt | wc
```

Here's what happens step by step:

1. `ls /` lists all the files in the root directory. Its output is a bunch of
   lines of text.
2. That text slides down the pipe to `grep txt`, which reads every line and
   keeps only the ones containing "txt". Everything else gets thrown away.
3. The filtered lines slide down another pipe to `wc`, which counts how many
   lines it received and prints the total.

Three tiny tools, each doing one thing well, connected together to answer the
question "how many files in `/` have 'txt' in their name?"

This idea has a name: the **Unix philosophy**. Build small, focused tools that
each do one thing, then connect them with pipes to solve bigger problems. It's
like building with LEGO bricks -- each brick is simple, but you can combine
them into anything.

Remember how the shell returns everything as strings? That's why pipes work so
smoothly. Since every command produces text, any command's output can become
any other command's input.

## Scripting

So far you've been giving the receptionist one request at a time. But what if
you had a whole checklist of things to do? You could hand them the entire list
and say "do all of these, in order."

That's a **script** -- a text file with commands, one per line. Instead of
typing commands one by one, you write them all down and tell the shell to run
the file.

```bash
# Set up a data directory and create a file in it
mkdir /data
export NAME=hello
echo $NAME
if ls /data
then
  touch /data/$NAME.txt
fi
```

Let's break down the special features you see here.

**Comments** start with `#`. They're notes for humans. The shell completely
ignores them. Use comments to explain *why* you're doing something so that
future-you (or someone else) can understand the script.

**Variables** use the `$` sign. When the shell sees `$NAME`, it replaces it
with whatever value `NAME` holds before running the command. So if `NAME` is
`hello`, then `touch /data/$NAME.txt` actually runs `touch /data/hello.txt`.
Think of `$NAME` as a placeholder that gets filled in.

**Conditionals** let you make decisions. The `if`/`then`/`else`/`fi` block
works like this:

```bash
if some_command
then
  # This runs if some_command succeeded
else
  # This runs if some_command failed
fi
```

The shell runs `some_command`. If it works (no error), it runs the `then`
block. If it fails, it runs the `else` block. The `else` part is optional --
you can leave it out. `fi` marks the end (it's `if` spelled backwards, which
is a real thing that actual Unix shells do).

**source** runs a script from a file. If you saved the script above to
`/scripts/setup.sh`, you could run it with:

```
source /scripts/setup.sh
```

The shell reads the file, and executes each line as if you had typed it
yourself.

## Job Control

Imagine you're at a restaurant. You order your food, and while the kitchen is
working on it, you don't just sit there staring at the kitchen door. You talk
to your friends, check your phone, maybe order a drink. When the food is
ready, the waiter brings it over.

**Job control** works the same way. You can send a process to the background
so it runs on its own, and you keep typing other commands. Meanwhile, the
background process keeps doing its thing.

Here's the important bit: jobs are a **shell** concept, not a kernel concept.
The [kernel](kernel-and-syscalls.md) knows about processes, but it doesn't
know or care which ones you consider "background jobs." The shell keeps its own
list.

The commands:

- `bg <pid>` -- send a process to the background (let it cook while you keep
  working)
- `fg <job_id>` -- bring a background job back to the foreground (go check on
  your food)
- `jobs` -- list all your background jobs (what's currently cooking?)

## History and Aliases

### History

The shell remembers every command you type. It's like a diary of your entire
session. Type `history` and you'll see a numbered list of everything you've
run:

```
  1  ls /
  2  mkdir /data
  3  touch /data/notes.txt
  4  cat /data/notes.txt
```

This is useful when you want to remember what you did, or when you want to
double-check the exact command you ran earlier.

### Aliases

An alias is a shortcut you create. Let's say you're tired of typing `ls /`
over and over. You can make a shortcut:

```
alias ll=ls /
```

Now typing `ll` does the exact same thing as typing `ls /`. The shell sees
`ll`, checks its alias list, and quietly replaces it with `ls /` before
running anything.

Think of aliases like speed dial on a phone. Instead of dialing a full number
every time, you press one button and the phone fills in the rest.

Use `alias` with no arguments to see all your current aliases, and
`unalias <name>` to remove one.

## Environment Variables

Environment variables are like sticky notes on your desk. Each one has a name
and a value, and they store settings that any program can read:

```
USER=rob
HOME=/root
PATH=/bin
```

To set one:

```
export GREETING=hello
```

To see all of them:

```
env
```

To use one in a command, put a `$` in front of the name:

```
echo $GREETING
```

That prints `hello`.

Here's something neat: when you `fork` a process (create a copy of it), the
child process gets its own **copy** of all the environment variables. If the
child changes a variable, the parent's copy stays the same. It's like
photocopying all your sticky notes for a coworker -- they can scribble on
their copies all they want, and your originals are untouched.

This is actually an important concept in real operating systems. It's how
parent processes pass configuration to their children without worrying about
the children messing up the parent's settings. The
[kernel](kernel-and-syscalls.md) handles the copying when a fork happens.

## Putting It All Together

The shell is your window into the operating system. It takes your plain-English
(well, plain-command) requests, translates them into system calls, and gives
you back the results. It adds convenience features on top -- pipes, scripts,
job control, history, aliases, variables -- that make the raw power of the
kernel accessible and pleasant to use.

If the kernel is the engine of a car, the shell is the steering wheel, the
pedals, and the dashboard. You don't need to understand every piston and valve
to drive somewhere, but it sure helps to know what all those controls do.

Next up, you might want to read about [the kernel](kernel-and-syscalls.md) to
see what happens on the other side of those system calls.
