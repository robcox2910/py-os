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
| `perf`    | Show performance metrics (context switches, wait time, throughput) |
| `exit`    | Shut down the kernel and leave the shell |

**Synchronization** -- managing shared resources:

| Command     | What it does |
|-------------|-------------|
| `mutex`     | Create, acquire, release, or list mutexes |
| `semaphore` | Create, acquire, release, or list semaphores |
| `rwlock`    | Create, acquire, release, or list reader-writer locks |
| `pi`        | Priority inheritance demo and status |
| `ordering`  | Deadlock prevention: register ranks, set mode, view violations, demo |
| `shm`       | Shared memory: create, attach, detach, write, read, list, destroy, demo |
| `dns`       | DNS: register, lookup, remove, list, flush, demo |
| `socket`    | Raw sockets: create, bind, listen, connect, accept, send, recv, close, list |
| `http`      | HTTP protocol demo (request/response over sockets) |
| `proc`      | /proc virtual filesystem demo (live kernel state as files) |

**Virtual filesystem** -- inspecting the system through /proc:

`cat` and `ls` automatically detect `/proc` paths and read from the
virtual filesystem instead of the real one. For example:

```
cat /proc/meminfo       -- memory statistics
cat /proc/uptime        -- system uptime
cat /proc/stat          -- performance metrics (context switches, throughput)
ls /proc                -- list all /proc entries
ls /proc/42             -- list files for process 42
cat /proc/42/status     -- process 42's details
cat /proc/42/sched      -- per-process timing (wait, CPU, response, turnaround)
```

**Scheduling** -- controlling how processes share the CPU:

| Command     | What it does |
|-------------|-------------|
| `scheduler` | Switch scheduling policies or view current settings |

**Storage** -- crash recovery and disk management:

| Command   | What it does |
|-----------|-------------|
| `journal` | Show the write-ahead log status for crash recovery |

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

## Redirection

Pipes connect commands to each other. But what if you want to send a command's
output to a **file** instead? Or read a command's input from a file instead of
typing it? That's what **redirection** does.

Think of it like mail. Normally, when a command finishes, it hands you the
result directly -- like someone handing you a letter. Redirection says "don't
hand it to me, put it in that mailbox over there instead."

### Output redirection (`>`)

The `>` operator takes a command's output and writes it into a file:

```
echo hello > /greeting.txt
cat /greeting.txt
```

The first command writes "hello" into `/greeting.txt`. The second reads it
back. Notice that `echo hello >` showed nothing on screen -- the output went
to the file instead of being displayed.

If the file doesn't exist, `>` creates it. If it already exists, `>` **erases
everything in it** and writes the new content. It's like ripping out all the
pages of a notebook and starting fresh.

### Append redirection (`>>`)

What if you don't want to erase the file? Use `>>` to **add** to the end:

```
echo dear diary >> /diary.txt
echo today was great >> /diary.txt
```

Think of `>>` as "keep writing where I left off" and `>` as "start a brand new
page." If you're building a log file where you want to add entries over time,
`>>` is what you want.

### Input redirection (`<`)

The `<` operator goes the other direction. Instead of redirecting output, it
redirects **input** -- it feeds the contents of a file into a command:

```
grep apple < /fruits.txt
```

This is like saying "open that file and read it out loud to `grep`." The
`grep` command then filters the lines just like it would with piped input. It
works with any pipe-aware command like `grep` or `wc`:

```
wc < /fruits.txt
```

You can even combine input and output redirection:

```
grep apple < /fruits.txt > /results.txt
```

That reads from `/fruits.txt`, filters for lines containing "apple", and writes
the matching lines into `/results.txt`.

### Error redirection (`2>`)

Sometimes a command fails. When that happens, the shell produces an **error
message** instead of normal output. The `2>` operator captures those error
messages and sends them to a file:

```
cat /nonexistent 2> /errors.txt
```

If `/nonexistent` doesn't exist, the error message goes into `/errors.txt`
instead of being displayed. Normal (successful) output is unaffected -- `2>`
only catches errors.

Think of it like sorting mail. You have two piles: one for regular letters
(normal output) and one for bills and complaints (errors). The `>` operator
redirects the regular pile, and `2>` redirects the complaints pile. You can
even use both at once:

```
ls / > /output.txt 2> /errors.txt
```

**Why the `2`?** In real Unix systems, every program has numbered channels
called **file descriptors**. Channel 1 is "standard output" (stdout) and
channel 2 is "standard error" (stderr). So `2>` literally means "redirect
channel 2." PyOS simulates this by looking at whether the output string starts
with "Error:" -- if it does, it's treated as stderr.

### Redirection and pipes together

You can combine redirection with pipes. Redirection applies to whatever stage
it appears in:

```
ls / | grep txt > /matches.txt
```

Here, `ls /` produces a listing, the pipe feeds it to `grep txt`, and then `>`
sends grep's filtered output to a file.

**Limitation:** You can't combine redirection with background execution (`&`).
If you try `echo hello > /out.txt &`, you'll get an error. This keeps things
simple -- the interaction between backgrounding and file I/O adds complexity
that belongs in a later feature.

### All redirection operators

| Operator | What it does |
|----------|-------------|
| `>` | Write output to a file (create or overwrite) |
| `>>` | Append output to a file (create if needed) |
| `<` | Read input from a file |
| `2>` | Write error output to a file |

### Vocabulary

- **Redirection** -- routing a command's input or output to/from a file instead
  of the screen
- **Standard output (stdout)** -- the normal output channel (file descriptor 1)
- **Standard error (stderr)** -- the error output channel (file descriptor 2)
- **Overwrite** -- `>` replaces the file's contents completely
- **Append** -- `>>` adds to the end of the file without erasing

## Loops

Imagine you have a big stack of trading cards and you need to sort them. You
wouldn't write a separate instruction for each card -- you'd say "keep doing
this until the stack is empty" or "do this for every card in the pile." That's
what loops do in a script: they repeat a block of commands automatically.

### While loops

A while loop is like a traffic light. Keep going as long as the light is green.
The moment it turns red, stop.

```bash
while cat /flag
do
  echo "still going"
  rm /flag
done
```

Here's what happens:

1. The shell runs `cat /flag`. If it succeeds (the file exists), the light is
   "green" -- enter the loop body.
2. Inside the body, we echo a message and delete the flag file.
3. Back to the top: try `cat /flag` again. This time it fails (file is gone),
   so the light turns "red" and the loop stops.

The condition is checked **every time** before entering the body. If the
condition fails on the very first check, the body never runs at all -- just like
a red light stopping you before you even start.

**Important:** The condition is re-expanded each iteration. If you use `$VAR`
in the condition, it picks up the latest value of that variable every time
around the loop. This is how you can change a variable inside the body and have
the condition notice.

### For loops

A for loop is like taking attendance at school. The teacher has a list of names,
and for each name on the list, they call it out and mark it down.

```bash
for FRUIT in apple banana cherry
do
  echo $FRUIT
done
```

This outputs:

```
apple
banana
cherry
```

The shell takes each item after `in`, assigns it to the variable `FRUIT`, and
runs the body once. Then it assigns the next item and runs the body again, until
the list is exhausted.

You can use a variable for the list, too:

```bash
export COLORS="red green blue"
for C in $COLORS
do
  echo $C
done
```

The `$COLORS` variable gets expanded to `red green blue`, and the loop iterates
over those three words.

### Nesting

Loops can go inside other loops, and loops can go inside `if` blocks (and vice
versa). Think of Russian nesting dolls -- each doll can contain another doll
inside.

```bash
for DIR in /data /logs
do
  mkdir $DIR
  for FILE in a.txt b.txt
  do
    touch $DIR/$FILE
  done
done
```

This creates two directories and puts two files in each one. The outer loop runs
twice (once for `/data`, once for `/logs`), and for each outer iteration, the
inner loop runs twice (once for `a.txt`, once for `b.txt`). Total: four files
created.

You can also put a while loop inside a for loop, an if inside a while, or any
combination. The shell handles nesting by running each inner block as its own
mini-script -- the same technique that makes the whole scripting engine work.

### Safety net

What if you accidentally write a while loop whose condition never fails?

```bash
while cat /always-exists
do
  echo "forever!"
done
```

In a real OS, this would run until you kill the process (Ctrl+C). In PyOS, we
have a built-in safety limit: **1,000 iterations**. If a loop hits this limit,
it stops and reports an error. This prevents your scripts from running away and
freezing the system.

### All loop commands

| Syntax | What it does |
|--------|-------------|
| `while <cmd>` / `do` / `done` | Repeat while `<cmd>` succeeds |
| `for VAR in items...` / `do` / `done` | Iterate over a list of items |

### Vocabulary

- **While loop** -- repeat a block as long as a condition is true
- **For loop** -- repeat a block once for each item in a list
- **Iteration** -- one pass through the loop body
- **Nesting** -- putting one loop (or conditional) inside another
- **Infinite loop** -- a loop that never stops (PyOS limits these to 1,000
  iterations)

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

### The `&` operator

Adding `&` to the end of a `run` command is like telling the kitchen "bring it
when it's ready, I don't need to watch you cook." The program runs, but instead
of showing its output right away, the shell captures it silently and gives you
a job notification:

```
> run hello &
[1] 42
```

That `[1]` is the **job number** and `42` is the process ID. The program has
already finished -- its output is waiting for you whenever you're ready to look
at it.

**Important:** In a real operating system, `&` makes a process run *at the
same time* as your other commands (true concurrency). PyOS is a simulator
without threads, so the process actually runs to completion immediately -- the
only difference is that the output gets stored in the job instead of being
printed. Think of it like a restaurant that cooks your food instantly but keeps
it warm on a shelf instead of bringing it to your table right away.

The `&` operator is only meaningful for `run` commands (which create and
execute processes). Other commands like `touch` or `ls` are so fast that
backgrounding them doesn't make sense -- they just run normally.

One limitation: you can't combine pipes with `&` (like `ls / | grep txt &`).
Real shells can do this, but it adds complexity that we'll save for later.

### Retrieving output

Once a job is running in the background, you have two ways to get its output:

**`fg <job_id>`** -- brings the job to the foreground and shows its captured
output. This also removes the job from the list.

```
> run hello &
[1] 42
> fg 1
Hello from PyOS!
[exit code: 0]
```

**`waitjob`** -- collects output from background jobs without "bringing them
forward." Use `waitjob` to see all jobs, or `waitjob <job_id>` for a specific
one. Either way, the jobs are removed after you collect them.

```
> run hello &
[1] 42
> run counter &
[2] 43
> waitjob
[1] hello:
Hello from PyOS!
[exit code: 0]
[2] counter:
1
2
3
4
5
[exit code: 0]
```

Why is `waitjob` a separate command from `wait`? Because they're different
concepts. `wait` is a **kernel-level** command -- it tells a parent process to
wait for a child process to finish (like a parent waiting for their kid to come
home). `waitjob` is a **shell-level** command -- it retrieves output from a
background job you started with `&`. Keeping them separate helps reinforce
where each concept lives in the OS layers.

### All job commands

| Command | What it does |
|---------|-------------|
| `run <program> &` | Run a program in the background |
| `bg <pid>` | Add an existing process as a background job |
| `fg <job_id>` | Bring a job to the foreground (shows output, removes job) |
| `jobs` | List all background jobs |
| `waitjob` | Collect output from all jobs and remove them |
| `waitjob <job_id>` | Collect output from a specific job and remove it |

### Vocabulary

- **Background job** -- a process whose output is captured silently instead of
  shown immediately
- **Foreground** -- the normal mode where a command's output is shown right away
- **`&` operator** -- the ampersand at the end of a command that triggers
  background execution
- **Job number** -- a small number like `[1]` or `[2]` that the shell assigns
  for your convenience (much easier to remember than a PID)

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

## Tab Completion

You know how your phone suggests the rest of a word while you're typing? Tab
completion works the same way. Start typing a command, press the **Tab** key,
and the shell fills in the rest for you. If there's more than one possibility,
press Tab twice to see all the options.

For example, type `he` and press Tab -- the shell completes it to `help`
because that's the only command starting with "he". Type `ls /` and press Tab
-- you'll see every file and directory in the root folder.

Tab completion isn't just for commands. It works in several contexts depending
on what you're typing:

| Where you are | What completes |
|---------------|----------------|
| First word on the line | Command names (`ls`, `cat`, `mkdir`, ...) |
| After `scheduler`, `mutex`, `semaphore`, `rwlock`, `journal`, `pi`, `ordering`, `shm`, `dns`, `socket`, `http`, `proc` | Subcommands (`fcfs`, `create`, `list`, `status`, `demo`, `register`, `mode`, `violations`, ...) |
| After a file command (`ls`, `cat`, `rm`, ...) | Filesystem paths |
| After `run` | Built-in program names |
| After `unset` | Environment variable names |
| After `signal <pid>` or `handle <pid>` | Signal names (`SIGTERM`, `SIGKILL`, ...) |
| `$` prefix anywhere | Environment variable names with `$` prefix |

Under the hood, this works by importing Python's `readline` module and giving
it a **completer function**. Every time you press Tab, readline calls that
function with whatever partial text you've typed so far. The completer looks at
the context -- which command you're typing, where in the line you are -- and
returns a list of suggestions. All the logic lives in a separate `Completer`
class so it can be tested without any I/O.

### Vocabulary

- **Tab completion** -- pressing Tab to auto-fill a partial command, path, or
  name
- **Completer** -- the code that decides what suggestions to offer based on
  context
- **readline** -- a library that adds line-editing features (Tab completion,
  arrow keys, history) to terminal input

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
job control, history, aliases, tab completion, variables -- that make the raw
power of the kernel accessible and pleasant to use.

If the kernel is the engine of a car, the shell is the steering wheel, the
pedals, and the dashboard. You don't need to understand every piston and valve
to drive somewhere, but it sure helps to know what all those controls do.

Next up, you might want to read about [the kernel](kernel-and-syscalls.md) to
see what happens on the other side of those system calls.
