# Shell Reference

Complete list of shell commands, grouped by subsystem. All commands are available in both the terminal REPL (`pyos`) and the web UI (`pyos-web`).

A live terminal dashboard is also available via `pyos-tui` (requires the `[tui]` extra — see [TUI Dashboard](concepts/tui.md)).

Commands can be piped: `ls / | grep txt | wc`

## General

| Command | Description |
|---------|-------------|
| `help` | List available commands |
| `echo args` | Print arguments to output |
| `history` | Show command history |
| `alias N=CMD` | Create a command alias |
| `unalias N` | Remove a command alias |
| `exit` | Shut down the kernel |

## Processes

| Command | Description |
|---------|-------------|
| `ps` | Show running processes |
| `run prog [p]` | Run a built-in program with optional priority |
| `kill pid` | Terminate a process by PID |
| `fork pid` | Fork a process (create a child copy) |
| `wait pid` | Wait for any child to terminate and collect its exit code |
| `waitpid p c` | Wait for a specific child (c) of parent (p) to terminate |
| `pstree` | Show the process tree hierarchy |
| `threads pid` | List threads of a process |
| `top` | System status dashboard |
| `signal pid sig` | Send a signal (SIGTERM, SIGKILL, SIGUSR1, etc.) |
| `handle pid act` | Register a signal handler (log, ignore) |

## Scheduling

| Command | Description |
|---------|-------------|
| `scheduler` | Show or switch scheduling policy (fcfs, rr, priority, aging, mlfq, cfs) |
| `scheduler boost` | Reset MLFQ levels (anti-starvation) |
| `scheduler balance` | Rebalance processes across CPUs |
| `cpu` | Show per-CPU status and scheduling info |
| `taskset pid [cpus]` | Show or set CPU affinity for a process |
| `benchmark` | Run scheduling benchmarks (run, demo) |
| `tick [N]` | Advance the system clock by N ticks (default 1) |

## Memory

| Command | Description |
|---------|-------------|
| `mmap path` | Memory-map a file |
| `munmap addr` | Unmap a memory-mapped region |
| `msync addr` | Sync a shared mapping |
| `slabcreate name size` | Create a slab cache |
| `slaballoc name` | Allocate from a slab cache |
| `slabfree name addr` | Free a slab allocation |
| `slabinfo` | Show slab allocator statistics |
| `swap` | Show swap space status (policy, usage, page faults) |
| `swap policy P` | Change replacement policy (fifo, lru, clock) |
| `swap demo` | Exercise the pager — force page faults and show stats |

## Files

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory contents |
| `mkdir path` | Create a directory |
| `touch path` | Create an empty file |
| `write path content` | Write content to a file |
| `cat path` | Read file contents |
| `rm path` | Remove a file or directory |
| `ln target link` | Create hard or symbolic links |
| `readlink path` | Read a symlink target |
| `stat path` | Show file metadata (type, size, links) |
| `open path` | Open a file and get a file descriptor |
| `close fd` | Close a file descriptor |
| `readfd fd` | Read from a file descriptor |
| `writefd fd content` | Write to a file descriptor |
| `seek fd pos` | Reposition a file descriptor's offset |
| `lsfd` | List open file descriptors |
| `journal cmd` | Manage journaling (status, checkpoint, recover, crash) |
| `proc` | /proc virtual filesystem demo |

## Users and Permissions

| Command | Description |
|---------|-------------|
| `whoami` | Show the current user |
| `adduser name` | Create a new user |
| `su uid` | Switch to another user |

## Environment

| Command | Description |
|---------|-------------|
| `env` | List environment variables |
| `export K=V` | Set an environment variable |
| `unset key` | Remove an environment variable |

## Jobs

| Command | Description |
|---------|-------------|
| `jobs` | List background jobs |
| `bg pid` | Move a process to background |
| `fg job_id` | Bring a job to foreground |
| `waitjob id` | Wait for a background job to complete |

## Devices

| Command | Description |
|---------|-------------|
| `devices` | List registered devices |
| `devread dev` | Read from a device |
| `devwrite dev data` | Write to a device |
| `fb` | Show framebuffer info (dimensions, status) |
| `fb render` | Display the current framebuffer contents |
| `fb pixel x y c` | Set a character at position (x, y) |
| `fb text x y msg` | Draw text starting at (x, y) |
| `fb rect x1 y1 x2 y2 c` | Fill a rectangle with a character |
| `fb clear` | Clear the framebuffer |
| `fb demo` | Draw a demo pattern with borders and text |

## Networking

| Command | Description |
|---------|-------------|
| `socket cmd` | Socket operations (create, bind, listen, connect, accept, send, recv, close, list) |
| `dns cmd` | DNS operations (register, lookup, remove, list, flush, demo) |
| `http cmd` | HTTP demo (end-to-end request/response over sockets) |
| `tcp cmd` | TCP connections (listen, connect, send, recv, close, info, list, demo) |

## Synchronization

| Command | Description |
|---------|-------------|
| `mutex cmd` | Manage mutexes (create, list) |
| `semaphore cmd` | Manage semaphores (create, list) |
| `rwlock cmd` | Manage reader-writer locks (create, list) |
| `resources` | Show resource allocation status |
| `deadlock` | Run deadlock detection |
| `pi cmd` | Priority inheritance (demo, status) |
| `ordering cmd` | Resource ordering (register, status, mode, violations, demo) |
| `shm cmd` | Shared memory (create, attach, detach, write, read, list, destroy, demo) |

## Interrupts and Timers

| Command | Description |
|---------|-------------|
| `interrupt cmd` | Manage interrupts (list, mask, unmask) |
| `timer cmd` | Manage the timer (info, set) |

## Scripting

| Command | Description |
|---------|-------------|
| `source path` | Run a script from a file |
| `grep pattern` | Filter piped input (used with `\|`) |
| `wc` | Count lines in piped input |

## Diagnostics

| Command | Description |
|---------|-------------|
| `log` | Show kernel log entries |
| `dmesg` | Show kernel boot log |
| `perf` | Show performance metrics |
| `strace cmd` | Syscall tracing (on, off, show, clear, demo) |
| `dashboard cmd` | System dashboard (cpu, memory, processes, fs) |

## Tutorials

| Command | Description |
|---------|-------------|
| `learn [topic]` | Interactive tutorials (processes, memory, filesystem, shell, scheduling) |
