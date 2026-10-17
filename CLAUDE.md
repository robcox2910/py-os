# PyOS

## Project notes

PyOS (`py_os`, repo `py-os`, distribution `pyos-learn`) is a teaching operating system simulated in Python: kernel, scheduler, memory, filesystem, IPC, sockets and a shell, written to be read. Source is in `src/py_os`, tests mirror it under `tests/`.

### Package layout

- `kernel.py` -- the `Kernel` that owns and boots every subsystem; `syscalls.py` -- the `SyscallNumber` table and dispatch; user-facing code only ever sees `SyscallError`.
- `process/`, `memory/`, `fs/`, `io/`, `sync/` -- subsystem packages (scheduling and PCBs, paging and slab allocator, inodes/journal/procfs, devices/DNS/HTTP/sockets, locks and semaphores).
- `shell/` -- the command interpreter, `repl.py` -- the interactive loop, `web/` and `tui/` -- optional front-ends (flask / textual extras).
- `users.py` (accounts, ACLs, `OsPermissionError`), `containers.py`, `env.py`, `jobs.py`, `logging.py`, `tutorials.py`.

### The shell package

- `shell/base.py` holds `ShellBase` (parsing, pipes, redirection, history, aliases, dispatch). `shell/__init__.py` composes `Shell` from `ShellBase` plus the command-group mixins.
- Command groups live in `shell/commands/*.py` (files, processes, memory, network, ...). Each group defines handler methods and a `COMMANDS` tuple of `(name, handler)` pairs; `ShellBase.__init__` builds its dispatch dict from every group's `COMMANDS`. To add a command: write the method, add one entry to that group's `COMMANDS`.
- Shell handlers talk to the kernel only through `kernel.syscall(...)`, never by reaching into subsystems.

### The `_missing_subsystem` pattern

Kernel subsystems are `None` until boot. Rather than `assert` (banned at runtime, see `tests/test_no_runtime_asserts.py`), code does `if self._scheduler is None: _raise_missing_subsystem("scheduler")`. The helper is typed `NoReturn`, so pyright narrows the attribute afterwards. `kernel.py` raises `RuntimeError`; `syscalls.py` has its own helper raising `SyscallError`. Calling a raising helper (instead of `raise X("literal")`) also keeps ruff's EM101 satisfied.

### Complexity

Ruff `C90` runs with `max-complexity = 15` (and pylint `max-args = 9`). Split big functions into helpers or table-driven dispatch rather than raising the limit.

### Running it

- Shell: `uv run pyos` (or `uv run python -m py_os`); web: `uv run pyos-web` (needs `--extra web`); TUI: `uv run pyos-tui` (needs `--extra tui`).
- Checks: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, `uv run pytest` (coverage floor 80%).
