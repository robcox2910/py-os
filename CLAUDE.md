# PyOS

<!-- standard:start -->
## Code Style

- All public functions, methods, classes, and modules **must** have a docstring
- Use imperative mood: "Return the result." not "Returns the result."
- One-line docstrings for simple functions; multi-line with summary + details for complex ones
- Follow the Google docstring convention (D211, D212 selected via ruff)

## Linting

- Ruff enforces a comprehensive rule set -- run `uv run ruff check .` before committing
- Pyright runs in strict mode -- run `uv run pyright src tests` before committing
- All violations must be fixed, not ignored. Exceptions are the repo-owned `ignore` and `per-file-ignores` lists in `pyproject.toml`, which belong to this repo; the series sync never edits them

## Testing

- TDD workflow: Red-Green-Refactor
- Coverage is enforced by pytest-cov; the floor in `pyproject.toml` is repo-owned
- Test classes and methods also require docstrings
- Use named constants instead of magic values (PLR2004)
- Run `uv run pytest` before committing
- Property-based tests (Hypothesis) live in `tests/test_properties.py` and `tests/test_model.py`; the shared profiles are in the root `conftest.py` (owned by `series sync`). Run `uv run pytest --hypothesis-profile=thorough` before a release.

## Commits

- Use conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `ci:`, `chore:`
- All changes go via PR from a feature branch (main is protected); merge when CI is green

## Dependencies

- Package manager: uv
- Run `uv sync --all-extras` after modifying dependencies
- `uv.lock` is committed; CI and pre-commit audit it with pip-audit through `uvx`, so pip-audit is not a project dependency
- Sibling projects, where used, are pinned release tags in `[tool.uv.sources]` (git + tag); never use `path` sources

## Releasing

- A release is a `vX.Y.Z` tag on main after the PR is merged
- Docs-only and tooling-only changes do not get a release tag
- Docs are built with `mkdocs build --strict` and deployed to GitHub Pages by the docs workflow
<!-- standard:end -->

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
