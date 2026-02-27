# Contributing to PyOS

Thanks for your interest in contributing! This guide covers everything you need
to get started.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.14+ | [python.org](https://www.python.org/downloads/) |
| uv | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| git | 2.x+ | [git-scm.com](https://git-scm.com/) |

## Setup

```bash
# Clone the repo
git clone https://github.com/robcox2910/py-os.git
cd py-os

# Install all dependencies (including dev tools)
uv sync --all-extras

# Install pre-commit hooks
uv run pre-commit install
```

Verify everything works:

```bash
uv run pytest --cov          # tests pass, >= 80% coverage
uv run ruff check src/ tests/  # no lint errors
uv run pyright src tests       # no type errors
```

## TDD Workflow

We follow **Red-Green-Refactor** for every code change:

1. **Red** — Write a failing test that describes the behaviour you want.
2. **Green** — Write the simplest code that makes the test pass.
3. **Refactor** — Clean up while keeping all tests green.

Never skip the red step. If you can't write a failing test first, take a moment
to think about what the code should actually do.

## Branch Naming

Create a branch from `main` using one of these prefixes:

| Prefix | When to use |
|--------|-------------|
| `feat/` | New feature or command |
| `fix/` | Bug fix |
| `refactor/` | Restructuring without behaviour change |
| `test/` | Test-only changes |
| `docs/` | Documentation updates |
| `ci/` | CI/CD workflow changes |
| `chore/` | Dependency bumps, config tweaks |

Example: `feat/benchmark-suite`, `fix/scheduler-priority-bug`

## Conventional Commits

Every commit message must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description in imperative mood>

Optional longer explanation.
```

Types match the branch prefixes: `feat:`, `fix:`, `refactor:`, `test:`,
`docs:`, `ci:`, `chore:`.

Good examples:

```
feat: add benchmark command for scheduler comparison
fix: prevent deadlock when forking with held mutex
docs: clarify memory paging analogy
```

Bad examples:

```
updated stuff          # no type, vague description
feat: adds benchmarks  # not imperative mood ("adds" → "add")
```

## Code Style

### Modern Python

Use Python 3.14 idioms everywhere:

- `X | Y` for union types (not `Union[X, Y]` or `Optional[X]`)
- `StrEnum` for string enumerations
- `match/case` instead of if/elif chains where appropriate
- Direct imports: `from enum import StrEnum` not `import enum`

### Docstrings

Every public function, method, class, and module needs a docstring:

- Use **imperative mood**: "Return the process." not "Returns the process."
- One-liner for simple functions, multi-line (Google style) for complex ones.

```python
def terminate(self, pid: int) -> bool:
    """Terminate a process by PID."""

def allocate(self, num_pages: int, pid: int) -> list[int]:
    """Allocate contiguous pages for a process.

    Args:
        num_pages: Number of pages to allocate.
        pid: Process requesting the allocation.

    Returns:
        List of allocated frame numbers.

    Raises:
        MemoryError: If not enough free frames are available.
    """
```

### Named Constants

Use named constants instead of magic numbers in tests and source code. Ruff
rule PLR2004 enforces this.

```python
# Good
EXPECTED_FRAME_COUNT = 64
assert manager.free_frames == EXPECTED_FRAME_COUNT

# Bad
assert manager.free_frames == 64
```

## Linting and Type Checking

Run these before every commit (pre-commit hooks enforce them automatically):

```bash
uv run ruff check src/ tests/   # lint
uv run ruff format src/ tests/   # format (or --check to verify)
uv run pyright src tests          # type check (strict mode)
```

Fix all violations. Inline `# noqa:` is acceptable only when tools genuinely
conflict (e.g., ARG002 vs pyright protocol parameter names).

## Testing

```bash
uv run pytest                # run all tests
uv run pytest --cov          # with coverage report
uv run pytest tests/test_x.py  # run a specific file
uv run pytest -k "test_name"   # run tests matching a pattern
```

- Minimum **80% coverage** is enforced.
- Test classes and methods need docstrings too.
- Use `pytest.raises` as a context manager for exception testing.

## Adding a Shell Command

1. **Add the syscall** (if needed) in `src/py_os/syscalls.py`:
   - Add the enum value to `SysCall`
   - Add a handler method `_handle_<name>`
   - Register it in the dispatch table

2. **Add the shell command** in `src/py_os/shell.py`:
   - Add `"command_name": self._cmd_name` to the dispatch dict in `__init__`
   - Implement `_cmd_name(self, args: list[str]) -> str`

3. **Add tab completion** in `src/py_os/completer.py`:
   - Add `"command_name": ["sub1", "sub2"]` to `_SUBCOMMANDS` (if it has
     subcommands)

4. **Write tests** in `tests/test_command_name.py` following TDD.

5. **Update docs** — add a row to the shell commands table in `README.md`.

## Documentation Style

Our docs target a **12-year-old with an interest in computing**. Keep language
simple, use analogies, and avoid jargon without explanation.

Good:

> Memory is like a warehouse with numbered shelves. Each shelf (called a
> "frame") can hold one page of data. When a program needs space, the OS finds
> empty shelves and assigns them.

Bad:

> The memory manager implements a demand-paged virtual memory system with
> frame-based physical allocation.

## Pull Request Process

1. Create a feature branch from `main`.
2. Make your changes following TDD.
3. Ensure all checks pass: `uv run ruff check .`, `uv run pyright src tests`,
   `uv run pytest --cov`.
4. Push your branch and open a PR against `main`.
5. PRs are squash-merged to keep history clean.

## Questions?

Open an issue on [GitHub](https://github.com/robcox2910/py-os/issues) — we're
happy to help!
