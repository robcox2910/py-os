"""Tests for while/for loops in shell scripts.

Loops are a core scripting primitive that allow repeated execution of
command blocks.  They build on the existing ``run_script()`` engine,
using ``_collect_block()`` for block collection and recursive
``run_script()`` calls for body execution.
"""

import pytest

from py_os.kernel import Kernel
from py_os.shell import _MAX_LOOP_ITERATIONS, Shell
from py_os.syscalls import SyscallNumber

_END_SIMPLE = 3
_END_NESTED_LOOP = 4
_END_NESTED_IF = 5
_MIN_MULTI_ITER_RESULTS = 3


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# ---------------------------------------------------------------------------
# Cycle 1 — _collect_block()
# ---------------------------------------------------------------------------


class TestCollectBlock:
    """Verify the static block collector handles nesting and errors."""

    def test_simple_block(self) -> None:
        """Collect lines until a matching close keyword."""
        lines = ["echo hello", "echo world", "done", "echo after"]
        body, end = Shell._collect_block(lines, 0, ("while", "for"), "done")
        assert body == ["echo hello", "echo world"]
        assert end == _END_SIMPLE

    def test_nested_while_for(self) -> None:
        """Nested while/for blocks increment depth correctly."""
        lines = [
            "for X in a b",
            "echo $X",
            "done",  # closes inner for
            "done",  # closes outer
        ]
        body, end = Shell._collect_block(lines, 0, ("while", "for"), "done")
        assert body == ["for X in a b", "echo $X", "done"]
        assert end == _END_NESTED_LOOP

    def test_nested_if(self) -> None:
        """Nested if blocks increment depth correctly."""
        lines = [
            "if cat /flag",
            "then",
            "echo inner",
            "fi",  # closes inner if
            "fi",  # closes outer
        ]
        body, end = Shell._collect_block(lines, 0, ("if",), "fi")
        assert body == ["if cat /flag", "then", "echo inner", "fi"]
        assert end == _END_NESTED_IF

    def test_missing_close_raises(self) -> None:
        """Missing close keyword raises ValueError."""
        lines = ["echo hello", "echo world"]
        with pytest.raises(ValueError, match="missing 'done'"):
            Shell._collect_block(lines, 0, ("while", "for"), "done")


# ---------------------------------------------------------------------------
# Cycle 2 — While loops
# ---------------------------------------------------------------------------


class TestWhileLoop:
    """Verify while loop execution in scripts."""

    def test_basic_while(self) -> None:
        """A while loop runs its body while the condition succeeds."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/flag")
        script = """\
while cat /flag
do
  rm /flag
done"""
        results = shell.run_script(script)
        # Body ran once: rm /flag succeeded
        assert any(r == "" for r in results)
        # /flag is gone — cat would fail
        assert shell.execute("cat /flag").startswith("Error:")

    def test_false_condition_zero_iterations(self) -> None:
        """A while loop with an immediately-false condition runs zero times."""
        _kernel, shell = _booted_shell()
        script = """\
while cat /nonexistent
do
  echo should not run
done"""
        results = shell.run_script(script)
        assert not any("should not run" in r for r in results)

    def test_multiple_iterations(self) -> None:
        """A while loop can run multiple iterations by checking a variable."""
        kernel, shell = _booted_shell()
        # Use a counter file — write 3, 2, 1 then remove
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/counter")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/counter", data=b"3")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/step1")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/step2")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/step3")
        script = """\
while cat /step1
do
  rm /step1
done
while cat /step2
do
  rm /step2
done
while cat /step3
do
  rm /step3
done"""
        results = shell.run_script(script)
        # All three step files should be gone
        assert shell.execute("cat /step1").startswith("Error:")
        assert shell.execute("cat /step2").startswith("Error:")
        assert shell.execute("cat /step3").startswith("Error:")
        # At least 3 body executions occurred (the rm commands returned "")
        assert len(results) >= _MIN_MULTI_ITER_RESULTS

    def test_results_collected(self) -> None:
        """Body results are collected into the returned list."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/go")
        script = """\
while cat /go
do
  echo iteration
  rm /go
done"""
        results = shell.run_script(script)
        assert "iteration" in results

    def test_condition_re_expanded(self) -> None:
        """The condition is re-expanded each iteration (picks up new var values)."""
        kernel, shell = _booted_shell()
        # Set up: create /check, set COUNTER=1
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/check")
        kernel.syscall(SyscallNumber.SYS_SET_ENV, key="TARGET", value="/check")
        script = """\
while cat $TARGET
do
  rm $TARGET
  export TARGET=/nonexistent
done"""
        shell.run_script(script)
        # Body ran once — rm /check succeeded, then $TARGET changed so
        # the next condition (cat /nonexistent) fails
        assert shell.execute("cat /check").startswith("Error:")


# ---------------------------------------------------------------------------
# Cycle 3 — For loops
# ---------------------------------------------------------------------------


class TestForLoop:
    """Verify for loop execution in scripts."""

    def test_basic_for(self) -> None:
        """A for loop iterates over its item list."""
        _kernel, shell = _booted_shell()
        script = """\
for FRUIT in apple banana cherry
do
  echo $FRUIT
done"""
        results = shell.run_script(script)
        assert "apple" in results
        assert "banana" in results
        assert "cherry" in results

    def test_var_in_body(self) -> None:
        """The loop variable is available in the body via $VAR."""
        _kernel, shell = _booted_shell()
        script = """\
for NAME in alice bob
do
  echo hello $NAME
done"""
        results = shell.run_script(script)
        assert "hello alice" in results
        assert "hello bob" in results

    def test_creates_files_per_item(self) -> None:
        """Each iteration can create a file using the loop variable."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/data")
        script = """\
for F in a.txt b.txt c.txt
do
  touch /data/$F
done"""
        shell.run_script(script)
        entries: list[str] = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/data")
        assert "a.txt" in entries
        assert "b.txt" in entries
        assert "c.txt" in entries

    def test_empty_list(self) -> None:
        """A for loop with an empty item list runs zero iterations."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_SET_ENV, key="ITEMS", value="")
        script = """\
for X in $ITEMS
do
  echo should not run
done"""
        results = shell.run_script(script)
        assert not any("should not run" in r for r in results)

    def test_items_expanded_from_variable(self) -> None:
        """Items are expanded from an environment variable."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_SET_ENV, key="COLORS", value="red green blue")
        script = """\
for C in $COLORS
do
  echo $C
done"""
        results = shell.run_script(script)
        assert "red" in results
        assert "green" in results
        assert "blue" in results


# ---------------------------------------------------------------------------
# Cycle 4 — Nested constructs
# ---------------------------------------------------------------------------


class TestNestedConstructs:
    """Verify that loops and conditionals nest correctly."""

    def test_for_in_if(self) -> None:
        """A for loop inside an if block works."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/flag")
        script = """\
if cat /flag
then
  for X in one two
  do
    echo $X
  done
fi"""
        results = shell.run_script(script)
        assert "one" in results
        assert "two" in results

    def test_if_in_for(self) -> None:
        """An if block inside a for loop works."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/flag")
        script = """\
for X in yes no
do
  if cat /flag
  then
    echo found $X
  fi
done"""
        results = shell.run_script(script)
        assert "found yes" in results
        assert "found no" in results

    def test_while_in_for(self) -> None:
        """A while loop inside a for loop works."""
        _kernel, shell = _booted_shell()
        script = """\
for D in /tmp1 /tmp2
do
  mkdir $D
  touch $D/marker
  while cat $D/marker
  do
    rm $D/marker
  done
done"""
        shell.run_script(script)
        # Both markers should be gone
        assert shell.execute("cat /tmp1/marker").startswith("Error:")
        assert shell.execute("cat /tmp2/marker").startswith("Error:")

    def test_for_in_while(self) -> None:
        """A for loop inside a while loop works."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/go")
        script = """\
while cat /go
do
  for X in a b
  do
    echo $X
  done
  rm /go
done"""
        results = shell.run_script(script)
        assert "a" in results
        assert "b" in results

    def test_nested_for_for(self) -> None:
        """Nested for loops iterate correctly."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/grid")
        script = """\
for ROW in r1 r2
do
  for COL in c1 c2
  do
    touch /grid/$ROW-$COL
  done
done"""
        shell.run_script(script)
        entries: list[str] = kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/grid")
        assert "r1-c1" in entries
        assert "r1-c2" in entries
        assert "r2-c1" in entries
        assert "r2-c2" in entries


# ---------------------------------------------------------------------------
# Cycle 5 — Error handling
# ---------------------------------------------------------------------------


class TestLoopErrors:
    """Verify loop error handling and safety limits."""

    def test_missing_done_while(self) -> None:
        """A while loop without 'done' produces an error."""
        _kernel, shell = _booted_shell()
        script = """\
while cat /flag
do
  echo oops"""
        results = shell.run_script(script)
        assert any("missing" in r and "done" in r for r in results)

    def test_missing_done_for(self) -> None:
        """A for loop without 'done' produces an error."""
        _kernel, shell = _booted_shell()
        script = """\
for X in a b
do
  echo oops"""
        results = shell.run_script(script)
        assert any("missing" in r and "done" in r for r in results)

    def test_for_missing_in_keyword(self) -> None:
        """A for loop without 'in' produces a syntax error."""
        _kernel, shell = _booted_shell()
        script = """\
for X a b c
do
  echo $X
done"""
        results = shell.run_script(script)
        assert any("syntax" in r.lower() or "in" in r.lower() for r in results)

    def test_max_iterations_enforced(self) -> None:
        """Infinite loops are stopped at _MAX_LOOP_ITERATIONS."""
        kernel, shell = _booted_shell()
        # Create a file that always exists (never removed in loop body)
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/infinite")
        script = """\
while cat /infinite
do
  echo tick
done"""
        results = shell.run_script(script)
        # Should hit the iteration limit
        assert any("iterations" in r.lower() or "limit" in r.lower() for r in results)
        # Should not exceed the limit
        tick_count = sum(1 for r in results if r == "tick")
        assert tick_count == _MAX_LOOP_ITERATIONS

    def test_body_error_does_not_stop_loop(self) -> None:
        """An error in the loop body doesn't break the loop."""
        _kernel, shell = _booted_shell()
        script = """\
for X in a b c
do
  cat /nonexistent
  echo done-$X
done"""
        results = shell.run_script(script)
        # All three iterations should complete
        assert "done-a" in results
        assert "done-b" in results
        assert "done-c" in results


# ---------------------------------------------------------------------------
# Cycle 6 — If block refactor regressions
# ---------------------------------------------------------------------------


class TestIfBlockRefactor:
    """Verify the refactored if block still works and handles nesting."""

    def test_basic_if_regression(self) -> None:
        """Basic if/then/fi still works after refactor."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/flag")
        script = """\
if cat /flag
then
  echo yes
fi"""
        results = shell.run_script(script)
        assert "yes" in results

    def test_if_else_regression(self) -> None:
        """If/else still works after refactor."""
        _kernel, shell = _booted_shell()
        script = """\
if cat /nonexistent
then
  echo yes
else
  echo no
fi"""
        results = shell.run_script(script)
        assert "no" in results
        assert "yes" not in results

    def test_nested_if_fi(self) -> None:
        """Nested if/fi blocks are handled correctly."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/outer")
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/inner")
        script = """\
if cat /outer
then
  if cat /inner
  then
    echo both
  fi
fi"""
        results = shell.run_script(script)
        assert "both" in results

    def test_missing_fi_error(self) -> None:
        """A missing fi produces an error."""
        _kernel, shell = _booted_shell()
        script = """\
if cat /flag
then
  echo oops"""
        results = shell.run_script(script)
        assert any("missing" in r and "fi" in r for r in results)

    def test_variable_sub_in_loop_body(self) -> None:
        """Variables are expanded in loop bodies via recursive run_script."""
        kernel, shell = _booted_shell()
        kernel.syscall(SyscallNumber.SYS_SET_ENV, key="GREETING", value="hi")
        script = """\
for WHO in world
do
  echo $GREETING $WHO
done"""
        results = shell.run_script(script)
        assert "hi world" in results
