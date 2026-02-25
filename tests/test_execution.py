"""Tests for process execution — running Python callables as programs.

In a real OS, a process is a *program in execution*. Until now, our
processes had state transitions but never ran any code. This module
makes processes executable:

    - **exec()** — load a callable into a process (like Unix ``execve()``).
    - **run** — dispatch, execute, capture output, and terminate.
    - **Exit codes** — 0 for success, 1 for failure (like ``$?`` in bash).
    - **Output capture** — the callable's return value is the process stdout.

In real Unix, ``fork()`` creates the process and ``exec()`` loads the
program. This two-step pattern lets the shell set up redirections and
pipes between fork and exec.
"""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.process.pcb import Process
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# -- Process-level execution ---------------------------------------------------

_NUM_PAGES = 1


class TestProcessProgram:
    """Verify that processes can carry and execute programs."""

    def test_no_program_by_default(self) -> None:
        """A new process has no program loaded."""
        proc = Process(name="idle")
        assert proc.program is None

    def test_set_program(self) -> None:
        """A program (callable) can be loaded into a process."""
        proc = Process(name="hello")
        proc.program = lambda: "Hello, world!"
        assert proc.program is not None

    def test_no_output_before_execution(self) -> None:
        """Output is None before the program runs."""
        proc = Process(name="pending")
        proc.program = lambda: "output"
        assert proc.output is None

    def test_no_exit_code_before_execution(self) -> None:
        """Exit code is None before the program runs."""
        proc = Process(name="pending")
        proc.program = lambda: "output"
        assert proc.exit_code is None

    def test_execute_captures_output(self) -> None:
        """Executing a program captures its return value as output."""
        proc = Process(name="greeter")
        proc.program = lambda: "Hello!"
        proc.admit()
        proc.dispatch()
        proc.execute()
        assert proc.output == "Hello!"

    def test_execute_sets_exit_code_zero(self) -> None:
        """A successful program sets exit code 0."""
        proc = Process(name="ok")
        proc.program = lambda: "done"
        proc.admit()
        proc.dispatch()
        proc.execute()
        assert proc.exit_code == 0

    def test_execute_handles_failure(self) -> None:
        """A program that raises sets exit code 1 and captures the error."""

        def failing_program() -> str:
            msg = "something went wrong"
            raise RuntimeError(msg)

        proc = Process(name="crasher")
        proc.program = failing_program
        proc.admit()
        proc.dispatch()
        proc.execute()
        assert proc.exit_code == 1
        assert proc.output == "something went wrong"

    def test_execute_requires_running_state(self) -> None:
        """Execute raises if the process is not in RUNNING state."""
        proc = Process(name="not-ready")
        proc.program = lambda: "output"
        with pytest.raises(RuntimeError, match="not running"):
            proc.execute()

    def test_execute_requires_program(self) -> None:
        """Execute raises if no program is loaded."""
        proc = Process(name="empty")
        proc.admit()
        proc.dispatch()
        with pytest.raises(RuntimeError, match="No program loaded"):
            proc.execute()


# -- Kernel-level execution ----------------------------------------------------


class TestKernelExec:
    """Verify that the kernel can load programs into processes."""

    def test_exec_loads_program(self) -> None:
        """exec_process loads a callable into an existing process."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        proc = kernel.create_process(name="target", num_pages=_NUM_PAGES)
        kernel.exec_process(pid=proc.pid, program=lambda: "loaded")
        assert proc.program is not None
        kernel.shutdown()

    def test_exec_nonexistent_raises(self) -> None:
        """exec_process raises for a PID that doesn't exist."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        pid_nonexistent = 9999
        with pytest.raises(ValueError, match="not found"):
            kernel.exec_process(pid=pid_nonexistent, program=lambda: "x")
        kernel.shutdown()

    def test_exec_terminated_raises(self) -> None:
        """exec_process raises for a terminated process."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        proc = kernel.create_process(name="done", num_pages=_NUM_PAGES)
        proc.dispatch()
        kernel.terminate_process(pid=proc.pid)
        pid = proc.pid
        with pytest.raises(ValueError, match="not found"):
            kernel.exec_process(pid=pid, program=lambda: "x")
        kernel.shutdown()


class TestKernelRun:
    """Verify that the kernel can run processes end-to-end."""

    def test_run_process_returns_output(self) -> None:
        """run_process dispatches, executes, and returns the output."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        proc = kernel.create_process(name="runner", num_pages=_NUM_PAGES)
        kernel.exec_process(pid=proc.pid, program=lambda: "result")
        result = kernel.run_process(pid=proc.pid)
        assert result["output"] == "result"
        assert result["exit_code"] == 0
        kernel.shutdown()

    def test_run_process_terminates(self) -> None:
        """The process is terminated and removed after running."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        proc = kernel.create_process(name="oneshot", num_pages=_NUM_PAGES)
        pid = proc.pid
        kernel.exec_process(pid=pid, program=lambda: "done")
        kernel.run_process(pid=pid)
        assert pid not in kernel.processes
        kernel.shutdown()

    def test_run_process_frees_memory(self) -> None:
        """Memory is freed after the process completes."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        assert kernel.memory is not None
        free_before = kernel.memory.free_frames
        proc = kernel.create_process(name="memuser", num_pages=_NUM_PAGES)
        kernel.exec_process(pid=proc.pid, program=lambda: "done")
        kernel.run_process(pid=proc.pid)
        assert kernel.memory.free_frames == free_before
        kernel.shutdown()

    def test_run_failing_program(self) -> None:
        """A failing program returns exit code 1 and error output."""

        def crasher() -> str:
            msg = "boom"
            raise RuntimeError(msg)

        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        proc = kernel.create_process(name="crasher", num_pages=_NUM_PAGES)
        kernel.exec_process(pid=proc.pid, program=crasher)
        result = kernel.run_process(pid=proc.pid)
        assert result["exit_code"] == 1
        assert result["output"] == "boom"
        kernel.shutdown()

    def test_run_nonexistent_raises(self) -> None:
        """run_process raises for a PID that doesn't exist."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        pid_nonexistent = 9999
        with pytest.raises(ValueError, match="not found"):
            kernel.run_process(pid=pid_nonexistent)
        kernel.shutdown()

    def test_run_without_program_raises(self) -> None:
        """run_process raises if no program is loaded."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        proc = kernel.create_process(name="empty", num_pages=_NUM_PAGES)
        with pytest.raises(ValueError, match="No program"):
            kernel.run_process(pid=proc.pid)
        kernel.shutdown()


# -- Syscall integration -------------------------------------------------------


class TestExecSyscall:
    """Verify the SYS_EXEC syscall works through the syscall layer."""

    def test_exec_via_syscall(self) -> None:
        """SYS_EXEC loads a program through the syscall interface."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS, name="sys-proc", num_pages=_NUM_PAGES
        )
        pid = result["pid"]
        kernel.syscall(SyscallNumber.SYS_EXEC, pid=pid, program=lambda: "syscall output")
        run_result = kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
        assert run_result["output"] == "syscall output"
        assert run_result["exit_code"] == 0
        kernel.shutdown()

    def test_exec_nonexistent_via_syscall(self) -> None:
        """SYS_EXEC on a missing PID raises SyscallError."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        pid_nonexistent = 9999
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_EXEC, pid=pid_nonexistent, program=lambda: "x")
        kernel.shutdown()

    def test_run_via_syscall(self) -> None:
        """SYS_RUN dispatches and executes through the syscall interface."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS, name="runnable", num_pages=_NUM_PAGES
        )
        pid = result["pid"]
        kernel.syscall(SyscallNumber.SYS_EXEC, pid=pid, program=lambda: "ran!")
        run_result = kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
        assert run_result["output"] == "ran!"
        kernel.shutdown()

    def test_run_no_program_via_syscall(self) -> None:
        """SYS_RUN without a loaded program raises SyscallError."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS, name="no-prog", num_pages=_NUM_PAGES
        )
        pid = result["pid"]
        with pytest.raises(SyscallError, match="No program"):
            kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
        kernel.shutdown()


# -- Shell integration ---------------------------------------------------------


class TestShellRun:
    """Verify the shell 'run' command creates and runs processes."""

    def test_run_builtin_hello(self) -> None:
        """The 'run hello' command runs a built-in hello program."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        shell = Shell(kernel=kernel)
        output = shell.execute("run hello")
        assert "Hello" in output
        kernel.shutdown()

    def test_run_builtin_counter(self) -> None:
        """The 'run counter' command runs a built-in counter program."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        shell = Shell(kernel=kernel)
        output = shell.execute("run counter")
        assert "1" in output
        kernel.shutdown()

    def test_run_unknown_program(self) -> None:
        """Running an unknown program name shows an error."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        shell = Shell(kernel=kernel)
        output = shell.execute("run nosuchprogram")
        assert "Unknown program" in output
        kernel.shutdown()

    def test_run_no_args(self) -> None:
        """Running without a program name shows usage."""
        kernel = Kernel()
        kernel.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        shell = Shell(kernel=kernel)
        output = shell.execute("run")
        assert "Usage" in output or "run <program>" in output
        kernel.shutdown()
