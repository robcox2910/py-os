"""Tests for the process module.

A process is a program in execution. The OS tracks each process via a
Process Control Block (PCB) containing its PID, state, priority, and
resource information. Processes follow a strict state machine:

    NEW → READY ⇄ RUNNING → TERMINATED
                    ↓  ↑
                  WAITING
"""

import pytest

from py_os.process import Process, ProcessState

INITIAL_PRIORITY = 0
CUSTOM_PRIORITY = 5
HIGH_PRIORITY = 10


class TestProcessCreation:
    """Verify that a newly created process has correct defaults."""

    def test_new_process_has_unique_pid(self) -> None:
        """Each process should receive a unique PID."""
        p1 = Process(name="init")
        p2 = Process(name="shell")
        assert p1.pid != p2.pid

    def test_new_process_starts_in_new_state(self) -> None:
        """A freshly created process should be in the NEW state."""
        process = Process(name="init")
        assert process.state is ProcessState.NEW

    def test_new_process_has_default_priority(self) -> None:
        """Without an explicit priority, default should be zero."""
        process = Process(name="init")
        assert process.priority == INITIAL_PRIORITY

    def test_new_process_accepts_custom_priority(self) -> None:
        """A process can be created with a specific priority."""
        process = Process(name="init", priority=CUSTOM_PRIORITY)
        assert process.priority == CUSTOM_PRIORITY

    def test_new_process_stores_name(self) -> None:
        """The process name should be accessible after creation."""
        process = Process(name="my_daemon")
        assert process.name == "my_daemon"

    def test_new_process_has_no_parent_by_default(self) -> None:
        """A root process has no parent PID."""
        process = Process(name="init")
        assert process.parent_pid is None

    def test_new_process_accepts_parent_pid(self) -> None:
        """A child process stores its parent's PID."""
        parent = Process(name="shell")
        child = Process(name="ls", parent_pid=parent.pid)
        assert child.parent_pid == parent.pid


class TestProcessStateTransitions:
    """Verify legal and illegal state transitions.

    The state machine:
        NEW → READY ⇄ RUNNING → TERMINATED
                        ↓  ↑
                      WAITING
    """

    def test_admit_transitions_new_to_ready(self) -> None:
        """Admitting a NEW process puts it in the READY queue."""
        process = Process(name="init")
        process.admit()
        assert process.state is ProcessState.READY

    def test_dispatch_transitions_ready_to_running(self) -> None:
        """Dispatching a READY process gives it the CPU."""
        process = Process(name="init")
        process.admit()
        process.dispatch()
        assert process.state is ProcessState.RUNNING

    def test_preempt_transitions_running_to_ready(self) -> None:
        """Preempting a RUNNING process returns it to READY."""
        process = Process(name="init")
        process.admit()
        process.dispatch()
        process.preempt()
        assert process.state is ProcessState.READY

    def test_wait_transitions_running_to_waiting(self) -> None:
        """A RUNNING process that needs I/O moves to WAITING."""
        process = Process(name="init")
        process.admit()
        process.dispatch()
        process.wait()
        assert process.state is ProcessState.WAITING

    def test_wake_transitions_waiting_to_ready(self) -> None:
        """When I/O completes, a WAITING process becomes READY."""
        process = Process(name="init")
        process.admit()
        process.dispatch()
        process.wait()
        process.wake()
        assert process.state is ProcessState.READY

    def test_terminate_transitions_running_to_terminated(self) -> None:
        """A RUNNING process can be terminated."""
        process = Process(name="init")
        process.admit()
        process.dispatch()
        process.terminate()
        assert process.state is ProcessState.TERMINATED


class TestProcessIllegalTransitions:
    """Verify that invalid state transitions raise errors."""

    def test_cannot_dispatch_new_process(self) -> None:
        """A NEW process must be admitted before dispatch."""
        process = Process(name="init")
        with pytest.raises(RuntimeError, match="Cannot dispatch"):
            process.dispatch()

    def test_cannot_admit_running_process(self) -> None:
        """A RUNNING process cannot be admitted again."""
        process = Process(name="init")
        process.admit()
        process.dispatch()
        with pytest.raises(RuntimeError, match="Cannot admit"):
            process.admit()

    def test_cannot_terminate_new_process(self) -> None:
        """A NEW process cannot be terminated directly."""
        process = Process(name="init")
        with pytest.raises(RuntimeError, match="Cannot terminate"):
            process.terminate()

    def test_cannot_wait_ready_process(self) -> None:
        """Only a RUNNING process can wait for I/O."""
        process = Process(name="init")
        process.admit()
        with pytest.raises(RuntimeError, match="Cannot wait"):
            process.wait()

    def test_cannot_wake_ready_process(self) -> None:
        """Only a WAITING process can be woken."""
        process = Process(name="init")
        process.admit()
        with pytest.raises(RuntimeError, match="Cannot wake"):
            process.wake()


class TestProcessRepr:
    """Verify the string representation of a process."""

    def test_repr_contains_pid_name_and_state(self) -> None:
        """The repr should be useful for debugging."""
        process = Process(name="init")
        text = repr(process)
        assert "init" in text
        assert "new" in text
        assert str(process.pid) in text
