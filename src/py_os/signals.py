"""Signal delivery system.

Signals are asynchronous notifications sent to processes, modelled
after Unix signals.  They allow inter-process communication and
process lifecycle control.

Six signals:
    - **SIGKILL** (9) — forced termination.  Uncatchable — the process
      is killed immediately.
    - **SIGUSR1** (10) — user-defined signal 1.  No built-in meaning;
      ignored by default unless a handler is registered.
    - **SIGUSR2** (12) — user-defined signal 2.  Same as SIGUSR1.
    - **SIGTERM** (15) — polite termination request.  The process can
      register a handler; if one exists, the handler *replaces* the
      default terminate action (the process stays alive).
    - **SIGCONT** (18) — resume execution (WAITING → READY).  If a
      handler is registered it fires, but the process always resumes
      regardless.
    - **SIGSTOP** (19) — pause execution (RUNNING → WAITING).
      Uncatchable — no handler can be registered.

Catchable vs uncatchable:
    - **Uncatchable**: SIGKILL and SIGSTOP.  These always perform their
      default action; attempting to register a handler raises
      ``SignalError``.
    - **Catchable**: All other signals.  A registered handler replaces
      the default action (except SIGCONT, where the handler is
      additive — it fires AND the process resumes).

Design choices:
    - **IntEnum with Unix values** — makes the signals instantly
      recognisable to anyone familiar with Unix (``kill -9``).
    - **Data-driven default actions** — the ``DEFAULT_ACTIONS`` table
      replaces a hardcoded match/case in the kernel, making signal
      behaviour extensible and testable.
    - **Handlers are kernel-managed** — stored per (pid, signal) pair
      on the kernel, not on the process object itself.
"""

from enum import IntEnum, StrEnum


class Signal(IntEnum):
    """Standard signals with Unix-compatible numeric values."""

    SIGKILL = 9
    SIGUSR1 = 10
    SIGUSR2 = 12
    SIGTERM = 15
    SIGCONT = 18
    SIGSTOP = 19


class SignalAction(StrEnum):
    """Default actions that the kernel performs for each signal.

    When no handler is registered (or the signal is uncatchable), the
    kernel looks up the signal in ``DEFAULT_ACTIONS`` and performs the
    corresponding action.
    """

    TERMINATE = "terminate"
    STOP = "stop"
    CONTINUE = "continue"
    IGNORE = "ignore"


DEFAULT_ACTIONS: dict[Signal, SignalAction] = {
    Signal.SIGKILL: SignalAction.TERMINATE,
    Signal.SIGUSR1: SignalAction.IGNORE,
    Signal.SIGUSR2: SignalAction.IGNORE,
    Signal.SIGTERM: SignalAction.TERMINATE,
    Signal.SIGCONT: SignalAction.CONTINUE,
    Signal.SIGSTOP: SignalAction.STOP,
}
"""Map every signal to its default action.

The kernel consults this table when delivering a signal that has no
registered handler (or for uncatchable signals where handlers are
forbidden).
"""

UNCATCHABLE: frozenset[Signal] = frozenset({Signal.SIGKILL, Signal.SIGSTOP})
"""Signals that cannot have a handler registered.

Attempting to register a handler for an uncatchable signal raises
``SignalError``.  This mirrors Unix, where SIGKILL and SIGSTOP are
the only two signals a process can never intercept.
"""


class SignalError(Exception):
    """Raised when signal delivery fails."""
