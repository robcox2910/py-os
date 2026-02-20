"""Signal delivery system.

Signals are asynchronous notifications sent to processes, modelled
after Unix signals.  They allow inter-process communication and
process lifecycle control.

Key signals:
    - **SIGTERM** (15) — polite termination request.  The process can
      register a handler for cleanup before being terminated.
    - **SIGKILL** (9) — forced termination.  Cannot be caught or
      handled — the process is killed immediately.
    - **SIGSTOP** (19) — pause execution (RUNNING → WAITING).
    - **SIGCONT** (18) — resume execution (WAITING → READY).

Design choices:
    - **IntEnum with Unix values** — makes the signals instantly
      recognisable to anyone familiar with Unix (``kill -9``).
    - **SIGKILL is uncatchable** — mirrors the real guarantee that
      a misbehaving process can always be killed.
    - **Handlers are kernel-managed** — stored per (pid, signal) pair
      on the kernel, not on the process object itself.
"""

from enum import IntEnum


class Signal(IntEnum):
    """Standard signals with Unix-compatible numeric values."""

    SIGKILL = 9
    SIGTERM = 15
    SIGCONT = 18
    SIGSTOP = 19


class SignalError(Exception):
    """Raised when signal delivery fails."""
