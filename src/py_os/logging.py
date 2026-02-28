"""Kernel logging and audit system.

The logger records structured log entries for system events — an audit
trail of what happened, when, and who did it.

Real operating systems maintain kernel log buffers (``dmesg`` on Linux)
that capture boot messages, driver events, and errors.  Our logger
mirrors this concept:

- **LogLevel** — severity levels ordered for filtering (DEBUG < ERROR).
- **LogEntry** — a single structured record (level, message, source, uid).
- **Logger** — an append-only log with filtering and clearing.

Design choices:
    - **IntEnum for levels** so they compare naturally with ``<``.
    - **Frozen dataclass for entries** — log records should be immutable.
    - **Filter returns a list, not a generator** — the log is typically
      small and callers usually want to iterate multiple times.
"""

from dataclasses import dataclass
from enum import IntEnum


class LogLevel(IntEnum):
    """Severity levels for log entries.

    Using IntEnum means levels compare with ``<`` / ``>`` naturally,
    which makes minimum-level filtering trivial.
    """

    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3


@dataclass(frozen=True)
class LogEntry:
    """A single structured log record.

    Attributes:
        level: The severity of this event.
        message: A human-readable description of what happened.
        source: The subsystem that generated the event (e.g. "kernel").
        uid: The user id that triggered the event (0 = root / system).

    """

    level: LogLevel
    message: str
    source: str
    uid: int = 0

    def __str__(self) -> str:
        """Format as ``[LEVEL] source: message``."""
        return f"[{self.level.name}] {self.source}: {self.message}"


class Logger:
    """Append-only log buffer with filtering.

    The logger collects ``LogEntry`` records and provides simple
    querying by level and/or source.  This is the in-memory equivalent
    of ``/var/log/kern.log``.
    """

    def __init__(self) -> None:
        """Create an empty logger."""
        self._entries: list[LogEntry] = []

    @property
    def entries(self) -> list[LogEntry]:
        """Return all log entries in chronological order."""
        return list(self._entries)

    def log(
        self,
        level: LogLevel,
        message: str,
        *,
        source: str,
        uid: int = 0,
    ) -> None:
        """Append a new entry to the log.

        Args:
            level: Severity of the event.
            message: Human-readable event description.
            source: Subsystem that generated the event.
            uid: User id associated with the event.

        """
        self._entries.append(LogEntry(level=level, message=message, source=source, uid=uid))

    def filter(
        self,
        *,
        min_level: LogLevel | None = None,
        source: str | None = None,
    ) -> list[LogEntry]:
        """Return entries matching the given criteria.

        Args:
            min_level: If set, only return entries at or above this level.
            source: If set, only return entries from this source.

        Returns:
            A filtered list of log entries.

        """
        result = self._entries
        if min_level is not None:
            result = [e for e in result if e.level >= min_level]
        if source is not None:
            result = [e for e in result if e.source == source]
        return result if result is not self._entries else list(result)

    def clear(self) -> None:
        """Remove all log entries."""
        self._entries.clear()
