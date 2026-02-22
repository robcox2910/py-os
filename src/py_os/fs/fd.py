"""File descriptors — per-process tables tracking open files.

In Unix, programs interact with files through **file descriptors** (small
integers).  The workflow is:

1. ``open(path, mode)`` → the kernel allocates the lowest available fd
   number and returns it.
2. ``read(fd, count)`` / ``write(fd, data)`` → operates at the fd's
   current offset, then advances the offset.
3. ``seek(fd, offset, whence)`` → repositions the offset without
   reading or writing.
4. ``close(fd)`` → releases the fd for reuse.

Key concepts:

- **File descriptor (fd)**: a small non-negative integer that identifies
  an open file within a single process.  Fds 0, 1, 2 are reserved for
  stdin, stdout, stderr (even though we don't implement them yet).
- **Open file description (OFD)**: the bookkeeping record behind an fd —
  path, mode, and current byte offset.
- **Fd table**: per-process mapping from fd numbers to OFDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FdError(Exception):
    """Raise when a file descriptor operation fails."""


class SeekWhence(StrEnum):
    """Direction for seek operations.

    - SET — absolute offset from the beginning of the file.
    - CUR — relative offset from the current position.
    - END — relative offset from the end of the file.
    """

    SET = "set"
    CUR = "cur"
    END = "end"


class FileMode(StrEnum):
    """Access mode for an open file.

    - READ  — read-only access.
    - WRITE — write-only access.
    - READ_WRITE — both read and write access.
    """

    READ = "r"
    WRITE = "w"
    READ_WRITE = "rw"


@dataclass
class OpenFileDescription:
    """Track an open file's path, mode, and current offset.

    Not frozen — ``offset`` must be mutable so reads and writes can
    advance the position.
    """

    path: str
    mode: FileMode
    offset: int = 0
    inode_number: int = 0


class FdTable:
    """Per-process table mapping fd numbers to open file descriptions.

    Fd numbers 0, 1, 2 are reserved for stdin, stdout, stderr.
    Allocation starts at ``FIRST_FD`` (3) and always picks the lowest
    available number, mimicking Unix behaviour.
    """

    FIRST_FD = 3

    def __init__(self) -> None:
        """Create an empty fd table."""
        self._fds: dict[int, OpenFileDescription] = {}

    def allocate(self, ofd: OpenFileDescription) -> int:
        """Assign the lowest available fd (>= 3) to an open file description.

        Args:
            ofd: The open file description to register.

        Returns:
            The newly assigned fd number.

        """
        fd = self.FIRST_FD
        while fd in self._fds:
            fd += 1
        self._fds[fd] = ofd
        return fd

    def lookup(self, fd: int) -> OpenFileDescription:
        """Return the open file description for a given fd.

        Args:
            fd: The file descriptor number.

        Raises:
            FdError: If the fd is not open.

        """
        ofd = self._fds.get(fd)
        if ofd is None:
            msg = f"Bad file descriptor: {fd}"
            raise FdError(msg)
        return ofd

    def close(self, fd: int) -> None:
        """Close an fd, releasing it for reuse.

        Args:
            fd: The file descriptor number.

        Raises:
            FdError: If the fd is not open.

        """
        if fd not in self._fds:
            msg = f"Bad file descriptor: {fd}"
            raise FdError(msg)
        del self._fds[fd]

    def list_fds(self) -> dict[int, OpenFileDescription]:
        """Return a snapshot of all open fds.

        Returns:
            A dict mapping fd numbers to open file descriptions.

        """
        return dict(self._fds)

    def duplicate(self) -> FdTable:
        """Deep copy the fd table for fork.

        Each open file description is copied independently so the child
        process gets its own offsets.  (In real Unix, parent and child
        share the same open file description — we simplify by copying.)

        Returns:
            A new FdTable with independent copies of every entry.

        """
        new_table = FdTable()
        for fd, ofd in self._fds.items():
            new_table._fds[fd] = OpenFileDescription(
                path=ofd.path,
                mode=ofd.mode,
                offset=ofd.offset,
                inode_number=ofd.inode_number,
            )
        return new_table
