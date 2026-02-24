"""File system subsystem — inodes, directories, persistence, and file descriptors.

Re-exports public symbols so callers can write::

    from py_os.fs import FileSystem, FdTable
"""

from py_os.fs.fd import FdError, FdTable, FileMode, OpenFileDescription, SeekWhence
from py_os.fs.filesystem import MAX_SYMLINK_DEPTH, FileSystem, FileType, InodeInfo
from py_os.fs.journal import Journal, JournaledFileSystem, JournalOp, TransactionState
from py_os.fs.persistence import (
    dump_filesystem,
    dump_journaled_filesystem,
    load_filesystem,
    load_journaled_filesystem,
)
from py_os.fs.procfs import ProcError, ProcFilesystem

__all__ = [
    "MAX_SYMLINK_DEPTH",
    "FdError",
    "FdTable",
    "FileMode",
    "FileSystem",
    "FileType",
    "InodeInfo",
    "Journal",
    "JournalOp",
    "JournaledFileSystem",
    "OpenFileDescription",
    "ProcError",
    "ProcFilesystem",
    "SeekWhence",
    "TransactionState",
    "dump_filesystem",
    "dump_journaled_filesystem",
    "load_filesystem",
    "load_journaled_filesystem",
]
