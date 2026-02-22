"""File system subsystem — inodes, directories, persistence, and file descriptors.

Re-exports public symbols so callers can write::

    from py_os.fs import FileSystem, FdTable
"""

from py_os.fs.fd import FdError, FdTable, FileMode, OpenFileDescription, SeekWhence
from py_os.fs.filesystem import MAX_SYMLINK_DEPTH, FileSystem, FileType, InodeInfo
from py_os.fs.persistence import dump_filesystem, load_filesystem

__all__ = [
    "MAX_SYMLINK_DEPTH",
    "FdError",
    "FdTable",
    "FileMode",
    "FileSystem",
    "FileType",
    "InodeInfo",
    "OpenFileDescription",
    "SeekWhence",
    "dump_filesystem",
    "load_filesystem",
]
