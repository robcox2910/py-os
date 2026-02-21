"""File system subsystem — inodes, directories, and persistence.

Re-exports public symbols so callers can write::

    from py_os.fs import FileSystem
"""

from py_os.fs.filesystem import FileSystem, FileType, InodeInfo
from py_os.fs.persistence import dump_filesystem, load_filesystem

__all__ = [
    "FileSystem",
    "FileType",
    "InodeInfo",
    "dump_filesystem",
    "load_filesystem",
]
