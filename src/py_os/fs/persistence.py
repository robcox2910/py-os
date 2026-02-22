"""Filesystem persistence — save and load to/from disk.

Real filesystems write their data structures (superblock, inode table,
data blocks) to a storage medium so files survive reboots.  Common
on-disk formats include ext4, NTFS, APFS, and Btrfs.

Our persistence layer serializes the in-memory filesystem to **JSON**
and restores it on load.  This is a simplified analogue:

    - ``dump_filesystem(fs, path)`` — save to a file (like ``sync`` or unmount).
    - ``load_filesystem(path)`` — restore from a file (like ``mount``).

Key concepts:
    - **Serialization** — converting in-memory structures to a storable format.
    - **Deserialization** — reconstructing structures from stored data.
    - **Base64 encoding** — binary file data is encoded as ASCII text for JSON.
    - **Journaling** — log operations before applying them, so a crash
      mid-write doesn't corrupt data.  See ``fs/journal.py``.
"""

import json
from pathlib import Path

from py_os.fs.filesystem import FileSystem
from py_os.fs.journal import JournaledFileSystem


def dump_filesystem(fs: FileSystem, path: Path) -> None:
    """Save a filesystem to a JSON file.

    Analogous to unmounting a filesystem — all in-memory state
    is flushed to persistent storage.

    Args:
        fs: The filesystem to save.
        path: The file path to write to.

    """
    data = fs.to_dict()
    path.write_text(json.dumps(data, indent=2))


def load_filesystem(path: Path) -> FileSystem:
    """Load a filesystem from a JSON file.

    Analogous to mounting a filesystem — the on-disk structures
    are read into memory so they can be accessed.

    Args:
        path: The file path to read from.

    Returns:
        A reconstructed FileSystem instance.

    Raises:
        FileNotFoundError: If the path does not exist.

    """
    text = path.read_text()
    data = json.loads(text)
    return FileSystem.from_dict(data)


def dump_journaled_filesystem(jfs: JournaledFileSystem, path: Path) -> None:
    """Save a journaled filesystem (fs + journal + checkpoint) to JSON.

    Args:
        jfs: The journaled filesystem to save.
        path: The file path to write to.

    """
    data = jfs.to_dict()
    path.write_text(json.dumps(data, indent=2))


def load_journaled_filesystem(path: Path) -> JournaledFileSystem:
    """Load a journaled filesystem from JSON.

    Args:
        path: The file path to read from.

    Returns:
        A reconstructed JournaledFileSystem instance.

    Raises:
        FileNotFoundError: If the path does not exist.

    """
    text = path.read_text()
    data = json.loads(text)
    return JournaledFileSystem.from_dict(data)
