"""In-memory file system with inodes, directories, and path resolution.

Models the Unix file system architecture:

- **Inode**: metadata record for a file or directory (type, size, data).
  The name does NOT live in the inode — it lives in the parent directory.
  This separation is what makes hard links possible in real Unix.

- **Directory**: a special inode whose data is a ``dict[str, int]``
  mapping child names to their inode numbers.

- **Path resolution**: ``/foo/bar/baz.txt`` is walked component by
  component from the root inode, looking up each name in the current
  directory's entries.

Why inodes instead of nested dicts?
    Inodes mirror how real file systems work. They give us a single
    place to store metadata, and they decouple names from identity.
    A file can exist with zero names (orphan) or many names (hard links).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import count
from typing import Any


class FileType(StrEnum):
    """The kind of object an inode represents."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"


MAX_SYMLINK_DEPTH = 40
"""Maximum symlink resolution depth — matches Linux's SYMLOOP_MAX."""


@dataclass
class InodeInfo:
    """Read-only snapshot of an inode's metadata (returned by stat)."""

    inode_number: int
    file_type: FileType
    size: int
    link_count: int = 1


@dataclass
class _Inode:
    """Internal inode — the core metadata record.

    For files, ``data`` holds the raw bytes.
    For directories, ``children`` maps names to inode numbers.
    """

    inode_number: int
    file_type: FileType
    data: bytes = b""
    children: dict[str, int] = field(default_factory=dict)  # pyright: ignore[reportUnknownVariableType]
    link_count: int = 1

    @property
    def size(self) -> int:
        """Return the size of the file data in bytes."""
        return len(self.data)

    def to_info(self) -> InodeInfo:
        """Create a read-only snapshot of this inode."""
        return InodeInfo(
            inode_number=self.inode_number,
            file_type=self.file_type,
            size=self.size,
            link_count=self.link_count,
        )


# Module-level inode counter, same pattern as PID generation.
_inode_counter = count(start=0)

ROOT_INODE = 0


def _split_path(path: str) -> tuple[str, str]:
    """Split a path into (parent_path, child_name).

    Examples::

        "/foo/bar/baz.txt" → ("/foo/bar", "baz.txt")
        "/hello.txt"       → ("/", "hello.txt")
        "/"                → ("", "")

    """
    if path == "/":
        return ("", "")
    path = path.rstrip("/")
    last_slash = path.rfind("/")
    if last_slash == 0:
        return ("/", path[1:])
    return (path[:last_slash], path[last_slash + 1 :])


class FileSystem:
    """An in-memory file system with inodes and hierarchical directories.

    The file system is initialised with a root directory at ``/``.
    All operations take absolute paths and resolve them by walking
    from the root inode.
    """

    def __init__(self) -> None:
        """Create a file system with an empty root directory."""
        root = _Inode(inode_number=next(_inode_counter), file_type=FileType.DIRECTORY)
        self._inodes: dict[int, _Inode] = {root.inode_number: root}
        self._root_ino: int = root.inode_number

    def _resolve(self, path: str, *, _depth: int = 0) -> _Inode | None:
        """Walk the path from root, following symlinks, and return the target inode.

        When a path component resolves to a symlink:
        - Absolute target → restart resolution from root.
        - Relative target → resolve from the symlink's parent directory.

        The *_depth* counter prevents infinite loops from circular
        symlinks.  It is incremented each time a symlink is followed.

        Raises:
            OSError: If symlink depth exceeds MAX_SYMLINK_DEPTH.

        """
        if _depth > MAX_SYMLINK_DEPTH:
            msg = "Too many levels of symbolic links"
            raise OSError(msg)

        if path == "/":
            return self._inodes[self._root_ino]

        parts = path.strip("/").split("/")
        current = self._inodes[self._root_ino]

        for i, part in enumerate(parts):
            if current.file_type is not FileType.DIRECTORY:
                return None
            child_ino = current.children.get(part)
            if child_ino is None:
                return None
            child = self._inodes[child_ino]

            if child.file_type is FileType.SYMLINK:
                target = child.data.decode()
                remaining = "/".join(parts[i + 1 :])
                if target.startswith("/"):
                    full = target + ("/" + remaining if remaining else "")
                else:
                    # Resolve relative to the symlink's parent directory
                    parent_parts = parts[:i]
                    parent = "/" + "/".join(parent_parts) if parent_parts else "/"
                    full = parent.rstrip("/") + "/" + target
                    if remaining:
                        full += "/" + remaining
                return self._resolve(full, _depth=_depth + 1)

            current = child

        return current

    def exists(self, path: str) -> bool:
        """Check whether a path exists in the file system."""
        try:
            return self._resolve(path) is not None
        except OSError:
            return False

    def stat(self, path: str) -> InodeInfo:
        """Return metadata for the given path.

        Args:
            path: Absolute path to stat.

        Raises:
            FileNotFoundError: If the path does not exist.

        """
        inode = self._resolve(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        return inode.to_info()

    def lstat(self, path: str) -> InodeInfo:
        """Return metadata without following the final symlink.

        Like stat(), but if *path* is a symlink it returns metadata
        about the symlink itself rather than its target.

        Args:
            path: Absolute path to stat.

        Raises:
            FileNotFoundError: If the path does not exist.

        """
        inode = self._resolve_no_follow(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        return inode.to_info()

    def list_dir(self, path: str) -> list[str]:
        """List the names in a directory.

        Args:
            path: Absolute path to a directory.

        Raises:
            FileNotFoundError: If the path does not exist.
            NotADirectoryError: If the path is not a directory.

        """
        inode = self._resolve(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        if inode.file_type is not FileType.DIRECTORY:
            msg = f"Not a directory: {path}"
            raise NotADirectoryError(msg)
        return sorted(inode.children.keys())

    def create_file(self, path: str) -> None:
        """Create an empty file at the given path.

        Args:
            path: Absolute path for the new file.

        Raises:
            FileExistsError: If the path already exists.
            FileNotFoundError: If the parent directory does not exist.

        """
        self._create(path, FileType.FILE)

    def create_dir(self, path: str) -> None:
        """Create an empty directory at the given path.

        Args:
            path: Absolute path for the new directory.

        Raises:
            FileExistsError: If the path already exists.
            FileNotFoundError: If the parent directory does not exist.

        """
        self._create(path, FileType.DIRECTORY)

    def _create(self, path: str, file_type: FileType) -> None:
        """Create an inode and link it into its parent directory."""
        if self.exists(path):
            _, name = _split_path(path)
            msg = f"Already exists: {name}"
            raise FileExistsError(msg)

        parent_path, name = _split_path(path)
        parent = self._resolve(parent_path)
        if parent is None or parent.file_type is not FileType.DIRECTORY:
            msg = f"Parent directory not found: {parent_path or name}"
            raise FileNotFoundError(msg)

        new_inode = _Inode(inode_number=next(_inode_counter), file_type=file_type)
        self._inodes[new_inode.inode_number] = new_inode
        parent.children[name] = new_inode.inode_number

    def read(self, path: str) -> bytes:
        """Read the contents of a file.

        Args:
            path: Absolute path to a file.

        Raises:
            FileNotFoundError: If the path does not exist.
            IsADirectoryError: If the path is a directory.

        """
        inode = self._resolve(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        if inode.file_type is FileType.DIRECTORY:
            msg = f"Is a directory: {path}"
            raise IsADirectoryError(msg)
        return inode.data

    def write(self, path: str, data: bytes) -> None:
        """Write data to a file (replaces existing content).

        Args:
            path: Absolute path to a file.
            data: The bytes to write.

        Raises:
            FileNotFoundError: If the path does not exist.
            IsADirectoryError: If the path is a directory.

        """
        inode = self._resolve(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        if inode.file_type is FileType.DIRECTORY:
            msg = f"Is a directory: {path}"
            raise IsADirectoryError(msg)
        inode.data = data

    def read_at(self, path: str, *, offset: int, count: int) -> bytes:
        """Read *count* bytes from a file starting at *offset*.

        Matches Unix ``read(2)`` semantics:
        - Reading past EOF returns fewer bytes than requested.
        - Reading at or beyond EOF returns ``b""``.

        Args:
            path: Absolute path to a file.
            offset: Byte offset to start reading from.
            count: Maximum number of bytes to read.

        Raises:
            FileNotFoundError: If the path does not exist.
            IsADirectoryError: If the path is a directory.

        """
        inode = self._resolve(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        if inode.file_type is FileType.DIRECTORY:
            msg = f"Is a directory: {path}"
            raise IsADirectoryError(msg)
        return inode.data[offset : offset + count]

    def write_at(self, path: str, *, offset: int, data: bytes) -> None:
        r"""Write *data* into a file at *offset*, splicing into existing content.

        Matches Unix ``lseek`` + ``write`` behaviour:
        - Writing within the file overwrites bytes in place.
        - Writing beyond EOF pads the gap with ``\x00`` bytes.

        Args:
            path: Absolute path to a file.
            offset: Byte offset to start writing at.
            data: The bytes to write.

        Raises:
            FileNotFoundError: If the path does not exist.
            IsADirectoryError: If the path is a directory.

        """
        inode = self._resolve(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        if inode.file_type is FileType.DIRECTORY:
            msg = f"Is a directory: {path}"
            raise IsADirectoryError(msg)
        existing = inode.data
        # Pad with nulls if offset is past current EOF
        if offset > len(existing):
            existing = existing + b"\x00" * (offset - len(existing))
        inode.data = existing[:offset] + data + existing[offset + len(data) :]

    def link(self, target_path: str, link_path: str) -> None:
        """Create a hard link — a second name for an existing file.

        Both names share the same inode, so changes through one name
        are visible through the other.  Directories cannot be hard-linked
        because that would create cycles in the directory tree.

        Args:
            target_path: Absolute path to the existing file.
            link_path: Absolute path for the new name.

        Raises:
            FileNotFoundError: If *target_path* or the parent of
                *link_path* does not exist.
            FileExistsError: If *link_path* already exists.
            OSError: If *target_path* is a directory.

        """
        target = self._resolve(target_path)
        if target is None:
            msg = f"Path not found: {target_path}"
            raise FileNotFoundError(msg)

        if target.file_type is FileType.DIRECTORY:
            msg = "Cannot hard-link a directory"
            raise OSError(msg)

        if self.exists(link_path):
            _, name = _split_path(link_path)
            msg = f"Already exists: {name}"
            raise FileExistsError(msg)

        parent_path, name = _split_path(link_path)
        parent = self._resolve(parent_path)
        if parent is None or parent.file_type is not FileType.DIRECTORY:
            msg = f"Parent directory not found: {parent_path or name}"
            raise FileNotFoundError(msg)

        parent.children[name] = target.inode_number
        target.link_count += 1

    def symlink(self, target_path: str, link_path: str) -> None:
        """Create a symbolic link pointing to *target_path*.

        The target does not need to exist — dangling symlinks are valid
        in Unix.  The symlink is a new inode whose data stores the
        target path as UTF-8 bytes.

        Args:
            target_path: The path the symlink will point to.
            link_path: Absolute path for the new symlink.

        Raises:
            FileExistsError: If *link_path* already exists.
            FileNotFoundError: If the parent of *link_path* is missing.

        """
        if self.exists(link_path):
            _, name = _split_path(link_path)
            msg = f"Already exists: {name}"
            raise FileExistsError(msg)

        parent_path, name = _split_path(link_path)
        parent = self._resolve(parent_path)
        if parent is None or parent.file_type is not FileType.DIRECTORY:
            msg = f"Parent directory not found: {parent_path or name}"
            raise FileNotFoundError(msg)

        new_inode = _Inode(
            inode_number=next(_inode_counter),
            file_type=FileType.SYMLINK,
            data=target_path.encode(),
        )
        self._inodes[new_inode.inode_number] = new_inode
        parent.children[name] = new_inode.inode_number

    def readlink(self, path: str) -> str:
        """Return the target path stored in a symbolic link.

        Args:
            path: Absolute path to a symlink.

        Raises:
            FileNotFoundError: If the path does not exist.
            OSError: If the path is not a symlink.

        """
        inode = self._resolve_no_follow(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)
        if inode.file_type is not FileType.SYMLINK:
            msg = f"Not a symlink: {path}"
            raise OSError(msg)
        return inode.data.decode()

    def _resolve_no_follow(self, path: str, *, _depth: int = 0) -> _Inode | None:
        """Resolve *path* without following the final symlink component.

        Intermediate symlinks ARE followed, but the last component is
        returned as-is even if it is a symlink.  Used by readlink(),
        lstat(), and delete().

        Raises:
            OSError: If symlink depth exceeds MAX_SYMLINK_DEPTH.

        """
        if _depth > MAX_SYMLINK_DEPTH:
            msg = "Too many levels of symbolic links"
            raise OSError(msg)

        if path == "/":
            return self._inodes[self._root_ino]

        parts = path.strip("/").split("/")
        current = self._inodes[self._root_ino]

        for i, part in enumerate(parts):
            if current.file_type is not FileType.DIRECTORY:
                return None
            child_ino = current.children.get(part)
            if child_ino is None:
                return None
            child = self._inodes[child_ino]
            is_last = i == len(parts) - 1

            if is_last:
                # Don't follow the final component
                return child

            # Follow intermediate symlinks
            if child.file_type is FileType.SYMLINK:
                target = child.data.decode()
                remaining = "/".join(parts[i + 1 :])
                if target.startswith("/"):
                    full = target + ("/" + remaining if remaining else "")
                else:
                    parent_parts = parts[:i]
                    parent = "/" + "/".join(parent_parts) if parent_parts else "/"
                    full = parent.rstrip("/") + "/" + target
                    if remaining:
                        full += "/" + remaining
                return self._resolve_no_follow(full, _depth=_depth + 1)

            current = child

        return current  # pragma: no cover — loop always returns on last

    def delete(self, path: str) -> None:
        """Delete a file or empty directory.

        For files with multiple hard links, only the name is removed
        and link_count is decremented.  The inode is freed only when
        link_count reaches zero.

        Args:
            path: Absolute path to delete.

        Raises:
            FileNotFoundError: If the path does not exist.
            OSError: If the path is the root or a non-empty directory.

        """
        if path == "/":
            msg = "Cannot delete root directory"
            raise OSError(msg)

        # Use _resolve_no_follow so deleting a symlink removes the
        # symlink itself, not whatever it points to.
        inode = self._resolve_no_follow(path)
        if inode is None:
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)

        if inode.file_type is FileType.DIRECTORY and inode.children:
            msg = f"Directory not empty: {path}"
            raise OSError(msg)

        parent_path, name = _split_path(path)
        parent = self._resolve(parent_path)
        if parent is None:  # pragma: no cover — unreachable if child resolved
            msg = f"Parent directory not found: {parent_path}"
            raise FileNotFoundError(msg)
        del parent.children[name]
        inode.link_count -= 1
        if inode.link_count <= 0:
            del self._inodes[inode.inode_number]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the filesystem to a dictionary.

        File data is base64-encoded so binary content survives JSON
        serialization.  In real filesystems, the on-disk format is
        a binary superblock + inode table + data blocks.  Our JSON
        format is the teaching equivalent.
        """
        inodes = {}
        for ino_num, inode in self._inodes.items():
            inodes[str(ino_num)] = {
                "inode_number": inode.inode_number,
                "file_type": inode.file_type.value,
                "data": base64.b64encode(inode.data).decode("ascii"),
                "children": dict(inode.children),
                "link_count": inode.link_count,
            }
        return {"root_ino": self._root_ino, "inodes": inodes}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileSystem:
        """Deserialize a filesystem from a dictionary.

        Reconstructs the inode table and root reference from the
        serialized format produced by ``to_dict()``.
        """
        fs = object.__new__(cls)
        fs._root_ino = data["root_ino"]
        fs._inodes = {}
        for ino_data in data["inodes"].values():
            inode = _Inode(
                inode_number=ino_data["inode_number"],
                file_type=FileType(ino_data["file_type"]),
                data=base64.b64decode(ino_data["data"]),
                children=ino_data.get("children", {}),
                link_count=ino_data.get("link_count", 1),
            )
            fs._inodes[inode.inode_number] = inode
        return fs
