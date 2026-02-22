"""Tests for the file system module.

The file system provides an in-memory hierarchical structure with inodes,
directories, and path resolution.  It mirrors the Unix model: inodes
hold metadata, directories map names to inode numbers, and paths are
resolved by walking the tree from the root.
"""

import pytest

from py_os.fs.filesystem import FileSystem, FileType

ROOT_PATH = "/"


class TestFileSystemCreation:
    """Verify the initial state of a fresh file system."""

    def test_root_directory_exists(self) -> None:
        """A new file system should have a root directory."""
        fs = FileSystem()
        assert fs.exists(ROOT_PATH)

    def test_root_is_a_directory(self) -> None:
        """The root path should be a directory, not a file."""
        fs = FileSystem()
        info = fs.stat(ROOT_PATH)
        assert info.file_type is FileType.DIRECTORY

    def test_root_is_empty(self) -> None:
        """A fresh root directory should have no entries."""
        fs = FileSystem()
        assert fs.list_dir(ROOT_PATH) == []


class TestCreateFile:
    """Verify creating files."""

    def test_create_file_in_root(self) -> None:
        """A file created in root should exist afterward."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        assert fs.exists("/hello.txt")

    def test_created_file_is_a_file(self) -> None:
        """A created file should have FILE type, not DIRECTORY."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        info = fs.stat("/hello.txt")
        assert info.file_type is FileType.FILE

    def test_created_file_has_zero_size(self) -> None:
        """A newly created file should have size zero."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        info = fs.stat("/hello.txt")
        expected_size = 0
        assert info.size == expected_size

    def test_created_file_appears_in_listing(self) -> None:
        """The file name should appear in the parent directory listing."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        assert "hello.txt" in fs.list_dir(ROOT_PATH)

    def test_create_duplicate_file_raises(self) -> None:
        """Creating a file that already exists should raise."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        with pytest.raises(FileExistsError, match=r"hello\.txt"):
            fs.create_file("/hello.txt")

    def test_create_file_in_nonexistent_directory_raises(self) -> None:
        """The parent directory must exist."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError, match="nope"):
            fs.create_file("/nope/hello.txt")


class TestCreateDirectory:
    """Verify creating directories."""

    def test_create_directory(self) -> None:
        """A created directory should exist and be a directory."""
        fs = FileSystem()
        fs.create_dir("/docs")
        assert fs.exists("/docs")
        info = fs.stat("/docs")
        assert info.file_type is FileType.DIRECTORY

    def test_create_nested_file(self) -> None:
        """Files can be created inside subdirectories."""
        fs = FileSystem()
        fs.create_dir("/docs")
        fs.create_file("/docs/readme.txt")
        assert fs.exists("/docs/readme.txt")
        assert "readme.txt" in fs.list_dir("/docs")

    def test_create_duplicate_directory_raises(self) -> None:
        """Creating a directory that already exists should raise."""
        fs = FileSystem()
        fs.create_dir("/docs")
        with pytest.raises(FileExistsError, match="docs"):
            fs.create_dir("/docs")


class TestReadWrite:
    """Verify reading and writing file data."""

    def test_write_and_read_back(self) -> None:
        """Data written to a file should be readable."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        fs.write("/hello.txt", b"Hello, OS!")
        assert fs.read("/hello.txt") == b"Hello, OS!"

    def test_write_updates_size(self) -> None:
        """Writing data should update the file's size."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        content = b"Hello, OS!"
        fs.write("/hello.txt", content)
        info = fs.stat("/hello.txt")
        assert info.size == len(content)

    def test_write_overwrites_previous_content(self) -> None:
        """Writing replaces the entire file content (not append)."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        fs.write("/hello.txt", b"first")
        fs.write("/hello.txt", b"second")
        assert fs.read("/hello.txt") == b"second"

    def test_read_empty_file_returns_empty_bytes(self) -> None:
        """Reading a file with no writes should return empty bytes."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        assert fs.read("/hello.txt") == b""

    def test_read_nonexistent_file_raises(self) -> None:
        """Reading a path that doesn't exist should raise."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError):
            fs.read("/nope.txt")

    def test_write_to_directory_raises(self) -> None:
        """Writing data to a directory is not allowed."""
        fs = FileSystem()
        fs.create_dir("/docs")
        with pytest.raises(IsADirectoryError):
            fs.write("/docs", b"nope")

    def test_read_directory_raises(self) -> None:
        """Reading a directory as if it were a file is not allowed."""
        fs = FileSystem()
        fs.create_dir("/docs")
        with pytest.raises(IsADirectoryError):
            fs.read("/docs")


class TestDelete:
    """Verify deleting files and directories."""

    def test_delete_file(self) -> None:
        """A deleted file should no longer exist."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        fs.delete("/hello.txt")
        assert not fs.exists("/hello.txt")

    def test_delete_empty_directory(self) -> None:
        """An empty directory can be deleted."""
        fs = FileSystem()
        fs.create_dir("/docs")
        fs.delete("/docs")
        assert not fs.exists("/docs")

    def test_delete_nonempty_directory_raises(self) -> None:
        """A directory with contents cannot be deleted."""
        fs = FileSystem()
        fs.create_dir("/docs")
        fs.create_file("/docs/readme.txt")
        with pytest.raises(OSError, match="not empty"):
            fs.delete("/docs")

    def test_delete_nonexistent_raises(self) -> None:
        """Deleting something that doesn't exist should raise."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError):
            fs.delete("/nope.txt")

    def test_delete_root_raises(self) -> None:
        """The root directory cannot be deleted."""
        fs = FileSystem()
        with pytest.raises(OSError, match="root"):
            fs.delete(ROOT_PATH)

    def test_deleted_file_frees_name(self) -> None:
        """After deletion, the name can be reused."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        fs.delete("/hello.txt")
        fs.create_file("/hello.txt")
        assert fs.exists("/hello.txt")


# -- Offset-based I/O -------------------------------------------------------


class TestReadAt:
    """Verify FileSystem.read_at() — reading a slice of a file at an offset."""

    def test_read_at_beginning(self) -> None:
        """Reading from offset 0 should return the first count bytes."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write("/data.txt", b"Hello, world!")
        result = fs.read_at("/data.txt", offset=0, count=5)
        assert result == b"Hello"

    def test_read_at_middle(self) -> None:
        """Reading from a mid-file offset should return the correct slice."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write("/data.txt", b"Hello, world!")
        result = fs.read_at("/data.txt", offset=7, count=5)
        assert result == b"world"

    def test_read_at_past_eof_returns_fewer_bytes(self) -> None:
        """Reading more bytes than available should return only what exists."""
        fs = FileSystem()
        fs.create_file("/small.txt")
        fs.write("/small.txt", b"Hi")
        result = fs.read_at("/small.txt", offset=0, count=100)
        assert result == b"Hi"

    def test_read_at_beyond_eof_returns_empty(self) -> None:
        """Reading at an offset beyond the file size should return b''."""
        fs = FileSystem()
        fs.create_file("/small.txt")
        fs.write("/small.txt", b"Hi")
        beyond_eof = 10
        result = fs.read_at("/small.txt", offset=beyond_eof, count=5)
        assert result == b""

    def test_read_at_empty_file(self) -> None:
        """Reading from an empty file should return b''."""
        fs = FileSystem()
        fs.create_file("/empty.txt")
        result = fs.read_at("/empty.txt", offset=0, count=10)
        assert result == b""

    def test_read_at_nonexistent_raises(self) -> None:
        """Reading from a nonexistent path should raise FileNotFoundError."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError):
            fs.read_at("/nope.txt", offset=0, count=5)

    def test_read_at_directory_raises(self) -> None:
        """Reading from a directory should raise IsADirectoryError."""
        fs = FileSystem()
        fs.create_dir("/docs")
        with pytest.raises(IsADirectoryError):
            fs.read_at("/docs", offset=0, count=5)


class TestWriteAt:
    """Verify FileSystem.write_at() — writing data at a specific offset."""

    def test_write_at_beginning(self) -> None:
        """Writing at offset 0 should overwrite the start of the file."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write("/data.txt", b"Hello, world!")
        fs.write_at("/data.txt", offset=0, data=b"Jello")
        assert fs.read("/data.txt") == b"Jello, world!"

    def test_write_at_middle(self) -> None:
        """Writing at a mid-file offset should splice in the data."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write("/data.txt", b"Hello, world!")
        fs.write_at("/data.txt", offset=7, data=b"Earth")
        assert fs.read("/data.txt") == b"Hello, Earth!"

    def test_write_at_extends_file(self) -> None:
        """Writing beyond EOF should extend the file with null padding."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write("/data.txt", b"Hi")
        gap_offset = 5
        fs.write_at("/data.txt", offset=gap_offset, data=b"!")
        result = fs.read("/data.txt")
        expected_length = 6
        assert len(result) == expected_length
        assert result == b"Hi\x00\x00\x00!"

    def test_write_at_empty_file(self) -> None:
        """Writing at offset 0 to an empty file should set the content."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write_at("/data.txt", offset=0, data=b"New")
        assert fs.read("/data.txt") == b"New"

    def test_write_at_nonexistent_raises(self) -> None:
        """Writing to a nonexistent path should raise FileNotFoundError."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError):
            fs.write_at("/nope.txt", offset=0, data=b"x")

    def test_write_at_directory_raises(self) -> None:
        """Writing to a directory should raise IsADirectoryError."""
        fs = FileSystem()
        fs.create_dir("/docs")
        with pytest.raises(IsADirectoryError):
            fs.write_at("/docs", offset=0, data=b"x")
