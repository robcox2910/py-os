"""Tests for persistent filesystem (save/load to disk).

Real file systems persist data to a storage medium (disk, SSD, NVM).
When you power off and reboot, your files are still there because the
filesystem wrote its data structures (inodes, directory entries, file
data) to the disk.

Our persistence layer serializes the in-memory filesystem to JSON and
restores it on load.  This teaches:
    - **Serialization** — converting in-memory structures to a storable format.
    - **Deserialization** — reconstructing in-memory structures from stored data.
    - **Journaling concept** — though we use simple save/load, real
      filesystems (ext4, NTFS) use journals to survive crashes mid-write.
"""

import json
from pathlib import Path

from py_os.fs.filesystem import FileSystem
from py_os.fs.persistence import dump_filesystem, load_filesystem

# -- Round-trip (save and reload) -----------------------------------------------


class TestRoundTrip:
    """Verify that filesystem state survives save/load cycles."""

    def test_empty_filesystem(self, tmp_path: Path) -> None:
        """An empty filesystem should round-trip correctly."""
        fs = FileSystem()
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)
        fs2 = load_filesystem(path)
        assert fs2.list_dir("/") == []

    def test_files_persist(self, tmp_path: Path) -> None:
        """Files created before save should exist after load."""
        fs = FileSystem()
        fs.create_file("/hello.txt")
        fs.write("/hello.txt", b"world")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        assert "hello.txt" in fs2.list_dir("/")
        assert fs2.read("/hello.txt") == b"world"

    def test_directories_persist(self, tmp_path: Path) -> None:
        """Directories and their contents should persist."""
        fs = FileSystem()
        fs.create_dir("/data")
        fs.create_file("/data/notes.txt")
        fs.write("/data/notes.txt", b"important")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        assert "data" in fs2.list_dir("/")
        assert "notes.txt" in fs2.list_dir("/data")
        assert fs2.read("/data/notes.txt") == b"important"

    def test_nested_directories(self, tmp_path: Path) -> None:
        """Deeply nested directory trees should persist."""
        fs = FileSystem()
        fs.create_dir("/a")
        fs.create_dir("/a/b")
        fs.create_dir("/a/b/c")
        fs.create_file("/a/b/c/deep.txt")
        fs.write("/a/b/c/deep.txt", b"deep data")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        assert fs2.read("/a/b/c/deep.txt") == b"deep data"

    def test_multiple_files(self, tmp_path: Path) -> None:
        """Multiple files in the same directory should all persist."""
        fs = FileSystem()
        file_count = 3
        for i in range(file_count):
            fs.create_file(f"/file{i}.txt")
            fs.write(f"/file{i}.txt", f"content {i}".encode())
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        entries = fs2.list_dir("/")
        assert len(entries) == file_count
        for i in range(file_count):
            assert fs2.read(f"/file{i}.txt") == f"content {i}".encode()

    def test_binary_data(self, tmp_path: Path) -> None:
        """Binary (non-UTF-8) data should survive round-trip."""
        fs = FileSystem()
        fs.create_file("/binary.bin")
        binary_data = bytes(range(256))
        fs.write("/binary.bin", binary_data)
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        assert fs2.read("/binary.bin") == binary_data


# -- Serialization format ------------------------------------------------------


class TestSerializationFormat:
    """Verify the JSON format is reasonable."""

    def test_output_is_valid_json(self, tmp_path: Path) -> None:
        """Dump should produce valid JSON."""
        fs = FileSystem()
        fs.create_file("/test.txt")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)
        data = json.loads(path.read_text())
        assert "inodes" in data

    def test_contains_root(self, tmp_path: Path) -> None:
        """Serialized data should contain the root inode."""
        fs = FileSystem()
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)
        data = json.loads(path.read_text())
        assert "root_ino" in data


# -- Edge cases ----------------------------------------------------------------


class TestEdgeCases:
    """Verify persistence handles edge cases."""

    def test_empty_file(self, tmp_path: Path) -> None:
        """An empty file (no data written) should persist."""
        fs = FileSystem()
        fs.create_file("/empty.txt")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        assert "empty.txt" in fs2.list_dir("/")
        assert fs2.read("/empty.txt") == b""

    def test_overwrite_save_file(self, tmp_path: Path) -> None:
        """Saving twice to the same path should overwrite cleanly."""
        fs = FileSystem()
        fs.create_file("/v1.txt")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs.create_file("/v2.txt")
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        entries = fs2.list_dir("/")
        assert "v1.txt" in entries
        assert "v2.txt" in entries

    def test_loaded_fs_is_independent(self, tmp_path: Path) -> None:
        """Loaded filesystem should be independent of the original."""
        fs = FileSystem()
        fs.create_file("/original.txt")
        path = tmp_path / "fs.json"
        dump_filesystem(fs, path)

        fs2 = load_filesystem(path)
        fs2.create_file("/new_in_loaded.txt")

        # Original should not see the new file
        assert "new_in_loaded.txt" not in fs.list_dir("/")

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        """Loading from a nonexistent path should raise."""
        path = tmp_path / "missing.json"
        try:
            load_filesystem(path)
            raised = False
        except FileNotFoundError:
            raised = True
        assert raised
