"""Tests for symbolic and hard links — multiple names for files.

Links are a fundamental Unix concept that separates a file's **name**
from its **identity** (the inode).  Hard links give the same inode
multiple names in the directory tree.  Symbolic links create a new
inode that stores a path to another file — like a shortcut.

This module tests both link types, path resolution through symlinks,
loop detection, serialization, kernel integration, syscalls, and
shell commands.
"""

import pytest

from py_os.fs.fd import FileMode
from py_os.fs.filesystem import MAX_SYMLINK_DEPTH, FileSystem, FileType, InodeInfo, _Inode
from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# ---------------------------------------------------------------------------
# Cycle 1 — Data structure foundations
# ---------------------------------------------------------------------------


class TestLinkDataStructures:
    """Verify new data-structure fields needed for links."""

    def test_file_type_has_symlink_member(self) -> None:
        """FileType should include a SYMLINK variant."""
        assert FileType.SYMLINK == "symlink"

    def test_file_type_has_three_members(self) -> None:
        """FileType should have file, directory, and symlink."""
        expected_count = 3
        assert len(FileType) == expected_count

    def test_inode_link_count_defaults_to_one(self) -> None:
        """A new inode should start with link_count=1."""
        inode = _Inode(inode_number=0, file_type=FileType.FILE)
        assert inode.link_count == 1

    def test_inode_link_count_is_settable(self) -> None:
        """link_count should be a mutable field on _Inode."""
        inode = _Inode(inode_number=0, file_type=FileType.FILE, link_count=5)
        expected_count = 5
        assert inode.link_count == expected_count

    def test_inode_info_link_count_defaults_to_one(self) -> None:
        """InodeInfo should expose link_count, defaulting to 1."""
        info = InodeInfo(inode_number=0, file_type=FileType.FILE, size=0)
        assert info.link_count == 1

    def test_inode_info_link_count_is_settable(self) -> None:
        """InodeInfo link_count should be settable at construction."""
        info = InodeInfo(inode_number=0, file_type=FileType.FILE, size=0, link_count=3)
        expected_count = 3
        assert info.link_count == expected_count

    def test_to_info_includes_link_count(self) -> None:
        """_Inode.to_info() should carry link_count to InodeInfo."""
        inode = _Inode(inode_number=7, file_type=FileType.FILE, link_count=4)
        info = inode.to_info()
        expected_count = 4
        assert info.link_count == expected_count

    def test_max_symlink_depth_is_forty(self) -> None:
        """MAX_SYMLINK_DEPTH should be 40, matching Linux's SYMLOOP_MAX."""
        expected_depth = 40
        assert expected_depth == MAX_SYMLINK_DEPTH


# ---------------------------------------------------------------------------
# Cycle 2 — Hard links and delete refactor
# ---------------------------------------------------------------------------


class TestHardLink:
    """Verify link() creates a second name pointing to the same inode."""

    def test_link_creates_second_name(self) -> None:
        """link() should make the target accessible under the new name."""
        fs = FileSystem()
        fs.create_file("/original.txt")
        fs.write("/original.txt", b"hello")
        fs.link("/original.txt", "/alias.txt")

        assert fs.read("/alias.txt") == b"hello"

    def test_link_shares_same_inode(self) -> None:
        """Both names should resolve to the same inode number."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        fs.link("/a.txt", "/b.txt")

        assert fs.stat("/a.txt").inode_number == fs.stat("/b.txt").inode_number

    def test_link_increments_link_count(self) -> None:
        """Creating a hard link should increment the inode's link_count."""
        fs = FileSystem()
        fs.create_file("/f.txt")
        assert fs.stat("/f.txt").link_count == 1

        fs.link("/f.txt", "/g.txt")
        expected_count = 2
        assert fs.stat("/f.txt").link_count == expected_count
        assert fs.stat("/g.txt").link_count == expected_count

    def test_link_to_nonexistent_target_raises(self) -> None:
        """link() should raise FileNotFoundError for a missing target."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError, match="not found"):
            fs.link("/missing.txt", "/link.txt")

    def test_link_existing_destination_raises(self) -> None:
        """link() should raise FileExistsError when the link name exists."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        fs.create_file("/b.txt")
        with pytest.raises(FileExistsError, match="Already exists"):
            fs.link("/a.txt", "/b.txt")

    def test_link_directory_raises(self) -> None:
        """Hard-linking directories is forbidden (would create cycles)."""
        fs = FileSystem()
        fs.create_dir("/mydir")
        with pytest.raises(OSError, match="Cannot hard-link a directory"):
            fs.link("/mydir", "/alias")

    def test_link_parent_not_found_raises(self) -> None:
        """link() should raise FileNotFoundError when parent dir is missing."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        with pytest.raises(FileNotFoundError, match="not found"):
            fs.link("/a.txt", "/no/such/dir/link.txt")

    def test_link_in_subdirectory(self) -> None:
        """Hard links can span directories."""
        fs = FileSystem()
        fs.create_dir("/docs")
        fs.create_file("/hello.txt")
        fs.write("/hello.txt", b"world")
        fs.link("/hello.txt", "/docs/ref.txt")

        assert fs.read("/docs/ref.txt") == b"world"

    def test_write_through_one_name_visible_in_other(self) -> None:
        """Writing through one hard link name is visible via the other."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        fs.link("/a.txt", "/b.txt")
        fs.write("/a.txt", b"shared data")

        assert fs.read("/b.txt") == b"shared data"

    def test_multiple_hard_links(self) -> None:
        """A file can have more than two hard links."""
        fs = FileSystem()
        fs.create_file("/f.txt")
        fs.link("/f.txt", "/g.txt")
        fs.link("/f.txt", "/h.txt")

        expected_count = 3
        assert fs.stat("/f.txt").link_count == expected_count


class TestDeleteWithLinkCount:
    """Verify delete() decrements link_count and only frees at zero."""

    def test_delete_single_name_removes_inode(self) -> None:
        """Deleting the only name should remove the inode entirely."""
        fs = FileSystem()
        fs.create_file("/only.txt")
        fs.delete("/only.txt")

        assert not fs.exists("/only.txt")

    def test_delete_one_of_two_names_keeps_inode(self) -> None:
        """Deleting one hard link should keep the other accessible."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        fs.write("/a.txt", b"survive")
        fs.link("/a.txt", "/b.txt")

        fs.delete("/a.txt")

        assert not fs.exists("/a.txt")
        assert fs.read("/b.txt") == b"survive"

    def test_delete_decrements_link_count(self) -> None:
        """After deleting one name, link_count should drop by one."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        fs.link("/a.txt", "/b.txt")
        fs.link("/a.txt", "/c.txt")

        expected_before = 3
        assert fs.stat("/a.txt").link_count == expected_before

        fs.delete("/a.txt")
        expected_after = 2
        assert fs.stat("/b.txt").link_count == expected_after

    def test_delete_last_name_frees_inode(self) -> None:
        """Deleting the last name should free the inode from the table."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        ino = fs.stat("/a.txt").inode_number
        fs.link("/a.txt", "/b.txt")

        fs.delete("/a.txt")
        fs.delete("/b.txt")

        # The inode should no longer exist in the internal table
        assert ino not in fs._inodes


# ---------------------------------------------------------------------------
# Cycle 3 — Symlink creation and readlink
# ---------------------------------------------------------------------------


class TestSymlinkCreation:
    """Verify symlink() creates a new inode with the target path as data."""

    def test_symlink_creates_entry(self) -> None:
        """symlink() should create a new name in the parent directory."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        assert fs.exists("/link.txt")

    def test_symlink_inode_is_distinct(self) -> None:
        """A symlink has its own inode (different from the target)."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        target_ino = fs.stat("/target.txt").inode_number
        # Use _resolve_no_follow to get the symlink inode itself
        link_inode = fs._resolve_no_follow("/link.txt")
        assert link_inode is not None
        assert link_inode.inode_number != target_ino

    def test_symlink_stores_target_as_data(self) -> None:
        """The symlink's inode data should be the target path in UTF-8."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        link_inode = fs._resolve_no_follow("/link.txt")
        assert link_inode is not None
        assert link_inode.data == b"/target.txt"

    def test_symlink_file_type_is_symlink(self) -> None:
        """The symlink's inode should have file_type=SYMLINK."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        link_inode = fs._resolve_no_follow("/link.txt")
        assert link_inode is not None
        assert link_inode.file_type is FileType.SYMLINK

    def test_symlink_dangling_is_allowed(self) -> None:
        """symlink() should succeed even if the target doesn't exist."""
        fs = FileSystem()
        fs.symlink("/nonexistent", "/dangling.txt")

        link_inode = fs._resolve_no_follow("/dangling.txt")
        assert link_inode is not None
        assert link_inode.data == b"/nonexistent"

    def test_symlink_existing_name_raises(self) -> None:
        """symlink() should raise FileExistsError if link_path exists."""
        fs = FileSystem()
        fs.create_file("/existing.txt")
        with pytest.raises(FileExistsError, match="Already exists"):
            fs.symlink("/target", "/existing.txt")

    def test_symlink_parent_not_found_raises(self) -> None:
        """symlink() should raise FileNotFoundError if parent dir is missing."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError, match="not found"):
            fs.symlink("/target", "/no/such/link")

    def test_symlink_to_directory(self) -> None:
        """Symlinks to directories are allowed (unlike hard links)."""
        fs = FileSystem()
        fs.create_dir("/mydir")
        fs.symlink("/mydir", "/dirlink")

        link_inode = fs._resolve_no_follow("/dirlink")
        assert link_inode is not None
        assert link_inode.data == b"/mydir"


class TestReadlink:
    """Verify readlink() returns the symlink target path."""

    def test_readlink_returns_target(self) -> None:
        """readlink() should return the stored target path as a string."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        assert fs.readlink("/link.txt") == "/target.txt"

    def test_readlink_on_regular_file_raises(self) -> None:
        """readlink() on a non-symlink should raise OSError."""
        fs = FileSystem()
        fs.create_file("/regular.txt")
        with pytest.raises(OSError, match="Not a symlink"):
            fs.readlink("/regular.txt")

    def test_readlink_on_directory_raises(self) -> None:
        """readlink() on a directory should raise OSError."""
        fs = FileSystem()
        with pytest.raises(OSError, match="Not a symlink"):
            fs.readlink("/")

    def test_readlink_nonexistent_raises(self) -> None:
        """readlink() on a missing path should raise FileNotFoundError."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError, match="not found"):
            fs.readlink("/missing")


# ---------------------------------------------------------------------------
# Cycle 4 — Symlink resolution, lstat, delete symlinks
# ---------------------------------------------------------------------------


class TestSymlinkResolution:
    """Verify _resolve() follows symlinks transparently."""

    def test_stat_follows_symlink(self) -> None:
        """stat() should follow the symlink and return the target's info."""
        fs = FileSystem()
        fs.create_file("/real.txt")
        fs.symlink("/real.txt", "/link.txt")

        info = fs.stat("/link.txt")
        assert info.file_type is FileType.FILE
        assert info.inode_number == fs.stat("/real.txt").inode_number

    def test_read_through_symlink(self) -> None:
        """read() should follow the symlink to read the target file."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.write("/data.txt", b"content")
        fs.symlink("/data.txt", "/shortcut.txt")

        assert fs.read("/shortcut.txt") == b"content"

    def test_write_through_symlink(self) -> None:
        """write() should follow the symlink and modify the target."""
        fs = FileSystem()
        fs.create_file("/data.txt")
        fs.symlink("/data.txt", "/shortcut.txt")
        fs.write("/shortcut.txt", b"updated")

        assert fs.read("/data.txt") == b"updated"

    def test_symlink_chain(self) -> None:
        """Resolution should follow chains: A → B → C."""
        fs = FileSystem()
        fs.create_file("/c.txt")
        fs.write("/c.txt", b"chain")
        fs.symlink("/c.txt", "/b.txt")
        fs.symlink("/b.txt", "/a.txt")

        assert fs.read("/a.txt") == b"chain"

    def test_symlink_to_directory(self) -> None:
        """A symlink pointing to a directory should be traversable."""
        fs = FileSystem()
        fs.create_dir("/real_dir")
        fs.create_file("/real_dir/file.txt")
        fs.write("/real_dir/file.txt", b"inside")
        fs.symlink("/real_dir", "/dir_link")

        assert fs.read("/dir_link/file.txt") == b"inside"

    def test_list_dir_through_symlink(self) -> None:
        """list_dir() through a symlink to a directory should work."""
        fs = FileSystem()
        fs.create_dir("/actual")
        fs.create_file("/actual/a.txt")
        fs.symlink("/actual", "/alias")

        assert fs.list_dir("/alias") == ["a.txt"]

    def test_dangling_symlink_stat_raises(self) -> None:
        """stat() on a dangling symlink should raise FileNotFoundError."""
        fs = FileSystem()
        fs.symlink("/nonexistent", "/dangling")

        with pytest.raises(FileNotFoundError, match="not found"):
            fs.stat("/dangling")

    def test_dangling_symlink_read_raises(self) -> None:
        """read() on a dangling symlink should raise FileNotFoundError."""
        fs = FileSystem()
        fs.symlink("/nonexistent", "/dangling")

        with pytest.raises(FileNotFoundError, match="not found"):
            fs.read("/dangling")

    def test_symlink_loop_raises(self) -> None:
        """Circular symlinks should raise OSError (loop detected)."""
        fs = FileSystem()
        fs.symlink("/b", "/a")
        fs.symlink("/a", "/b")

        with pytest.raises(OSError, match="Too many levels of symbolic links"):
            fs.stat("/a")

    def test_self_referencing_symlink_raises(self) -> None:
        """A symlink pointing to itself should trigger loop detection."""
        fs = FileSystem()
        fs.symlink("/self", "/self")

        with pytest.raises(OSError, match="Too many levels of symbolic links"):
            fs.stat("/self")

    def test_relative_symlink(self) -> None:
        """A relative symlink target resolves from the symlink's parent."""
        fs = FileSystem()
        fs.create_dir("/dir")
        fs.create_file("/dir/real.txt")
        fs.write("/dir/real.txt", b"relative")
        fs.symlink("real.txt", "/dir/link.txt")

        assert fs.read("/dir/link.txt") == b"relative"

    def test_intermediate_symlink_in_path(self) -> None:
        """Symlinks in intermediate path components should be followed."""
        fs = FileSystem()
        fs.create_dir("/real")
        fs.create_file("/real/file.txt")
        fs.write("/real/file.txt", b"deep")
        fs.symlink("/real", "/sym")

        assert fs.read("/sym/file.txt") == b"deep"

    def test_absolute_symlink_restarts_from_root(self) -> None:
        """An absolute symlink target restarts resolution from root."""
        fs = FileSystem()
        fs.create_dir("/a")
        fs.create_dir("/b")
        fs.create_file("/b/file.txt")
        fs.write("/b/file.txt", b"abs")
        # Symlink in /a points to absolute path /b
        fs.symlink("/b", "/a/link")

        assert fs.read("/a/link/file.txt") == b"abs"


class TestLstat:
    """Verify lstat() returns symlink metadata without following."""

    def test_lstat_returns_symlink_type(self) -> None:
        """lstat() on a symlink should report file_type=SYMLINK."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        info = fs.lstat("/link.txt")
        assert info.file_type is FileType.SYMLINK

    def test_lstat_size_is_target_path_length(self) -> None:
        """lstat() size should be the length of the stored target path."""
        fs = FileSystem()
        fs.symlink("/some/path", "/link")

        info = fs.lstat("/link")
        expected_size = len("/some/path")
        assert info.size == expected_size

    def test_lstat_on_regular_file_works(self) -> None:
        """lstat() on a regular file should work the same as stat()."""
        fs = FileSystem()
        fs.create_file("/file.txt")
        fs.write("/file.txt", b"data")

        info = fs.lstat("/file.txt")
        assert info.file_type is FileType.FILE
        expected_size = 4
        assert info.size == expected_size

    def test_lstat_nonexistent_raises(self) -> None:
        """lstat() on a missing path should raise FileNotFoundError."""
        fs = FileSystem()
        with pytest.raises(FileNotFoundError, match="not found"):
            fs.lstat("/missing")

    def test_stat_vs_lstat_on_symlink(self) -> None:
        """stat() follows the symlink; lstat() does not."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.write("/target.txt", b"hello")
        fs.symlink("/target.txt", "/link.txt")

        stat_info = fs.stat("/link.txt")
        lstat_info = fs.lstat("/link.txt")

        assert stat_info.file_type is FileType.FILE
        assert lstat_info.file_type is FileType.SYMLINK
        assert stat_info.inode_number != lstat_info.inode_number


class TestDeleteSymlinks:
    """Verify delete() removes the symlink, not the target."""

    def test_delete_symlink_removes_link(self) -> None:
        """Deleting a symlink should remove the link name."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        fs.delete("/link.txt")

        assert not fs.exists("/link.txt")
        assert fs.exists("/target.txt")

    def test_delete_symlink_preserves_target(self) -> None:
        """Deleting a symlink must not affect the target's data."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.write("/target.txt", b"safe")
        fs.symlink("/target.txt", "/link.txt")

        fs.delete("/link.txt")

        assert fs.read("/target.txt") == b"safe"

    def test_delete_target_leaves_dangling_symlink(self) -> None:
        """Deleting the target should leave the symlink dangling."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        fs.delete("/target.txt")

        # The symlink itself still exists
        lstat_info = fs.lstat("/link.txt")
        assert lstat_info.file_type is FileType.SYMLINK

        # But following it fails
        with pytest.raises(FileNotFoundError):
            fs.stat("/link.txt")

    def test_delete_dangling_symlink(self) -> None:
        """Deleting a dangling symlink should succeed."""
        fs = FileSystem()
        fs.symlink("/nonexistent", "/dangling")

        fs.delete("/dangling")

        assert not fs.exists("/dangling")


# ---------------------------------------------------------------------------
# Cycle 5 — Serialization
# ---------------------------------------------------------------------------


class TestLinkSerialization:
    """Verify to_dict/from_dict round-trips with link_count and symlinks."""

    def test_round_trip_preserves_link_count(self) -> None:
        """Serializing and deserializing should preserve link_count."""
        fs = FileSystem()
        fs.create_file("/a.txt")
        fs.link("/a.txt", "/b.txt")

        restored = FileSystem.from_dict(fs.to_dict())

        expected_count = 2
        assert restored.stat("/a.txt").link_count == expected_count
        assert restored.stat("/b.txt").link_count == expected_count

    def test_round_trip_preserves_symlinks(self) -> None:
        """Serializing and deserializing should preserve symlinks."""
        fs = FileSystem()
        fs.create_file("/target.txt")
        fs.symlink("/target.txt", "/link.txt")

        restored = FileSystem.from_dict(fs.to_dict())

        assert restored.lstat("/link.txt").file_type is FileType.SYMLINK
        assert restored.readlink("/link.txt") == "/target.txt"

    def test_backward_compat_missing_link_count(self) -> None:
        """from_dict should default link_count=1 for old data."""
        fs = FileSystem()
        fs.create_file("/old.txt")
        data = fs.to_dict()

        # Remove link_count from the serialized data to simulate old format
        for ino_data in data["inodes"].values():
            ino_data.pop("link_count", None)

        restored = FileSystem.from_dict(data)
        assert restored.stat("/old.txt").link_count == 1

    def test_round_trip_hard_link_data_shared(self) -> None:
        """After round-trip, two hard links should still share the same inode."""
        fs = FileSystem()
        fs.create_file("/x.txt")
        fs.write("/x.txt", b"shared")
        fs.link("/x.txt", "/y.txt")

        restored = FileSystem.from_dict(fs.to_dict())

        assert restored.read("/x.txt") == b"shared"
        assert restored.read("/y.txt") == b"shared"
        assert restored.stat("/x.txt").inode_number == restored.stat("/y.txt").inode_number


# ---------------------------------------------------------------------------
# Cycle 6 — Kernel integration
# ---------------------------------------------------------------------------


def _booted_kernel() -> Kernel:
    """Return a booted kernel ready for testing."""
    k = Kernel()
    k.boot()
    return k


class TestKernelHardLink:
    """Verify kernel wrapper methods for hard links."""

    def test_link_file_creates_hard_link(self) -> None:
        """Kernel.link_file() should delegate to filesystem.link()."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/a.txt")
        k.filesystem.write("/a.txt", b"data")

        k.link_file("/a.txt", "/b.txt")

        assert k.filesystem.read("/b.txt") == b"data"
        expected_count = 2
        assert k.filesystem.stat("/a.txt").link_count == expected_count

    def test_link_file_not_running_raises(self) -> None:
        """link_file() should raise RuntimeError if kernel not running."""
        k = Kernel()
        with pytest.raises(RuntimeError, match="not running"):
            k.link_file("/a", "/b")

    def test_link_file_missing_target_raises(self) -> None:
        """link_file() should propagate FileNotFoundError."""
        k = _booted_kernel()
        with pytest.raises(FileNotFoundError):
            k.link_file("/missing", "/link")


class TestKernelSymlink:
    """Verify kernel wrapper methods for symbolic links."""

    def test_symlink_file_creates_symlink(self) -> None:
        """Kernel.symlink_file() should create a symlink."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/target.txt")
        k.filesystem.write("/target.txt", b"content")

        k.symlink_file("/target.txt", "/link.txt")

        assert k.filesystem.read("/link.txt") == b"content"
        assert k.filesystem.lstat("/link.txt").file_type is FileType.SYMLINK

    def test_readlink_file_returns_target(self) -> None:
        """Kernel.readlink_file() should return the symlink target."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/target.txt")

        k.symlink_file("/target.txt", "/link.txt")

        assert k.readlink_file("/link.txt") == "/target.txt"

    def test_open_file_through_symlink(self) -> None:
        """open_file() should follow symlinks transparently."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/real.txt")
        k.filesystem.write("/real.txt", b"hello")
        k.symlink_file("/real.txt", "/shortcut.txt")

        proc = k.create_process(name="test", num_pages=1)
        fd = k.open_file(proc.pid, "/shortcut.txt", FileMode.READ)
        data = k.read_fd(proc.pid, fd, count=100)

        assert data == b"hello"

    def test_open_file_through_hard_link(self) -> None:
        """open_file() should work through hard links."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/original.txt")
        k.filesystem.write("/original.txt", b"linked")
        k.link_file("/original.txt", "/alias.txt")

        proc = k.create_process(name="test", num_pages=1)
        fd = k.open_file(proc.pid, "/alias.txt", FileMode.READ)
        data = k.read_fd(proc.pid, fd, count=100)

        assert data == b"linked"


# ---------------------------------------------------------------------------
# Cycle 7 — Syscall integration
# ---------------------------------------------------------------------------


class TestLinkSyscalls:
    """Verify SYS_LINK, SYS_SYMLINK, SYS_READLINK dispatch correctly."""

    def test_sys_link_creates_hard_link(self) -> None:
        """SYS_LINK should create a hard link via the kernel."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/a.txt")
        k.filesystem.write("/a.txt", b"sys")

        k.syscall(SyscallNumber.SYS_LINK, target="/a.txt", link_path="/b.txt")

        assert k.filesystem.read("/b.txt") == b"sys"

    def test_sys_link_missing_target_raises_syscall_error(self) -> None:
        """SYS_LINK with a missing target should raise SyscallError."""
        k = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            k.syscall(SyscallNumber.SYS_LINK, target="/missing", link_path="/link")

    def test_sys_link_directory_raises_syscall_error(self) -> None:
        """SYS_LINK on a directory should raise SyscallError."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_dir("/dir")
        with pytest.raises(SyscallError, match="Cannot hard-link"):
            k.syscall(SyscallNumber.SYS_LINK, target="/dir", link_path="/alias")

    def test_sys_symlink_creates_symlink(self) -> None:
        """SYS_SYMLINK should create a symbolic link."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/target.txt")

        k.syscall(SyscallNumber.SYS_SYMLINK, target="/target.txt", link_path="/link.txt")

        assert k.filesystem.lstat("/link.txt").file_type is FileType.SYMLINK

    def test_sys_symlink_existing_raises_syscall_error(self) -> None:
        """SYS_SYMLINK with an existing link_path should raise SyscallError."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/exists.txt")
        with pytest.raises(SyscallError, match="Already exists"):
            k.syscall(SyscallNumber.SYS_SYMLINK, target="/target", link_path="/exists.txt")

    def test_sys_readlink_returns_target(self) -> None:
        """SYS_READLINK should return the symlink target path."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/target.txt")
        k.filesystem.symlink("/target.txt", "/link.txt")

        result: str = k.syscall(SyscallNumber.SYS_READLINK, path="/link.txt")
        assert result == "/target.txt"

    def test_sys_readlink_on_regular_file_raises(self) -> None:
        """SYS_READLINK on a non-symlink should raise SyscallError."""
        k = _booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/regular.txt")
        with pytest.raises(SyscallError, match="Not a symlink"):
            k.syscall(SyscallNumber.SYS_READLINK, path="/regular.txt")

    def test_sys_readlink_missing_raises(self) -> None:
        """SYS_READLINK on a missing path should raise SyscallError."""
        k = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            k.syscall(SyscallNumber.SYS_READLINK, path="/missing")

    def test_sys_link_number_is_34(self) -> None:
        """SYS_LINK should have value 34."""
        expected_value = 34
        assert expected_value == SyscallNumber.SYS_LINK

    def test_sys_symlink_number_is_35(self) -> None:
        """SYS_SYMLINK should have value 35."""
        expected_value = 35
        assert expected_value == SyscallNumber.SYS_SYMLINK

    def test_sys_readlink_number_is_36(self) -> None:
        """SYS_READLINK should have value 36."""
        expected_value = 36
        assert expected_value == SyscallNumber.SYS_READLINK


# ---------------------------------------------------------------------------
# Cycle 8 — Shell commands
# ---------------------------------------------------------------------------


def _booted_shell() -> Shell:
    """Return a shell attached to a booted kernel."""
    k = Kernel()
    k.boot()
    return Shell(kernel=k)


class TestShellLn:
    """Verify the ``ln`` shell command."""

    def test_ln_creates_hard_link(self) -> None:
        """``ln /a /b`` should create a hard link."""
        sh = _booted_shell()
        sh.execute("touch /file.txt")
        sh.execute("write /file.txt hello")

        result = sh.execute("ln /file.txt /alias.txt")

        assert result == ""
        assert sh.execute("cat /alias.txt") == "hello"

    def test_ln_s_creates_symlink(self) -> None:
        """``ln -s /target /link`` should create a symbolic link."""
        sh = _booted_shell()
        sh.execute("touch /target.txt")
        sh.execute("write /target.txt content")

        result = sh.execute("ln -s /target.txt /link.txt")

        assert result == ""
        assert sh.execute("cat /link.txt") == "content"

    def test_ln_no_args_shows_usage(self) -> None:
        """``ln`` with no args should print usage."""
        sh = _booted_shell()
        result = sh.execute("ln")
        assert "Usage:" in result

    def test_ln_missing_target_shows_error(self) -> None:
        """``ln /missing /link`` should show an error."""
        sh = _booted_shell()
        result = sh.execute("ln /missing /link")
        assert result.startswith("Error:")

    def test_ln_s_dangling(self) -> None:
        """``ln -s`` to a nonexistent target should succeed (dangling)."""
        sh = _booted_shell()
        result = sh.execute("ln -s /nonexistent /dangle")
        assert result == ""

    def test_ln_s_no_args_shows_usage(self) -> None:
        """``ln -s`` with missing args should show usage."""
        sh = _booted_shell()
        result = sh.execute("ln -s")
        assert "Usage:" in result


class TestShellReadlink:
    """Verify the ``readlink`` shell command."""

    def test_readlink_shows_target(self) -> None:
        """``readlink /link`` should print the stored target path."""
        sh = _booted_shell()
        sh.execute("touch /target.txt")
        sh.execute("ln -s /target.txt /link.txt")

        result = sh.execute("readlink /link.txt")
        assert result == "/target.txt"

    def test_readlink_regular_file_error(self) -> None:
        """``readlink`` on a non-symlink should show an error."""
        sh = _booted_shell()
        sh.execute("touch /regular.txt")

        result = sh.execute("readlink /regular.txt")
        assert result.startswith("Error:")

    def test_readlink_no_args_shows_usage(self) -> None:
        """``readlink`` with no args should print usage."""
        sh = _booted_shell()
        result = sh.execute("readlink")
        assert "Usage:" in result


class TestShellStat:
    """Verify the ``stat`` shell command."""

    def test_stat_regular_file(self) -> None:
        """``stat`` on a file should show metadata."""
        sh = _booted_shell()
        sh.execute("touch /hello.txt")
        sh.execute("write /hello.txt data")

        result = sh.execute("stat /hello.txt")

        assert "File: /hello.txt" in result
        assert "Type: file" in result
        expected_size = "Size: 4"
        assert expected_size in result
        assert "Links: 1" in result

    def test_stat_hard_linked_file(self) -> None:
        """``stat`` should show link count > 1 for hard-linked files."""
        sh = _booted_shell()
        sh.execute("touch /a.txt")
        sh.execute("ln /a.txt /b.txt")

        result = sh.execute("stat /a.txt")
        assert "Links: 2" in result

    def test_stat_symlink_shows_arrow(self) -> None:
        """``stat`` on a symlink should show ``-> target`` and type symlink."""
        sh = _booted_shell()
        sh.execute("touch /target.txt")
        sh.execute("ln -s /target.txt /link.txt")

        result = sh.execute("stat /link.txt")

        assert "File: /link.txt -> /target.txt" in result
        assert "Type: symlink" in result

    def test_stat_missing_shows_error(self) -> None:
        """``stat`` on a missing path should show an error."""
        sh = _booted_shell()
        result = sh.execute("stat /missing")
        assert result.startswith("Error:")

    def test_stat_no_args_shows_usage(self) -> None:
        """``stat`` with no args should print usage."""
        sh = _booted_shell()
        result = sh.execute("stat")
        assert "Usage:" in result
