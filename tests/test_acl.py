"""Tests for ACL permissions — groups, execute bits, and access control lists."""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber
from py_os.users import (
    AclEntry,
    AclEntryType,
    FilePermissions,
    Group,
    PermissionError,
    UserManager,
)

_TARGET_ID = 5
_TARGET_GID = 10
_CHOWN_UID = 5
_CHOWN_GID = 3
_TWO_GROUPS = 2


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create booted kernel + shell for testing."""
    kernel = _booted_kernel()
    return kernel, Shell(kernel=kernel)


# -- Group dataclass tests ---------------------------------------------------


class TestGroup:
    """Verify the Group frozen dataclass."""

    def test_creation(self) -> None:
        """Create a group with gid, name, and members."""
        group = Group(gid=1, name="devs", members=frozenset({1, 2}))
        assert group.gid == 1
        assert group.name == "devs"
        assert group.members == frozenset({1, 2})

    def test_frozen(self) -> None:
        """Group instances are immutable."""
        group = Group(gid=1, name="devs")
        with pytest.raises(AttributeError):
            group.name = "ops"  # type: ignore[misc]

    def test_default_members_empty(self) -> None:
        """Members default to an empty frozenset."""
        group = Group(gid=1, name="devs")
        assert group.members == frozenset()


# -- AclEntry tests -----------------------------------------------------------


class TestAclEntry:
    """Verify the AclEntry frozen dataclass."""

    def test_creation(self) -> None:
        """Create an ACL entry with all fields."""
        entry = AclEntry(
            entry_type=AclEntryType.USER,
            target_id=_TARGET_ID,
            read=True,
            write=True,
            execute=False,
        )
        assert entry.entry_type is AclEntryType.USER
        assert entry.target_id == _TARGET_ID
        assert entry.read is True
        assert entry.write is True
        assert entry.execute is False

    def test_defaults_are_false(self) -> None:
        """Permissions default to False."""
        entry = AclEntry(entry_type=AclEntryType.GROUP, target_id=1)
        assert entry.read is False
        assert entry.write is False
        assert entry.execute is False

    def test_frozen(self) -> None:
        """AclEntry instances are immutable."""
        entry = AclEntry(entry_type=AclEntryType.USER, target_id=1)
        with pytest.raises(AttributeError):
            entry.read = True  # type: ignore[misc]


# -- UserManager group methods ------------------------------------------------


class TestUserManagerGroups:
    """Verify group management on UserManager."""

    def test_create_group(self) -> None:
        """Create a group and verify its fields."""
        um = UserManager()
        group = um.create_group("devs")
        assert group.name == "devs"
        assert group.gid >= 1

    def test_create_duplicate_group_raises(self) -> None:
        """Duplicate group name raises ValueError."""
        um = UserManager()
        um.create_group("devs")
        with pytest.raises(ValueError, match="already exists"):
            um.create_group("devs")

    def test_get_group(self) -> None:
        """Look up a group by gid."""
        um = UserManager()
        group = um.create_group("devs")
        assert um.get_group(group.gid) == group

    def test_get_group_by_name(self) -> None:
        """Look up a group by name."""
        um = UserManager()
        group = um.create_group("devs")
        assert um.get_group_by_name("devs") == group

    def test_get_nonexistent_group(self) -> None:
        """Look up a nonexistent group returns None."""
        um = UserManager()
        assert um.get_group(999) is None
        assert um.get_group_by_name("nope") is None

    def test_add_to_group(self) -> None:
        """Add a user to a group."""
        um = UserManager()
        alice = um.create_user("alice")
        group = um.create_group("devs")
        updated = um.add_to_group(alice.uid, group.gid)
        assert alice.uid in updated.members

    def test_remove_from_group(self) -> None:
        """Remove a user from a group."""
        um = UserManager()
        alice = um.create_user("alice")
        group = um.create_group("devs")
        um.add_to_group(alice.uid, group.gid)
        updated = um.remove_from_group(alice.uid, group.gid)
        assert alice.uid not in updated.members

    def test_add_nonexistent_user_raises(self) -> None:
        """Add a nonexistent user raises ValueError."""
        um = UserManager()
        group = um.create_group("devs")
        with pytest.raises(ValueError, match="not found"):
            um.add_to_group(999, group.gid)

    def test_add_to_nonexistent_group_raises(self) -> None:
        """Add to a nonexistent group raises ValueError."""
        um = UserManager()
        with pytest.raises(ValueError, match="not found"):
            um.add_to_group(0, 999)

    def test_list_groups(self) -> None:
        """List all groups."""
        um = UserManager()
        um.create_group("devs")
        um.create_group("ops")
        groups = um.list_groups()
        names = [g.name for g in groups]
        assert "devs" in names
        assert "ops" in names

    def test_user_groups(self) -> None:
        """Return all groups a user belongs to."""
        um = UserManager()
        alice = um.create_user("alice")
        g1 = um.create_group("devs")
        g2 = um.create_group("ops")
        um.add_to_group(alice.uid, g1.gid)
        um.add_to_group(alice.uid, g2.gid)
        groups = um.user_groups(alice.uid)
        assert len(groups) == _TWO_GROUPS

    def test_user_group_ids(self) -> None:
        """Return group IDs for a user."""
        um = UserManager()
        alice = um.create_user("alice")
        g1 = um.create_group("devs")
        um.add_to_group(alice.uid, g1.gid)
        gids = um.user_group_ids(alice.uid)
        assert g1.gid in gids


# -- FilePermissions execute bit tests ----------------------------------------


class TestFilePermissionsExecute:
    """Verify execute permission checks."""

    def test_owner_execute_allowed(self) -> None:
        """Owner can execute when owner_execute is True."""
        perms = FilePermissions(owner_uid=1, owner_execute=True)
        perms.check_execute(uid=1)  # should not raise

    def test_owner_execute_denied(self) -> None:
        """Owner cannot execute when owner_execute is False."""
        perms = FilePermissions(owner_uid=1, owner_execute=False)
        with pytest.raises(PermissionError, match="Execute permission denied"):
            perms.check_execute(uid=1)

    def test_other_execute_allowed(self) -> None:
        """Other users can execute when other_execute is True."""
        perms = FilePermissions(owner_uid=1, other_execute=True)
        perms.check_execute(uid=2)  # should not raise

    def test_other_execute_denied(self) -> None:
        """Other users cannot execute when other_execute is False."""
        perms = FilePermissions(owner_uid=1)
        with pytest.raises(PermissionError, match="Execute permission denied"):
            perms.check_execute(uid=2)

    def test_root_bypasses_execute(self) -> None:
        """Root can always execute."""
        perms = FilePermissions(owner_uid=1)
        perms.check_execute(uid=0)  # should not raise


# -- FilePermissions group tests -----------------------------------------------


class TestFilePermissionsGroups:
    """Verify group-based permission checks."""

    def test_group_read_allowed(self) -> None:
        """Group member can read when group_read is True."""
        gid = 1
        perms = FilePermissions(owner_uid=1, group_gid=gid, group_read=True)
        perms.check_read(uid=2, groups=frozenset({gid}))  # should not raise

    def test_group_read_denied(self) -> None:
        """Group member denied read when group_read is False."""
        gid = 1
        perms = FilePermissions(owner_uid=1, group_gid=gid, group_read=False, other_read=False)
        with pytest.raises(PermissionError, match="Read permission denied"):
            perms.check_read(uid=2, groups=frozenset({gid}))

    def test_group_write_allowed(self) -> None:
        """Group member can write when group_write is True."""
        gid = 1
        perms = FilePermissions(owner_uid=1, group_gid=gid, group_write=True)
        perms.check_write(uid=2, groups=frozenset({gid}))  # should not raise

    def test_group_execute_allowed(self) -> None:
        """Group member can execute when group_execute is True."""
        gid = 1
        perms = FilePermissions(owner_uid=1, group_gid=gid, group_execute=True)
        perms.check_execute(uid=2, groups=frozenset({gid}))  # should not raise


# -- FilePermissions ACL tests -------------------------------------------------


class TestFilePermissionsAcl:
    """Verify ACL priority and overrides."""

    def test_user_acl_grants_read(self) -> None:
        """User ACL entry grants read to a specific user."""
        acl = AclEntry(entry_type=AclEntryType.USER, target_id=_TARGET_ID, read=True)
        perms = FilePermissions(owner_uid=1, other_read=False, acl_entries=(acl,))
        perms.check_read(uid=_TARGET_ID)  # should not raise

    def test_user_acl_denies_read(self) -> None:
        """User ACL entry denies read even when other_read is True."""
        acl = AclEntry(entry_type=AclEntryType.USER, target_id=_TARGET_ID, read=False)
        perms = FilePermissions(owner_uid=1, other_read=True, acl_entries=(acl,))
        with pytest.raises(PermissionError, match="ACL"):
            perms.check_read(uid=_TARGET_ID)

    def test_group_acl_grants_write(self) -> None:
        """Group ACL grants write to group members."""
        acl = AclEntry(entry_type=AclEntryType.GROUP, target_id=_TARGET_GID, write=True)
        perms = FilePermissions(owner_uid=1, other_write=False, acl_entries=(acl,))
        perms.check_write(uid=_TARGET_ID, groups=frozenset({_TARGET_GID}))

    def test_group_acl_denies_write(self) -> None:
        """Group ACL denies write to group members."""
        acl = AclEntry(entry_type=AclEntryType.GROUP, target_id=_TARGET_GID, write=False)
        perms = FilePermissions(owner_uid=1, other_write=True, acl_entries=(acl,))
        with pytest.raises(PermissionError, match="group ACL"):
            perms.check_write(uid=_TARGET_ID, groups=frozenset({_TARGET_GID}))

    def test_user_acl_overrides_group_acl(self) -> None:
        """User ACL takes priority over group ACL."""
        user_acl = AclEntry(entry_type=AclEntryType.USER, target_id=_TARGET_ID, read=True)
        group_acl = AclEntry(entry_type=AclEntryType.GROUP, target_id=_TARGET_GID, read=False)
        perms = FilePermissions(owner_uid=1, other_read=False, acl_entries=(user_acl, group_acl))
        # User 5 is in group 10 but user ACL takes priority
        perms.check_read(uid=_TARGET_ID, groups=frozenset({_TARGET_GID}))

    def test_acl_execute_grant(self) -> None:
        """ACL entry can grant execute permission."""
        acl = AclEntry(entry_type=AclEntryType.USER, target_id=_TARGET_ID, execute=True)
        perms = FilePermissions(owner_uid=1, other_execute=False, acl_entries=(acl,))
        perms.check_execute(uid=_TARGET_ID)  # should not raise

    def test_no_acl_falls_through_to_owner(self) -> None:
        """Without ACL, owner permissions apply."""
        perms = FilePermissions(owner_uid=_TARGET_ID, owner_read=True, other_read=False)
        perms.check_read(uid=_TARGET_ID)  # should not raise

    def test_no_acl_falls_through_to_other(self) -> None:
        """Without ACL, other permissions apply for non-owners."""
        perms = FilePermissions(owner_uid=1, other_read=True)
        perms.check_read(uid=99)  # should not raise


# -- Syscall group operations --------------------------------------------------


class TestSyscallGroupOps:
    """Verify group-related syscalls."""

    def test_create_group(self) -> None:
        """Create a group via syscall."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")
        assert result["name"] == "devs"
        assert result["gid"] >= 1

    def test_create_duplicate_group_raises(self) -> None:
        """Duplicate group creation raises SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")
        with pytest.raises(SyscallError, match="already exists"):
            kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")

    def test_list_groups(self) -> None:
        """List groups via syscall."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")
        result = kernel.syscall(SyscallNumber.SYS_LIST_GROUPS)
        assert len(result) == 1
        assert result[0]["name"] == "devs"

    def test_add_to_group(self) -> None:
        """Add user to group via syscall."""
        kernel = _booted_kernel()
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        group = kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")
        result = kernel.syscall(SyscallNumber.SYS_ADD_TO_GROUP, uid=user["uid"], gid=group["gid"])
        assert user["uid"] in result["members"]

    def test_remove_from_group(self) -> None:
        """Remove user from group via syscall."""
        kernel = _booted_kernel()
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        group = kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")
        kernel.syscall(SyscallNumber.SYS_ADD_TO_GROUP, uid=user["uid"], gid=group["gid"])
        result = kernel.syscall(
            SyscallNumber.SYS_REMOVE_FROM_GROUP, uid=user["uid"], gid=group["gid"]
        )
        assert user["uid"] not in result["members"]

    def test_user_groups(self) -> None:
        """List user's groups via syscall."""
        kernel = _booted_kernel()
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        group = kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="devs")
        kernel.syscall(SyscallNumber.SYS_ADD_TO_GROUP, uid=user["uid"], gid=group["gid"])
        result = kernel.syscall(SyscallNumber.SYS_USER_GROUPS, uid=user["uid"])
        assert len(result) == 1
        assert result[0]["name"] == "devs"


# -- Syscall ACL operations ---------------------------------------------------


class TestSyscallAclOps:
    """Verify chmod, chown, get_acl, set_acl syscalls."""

    def test_chmod(self) -> None:
        """Set permissions via chmod syscall."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/test.txt")
        kernel.syscall(SyscallNumber.SYS_CHMOD, path="/test.txt", mode="rwxr-xr--")
        result = kernel.syscall(SyscallNumber.SYS_GET_ACL, path="/test.txt")
        assert result["mode"] == "rwxr-xr--"

    def test_chmod_invalid_length_raises(self) -> None:
        """Invalid mode length raises SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/test.txt")
        with pytest.raises(SyscallError, match="9 characters"):
            kernel.syscall(SyscallNumber.SYS_CHMOD, path="/test.txt", mode="rwx")

    def test_chown(self) -> None:
        """Change owner and group via chown syscall."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/test.txt")
        kernel.syscall(
            SyscallNumber.SYS_CHOWN,
            path="/test.txt",
            uid=_CHOWN_UID,
            gid=_CHOWN_GID,
        )
        result = kernel.syscall(SyscallNumber.SYS_GET_ACL, path="/test.txt")
        assert result["owner_uid"] == _CHOWN_UID
        assert result["group_gid"] == _CHOWN_GID

    def test_get_acl(self) -> None:
        """Retrieve permissions and ACL via syscall."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/test.txt")
        result = kernel.syscall(SyscallNumber.SYS_GET_ACL, path="/test.txt")
        assert "mode" in result
        assert "acl" in result
        assert "owner_uid" in result

    def test_set_acl(self) -> None:
        """Set ACL entries via syscall."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/test.txt")
        entries = [
            {
                "type": "user",
                "target_id": _TARGET_ID,
                "read": True,
                "write": True,
                "execute": False,
            }
        ]
        kernel.syscall(SyscallNumber.SYS_SET_ACL, path="/test.txt", entries=entries)
        result = kernel.syscall(SyscallNumber.SYS_GET_ACL, path="/test.txt")
        assert len(result["acl"]) == 1
        assert result["acl"][0]["target_id"] == _TARGET_ID

    def test_chmod_nonexistent_raises(self) -> None:
        """Attempt to chmod a nonexistent file raises SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="No permissions"):
            kernel.syscall(SyscallNumber.SYS_CHMOD, path="/nope.txt", mode="rwxrwxrwx")

    def test_read_with_group_permissions(self) -> None:
        """File read respects group permissions."""
        kernel = _booted_kernel()
        alice = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        group = kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name="readers")
        kernel.syscall(SyscallNumber.SYS_ADD_TO_GROUP, uid=alice["uid"], gid=group["gid"])
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/secret.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/secret.txt", data=b"hidden")
        kernel.syscall(SyscallNumber.SYS_CHMOD, path="/secret.txt", mode="rw-r-----")
        kernel.syscall(SyscallNumber.SYS_CHOWN, path="/secret.txt", uid=0, gid=group["gid"])
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=alice["uid"])
        data = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/secret.txt")
        assert data == b"hidden"


# -- Shell command tests -------------------------------------------------------


class TestShellAclCommands:
    """Verify shell commands for ACL management."""

    def test_chmod_sets_permissions(self) -> None:
        """Verify chmod sets permissions on a file."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /test.txt")
        output = shell.execute("chmod /test.txt rwxr-xr--")
        assert "Permissions set" in output

    def test_chown_changes_ownership(self) -> None:
        """Verify chown changes file ownership."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /test.txt")
        output = shell.execute("chown /test.txt 5 3")
        assert "uid=5" in output
        assert "gid=3" in output

    def test_getfacl_displays_permissions(self) -> None:
        """Verify getfacl displays permissions."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /test.txt")
        output = shell.execute("getfacl /test.txt")
        assert "# file: /test.txt" in output
        assert "mode:" in output

    def test_setfacl_adds_acl_entry(self) -> None:
        """Verify setfacl adds an ACL entry."""
        _kernel, shell = _booted_shell()
        shell.execute("touch /test.txt")
        output = shell.execute("setfacl /test.txt user:5:rwx")
        assert "ACL set" in output
        output = shell.execute("getfacl /test.txt")
        assert "user:5:rwx" in output

    def test_groups_no_memberships(self) -> None:
        """Show message when user has no group memberships."""
        _kernel, shell = _booted_shell()
        output = shell.execute("groups")
        assert "No group memberships" in output

    def test_groups_list(self) -> None:
        """List all groups via shell."""
        _kernel, shell = _booted_shell()
        shell.execute("groups add devs")
        output = shell.execute("groups list")
        assert "devs" in output

    def test_groups_add(self) -> None:
        """Create a group via shell."""
        _kernel, shell = _booted_shell()
        output = shell.execute("groups add devs")
        assert "Created group devs" in output

    def test_groups_adduser(self) -> None:
        """Add a user to a group via shell."""
        _kernel, shell = _booted_shell()
        shell.execute("adduser alice")
        shell.execute("groups add devs")
        output = shell.execute("groups adduser 1 1")
        assert "Added uid 1" in output

    def test_groups_removeuser(self) -> None:
        """Remove a user from a group via shell."""
        _kernel, shell = _booted_shell()
        shell.execute("adduser alice")
        shell.execute("groups add devs")
        shell.execute("groups adduser 1 1")
        output = shell.execute("groups removeuser 1 1")
        assert "Removed uid 1" in output

    def test_chmod_usage_message(self) -> None:
        """Show usage when chmod called without args."""
        _kernel, shell = _booted_shell()
        output = shell.execute("chmod")
        assert "Usage:" in output

    def test_chown_usage_message(self) -> None:
        """Show usage when chown called without args."""
        _kernel, shell = _booted_shell()
        output = shell.execute("chown")
        assert "Usage:" in output

    def test_getfacl_usage_message(self) -> None:
        """Show usage when getfacl called without args."""
        _kernel, shell = _booted_shell()
        output = shell.execute("getfacl")
        assert "Usage:" in output

    def test_setfacl_usage_message(self) -> None:
        """Show usage when setfacl called without args."""
        _kernel, shell = _booted_shell()
        output = shell.execute("setfacl")
        assert "Usage:" in output
