"""Tests for the users and permissions module.

Users provide identity — every process and file is owned by a user.
Permissions control what operations a user can perform on a resource.
Together they form the access control foundation of the OS.
"""

import pytest

from py_os.users import FilePermissions, User, UserManager
from py_os.users import PermissionError as OsPermissionError

ROOT_UID = 0


class TestUserCreation:
    """Verify user initialisation."""

    def test_user_has_uid(self) -> None:
        """A user should have a numeric uid."""
        user = User(uid=1, username="alice")
        assert user.uid == 1

    def test_user_has_username(self) -> None:
        """A user should have a string username."""
        user = User(uid=1, username="alice")
        assert user.username == "alice"

    def test_user_repr(self) -> None:
        """Repr should include uid and username."""
        user = User(uid=1, username="alice")
        assert "alice" in repr(user)
        assert "1" in repr(user)

    def test_users_with_same_uid_are_equal(self) -> None:
        """Two users with the same uid should be equal."""
        u1 = User(uid=1, username="alice")
        u2 = User(uid=1, username="alice")
        assert u1 == u2

    def test_users_with_different_uid_are_not_equal(self) -> None:
        """Users with different uids should not be equal."""
        u1 = User(uid=1, username="alice")
        u2 = User(uid=2, username="bob")
        assert u1 != u2


class TestUserManager:
    """Verify user management."""

    def test_root_user_exists_by_default(self) -> None:
        """The root user (uid=0) should always exist."""
        mgr = UserManager()
        root = mgr.get_user(ROOT_UID)
        assert root is not None
        assert root.username == "root"

    def test_create_user(self) -> None:
        """Creating a user should make it retrievable."""
        mgr = UserManager()
        user = mgr.create_user("alice")
        assert user.username == "alice"
        assert mgr.get_user(user.uid) is user

    def test_create_duplicate_username_raises(self) -> None:
        """Creating a user with an existing username should raise."""
        mgr = UserManager()
        mgr.create_user("alice")
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_user("alice")

    def test_get_nonexistent_user_returns_none(self) -> None:
        """Getting a non-existent uid should return None."""
        mgr = UserManager()
        assert mgr.get_user(999) is None

    def test_get_user_by_name(self) -> None:
        """Users should be retrievable by username."""
        mgr = UserManager()
        alice = mgr.create_user("alice")
        assert mgr.get_user_by_name("alice") is alice

    def test_get_user_by_name_nonexistent(self) -> None:
        """Getting a non-existent username should return None."""
        mgr = UserManager()
        assert mgr.get_user_by_name("nobody") is None

    def test_list_users(self) -> None:
        """All users should be listable."""
        mgr = UserManager()
        mgr.create_user("alice")
        mgr.create_user("bob")
        users = mgr.list_users()
        names = [u.username for u in users]
        assert "root" in names
        assert "alice" in names
        assert "bob" in names

    def test_uids_are_unique(self) -> None:
        """Each new user should get a unique uid."""
        mgr = UserManager()
        alice = mgr.create_user("alice")
        bob = mgr.create_user("bob")
        assert alice.uid != bob.uid
        assert alice.uid != ROOT_UID
        assert bob.uid != ROOT_UID


class TestFilePermissions:
    """Verify file permission checks."""

    def test_default_permissions(self) -> None:
        """Default permissions should allow owner read/write."""
        perms = FilePermissions(owner_uid=1)
        assert perms.owner_uid == 1
        assert perms.owner_read is True
        assert perms.owner_write is True
        assert perms.other_read is True
        assert perms.other_write is False

    def test_owner_can_read(self) -> None:
        """The owner should be able to read their file."""
        perms = FilePermissions(owner_uid=1)
        perms.check_read(uid=1)  # should not raise

    def test_owner_can_write(self) -> None:
        """The owner should be able to write their file."""
        perms = FilePermissions(owner_uid=1)
        perms.check_write(uid=1)  # should not raise

    def test_other_can_read_by_default(self) -> None:
        """Non-owners should be able to read by default."""
        perms = FilePermissions(owner_uid=1)
        perms.check_read(uid=2)  # should not raise

    def test_other_cannot_write_by_default(self) -> None:
        """Non-owners should not be able to write by default."""
        perms = FilePermissions(owner_uid=1)
        with pytest.raises(OsPermissionError, match="denied"):
            perms.check_write(uid=2)

    def test_restricted_file_denies_other_read(self) -> None:
        """A file with other_read=False should deny non-owner reads."""
        perms = FilePermissions(owner_uid=1, other_read=False)
        with pytest.raises(OsPermissionError, match="denied"):
            perms.check_read(uid=2)

    def test_root_bypasses_permissions(self) -> None:
        """Root (uid=0) should bypass all permission checks."""
        perms = FilePermissions(owner_uid=1, other_read=False, other_write=False)
        perms.check_read(uid=ROOT_UID)  # should not raise
        perms.check_write(uid=ROOT_UID)  # should not raise
