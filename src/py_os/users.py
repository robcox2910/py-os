"""Users and permissions — access control for the operating system.

Every real OS has a concept of **identity**: who is making a request?
This module provides three building blocks:

**User** — an identity with a numeric ``uid`` and string ``username``.
    In Unix, every process has a uid, and every file has an owner uid.
    The uid is what the kernel actually checks — usernames are for humans.

**UserManager** — a registry of users with auto-incrementing uids.
    Think of ``/etc/passwd`` on Linux.  The manager always creates a
    root user (uid=0) who has superuser privileges.

**FilePermissions** — owner + permission bits (read/write for owner
    and others).  When a syscall tries to read or write a file, the
    kernel checks these bits against the caller's uid.  Root (uid=0)
    bypasses all checks — just like real Unix.

Why separate owner/other instead of full Unix rwxrwxrwx?
    Simplicity.  The two-tier model (owner vs everyone else) captures
    the essential concept without the complexity of groups and the
    execute bit.  It's easy to extend later.
"""

from dataclasses import dataclass, field
from itertools import count


# We define our own PermissionError to avoid shadowing the built-in.
# In a real OS this would be EACCES / EPERM.
class PermissionError(Exception):
    """Raised when a user lacks permission for an operation."""


ROOT_UID = 0


@dataclass(frozen=True)
class User:
    """An identity in the system.

    Frozen dataclass gives us immutability, ``__eq__`` based on all
    fields, and ``__hash__`` for free — users can be dict keys or
    set members.
    """

    uid: int
    username: str

    def __repr__(self) -> str:
        """Return a readable representation."""
        return f"User(uid={self.uid}, username={self.username!r})"


class UserManager:
    """Registry of users — the OS's ``/etc/passwd``.

    Auto-creates root (uid=0) on initialisation.  New users get
    sequential uids starting from 1.
    """

    def __init__(self) -> None:
        """Create a manager with only the root user."""
        self._uid_counter = count(start=1)
        self._users: dict[int, User] = {}
        self._names: dict[str, int] = {}

        # Root always exists.
        root = User(uid=ROOT_UID, username="root")
        self._users[ROOT_UID] = root
        self._names["root"] = ROOT_UID

    def create_user(self, username: str) -> User:
        """Create a new user with the given username.

        Args:
            username: The human-readable name.

        Returns:
            The newly created user.

        Raises:
            ValueError: If the username already exists.

        """
        if username in self._names:
            msg = f"User '{username}' already exists"
            raise ValueError(msg)

        uid = next(self._uid_counter)
        user = User(uid=uid, username=username)
        self._users[uid] = user
        self._names[username] = uid
        return user

    def get_user(self, uid: int) -> User | None:
        """Look up a user by uid.

        Returns:
            The user, or None if not found.

        """
        return self._users.get(uid)

    def get_user_by_name(self, username: str) -> User | None:
        """Look up a user by username.

        Returns:
            The user, or None if not found.

        """
        uid = self._names.get(username)
        if uid is None:
            return None
        return self._users.get(uid)

    def list_users(self) -> list[User]:
        """Return all registered users."""
        return list(self._users.values())


@dataclass
class FilePermissions:
    """Permission bits for a file or directory.

    Models a simplified Unix permission scheme: owner vs others,
    with separate read and write flags.  Root (uid=0) bypasses
    all checks.

    Defaults mirror common Unix behaviour:
    - Owner can read and write (rw-).
    - Others can read but not write (r--).
    """

    owner_uid: int
    owner_read: bool = field(default=True)
    owner_write: bool = field(default=True)
    other_read: bool = field(default=True)
    other_write: bool = field(default=False)

    def check_read(self, *, uid: int) -> None:
        """Raise if the uid lacks read permission.

        Args:
            uid: The uid of the requesting user.

        Raises:
            PermissionError: If access is denied.

        """
        if uid == ROOT_UID:
            return
        if uid == self.owner_uid:
            if not self.owner_read:
                msg = "Read permission denied (owner)"
                raise PermissionError(msg)
        elif not self.other_read:
            msg = "Read permission denied"
            raise PermissionError(msg)

    def check_write(self, *, uid: int) -> None:
        """Raise if the uid lacks write permission.

        Args:
            uid: The uid of the requesting user.

        Raises:
            PermissionError: If access is denied.

        """
        if uid == ROOT_UID:
            return
        if uid == self.owner_uid:
            if not self.owner_write:
                msg = "Write permission denied (owner)"
                raise PermissionError(msg)
        elif not self.other_write:
            msg = "Write permission denied"
            raise PermissionError(msg)
