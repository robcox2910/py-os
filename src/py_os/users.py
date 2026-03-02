"""Users and permissions — access control for the operating system.

Every real OS has a concept of **identity**: who is making a request?
This module provides the building blocks:

**User** — an identity with a numeric ``uid`` and string ``username``.
    In Unix, every process has a uid, and every file has an owner uid.
    The uid is what the kernel actually checks — usernames are for humans.

**Group** — a set of users who share permissions.
    Think of school clubs: the Art Club members can all access the art
    supplies cupboard.  Groups work the same way — everyone in the
    group gets the group's permissions.

**UserManager** — a registry of users and groups with auto-incrementing
    ids.  Think of ``/etc/passwd`` and ``/etc/group`` on Linux.
    The manager always creates a root user (uid=0) who has superuser
    privileges.

**FilePermissions** — permission bits (read/write/execute for owner,
    group, and others) plus optional ACL entries.  When a syscall tries
    to read, write, or execute a file, the kernel checks these bits
    against the caller's uid and group memberships.  Root (uid=0)
    bypasses all checks — just like real Unix.

**AclEntry** — a fine-grained permission override for a specific user
    or group.  Like a VIP guest list at a party — even if you're not
    the host (owner) and not in the general group, a specific ACL
    entry can grant (or deny) you access.
"""

from dataclasses import dataclass, field
from enum import StrEnum
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


@dataclass(frozen=True)
class Group:
    """A named set of users who share permissions.

    Think of a school club: the club has a name and a membership list.
    Any member of the club gets the club's permissions.
    """

    gid: int
    name: str
    members: frozenset[int] = field(
        default_factory=lambda: frozenset[int]()  # noqa: PLW0108
    )


class AclEntryType(StrEnum):
    """Type of ACL entry — targets a specific user or group."""

    USER = "user"
    GROUP = "group"


@dataclass(frozen=True)
class AclEntry:
    """A single entry in an Access Control List.

    Like a line on a VIP guest list: it says who (a user or group)
    and what they're allowed to do (read, write, execute).
    """

    entry_type: AclEntryType
    target_id: int
    read: bool = False
    write: bool = False
    execute: bool = False


class UserManager:
    """Registry of users and groups — the OS's ``/etc/passwd`` + ``/etc/group``.

    Auto-creates root (uid=0) on initialisation.  New users get
    sequential uids starting from 1.  Groups get sequential gids
    starting from 1.
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

        # Groups
        self._gid_counter = count(start=1)
        self._groups: dict[int, Group] = {}
        self._group_names: dict[str, int] = {}

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

    # -- Group management -------------------------------------------------------

    def create_group(self, name: str) -> Group:
        """Create a named group.

        Args:
            name: The group name.

        Returns:
            The newly created group.

        Raises:
            ValueError: If the group name already exists.

        """
        if name in self._group_names:
            msg = f"Group '{name}' already exists"
            raise ValueError(msg)
        gid = next(self._gid_counter)
        group = Group(gid=gid, name=name)
        self._groups[gid] = group
        self._group_names[name] = gid
        return group

    def get_group(self, gid: int) -> Group | None:
        """Look up a group by gid."""
        return self._groups.get(gid)

    def get_group_by_name(self, name: str) -> Group | None:
        """Look up a group by name."""
        gid = self._group_names.get(name)
        if gid is None:
            return None
        return self._groups.get(gid)

    def add_to_group(self, uid: int, gid: int) -> Group:
        """Add a user to a group.

        Args:
            uid: The user id to add.
            gid: The group id.

        Returns:
            The updated group.

        Raises:
            ValueError: If the user or group does not exist.

        """
        if uid not in self._users:
            msg = f"User {uid} not found"
            raise ValueError(msg)
        group = self._groups.get(gid)
        if group is None:
            msg = f"Group {gid} not found"
            raise ValueError(msg)
        updated = Group(gid=group.gid, name=group.name, members=group.members | {uid})
        self._groups[gid] = updated
        return updated

    def remove_from_group(self, uid: int, gid: int) -> Group:
        """Remove a user from a group.

        Args:
            uid: The user id to remove.
            gid: The group id.

        Returns:
            The updated group.

        Raises:
            ValueError: If the user or group does not exist.

        """
        if uid not in self._users:
            msg = f"User {uid} not found"
            raise ValueError(msg)
        group = self._groups.get(gid)
        if group is None:
            msg = f"Group {gid} not found"
            raise ValueError(msg)
        updated = Group(gid=group.gid, name=group.name, members=group.members - {uid})
        self._groups[gid] = updated
        return updated

    def list_groups(self) -> list[Group]:
        """Return all registered groups."""
        return list(self._groups.values())

    def user_groups(self, uid: int) -> list[Group]:
        """Return all groups a user belongs to.

        Args:
            uid: The user id.

        Returns:
            List of groups containing this user.

        """
        return [g for g in self._groups.values() if uid in g.members]

    def user_group_ids(self, uid: int) -> frozenset[int]:
        """Return the set of group ids a user belongs to.

        Args:
            uid: The user id.

        Returns:
            Frozenset of gids.

        """
        return frozenset(g.gid for g in self._groups.values() if uid in g.members)


@dataclass
class FilePermissions:
    """Permission bits for a file or directory.

    Models a Unix-style permission scheme with owner, group, and others,
    each having read, write, and execute flags.  Root (uid=0) bypasses
    all checks.

    ACL entries provide fine-grained overrides: a specific user ACL
    takes priority over group/owner/other checks, and a specific group
    ACL takes priority over the file's group and other checks.

    Priority order (highest to lowest):
    1. Root (uid=0) — always allowed
    2. User-specific ACL entry
    3. Group-specific ACL entry (if user is a member)
    4. Owner permissions (if uid matches owner_uid)
    5. Group permissions (if user is in group_gid)
    6. Other permissions

    Defaults mirror common Unix behaviour:
    - Owner can read and write (rw-).
    - Others can read but not write (r--).
    - No execute permission by default.
    """

    owner_uid: int
    owner_read: bool = field(default=True)
    owner_write: bool = field(default=True)
    owner_execute: bool = field(default=False)
    group_gid: int | None = field(default=None)
    group_read: bool = field(default=False)
    group_write: bool = field(default=False)
    group_execute: bool = field(default=False)
    other_read: bool = field(default=True)
    other_write: bool = field(default=False)
    other_execute: bool = field(default=False)
    acl_entries: tuple[AclEntry, ...] = field(default=())

    def _find_user_acl(self, uid: int) -> AclEntry | None:
        """Find a user-specific ACL entry."""
        for entry in self.acl_entries:
            if entry.entry_type is AclEntryType.USER and entry.target_id == uid:
                return entry
        return None

    def _find_group_acls(self, groups: frozenset[int] | None) -> list[AclEntry]:
        """Find all group ACL entries matching the user's groups."""
        if groups is None:
            return []
        return [
            entry
            for entry in self.acl_entries
            if entry.entry_type is AclEntryType.GROUP and entry.target_id in groups
        ]

    def check_read(self, *, uid: int, groups: frozenset[int] | None = None) -> None:
        """Raise if the uid lacks read permission.

        Args:
            uid: The uid of the requesting user.
            groups: The user's group memberships (gids).

        Raises:
            PermissionError: If access is denied.

        """
        if uid == ROOT_UID:
            return
        # 1. Check user-specific ACL
        user_acl = self._find_user_acl(uid)
        if user_acl is not None:
            if not user_acl.read:
                msg = "Read permission denied (ACL)"
                raise PermissionError(msg)
            return
        # 2. Check group-specific ACLs
        group_acls = self._find_group_acls(groups)
        if group_acls:
            if any(acl.read for acl in group_acls):
                return
            msg = "Read permission denied (group ACL)"
            raise PermissionError(msg)
        # 3. Check owner
        if uid == self.owner_uid:
            if not self.owner_read:
                msg = "Read permission denied (owner)"
                raise PermissionError(msg)
            return
        # 4. Check file group
        if groups is not None and self.group_gid is not None and self.group_gid in groups:
            if not self.group_read:
                msg = "Read permission denied (group)"
                raise PermissionError(msg)
            return
        # 5. Check other
        if not self.other_read:
            msg = "Read permission denied"
            raise PermissionError(msg)

    def check_write(self, *, uid: int, groups: frozenset[int] | None = None) -> None:
        """Raise if the uid lacks write permission.

        Args:
            uid: The uid of the requesting user.
            groups: The user's group memberships (gids).

        Raises:
            PermissionError: If access is denied.

        """
        if uid == ROOT_UID:
            return
        # 1. Check user-specific ACL
        user_acl = self._find_user_acl(uid)
        if user_acl is not None:
            if not user_acl.write:
                msg = "Write permission denied (ACL)"
                raise PermissionError(msg)
            return
        # 2. Check group-specific ACLs
        group_acls = self._find_group_acls(groups)
        if group_acls:
            if any(acl.write for acl in group_acls):
                return
            msg = "Write permission denied (group ACL)"
            raise PermissionError(msg)
        # 3. Check owner
        if uid == self.owner_uid:
            if not self.owner_write:
                msg = "Write permission denied (owner)"
                raise PermissionError(msg)
            return
        # 4. Check file group
        if groups is not None and self.group_gid is not None and self.group_gid in groups:
            if not self.group_write:
                msg = "Write permission denied (group)"
                raise PermissionError(msg)
            return
        # 5. Check other
        if not self.other_write:
            msg = "Write permission denied"
            raise PermissionError(msg)

    def check_execute(self, *, uid: int, groups: frozenset[int] | None = None) -> None:
        """Raise if the uid lacks execute permission.

        Args:
            uid: The uid of the requesting user.
            groups: The user's group memberships (gids).

        Raises:
            PermissionError: If access is denied.

        """
        if uid == ROOT_UID:
            return
        # 1. Check user-specific ACL
        user_acl = self._find_user_acl(uid)
        if user_acl is not None:
            if not user_acl.execute:
                msg = "Execute permission denied (ACL)"
                raise PermissionError(msg)
            return
        # 2. Check group-specific ACLs
        group_acls = self._find_group_acls(groups)
        if group_acls:
            if any(acl.execute for acl in group_acls):
                return
            msg = "Execute permission denied (group ACL)"
            raise PermissionError(msg)
        # 3. Check owner
        if uid == self.owner_uid:
            if not self.owner_execute:
                msg = "Execute permission denied (owner)"
                raise PermissionError(msg)
            return
        # 4. Check file group
        if groups is not None and self.group_gid is not None and self.group_gid in groups:
            if not self.group_execute:
                msg = "Execute permission denied (group)"
                raise PermissionError(msg)
            return
        # 5. Check other
        if not self.other_execute:
            msg = "Execute permission denied"
            raise PermissionError(msg)
