"""Users and groups commands -- who you are, adding users, switching users and groups."""

from py_os.shell.base import ShellBase
from py_os.syscalls import SyscallError, SyscallNumber


class UserCommands(ShellBase):
    """Shell commands for who you are, adding users, switching users and groups."""

    def _cmd_whoami(self, _args: list[str]) -> str:
        """Show the current user."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_WHOAMI)
        return f"{result['username']} (uid={result['uid']})"

    def _cmd_adduser(self, args: list[str]) -> str:
        """Create a new user."""
        if not args:
            return "Usage: adduser <username>"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_USER, username=args[0]
            )
            return f"User '{result['username']}' created (uid={result['uid']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_su(self, args: list[str]) -> str:
        """Switch to another user by uid."""
        if not args:
            return "Usage: su <uid>"
        try:
            uid = int(args[0])
        except ValueError:
            return f"Error: invalid uid '{args[0]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=uid)
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_WHOAMI)
            return f"Switched to {result['username']} (uid={result['uid']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_groups(self, args: list[str]) -> str:
        """Manage groups: groups, groups list, groups add NAME, groups adduser UID GID."""
        if not args:
            return self._cmd_groups_current()
        match args[0]:
            case "list":
                return self._cmd_groups_list()
            case "add":
                return self._cmd_groups_add(args[1:])
            case "adduser":
                return self._cmd_groups_adduser(args[1:])
            case "removeuser":
                return self._cmd_groups_removeuser(args[1:])
            case _:
                return "Usage: groups [list|add NAME|adduser UID GID|removeuser UID GID]"

    def _cmd_groups_current(self) -> str:
        """Show current user's group memberships."""
        try:
            whoami: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_WHOAMI)
            uid: int = whoami["uid"]  # type: ignore[assignment]
            result = self._kernel.syscall(SyscallNumber.SYS_USER_GROUPS, uid=uid)
            if not result:
                return "No group memberships"
            return " ".join(f"{g['name']}({g['gid']})" for g in result)
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_groups_list(self) -> str:
        """List all groups."""
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_LIST_GROUPS)
            if not result:
                return "No groups"
            lines = ["GID  NAME            MEMBERS"]
            for g in result:
                members = ", ".join(str(m) for m in g["members"])
                lines.append(f"{g['gid']:<4} {g['name']:<15} [{members}]")
            return "\n".join(lines)
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_groups_add(self, args: list[str]) -> str:
        """Create a group: groups add NAME."""
        if not args:
            return "Usage: groups add <name>"
        name = args[0]
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CREATE_GROUP, name=name)
            return f"Created group {result['name']} (gid={result['gid']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_groups_adduser(self, args: list[str]) -> str:
        """Add user to group: groups adduser UID GID."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: groups adduser <uid> <gid>"
        try:
            uid = int(args[0])
            gid = int(args[1])
        except ValueError:
            return "Error: uid and gid must be integers"
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_ADD_TO_GROUP, uid=uid, gid=gid)
            return f"Added uid {uid} to group {result['name']} (gid={gid})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_groups_removeuser(self, args: list[str]) -> str:
        """Remove user from group: groups removeuser UID GID."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: groups removeuser <uid> <gid>"
        try:
            uid = int(args[0])
            gid = int(args[1])
        except ValueError:
            return "Error: uid and gid must be integers"
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_REMOVE_FROM_GROUP, uid=uid, gid=gid)
            return f"Removed uid {uid} from group {result['name']} (gid={gid})"
        except SyscallError as e:
            return f"Error: {e}"

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("whoami", _cmd_whoami),
        ("adduser", _cmd_adduser),
        ("su", _cmd_su),
        ("groups", _cmd_groups),
    )
