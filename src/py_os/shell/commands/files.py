"""Files commands -- making, reading, linking and protecting files -- plus file descriptors and the journal."""

from py_os.process.binary import PYBIN_MAGIC
from py_os.shell.base import ASCII_PRINTABLE_MAX, ASCII_PRINTABLE_MIN, ShellBase
from py_os.syscalls import SyscallError, SyscallNumber


class FileCommands(ShellBase):
    """Shell commands for making, reading, linking and protecting files -- plus file descriptors and the journal."""

    def _cmd_ls(self, args: list[str]) -> str:
        """List directory contents."""
        path = args[0] if args else "/"
        if path.startswith("/proc"):
            try:
                entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_PROC_LIST, path=path)
            except SyscallError as e:
                return f"Error: {e}"
            return "\n".join(entries) if entries else ""
        try:
            entries = self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path=path)
        except SyscallError as e:
            return f"Error: {e}"
        return "\n".join(entries) if entries else ""

    def _cmd_mkdir(self, args: list[str]) -> str:
        """Create a directory."""
        if not args:
            return "Usage: mkdir <path>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_touch(self, args: list[str]) -> str:
        """Create an empty file."""
        if not args:
            return "Usage: touch <path>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_write(self, args: list[str]) -> str:
        """Write content to a file."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: write <path> <content...>"

        path = args[0]
        content = " ".join(args[1:])
        try:
            self._kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path=path, data=content.encode())
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_cat(self, args: list[str]) -> str:
        """Read file contents."""
        if not args:
            return "Usage: cat <path>"
        if args[0].startswith("/proc"):
            try:
                return self._kernel.syscall(SyscallNumber.SYS_PROC_READ, path=args[0])
            except SyscallError as e:
                return f"Error: not found — {e}"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=args[0])
            return data.decode()
        except SyscallError as e:
            return f"Error: not found — {e}"

    def _cmd_rm(self, args: list[str]) -> str:
        """Remove a file or directory."""
        if not args:
            return "Usage: rm <path>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_grep(self, args: list[str]) -> str:
        """Filter piped input lines matching a pattern."""
        if not args:
            return "Usage: grep <pattern>"
        pattern = args[0]
        lines = self._pipe_input.splitlines() if self._pipe_input else []
        matched = [line for line in lines if pattern in line]
        return "\n".join(matched)

    def _cmd_wc(self, _args: list[str]) -> str:
        """Count lines in piped input."""
        if not self._pipe_input:
            return "Usage: wc (pipe input required)"
        lines = self._pipe_input.splitlines()
        return f"{len(lines)} lines"

    def _cmd_open(self, args: list[str]) -> str:
        """Open a file and get a file descriptor."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: open <pid> <path> [r|w|rw]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        path = args[1]
        mode = args[2] if len(args) > 2 else "r"  # noqa: PLR2004
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_OPEN, pid=pid, path=path, mode=mode
            )
            return f"Opened '{path}' as fd {result['fd']} for pid {pid}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_close(self, args: list[str]) -> str:
        """Close a file descriptor."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: close <pid> <fd>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CLOSE, pid=pid, fd=fd)
            return f"Closed fd {fd} for pid {pid}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_readfd(self, args: list[str]) -> str:
        """Read bytes from a file descriptor."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: readfd <pid> <fd> <count>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        try:
            count = int(args[2])
        except ValueError:
            return f"Error: invalid count '{args[2]}'"
        try:
            result_read: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_READ_FD, pid=pid, fd=fd, count=count
            )
            data: bytes = result_read["data"]  # type: ignore[assignment]
            return data.decode(errors="replace")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_writefd(self, args: list[str]) -> str:
        """Write data to a file descriptor."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: writefd <pid> <fd> <data...>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        content = " ".join(args[2:])
        try:
            result_write: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FD, pid=pid, fd=fd, data=content.encode()
            )
            return f"Wrote {result_write['bytes_written']} bytes to fd {fd}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_seek(self, args: list[str]) -> str:
        """Reposition a file descriptor's offset."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: seek <pid> <fd> <offset> [set|cur|end]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            fd = int(args[1])
        except ValueError:
            return f"Error: invalid fd '{args[1]}'"
        try:
            offset = int(args[2])
        except ValueError:
            return f"Error: invalid offset '{args[2]}'"
        whence = args[3] if len(args) > 3 else "set"  # noqa: PLR2004
        try:
            result_seek: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SEEK, pid=pid, fd=fd, offset=offset, whence=whence
            )
            return f"Seeked fd {fd} to offset {result_seek['offset']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_lsfd(self, args: list[str]) -> str:
        """List open file descriptors for a process."""
        if not args:
            return "Usage: lsfd <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        fds: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_FDS, pid=pid)
        if not fds:
            return f"No open file descriptors for pid {pid}."
        lines = ["FD  MODE  OFFSET  PATH"]
        lines.extend(
            f"{fd_info['fd']!s:<3} {fd_info['mode']!s:<5}"
            f" {fd_info['offset']!s:<7} {fd_info['path']}"
            for fd_info in fds
        )
        return "\n".join(lines)

    def _cmd_ln(self, args: list[str]) -> str:
        """Create a hard or symbolic link.

        ``ln <target> <link>``     → hard link
        ``ln -s <target> <link>``  → symbolic link
        """
        symbolic = args[0] == "-s" if args else False
        actual_args = args[1:] if symbolic else args

        min_args = 2
        if len(actual_args) < min_args:
            return "Usage: ln [-s] <target> <link_name>"

        target = actual_args[0]
        link_path = actual_args[1]
        syscall = SyscallNumber.SYS_SYMLINK if symbolic else SyscallNumber.SYS_LINK
        try:
            self._kernel.syscall(syscall, target=target, link_path=link_path)
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_readlink(self, args: list[str]) -> str:
        """Print the target of a symbolic link."""
        if not args:
            return "Usage: readlink <path>"
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_READLINK, path=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_stat(self, args: list[str]) -> str:
        """Display file metadata (inode, type, size, links).

        Use lstat internally so symlinks show their own metadata.
        """
        if not args:
            return "Usage: stat <path>"
        path = args[0]
        try:
            info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_LSTAT, path=path)
        except SyscallError as e:
            return f"Error: {e}"

        if str(info["file_type"]) == "symlink" and "target" in info:
            file_line = f"  File: {path} -> {info['target']}"
        else:
            file_line = f"  File: {path}"

        lines = [
            file_line,
            f"  Inode: {info['inode_number']}",
            f"  Type: {info['file_type']}",
            f"  Size: {info['size']}",
            f"  Links: {info['link_count']}",
        ]
        return "\n".join(lines)

    def _cmd_journal(self, args: list[str]) -> str:
        """Manage the filesystem journal — status, checkpoint, recover, crash."""
        if not args:
            return "Usage: journal <status|checkpoint|recover|crash>"
        match args[0]:
            case "status":
                return self._cmd_journal_status()
            case "checkpoint":
                return self._cmd_journal_checkpoint()
            case "recover":
                return self._cmd_journal_recover()
            case "crash":
                return self._cmd_journal_crash()
            case _:
                return "Usage: journal <status|checkpoint|recover|crash>"

    def _cmd_journal_status(self) -> str:
        """Show journal transaction status."""
        status: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_JOURNAL_STATUS)
        return (
            f"Transactions: {status['total']} total"
            f" ({status['active']} active,"
            f" {status['committed']} committed,"
            f" {status['aborted']} aborted)"
        )

    def _cmd_journal_checkpoint(self) -> str:
        """Create a journal checkpoint."""
        self._kernel.syscall(SyscallNumber.SYS_JOURNAL_CHECKPOINT)
        return "Checkpoint created"

    def _cmd_journal_recover(self) -> str:
        """Recover from a crash by replaying committed transactions."""
        result: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_JOURNAL_RECOVER)
        count = result["replayed"]
        return f"Recovery complete: replayed {count} transactions"

    def _cmd_journal_crash(self) -> str:
        """Simulate a crash for educational purposes."""
        self._kernel.syscall(SyscallNumber.SYS_JOURNAL_CRASH)
        return "Crash simulated \u2014 uncommitted work lost"

    def _cmd_chmod(self, args: list[str]) -> str:
        """Set file permissions: chmod path rwxrwxrwx."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: chmod <path> <rwxrwxrwx>"
        path, mode = args[0], args[1]
        try:
            self._kernel.syscall(SyscallNumber.SYS_CHMOD, path=path, mode=mode)
            return f"Permissions set on {path}: {mode}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_chown(self, args: list[str]) -> str:
        """Change file owner/group: chown path uid [gid]."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: chown <path> <uid> [gid]"
        path = args[0]
        try:
            uid = int(args[1])
        except ValueError:
            return f"Error: invalid uid '{args[1]}'"
        gid: int | None = None
        if len(args) >= 3:  # noqa: PLR2004
            try:
                gid = int(args[2])
            except ValueError:
                return f"Error: invalid gid '{args[2]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_CHOWN, path=path, uid=uid, gid=gid)
            msg = f"Owner of {path} set to uid={uid}"
            if gid is not None:
                msg += f", gid={gid}"
            return msg
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_getfacl(self, args: list[str]) -> str:
        """Display permissions and ACL entries: getfacl path."""
        if not args:
            return "Usage: getfacl <path>"
        path = args[0]
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_GET_ACL, path=path)
            lines = [
                f"# file: {path}",
                f"# owner: {result['owner_uid']}",
                f"# group: {result['group_gid']}",
                f"mode: {result['mode']}",
            ]
            acl_list: list[dict[str, object]] = result["acl"]  # type: ignore[assignment]
            for entry in acl_list:
                perms = (
                    ("r" if entry["read"] else "-")
                    + ("w" if entry["write"] else "-")
                    + ("x" if entry["execute"] else "-")
                )
                lines.append(f"{entry['type']}:{entry['target_id']}:{perms}")
            return "\n".join(lines)
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_setfacl(self, args: list[str]) -> str:
        """Add an ACL entry: setfacl path user:uid:rwx or setfacl path group:gid:r-x."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: setfacl <path> <user|group>:<id>:<rwx>"
        parsed = self._parse_acl_spec(args[1])
        if isinstance(parsed, str):
            return parsed
        return self._apply_acl_entry(args[0], parsed)

    def _parse_acl_spec(self, spec: str) -> dict[str, object] | str:
        """Parse an ACL spec string like 'user:1:rwx' into an entry dict."""
        parts = spec.split(":")
        expected_parts = 3
        if len(parts) != expected_parts:
            return "Error: ACL spec must be type:id:perms (e.g. user:1:rwx)"
        entry_type, target_id_str, perm_str = parts
        if entry_type not in {"user", "group"}:
            return f"Error: type must be 'user' or 'group', got '{entry_type}'"
        try:
            target_id = int(target_id_str)
        except ValueError:
            return f"Error: invalid id '{target_id_str}'"
        return {
            "type": entry_type,
            "target_id": target_id,
            "read": "r" in perm_str,
            "write": "w" in perm_str,
            "execute": "x" in perm_str,
        }

    def _apply_acl_entry(self, path: str, new_entry: dict[str, object]) -> str:
        """Fetch existing ACLs, merge in new_entry, and apply."""
        try:
            current: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_GET_ACL, path=path)
        except SyscallError as e:
            return f"Error: {e}"
        existing: list[dict[str, object]] = current["acl"]  # type: ignore[assignment]
        updated = [
            e
            for e in existing
            if not (e["type"] == new_entry["type"] and e["target_id"] == new_entry["target_id"])
        ]
        updated.append(new_entry)
        try:
            self._kernel.syscall(SyscallNumber.SYS_SET_ACL, path=path, entries=updated)
            spec = f"{new_entry['type']}:{new_entry['target_id']}"
            perms = (
                ("r" if new_entry["read"] else "-")
                + ("w" if new_entry["write"] else "-")
                + ("x" if new_entry["execute"] else "-")
            )
            return f"ACL set on {path}: {spec}:{perms}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_hexdump(self, args: list[str]) -> str:
        """Show an annotated hex dump of a PyBin file: hexdump PATH."""
        if not args:
            return "Usage: hexdump <path>"
        path = args[0]
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=path)
        except SyscallError as e:
            return f"Error: {e}"
        return self._format_hexdump(data)

    @staticmethod
    def _format_hexdump(data: bytes) -> str:
        """Format binary data as an annotated hex dump."""
        lines: list[str] = []
        bytes_per_row = 16
        for offset in range(0, len(data), bytes_per_row):
            chunk = data[offset : offset + bytes_per_row]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(
                chr(b) if ASCII_PRINTABLE_MIN <= b < ASCII_PRINTABLE_MAX else "." for b in chunk
            )
            lines.append(f"{offset:04x}  {hex_part:<48s}  {ascii_part}")
        # Add annotation for magic bytes
        if data[:4] == PYBIN_MAGIC:
            lines.insert(0, f"PyBin binary ({len(data)} bytes)")
            lines.insert(1, f"  Magic: {PYBIN_MAGIC!r}")
        return "\n".join(lines)

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("ls", _cmd_ls),
        ("mkdir", _cmd_mkdir),
        ("touch", _cmd_touch),
        ("write", _cmd_write),
        ("cat", _cmd_cat),
        ("rm", _cmd_rm),
        ("grep", _cmd_grep),
        ("wc", _cmd_wc),
        ("ln", _cmd_ln),
        ("readlink", _cmd_readlink),
        ("stat", _cmd_stat),
        ("chmod", _cmd_chmod),
        ("chown", _cmd_chown),
        ("getfacl", _cmd_getfacl),
        ("setfacl", _cmd_setfacl),
        ("hexdump", _cmd_hexdump),
        ("journal", _cmd_journal),
        ("open", _cmd_open),
        ("close", _cmd_close),
        ("readfd", _cmd_readfd),
        ("writefd", _cmd_writefd),
        ("seek", _cmd_seek),
        ("lsfd", _cmd_lsfd),
    )
