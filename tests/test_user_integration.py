"""Tests for user integration into the kernel, syscalls, and shell.

Verifies that:
- The kernel boots a UserManager and tracks the current user.
- New user-related syscalls work (create user, list users, switch user, whoami).
- File permissions are enforced on read/write syscalls.
- The shell exposes whoami, adduser, and su commands.
"""

import pytest

from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber
from py_os.users import ROOT_UID

NUM_PAGES = 2


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = _booted_kernel()
    return kernel, Shell(kernel=kernel)


class TestKernelUserSubsystem:
    """Verify that the kernel manages users as a subsystem."""

    def test_user_manager_available_after_boot(self) -> None:
        """The user manager should be accessible after booting."""
        kernel = _booted_kernel()
        assert kernel.user_manager is not None

    def test_user_manager_none_before_boot(self) -> None:
        """The user manager should not be accessible before booting."""
        kernel = Kernel()
        assert kernel.user_manager is None

    def test_user_manager_none_after_shutdown(self) -> None:
        """The user manager should be torn down after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.user_manager is None

    def test_current_uid_is_root_after_boot(self) -> None:
        """The kernel should start as root after boot."""
        kernel = _booted_kernel()
        assert kernel.current_uid == ROOT_UID


class TestSyscallUserOps:
    """Verify user-related system calls."""

    def test_whoami(self) -> None:
        """SYS_WHOAMI should return the current user info."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_WHOAMI)
        assert result["uid"] == ROOT_UID
        assert result["username"] == "root"

    def test_create_user(self) -> None:
        """SYS_CREATE_USER should create a new user."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        assert result["username"] == "alice"
        assert result["uid"] > ROOT_UID

    def test_create_duplicate_user_raises(self) -> None:
        """Creating a duplicate username should raise SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        with pytest.raises(SyscallError, match="already exists"):
            kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")

    def test_list_users(self) -> None:
        """SYS_LIST_USERS should return all users."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        result = kernel.syscall(SyscallNumber.SYS_LIST_USERS)
        names = [u["username"] for u in result]
        assert "root" in names
        assert "alice" in names

    def test_switch_user(self) -> None:
        """SYS_SWITCH_USER should change the current uid."""
        kernel = _booted_kernel()
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=user["uid"])
        result = kernel.syscall(SyscallNumber.SYS_WHOAMI)
        assert result["username"] == "alice"

    def test_switch_to_nonexistent_user_raises(self) -> None:
        """Switching to a non-existent uid should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=999)


class TestSyscallPermissionEnforcement:
    """Verify that file syscalls enforce permissions."""

    def test_non_owner_cannot_write(self) -> None:
        """A non-owner should be denied write access by default."""
        kernel = _booted_kernel()
        # Root creates a file (owner = root, uid=0)
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/secret.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/secret.txt", data=b"classified")

        # Switch to a non-root user
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=user["uid"])

        # Alice can read (other_read=True by default)
        data: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/secret.txt")
        assert data == b"classified"

        # Alice cannot write (other_write=False by default)
        with pytest.raises(SyscallError, match="denied"):
            kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/secret.txt", data=b"hacked")

    def test_owner_can_write_own_file(self) -> None:
        """A user should be able to write files they own."""
        kernel = _booted_kernel()
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=user["uid"])

        # Alice creates and writes her own file
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/alice.txt")
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/alice.txt", data=b"my data")
        result: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/alice.txt")
        assert result == b"my data"

    def test_root_bypasses_permissions(self) -> None:
        """Root should be able to write any file regardless of ownership."""
        kernel = _booted_kernel()
        # Alice creates a file
        user = kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="alice")
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=user["uid"])
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/alice.txt")

        # Switch back to root and write it
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=ROOT_UID)
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/alice.txt", data=b"root was here")
        result: bytes = kernel.syscall(SyscallNumber.SYS_READ_FILE, path="/alice.txt")
        assert result == b"root was here"


class TestShellUserCommands:
    """Verify the shell's user-related commands."""

    def test_whoami_as_root(self) -> None:
        """Whoami should show root initially."""
        _kernel, shell = _booted_shell()
        result = shell.execute("whoami")
        assert "root" in result

    def test_adduser_and_whoami(self) -> None:
        """Adduser should create a user, su should switch to them."""
        kernel, shell = _booted_shell()
        result = shell.execute("adduser alice")
        assert "alice" in result
        # Get alice's uid from the kernel
        assert kernel.user_manager is not None
        alice = kernel.user_manager.get_user_by_name("alice")
        assert alice is not None
        shell.execute(f"su {alice.uid}")
        result = shell.execute("whoami")
        assert "alice" in result

    def test_adduser_missing_arg(self) -> None:
        """Adduser without a name should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("adduser")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_su_missing_arg(self) -> None:
        """Su without a uid should produce a usage error."""
        _kernel, shell = _booted_shell()
        result = shell.execute("su")
        assert "usage" in result.lower() or "error" in result.lower()

    def test_help_includes_new_commands(self) -> None:
        """Help should list the new user commands."""
        _kernel, shell = _booted_shell()
        result = shell.execute("help")
        assert "whoami" in result
        assert "adduser" in result
        assert "su" in result
