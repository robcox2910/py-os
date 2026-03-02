"""Tests for containers — namespace isolation within a single kernel."""

import pytest

from py_os.containers import (
    Container,
    ContainerError,
    ContainerManager,
    ContainerState,
    MountNamespace,
    NetworkNamespace,
    PidNamespace,
)
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

_FIRST_VPID = 1
_SECOND_VPID = 2
_REAL_PID_A = 10
_REAL_PID_B = 20
_REAL_PID_C = 30


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


# -- PidNamespace tests --------------------------------------------------------


class TestPidNamespace:
    """Verify PID namespace virtual-to-real mapping."""

    def test_first_vpid_is_one(self) -> None:
        """First registered process gets virtual PID 1."""
        ns = PidNamespace()
        vpid = ns.register(_REAL_PID_A)
        assert vpid == _FIRST_VPID

    def test_second_vpid_is_two(self) -> None:
        """Second registered process gets virtual PID 2."""
        ns = PidNamespace()
        ns.register(_REAL_PID_A)
        vpid = ns.register(_REAL_PID_B)
        assert vpid == _SECOND_VPID

    def test_real_pid_lookup(self) -> None:
        """Translate virtual PID back to real PID."""
        ns = PidNamespace()
        vpid = ns.register(_REAL_PID_A)
        assert ns.real_pid(vpid) == _REAL_PID_A

    def test_virtual_pid_lookup(self) -> None:
        """Translate real PID to virtual PID."""
        ns = PidNamespace()
        ns.register(_REAL_PID_A)
        assert ns.virtual_pid(_REAL_PID_A) == _FIRST_VPID

    def test_unknown_vpid_raises(self) -> None:
        """Looking up unknown virtual PID raises ContainerError."""
        ns = PidNamespace()
        with pytest.raises(ContainerError, match="Virtual PID"):
            ns.real_pid(99)

    def test_unknown_real_pid_raises(self) -> None:
        """Looking up unknown real PID raises ContainerError."""
        ns = PidNamespace()
        with pytest.raises(ContainerError, match="Real PID"):
            ns.virtual_pid(99)

    def test_unregister_removes_mapping(self) -> None:
        """Unregister removes both directions of the mapping."""
        ns = PidNamespace()
        ns.register(_REAL_PID_A)
        ns.unregister(_REAL_PID_A)
        assert ns.virtual_pids() == []

    def test_unregister_unknown_is_noop(self) -> None:
        """Unregistering an unknown PID does nothing."""
        ns = PidNamespace()
        ns.unregister(999)  # Should not raise

    def test_virtual_pids_sorted(self) -> None:
        """Virtual PIDs are returned sorted."""
        ns = PidNamespace()
        ns.register(_REAL_PID_B)
        ns.register(_REAL_PID_A)
        assert ns.virtual_pids() == [_FIRST_VPID, _SECOND_VPID]

    def test_duplicate_register_returns_same_vpid(self) -> None:
        """Registering the same real PID again returns existing virtual PID."""
        ns = PidNamespace()
        vpid1 = ns.register(_REAL_PID_A)
        vpid2 = ns.register(_REAL_PID_A)
        assert vpid1 == vpid2


# -- MountNamespace tests -----------------------------------------------------


class TestMountNamespace:
    """Verify mount namespace path translation."""

    def test_translate_root(self) -> None:
        """Container root '/' translates to the fs_root."""
        ns = MountNamespace("/containers/web")
        assert ns.translate_path("/") == "/containers/web"

    def test_translate_subpath(self) -> None:
        """Container subpath translates correctly."""
        ns = MountNamespace("/containers/web")
        assert ns.translate_path("/index.html") == "/containers/web/index.html"

    def test_translate_nested(self) -> None:
        """Nested container path translates correctly."""
        ns = MountNamespace("/containers/web")
        assert ns.translate_path("/var/log") == "/containers/web/var/log"

    def test_container_path_inside(self) -> None:
        """Real path inside namespace translates back."""
        ns = MountNamespace("/containers/web")
        assert ns.container_path("/containers/web/index.html") == "/index.html"

    def test_container_path_root(self) -> None:
        """Real path matching fs_root translates to '/'."""
        ns = MountNamespace("/containers/web")
        assert ns.container_path("/containers/web") == "/"

    def test_container_path_outside_returns_none(self) -> None:
        """Real path outside namespace returns None."""
        ns = MountNamespace("/containers/web")
        assert ns.container_path("/etc/passwd") is None

    def test_fs_root_property(self) -> None:
        """The fs_root property returns the configured root."""
        ns = MountNamespace("/containers/db")
        assert ns.fs_root == "/containers/db"

    def test_trailing_slash_stripped(self) -> None:
        """Trailing slash on fs_root is stripped."""
        ns = MountNamespace("/containers/web/")
        assert ns.fs_root == "/containers/web"


# -- NetworkNamespace tests ----------------------------------------------------


class TestNetworkNamespace:
    """Verify network namespace isolation."""

    def test_has_socket_manager(self) -> None:
        """Network namespace provides its own socket manager."""
        ns = NetworkNamespace()
        assert ns.socket_manager is not None

    def test_has_dns_resolver(self) -> None:
        """Network namespace provides its own DNS resolver."""
        ns = NetworkNamespace()
        assert ns.dns_resolver is not None

    def test_isolated_socket_managers(self) -> None:
        """Two network namespaces have different socket managers."""
        ns1 = NetworkNamespace()
        ns2 = NetworkNamespace()
        assert ns1.socket_manager is not ns2.socket_manager

    def test_isolated_dns_resolvers(self) -> None:
        """Two network namespaces have different DNS resolvers."""
        ns1 = NetworkNamespace()
        ns2 = NetworkNamespace()
        assert ns1.dns_resolver is not ns2.dns_resolver


# -- Container tests -----------------------------------------------------------


class TestContainer:
    """Verify container lifecycle and process tracking."""

    def test_initial_state_is_created(self) -> None:
        """New container starts in CREATED state."""
        c = Container("web", fs_root="/containers/web")
        assert c.state is ContainerState.CREATED

    def test_start_transitions_to_running(self) -> None:
        """Starting a container transitions to RUNNING."""
        c = Container("web", fs_root="/containers/web")
        c.start()
        assert c.state is ContainerState.RUNNING

    def test_stop_transitions_to_stopped(self) -> None:
        """Stopping a container transitions to STOPPED."""
        c = Container("web", fs_root="/containers/web")
        c.start()
        c.stop()
        assert c.state is ContainerState.STOPPED

    def test_name_property(self) -> None:
        """Container name is accessible via property."""
        c = Container("myapp", fs_root="/containers/myapp")
        assert c.name == "myapp"

    def test_add_process_returns_vpid(self) -> None:
        """Adding a process returns its virtual PID."""
        c = Container("web", fs_root="/containers/web")
        vpid = c.add_process(_REAL_PID_A)
        assert vpid == _FIRST_VPID

    def test_contains_process(self) -> None:
        """Container correctly identifies its processes."""
        c = Container("web", fs_root="/containers/web")
        c.add_process(_REAL_PID_A)
        assert c.contains_process(_REAL_PID_A)
        assert not c.contains_process(_REAL_PID_B)

    def test_remove_process(self) -> None:
        """Removing a process removes it from the container."""
        c = Container("web", fs_root="/containers/web")
        c.add_process(_REAL_PID_A)
        c.remove_process(_REAL_PID_A)
        assert not c.contains_process(_REAL_PID_A)

    def test_process_count(self) -> None:
        """Process count reflects added processes."""
        c = Container("web", fs_root="/containers/web")
        assert c.process_count == 0
        c.add_process(_REAL_PID_A)
        c.add_process(_REAL_PID_B)
        assert c.process_count == _SECOND_VPID

    def test_has_all_namespaces(self) -> None:
        """Container provides PID, mount, and network namespaces."""
        c = Container("web", fs_root="/containers/web")
        assert isinstance(c.pid_namespace, PidNamespace)
        assert isinstance(c.mount_namespace, MountNamespace)
        assert isinstance(c.network_namespace, NetworkNamespace)


# -- ContainerManager tests ---------------------------------------------------


class TestContainerManager:
    """Verify container manager operations."""

    def test_create_container(self) -> None:
        """Create a container and retrieve it."""
        mgr = ContainerManager()
        c = mgr.create("web", fs_root="/containers/web")
        assert c.name == "web"

    def test_get_container(self) -> None:
        """Get a container by name."""
        mgr = ContainerManager()
        mgr.create("web", fs_root="/containers/web")
        c = mgr.get("web")
        assert c.name == "web"

    def test_get_nonexistent_raises(self) -> None:
        """Getting a nonexistent container raises ContainerError."""
        mgr = ContainerManager()
        with pytest.raises(ContainerError, match="not found"):
            mgr.get("nope")

    def test_duplicate_name_raises(self) -> None:
        """Creating a container with a duplicate name raises ContainerError."""
        mgr = ContainerManager()
        mgr.create("web", fs_root="/containers/web")
        with pytest.raises(ContainerError, match="already exists"):
            mgr.create("web", fs_root="/containers/web2")

    def test_destroy_container(self) -> None:
        """Destroy removes the container."""
        mgr = ContainerManager()
        mgr.create("web", fs_root="/containers/web")
        mgr.destroy("web")
        with pytest.raises(ContainerError, match="not found"):
            mgr.get("web")

    def test_destroy_nonexistent_raises(self) -> None:
        """Destroying a nonexistent container raises ContainerError."""
        mgr = ContainerManager()
        with pytest.raises(ContainerError, match="not found"):
            mgr.destroy("nope")

    def test_list_containers(self) -> None:
        """List returns summary of all containers."""
        mgr = ContainerManager()
        mgr.create("web", fs_root="/containers/web")
        mgr.create("db", fs_root="/containers/db")
        result = mgr.list_containers()
        names = {c["name"] for c in result}
        assert names == {"web", "db"}

    def test_list_empty(self) -> None:
        """List returns empty list when no containers exist."""
        mgr = ContainerManager()
        assert mgr.list_containers() == []

    def test_container_for_process(self) -> None:
        """Find which container owns a process."""
        mgr = ContainerManager()
        c = mgr.create("web", fs_root="/containers/web")
        c.add_process(_REAL_PID_A)
        found = mgr.container_for_process(_REAL_PID_A)
        assert found is c

    def test_container_for_unknown_process(self) -> None:
        """Unknown process returns None."""
        mgr = ContainerManager()
        assert mgr.container_for_process(_REAL_PID_A) is None

    def test_destroy_sets_stopped(self) -> None:
        """Destroying a running container sets it to STOPPED."""
        mgr = ContainerManager()
        c = mgr.create("web", fs_root="/containers/web")
        c.start()
        mgr.destroy("web")
        assert c.state is ContainerState.STOPPED


# -- Kernel container integration tests ----------------------------------------


class TestKernelContainers:
    """Verify kernel-level container operations."""

    def test_container_manager_available_after_boot(self) -> None:
        """Container manager is available after boot."""
        kernel = _booted_kernel()
        assert kernel.container_manager is not None

    def test_container_manager_none_before_boot(self) -> None:
        """Container manager is None before boot."""
        kernel = Kernel()
        assert kernel.container_manager is None

    def test_container_manager_none_after_shutdown(self) -> None:
        """Container manager is None after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.container_manager is None

    def test_container_create(self) -> None:
        """Create a container via kernel."""
        kernel = _booted_kernel()
        info = kernel.container_create("web")
        assert info["name"] == "web"
        assert info["state"] == "created"

    def test_container_list(self) -> None:
        """List containers via kernel."""
        kernel = _booted_kernel()
        kernel.container_create("web")
        kernel.container_create("db")
        result = kernel.container_list()
        names = {c["name"] for c in result}
        assert names == {"web", "db"}

    def test_container_info(self) -> None:
        """Get container info via kernel."""
        kernel = _booted_kernel()
        kernel.container_create("web")
        info = kernel.container_info("web")
        assert info["name"] == "web"
        assert "fs_root" in info
        assert "pid_namespace" in info
        assert "network" in info

    def test_container_destroy(self) -> None:
        """Destroy a container via kernel."""
        kernel = _booted_kernel()
        kernel.container_create("web")
        kernel.container_destroy("web")
        assert kernel.container_list() == []

    def test_container_exec(self) -> None:
        """Execute a program inside a container."""
        kernel = _booted_kernel()
        kernel.container_create("web")
        result = kernel.container_exec(
            "web", program=lambda: "hello from container", program_name="hello"
        )
        assert result["vpid"] == _FIRST_VPID
        assert result["output"] == "hello from container"


# -- Syscall container tests ---------------------------------------------------


class TestSyscallContainerOps:
    """Verify container-related syscalls."""

    def test_sys_container_create(self) -> None:
        """SYS_CONTAINER_CREATE creates a container."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
        assert result["name"] == "web"

    def test_sys_container_list(self) -> None:
        """SYS_CONTAINER_LIST lists all containers."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
        result = kernel.syscall(SyscallNumber.SYS_CONTAINER_LIST)
        assert len(result) == _FIRST_VPID

    def test_sys_container_info(self) -> None:
        """SYS_CONTAINER_INFO returns container details."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
        result = kernel.syscall(SyscallNumber.SYS_CONTAINER_INFO, name="web")
        assert result["name"] == "web"

    def test_sys_container_exec(self) -> None:
        """SYS_CONTAINER_EXEC runs a program in a container."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
        result = kernel.syscall(
            SyscallNumber.SYS_CONTAINER_EXEC,
            name="web",
            program_name="hello",
        )
        assert result["vpid"] == _FIRST_VPID

    def test_sys_container_destroy(self) -> None:
        """SYS_CONTAINER_DESTROY removes a container."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
        kernel.syscall(SyscallNumber.SYS_CONTAINER_DESTROY, name="web")
        result = kernel.syscall(SyscallNumber.SYS_CONTAINER_LIST)
        assert result == []

    def test_sys_container_create_duplicate_raises(self) -> None:
        """Creating a duplicate container raises SyscallError."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
        with pytest.raises(SyscallError, match="already exists"):
            kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")

    def test_sys_container_info_nonexistent_raises(self) -> None:
        """Info on a nonexistent container raises SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_CONTAINER_INFO, name="nope")


# -- Shell container command tests ---------------------------------------------


class TestShellContainerCommands:
    """Verify shell container commands."""

    def test_container_create(self) -> None:
        """Shell 'container create' creates a container."""
        _kernel, shell = _booted_shell()
        output = shell.execute("container create web")
        assert "Created container" in output
        assert "web" in output

    def test_container_list(self) -> None:
        """Shell 'container list' shows containers."""
        _kernel, shell = _booted_shell()
        shell.execute("container create web")
        output = shell.execute("container list")
        assert "web" in output

    def test_container_list_empty(self) -> None:
        """Shell 'container list' when empty shows message."""
        _kernel, shell = _booted_shell()
        output = shell.execute("container list")
        assert "No containers" in output

    def test_container_info(self) -> None:
        """Shell 'container info' shows container details."""
        _kernel, shell = _booted_shell()
        shell.execute("container create web")
        output = shell.execute("container info web")
        assert "web" in output
        assert "State" in output

    def test_container_exec(self) -> None:
        """Shell 'container exec' runs a program."""
        _kernel, shell = _booted_shell()
        shell.execute("container create web")
        # Compile a demo program first
        shell.execute("compile hello")
        output = shell.execute("container exec web hello")
        assert "Hello from PyBin!" in output or "VPID" in output

    def test_container_destroy(self) -> None:
        """Shell 'container destroy' removes a container."""
        _kernel, shell = _booted_shell()
        shell.execute("container create web")
        output = shell.execute("container destroy web")
        assert "Destroyed" in output

    def test_container_no_args_shows_usage(self) -> None:
        """Shell 'container' without args shows usage."""
        _kernel, shell = _booted_shell()
        output = shell.execute("container")
        assert "Usage:" in output

    def test_container_unknown_subcommand(self) -> None:
        """Shell 'container xyz' shows usage."""
        _kernel, shell = _booted_shell()
        output = shell.execute("container xyz")
        assert "Usage:" in output

    def test_container_demo(self) -> None:
        """Shell 'container demo' runs a demonstration."""
        _kernel, shell = _booted_shell()
        output = shell.execute("container demo")
        assert "container" in output.lower() or "Container" in output
