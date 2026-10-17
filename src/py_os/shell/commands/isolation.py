"""Containers and clusters commands -- boxing programs up in containers and linking machines into a cluster."""

import contextlib
from collections.abc import Callable

from py_os.io.bridge import Cluster
from py_os.shell.base import MIN_CONTAINER_EXEC_ARGS, ShellBase
from py_os.syscalls import SyscallError, SyscallNumber

# A table of sub-commands: word typed by the user -> the method that handles it.
type _SubcommandTable = dict[str, Callable[[list[str]], str]]


class IsolationCommands(ShellBase):
    """Shell commands for boxing programs up in containers and linking machines into a cluster."""

    def _cmd_container(self, args: list[str]) -> str:
        """Manage containers: create, list, exec, info, destroy, demo."""
        usage = "Usage: container <create|list|exec|info|destroy|demo> [args]"
        if not args:
            return usage
        subcmds: _SubcommandTable = {
            "create": self._cmd_container_create,
            "list": lambda _: self._cmd_container_list(),
            "exec": self._cmd_container_exec,
            "info": self._cmd_container_info,
            "destroy": self._cmd_container_destroy,
            "demo": lambda _: self._cmd_container_demo(),
        }
        handler = subcmds.get(args[0])
        if handler is None:
            return usage
        return handler(args[1:])

    def _cmd_container_create(self, args: list[str]) -> str:
        """Create a new container."""
        if not args:
            return "Usage: container create <name>"
        name = args[0]
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name=name)
            return f"Created container '{result['name']}' (state: {result['state']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_container_list(self) -> str:
        """List all containers."""
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CONTAINER_LIST)
        except SyscallError as e:
            return f"Error: {e}"
        if not result:
            return "No containers running"
        lines = ["NAME        STATE      PROCS  FS_ROOT"]
        lines.extend(
            f"{c['name']:<12s}{c['state']:<11s}{c['processes']:<7d}{c['fs_root']}" for c in result
        )
        return "\n".join(lines)

    def _cmd_container_exec(self, args: list[str]) -> str:
        """Execute a program inside a container."""
        if len(args) < MIN_CONTAINER_EXEC_ARGS:
            return "Usage: container exec <name> <program>"
        name, program_name = args[0], args[1]
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_CONTAINER_EXEC,
                name=name,
                program_name=program_name,
            )
            return f"VPID {result['vpid']} in '{name}':\n{result.get('output', '')}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_container_info(self, args: list[str]) -> str:
        """Show container details."""
        if not args:
            return "Usage: container info <name>"
        name = args[0]
        try:
            info = self._kernel.syscall(SyscallNumber.SYS_CONTAINER_INFO, name=name)
        except SyscallError as e:
            return f"Error: {e}"
        lines = [
            f"Container: {info['name']}",
            f"  State: {info['state']}",
            f"  Processes: {info['processes']}",
            f"  FS root: {info['fs_root']}",
            f"  PID namespace: {info['pid_namespace']}",
            f"  Network: {info['network']}",
        ]
        return "\n".join(lines)

    def _cmd_container_destroy(self, args: list[str]) -> str:
        """Destroy a container."""
        if not args:
            return "Usage: container destroy <name>"
        name = args[0]
        try:
            self._kernel.syscall(SyscallNumber.SYS_CONTAINER_DESTROY, name=name)
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"Destroyed container '{name}'"

    def _cmd_container_demo(self) -> str:
        """Run a container demonstration."""
        lines = ["=== Container Demo ===", ""]
        # Create two containers
        try:
            self._kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="web")
            lines.append("Created container 'web'")
            self._kernel.syscall(SyscallNumber.SYS_CONTAINER_CREATE, name="db")
            lines.append("Created container 'db'")
        except SyscallError as e:
            lines.append(f"Setup: {e}")
        # Run programs
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_CONTAINER_EXEC,
                name="web",
                program_name="hello",
            )
            lines.append(f"Ran 'hello' in web -> VPID {result['vpid']}: {result.get('output', '')}")
        except SyscallError as e:
            lines.append(f"Exec: {e}")
        # List
        try:
            containers = self._kernel.syscall(SyscallNumber.SYS_CONTAINER_LIST)
            lines.append(f"\n{len(containers)} container(s) active")
            lines.extend(f"  {c['name']} ({c['state']})" for c in containers)
        except SyscallError as e:
            lines.append(f"List: {e}")
        # Cleanup
        for name in ("web", "db"):
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_CONTAINER_DESTROY, name=name)
        lines.append("\nContainers cleaned up.")
        return "\n".join(lines)

    def _cmd_cluster(self, args: list[str]) -> str:
        """Manage inter-machine networking: create, add, list, ping, etc."""
        usage = "Usage: cluster <create|add|remove|send|recv|ping|list|dns|demo> [args]"
        if not args:
            return usage
        subcmds: _SubcommandTable = {
            "create": lambda _: self._cmd_cluster_create(),
            "add": lambda _: self._cmd_cluster_add(),
            "remove": self._cmd_cluster_remove,
            "send": self._cmd_cluster_send,
            "recv": lambda _: self._cmd_cluster_recv(),
            "ping": self._cmd_cluster_ping,
            "list": lambda _: self._cmd_cluster_list(),
            "dns": self._cmd_cluster_dns,
            "demo": lambda _: self._cmd_cluster_demo(),
        }
        handler = subcmds.get(args[0])
        if handler is None:
            return usage
        return handler(args[1:])

    def _cmd_cluster_create(self) -> str:
        """Initialize a cluster with this kernel."""
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CLUSTER_CREATE)
            return f"Cluster created. This kernel is ID {result['kernel_id']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_cluster_add(self) -> str:
        """Add a new kernel to the cluster."""
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CLUSTER_ADD)
            return f"Added kernel {result['kernel_id']} to cluster"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_cluster_remove(self, args: list[str]) -> str:
        """Remove a kernel from the cluster."""
        if not args:
            return "Usage: cluster remove <kernel_id>"
        try:
            kid = int(args[0])
            self._kernel.syscall(SyscallNumber.SYS_CLUSTER_REMOVE, kernel_id=kid)
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        else:
            return f"Removed kernel {kid} from cluster"

    def _cmd_cluster_send(self, args: list[str]) -> str:
        """Send a message to another kernel."""
        if len(args) < MIN_CONTAINER_EXEC_ARGS:
            return "Usage: cluster send <kernel_id> <message>"
        try:
            kid = int(args[0])
            msg = " ".join(args[1:])
            self._kernel.syscall(
                SyscallNumber.SYS_CLUSTER_SEND,
                to_id=kid,
                data=msg.encode(),
            )
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        else:
            return f"Sent to kernel {kid}: {msg}"

    def _cmd_cluster_recv(self) -> str:
        """Receive the next message from the cluster."""
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CLUSTER_RECV)
            data = result.get("data")
            if data is None:
                return "No messages"
            return f"Received: {data.decode()}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_cluster_ping(self, args: list[str]) -> str:
        """Ping another kernel."""
        if not args:
            return "Usage: cluster ping <kernel_id>"
        try:
            kid = int(args[0])
            result = self._kernel.syscall(SyscallNumber.SYS_CLUSTER_PING, target_id=kid)
            status = "reachable" if result["reachable"] else "unreachable"
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        else:
            return f"Kernel {kid}: {status}"

    def _cmd_cluster_list(self) -> str:
        """List all kernels in the cluster."""
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CLUSTER_LIST)
        except SyscallError as e:
            return f"Error: {e}"
        if not result:
            return "No kernels in cluster"
        lines = ["ID    STATE      PENDING"]
        lines.extend(f"{k['id']:<6d}{k['state']:<11s}{k['pending']}" for k in result)
        return "\n".join(lines)

    def _cmd_cluster_dns(self, args: list[str]) -> str:
        """Cross-kernel DNS lookup."""
        if len(args) < MIN_CONTAINER_EXEC_ARGS:
            return "Usage: cluster dns <kernel_id> <hostname>"
        try:
            kid = int(args[0])
            hostname = args[1]
            result = self._kernel.syscall(
                SyscallNumber.SYS_CLUSTER_DNS,
                target_id=kid,
                hostname=hostname,
            )
            addr = result.get("address")
            if addr is None:
                return f"{hostname}: not found on kernel {kid}"
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        else:
            return f"{hostname} -> {addr} (via kernel {kid})"

    def _cmd_cluster_demo(self) -> str:
        """Run a cluster demonstration."""
        cluster = Cluster()
        return cluster.demo()

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("container", _cmd_container),
        ("cluster", _cmd_cluster),
    )
