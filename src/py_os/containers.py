"""Containers — namespace isolation within a single kernel.

Real containers (like Docker) use **namespaces** to give each container
its own private view of the system.  A process inside a container sees
its own PID 1, its own filesystem root, and its own network — even though
the host kernel is shared.

Think of it like portable classrooms in a school parking lot.  Every
classroom has its own door number (PID namespace), its own cupboard
(mount namespace), and its own phone line (network namespace), but they
all share the same school building (kernel).

Our containers implement the same three namespaces:

- **PID namespace** — processes inside a container see virtual PIDs
  starting from 1, even though the kernel assigns real PIDs globally.
- **Mount namespace** — paths inside a container are translated to a
  subtree of the real filesystem (e.g., ``/`` inside the container
  maps to ``/containers/web/`` on the host).
- **Network namespace** — each container gets its own socket manager
  and DNS resolver, so network traffic is isolated.
"""

from __future__ import annotations

from enum import StrEnum

from py_os.io.dns import DnsResolver
from py_os.io.networking import SocketManager


class ContainerError(Exception):
    """Raise when a container operation fails."""


class ContainerState(StrEnum):
    """Lifecycle states for a container."""

    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"


class PidNamespace:
    """Map virtual PIDs (inside container) to real PIDs (kernel-wide).

    Inside a container, the first process is PID 1 — just like on a
    freshly booted Linux system.  The PID namespace maintains a
    two-way mapping so the kernel can translate between virtual and
    real PIDs.
    """

    def __init__(self) -> None:
        """Create an empty PID namespace."""
        self._virtual_to_real: dict[int, int] = {}
        self._real_to_virtual: dict[int, int] = {}
        self._next_vpid = 1

    def register(self, real_pid: int) -> int:
        """Register a real PID and return the assigned virtual PID."""
        if real_pid in self._real_to_virtual:
            return self._real_to_virtual[real_pid]
        vpid = self._next_vpid
        self._next_vpid += 1
        self._virtual_to_real[vpid] = real_pid
        self._real_to_virtual[real_pid] = vpid
        return vpid

    def real_pid(self, vpid: int) -> int:
        """Translate a virtual PID to its real PID.

        Raises:
            ContainerError: If the virtual PID is not registered.

        """
        if vpid not in self._virtual_to_real:
            msg = f"Virtual PID {vpid} not found in namespace"
            raise ContainerError(msg)
        return self._virtual_to_real[vpid]

    def virtual_pid(self, real_pid: int) -> int:
        """Translate a real PID to its virtual PID.

        Raises:
            ContainerError: If the real PID is not registered.

        """
        if real_pid not in self._real_to_virtual:
            msg = f"Real PID {real_pid} not found in namespace"
            raise ContainerError(msg)
        return self._real_to_virtual[real_pid]

    def unregister(self, real_pid: int) -> None:
        """Remove a process from the namespace."""
        if real_pid not in self._real_to_virtual:
            return
        vpid = self._real_to_virtual.pop(real_pid)
        self._virtual_to_real.pop(vpid, None)

    def virtual_pids(self) -> list[int]:
        """Return all virtual PIDs in this namespace."""
        return sorted(self._virtual_to_real.keys())


class MountNamespace:
    """Translate container paths to real filesystem paths.

    A container with ``fs_root="/containers/web"`` sees ``/index.html``
    as its root, but the kernel stores it at ``/containers/web/index.html``.
    """

    def __init__(self, fs_root: str) -> None:
        """Create a mount namespace rooted at *fs_root*."""
        self._fs_root = fs_root.rstrip("/")

    @property
    def fs_root(self) -> str:
        """Return the real filesystem root for this namespace."""
        return self._fs_root

    def translate_path(self, container_path: str) -> str:
        """Translate a container-relative path to a real path."""
        if container_path == "/":
            return self._fs_root
        clean = container_path.rstrip("/")
        return f"{self._fs_root}{clean}"

    def container_path(self, real_path: str) -> str | None:
        """Translate a real path back to a container path.

        Return ``None`` if the real path is outside this namespace.
        """
        if real_path == self._fs_root:
            return "/"
        prefix = f"{self._fs_root}/"
        if real_path.startswith(prefix):
            return "/" + real_path[len(prefix) :]
        return None


class NetworkNamespace:
    """Isolated network stack for a container.

    Each container gets its own socket manager and DNS resolver,
    so network traffic between containers is completely separate.

    Note: Network isolation is not yet wired into kernel exec —
    containers currently share the host kernel's network stack.
    This class documents the intended design for future work.
    """

    def __init__(self) -> None:
        """Create an isolated network namespace."""
        self._socket_manager = SocketManager()
        self._dns_resolver = DnsResolver()

    @property
    def socket_manager(self) -> SocketManager:
        """Return this namespace's socket manager."""
        return self._socket_manager

    @property
    def dns_resolver(self) -> DnsResolver:
        """Return this namespace's DNS resolver."""
        return self._dns_resolver


class Container:
    """A lightweight isolated environment within the kernel.

    Each container has its own PID, mount, and network namespaces,
    and tracks which real processes belong to it.
    """

    def __init__(
        self,
        name: str,
        *,
        fs_root: str,
    ) -> None:
        """Create a container with the given name and filesystem root."""
        self._name = name
        self._state = ContainerState.CREATED
        self._pid_namespace = PidNamespace()
        self._mount_namespace = MountNamespace(fs_root)
        self._network_namespace = NetworkNamespace()
        self._process_pids: set[int] = set()

    @property
    def name(self) -> str:
        """Return the container name."""
        return self._name

    @property
    def state(self) -> ContainerState:
        """Return the current container state."""
        return self._state

    @property
    def pid_namespace(self) -> PidNamespace:
        """Return the PID namespace."""
        return self._pid_namespace

    @property
    def mount_namespace(self) -> MountNamespace:
        """Return the mount namespace."""
        return self._mount_namespace

    @property
    def network_namespace(self) -> NetworkNamespace:
        """Return the network namespace."""
        return self._network_namespace

    def start(self) -> None:
        """Transition to RUNNING state.

        Raises:
            ContainerError: If the container is not in CREATED state.

        """
        if self._state is not ContainerState.CREATED:
            msg = f"Cannot start container '{self._name}': state is {self._state}"
            raise ContainerError(msg)
        self._state = ContainerState.RUNNING

    def stop(self) -> None:
        """Transition to STOPPED state.

        Raises:
            ContainerError: If the container is not in RUNNING state.

        """
        if self._state is not ContainerState.RUNNING:
            msg = f"Cannot stop container '{self._name}': state is {self._state}"
            raise ContainerError(msg)
        self._state = ContainerState.STOPPED

    def add_process(self, real_pid: int) -> int:
        """Add a process and return its virtual PID."""
        self._process_pids.add(real_pid)
        return self._pid_namespace.register(real_pid)

    def remove_process(self, real_pid: int) -> None:
        """Remove a process from the container."""
        self._process_pids.discard(real_pid)
        self._pid_namespace.unregister(real_pid)

    def contains_process(self, real_pid: int) -> bool:
        """Check whether a process belongs to this container."""
        return real_pid in self._process_pids

    @property
    def process_count(self) -> int:
        """Return the number of processes in this container."""
        return len(self._process_pids)


class ContainerManager:
    """Manage the lifecycle of all containers in the system.

    The kernel delegates container operations to this manager,
    which tracks containers by name and maps processes to their
    containers.
    """

    def __init__(self) -> None:
        """Create an empty container manager."""
        self._containers: dict[str, Container] = {}

    def create(self, name: str, *, fs_root: str) -> Container:
        """Create a new container.

        Raises:
            ContainerError: If a container with this name already exists.

        """
        if name in self._containers:
            msg = f"Container '{name}' already exists"
            raise ContainerError(msg)
        container = Container(name, fs_root=fs_root)
        self._containers[name] = container
        return container

    def get(self, name: str) -> Container:
        """Look up a container by name.

        Raises:
            ContainerError: If no container with this name exists.

        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ContainerError(msg)
        return self._containers[name]

    def destroy(self, name: str) -> None:
        """Destroy a container.

        Raises:
            ContainerError: If no container with this name exists.

        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ContainerError(msg)
        container = self._containers[name]
        if container.state is ContainerState.RUNNING:
            container.stop()
        del self._containers[name]

    def list_containers(self) -> list[dict[str, str | int]]:
        """Return a summary of all containers."""
        return [
            {
                "name": c.name,
                "state": c.state.value,
                "processes": c.process_count,
                "fs_root": c.mount_namespace.fs_root,
            }
            for c in self._containers.values()
        ]

    def container_for_process(self, real_pid: int) -> Container | None:
        """Find which container (if any) owns a process."""
        for container in self._containers.values():
            if container.contains_process(real_pid):
                return container
        return None
