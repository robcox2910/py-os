"""Virtual /proc filesystem — live kernel state as readable files.

In real Linux, ``/proc`` is a **virtual filesystem**.  It looks like a
directory full of files, but nothing is stored on disk.  Every time you
read a file inside ``/proc``, the kernel generates the content on-the-fly
from its live internal state.  This is how tools like ``ps``, ``top``,
and ``free`` actually work — they just read ``/proc`` files.

Think of it like a **magic bulletin board** at school.  Nobody writes real
papers and pins them there.  When you walk up and look at a section, the
information appears automatically from the school's current records.  A new
student arrives → instantly on the board.  Student leaves → entry vanishes.

File tree::

    /proc/
    ├── meminfo          — Memory statistics
    ├── uptime           — System uptime in seconds
    ├── cpuinfo          — Scheduler policy, ready queue size
    ├── [pid]/           — One directory per process
    │   ├── status       — Process metadata
    │   ├── maps         — Memory mappings
    │   └── cmdline      — Process name
    └── self/            — Alias for current running process
        ├── status
        ├── maps
        └── cmdline
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py_os.kernel import Kernel
    from py_os.process.pcb import Process

# Global files that live directly under /proc
_GLOBAL_FILES: frozenset[str] = frozenset({"meminfo", "uptime", "cpuinfo", "stat"})

# Per-process files under /proc/{pid}/
_PER_PROCESS_FILES: list[str] = ["status", "maps", "cmdline", "sched"]


class ProcError(Exception):
    """Raise when a /proc operation fails."""


class ProcFilesystem:
    """Virtual filesystem exposing live kernel state as /proc files.

    Returns ``str`` (not ``bytes``) because /proc files are human-readable
    text generated on-the-fly, unlike real files which store raw bytes.
    """

    def __init__(self, *, kernel: Kernel) -> None:
        """Create a /proc filesystem backed by the given kernel.

        Args:
            kernel: The running kernel whose state is exposed.

        """
        self._kernel = kernel

    @property
    def kernel(self) -> Kernel:
        """Return the backing kernel instance."""
        return self._kernel

    def read(self, path: str) -> str:
        """Read a virtual /proc file and return its generated content.

        Args:
            path: Absolute path starting with ``/proc/``.

        Returns:
            The generated file content as a string.

        Raises:
            ProcError: If the path does not exist in /proc.

        """
        stripped = self._strip_prefix(path)
        parts = stripped.split("/")

        match parts:
            case ["meminfo"]:
                return self._generate_meminfo()
            case ["uptime"]:
                return self._generate_uptime()
            case ["cpuinfo"]:
                return self._generate_cpuinfo()
            case ["stat"]:
                return self._generate_stat()
            case ["self", subfile]:
                pid = self._resolve_self_pid()
                return self._read_process_file(pid, subfile)
            case [pid_str, subfile] if pid_str.isdigit():
                return self._read_process_file(int(pid_str), subfile)
            case _:
                msg = f"No such /proc file: {path}"
                raise ProcError(msg)

    def list_dir(self, path: str) -> list[str]:
        """List entries in a virtual /proc directory.

        Args:
            path: Absolute path starting with ``/proc``.

        Returns:
            Sorted list of entry names.

        Raises:
            ProcError: If the path is not a valid /proc directory.

        """
        stripped = self._strip_prefix(path)

        match stripped:
            case "":
                return self._list_root()
            case "self":
                return list(_PER_PROCESS_FILES)
            case _ if stripped.isdigit():
                pid = int(stripped)
                self._get_process(pid)
                return list(_PER_PROCESS_FILES)
            case _:
                msg = f"Not a /proc directory: {path}"
                raise ProcError(msg)

    # -- Private generators ---------------------------------------------------

    def _generate_meminfo(self) -> str:
        """Generate /proc/meminfo from the memory manager."""
        mem = self._kernel.memory
        assert mem is not None  # noqa: S101
        total = mem.total_frames
        free = mem.free_frames
        used = total - free
        shared = mem.shared_frame_count
        return (
            f"MemTotal:       {total} frames\n"
            f"MemFree:        {free} frames\n"
            f"MemUsed:        {used} frames\n"
            f"Shared:         {shared} frames"
        )

    def _generate_uptime(self) -> str:
        """Generate /proc/uptime from the kernel boot time."""
        return f"{self._kernel.uptime:.2f} seconds"

    def _generate_cpuinfo(self) -> str:
        """Generate /proc/cpuinfo from the scheduler."""
        sched = self._kernel.scheduler
        assert sched is not None  # noqa: S101

        if sched.num_cpus > 1:
            lines = [f"NumCPUs:        {sched.num_cpus}"]
            for cpu_id in range(sched.num_cpus):
                cpu_sched = sched.cpu_scheduler(cpu_id)
                policy_name = type(cpu_sched.policy).__name__
                ready = sched.cpu_ready_count(cpu_id)
                current = sched.cpu_current(cpu_id)
                current_str = (
                    f"pid {current.pid} ({current.name})" if current is not None else "none"
                )
                lines.append(f"CPU {cpu_id}:")
                lines.append(f"  Policy:       {policy_name}")
                lines.append(f"  ReadyQueue:   {ready}")
                lines.append(f"  Current:      {current_str}")
            return "\n".join(lines)

        policy_name = type(sched.policy).__name__
        ready = sched.ready_count
        current = sched.current
        current_str = f"pid {current.pid} ({current.name})" if current is not None else "none"
        return (
            f"Policy:         {policy_name}\nReadyQueue:     {ready}\nCurrent:        {current_str}"
        )

    def _generate_stat(self) -> str:
        """Generate /proc/stat from kernel performance metrics."""
        metrics = self._kernel.perf_metrics()
        return (
            f"CtxSwitches:    {metrics['context_switches']}\n"
            f"TotalCreated:   {metrics['total_created']}\n"
            f"TotalCompleted: {metrics['total_completed']}\n"
            f"AvgWaitTime:    {metrics['avg_wait_time']:.2f} seconds\n"
            f"AvgTurnaround:  {metrics['avg_turnaround_time']:.2f} seconds\n"
            f"AvgResponse:    {metrics['avg_response_time']:.2f} seconds\n"
            f"Throughput:     {metrics['throughput']:.2f} procs/sec\n"
            f"Migrations:     {metrics['migrations']}"
        )

    def _generate_sched(self, pid: int) -> str:
        """Generate /proc/{pid}/sched from per-process timing."""
        proc = self._get_process(pid)
        response = proc.response_time
        turnaround = proc.turnaround_time
        resp_str = f"{response:.2f} seconds" if response is not None else "pending"
        turn_str = f"{turnaround:.2f} seconds" if turnaround is not None else "pending"
        return (
            f"WaitTime:       {proc.wait_time:.2f} seconds\n"
            f"CpuTime:        {proc.cpu_time:.2f} seconds\n"
            f"ResponseTime:   {resp_str}\n"
            f"Turnaround:     {turn_str}"
        )

    def _generate_status(self, pid: int) -> str:
        """Generate /proc/{pid}/status from the process control block."""
        proc = self._get_process(pid)
        thread_count = len(proc.threads)
        cpu_str = str(proc.cpu_id) if proc.cpu_id is not None else "none"
        return (
            f"Name:           {proc.name}\n"
            f"Pid:            {proc.pid}\n"
            f"PPid:           {proc.parent_pid}\n"
            f"State:          {proc.state}\n"
            f"Priority:       {proc.priority}\n"
            f"EffPriority:    {proc.effective_priority}\n"
            f"Threads:        {thread_count}\n"
            f"CPU:            {cpu_str}"
        )

    def _generate_maps(self, pid: int) -> str:
        """Generate /proc/{pid}/maps from memory and mmap state."""
        self._get_process(pid)
        mem = self._kernel.memory
        assert mem is not None  # noqa: S101

        pages = mem.pages_for(pid)
        lines: list[str] = [f"Pages:          {' '.join(str(p) for p in pages)}"]

        regions = self._kernel.mmap_regions(pid)
        for region in regions.values():
            shared_str = "shared" if region.shared else "private"
            lines.append(
                f"Mmap:           {region.path} vpn={region.start_vpn} "
                f"pages={region.num_pages} {shared_str}"
            )

        return "\n".join(lines)

    def _generate_cmdline(self, pid: int) -> str:
        """Generate /proc/{pid}/cmdline — the process name."""
        proc = self._get_process(pid)
        return proc.name

    # -- Helpers ---------------------------------------------------------------

    def _strip_prefix(self, path: str) -> str:
        """Strip the /proc/ prefix and return the remainder.

        Raises:
            ProcError: If the path doesn't start with /proc.

        """
        normalized = path.rstrip("/")
        if normalized == "/proc":
            return ""
        if normalized.startswith("/proc/"):
            return normalized[len("/proc/") :]
        msg = f"Path does not start with /proc: {path}"
        raise ProcError(msg)

    def _resolve_self_pid(self) -> int:
        """Return the PID of the currently running process.

        Raises:
            ProcError: If no process is currently running.

        """
        sched = self._kernel.scheduler
        assert sched is not None  # noqa: S101
        current = sched.current
        if current is None:
            msg = "No currently running process for /proc/self"
            raise ProcError(msg)
        return current.pid

    def _get_process(self, pid: int) -> Process:
        """Look up a process by PID.

        Raises:
            ProcError: If the PID does not exist in the process table.

        """
        proc = self._kernel.processes.get(pid)
        if proc is None:
            msg = f"Process {pid} not found"
            raise ProcError(msg)
        return proc

    def _read_process_file(self, pid: int, subfile: str) -> str:
        """Dispatch a per-process file read.

        Raises:
            ProcError: If the subfile is not recognized.

        """
        match subfile:
            case "status":
                return self._generate_status(pid)
            case "maps":
                return self._generate_maps(pid)
            case "cmdline":
                return self._generate_cmdline(pid)
            case "sched":
                return self._generate_sched(pid)
            case _:
                msg = f"No such file: /proc/{pid}/{subfile}"
                raise ProcError(msg)

    def _list_root(self) -> list[str]:
        """List the root /proc directory entries."""
        entries = sorted(_GLOBAL_FILES)
        entries.append("self")
        for pid in sorted(self._kernel.processes):
            entries.append(str(pid))
        return entries
