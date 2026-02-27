"""Interactive tutorial system for learning OS concepts.

Each lesson is a guided walkthrough that uses **real syscalls** to
demonstrate a subsystem.  The goal is to make the OS feel tangible:
you see processes being created, memory being allocated, files being
written, and signals being sent — all with friendly commentary.

Lessons are designed for someone who knows basic Python but is new
to operating-system concepts.  Each one:

1. Opens with a **real-world analogy** (recipes, warehouses, libraries…).
2. Walks through **numbered steps** using actual syscalls.
3. Ends with a **summary** and a pointer to the next lesson.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from py_os.process.signals import Signal
from py_os.syscalls import SyscallError, SyscallNumber

if TYPE_CHECKING:
    from py_os.kernel import Kernel

_LESSON_ORDER: list[str] = [
    "filesystem",
    "ipc",
    "memory",
    "networking",
    "processes",
    "scheduling",
    "signals",
]


class TutorialRunner:
    """Run interactive lessons that teach OS concepts with real syscalls."""

    def __init__(self, kernel: Kernel) -> None:
        """Create a tutorial runner backed by a running kernel.

        Args:
            kernel: A booted kernel to execute syscalls against.

        """
        self._kernel = kernel
        self._lessons: dict[str, str] = {
            "processes": "Processes — the programs that run on your OS",
            "memory": "Memory — how the OS manages limited space",
            "filesystem": "Filesystem — how files and folders are organised",
            "scheduling": "Scheduling — how the CPU decides who goes next",
            "signals": "Signals — how processes talk with bells and whistles",
            "ipc": "IPC — how processes share data",
            "networking": "Networking — sockets, DNS, and talking to others",
        }

    def list_lessons(self) -> list[str]:
        """Return sorted list of available lesson names."""
        return sorted(self._lessons)

    def run(self, name: str) -> str:
        """Run a lesson by name and return its formatted output.

        Args:
            name: The lesson name (e.g. ``"processes"``).

        Returns:
            Multi-line string with the lesson content.

        Raises:
            KeyError: If the lesson name is not recognised.

        """
        runners = {
            "processes": self._lesson_processes,
            "memory": self._lesson_memory,
            "filesystem": self._lesson_filesystem,
            "scheduling": self._lesson_scheduling,
            "signals": self._lesson_signals,
            "ipc": self._lesson_ipc,
            "networking": self._lesson_networking,
        }
        runner = runners.get(name)
        if runner is None:
            msg = f"Unknown lesson: {name}"
            raise KeyError(msg)
        return runner()

    def run_all(self) -> str:
        """Run all lessons in order and return combined output."""
        parts: list[str] = []
        for name in _LESSON_ORDER:
            parts.append(self.run(name))
            parts.append("")
        return "\n".join(parts)

    # -- Individual lessons ---------------------------------------------------

    def _lesson_processes(self) -> str:
        """Teach process creation, execution, and lifecycle."""
        lines: list[str] = [
            "=== Lesson: Processes ===",
            "",
            "Think of a process like a recipe being cooked. The recipe (program)",
            "sits in a cookbook until a cook (the CPU) picks it up. Once the cook",
            "starts following the steps, it becomes an active process.",
            "",
        ]

        # Step 1: List existing processes
        lines.append("Step 1: See what's already running")
        try:
            procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
            lines.append(f"  The OS has {len(procs)} process(es) running right now.")
            lines.extend(f"    PID {p['pid']}: {p['name']} ({p['state']})" for p in procs)
        except SyscallError as e:
            lines.append(f"  (Could not list processes: {e})")
        lines.append("")

        # Step 2: Create a new process
        lines.append("Step 2: Create a new process")
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="tutorial-hello", num_pages=1
            )
            pid = result["pid"]
            lines.append(f"  Created process 'tutorial-hello' with PID {pid}.")
            lines.append("  It's now in the READY state — waiting for the CPU.")

            # Step 3: Load and run it
            lines.append("")
            lines.append("Step 3: Load a program and run it")
            self._kernel.syscall(
                SyscallNumber.SYS_EXEC, pid=pid, program=lambda: "Hello from the tutorial!"
            )
            run_result = self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
            lines.append(f"  Output: {run_result['output']}")
            lines.append(f"  Exit code: {run_result['exit_code']}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Summary
        lines.extend(
            [
                "Summary: You learned how processes are created (NEW → READY),",
                "dispatched to the CPU (READY → RUNNING), and complete (→ TERMINATED).",
                "",
                "Next up: 'memory' — learn how the OS manages limited space.",
            ]
        )
        return "\n".join(lines)

    def _lesson_memory(self) -> str:
        """Teach memory management with frames and slab allocation."""
        lines: list[str] = [
            "=== Lesson: Memory ===",
            "",
            "Memory is like a warehouse with numbered shelves. Each shelf",
            "(called a 'frame') can hold one page of data. When a program",
            "needs space, the OS finds empty shelves and assigns them.",
            "",
        ]

        # Step 1: Check current memory
        lines.append("Step 1: Check how much memory we have")
        try:
            mem: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
            lines.append(f"  Total frames: {mem['total_frames']}")
            lines.append(f"  Free frames:  {mem['free_frames']}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 2: Create a slab cache
        lines.append("Step 2: Create a slab cache (a fast memory pool)")
        lines.append("  Slabs are like pre-cut shelving units — all the same size,")
        lines.append("  ready for quick allocation.")
        try:
            self._kernel.syscall(SyscallNumber.SYS_SLAB_CREATE, name="tutorial-cache", obj_size=32)
            lines.append("  Created slab cache 'tutorial-cache' (32 bytes per object).")

            # Step 3: Allocate from the slab
            lines.append("")
            lines.append("Step 3: Allocate an object from the slab")
            alloc: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SLAB_ALLOC, cache="tutorial-cache"
            )
            lines.append(
                f"  Allocated object: slab {alloc['slab_index']}, slot {alloc['slot_index']}"
            )

            # Step 4: Free it back
            lines.append("")
            lines.append("Step 4: Free the object back to the slab")
            self._kernel.syscall(
                SyscallNumber.SYS_SLAB_FREE,
                cache="tutorial-cache",
                slab_index=alloc["slab_index"],
                slot_index=alloc["slot_index"],
            )
            lines.append("  Object freed — the shelf is available again.")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        lines.extend(
            [
                "Summary: You learned that memory is divided into frames, and",
                "slab caches provide fast allocation for same-sized objects.",
                "",
                "Next up: 'filesystem' — learn how files and folders work.",
            ]
        )
        return "\n".join(lines)

    def _lesson_filesystem(self) -> str:
        """Teach filesystem operations: directories, files, links."""
        lines: list[str] = [
            "=== Lesson: Filesystem ===",
            "",
            "The filesystem is like a library. Directories are shelves, and",
            "files are the books on those shelves. Each book has a label (name)",
            "and contents (data).",
            "",
        ]

        # Step 1: Create a directory
        lines.append("Step 1: Create a directory (a new shelf)")
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/tutorial")
            lines.append("  Created /tutorial")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 2: Create and write a file
        lines.append("Step 2: Create a file and write some data")
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/tutorial/hello.txt")
            self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FILE,
                path="/tutorial/hello.txt",
                data=b"Hello from the tutorial!",
            )
            lines.append("  Wrote 'Hello from the tutorial!' to /tutorial/hello.txt")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 3: Read the file back
        lines.append("Step 3: Read the file back")
        try:
            data: str = self._kernel.syscall(
                SyscallNumber.SYS_READ_FILE, path="/tutorial/hello.txt"
            )
            lines.append(f"  Contents: {data}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 4: Create a link
        lines.append("Step 4: Create a hard link (two names, one book)")
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_LINK,
                target="/tutorial/hello.txt",
                link_path="/tutorial/greeting.txt",
            )
            lines.append("  Linked /tutorial/greeting.txt → /tutorial/hello.txt")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Cleanup
        self._cleanup_fs("/tutorial/greeting.txt", "/tutorial/hello.txt", "/tutorial")

        lines.extend(
            [
                "Summary: You learned how to create directories and files,",
                "write and read data, and link files together.",
                "",
                "Next up: 'scheduling' — learn how the CPU picks which process runs.",
            ]
        )
        return "\n".join(lines)

    def _lesson_scheduling(self) -> str:
        """Teach scheduler policies and how the CPU picks the next process."""
        lines: list[str] = [
            "=== Lesson: Scheduling ===",
            "",
            "Imagine a sports day with only one track. Multiple runners want",
            "to race, but only one can run at a time. The coach (scheduler)",
            "decides the order using different strategies.",
            "",
        ]

        # Step 1: Check current policy
        lines.append("Step 1: See the current scheduling policy")
        try:
            info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
            lines.append(f"  Current policy: {info['policy']}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 2: Explain policies
        lines.append("Step 2: The different coaching strategies")
        lines.append("  FCFS (First Come, First Served) — whoever arrives first runs first.")
        lines.append("  Round Robin — everyone gets a short turn, then goes to the back.")
        lines.append("  Priority — fastest runners go first.")
        lines.append("  Aging — like Priority, but slow runners gradually move up.")
        lines.append("  CFS — tracks who has run least and picks them.")
        lines.append("")

        # Step 3: Check performance metrics
        lines.append("Step 3: Check performance metrics")
        try:
            metrics: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append(f"  Context switches: {metrics['context_switches']}")
            lines.append(f"  Processes created: {metrics['total_created']}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        lines.extend(
            [
                "Summary: You learned that the scheduler picks which process",
                "gets the CPU, and different policies have different trade-offs.",
                "",
                "Next up: 'signals' — learn how processes communicate with bells.",
            ]
        )
        return "\n".join(lines)

    def _lesson_signals(self) -> str:
        """Teach signal sending and handler registration."""
        lines: list[str] = [
            "=== Lesson: Signals ===",
            "",
            "Signals are like bells in a school. A bell rings (signal sent)",
            "and everyone knows what to do — stop for lunch, go to class,",
            "or evacuate. Each bell has a default meaning, but you can",
            "register a custom handler ('when this bell rings, do THIS').",
            "",
        ]

        # Step 1: Create a process to signal
        lines.append("Step 1: Create a process we can send signals to")
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="signal-target", num_pages=1
            )
            pid = result["pid"]
            lines.append(f"  Created 'signal-target' with PID {pid}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
            return "\n".join(lines)
        lines.append("")

        # Step 2: Register a handler
        lines.append("Step 2: Register a signal handler")
        self._signal_received: list[str] = []

        def _log_handler() -> None:
            self._signal_received.append("SIGUSR1")

        try:
            self._kernel.syscall(
                SyscallNumber.SYS_REGISTER_HANDLER,
                pid=pid,
                signal=Signal.SIGUSR1,
                handler=_log_handler,
            )
            lines.append(f"  Registered handler for SIGUSR1 on PID {pid}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 3: Send a signal
        lines.append("Step 3: Send a SIGUSR1 signal")
        try:
            self._kernel.syscall(SyscallNumber.SYS_SEND_SIGNAL, pid=pid, signal=Signal.SIGUSR1)
            lines.append(f"  Sent SIGUSR1 to PID {pid} — the handler was invoked!")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 4: Terminate with SIGTERM
        lines.append("Step 4: Send SIGTERM to terminate the process")
        try:
            self._kernel.syscall(SyscallNumber.SYS_SEND_SIGNAL, pid=pid, signal=Signal.SIGTERM)
            lines.append(f"  Sent SIGTERM to PID {pid} — process terminated.")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        lines.extend(
            [
                "Summary: You learned that signals are notifications sent to",
                "processes, and handlers let you customise the response.",
                "",
                "Next up: 'ipc' — learn how processes share data.",
            ]
        )
        return "\n".join(lines)

    def _lesson_ipc(self) -> str:
        """Teach inter-process communication via shared memory."""
        lines: list[str] = [
            "=== Lesson: IPC (Inter-Process Communication) ===",
            "",
            "Sometimes processes need to share data — like co-workers",
            "passing notes through a shared mailbox. Shared memory is",
            "one of the fastest ways to do this.",
            "",
        ]

        # Step 1: Create shared memory
        init_pid = 1
        lines.append("Step 1: Create a shared memory region")
        try:
            shm: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_CREATE,
                name="tutorial-shm",
                size=64,
                pid=init_pid,
            )
            lines.append(f"  Created shared memory 'tutorial-shm' ({shm['num_pages']} pages)")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
            return "\n".join(lines)
        lines.append("")

        # Step 2: Attach a process
        lines.append("Step 2: Attach a process to the shared memory")
        try:
            self._kernel.syscall(SyscallNumber.SYS_SHM_ATTACH, name="tutorial-shm", pid=init_pid)
            lines.append(f"  PID {init_pid} attached to 'tutorial-shm'")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 3: Write data
        lines.append("Step 3: Write a message into shared memory")
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SHM_WRITE,
                name="tutorial-shm",
                pid=init_pid,
                data="Hello from shared memory!",
            )
            lines.append("  Wrote: 'Hello from shared memory!'")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 4: Read data back
        lines.append("Step 4: Read the message back")
        try:
            read_result = self._kernel.syscall(
                SyscallNumber.SYS_SHM_READ, name="tutorial-shm", pid=init_pid
            )
            lines.append(f"  Read: '{read_result['data']}'")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Cleanup
        with contextlib.suppress(SyscallError):
            self._kernel.syscall(SyscallNumber.SYS_SHM_DESTROY, name="tutorial-shm")

        lines.extend(
            [
                "Summary: You learned that shared memory lets processes",
                "read and write the same data region — fast but needs care.",
                "",
                "Next up: 'networking' — learn about sockets and DNS.",
            ]
        )
        return "\n".join(lines)

    def _lesson_networking(self) -> str:
        """Teach networking: DNS, sockets, client-server."""
        lines: list[str] = [
            "=== Lesson: Networking ===",
            "",
            "Networking is like a phone system. DNS is the phone book",
            "(name → number), and sockets are the phone lines you use",
            "to make calls and send messages.",
            "",
        ]

        # Step 1: Register a DNS name
        lines.append("Step 1: Register a DNS name")
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname="tutorial.pyos",
                address="10.0.0.1",
            )
            lines.append("  Registered: tutorial.pyos → 10.0.0.1")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 2: Look it up
        lines.append("Step 2: Look up the DNS name")
        try:
            address: str = self._kernel.syscall(
                SyscallNumber.SYS_DNS_LOOKUP, hostname="tutorial.pyos"
            )
            lines.append(f"  DNS lookup: tutorial.pyos → {address}")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        # Step 3: Create a server socket
        lines.append("Step 3: Create a server socket")
        try:
            server: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            server_id = int(str(server["sock_id"]))
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_BIND,
                sock_id=server_id,
                address="10.0.0.1",
                port=80,
            )
            self._kernel.syscall(SyscallNumber.SYS_SOCKET_LISTEN, sock_id=server_id)
            lines.append(f"  Server listening on 10.0.0.1:80 (sock_id={server_id})")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
            return "\n".join(lines)
        lines.append("")

        # Step 4: Connect and send a message
        lines.append("Step 4: Connect a client and send a message")
        try:
            client: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SOCKET_CREATE)
            client_id = int(str(client["sock_id"]))
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_CONNECT,
                sock_id=client_id,
                address="10.0.0.1",
                port=80,
            )
            self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_SEND, sock_id=client_id, data=b"Hello, server!"
            )
            lines.append("  Client sent: 'Hello, server!'")

            # Accept and receive on server side
            accept_result: dict[str, object] | None = self._kernel.syscall(
                SyscallNumber.SYS_SOCKET_ACCEPT, sock_id=server_id
            )
            if accept_result is not None:
                conn_id = int(str(accept_result["sock_id"]))
                recv_data: bytes = self._kernel.syscall(
                    SyscallNumber.SYS_SOCKET_RECV, sock_id=conn_id
                )
                lines.append(f"  Server received: '{recv_data.decode()}'")
        except SyscallError as e:
            lines.append(f"  (Error: {e})")
        lines.append("")

        lines.extend(
            [
                "Summary: You learned that DNS maps names to addresses,",
                "sockets provide bidirectional communication channels,",
                "and the client-server model is how networked programs talk.",
                "",
                "Congratulations — you've completed all the tutorials!",
            ]
        )
        return "\n".join(lines)

    # -- Helpers --------------------------------------------------------------

    def _cleanup_fs(self, *paths: str) -> None:
        """Remove filesystem paths silently (best-effort cleanup)."""
        for path in paths:
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path=path)
