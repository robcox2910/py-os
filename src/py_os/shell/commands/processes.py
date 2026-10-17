"""Processes and scheduling commands -- running programs, jobs, signals, threads, the scheduler and performance tools."""

import contextlib
from collections.abc import Callable
from typing import ClassVar

from py_os.process.binary import DEMO_PROGRAMS, BinaryLoader, BinaryLoaderError
from py_os.process.signals import Signal
from py_os.shell.base import ShellBase
from py_os.syscalls import SyscallError, SyscallNumber

# A signal handler: something to run when a signal arrives.
type _SignalHandler = Callable[[], None]


# A table of sub-commands: word typed by the user -> the method that handles it.
type _SubcommandTable = dict[str, Callable[[list[str]], str]]


class ProcessCommands(ShellBase):
    """Shell commands for running programs, jobs, signals, threads, the scheduler and performance tools."""

    def _cmd_ps(self, _args: list[str]) -> str:
        """Show running processes."""
        procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        lines = ["PID    CPU  STATE       NAME"]
        for p in procs:
            cpu = str(p["cpu_id"]) if p["cpu_id"] is not None else "-"
            lines.append(f"{p['pid']:<6} {cpu:<4} {p['state']!s:<11} {p['name']}")
        return "\n".join(lines)

    def _cmd_kill(self, args: list[str]) -> str:
        """Terminate a process by PID."""
        if not args:
            return "Usage: kill <pid>"

        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"

        try:
            self._kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=pid)
        except SyscallError as e:
            return f"Error: {e}"
        return f"Process {pid} terminated."

    def _cmd_signal(self, args: list[str]) -> str:
        """Send a signal to a process."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: signal <pid> <SIGNAL>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            sig = Signal[args[1]]
        except KeyError:
            return f"Error: unknown signal '{args[1]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SEND_SIGNAL, pid=pid, signal=sig)
        except SyscallError as e:
            return f"Error: {e}"
        return f"Signal {sig.name} delivered to pid {pid}."

    def _cmd_top(self, _args: list[str]) -> str:
        """Show system status dashboard."""
        info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SYSINFO)
        uptime = float(str(info["uptime"]))
        lines = [
            "=== PyOS System Monitor ===",
            f"Uptime:      {uptime:.2f}s",
            f"Memory:      {info['memory_free']}/{info['memory_total']} frames free",
            f"Processes:   {info['process_count']}",
            f"Devices:     {info['device_count']}",
            f"User:        {info['current_user']}",
            f"Env vars:    {info['env_count']}",
            f"Log entries: {info['log_count']}",
        ]
        return "\n".join(lines)

    def _cmd_jobs(self, _args: list[str]) -> str:
        """List background jobs."""
        jobs = self._jobs.list_jobs()
        if not jobs:
            return "No background jobs."
        return "\n".join(str(j) for j in jobs)

    def _cmd_bg(self, args: list[str]) -> str:
        """Add a process as a background job."""
        if not args:
            return "Usage: bg <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        # Verify the process exists
        procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        proc = next((p for p in procs if p["pid"] == pid), None)
        if proc is None:
            return f"Error: process {pid} not found"
        name = str(proc["name"])
        job = self._jobs.add(pid=pid, name=name)
        return str(job)

    def _cmd_fg(self, args: list[str]) -> str:
        """Bring a background job to the foreground.

        If the job has captured output (from ``run ... &``), display it.
        Otherwise fall back to the standard "moved to foreground" message
        (for jobs created via ``bg``).
        """
        if not args:
            return "Usage: fg <job_id>"
        try:
            job_id = int(args[0])
        except ValueError:
            return f"Error: invalid job id '{args[0]}'"
        job = self._jobs.get(job_id)
        if job is None:
            return f"Error: job {job_id} not found"
        self._jobs.remove(job_id)
        if job.output is not None:
            return job.output
        return f"{job.name} (pid={job.pid}) moved to foreground."

    def _cmd_waitjob(self, args: list[str]) -> str:
        """Collect output from background jobs.

        ``waitjob``         — collect all jobs
        ``waitjob <job_id>`` — collect a specific job

        Unlike ``wait`` (kernel-level parent-child semantics), ``waitjob``
        is a shell-level concept for retrieving background job output.
        """
        if not args:
            jobs = self._jobs.list_jobs()
            if not jobs:
                return "No background jobs."
            outputs: list[str] = []
            for job in jobs:
                header = f"[{job.job_id}] {job.name}:"
                body = job.output if job.output is not None else "(no output)"
                outputs.append(f"{header}\n{body}")
                self._jobs.remove(job.job_id)
            return "\n".join(outputs)
        try:
            job_id = int(args[0])
        except ValueError:
            return f"Error: invalid job id '{args[0]}'"
        job = self._jobs.get(job_id)
        if job is None:
            return f"Error: job {job_id} not found"
        self._jobs.remove(job_id)
        if job.output is not None:
            return job.output
        return f"{job.name} (pid={job.pid}) — no captured output."

    def _cmd_fork(self, args: list[str]) -> str:
        """Fork a process, creating a child copy."""
        if not args:
            return "Usage: fork <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_FORK, parent_pid=pid)
            return f"Forked pid {pid} → child pid {result['child_pid']} ({result['name']})"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_pstree(self, _args: list[str]) -> str:
        """Show the process tree (parent-child hierarchy)."""
        procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        if not procs:
            return "No processes."
        # Build parent → children mapping
        by_pid: dict[int, dict[str, object]] = {int(str(p["pid"])): p for p in procs}
        children: dict[int | None, list[int]] = {}
        for p in procs:
            parent_pid = p["parent_pid"]
            parent_key: int | None = int(str(parent_pid)) if parent_pid is not None else None
            children.setdefault(parent_key, []).append(int(str(p["pid"])))

        lines: list[str] = []

        def _walk(pid: int, prefix: str, *, is_last: bool) -> None:
            proc = by_pid[pid]
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{proc['name']} (pid={pid})")
            kids = children.get(pid, [])
            for i, child_pid in enumerate(kids):
                extension = "    " if is_last else "│   "
                _walk(child_pid, prefix + extension, is_last=i == len(kids) - 1)

        # Start from root processes (no parent)
        roots = children.get(None, [])
        for i, root_pid in enumerate(roots):
            _walk(root_pid, "", is_last=i == len(roots) - 1)

        return "\n".join(lines) if lines else "No processes."

    def _cmd_threads(self, args: list[str]) -> str:
        """List threads of a process."""
        if not args:
            return "Usage: threads <pid>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            threads: list[dict[str, object]] = self._kernel.syscall(
                SyscallNumber.SYS_LIST_THREADS, pid=pid
            )
        except SyscallError as e:
            return f"Error: {e}"
        lines = [f"Threads for pid {pid}:"]
        lines.extend(f"  TID {t['tid']:<4} {t['state']!s:<11} {t['name']}" for t in threads)
        return "\n".join(lines)

    def _cmd_run(self, args: list[str]) -> str:
        """Create a process, load a built-in or binary program, and run it."""
        if args and args[0].startswith("/"):
            return self._run_binary(args[0])
        result = self._create_and_run_program(args)
        if isinstance(result, str):
            return result
        _pid, output, exit_code = result
        return f"{output}\n[exit code: {exit_code}]"

    def _run_binary(self, path: str) -> str:
        """Load a PyBin binary from the filesystem and run it."""
        try:
            data = self._kernel.syscall(SyscallNumber.SYS_READ_FILE, path=path)
        except SyscallError as e:
            return f"Error: {e}"
        try:
            program = BinaryLoader.load(data)
        except BinaryLoaderError as e:
            return f"Error loading binary: {e}"
        try:
            result = self._kernel.syscall(SyscallNumber.SYS_CREATE_PROCESS, name=path, num_pages=1)
            pid: int = result["pid"]
            self._kernel.syscall(SyscallNumber.SYS_EXEC, pid=pid, program=program)
            run_result = self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
            output: str = run_result["output"]
            exit_code: int = run_result["exit_code"]
        except SyscallError as e:
            return f"Error: {e}"
        else:
            return f"{output}\n[exit code: {exit_code}]"

    def _cmd_scheduler(self, args: list[str]) -> str:  # noqa: PLR0911
        """Show or switch the scheduling policy."""
        if not args:
            return self._cmd_scheduler_show()
        match args[0]:
            case "fcfs" | "rr" | "priority" | "aging":
                return self._cmd_scheduler_switch(args[0], args[1:])
            case "mlfq":
                return self._cmd_scheduler_mlfq(args[1:])
            case "cfs":
                return self._cmd_scheduler_cfs(args[1:])
            case "boost":
                return self._cmd_scheduler_boost()
            case "balance":
                return self._cmd_scheduler_balance()
            case _:
                return (
                    f"Error: unknown policy '{args[0]}'."
                    " Use fcfs, rr, priority, aging, mlfq, cfs, or balance."
                )

    def _cmd_scheduler_show(self) -> str:
        """Display the current scheduling policy name."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
        num_cpus = result.get("num_cpus", 1)
        cpu_info = f" ({num_cpus} CPUs)" if int(str(num_cpus)) > 1 else ""
        return f"Current policy: {result['policy']}{cpu_info}"

    def _cmd_scheduler_switch(self, name: str, args: list[str]) -> str:
        """Switch the scheduling policy via syscall."""
        if name == "rr":
            if not args:
                return "Usage: scheduler rr <quantum>"
            try:
                quantum = int(args[0])
            except ValueError:
                return f"Error: invalid quantum '{args[0]}'"
            try:
                result: str = self._kernel.syscall(
                    SyscallNumber.SYS_SET_SCHEDULER,
                    policy=name,
                    quantum=quantum,
                )
            except SyscallError as e:
                return f"Error: {e}"
            return result
        try:
            result = self._kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                policy=name,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_scheduler_mlfq(self, args: list[str]) -> str:
        """Switch to MLFQ with optional num_levels and base_quantum."""
        kwargs: dict[str, int | str] = {"policy": "mlfq"}
        if args:
            try:
                kwargs["num_levels"] = int(args[0])
            except ValueError:
                return f"Error: invalid num_levels '{args[0]}'"
        if len(args) >= 2:  # noqa: PLR2004
            try:
                kwargs["base_quantum"] = int(args[1])
            except ValueError:
                return f"Error: invalid base_quantum '{args[1]}'"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                **kwargs,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_scheduler_cfs(self, args: list[str]) -> str:
        """Switch to CFS with optional base_slice."""
        kwargs: dict[str, int | str] = {"policy": "cfs"}
        if args:
            try:
                kwargs["base_slice"] = int(args[0])
            except ValueError:
                return f"Error: invalid base_slice '{args[0]}'"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_SET_SCHEDULER,
                **kwargs,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_scheduler_boost(self) -> str:
        """Trigger an MLFQ priority boost via syscall."""
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_SCHEDULER_BOOST)
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_handle(self, args: list[str]) -> str:
        """Register a signal handler for a process.

        Built-in actions:
            - ``log`` — store the signal name in env var
              ``_LAST_SIGNAL_{pid}``.
            - ``ignore`` — suppress the signal's default action.
        """
        min_args = 3
        if len(args) < min_args:
            return "Usage: handle <pid> <SIGNAL> <log|ignore>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            sig = Signal[args[1]]
        except KeyError:
            return f"Error: unknown signal '{args[1]}'"

        action_name = args[2]
        match action_name:
            case "log":

                def _log_handler(_pid: int = pid, _sig: Signal = sig) -> None:
                    self._kernel.syscall(
                        SyscallNumber.SYS_SET_ENV,
                        key=f"_LAST_SIGNAL_{_pid}",
                        value=_sig.name,
                    )

                handler: _SignalHandler = _log_handler
            case "ignore":

                def _ignore_handler() -> None:
                    pass

                handler = _ignore_handler
            case _:
                return f"Error: unknown action '{action_name}'. Use log or ignore."

        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_REGISTER_HANDLER,
                pid=pid,
                signal=sig,
                handler=handler,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_wait(self, args: list[str]) -> str:
        """Wait for any child of a parent process to terminate."""
        if not args:
            return "Usage: wait <parent_pid>"
        try:
            parent_pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            result_wait: dict[str, object] | None = self._kernel.syscall(
                SyscallNumber.SYS_WAIT, parent_pid=parent_pid
            )
        except SyscallError as e:
            return f"Error: {e}"
        if result_wait is None:
            return f"Process {parent_pid} is now waiting for a child."
        return (
            f"Collected child pid {result_wait['child_pid']}"
            f" (exit_code={result_wait['exit_code']}"
            f", output={result_wait['output']!r})"
        )

    def _cmd_waitpid(self, args: list[str]) -> str:
        """Wait for a specific child process to terminate."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: waitpid <parent_pid> <child_pid>"
        try:
            parent_pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            child_pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        try:
            result_waitpid: dict[str, object] | None = self._kernel.syscall(
                SyscallNumber.SYS_WAITPID,
                parent_pid=parent_pid,
                child_pid=child_pid,
            )
        except SyscallError as e:
            return f"Error: {e}"
        if result_waitpid is None:
            return f"Process {parent_pid} is now waiting for child {child_pid}."
        return (
            f"Collected child pid {result_waitpid['child_pid']}"
            f" (exit_code={result_waitpid['exit_code']}"
            f", output={result_waitpid['output']!r})"
        )

    def _cmd_proc(self, args: list[str]) -> str:
        """/proc virtual filesystem — inspect live kernel state."""
        dispatch: _SubcommandTable = {
            "demo": lambda _a: self._cmd_proc_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: proc <demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_proc_demo(self) -> str:
        """Walk through the /proc virtual filesystem."""
        lines: list[str] = [
            "=== /proc Virtual Filesystem Demo ===",
            "",
            "/proc is like a magic bulletin board. Nobody writes real papers and",
            "pins them there. When you look at a section, the information appears",
            "automatically from the school's current records.",
            "",
        ]

        # Step 1: List /proc root
        try:
            entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_PROC_LIST, path="/proc")
            lines.append("Step 1: ls /proc — what's on the bulletin board?")
            lines.append(f"  {', '.join(entries)}")
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 1 failed: {e}")
            return "\n".join(lines)

        # Step 2: Read global files
        lines.append("Step 2: Reading global /proc files...")
        for name in ("meminfo", "uptime", "cpuinfo"):
            try:
                content: str = self._kernel.syscall(
                    SyscallNumber.SYS_PROC_READ, path=f"/proc/{name}"
                )
                lines.append(f"  cat /proc/{name}:")
                lines.extend(f"    {line}" for line in content.splitlines())
                lines.append("")
            except SyscallError as e:
                lines.append(f"  /proc/{name} failed: {e}")

        # Step 3: Create a demo process and explore its /proc entry
        demo_pid: int | None = None
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="demo_proc", num_pages=2
            )
            demo_pid = int(str(result["pid"]))
            lines.append(f"Step 3: Created process 'demo_proc' (pid {demo_pid})")
            lines.append("")

            # List the process directory
            proc_entries: list[str] = self._kernel.syscall(
                SyscallNumber.SYS_PROC_LIST, path=f"/proc/{demo_pid}"
            )
            lines.append(f"  ls /proc/{demo_pid}: {', '.join(proc_entries)}")
            lines.append("")

            # Read each file
            for fname in proc_entries:
                content = self._kernel.syscall(
                    SyscallNumber.SYS_PROC_READ, path=f"/proc/{demo_pid}/{fname}"
                )
                lines.append(f"  cat /proc/{demo_pid}/{fname}:")
                lines.extend(f"    {line}" for line in content.splitlines())
                lines.append("")
        except SyscallError as e:
            lines.append(f"Step 3 failed: {e}")

        # Cleanup — dispatch then terminate (process must be RUNNING to terminate)
        if demo_pid is not None:
            try:
                dispatched = self._kernel.syscall(SyscallNumber.SYS_DISPATCH)
                if dispatched is not None:
                    self._kernel.syscall(SyscallNumber.SYS_TERMINATE_PROCESS, pid=demo_pid)
            except SyscallError, RuntimeError:
                pass

        lines.append("Virtual files are generated live — no disk storage needed!")
        return "\n".join(lines)

    def _cmd_perf(self, args: list[str]) -> str:
        """Show performance metrics or run a guided demo."""
        dispatch: _SubcommandTable = {
            "demo": lambda _a: self._cmd_perf_demo(),
        }
        if args and args[0] in dispatch:
            return dispatch[args[0]](args[1:])
        return self._cmd_perf_summary()

    def _cmd_perf_summary(self) -> str:
        """Format a performance metrics summary."""
        try:
            metrics: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
        except SyscallError as e:
            return f"Error: {e}"
        return (
            "=== PyOS Performance Metrics ===\n"
            f"Context switches:    {metrics['context_switches']}\n"
            f"Processes created:   {metrics['total_created']}\n"
            f"Processes completed: {metrics['total_completed']}\n"
            f"Avg wait time:       {float(str(metrics['avg_wait_time'])):.2f}s\n"
            f"Avg turnaround:      {float(str(metrics['avg_turnaround_time'])):.2f}s\n"
            f"Avg response:        {float(str(metrics['avg_response_time'])):.2f}s\n"
            f"Throughput:          {float(str(metrics['throughput'])):.2f} procs/sec\n"
            f"Migrations:          {metrics['migrations']}"
        )

    def _cmd_perf_demo(self) -> str:
        """Walk through performance metrics with a guided demo."""
        lines: list[str] = [
            "=== Performance Metrics Demo ===",
            "",
            "Imagine a sports day. Every time a runner steps up to the start line,",
            "a helper clicks a stopwatch. When the runner starts, the helper notes",
            "how long they waited. When they finish, we record the total race time.",
            "",
        ]

        # Step 1: Show initial metrics
        try:
            metrics: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append("Step 1: Initial metrics (before any work)")
            lines.append(f"  Context switches:    {metrics['context_switches']}")
            lines.append(f"  Processes created:   {metrics['total_created']}")
            lines.append(f"  Processes completed: {metrics['total_completed']}")
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 1 failed: {e}")
            return "\n".join(lines)

        # Step 2: Create and run a process
        demo_pid: int | None = None
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="perf_demo", num_pages=1
            )
            demo_pid = int(str(result["pid"]))
            self._kernel.syscall(
                SyscallNumber.SYS_EXEC,
                pid=demo_pid,
                program=lambda: "demo output",
            )
            self._kernel.syscall(SyscallNumber.SYS_RUN, pid=demo_pid)

            metrics = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append("Step 2: After creating and running one process")
            lines.append(f"  Context switches:    {metrics['context_switches']}")
            lines.append(f"  Processes completed: {metrics['total_completed']}")
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 2 failed: {e}")

        # Step 3: Create and run multiple processes
        try:
            for name in ("worker_a", "worker_b", "worker_c"):
                r: dict[str, object] = self._kernel.syscall(
                    SyscallNumber.SYS_CREATE_PROCESS, name=name, num_pages=1
                )
                pid = int(str(r["pid"]))
                self._kernel.syscall(
                    SyscallNumber.SYS_EXEC,
                    pid=pid,
                    program=lambda: "batch output",
                )
                self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)

            lines.append("Step 3: After running 3 more processes")
            metrics = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            lines.append(f"  Processes created:   {metrics['total_created']}")
            lines.append(f"  Processes completed: {metrics['total_completed']}")
            lines.append(f"  Avg wait time:       {float(str(metrics['avg_wait_time'])):.4f}s")
            lines.append(
                f"  Avg turnaround:      {float(str(metrics['avg_turnaround_time'])):.4f}s"
            )
            lines.append(f"  Avg response:        {float(str(metrics['avg_response_time'])):.4f}s")
            lines.append(
                f"  Throughput:          {float(str(metrics['throughput'])):.2f} procs/sec"
            )
            lines.append("")
        except SyscallError as e:
            lines.append(f"Step 3 failed: {e}")

        # Step 4: Explain each metric
        lines.extend(
            [
                "Step 4: What each metric means",
                "  Wait time:       How long a process sat in the READY queue",
                "  Turnaround time: Total time from creation to termination",
                "  Response time:   Time from creation to first CPU dispatch",
                "  Context switches: How many times the CPU switched processes",
                "  Throughput:      Processes completed per second of uptime",
            ]
        )

        return "\n".join(lines)

    def _cmd_strace(self, args: list[str]) -> str:
        """Syscall tracing — see every request the kernel handles."""
        dispatch: _SubcommandTable = {
            "on": lambda _a: self._cmd_strace_on(),
            "off": lambda _a: self._cmd_strace_off(),
            "show": lambda _a: self._cmd_strace_show(),
            "clear": lambda _a: self._cmd_strace_clear(),
            "demo": lambda _a: self._cmd_strace_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: strace <on|off|show|clear|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_strace_on(self) -> str:
        """Enable syscall tracing."""
        self._kernel.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        return "Strace enabled."

    def _cmd_strace_off(self) -> str:
        """Disable syscall tracing."""
        self._kernel.syscall(SyscallNumber.SYS_STRACE_DISABLE)
        return "Strace disabled."

    def _cmd_strace_show(self) -> str:
        """Display the current strace log."""
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_STRACE_LOG)
        if not entries:
            return "(strace log is empty)"
        return "\n".join(entries)

    def _cmd_strace_clear(self) -> str:
        """Clear the strace log."""
        self._kernel.syscall(SyscallNumber.SYS_STRACE_CLEAR)
        return "Strace log cleared."

    def _cmd_strace_demo(self) -> str:
        """Walk through strace with a guided demo."""
        lines: list[str] = [
            "=== Strace Demo ===",
            "",
            "Strace is like standing in a kitchen with a clipboard. Normally",
            "you sit in the dining room and just see the food appear. But strace",
            "lets you write down every order the chef (program) makes to the",
            "assistants (kernel): 'Get me flour' -> 'Here's the flour.'",
            "You see every request and every response.",
            "",
        ]

        # Step 1: Enable strace
        self._kernel.syscall(SyscallNumber.SYS_STRACE_ENABLE)
        lines.append("Step 1: Strace enabled — now every syscall is recorded.")
        lines.append("")

        # Step 2: Run some syscalls
        lines.append("Step 2: Making some syscalls...")
        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_DIR, path="/strace_demo")
            lines.append("  mkdir /strace_demo")
        except SyscallError:
            lines.append("  mkdir /strace_demo (already exists)")

        try:
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/strace_demo/hello.txt")
            self._kernel.syscall(
                SyscallNumber.SYS_WRITE_FILE,
                path="/strace_demo/hello.txt",
                data=b"Hello from strace!",
            )
            lines.append("  write /strace_demo/hello.txt")
        except SyscallError:
            lines.append("  write /strace_demo/hello.txt (error)")

        try:
            self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path="/strace_demo")
            lines.append("  ls /strace_demo")
        except SyscallError:
            pass

        lines.append("")

        # Step 3: Show the captured trace
        lines.append("Step 3: Here's what strace captured:")
        entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_STRACE_LOG)
        lines.extend(f"  {entry}" for entry in entries)
        lines.append("")

        # Step 4: Disable and cleanup
        self._kernel.syscall(SyscallNumber.SYS_STRACE_DISABLE)
        lines.append("Step 4: Strace disabled. The log is preserved for review.")

        # Cleanup demo files
        try:
            self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/strace_demo/hello.txt")
            self._kernel.syscall(SyscallNumber.SYS_DELETE_FILE, path="/strace_demo")
        except SyscallError:
            pass

        return "\n".join(lines)

    def _cmd_cpu(self, _args: list[str]) -> str:
        """Show per-CPU status."""
        try:
            cpu_info: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_CPU_INFO)
        except SyscallError as e:
            return f"Error: {e}"
        lines: list[str] = [f"=== {len(cpu_info)} CPU(s) ==="]
        for info in cpu_info:
            current = info["current"]
            current_str = f"pid {current}" if current is not None else "idle"
            lines.append(
                f"CPU {info['cpu_id']}: policy={info['policy']}"
                f"  ready={info['ready_count']}  current={current_str}"
            )
        return "\n".join(lines)

    def _cmd_taskset(self, args: list[str]) -> str:
        """Show or set CPU affinity for a process."""
        if not args:
            return "Usage: taskset <pid> [cpu_list]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        if len(args) == 1:
            return self._cmd_taskset_show(pid)
        return self._cmd_taskset_set(pid, args[1:])

    def _cmd_taskset_show(self, pid: int) -> str:
        """Display CPU affinity for a process."""
        try:
            affinity: list[int] = self._kernel.syscall(SyscallNumber.SYS_GET_AFFINITY, pid=pid)
        except SyscallError as e:
            return f"Error: {e}"
        return f"PID {pid} affinity: {affinity}"

    def _cmd_taskset_set(self, pid: int, cpu_args: list[str]) -> str:
        """Set CPU affinity for a process."""
        try:
            cpus = [int(c) for c in cpu_args]
        except ValueError:
            return "Error: CPU IDs must be integers"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SET_AFFINITY, pid=pid, cpus=cpus)
        except SyscallError as e:
            return f"Error: {e}"
        return f"PID {pid} affinity set to {cpus}"

    def _cmd_scheduler_balance(self) -> str:
        """Trigger load balancing across CPUs."""
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_BALANCE)
        except SyscallError as e:
            return f"Error: {e}"
        count = result["count"]
        migrations = result["migrations"]
        if not migrations:
            return "Load balanced: 0 migrations (already balanced)"
        lines = [f"Load balanced: {count} migration(s)"]
        for pid, from_cpu, to_cpu in migrations:  # type: ignore[union-attr]
            lines.append(f"  PID {pid}: CPU {from_cpu} → CPU {to_cpu}")
        return "\n".join(lines)

    def _cmd_tick(self, args: list[str]) -> str:
        """Advance the system clock by N ticks (default 1)."""
        count = 1
        if args:
            try:
                count = int(args[0])
            except ValueError:
                return f"Error: invalid tick count '{args[0]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_TICK, count=count)
            lines = [f"Ticked {result['ticks']} time(s)"]
            lines.append(f"  Current tick: {result['final_tick']}")
            lines.append(f"  Interrupts serviced: {result['total_interrupts_serviced']}")
            if result["preempted"]:
                lines.append("  Preemption occurred")
            return "\n".join(lines)
        except SyscallError as e:
            return f"Error: {e}"

    _BENCHMARK_POLICIES: ClassVar[list[tuple[str, str]]] = [
        ("fcfs", "FCFS"),
        ("rr", "RR"),
        ("priority", "Priority"),
        ("aging", "Aging"),
        ("cfs", "CFS"),
    ]

    def _cmd_benchmark(self, args: list[str]) -> str:
        """Compare scheduler policies with standardised workloads."""
        if not args:
            return "Usage: benchmark <run [cpu|io|mixed]|demo>"
        match args[0]:
            case "run":
                workload = args[1] if len(args) > 1 else "cpu"
                return self._benchmark_run(workload)
            case "demo":
                return self._benchmark_demo()
            case _:
                return "Usage: benchmark <run [cpu|io|mixed]|demo>"

    def _benchmark_run(self, workload: str) -> str:
        """Run a workload under each policy and display a comparison table."""
        workload_labels = {"cpu": "CPU-bound", "io": "IO-bound", "mixed": "Mixed"}
        label = workload_labels.get(workload)
        if label is None:
            return f"Unknown workload: {workload}. Use cpu, io, or mixed."

        # Save the original policy name
        info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SCHEDULER_INFO)
        original_policy = str(info["policy"])

        proc_count = 5
        rows: list[tuple[str, int, int, float]] = []

        for policy_key, policy_name in self._BENCHMARK_POLICIES:
            self._benchmark_switch_policy(policy_key)
            self._kernel.syscall(SyscallNumber.SYS_PERF_RESET)
            self._benchmark_run_workload(workload, proc_count)
            metrics: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PERF_METRICS)
            switches = int(str(metrics["context_switches"]))
            completed = int(str(metrics["total_completed"]))
            avg_wait = float(str(metrics["avg_wait_time"]))
            rows.append((policy_name, switches, completed, avg_wait))

        # Restore original policy
        self._benchmark_restore_policy(original_policy)

        return self._benchmark_format_table(label, rows)

    def _benchmark_switch_policy(self, policy_key: str) -> None:
        """Switch to the given scheduling policy for benchmarking."""
        kwargs: dict[str, object] = {"policy": policy_key}
        if policy_key == "rr":
            kwargs["quantum"] = 2
        self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, **kwargs)

    def _benchmark_restore_policy(self, original: str) -> None:
        """Restore the scheduling policy to its original state."""
        # Parse the original policy string to extract the policy key
        lower = original.lower()
        if "fcfs" in lower:
            self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="fcfs")
        elif "round robin" in lower:
            self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="rr", quantum=2)
        elif "aging" in lower:
            self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="aging")
        elif "priority" in lower:
            self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="priority")
        elif "mlfq" in lower:
            self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="mlfq")
        elif "cfs" in lower:
            self._kernel.syscall(SyscallNumber.SYS_SET_SCHEDULER, policy="cfs")

    def _benchmark_run_workload(self, workload: str, count: int) -> None:
        """Create, execute, and run *count* processes for the given workload type."""
        pids: list[int] = []
        for i in range(count):
            priority = i if workload in ("io", "mixed") else 0
            try:
                result = self._kernel.syscall(
                    SyscallNumber.SYS_CREATE_PROCESS,
                    name=f"bench-{workload}-{i}",
                    num_pages=1,
                    priority=priority,
                )
                pid = result["pid"]
                pids.append(pid)
                self._kernel.syscall(
                    SyscallNumber.SYS_EXEC,
                    pid=pid,
                    program=lambda: "done",
                )
                self._kernel.syscall(SyscallNumber.SYS_RUN, pid=pid)
            except SyscallError:
                continue
        # SYS_RUN bypasses the scheduler dispatch — clean up leftover
        # entries so set_scheduler_policy won't encounter terminated procs.
        self._kernel.purge_terminated_from_scheduler()

    def _benchmark_format_table(self, label: str, rows: list[tuple[str, int, int, float]]) -> str:
        """Format benchmark results as an ASCII comparison table."""
        lines: list[str] = [
            f"=== Benchmark: {label} Workload ===",
            "",
            f"{'Policy':<12} {'Switches':>10} {'Completed':>10} {'Avg Wait':>10}",
            f"{'-' * 12} {'-' * 10} {'-' * 10} {'-' * 10}",
        ]
        for name, switches, completed, avg_wait in rows:
            lines.append(f"{name:<12} {switches:>10} {completed:>10} {avg_wait:>10.4f}")
        return "\n".join(lines)

    def _benchmark_demo(self) -> str:
        """Walk through benchmarking with a sports day analogy."""
        lines: list[str] = [
            "=== Benchmark Demo ===",
            "",
            "Imagine a sports day at school. Five coaches each organise the same",
            "set of races, but each coach uses a different strategy:",
            "",
            "  - Coach FCFS:     First Come, First Served — whoever signs up first runs first.",
            "  - Coach RR:       Round Robin — everyone gets a short turn, then goes to the back.",
            "  - Coach Priority: Fastest runners go first.",
            "  - Coach Aging:    Like Priority, but slower runners gradually move up.",
            "  - Coach CFS:      Completely Fair — tracks who has run least and picks them.",
            "",
        ]

        # Step 1: Explain what we're doing
        lines.append("Step 1: We run the SAME races under each coach's rules.")
        lines.append("Step 2: We compare how many context switches each coach needed,")
        lines.append("        how many races were completed, and how long runners waited.")
        lines.append("")

        # Step 3: Run a mini benchmark
        lines.append("Step 3: Running a mini CPU-bound benchmark...")
        lines.append("")
        table = self._benchmark_run("cpu")
        lines.append(table)
        lines.append("")

        # Step 4: Summary
        lines.append("Step 4: What to look for")
        lines.append("  - Fewer context switches = less overhead")
        lines.append("  - Lower avg wait = processes start sooner")
        lines.append("  - Each policy has trade-offs — no single 'best' answer!")

        return "\n".join(lines)

    def _cmd_compile(self, args: list[str]) -> str:
        """Compile a demo program to /bin: compile NAME or compile list."""
        if not args:
            return "Usage: compile <name> | compile list"
        if args[0] == "list":
            names = sorted(DEMO_PROGRAMS.keys())
            return "Available demos: " + ", ".join(names)
        name = args[0]
        if name not in DEMO_PROGRAMS:
            return f"Unknown demo: {name}. Use 'compile list' to see options."
        path = f"/bin/{name}"
        data = DEMO_PROGRAMS[name]()
        with contextlib.suppress(SyscallError):
            self._kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path=path)
        try:
            self._kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path=path, data=data)
            self._kernel.syscall(SyscallNumber.SYS_CHMOD, path=path, mode="rwxr-xr-x")
            return f"Compiled {name} -> {path} ({len(data)} bytes)"
        except SyscallError as e:
            return f"Error: {e}"

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("ps", _cmd_ps),
        ("kill", _cmd_kill),
        ("signal", _cmd_signal),
        ("top", _cmd_top),
        ("jobs", _cmd_jobs),
        ("bg", _cmd_bg),
        ("fg", _cmd_fg),
        ("fork", _cmd_fork),
        ("pstree", _cmd_pstree),
        ("threads", _cmd_threads),
        ("run", _cmd_run),
        ("wait", _cmd_wait),
        ("waitpid", _cmd_waitpid),
        ("waitjob", _cmd_waitjob),
        ("handle", _cmd_handle),
        ("scheduler", _cmd_scheduler),
        ("cpu", _cmd_cpu),
        ("taskset", _cmd_taskset),
        ("tick", _cmd_tick),
        ("strace", _cmd_strace),
        ("proc", _cmd_proc),
        ("perf", _cmd_perf),
        ("benchmark", _cmd_benchmark),
        ("compile", _cmd_compile),
    )
