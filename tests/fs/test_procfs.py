"""Tests for the /proc virtual filesystem.

``/proc`` is a magic bulletin board — nobody writes real papers and pins
them there.  When you walk up and look, the information appears
automatically from the school's current records.  New student arrives →
instantly on the board.  Student leaves → entry vanishes.

These tests verify that ProcFilesystem generates correct, live content
from kernel state — memory stats, uptime, scheduler info, and per-process
details — without touching the real inode-based filesystem.
"""

import pytest

from py_os.completer import Completer
from py_os.fs.procfs import ProcError, ProcFilesystem
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_STATUS_LINES = 7
EXPECTED_MEMINFO_LINES = 4


def _booted_kernel() -> Kernel:
    """Return a freshly booted kernel."""
    k = Kernel()
    k.boot()
    k._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
    return k


# ---------------------------------------------------------------------------
# Cycle 1 — ProcError + ProcFilesystem init
# ---------------------------------------------------------------------------


class TestProcErrorAndInit:
    """Verify ProcError is a proper exception and ProcFilesystem initialises."""

    def test_proc_error_is_exception(self) -> None:
        """ProcError should be a standard exception."""
        with pytest.raises(ProcError, match="oops"):
            raise ProcError("oops")

    def test_procfs_creates_and_stores_kernel(self) -> None:
        """ProcFilesystem should store a reference to its kernel."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        assert pfs.kernel is k
        k.shutdown()

    def test_procfs_bad_path_raises(self) -> None:
        """Reading a nonexistent /proc file should raise ProcError."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        with pytest.raises(ProcError, match="No such /proc file"):
            pfs.read("/proc/nonexistent")
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 2 — Global files: meminfo, uptime, cpuinfo
# ---------------------------------------------------------------------------


class TestProcGlobalFiles:
    """Verify /proc/meminfo, /proc/uptime, and /proc/cpuinfo."""

    def test_meminfo_contains_mem_total(self) -> None:
        """Verify meminfo reports MemTotal."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/meminfo")
        assert "MemTotal:" in content
        k.shutdown()

    def test_meminfo_contains_mem_free(self) -> None:
        """Verify meminfo reports MemFree."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/meminfo")
        assert "MemFree:" in content
        k.shutdown()

    def test_meminfo_has_four_lines(self) -> None:
        """Verify meminfo has exactly 4 lines (Total, Free, Used, Shared)."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/meminfo")
        assert len(content.strip().splitlines()) == EXPECTED_MEMINFO_LINES
        k.shutdown()

    def test_uptime_is_non_negative(self) -> None:
        """Verify uptime is a non-negative number followed by 'seconds'."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/uptime")
        seconds = float(content.split()[0])
        assert seconds >= 0
        assert content.endswith("seconds")
        k.shutdown()

    def test_cpuinfo_shows_policy(self) -> None:
        """Verify cpuinfo names the scheduler policy."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/cpuinfo")
        assert "Policy:" in content
        assert "FCFSPolicy" in content
        k.shutdown()

    def test_cpuinfo_shows_ready_queue(self) -> None:
        """Verify cpuinfo reports the ready queue size."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        content = pfs.read("/proc/cpuinfo")
        assert "ReadyQueue:" in content
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 3 — Per-process files: status, maps, cmdline
# ---------------------------------------------------------------------------


class TestProcProcessFiles:
    """Verify /proc/{pid}/status, maps, and cmdline."""

    def test_status_contains_name(self) -> None:
        """Verify status shows the process name."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="worker", num_pages=2)
        content = pfs.read(f"/proc/{p.pid}/status")
        assert "Name:           worker" in content
        k.shutdown()

    def test_status_contains_pid(self) -> None:
        """Verify status shows the process PID."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="worker", num_pages=2)
        content = pfs.read(f"/proc/{p.pid}/status")
        assert f"Pid:            {p.pid}" in content
        k.shutdown()

    def test_status_contains_state(self) -> None:
        """Verify status shows the process state."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="worker", num_pages=2)
        content = pfs.read(f"/proc/{p.pid}/status")
        assert "State:" in content
        k.shutdown()

    def test_status_has_seven_lines(self) -> None:
        """Verify status has 7 lines (Name, Pid, PPid, State, Priority, EffPriority, Threads)."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="worker", num_pages=2)
        content = pfs.read(f"/proc/{p.pid}/status")
        assert len(content.strip().splitlines()) == EXPECTED_STATUS_LINES
        k.shutdown()

    def test_maps_shows_pages(self) -> None:
        """Verify maps shows the allocated physical frames."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="worker", num_pages=2)
        content = pfs.read(f"/proc/{p.pid}/maps")
        assert "Pages:" in content
        k.shutdown()

    def test_cmdline_is_process_name(self) -> None:
        """Verify cmdline returns the bare process name."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="myapp", num_pages=1)
        content = pfs.read(f"/proc/{p.pid}/cmdline")
        assert content == "myapp"
        k.shutdown()

    def test_nonexistent_pid_raises(self) -> None:
        """Reading a non-existent PID should raise ProcError."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        with pytest.raises(ProcError, match=r"Process .* not found"):
            pfs.read("/proc/99999/status")
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 4 — /proc/self
# ---------------------------------------------------------------------------


class TestProcSelf:
    """Verify /proc/self resolves to the currently running process."""

    def test_self_status_works(self) -> None:
        """Reading /proc/self/status should work when a process is running."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        k.create_process(name="runner", num_pages=1)
        assert k.scheduler is not None
        dispatched = k.scheduler.dispatch()
        assert dispatched is not None
        content = pfs.read("/proc/self/status")
        assert f"Pid:            {dispatched.pid}" in content
        k.shutdown()

    def test_self_cmdline_works(self) -> None:
        """Reading /proc/self/cmdline should return the running process name."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        k.create_process(name="runner", num_pages=1)
        assert k.scheduler is not None
        # Dispatch init first (FCFS), preempt it, then dispatch runner
        init_proc = k.scheduler.dispatch()
        assert init_proc is not None
        init_proc.preempt()
        k.scheduler.add(init_proc)
        dispatched = k.scheduler.dispatch()
        assert dispatched is not None
        content = pfs.read("/proc/self/cmdline")
        assert content == "runner"
        k.shutdown()

    def test_self_no_current_raises(self) -> None:
        """Reading /proc/self when no process is running should raise ProcError."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        with pytest.raises(ProcError, match="No currently running process"):
            pfs.read("/proc/self/status")
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 5 — list_dir
# ---------------------------------------------------------------------------


class TestProcListDir:
    """Verify listing /proc directories."""

    def test_root_has_global_files(self) -> None:
        """Root listing should include meminfo, uptime, cpuinfo, stat, self."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        entries = pfs.list_dir("/proc")
        assert "meminfo" in entries
        assert "uptime" in entries
        assert "cpuinfo" in entries
        assert "stat" in entries
        assert "self" in entries
        k.shutdown()

    def test_root_includes_pid_directories(self) -> None:
        """Root listing should include PID entries for created processes."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="lister", num_pages=1)
        entries = pfs.list_dir("/proc")
        assert str(p.pid) in entries
        k.shutdown()

    def test_root_with_trailing_slash(self) -> None:
        """Root listing should work with /proc/ (trailing slash)."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        entries = pfs.list_dir("/proc/")
        assert "meminfo" in entries
        k.shutdown()

    def test_pid_dir_has_four_entries(self) -> None:
        """Listing a PID directory should return status, maps, cmdline, sched."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        p = k.create_process(name="lister", num_pages=1)
        entries = pfs.list_dir(f"/proc/{p.pid}")
        expected_entries = 4
        assert len(entries) == expected_entries
        assert "status" in entries
        assert "maps" in entries
        assert "cmdline" in entries
        assert "sched" in entries
        k.shutdown()

    def test_bad_pid_dir_raises(self) -> None:
        """Listing a non-existent PID directory should raise ProcError."""
        k = _booted_kernel()
        pfs = ProcFilesystem(kernel=k)
        with pytest.raises(ProcError, match=r"Process .* not found"):
            pfs.list_dir("/proc/99999")
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 6 — Kernel integration
# ---------------------------------------------------------------------------


class TestKernelProcIntegration:
    """Verify /proc is wired into the kernel lifecycle."""

    def test_proc_fs_none_before_boot(self) -> None:
        """The proc_filesystem property should be None before boot."""
        k = Kernel()
        assert k.proc_filesystem is None

    def test_proc_fs_available_after_boot(self) -> None:
        """The proc_filesystem property should be a ProcFilesystem after boot."""
        k = _booted_kernel()
        assert isinstance(k.proc_filesystem, ProcFilesystem)
        k.shutdown()

    def test_proc_fs_none_after_shutdown(self) -> None:
        """The proc_filesystem property should be None after shutdown."""
        k = _booted_kernel()
        k.shutdown()
        assert k.proc_filesystem is None

    def test_kernel_proc_read(self) -> None:
        """Kernel.proc_read should return /proc file content."""
        k = _booted_kernel()
        content = k.proc_read("/proc/uptime")
        assert "seconds" in content
        k.shutdown()

    def test_kernel_proc_list(self) -> None:
        """Kernel.proc_list should return /proc directory entries."""
        k = _booted_kernel()
        entries = k.proc_list("/proc")
        assert "meminfo" in entries
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 7 — Syscall integration
# ---------------------------------------------------------------------------


class TestProcSyscalls:
    """Verify SYS_PROC_READ and SYS_PROC_LIST syscalls."""

    def test_syscall_read_meminfo(self) -> None:
        """SYS_PROC_READ should return /proc/meminfo content."""
        k = _booted_kernel()
        content: str = k.syscall(SyscallNumber.SYS_PROC_READ, path="/proc/meminfo")
        assert "MemTotal:" in content
        k.shutdown()

    def test_syscall_list_root(self) -> None:
        """SYS_PROC_LIST should return root /proc entries."""
        k = _booted_kernel()
        entries: list[str] = k.syscall(SyscallNumber.SYS_PROC_LIST, path="/proc")
        assert "meminfo" in entries
        k.shutdown()

    def test_syscall_read_bad_path_raises(self) -> None:
        """SYS_PROC_READ on a bad path should raise SyscallError."""
        k = _booted_kernel()
        with pytest.raises(SyscallError, match="No such /proc file"):
            k.syscall(SyscallNumber.SYS_PROC_READ, path="/proc/nope")
        k.shutdown()

    def test_syscall_list_bad_path_raises(self) -> None:
        """SYS_PROC_LIST on a bad path should raise SyscallError."""
        k = _booted_kernel()
        with pytest.raises(SyscallError, match="Not a /proc directory"):
            k.syscall(SyscallNumber.SYS_PROC_LIST, path="/proc/nope")
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 8 — Shell integration
# ---------------------------------------------------------------------------


class TestShellProcIntegration:
    """Verify cat and ls handle /proc paths in the shell."""

    def test_cat_proc_meminfo(self) -> None:
        """Verify ``cat /proc/meminfo`` shows memory stats."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        output = sh.execute("cat /proc/meminfo")
        assert "MemTotal:" in output
        k.shutdown()

    def test_cat_proc_uptime(self) -> None:
        """Verify ``cat /proc/uptime`` shows uptime."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        output = sh.execute("cat /proc/uptime")
        assert "seconds" in output
        k.shutdown()

    def test_ls_proc(self) -> None:
        """Verify ``ls /proc`` lists virtual files."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        output = sh.execute("ls /proc")
        assert "meminfo" in output
        assert "self" in output
        k.shutdown()

    def test_ls_proc_pid(self) -> None:
        """Verify ``ls /proc/{pid}`` lists per-process files."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        p = k.create_process(name="testproc", num_pages=1)
        output = sh.execute(f"ls /proc/{p.pid}")
        assert "status" in output
        assert "maps" in output
        assert "cmdline" in output
        k.shutdown()

    def test_cat_proc_status(self) -> None:
        """Verify ``cat /proc/{pid}/status`` shows process details."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        p = k.create_process(name="testproc", num_pages=1)
        output = sh.execute(f"cat /proc/{p.pid}/status")
        assert "Name:           testproc" in output
        k.shutdown()

    def test_regular_cat_still_works(self) -> None:
        """Regular cat (non-/proc) should still use the real filesystem."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        sh.execute("touch /hello.txt")
        sh.execute("write /hello.txt greetings")
        output = sh.execute("cat /hello.txt")
        assert "greetings" in output
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 9 — proc demo command
# ---------------------------------------------------------------------------


class TestProcDemoCommand:
    """Verify the 'proc demo' guided walkthrough."""

    def test_demo_header(self) -> None:
        """Demo should print a /proc header line."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        output = sh.execute("proc demo")
        assert "/proc Virtual Filesystem" in output
        k.shutdown()

    def test_demo_has_steps(self) -> None:
        """Demo should include numbered steps."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        output = sh.execute("proc demo")
        assert "Step 1" in output
        assert "Step 2" in output
        k.shutdown()


# ---------------------------------------------------------------------------
# Cycle 10 — Completer integration
# ---------------------------------------------------------------------------


class TestProcCompleter:
    """Verify tab completion for proc commands and /proc paths."""

    def test_proc_subcommand_completion(self) -> None:
        """Completing 'proc ' should suggest 'demo'."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        comp = Completer(sh)
        candidates = comp.completions("", "proc ")
        assert "demo" in candidates
        k.shutdown()

    def test_proc_command_completes(self) -> None:
        """Completing 'pro' should include 'proc'."""
        k = _booted_kernel()
        sh = Shell(kernel=k)
        comp = Completer(sh)
        candidates = comp.completions("pro", "pro")
        assert "proc" in candidates
        k.shutdown()
