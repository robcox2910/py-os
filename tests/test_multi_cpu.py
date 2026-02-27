"""Tests for multi-CPU scheduling — per-CPU schedulers, load balancing, affinity.

Imagine a school with multiple whiteboards. Each whiteboard can have one
student at a time. The teacher keeps separate queues for each whiteboard
and periodically checks if one queue is much longer than the others. If
so, they move a student to a shorter queue. Some students prefer a
specific whiteboard — that's CPU affinity.
"""

from __future__ import annotations

from py_os.bootloader import Bootloader, KernelImage
from py_os.kernel import ExecutionMode, Kernel
from py_os.process.pcb import Process, ProcessState
from py_os.process.scheduler import (
    FCFSPolicy,
    MultiCPUScheduler,
    RoundRobinPolicy,
)
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber

# Named constants
NUM_CPUS_TWO = 2
NUM_CPUS_FOUR = 4
RR_QUANTUM = 4


def _ready_process(name: str = "p", priority: int = 0) -> Process:
    """Create a process and advance it to READY state."""
    p = Process(name=name, priority=priority)
    p.admit()
    return p


# -- Cycle 1: Process PCB cpu_id field ----------------------------------------


class TestProcessCpuId:
    """Verify the cpu_id field on the Process control block."""

    def test_cpu_id_default_none(self) -> None:
        """A new process should have cpu_id None (not yet assigned)."""
        p = Process(name="test")
        assert p.cpu_id is None

    def test_cpu_id_settable(self) -> None:
        """The cpu_id should be assignable and readable."""
        p = Process(name="test")
        p.cpu_id = 3
        expected_cpu = 3
        assert p.cpu_id == expected_cpu

    def test_cpu_id_cleared_on_terminate(self) -> None:
        """After termination, cpu_id should revert to None."""
        p = Process(name="test")
        p.admit()
        p.dispatch()
        p.cpu_id = 1
        p.terminate()
        assert p.cpu_id is None


# -- Cycle 2: MultiCPUScheduler creation + single-CPU compat -----------------


class TestMultiCPUSchedulerSingleCPU:
    """Verify backward-compatible single-CPU operation."""

    def test_creation_default_one_cpu(self) -> None:
        """Default creation should have 1 CPU with empty queues."""
        multi = MultiCPUScheduler(policy_factory=FCFSPolicy)
        assert multi.num_cpus == 1
        assert multi.ready_count == 0

    def test_single_cpu_add_dispatch(self) -> None:
        """Add + dispatch on a single CPU should work like Scheduler."""
        multi = MultiCPUScheduler(policy_factory=FCFSPolicy)
        p = _ready_process("worker")
        multi.add(p)
        dispatched = multi.dispatch()
        assert dispatched is not None
        assert dispatched is p
        assert dispatched.state is ProcessState.RUNNING

    def test_single_cpu_preempt(self) -> None:
        """Preempt should return the running process to the queue."""
        multi = MultiCPUScheduler(policy_factory=FCFSPolicy)
        p = _ready_process("worker")
        multi.add(p)
        multi.dispatch()
        multi.preempt()
        assert multi.current is None
        assert multi.ready_count == 1

    def test_single_cpu_terminate(self) -> None:
        """Terminate should clear the current slot."""
        multi = MultiCPUScheduler(policy_factory=FCFSPolicy)
        p = _ready_process("worker")
        multi.add(p)
        multi.dispatch()
        multi.terminate_current()
        assert multi.current is None
        assert p.state is ProcessState.TERMINATED

    def test_single_cpu_properties(self) -> None:
        """Aggregate properties should reflect single-CPU state."""
        multi = MultiCPUScheduler(policy_factory=FCFSPolicy)
        p1 = _ready_process("a")
        p2 = _ready_process("b")
        multi.add(p1)
        multi.add(p2)
        expected_ready = 2
        assert multi.ready_count == expected_ready
        assert multi.current is None
        assert multi.context_switches == 0
        assert isinstance(multi.policy, FCFSPolicy)


# -- Cycle 3: Multi-CPU dispatch and per-CPU queues ---------------------------


class TestMultiCPUDispatchPerCPU:
    """Verify per-CPU dispatch with multiple CPUs."""

    def test_multi_cpu_dispatch_per_cpu(self) -> None:
        """Dispatch on CPU 0 and CPU 1 should return different processes."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p0 = _ready_process("on_cpu0")
        p1 = _ready_process("on_cpu1")
        multi.add(p0, cpu_id=0)
        multi.add(p1, cpu_id=1)
        d0 = multi.dispatch(cpu_id=0)
        d1 = multi.dispatch(cpu_id=1)
        assert d0 is p0
        assert d1 is p1

    def test_add_auto_assigns_least_loaded(self) -> None:
        """Without explicit cpu_id, process goes to the emptiest CPU."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        # Add 3 processes — should distribute 2 to one, 1 to other
        p1 = _ready_process("a")
        p2 = _ready_process("b")
        p3 = _ready_process("c")
        multi.add(p1)
        multi.add(p2)
        multi.add(p3)
        counts = [multi.cpu_ready_count(i) for i in range(NUM_CPUS_TWO)]
        assert sorted(counts) == [1, 2]

    def test_add_explicit_cpu_id(self) -> None:
        """Specifying cpu_id should place the process on that CPU."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p = _ready_process("pinned")
        multi.add(p, cpu_id=1)
        assert multi.cpu_ready_count(0) == 0
        assert multi.cpu_ready_count(1) == 1

    def test_cpu_ready_count(self) -> None:
        """Per-CPU ready counts should be correct."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        for _ in range(3):
            multi.add(_ready_process(), cpu_id=0)
        multi.add(_ready_process(), cpu_id=1)
        expected_cpu0 = 3
        assert multi.cpu_ready_count(0) == expected_cpu0
        assert multi.cpu_ready_count(1) == 1

    def test_cpu_current(self) -> None:
        """Per-CPU current processes should be tracked separately."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p0 = _ready_process("on_0")
        p1 = _ready_process("on_1")
        multi.add(p0, cpu_id=0)
        multi.add(p1, cpu_id=1)
        multi.dispatch(cpu_id=0)
        assert multi.cpu_current(0) is p0
        assert multi.cpu_current(1) is None
        multi.dispatch(cpu_id=1)
        assert multi.cpu_current(1) is p1

    def test_dispatch_all(self) -> None:
        """dispatch_all should dispatch on every CPU."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p0 = _ready_process("a")
        p1 = _ready_process("b")
        multi.add(p0, cpu_id=0)
        multi.add(p1, cpu_id=1)
        results = multi.dispatch_all()
        assert results[0] is p0
        assert results[1] is p1


# -- Cycle 4: Load balancing -------------------------------------------------


class TestLoadBalancing:
    """Verify load balancing across CPUs."""

    def test_balance_moves_from_overloaded(self) -> None:
        """Processes should migrate from a busy CPU to an empty one."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        # Put 4 processes on CPU 0, none on CPU 1
        for _ in range(NUM_CPUS_FOUR):
            multi.add(_ready_process(), cpu_id=0)
        assert multi.cpu_ready_count(0) == NUM_CPUS_FOUR
        assert multi.cpu_ready_count(1) == 0
        moved = multi.balance()
        assert len(moved) > 0
        # After balancing, difference should be at most 1
        diff = abs(multi.cpu_ready_count(0) - multi.cpu_ready_count(1))
        assert diff <= 1

    def test_balance_noop_when_balanced(self) -> None:
        """No migrations when CPUs have equal load."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        multi.add(_ready_process(), cpu_id=0)
        multi.add(_ready_process(), cpu_id=1)
        moved = multi.balance()
        assert moved == []

    def test_balance_returns_migration_list(self) -> None:
        """balance() should return (pid, from_cpu, to_cpu) tuples."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        procs = [_ready_process(f"p{i}") for i in range(NUM_CPUS_FOUR)]
        for p in procs:
            multi.add(p, cpu_id=0)
        moved = multi.balance()
        for pid, from_cpu, to_cpu in moved:
            assert from_cpu == 0
            assert to_cpu == 1
            assert isinstance(pid, int)

    def test_migrations_counter(self) -> None:
        """The migrations property should track total migrations."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        assert multi.migrations == 0
        for _ in range(NUM_CPUS_FOUR):
            multi.add(_ready_process(), cpu_id=0)
        moved = multi.balance()
        assert multi.migrations == len(moved)

    def test_migrate_explicit(self) -> None:
        """migrate() should move a specific process between CPUs."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p = _ready_process("mover")
        multi.add(p, cpu_id=0)
        assert multi.migrate(p.pid, from_cpu=0, to_cpu=1)
        assert multi.cpu_ready_count(0) == 0
        assert multi.cpu_ready_count(1) == 1


# -- Cycle 5: CPU affinity ---------------------------------------------------


class TestCPUAffinity:
    """Verify CPU affinity constraints."""

    def test_default_affinity_all_cpus(self) -> None:
        """By default a process can run on any CPU."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_FOUR, policy_factory=FCFSPolicy)
        p = _ready_process("free")
        affinity = multi.get_affinity(p.pid)
        assert affinity == frozenset(range(NUM_CPUS_FOUR))

    def test_set_affinity_restricts(self) -> None:
        """A process with affinity {1} should only go to CPU 1."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p = _ready_process("pinned")
        multi.set_affinity(p.pid, frozenset({1}))
        multi.add(p)  # auto-assign should respect affinity
        assert multi.cpu_ready_count(1) == 1
        assert multi.cpu_ready_count(0) == 0

    def test_balance_respects_affinity(self) -> None:
        """Pinned processes should not be moved during balancing."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        # Pin 3 processes to CPU 0
        for _ in range(3):
            p = _ready_process("pinned")
            multi.set_affinity(p.pid, frozenset({0}))
            multi.add(p, cpu_id=0)
        moved = multi.balance()
        # None should move — they're all pinned to CPU 0
        assert moved == []
        expected_count = 3
        assert multi.cpu_ready_count(0) == expected_count

    def test_migrate_rejects_non_affinity(self) -> None:
        """Cannot migrate a process to a CPU outside its affinity."""
        multi = MultiCPUScheduler(num_cpus=NUM_CPUS_TWO, policy_factory=FCFSPolicy)
        p = _ready_process("stuck")
        multi.set_affinity(p.pid, frozenset({0}))
        multi.add(p, cpu_id=0)
        result = multi.migrate(p.pid, from_cpu=0, to_cpu=1)
        assert result is False
        assert multi.cpu_ready_count(0) == 1


# -- Cycle 6: Kernel integration ---------------------------------------------

NUM_PAGES = 1


def _booted_kernel(num_cpus: int = 1) -> Kernel:
    """Create and boot a kernel with optional multi-CPU support."""
    kernel = Kernel(total_frames=64, num_cpus=num_cpus)
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


class TestKernelMultiCPU:
    """Verify kernel integration with MultiCPUScheduler."""

    def test_kernel_boot_with_multi_cpu(self) -> None:
        """Kernel should boot successfully with N CPUs."""
        kernel = _booted_kernel(num_cpus=NUM_CPUS_TWO)
        assert kernel.scheduler is not None
        assert isinstance(kernel.scheduler, MultiCPUScheduler)
        assert kernel.scheduler.num_cpus == NUM_CPUS_TWO

    def test_create_process_distributed(self) -> None:
        """Processes should spread across CPUs."""
        kernel = _booted_kernel(num_cpus=NUM_CPUS_TWO)
        assert kernel.scheduler is not None
        for i in range(NUM_CPUS_FOUR):
            kernel.create_process(name=f"worker{i}", num_pages=NUM_PAGES)
        # init + 4 workers = 5 total, distributed across 2 CPUs
        total = kernel.scheduler.ready_count
        expected_total = 5
        assert total == expected_total
        # Both CPUs should have processes
        assert kernel.scheduler.cpu_ready_count(0) > 0
        assert kernel.scheduler.cpu_ready_count(1) > 0

    def test_set_scheduler_policy_multi_cpu(self) -> None:
        """Policy change should propagate to all CPUs."""
        kernel = _booted_kernel(num_cpus=NUM_CPUS_TWO)
        kernel.set_scheduler_policy(lambda: RoundRobinPolicy(quantum=RR_QUANTUM))
        sched = kernel.scheduler
        assert sched is not None
        assert isinstance(sched, MultiCPUScheduler)
        assert isinstance(sched.policy, RoundRobinPolicy)
        # Both CPUs should have the new policy
        for cpu_id in range(NUM_CPUS_TWO):
            assert isinstance(sched.cpu_scheduler(cpu_id).policy, RoundRobinPolicy)

    def test_perf_metrics_includes_migrations(self) -> None:
        """Performance metrics should include migration count."""
        kernel = _booted_kernel(num_cpus=NUM_CPUS_TWO)
        metrics = kernel.perf_metrics()
        assert "migrations" in metrics
        assert metrics["migrations"] == 0

    def test_num_cpus_property(self) -> None:
        """Kernel should expose the number of CPUs."""
        kernel = _booted_kernel(num_cpus=NUM_CPUS_FOUR)
        assert kernel.num_cpus == NUM_CPUS_FOUR


# -- Cycle 7: Syscalls -------------------------------------------------------


def _syscall_kernel(num_cpus: int = 2) -> Kernel:
    """Boot a kernel and prepare for syscall testing."""
    kernel = Kernel(total_frames=64, num_cpus=num_cpus)
    kernel.boot()
    return kernel


class TestMultiCPUSyscalls:
    """Verify multi-CPU system calls."""

    def test_sys_cpu_info(self) -> None:
        """SYS_CPU_INFO should return per-CPU data."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(SyscallNumber.SYS_CPU_INFO)
        assert len(result) == NUM_CPUS_TWO
        assert "cpu_id" in result[0]
        assert "ready_count" in result[0]
        assert "current" in result[0]

    def test_sys_set_affinity(self) -> None:
        """SYS_SET_AFFINITY should set CPU affinity for a process."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="worker",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        kernel.syscall(
            SyscallNumber.SYS_SET_AFFINITY,
            pid=pid,
            cpus=[1],
        )
        affinity = kernel.syscall(
            SyscallNumber.SYS_GET_AFFINITY,
            pid=pid,
        )
        assert affinity == [1]

    def test_sys_get_affinity(self) -> None:
        """SYS_GET_AFFINITY should return default affinity (all CPUs)."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="worker",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        affinity = kernel.syscall(
            SyscallNumber.SYS_GET_AFFINITY,
            pid=pid,
        )
        assert sorted(affinity) == [0, 1]

    def test_sys_balance(self) -> None:
        """SYS_BALANCE should trigger load balancing."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(SyscallNumber.SYS_BALANCE)
        assert "migrations" in result
        assert isinstance(result["migrations"], list)

    def test_sys_migrate(self) -> None:
        """SYS_MIGRATE should migrate a process between CPUs."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        # Create a process — it will auto-assign to a CPU
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="mover",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        # Find which CPU it's on
        proc_info = kernel.syscall(
            SyscallNumber.SYS_PROCESS_INFO,
            pid=pid,
        )
        from_cpu = proc_info["cpu_id"]
        to_cpu = 1 if from_cpu == 0 else 0
        migrate_result = kernel.syscall(
            SyscallNumber.SYS_MIGRATE,
            pid=pid,
            from_cpu=from_cpu,
            to_cpu=to_cpu,
        )
        assert migrate_result["success"] is True


# -- Cycle 8: /proc filesystem -----------------------------------------------


class TestProcMultiCPU:
    """/proc should expose multi-CPU state."""

    def test_proc_cpuinfo_multi_cpu(self) -> None:
        """/proc/cpuinfo should show per-CPU sections."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        content = kernel.syscall(SyscallNumber.SYS_PROC_READ, path="/proc/cpuinfo")
        assert "NumCPUs:" in content
        assert "CPU 0:" in content
        assert "CPU 1:" in content

    def test_proc_pid_status_has_cpu(self) -> None:
        """/proc/{pid}/status should include CPU field."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="worker",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        content = kernel.syscall(SyscallNumber.SYS_PROC_READ, path=f"/proc/{pid}/status")
        assert "CPU:" in content

    def test_proc_stat_has_migrations(self) -> None:
        """/proc/stat should include Migrations field."""
        kernel = _syscall_kernel(num_cpus=NUM_CPUS_TWO)
        content = kernel.syscall(SyscallNumber.SYS_PROC_READ, path="/proc/stat")
        assert "Migrations:" in content


# -- Cycle 9: Shell commands --------------------------------------------------


def _shell_kernel(num_cpus: int = 2) -> tuple[Kernel, Shell]:
    """Boot a kernel and create a shell for testing."""
    kernel = Kernel(total_frames=64, num_cpus=num_cpus)
    kernel.boot()
    shell = Shell(kernel=kernel)
    return kernel, shell


class TestShellMultiCPU:
    """Verify shell commands for multi-CPU features."""

    def test_ps_shows_cpu_column(self) -> None:
        """Verify ps output includes CPU column."""
        _kernel, shell = _shell_kernel(num_cpus=NUM_CPUS_TWO)
        output = shell.execute("ps")
        assert "CPU" in output.split("\n")[0]

    def test_cpu_command_shows_per_cpu(self) -> None:
        """The cpu command should show per-CPU status."""
        _kernel, shell = _shell_kernel(num_cpus=NUM_CPUS_TWO)
        output = shell.execute("cpu")
        assert "CPU 0" in output
        assert "CPU 1" in output

    def test_taskset_show_affinity(self) -> None:
        """Taskset should display current affinity for a PID."""
        kernel, shell = _shell_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="worker",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        output = shell.execute(f"taskset {pid}")
        assert "0" in output
        assert "1" in output

    def test_taskset_set_affinity(self) -> None:
        """Taskset should change affinity when given CPU list."""
        kernel, shell = _shell_kernel(num_cpus=NUM_CPUS_TWO)
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_PROCESS,
            name="worker",
            num_pages=NUM_PAGES,
        )
        pid = result["pid"]
        output = shell.execute(f"taskset {pid} 1")
        assert "1" in output

    def test_scheduler_balance(self) -> None:
        """Scheduler balance command should show migration count."""
        _kernel, shell = _shell_kernel(num_cpus=NUM_CPUS_TWO)
        output = shell.execute("scheduler balance")
        assert "migration" in output.lower()


# -- Cycle 10: Bootloader + documentation ------------------------------------


class TestBootloaderMultiCPU:
    """Verify bootloader passes num_cpus to kernel."""

    def test_kernel_image_num_cpus(self) -> None:
        """KernelImage should store num_cpus field."""
        img = KernelImage(
            version="0.1.0",
            total_frames=64,
            default_policy="fcfs",
            num_cpus=NUM_CPUS_FOUR,
        )
        assert img.num_cpus == NUM_CPUS_FOUR

    def test_boot_with_multi_cpu_image(self) -> None:
        """Bootloader should pass num_cpus to the kernel."""
        bootloader = Bootloader(total_frames=64, num_cpus=NUM_CPUS_TWO)
        kernel = bootloader.boot()
        kernel._execution_mode = ExecutionMode.KERNEL
        assert kernel.num_cpus == NUM_CPUS_TWO
        assert kernel.scheduler is not None
        assert kernel.scheduler.num_cpus == NUM_CPUS_TWO
