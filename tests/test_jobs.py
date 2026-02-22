"""Tests for the job control system.

Job control lets users manage background and foreground processes.
A "job" is a shell-level concept that wraps a kernel process, adding
a job number and status tracking (running, stopped, done).
"""

from py_os.jobs import Job, JobManager, JobStatus
from py_os.kernel import Kernel
from py_os.process.pcb import Process
from py_os.shell import Shell


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


def _running_process(kernel: Kernel, name: str = "test") -> Process:
    """Create a process and dispatch it so it's RUNNING."""
    proc = kernel.create_process(name=name, num_pages=4)
    assert kernel.scheduler is not None
    kernel.scheduler.dispatch()
    return proc


class TestJobStatus:
    """Verify job status values."""

    def test_status_values(self) -> None:
        """JobStatus should have running, stopped, and done."""
        assert JobStatus.RUNNING == "running"
        assert JobStatus.STOPPED == "stopped"
        assert JobStatus.DONE == "done"


class TestJob:
    """Verify the Job data structure."""

    def test_job_has_fields(self) -> None:
        """A job should store job_id, pid, name, and status."""
        job = Job(job_id=1, pid=42, name="sleep")
        assert job.job_id == 1
        expected_pid = 42
        assert job.pid == expected_pid
        assert job.name == "sleep"
        assert job.status is JobStatus.RUNNING

    def test_job_str(self) -> None:
        """String representation should include job id and status."""
        job = Job(job_id=1, pid=42, name="sleep")
        text = str(job)
        assert "[1]" in text
        assert "sleep" in text
        assert "running" in text


class TestJobManager:
    """Verify the job manager."""

    def test_add_job(self) -> None:
        """Adding a job should assign an incrementing job id."""
        mgr = JobManager()
        job = mgr.add(pid=10, name="first")
        assert job.job_id == 1
        job2 = mgr.add(pid=20, name="second")
        expected_id = 2
        assert job2.job_id == expected_id

    def test_get_by_id(self) -> None:
        """Getting a job by id should return the correct job."""
        mgr = JobManager()
        mgr.add(pid=10, name="test")
        job = mgr.get(1)
        assert job is not None
        assert job.name == "test"

    def test_get_missing_returns_none(self) -> None:
        """Getting a non-existent job should return None."""
        mgr = JobManager()
        assert mgr.get(99) is None

    def test_list_jobs(self) -> None:
        """Listing should return all jobs."""
        mgr = JobManager()
        mgr.add(pid=10, name="a")
        mgr.add(pid=20, name="b")
        jobs = mgr.list_jobs()
        expected_count = 2
        assert len(jobs) == expected_count

    def test_remove_job(self) -> None:
        """Removing a job should make it no longer retrievable."""
        mgr = JobManager()
        mgr.add(pid=10, name="test")
        mgr.remove(1)
        assert mgr.get(1) is None

    def test_get_by_pid(self) -> None:
        """Getting a job by PID should return the correct job."""
        mgr = JobManager()
        mgr.add(pid=42, name="test")
        job = mgr.get_by_pid(42)
        assert job is not None
        assert job.name == "test"

    def test_get_by_pid_missing(self) -> None:
        """Getting by a non-existent PID should return None."""
        mgr = JobManager()
        assert mgr.get_by_pid(999) is None


class TestJobOutputFields:
    """Verify the output and exit_code fields on Job."""

    def test_output_defaults_to_none(self) -> None:
        """A new job should have output=None by default."""
        job = Job(job_id=1, pid=10, name="test")
        assert job.output is None

    def test_exit_code_defaults_to_none(self) -> None:
        """A new job should have exit_code=None by default."""
        job = Job(job_id=1, pid=10, name="test")
        assert job.exit_code is None

    def test_output_can_be_set(self) -> None:
        """Output should be settable after creation."""
        job = Job(job_id=1, pid=10, name="test")
        job.output = "Hello from PyOS!\n[exit code: 0]"
        assert job.output == "Hello from PyOS!\n[exit code: 0]"

    def test_exit_code_can_be_set(self) -> None:
        """Exit code should be settable after creation."""
        job = Job(job_id=1, pid=10, name="test")
        job.exit_code = 0
        assert job.exit_code == 0


class TestShellJobCommands:
    """Verify the shell's job control commands."""

    def test_jobs_lists_background_jobs(self) -> None:
        """The jobs command should list tracked jobs."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        proc = _running_process(kernel, name="daemon")
        shell.execute(f"bg {proc.pid}")
        result = shell.execute("jobs")
        assert "daemon" in result

    def test_bg_adds_job(self) -> None:
        """The bg command should add a process as a background job."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        proc = _running_process(kernel, name="worker")
        result = shell.execute(f"bg {proc.pid}")
        assert "[1]" in result or "background" in result.lower()

    def test_bg_missing_args(self) -> None:
        """Bg without args should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("bg")
        assert "usage" in result.lower()

    def test_fg_brings_to_foreground(self) -> None:
        """The fg command should mark a job as foreground (done)."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        proc = _running_process(kernel, name="worker")
        shell.execute(f"bg {proc.pid}")
        result = shell.execute("fg 1")
        assert "foreground" in result.lower() or "worker" in result.lower()

    def test_fg_missing_args(self) -> None:
        """Fg without args should show usage."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("fg")
        assert "usage" in result.lower()

    def test_fg_invalid_job(self) -> None:
        """Fg with a non-existent job id should show error."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("fg 99")
        assert "error" in result.lower() or "not found" in result.lower()

    def test_help_includes_job_commands(self) -> None:
        """Help should list jobs, bg, and fg commands."""
        kernel = _booted_kernel()
        shell = Shell(kernel=kernel)
        result = shell.execute("help")
        assert "jobs" in result
        assert "bg" in result
        assert "fg" in result
