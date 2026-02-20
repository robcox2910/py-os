"""Job control — shell-level process management.

In Unix, a "job" is a shell concept layered on top of kernel processes.
When you run ``sleep 60 &``, the shell creates a kernel process *and*
a job entry to track it.  Job control commands (``jobs``, ``fg``,
``bg``, ``Ctrl-Z``) operate on these shell-level jobs.

Key ideas:
    - **Jobs are not processes** — they're a shell abstraction that
      *wraps* a process, adding a job number and status tracking.
    - **Job numbers are small** — ``[1]``, ``[2]``, etc., for human
      convenience (unlike PIDs which can be large).
    - **Job status** — RUNNING (executing in background), STOPPED
      (paused via SIGSTOP/Ctrl-Z), DONE (finished).

Design choices:
    - ``JobManager`` is owned by the shell, not the kernel — because
      jobs are a user-space concept.
    - Auto-incrementing job IDs via ``itertools.count``.
"""

from dataclasses import dataclass
from enum import StrEnum
from itertools import count


class JobStatus(StrEnum):
    """Status of a shell job."""

    RUNNING = "running"
    STOPPED = "stopped"
    DONE = "done"


@dataclass
class Job:
    """A shell job wrapping a kernel process.

    Attributes:
        job_id: Small human-friendly job number ([1], [2], ...).
        pid: The underlying kernel process PID.
        name: The command or process name.
        status: Current job status.

    """

    job_id: int
    pid: int
    name: str
    status: JobStatus = JobStatus.RUNNING

    def __str__(self) -> str:
        """Format as ``[id] status name (pid=N)``."""
        return f"[{self.job_id}] {self.status} {self.name} (pid={self.pid})"


class JobManager:
    """Track background jobs for the shell.

    The job manager maintains a registry of jobs, each identified
    by a small incrementing job number.  This is separate from the
    kernel's process table — jobs are a shell-level concept.
    """

    def __init__(self) -> None:
        """Create an empty job manager."""
        self._jobs: dict[int, Job] = {}
        self._counter = count(start=1)

    def add(self, *, pid: int, name: str) -> Job:
        """Add a new background job.

        Args:
            pid: The kernel process PID.
            name: The command/process name.

        Returns:
            The newly created job.

        """
        job_id = next(self._counter)
        job = Job(job_id=job_id, pid=pid, name=name)
        self._jobs[job_id] = job
        return job

    def get(self, job_id: int) -> Job | None:
        """Return a job by its id, or None."""
        return self._jobs.get(job_id)

    def get_by_pid(self, pid: int) -> Job | None:
        """Return a job by its process PID, or None."""
        return next((j for j in self._jobs.values() if j.pid == pid), None)

    def remove(self, job_id: int) -> None:
        """Remove a job from tracking."""
        self._jobs.pop(job_id, None)

    def list_jobs(self) -> list[Job]:
        """Return all tracked jobs."""
        return list(self._jobs.values())
