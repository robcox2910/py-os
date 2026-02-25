"""Tests for shared memory IPC — roadmap item #18.

Shared memory is the fastest IPC mechanism: named memory regions that
multiple processes can attach to for direct, bidirectional data sharing.
"""

import math

import pytest

from py_os.completer import Completer
from py_os.io.shm import SharedMemoryError, SharedMemorySegment
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

# Default page size used by VirtualMemory
PAGE_SIZE = 256
# Common test segment size
SEGMENT_SIZE = 64


@pytest.fixture
def kernel() -> Kernel:
    """Return a booted kernel."""
    k = Kernel()
    k.boot()
    k._execution_mode = ExecutionMode.KERNEL
    return k


@pytest.fixture
def kernel_with_procs(kernel: Kernel) -> tuple[Kernel, int, int]:
    """Return a kernel with two processes (writer, reader)."""
    writer = kernel.create_process(name="writer", num_pages=1)
    reader = kernel.create_process(name="reader", num_pages=1)
    return kernel, writer.pid, reader.pid


# ── Cycle 1: SharedMemorySegment dataclass ──────────────────────────


class TestSharedMemorySegment:
    """Verify the SharedMemorySegment dataclass and SharedMemoryError."""

    def test_fields(self) -> None:
        """Segment stores all expected fields."""
        seg = SharedMemorySegment(
            name="test",
            size=SEGMENT_SIZE,
            num_pages=1,
            frames=[0],
            storage=[bytearray(PAGE_SIZE)],
            creator_pid=1,
        )
        assert seg.name == "test"
        assert seg.size == SEGMENT_SIZE
        assert seg.num_pages == 1
        assert seg.frames == [0]
        assert seg.creator_pid == 1

    def test_default_attachments_empty(self) -> None:
        """Segment starts with no attachments."""
        seg = SharedMemorySegment(
            name="x",
            size=1,
            num_pages=1,
            frames=[0],
            storage=[bytearray(PAGE_SIZE)],
            creator_pid=1,
        )
        assert seg.attachments == {}
        assert seg.marked_for_deletion is False

    def test_shared_memory_error(self) -> None:
        """SharedMemoryError is a standalone exception."""
        with pytest.raises(SharedMemoryError, match="boom"):
            raise SharedMemoryError("boom")


# ── Cycle 2: shm_create ─────────────────────────────────────────────


class TestShmCreate:
    """Verify shared memory creation."""

    def test_create_returns_segment(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Create return a segment with correct fields."""
        k, writer_pid, _reader_pid = kernel_with_procs
        seg = k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        assert seg.name == "board"
        assert seg.size == SEGMENT_SIZE
        expected_pages = math.ceil(SEGMENT_SIZE / PAGE_SIZE)
        assert seg.num_pages == expected_pages
        assert len(seg.frames) == expected_pages

    def test_create_allocates_frames(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Frames are allocated from the kernel (pid 0)."""
        k, writer_pid, _reader_pid = kernel_with_procs
        assert k.memory is not None
        free_before = k.memory.free_frames
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        expected_pages = math.ceil(SEGMENT_SIZE / PAGE_SIZE)
        assert k.memory.free_frames == free_before - expected_pages

    def test_duplicate_name_raises(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Creating a segment with an existing name raises."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        with pytest.raises(SharedMemoryError, match="already exists"):
            k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)

    def test_shm_list(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """List returns info for all segments."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        segments = k.shm_list()
        assert len(segments) == 1
        assert segments[0]["name"] == "board"
        assert segments[0]["size"] == SEGMENT_SIZE
        assert segments[0]["attached"] == 0

    def test_invalid_size_raises(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Size must be positive."""
        k, writer_pid, _reader_pid = kernel_with_procs
        with pytest.raises(SharedMemoryError, match="Invalid size"):
            k.shm_create(name="bad", size=0, pid=writer_pid)


# ── Cycle 3: shm_attach / shm_detach ────────────────────────────────


class TestShmAttachDetach:
    """Verify attach and detach operations."""

    def test_attach_returns_address(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Attach return a valid virtual address."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        addr = k.shm_attach(name="board", pid=writer_pid)
        assert addr >= 0
        assert addr % PAGE_SIZE == 0

    def test_attach_maps_into_vas(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Attach map the segment's frames into the process VAS."""
        k, writer_pid, _reader_pid = kernel_with_procs
        seg = k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        addr = k.shm_attach(name="board", pid=writer_pid)
        process = k.processes[writer_pid]
        assert process.virtual_memory is not None
        vpn = addr // PAGE_SIZE
        mapped_frame = process.virtual_memory.page_table.translate(vpn)
        assert mapped_frame == seg.frames[0]

    def test_attach_increments_refcount(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Attach increment the refcount on each frame."""
        k, writer_pid, _reader_pid = kernel_with_procs
        assert k.memory is not None
        seg = k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        # Kernel owns the base reference (refcount=1)
        base_rc = k.memory.refcount(seg.frames[0])
        k.shm_attach(name="board", pid=writer_pid)
        assert k.memory.refcount(seg.frames[0]) == base_rc + 1

    def test_detach_unmaps_and_decrements(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Detach unmap from VAS and decrement refcount."""
        k, writer_pid, _reader_pid = kernel_with_procs
        assert k.memory is not None
        seg = k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        addr = k.shm_attach(name="board", pid=writer_pid)
        vpn = addr // PAGE_SIZE

        rc_before = k.memory.refcount(seg.frames[0])
        k.shm_detach(name="board", pid=writer_pid)

        # Refcount decremented
        assert k.memory.refcount(seg.frames[0]) == rc_before - 1

        # VPN no longer mapped
        process = k.processes[writer_pid]
        assert process.virtual_memory is not None
        assert vpn not in process.virtual_memory.page_table.mappings()

    def test_double_attach_raises(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Attaching the same pid twice raises."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)
        with pytest.raises(SharedMemoryError, match="already attached"):
            k.shm_attach(name="board", pid=writer_pid)

    def test_detach_without_attach_raises(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Detaching a pid that isn't attached raises."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        with pytest.raises(SharedMemoryError, match="not attached"):
            k.shm_detach(name="board", pid=writer_pid)


# ── Cycle 4: shm_read / shm_write ───────────────────────────────────


class TestShmReadWrite:
    """Verify read and write through shared memory."""

    def test_write_then_read(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Write data and read it back from the same process."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)

        k.shm_write(name="board", pid=writer_pid, data=b"hello")
        result = k.shm_read(name="board", pid=writer_pid, size=5)
        assert result == b"hello"

    def test_data_visible_across_processes(
        self, kernel_with_procs: tuple[Kernel, int, int]
    ) -> None:
        """Data written by one process is visible to another."""
        k, writer_pid, reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)
        k.shm_attach(name="board", pid=reader_pid)

        k.shm_write(name="board", pid=writer_pid, data=b"shared data")
        result = k.shm_read(name="board", pid=reader_pid, size=11)
        assert result == b"shared data"

    def test_write_with_offset(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Write data at a non-zero offset."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)

        k.shm_write(name="board", pid=writer_pid, data=b"world", offset=5)
        result = k.shm_read(name="board", pid=writer_pid, offset=5, size=5)
        assert result == b"world"

    def test_boundary_validation(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Write exceeding segment size raise an error."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=10, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)

        with pytest.raises(SharedMemoryError, match="exceeds segment size"):
            k.shm_write(name="board", pid=writer_pid, data=b"x" * 11)


# ── Cycle 5: shm_destroy lifecycle ──────────────────────────────────


class TestShmLifecycle:
    """Verify create/destroy lifecycle including deferred deletion."""

    def test_destroy_no_attachments_frees(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Destroy with no attachments free the segment immediately."""
        k, writer_pid, _reader_pid = kernel_with_procs
        assert k.memory is not None
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        free_before = k.memory.free_frames
        k.shm_destroy(name="board")
        assert "board" not in [s["name"] for s in k.shm_list()]
        # Frames returned to free pool
        expected_pages = math.ceil(SEGMENT_SIZE / PAGE_SIZE)
        assert k.memory.free_frames == free_before + expected_pages

    def test_destroy_with_attachments_marks(
        self, kernel_with_procs: tuple[Kernel, int, int]
    ) -> None:
        """Destroy with attachments mark for deletion but don't free."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)
        k.shm_destroy(name="board")

        segments = k.shm_list()
        assert len(segments) == 1
        assert segments[0]["marked_for_deletion"] is True

    def test_last_detach_frees_marked(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Last detach from a marked segment free it."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)
        k.shm_destroy(name="board")

        k.shm_detach(name="board", pid=writer_pid)
        assert not k.shm_list()

    def test_attach_to_marked_raises(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Attaching to a segment marked for deletion raises."""
        k, writer_pid, reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shm_attach(name="board", pid=writer_pid)
        k.shm_destroy(name="board")

        with pytest.raises(SharedMemoryError, match="marked for deletion"):
            k.shm_attach(name="board", pid=reader_pid)


# ── Cycle 6: Fork integration ───────────────────────────────────────


class TestShmFork:
    """Verify shared memory survives fork."""

    def test_child_inherits_attachments(self, kernel: Kernel) -> None:
        """Child process inherit parent's shm attachments."""
        parent = kernel.create_process(name="parent", num_pages=1)
        seg = kernel.shm_create(name="board", size=SEGMENT_SIZE, pid=parent.pid)
        kernel.shm_attach(name="board", pid=parent.pid)

        child = kernel.fork_process(parent_pid=parent.pid)
        assert child.pid in seg.attachments

    def test_child_reads_parent_data(self, kernel: Kernel) -> None:
        """Child can read data written by parent."""
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.shm_create(name="board", size=SEGMENT_SIZE, pid=parent.pid)
        kernel.shm_attach(name="board", pid=parent.pid)
        kernel.shm_write(name="board", pid=parent.pid, data=b"from parent")

        child = kernel.fork_process(parent_pid=parent.pid)
        result = kernel.shm_read(name="board", pid=child.pid, size=11)
        assert result == b"from parent"

    def test_bidirectional_sharing(self, kernel: Kernel) -> None:
        """Child writes are visible to parent (true shared memory)."""
        parent = kernel.create_process(name="parent", num_pages=1)
        kernel.shm_create(name="board", size=SEGMENT_SIZE, pid=parent.pid)
        kernel.shm_attach(name="board", pid=parent.pid)

        child = kernel.fork_process(parent_pid=parent.pid)
        kernel.shm_write(name="board", pid=child.pid, data=b"from child")
        result = kernel.shm_read(name="board", pid=parent.pid, size=10)
        assert result == b"from child"


# ── Cycle 7: Cleanup on terminate / shutdown ─────────────────────────


class TestShmCleanup:
    """Verify cleanup during process termination and kernel shutdown."""

    def test_terminate_detaches(self, kernel: Kernel) -> None:
        """Terminating a process detach it from shared memory."""
        proc = kernel.create_process(name="worker", num_pages=1)
        proc.program = lambda: "done"
        seg = kernel.shm_create(name="board", size=SEGMENT_SIZE, pid=proc.pid)
        kernel.shm_attach(name="board", pid=proc.pid)
        assert proc.pid in seg.attachments

        # run_process terminates the process
        kernel.run_process(pid=proc.pid)
        assert proc.pid not in seg.attachments

    def test_terminate_last_on_marked_frees(self, kernel: Kernel) -> None:
        """Terminating the last attached process on a marked segment free it."""
        proc = kernel.create_process(name="worker", num_pages=1)
        proc.program = lambda: "done"
        kernel.shm_create(name="board", size=SEGMENT_SIZE, pid=proc.pid)
        kernel.shm_attach(name="board", pid=proc.pid)
        kernel.shm_destroy(name="board")

        kernel.run_process(pid=proc.pid)
        assert not kernel.shm_list()

    def test_shutdown_clears(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Kernel shutdown clear all shared memory segments."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.shm_create(name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.shutdown()
        # After shutdown, kernel is in SHUTDOWN state
        # Re-boot to verify no stale segments
        k.boot()
        k._execution_mode = ExecutionMode.KERNEL
        assert not k.shm_list()


# ── Cycle 8: Integration (syscalls, shell, completer) ────────────────


class TestShmIntegration:
    """Verify end-to-end integration through syscalls, shell, and completer."""

    def test_syscall_create(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """SYS_SHM_CREATE create a segment via syscall."""
        k, writer_pid, _reader_pid = kernel_with_procs
        result = k.syscall(
            SyscallNumber.SYS_SHM_CREATE, name="board", size=SEGMENT_SIZE, pid=writer_pid
        )
        assert result["name"] == "board"
        assert result["size"] == SEGMENT_SIZE

    def test_syscall_roundtrip(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Full syscall roundtrip: create → attach → write → read → detach → destroy."""
        k, writer_pid, reader_pid = kernel_with_procs

        k.syscall(SyscallNumber.SYS_SHM_CREATE, name="board", size=SEGMENT_SIZE, pid=writer_pid)
        k.syscall(SyscallNumber.SYS_SHM_ATTACH, name="board", pid=writer_pid)
        k.syscall(SyscallNumber.SYS_SHM_ATTACH, name="board", pid=reader_pid)

        k.syscall(SyscallNumber.SYS_SHM_WRITE, name="board", pid=writer_pid, data=b"hi")
        result = k.syscall(SyscallNumber.SYS_SHM_READ, name="board", pid=reader_pid, size=2)
        assert result["data"] == b"hi"

        k.syscall(SyscallNumber.SYS_SHM_DETACH, name="board", pid=writer_pid)
        k.syscall(SyscallNumber.SYS_SHM_DETACH, name="board", pid=reader_pid)
        k.syscall(SyscallNumber.SYS_SHM_DESTROY, name="board")

    def test_syscall_list(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """SYS_SHM_LIST return segment info."""
        k, writer_pid, _reader_pid = kernel_with_procs
        k.syscall(SyscallNumber.SYS_SHM_CREATE, name="board", size=SEGMENT_SIZE, pid=writer_pid)
        result: list[dict[str, object]] = k.syscall(SyscallNumber.SYS_SHM_LIST)
        assert len(result) == 1
        assert result[0]["name"] == "board"

    def test_syscall_error_handling(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Syscall errors are wrapped in SyscallError."""
        k, _writer_pid, _reader_pid = kernel_with_procs
        with pytest.raises(SyscallError, match="not found"):
            k.syscall(SyscallNumber.SYS_SHM_ATTACH, name="nope", pid=_writer_pid)

    def test_shell_create_and_list(self, kernel_with_procs: tuple[Kernel, int, int]) -> None:
        """Shell shm create and shm list work end-to-end."""
        k, writer_pid, _reader_pid = kernel_with_procs
        shell = Shell(kernel=k)
        out = shell.execute(f"shm create board 64 {writer_pid}")
        assert "Created" in out
        assert "board" in out

        out = shell.execute("shm list")
        assert "board" in out

    def test_shell_demo(self, kernel: Kernel) -> None:
        """Shell shm demo run without error."""
        shell = Shell(kernel=kernel)
        out = shell.execute("shm demo")
        assert "Shared Memory Demo" in out
        assert "whiteboard" in out

    def test_completer_shm_subcommands(self, kernel: Kernel) -> None:
        """Tab completer suggest shm subcommands."""
        shell = Shell(kernel=kernel)
        comp = Completer(shell)
        candidates = comp.completions("", "shm ")
        assert "create" in candidates
        assert "attach" in candidates
        assert "demo" in candidates

    def test_unshare_frame(self, kernel: Kernel) -> None:
        """MemoryManager.unshare_frame remove a frame from the page table."""
        assert kernel.memory is not None
        frame = kernel.memory.allocate_one(99)
        assert frame in kernel.memory.pages_for(99)
        kernel.memory.unshare_frame(pid=99, frame=frame)
        assert frame not in kernel.memory.pages_for(99)

    def test_unshare_frame_missing_is_noop(self, kernel: Kernel) -> None:
        """Unsharing a frame not in the table is a no-op."""
        assert kernel.memory is not None
        # No error raised
        kernel.memory.unshare_frame(pid=999, frame=999)
