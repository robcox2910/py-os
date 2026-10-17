"""Memory commands -- mapped memory, the slab allocator, swap and shared memory."""

import contextlib
from collections.abc import Callable

from py_os.shell.base import DEFAULT_PAGE_SIZE, ShellBase
from py_os.syscalls import SyscallError, SyscallNumber

# A table of sub-commands: word typed by the user -> the method that handles it.
type _SubcommandTable = dict[str, Callable[[list[str]], str]]


class MemoryCommands(ShellBase):
    """Shell commands for mapped memory, the slab allocator, swap and shared memory."""

    def _cmd_mmap(self, args: list[str]) -> str:
        """Map a file into a process's virtual address space."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: mmap <pid> <path> [--shared]"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        path = args[1]
        shared = "--shared" in args
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_MMAP,
                pid=pid,
                path=path,
                shared=shared,
            )
            return (
                f"Mapped {path} at address {result['virtual_address']}"
                f" ({result['num_pages']} pages)"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_munmap(self, args: list[str]) -> str:
        """Unmap a memory-mapped region."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: munmap <pid> <address>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            address = int(args[1])
        except ValueError:
            return f"Error: invalid address '{args[1]}'"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_MUNMAP,
                pid=pid,
                virtual_address=address,
            )
            return f"Unmapped address {address}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_msync(self, args: list[str]) -> str:
        """Sync a shared mapping's data back to the file."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: msync <pid> <address>"
        try:
            pid = int(args[0])
        except ValueError:
            return f"Error: invalid PID '{args[0]}'"
        try:
            address = int(args[1])
        except ValueError:
            return f"Error: invalid address '{args[1]}'"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_MSYNC,
                pid=pid,
                virtual_address=address,
            )
            # Look up region path for the output message
            regions = self._kernel.mmap_regions(pid)
            vpn = address // DEFAULT_PAGE_SIZE
            region = regions.get(vpn)
            path_info = f" to {region.path}" if region else ""
            return f"Synced address {address}{path_info}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slabcreate(self, args: list[str]) -> str:
        """Create a named slab cache with a given object size."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: slabcreate <name> <obj_size>"
        name = args[0]
        try:
            obj_size = int(args[1])
        except ValueError:
            return f"Error: invalid obj_size '{args[1]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SLAB_CREATE,
                name=name,
                obj_size=obj_size,
            )
            return (
                f"Created cache '{result['name']}'"
                f" ({result['obj_size']} bytes,"
                f" {result['capacity_per_slab']} per slab)"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slaballoc(self, args: list[str]) -> str:
        """Allocate an object from a slab cache."""
        if not args:
            return "Usage: slaballoc <cache>"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SLAB_ALLOC,
                cache=args[0],
            )
            return (
                f"Allocated from '{result['cache']}':"
                f" slab {result['slab_index']}, slot {result['slot_index']}"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slabfree(self, args: list[str]) -> str:
        """Free an object back to a slab cache."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: slabfree <cache> <slab_index> <slot_index>"
        name = args[0]
        try:
            slab_index = int(args[1])
        except ValueError:
            return f"Error: invalid slab_index '{args[1]}'"
        try:
            slot_index = int(args[2])
        except ValueError:
            return f"Error: invalid slot_index '{args[2]}'"
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SLAB_FREE,
                cache=name,
                slab_index=slab_index,
                slot_index=slot_index,
            )
            return f"Freed '{name}' slab {slab_index}, slot {slot_index}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_slabinfo(self, _args: list[str]) -> str:
        """Show slab cache statistics."""
        info: dict[str, dict[str, object]] = self._kernel.syscall(
            SyscallNumber.SYS_SLAB_INFO,
        )
        if not info:
            return "No slab caches."
        lines = ["CACHE      OBJ_SIZE  SLABS  USED  FREE"]
        for name in sorted(info):
            stats = info[name]
            lines.append(
                f"{name:<10} {stats['obj_size']!s:>8}"
                f"  {stats['total_slabs']!s:>5}"
                f"  {stats['used_slots']!s:>4}"
                f"  {stats['free_slots']!s:>4}"
            )
        return "\n".join(lines)

    def _cmd_shm(self, args: list[str]) -> str:
        """Manage shared memory segments."""
        dispatch: _SubcommandTable = {
            "create": self._cmd_shm_create,
            "attach": self._cmd_shm_attach,
            "detach": self._cmd_shm_detach,
            "write": self._cmd_shm_write,
            "read": self._cmd_shm_read,
            "list": lambda _a: self._cmd_shm_list(),
            "destroy": self._cmd_shm_destroy,
            "demo": lambda _a: self._cmd_shm_demo(),
        }
        if not args or args[0] not in dispatch:
            return "Usage: shm <create|attach|detach|write|read|list|destroy|demo>"
        return dispatch[args[0]](args[1:])

    def _cmd_shm_create(self, args: list[str]) -> str:
        """Create a named shared memory segment."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: shm create <name> <size> <pid>"
        name = args[0]
        try:
            size = int(args[1])
        except ValueError:
            return f"Error: invalid size '{args[1]}'"
        try:
            pid = int(args[2])
        except ValueError:
            return f"Error: invalid PID '{args[2]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_CREATE, name=name, size=size, pid=pid
            )
            return (
                f"Created shared memory '{result['name']}'"
                f" ({result['size']} bytes, {result['num_pages']} pages)"
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_attach(self, args: list[str]) -> str:
        """Attach a process to a shared memory segment."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: shm attach <name> <pid>"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_ATTACH, name=name, pid=pid
            )
            return f"Attached pid {pid} to '{name}' at address {result['virtual_address']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_detach(self, args: list[str]) -> str:
        """Detach a process from a shared memory segment."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: shm detach <name> <pid>"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SHM_DETACH, name=name, pid=pid)
            return f"Detached pid {pid} from '{name}'"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_write(self, args: list[str]) -> str:
        """Write data to a shared memory segment."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: shm write <name> <pid> <data> [offset]"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        offset = 0
        if len(args) > min_args:
            try:
                offset = int(args[-1])
                data = " ".join(args[2:-1])
            except ValueError:
                data = " ".join(args[2:])
        else:
            data = args[2]
        try:
            self._kernel.syscall(
                SyscallNumber.SYS_SHM_WRITE,
                name=name,
                pid=pid,
                data=data.encode(),
                offset=offset,
            )
            return f"Wrote {len(data)} bytes to '{name}'"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_read(self, args: list[str]) -> str:
        """Read data from a shared memory segment."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: shm read <name> <pid> [offset] [size]"
        name = args[0]
        try:
            pid = int(args[1])
        except ValueError:
            return f"Error: invalid PID '{args[1]}'"
        kwargs: dict[str, object] = {"name": name, "pid": pid}
        if len(args) > min_args:
            try:
                kwargs["offset"] = int(args[2])
            except ValueError:
                return f"Error: invalid offset '{args[2]}'"
        min_args_with_size = 4
        if len(args) >= min_args_with_size:
            try:
                kwargs["size"] = int(args[3])
            except ValueError:
                return f"Error: invalid size '{args[3]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SHM_READ, **kwargs)
            data: bytes = result["data"]  # type: ignore[assignment]
            return data.decode(errors="replace").rstrip("\x00")
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_list(self) -> str:
        """List all shared memory segments."""
        segments: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_SHM_LIST)
        if not segments:
            return "No shared memory segments."
        lines = ["NAME       SIZE  PAGES  CREATOR  ATTACHED  MARKED"]
        for seg in segments:
            marked = "yes" if seg["marked_for_deletion"] else "no"
            lines.append(
                f"{seg['name']:<10} {seg['size']!s:>5}"
                f"  {seg['num_pages']!s:>5}"
                f"  {seg['creator_pid']!s:>7}"
                f"  {seg['attached']!s:>8}"
                f"  {marked}"
            )
        return "\n".join(lines)

    def _cmd_shm_destroy(self, args: list[str]) -> str:
        """Destroy a shared memory segment."""
        if not args:
            return "Usage: shm destroy <name>"
        try:
            self._kernel.syscall(SyscallNumber.SYS_SHM_DESTROY, name=args[0])
            return f"Destroyed shared memory '{args[0]}'"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_shm_demo(self) -> str:
        """Walk through a shared memory demo — the shared whiteboard."""
        lines: list[str] = [
            "=== Shared Memory Demo ===",
            "",
            "Imagine a shared whiteboard in the school hallway.",
            "Any student can walk up and write on it, and everyone",
            "else can see what's there instantly.",
            "",
        ]

        try:
            # Create two processes
            writer_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="writer", num_pages=1
            )
            reader_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="reader", num_pages=1
            )
            writer_pid: int = writer_r["pid"]
            reader_pid: int = reader_r["pid"]

            lines.append(
                f"Step 1: Create two processes: writer (pid={writer_pid})"
                f" and reader (pid={reader_pid})"
            )

            # Create a shared memory segment
            seg_r: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_CREATE, name="_demo_board", size=64, pid=writer_pid
            )
            lines.append(
                f"Step 2: Create shared memory 'board'"
                f" ({seg_r['size']} bytes, {seg_r['num_pages']} pages)"
            )

            # Attach both processes
            self._kernel.syscall(SyscallNumber.SYS_SHM_ATTACH, name="_demo_board", pid=writer_pid)
            self._kernel.syscall(SyscallNumber.SYS_SHM_ATTACH, name="_demo_board", pid=reader_pid)
            lines.append("Step 3: Both processes attach to the shared memory")

            # Writer writes
            message = "Hello from Process A!"
            self._kernel.syscall(
                SyscallNumber.SYS_SHM_WRITE,
                name="_demo_board",
                pid=writer_pid,
                data=message.encode(),
            )
            lines.append(f'Step 4: Writer writes "{message}"')

            # Reader reads
            read_r: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_SHM_READ,
                name="_demo_board",
                pid=reader_pid,
                size=len(message),
            )
            data: bytes = read_r["data"]  # type: ignore[assignment]
            lines.append(f'Step 5: Reader reads: "{data.decode()}"')
            lines.append("  The data appeared instantly -- shared whiteboard!")

            lines.append("")
            lines.append("Note: Without synchronization (like a semaphore), two")
            lines.append("processes writing at the same time could corrupt data.")
            lines.append("Always use a lock or semaphore to protect shared memory!")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_SHM_DESTROY, name="_demo_board")

        return "\n".join(lines)

    def _cmd_swap(self, args: list[str]) -> str:
        """Display or manage swap space and page replacement."""
        if not args:
            return self._swap_status()
        match args[0]:
            case "policy":
                return self._swap_policy(args[1:])
            case "demo":
                return self._swap_demo()
            case _:
                return "Usage: swap [policy <fifo|lru|clock>|demo]"

    def _swap_status(self) -> str:
        """Display swap space status."""
        try:
            info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
        except SyscallError as e:
            return f"Error: {e}"
        lines: list[str] = [
            "--- Swap Status ---",
            f"  Policy:         {info['policy']}",
            f"  Swap used:      {info['swap_used']}/{info['swap_total']} pages",
            f"  Swap free:      {info['swap_free']} pages",
            f"  Page faults:    {info['page_faults']}",
            f"  Resident pages: {info['resident_count']}",
        ]
        return "\n".join(lines)

    def _swap_policy(self, args: list[str]) -> str:
        """Change the swap replacement policy."""
        if not args:
            return "Usage: swap policy <fifo|lru|clock>"
        name = args[0]
        try:
            self._kernel.syscall(SyscallNumber.SYS_SET_SWAP_POLICY, name=name)
        except SyscallError as e:
            return f"Error: {e}"
        return f"Swap policy changed to {name}"

    def _swap_demo(self) -> str:
        """Exercise the pager and show before/after statistics."""
        try:
            before: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SWAP_EXERCISE)
            after: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_SWAP_INFO)
        except SyscallError as e:
            return f"Error: {e}"
        lines: list[str] = [
            "--- Swap Demo ---",
            f"  Policy:          {before['policy']}",
            f"  Pages accessed:  {result['pages_accessed']}",
            f"  Faults before:   {result['faults_before']}",
            f"  Faults after:    {result['faults_after']}",
            f"  New faults:      {result['new_faults']}",
            f"  Swap used after: {after['swap_used']}/{after['swap_total']} pages",
        ]
        return "\n".join(lines)

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("mmap", _cmd_mmap),
        ("munmap", _cmd_munmap),
        ("msync", _cmd_msync),
        ("slabcreate", _cmd_slabcreate),
        ("slaballoc", _cmd_slaballoc),
        ("slabfree", _cmd_slabfree),
        ("slabinfo", _cmd_slabinfo),
        ("swap", _cmd_swap),
        ("shm", _cmd_shm),
    )
