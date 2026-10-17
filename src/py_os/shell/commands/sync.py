"""Synchronisation commands -- locks, semaphores, priority inheritance, lock ordering and deadlocks."""

import contextlib

from py_os.shell.base import ShellBase
from py_os.syscalls import SyscallError, SyscallNumber


class SyncCommands(ShellBase):
    """Shell commands for locks, semaphores, priority inheritance, lock ordering and deadlocks."""

    def _cmd_resources(self, _args: list[str]) -> str:
        """Show resource allocation status."""
        resources: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_RESOURCES)
        if not resources:
            return "No resources registered."
        lines = ["RESOURCE   AVAIL"]
        lines.extend(f"{r['name']!s:<10} {r['available']}" for r in resources)
        return "\n".join(lines)

    def _cmd_deadlock(self, _args: list[str]) -> str:
        """Run deadlock detection and report results."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_DETECT_DEADLOCK)
        deadlocked: set[int] = result["deadlocked"]  # type: ignore[assignment]
        if not deadlocked:
            return "No deadlock detected — system is safe."
        pids = sorted(deadlocked)
        return f"DEADLOCK detected! Stuck processes: {pids}"

    def _cmd_mutex(self, args: list[str]) -> str:
        """Manage mutexes — create or list."""
        if not args or args[0] not in {"create", "list"}:
            return "Usage: mutex <create|list> [args...]"
        if args[0] == "create":
            return self._cmd_mutex_create(args[1:])
        return self._cmd_mutex_list()

    def _cmd_mutex_create(self, args: list[str]) -> str:
        """Create a named mutex."""
        if not args:
            return "Usage: mutex create <name>"
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_mutex_list(self) -> str:
        """List all mutexes and their state."""
        mutexes: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_MUTEXES)
        if not mutexes:
            return "No mutexes."
        lines: list[str] = ["NAME       STATE       OWNER"]
        for m in mutexes:
            state = "locked" if m["locked"] else "unlocked"
            owner = str(m["owner"]) if m["owner"] is not None else "-"
            lines.append(f"{m['name']!s:<10} {state:<11} {owner}")
        return "\n".join(lines)

    def _cmd_semaphore(self, args: list[str]) -> str:
        """Manage semaphores — create or list."""
        if not args or args[0] not in {"create", "list"}:
            return "Usage: semaphore <create|list> [args...]"
        if args[0] == "create":
            return self._cmd_semaphore_create(args[1:])
        return self._cmd_semaphore_list()

    def _cmd_semaphore_create(self, args: list[str]) -> str:
        """Create a named semaphore with a given count."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: semaphore create <name> <count>"
        try:
            count = int(args[1])
        except ValueError:
            return f"Error: invalid count '{args[1]}'"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_SEMAPHORE,
                name=args[0],
                count=count,
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_semaphore_list(self) -> str:
        """List all semaphores and their counts."""
        sems: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_SEMAPHORES)
        if not sems:
            return "No semaphores."
        lines: list[str] = ["NAME       COUNT"]
        lines.extend(f"{s['name']!s:<10} {s['count']}" for s in sems)
        return "\n".join(lines)

    def _cmd_rwlock(self, args: list[str]) -> str:
        """Manage reader-writer locks — create or list."""
        if not args or args[0] not in {"create", "list"}:
            return "Usage: rwlock <create|list> [args...]"
        if args[0] == "create":
            return self._cmd_rwlock_create(args[1:])
        return self._cmd_rwlock_list()

    def _cmd_rwlock_create(self, args: list[str]) -> str:
        """Create a named reader-writer lock."""
        if not args:
            return "Usage: rwlock create <name>"
        try:
            result: str = self._kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name=args[0])
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_rwlock_list(self) -> str:
        """List all reader-writer locks and their state."""
        rwlocks: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_RWLOCKS)
        if not rwlocks:
            return "No reader-writer locks."
        lines: list[str] = ["NAME       READERS  WRITER  WAITING"]
        for r in rwlocks:
            readers = str(r["reader_count"])
            writer = str(r["writer_tid"]) if r["writer_tid"] is not None else "-"
            waiting = str(r["wait_queue_size"])
            lines.append(f"{r['name']!s:<10} {readers:<8} {writer:<7} {waiting}")
        return "\n".join(lines)

    def _cmd_pi(self, args: list[str]) -> str:
        """Priority inheritance demo and status.

        Subcommands:
            demo   — walk through the Mars Pathfinder scenario
            status — show which processes are currently boosted
        """
        if not args or args[0] not in {"demo", "status"}:
            return "Usage: pi <demo|status>"
        if args[0] == "demo":
            return self._cmd_pi_demo()
        return self._cmd_pi_status()

    def _cmd_pi_demo(self) -> str:
        """Walk through the Mars Pathfinder priority inversion scenario."""
        lines: list[str] = [
            "=== Mars Pathfinder Priority Inversion Demo ===",
            "",
            "In 1997, NASA's Mars Pathfinder rover kept rebooting on Mars.",
            "A low-priority task held a shared mutex, a high-priority task",
            "blocked waiting for it, and a medium-priority task kept running.",
            "",
            "Let's recreate this with three processes and a mutex:",
        ]

        try:
            # Create demo processes
            low_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="low_task", num_pages=1, priority=1
            )
            med_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="med_task", num_pages=1, priority=5
            )
            high_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="high_task", num_pages=1, priority=10
            )
            low_pid: int = low_r["pid"]
            med_pid: int = med_r["pid"]
            high_pid: int = high_r["pid"]

            low_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=low_pid
            )
            med_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=med_pid
            )
            high_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=high_pid
            )

            lines.append(f"  low_task  (pid={low_pid}, priority=1)")
            lines.append(f"  med_task  (pid={med_pid}, priority=5)")
            lines.append(f"  high_task (pid={high_pid}, priority=10)")

            # Create a mutex
            self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="_pi_demo_lock")

            # Low acquires the mutex
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX,
                name="_pi_demo_lock",
                tid=int(str(low_info["main_tid"])),
                pid=low_pid,
            )
            low_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=low_pid)
            lines.append("")
            lines.append("Step 1: low_task acquires the mutex.")
            lines.append(f"  low_task effective_priority = {low_info['effective_priority']}")

            # High tries to acquire — blocked, triggers PI
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX,
                name="_pi_demo_lock",
                tid=int(str(high_info["main_tid"])),
                pid=high_pid,
            )
            low_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=low_pid)
            med_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=med_pid)
            lines.append("")
            lines.append("Step 2: high_task tries to acquire — blocked!")
            lines.append("  Priority inheritance kicks in:")
            lines.append(
                f"  low_task effective_priority = {low_info['effective_priority']} (boosted!)"
            )
            lines.append(f"  med_task effective_priority = {med_info['effective_priority']}")
            lines.append("")
            lines.append("  Now low_task runs at priority 10, so the scheduler picks it")
            lines.append("  over med_task (priority 5). low_task finishes and releases.")

            # Low releases
            self._kernel.syscall(
                SyscallNumber.SYS_RELEASE_MUTEX,
                name="_pi_demo_lock",
                tid=int(str(low_info["main_tid"])),
                pid=low_pid,
            )
            low_info = self._kernel.syscall(SyscallNumber.SYS_PROCESS_INFO, pid=low_pid)
            lines.append("")
            lines.append("Step 3: low_task releases the mutex.")
            lines.append(
                f"  low_task effective_priority = {low_info['effective_priority']} (restored)"
            )
            lines.append("  high_task can now acquire and proceed.")

            lines.append("")
            lines.append("Without priority inheritance, med_task would have starved high_task.")
            lines.append("This is exactly what happened on Mars until engineers uploaded a fix!")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up demo resources
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="_pi_demo_lock")

        return "\n".join(lines)

    def _cmd_pi_status(self) -> str:
        """Show priority inheritance status."""
        result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_PI_STATUS)

        lines = ["=== Priority Inheritance Status ==="]
        lines.append(f"Enabled: {result['enabled']}")

        boosted_list: list[dict[str, object]] = result["boosted"]  # type: ignore[assignment]
        if boosted_list:
            lines.append("Boosted processes:")
            lines.extend(
                f"  pid {b['pid']} ({b['name']}):"
                f" base={b['base_priority']}, effective={b['effective_priority']}"
                for b in boosted_list
            )
        else:
            lines.append("No processes currently boosted.")

        return "\n".join(lines)

    def _cmd_ordering(self, args: list[str]) -> str:
        """Manage resource ordering — register, status, mode, violations, demo."""
        subs = {"register", "status", "mode", "violations", "demo"}
        if not args or args[0] not in subs:
            return "Usage: ordering <register|status|mode|violations|demo>"
        sub = args[0]
        if sub == "register":
            return self._cmd_ordering_register(args[1:])
        if sub == "mode":
            return self._cmd_ordering_mode(args[1:])
        if sub == "status":
            return self._cmd_ordering_status()
        if sub == "violations":
            return self._cmd_ordering_violations()
        return self._cmd_ordering_demo()

    def _cmd_ordering_register(self, args: list[str]) -> str:
        """Register a resource with a rank."""
        min_args = 2
        if len(args) < min_args:
            return "Usage: ordering register <resource> <rank>"
        name = args[0]
        try:
            rank = int(args[1])
        except ValueError:
            return f"Error: invalid rank '{args[1]}'"
        try:
            result: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_REGISTER_RANK,
                name=name,
                rank=rank,
            )
            return f"Registered '{result['name']}' with rank {result['rank']}"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_ordering_status(self) -> str:
        """Show ordering table and held resources."""
        try:
            result: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_CHECK_ORDERING)
        except SyscallError as e:
            return f"Error: {e}"
        lines = [
            "=== Resource Ordering Status ===",
            f"Mode: {result['mode']}",
            f"Violations: {result['violations']}",
        ]
        ranks: dict[str, int] = result["ranks"]  # type: ignore[assignment]
        if ranks:
            lines.append("")
            lines.append("RESOURCE                     RANK")
            lines.extend(
                f"  {name:<26} {ranks[name]}" for name in sorted(ranks, key=lambda n: ranks[n])
            )
        else:
            lines.append("No resources registered.")
        return "\n".join(lines)

    def _cmd_ordering_mode(self, args: list[str]) -> str:
        """Set the ordering enforcement mode."""
        if not args:
            return "Usage: ordering mode <strict|warn|off>"
        try:
            result: str = self._kernel.syscall(
                SyscallNumber.SYS_SET_ORDERING_MODE,
                mode=args[0],
            )
        except SyscallError as e:
            return f"Error: {e}"
        return result

    def _cmd_ordering_violations(self) -> str:
        """Show recorded ordering violations."""
        violations: list[dict[str, object]] = self._kernel.syscall(
            SyscallNumber.SYS_ORDERING_VIOLATIONS
        )
        if not violations:
            return "No ordering violations recorded."
        lines = ["RESOURCE                     REQ_RANK  MAX_HELD  PID"]
        lines.extend(
            f"  {v['resource_requested']!s:<26}"
            f" {v['requested_rank']!s:<9}"
            f" {v['max_held_rank']!s:<9}"
            f" {v['pid']}"
            for v in violations
        )
        return "\n".join(lines)

    def _cmd_ordering_demo(self) -> str:
        """Walk through the numbered-lockers resource ordering scenario."""
        lines: list[str] = [
            "=== Resource Ordering Demo ===",
            "",
            "Imagine numbered lockers in a school hallway.",
            "The rule: you can only walk forward (ascending locker numbers).",
            "If you need locker 3 and locker 7, open 3 first, then 7.",
            "You can never go backwards. Nobody ever gets stuck in a circle.",
            "",
            "Let's see this in action with two mutexes:",
        ]

        # Remember the current ordering mode so we can restore it
        ordering_status: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_CHECK_ORDERING)
        old_mode = str(ordering_status["mode"])

        try:
            # Create demo mutexes with explicit ranks
            self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="_demo_lock_a")
            self._kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="_demo_lock_b")
            self._kernel.syscall(SyscallNumber.SYS_REGISTER_RANK, name="mutex:_demo_lock_a", rank=1)
            self._kernel.syscall(SyscallNumber.SYS_REGISTER_RANK, name="mutex:_demo_lock_b", rank=2)

            # Create two processes
            p1_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="walker_1", num_pages=1
            )
            p2_r = self._kernel.syscall(
                SyscallNumber.SYS_CREATE_PROCESS, name="walker_2", num_pages=1
            )
            p1_pid: int = p1_r["pid"]
            p2_pid: int = p2_r["pid"]

            p1_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=p1_pid
            )
            p2_info: dict[str, object] = self._kernel.syscall(
                SyscallNumber.SYS_PROCESS_INFO, pid=p2_pid
            )
            p1_tid = int(str(p1_info["main_tid"]))
            p2_tid = int(str(p2_info["main_tid"]))

            lines.append("  mutex:_demo_lock_a  rank=1")
            lines.append("  mutex:_demo_lock_b  rank=2")
            lines.append(f"  walker_1 (pid={p1_pid})")
            lines.append(f"  walker_2 (pid={p2_pid})")

            # Set warn mode for the demo
            self._kernel.syscall(SyscallNumber.SYS_SET_ORDERING_MODE, mode="warn")

            # Process 1: ascending order (correct)
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_a", tid=p1_tid, pid=p1_pid
            )
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_b", tid=p1_tid, pid=p1_pid
            )
            lines.append("")
            lines.append("Step 1: walker_1 acquires lock_a (rank 1) then lock_b (rank 2)")
            lines.append("  Ascending order -- ALLOWED (walking forward)")

            # Release p1's locks
            self._kernel.syscall(
                SyscallNumber.SYS_RELEASE_MUTEX, name="_demo_lock_b", tid=p1_tid, pid=p1_pid
            )
            self._kernel.syscall(
                SyscallNumber.SYS_RELEASE_MUTEX, name="_demo_lock_a", tid=p1_tid, pid=p1_pid
            )

            # Process 2: descending order (violation!)
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_b", tid=p2_tid, pid=p2_pid
            )
            self._kernel.syscall(
                SyscallNumber.SYS_ACQUIRE_MUTEX, name="_demo_lock_a", tid=p2_tid, pid=p2_pid
            )
            lines.append("")
            lines.append("Step 2: walker_2 acquires lock_b (rank 2) then lock_a (rank 1)")
            lines.append("  Descending order -- VIOLATION! (walking backwards)")
            lines.append("  In strict mode, this would be rejected.")

            lines.append("")
            lines.append("This simple rule -- always go forward -- prevents circular wait,")
            lines.append("one of the four conditions required for deadlock.")
            lines.append("No circle can form because nobody ever goes backwards.")

        except SyscallError as e:
            lines.append(f"\nError during demo: {e}")
        finally:
            # Clean up demo resources
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="_demo_lock_a")
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_DESTROY_MUTEX, name="_demo_lock_b")
            with contextlib.suppress(SyscallError):
                self._kernel.syscall(SyscallNumber.SYS_SET_ORDERING_MODE, mode=old_mode)

        return "\n".join(lines)

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("mutex", _cmd_mutex),
        ("semaphore", _cmd_semaphore),
        ("rwlock", _cmd_rwlock),
        ("pi", _cmd_pi),
        ("ordering", _cmd_ordering),
        ("deadlock", _cmd_deadlock),
        ("resources", _cmd_resources),
    )
