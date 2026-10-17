"""Devices and hardware commands -- devices, interrupts, timers, the framebuffer, kernel messages and the dashboard."""

from collections.abc import Callable

from py_os.shell.base import ShellBase
from py_os.syscalls import SyscallError, SyscallNumber

# A table of sub-commands: word typed by the user -> the method that handles it.
type _SubcommandTable = dict[str, Callable[[list[str]], str]]


class DeviceCommands(ShellBase):
    """Shell commands for devices, interrupts, timers, the framebuffer, kernel messages and the dashboard."""

    def _cmd_devices(self, _args: list[str]) -> str:
        """List all registered devices."""
        names: list[str] = self._kernel.syscall(SyscallNumber.SYS_LIST_DEVICES)
        return "\n".join(names) if names else "No devices registered."

    def _cmd_devread(self, args: list[str]) -> str:
        """Read from a device."""
        if not args:
            return "Usage: devread <device>"
        try:
            data: bytes = self._kernel.syscall(SyscallNumber.SYS_DEVICE_READ, device=args[0])
            return data.decode() if data else "(empty)"
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_devwrite(self, args: list[str]) -> str:
        """Write to a device."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: devwrite <device> <data...>"
        device = args[0]
        data = " ".join(args[1:])
        try:
            self._kernel.syscall(SyscallNumber.SYS_DEVICE_WRITE, device=device, data=data.encode())
        except SyscallError as e:
            return f"Error: {e}"
        return ""

    def _cmd_dmesg(self, _args: list[str]) -> str:
        """Show kernel boot messages."""
        messages: list[str] = self._kernel.syscall(SyscallNumber.SYS_DMESG)
        return "\n".join(messages) if messages else "No boot messages."

    def _cmd_interrupt(self, args: list[str]) -> str:
        """Manage interrupts: list, mask <vector>, unmask <vector>."""
        if not args:
            return self._interrupt_list()

        match args[0]:
            case "list":
                return self._interrupt_list()
            case "mask":
                return self._interrupt_mask_unmask(args, mask=True)
            case "unmask":
                return self._interrupt_mask_unmask(args, mask=False)
            case _:
                return "Usage: interrupt [list | mask <vector> | unmask <vector>]"

    def _interrupt_mask_unmask(self, args: list[str], *, mask: bool) -> str:
        """Mask or unmask an interrupt vector."""
        action = "mask" if mask else "unmask"
        syscall = SyscallNumber.SYS_INTERRUPT_MASK if mask else SyscallNumber.SYS_INTERRUPT_UNMASK
        if len(args) < 2:  # noqa: PLR2004
            return f"Usage: interrupt {action} <vector>"
        try:
            vector = int(args[1])
        except ValueError:
            return f"Error: invalid vector '{args[1]}'"
        try:
            self._kernel.syscall(syscall, vector=vector)
            return f"Vector {vector} {action}ed"
        except SyscallError as e:
            return f"Error: {e}"

    def _interrupt_list(self) -> str:
        """Format the interrupt vector table."""
        try:
            vectors: list[dict[str, object]] = self._kernel.syscall(
                SyscallNumber.SYS_INTERRUPT_LIST
            )
        except SyscallError as e:
            return f"Error: {e}"
        if not vectors:
            return "No interrupt vectors registered"
        lines = ["VEC  TYPE      PRI  MASKED  PENDING  HANDLER"]
        lines.extend(
            f"{v['vector']:>3}  {v['type']!s:<8}  {v['priority']:>3}"
            f"  {'yes' if v['masked'] else 'no':>6}  {v['pending']:>7}"
            f"  {'yes' if v['has_handler'] else 'no'}"
            for v in vectors
        )
        return "\n".join(lines)

    def _cmd_timer(self, args: list[str]) -> str:
        """Manage the timer: info, set <interval>."""
        if not args or args[0] == "info":
            return self._timer_info()
        if args[0] == "set":
            return self._timer_set(args)
        return "Usage: timer [info | set <interval>]"

    def _timer_info(self) -> str:
        """Format timer device status."""
        try:
            info: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_TIMER_INFO)
            return "\n".join(
                [
                    "Timer device:",
                    f"  Interval:     {info['interval']} ticks",
                    f"  Current tick: {info['current_tick']}",
                    f"  Total ticks:  {info['total_ticks']}",
                    f"  Total fires:  {info['fires']}",
                ]
            )
        except SyscallError as e:
            return f"Error: {e}"

    def _timer_set(self, args: list[str]) -> str:
        """Set the timer interval."""
        if len(args) < 2:  # noqa: PLR2004
            return "Usage: timer set <interval>"
        try:
            interval = int(args[1])
        except ValueError:
            return f"Error: invalid interval '{args[1]}'"
        try:
            return self._kernel.syscall(SyscallNumber.SYS_TIMER_SET_INTERVAL, interval=interval)
        except SyscallError as e:
            return f"Error: {e}"

    def _cmd_dashboard(self, args: list[str]) -> str:
        """Display an ASCII system dashboard (cpu, memory, processes, fs)."""
        if not args:
            return self._dashboard_full()
        match args[0]:
            case "cpu":
                return self._dashboard_cpu()
            case "memory":
                return self._dashboard_memory()
            case "processes":
                return self._dashboard_processes()
            case "fs":
                return self._dashboard_fs()
            case _:
                return "Usage: dashboard [cpu|memory|processes|fs]"

    def _dashboard_full(self) -> str:
        """Assemble all four panels into a full dashboard."""
        lines: list[str] = [
            "+====== PyOS Dashboard ======+",
            "",
            self._dashboard_cpu(),
            "",
            self._dashboard_memory(),
            "",
            self._dashboard_processes(),
            "",
            self._dashboard_fs(),
        ]
        return "\n".join(lines)

    def _dashboard_cpu(self) -> str:
        """Render the CPU panel with policy and per-CPU status."""
        try:
            cpus: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_CPU_INFO)
        except SyscallError as e:
            return f"CPU: Error — {e}"

        lines: list[str] = ["--- CPU ---"]
        for cpu in cpus:
            current = cpu["current"]
            proc_str = f"PID {current}" if current is not None else "idle"
            lines.append(
                f"  CPU {cpu['cpu_id']}: {cpu['policy']}  "
                f"current={proc_str}  ready={cpu['ready_count']}"
            )
        return "\n".join(lines)

    def _dashboard_memory(self) -> str:
        """Render the memory panel with a visual bar and stats."""
        try:
            mem: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
        except SyscallError as e:
            return f"Memory: Error — {e}"

        total = mem["total_frames"]
        free = mem["free_frames"]
        used = total - free
        pct = (used / total * 100) if total > 0 else 0

        bar_width = self._DASHBOARD_BAR_WIDTH
        filled = round(used / total * bar_width) if total > 0 else 0
        empty = bar_width - filled
        bar = "[" + "#" * filled + "." * empty + "]"

        lines: list[str] = [
            "--- Memory ---",
            f"  {bar} {pct:.0f}%",
            f"  {used}/{total} frames allocated  (#=allocated .=free)",
        ]
        return "\n".join(lines)

    def _dashboard_processes(self) -> str:
        """Render the process table panel."""
        try:
            procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
        except SyscallError as e:
            return f"Processes: Error — {e}"

        lines: list[str] = [
            "--- Processes ---",
            f"  {'PID':<6} {'CPU':<4} {'STATE':<11} {'NAME'}",
        ]
        for p in procs:
            cpu = str(p["cpu_id"]) if p["cpu_id"] is not None else "-"
            lines.append(f"  {p['pid']:<6} {cpu:<4} {p['state']!s:<11} {p['name']}")
        return "\n".join(lines)

    def _dashboard_fs(self) -> str:
        """Render the filesystem tree panel (depth-limited to 2 levels)."""
        lines: list[str] = ["--- Filesystem ---"]
        self._dashboard_fs_tree(lines, "/", depth=0, max_depth=2)
        # /proc is a virtual filesystem not in the regular tree
        lines.append("  /proc/ (virtual)")
        return "\n".join(lines)

    def _dashboard_fs_tree(
        self, lines: list[str], path: str, *, depth: int, max_depth: int
    ) -> None:
        """Recursively build a filesystem tree with indentation."""
        if depth > max_depth:
            return
        indent = "  " + "  " * depth
        name = path.rsplit("/", maxsplit=1)[-1] or "/"
        suffix = " (virtual)" if path == "/proc" else ""
        lines.append(f"{indent}{name}/{suffix}")

        try:
            entries: list[str] = self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path=path)
        except SyscallError:
            return

        for entry in sorted(entries):
            child_path = f"{path.rstrip('/')}/{entry}"
            # Try listing as directory; if it fails, it's a file
            try:
                self._kernel.syscall(SyscallNumber.SYS_LIST_DIR, path=child_path)
            except SyscallError, NotADirectoryError:
                lines.append(f"{indent}  {entry}")
                continue
            self._dashboard_fs_tree(lines, child_path, depth=depth + 1, max_depth=max_depth)

    def _cmd_fb(self, args: list[str]) -> str:
        """Display or draw on the framebuffer."""
        dispatch: _SubcommandTable = {
            "render": lambda _a: self._fb_render(),
            "pixel": self._fb_pixel,
            "text": self._fb_text,
            "rect": self._fb_rect,
            "clear": lambda _a: self._fb_clear(),
            "demo": lambda _a: self._fb_demo(),
        }
        if not args:
            return self._fb_info()
        if args[0] not in dispatch:
            return "Usage: fb [render|pixel|text|rect|clear|demo]"
        return dispatch[args[0]](args[1:])

    def _fb_info(self) -> str:
        """Display framebuffer dimensions and status."""
        try:
            info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_FB_INFO)
        except SyscallError as e:
            return f"Error: {e}"
        lines: list[str] = [
            "--- Framebuffer ---",
            f"  Dimensions: {info['width']}x{info['height']}",
            f"  Status:     {info['status']}",
        ]
        return "\n".join(lines)

    def _fb_render(self) -> str:
        """Render the current framebuffer contents."""
        try:
            return self._kernel.syscall(SyscallNumber.SYS_FB_READ)
        except SyscallError as e:
            return f"Error: {e}"

    def _fb_pixel(self, args: list[str]) -> str:
        """Set a single pixel on the framebuffer."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: fb pixel <x> <y> <char>"
        try:
            cmd = f"pixel {args[0]} {args[1]} {args[2]}"
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command=cmd)
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        return f"Set pixel ({args[0]}, {args[1]}) = '{args[2]}'"

    def _fb_text(self, args: list[str]) -> str:
        """Draw text on the framebuffer."""
        min_args = 3
        if len(args) < min_args:
            return "Usage: fb text <x> <y> <message>"
        try:
            msg = " ".join(args[2:])
            cmd = f"text {args[0]} {args[1]} {msg}"
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command=cmd)
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        return f"Drew text at ({args[0]}, {args[1]})"

    def _fb_rect(self, args: list[str]) -> str:
        """Fill a rectangle on the framebuffer."""
        min_args = 5
        if len(args) < min_args:
            return "Usage: fb rect <x1> <y1> <x2> <y2> <char>"
        try:
            cmd = f"rect {args[0]} {args[1]} {args[2]} {args[3]} {args[4]}"
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command=cmd)
        except (SyscallError, ValueError) as e:
            return f"Error: {e}"
        return f"Filled rect ({args[0]},{args[1]}) to ({args[2]},{args[3]})"

    def _fb_clear(self) -> str:
        """Clear the framebuffer."""
        try:
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command="clear")
        except SyscallError as e:
            return f"Error: {e}"
        return "Framebuffer cleared"

    def _fb_demo(self) -> str:
        """Draw a demo pattern on the framebuffer."""
        try:
            # Draw a border
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command="clear")
            info: dict[str, object] = self._kernel.syscall(SyscallNumber.SYS_FB_INFO)
            w = int(str(info["width"]))
            h = int(str(info["height"]))
            # Top and bottom borders
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command=f"rect 0 0 {w - 1} 0 #")
            self._kernel.syscall(
                SyscallNumber.SYS_FB_WRITE, command=f"rect 0 {h - 1} {w - 1} {h - 1} #"
            )
            # Left and right borders
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command=f"rect 0 0 0 {h - 1} #")
            self._kernel.syscall(
                SyscallNumber.SYS_FB_WRITE, command=f"rect {w - 1} 0 {w - 1} {h - 1} #"
            )
            # Title text
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command="text 2 2 PyOS Framebuffer")
            self._kernel.syscall(SyscallNumber.SYS_FB_WRITE, command="text 2 4 Hello, World!")
            # Render
            rendered: str = self._kernel.syscall(SyscallNumber.SYS_FB_READ)
        except SyscallError as e:
            return f"Error: {e}"
        return f"--- Framebuffer Demo ---\n{rendered}"

    # Command name -> handler. ShellBase builds its dispatch table from these.
    COMMANDS = (
        ("devices", _cmd_devices),
        ("devread", _cmd_devread),
        ("devwrite", _cmd_devwrite),
        ("interrupt", _cmd_interrupt),
        ("timer", _cmd_timer),
        ("fb", _cmd_fb),
        ("dmesg", _cmd_dmesg),
        ("dashboard", _cmd_dashboard),
    )
