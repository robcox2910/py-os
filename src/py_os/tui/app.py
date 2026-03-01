"""TUI dashboard application — live Textual-based terminal for PyOS.

Launch via ``pyos-tui`` or ``python -m py_os.tui.app``.  Requires the
``[tui]`` optional extra (``textual>=0.90``).
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input

from py_os.bootloader import Bootloader
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber
from py_os.tui.widgets import (
    CommandOutput,
    CpuPanel,
    FramebufferViewer,
    MemoryBar,
    ProcessTable,
    SwapPanel,
)

_REFRESH_INTERVAL = 2.0


class PyOSApp(App[None]):
    """Live TUI dashboard for the PyOS simulator."""

    CSS = """
    Horizontal { height: 1fr; }
    Vertical { width: 1fr; }
    #left-panel { width: 60%; }
    #right-panel { width: 40%; }
    #command-area { height: auto; max-height: 10; }
    #cmd-input { dock: bottom; }
    ProcessTable { height: auto; min-height: 5; }
    MemoryBar { height: 3; }
    SwapPanel { height: auto; min-height: 5; }
    CpuPanel { height: auto; min-height: 3; }
    FramebufferViewer { height: auto; min-height: 5; }
    CommandOutput { height: auto; min-height: 3; max-height: 8; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(self) -> None:
        """Boot the kernel and create the shell."""
        super().__init__()
        self._kernel = Bootloader().boot()
        self._shell = Shell(kernel=self._kernel)

    def compose(self) -> ComposeResult:
        """Build the TUI layout."""
        yield Header()
        with Horizontal():
            with Vertical(id="left-panel"):
                yield ProcessTable(id="processes")
                yield MemoryBar(id="memory")
                yield SwapPanel(id="swap")
            with Vertical(id="right-panel"):
                yield CpuPanel(id="cpus")
                yield FramebufferViewer(id="framebuffer")
        yield CommandOutput(id="output")
        yield Input(placeholder="Type a shell command...", id="cmd-input")
        yield Footer()

    def on_mount(self) -> None:
        """Start the auto-refresh timer."""
        self.title = "PyOS Dashboard"
        self._refresh_panels()
        self.set_interval(_REFRESH_INTERVAL, self._refresh_panels)

    def _refresh_panels(self) -> None:
        """Fetch live data from the kernel and update all panels."""
        # Processes
        try:
            procs: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_LIST_PROCESSES)
            self.query_one("#processes", ProcessTable).update_data(procs)
        except SyscallError:
            pass

        # Memory
        try:
            mem: dict[str, int] = self._kernel.syscall(SyscallNumber.SYS_MEMORY_INFO)
            total = mem["total_frames"]
            free = mem["free_frames"]
            self.query_one("#memory", MemoryBar).update_data(total, total - free)
        except SyscallError:
            pass

        # CPU
        try:
            cpus: list[dict[str, object]] = self._kernel.syscall(SyscallNumber.SYS_CPU_INFO)
            self.query_one("#cpus", CpuPanel).update_data(cpus)
        except SyscallError:
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Execute a shell command and display the output."""
        command = event.value
        event.input.value = ""
        if not command.strip():
            return
        output = self._shell.execute(command)
        self.query_one("#output", CommandOutput).update_data(f"$ {command}\n{output}")

    def action_refresh(self) -> None:
        """Manually refresh all panels."""
        self._refresh_panels()


def main() -> None:
    """Entry point for the pyos-tui command."""
    app = PyOSApp()
    app.run()


if __name__ == "__main__":
    main()
