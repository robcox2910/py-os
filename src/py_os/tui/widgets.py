"""TUI widget components — formatting functions and Textual widgets.

The formatting functions are pure (no Textual dependency) so they can
be unit-tested without importing Textual.  The widget classes wrap
these formatters for use in the Textual app.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Pure formatting functions (no Textual dependency)
# ---------------------------------------------------------------------------

_BAR_WIDTH = 30


def format_process_table(data: list[dict[str, object]]) -> str:
    """Format a list of process dicts into an ASCII table.

    Args:
        data: Process info dicts with keys pid, name, state, cpu_id.

    Returns:
        A formatted multi-line string.

    """
    header = f"{'PID':<6} {'CPU':<4} {'STATE':<11} {'NAME'}"
    lines = ["--- Processes ---", header]
    for p in data:
        cpu = str(p["cpu_id"]) if p["cpu_id"] is not None else "-"
        lines.append(f"{p['pid']!s:<6} {cpu:<4} {p['state']!s:<11} {p['name']}")
    return "\n".join(lines)


def format_memory_bar(total: int, used: int, width: int = _BAR_WIDTH) -> str:
    """Format a memory usage bar with percentage.

    Args:
        total: Total frames.
        used: Used frames.
        width: Bar width in characters.

    Returns:
        A formatted memory bar string.

    """
    pct = (used / total * 100) if total > 0 else 0
    filled = round(used / total * width) if total > 0 else 0
    empty = width - filled
    bar = "[" + "#" * filled + "." * empty + "]"
    return f"--- Memory ---\n{bar} {pct:.0f}%\n{used}/{total} frames"


def format_swap_panel(info: dict[str, object]) -> str:
    """Format swap space information into a panel.

    Args:
        info: Swap info dict with keys policy, swap_used, swap_total,
            page_faults, resident_count.

    Returns:
        A formatted multi-line string.

    """
    lines = [
        "--- Swap ---",
        f"Policy:    {info.get('policy', 'n/a')}",
        f"Used:      {info.get('swap_used', 0)}/{info.get('swap_total', 0)}",
        f"Faults:    {info.get('page_faults', 0)}",
        f"Resident:  {info.get('resident_count', 0)}",
    ]
    return "\n".join(lines)


def format_cpu_panel(cpus: list[dict[str, object]]) -> str:
    """Format per-CPU status information.

    Args:
        cpus: List of CPU info dicts with keys cpu_id, policy,
            current, ready_count.

    Returns:
        A formatted multi-line string.

    """
    lines = ["--- CPUs ---"]
    for cpu in cpus:
        current = cpu["current"]
        proc_str = f"PID {current}" if current is not None else "idle"
        lines.append(
            f"CPU {cpu['cpu_id']}: {cpu['policy']}  current={proc_str}  ready={cpu['ready_count']}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Textual widget classes (lazy-imported to avoid hard dependency)
# ---------------------------------------------------------------------------

try:
    from textual.widgets import Static

    class ProcessTable(Static):
        """Display process table in the TUI."""

        def update_data(self, data: list[dict[str, object]]) -> None:
            """Refresh the process table with new data."""
            self.update(format_process_table(data))

    class MemoryBar(Static):
        """Display memory usage bar in the TUI."""

        def update_data(self, total: int, used: int) -> None:
            """Refresh the memory bar with new values."""
            self.update(format_memory_bar(total, used))

    class SwapPanel(Static):
        """Display swap space info in the TUI."""

        def update_data(self, info: dict[str, object]) -> None:
            """Refresh swap panel with new data."""
            self.update(format_swap_panel(info))

    class CpuPanel(Static):
        """Display per-CPU status in the TUI."""

        def update_data(self, cpus: list[dict[str, object]]) -> None:
            """Refresh CPU panel with new data."""
            self.update(format_cpu_panel(cpus))

    class FramebufferViewer(Static):
        """Display framebuffer render in the TUI."""

        def update_data(self, rendered: str) -> None:
            """Refresh with rendered framebuffer text."""
            self.update(rendered)

    class CommandOutput(Static):
        """Display shell command output in the TUI."""

        def update_data(self, output: str) -> None:
            """Refresh with command output text."""
            self.update(output)

except ImportError:  # pragma: no cover
    pass
