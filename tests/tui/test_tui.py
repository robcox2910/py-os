"""Tests for the TUI dashboard -- formatters and app integration.

Pure formatting functions are tested without Textual.  The Textual app
tests use the async pilot testing API and are guarded by
``pytest.importorskip``.
"""

from __future__ import annotations

import pytest

# Pure formatting functions are always importable (no Textual dep)
from py_os.tui.widgets import (
    format_cpu_panel,
    format_memory_bar,
    format_process_table,
    format_swap_panel,
)

textual = pytest.importorskip("textual")

from py_os.tui.app import PyOSApp  # noqa: E402, I001


# -- Pure formatting function tests -------------------------------------------


class TestFormatProcessTable:
    """Verify the process table formatter."""

    def test_empty_data(self) -> None:
        """Empty process list should still have a header."""
        result = format_process_table([])
        assert "Processes" in result
        assert "PID" in result

    def test_formats_process(self) -> None:
        """Process data should appear in the table."""
        data: list[dict[str, object]] = [{"pid": 1, "name": "init", "state": "ready", "cpu_id": 0}]
        result = format_process_table(data)
        assert "init" in result
        assert "ready" in result

    def test_none_cpu(self) -> None:
        """Process with no CPU should show dash."""
        data: list[dict[str, object]] = [
            {"pid": 2, "name": "idle", "state": "waiting", "cpu_id": None}
        ]
        result = format_process_table(data)
        assert "-" in result


class TestFormatMemoryBar:
    """Verify the memory bar formatter."""

    def test_half_used(self) -> None:
        """Half-used memory should show 50% bar."""
        total = 64
        used = 32
        result = format_memory_bar(total, used)
        assert "50%" in result
        assert "#" in result
        assert "." in result

    def test_empty(self) -> None:
        """Zero used memory should show 0%."""
        result = format_memory_bar(64, 0)
        assert "0%" in result

    def test_full(self) -> None:
        """Fully used memory should show 100%."""
        result = format_memory_bar(64, 64)
        assert "100%" in result

    def test_zero_total(self) -> None:
        """Zero total should not crash."""
        result = format_memory_bar(0, 0)
        assert "0%" in result


class TestFormatSwapPanel:
    """Verify the swap panel formatter."""

    def test_basic_info(self) -> None:
        """Swap panel should show policy and usage."""
        info: dict[str, object] = {
            "policy": "lru",
            "swap_used": 5,
            "swap_total": 32,
            "page_faults": 10,
            "resident_count": 16,
        }
        result = format_swap_panel(info)
        assert "lru" in result
        assert "5/32" in result
        assert "10" in result

    def test_empty_info(self) -> None:
        """Missing keys should default gracefully."""
        result = format_swap_panel({})
        assert "n/a" in result


class TestFormatCpuPanel:
    """Verify the CPU panel formatter."""

    def test_single_cpu(self) -> None:
        """Single CPU should appear in panel."""
        cpus: list[dict[str, object]] = [
            {"cpu_id": 0, "policy": "FCFS", "current": 1, "ready_count": 3}
        ]
        result = format_cpu_panel(cpus)
        assert "CPU 0" in result
        assert "PID 1" in result

    def test_idle_cpu(self) -> None:
        """Idle CPU should show 'idle'."""
        cpus: list[dict[str, object]] = [
            {"cpu_id": 0, "policy": "FCFS", "current": None, "ready_count": 0}
        ]
        result = format_cpu_panel(cpus)
        assert "idle" in result


# -- Textual app integration tests ---------------------------------------------


class TestTuiApp:
    """Verify the Textual app boots and has expected widgets."""

    @pytest.mark.asyncio
    async def test_app_creates(self) -> None:
        """App should boot without error."""
        app = PyOSApp()
        async with app.run_test() as pilot:
            assert pilot.app is not None

    @pytest.mark.asyncio
    async def test_has_input_widget(self) -> None:
        """App should contain an input widget."""
        app = PyOSApp()
        async with app.run_test():
            inputs = app.query("Input")
            assert len(inputs) > 0

    @pytest.mark.asyncio
    async def test_has_process_panel(self) -> None:
        """App should contain a process table panel."""
        app = PyOSApp()
        async with app.run_test():
            panel = app.query_one("#processes")
            assert panel is not None
