"""Tests for the framebuffer — a simulated character-based display device.

The framebuffer is a 2D grid of characters with drawing operations
(set_pixel, draw_text, fill_rect, clear) and a render method that
produces a bordered ASCII display.
"""

from py_os.io.devices import DeviceState
from py_os.io.framebuffer import DEFAULT_HEIGHT, DEFAULT_WIDTH, Framebuffer
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# -- Framebuffer unit tests ----------------------------------------------------


class TestFramebuffer:
    """Verify framebuffer drawing operations and Device protocol."""

    def test_default_dimensions(self) -> None:
        """Default framebuffer should be 40x12."""
        fb = Framebuffer()
        assert fb.width == DEFAULT_WIDTH
        assert fb.height == DEFAULT_HEIGHT

    def test_custom_dimensions(self) -> None:
        """Framebuffer should accept custom width and height."""
        custom_w = 20
        custom_h = 5
        fb = Framebuffer(width=custom_w, height=custom_h)
        assert fb.width == custom_w
        assert fb.height == custom_h

    def test_name(self) -> None:
        """Device name should be 'framebuffer'."""
        fb = Framebuffer()
        assert fb.name == "framebuffer"

    def test_status_ready(self) -> None:
        """Framebuffer should always report READY status."""
        fb = Framebuffer()
        assert fb.status is DeviceState.READY

    def test_set_pixel(self) -> None:
        """Setting a pixel should place the character in the grid."""
        fb = Framebuffer(width=5, height=3)
        fb.set_pixel(2, 1, "X")
        rendered = fb.render()
        lines = rendered.split("\n")
        # Row 1 (second content line, after top border)
        row_index = 2
        assert lines[row_index][3] == "X"  # col 2 + 1 for border

    def test_draw_text(self) -> None:
        """Drawing text should place characters starting at (x, y)."""
        fb = Framebuffer(width=10, height=3)
        fb.draw_text(1, 0, "Hi")
        rendered = fb.render()
        lines = rendered.split("\n")
        content_row = 1  # first content line
        assert "Hi" in lines[content_row]

    def test_fill_rect(self) -> None:
        """Filling a rectangle should set all cells in the range."""
        fb = Framebuffer(width=5, height=3)
        fb.fill_rect(1, 0, 3, 1, "#")
        rendered = fb.render()
        lines = rendered.split("\n")
        # Top content row: positions 1-3 should be '#'
        content_row_1 = 1
        content_row_2 = 2
        assert lines[content_row_1][2:5] == "###"  # cols 1-3 + border offset
        assert lines[content_row_2][2:5] == "###"

    def test_clear(self) -> None:
        """Clearing should reset all cells to spaces."""
        fb = Framebuffer(width=5, height=3)
        fb.set_pixel(0, 0, "X")
        fb.clear()
        rendered = fb.render()
        # All content rows should be spaces
        lines = rendered.split("\n")
        for i in range(1, 4):  # skip border lines
            content = lines[i][1:-1]  # strip border chars
            assert content == "     "

    def test_render_has_border(self) -> None:
        """Rendered output should have a box border."""
        fb = Framebuffer(width=5, height=3)
        rendered = fb.render()
        lines = rendered.split("\n")
        expected_rows = 5  # top + 3 content + bottom
        assert len(lines) == expected_rows
        assert lines[0].startswith("+")
        assert lines[0].endswith("+")
        assert lines[-1].startswith("+")
        for i in range(1, 4):
            assert lines[i].startswith("|")
            assert lines[i].endswith("|")

    def test_out_of_bounds_silent(self) -> None:
        """Out-of-bounds drawing should be silently ignored."""
        fb = Framebuffer(width=5, height=3)
        # These should not raise
        fb.set_pixel(-1, 0, "X")
        fb.set_pixel(100, 0, "X")
        fb.set_pixel(0, -1, "X")
        fb.set_pixel(0, 100, "X")
        fb.draw_text(0, 100, "test")

    def test_write_pixel_protocol(self) -> None:
        """Write with 'pixel' command should set a character."""
        fb = Framebuffer(width=5, height=3)
        fb.write(b"pixel 2 1 X")
        rendered = fb.render()
        assert "X" in rendered

    def test_write_clear_protocol(self) -> None:
        """Write with 'clear' command should clear the display."""
        fb = Framebuffer(width=5, height=3)
        fb.set_pixel(0, 0, "X")
        fb.write(b"clear")
        rendered = fb.render()
        assert "X" not in rendered

    def test_read_returns_bytes(self) -> None:
        """Read should return rendered display as bytes."""
        fb = Framebuffer(width=5, height=3)
        data = fb.read()
        assert isinstance(data, bytes)
        assert data == fb.render().encode()


# -- Kernel integration --------------------------------------------------------


class TestFramebufferKernel:
    """Verify framebuffer is registered at boot."""

    def test_registered_at_boot(self) -> None:
        """Framebuffer should be in the device manager after boot."""
        kernel = _booted_kernel()
        assert kernel.device_manager is not None
        assert kernel.device_manager.get("framebuffer") is not None

    def test_accessible_via_property(self) -> None:
        """Kernel.framebuffer should return the device."""
        kernel = _booted_kernel()
        assert kernel.framebuffer is not None
        assert kernel.framebuffer.name == "framebuffer"

    def test_in_dmesg(self) -> None:
        """Boot log should mention framebuffer."""
        kernel = _booted_kernel()
        assert any("Framebuffer" in line for line in kernel.dmesg())

    def test_none_after_shutdown(self) -> None:
        """Framebuffer should be None after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        kernel._execution_mode = ExecutionMode.KERNEL
        assert kernel.framebuffer is None


# -- Syscall integration -------------------------------------------------------


class TestSyscallFramebuffer:
    """Verify framebuffer syscalls."""

    def test_write_pixel(self) -> None:
        """SYS_FB_WRITE should draw on the framebuffer."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_FB_WRITE, command="pixel 0 0 X")
        rendered: str = kernel.syscall(SyscallNumber.SYS_FB_READ)
        assert "X" in rendered

    def test_read_contents(self) -> None:
        """SYS_FB_READ should return rendered string."""
        kernel = _booted_kernel()
        rendered: str = kernel.syscall(SyscallNumber.SYS_FB_READ)
        assert isinstance(rendered, str)
        assert "+" in rendered  # border

    def test_info_dict(self) -> None:
        """SYS_FB_INFO should return dimensions and status."""
        kernel = _booted_kernel()
        info: dict[str, object] = kernel.syscall(SyscallNumber.SYS_FB_INFO)
        assert info["width"] == DEFAULT_WIDTH
        assert info["height"] == DEFAULT_HEIGHT
        assert info["status"] == "ready"


# -- Shell integration ---------------------------------------------------------


class TestShellFramebuffer:
    """Verify the shell fb command."""

    def test_fb_info(self) -> None:
        """Command 'fb' should show dimensions."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb")
        assert "Framebuffer" in output
        assert "40x12" in output

    def test_fb_pixel(self) -> None:
        """Command 'fb pixel' should set a pixel."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb pixel 5 3 X")
        assert "Set pixel" in output

    def test_fb_render(self) -> None:
        """Command 'fb render' should show the display."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb render")
        assert "+" in output  # border chars

    def test_fb_text(self) -> None:
        """Command 'fb text' should draw text."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb text 0 0 Hello")
        assert "Drew text" in output

    def test_fb_rect(self) -> None:
        """Command 'fb rect' should fill a rectangle."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb rect 0 0 3 3 #")
        assert "Filled rect" in output

    def test_fb_clear(self) -> None:
        """Command 'fb clear' should clear the framebuffer."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb clear")
        assert "cleared" in output

    def test_fb_demo(self) -> None:
        """Command 'fb demo' should render a demo pattern."""
        _kernel, shell = _booted_shell()
        output = shell.execute("fb demo")
        assert "Demo" in output
        assert "PyOS" in output

    def test_help_listing(self) -> None:
        """Command 'fb' should appear in the help listing."""
        _kernel, shell = _booted_shell()
        output = shell.execute("help")
        assert "fb" in output
