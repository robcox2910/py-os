"""Framebuffer — a simulated character-based display device.

A framebuffer is a region of memory that holds the pixel (or character)
data for a display.  In a real computer, the GPU reads from the
framebuffer and draws the image on your monitor many times per second.

Our framebuffer is a 2D grid of characters — like a tiny ASCII screen.
Each cell holds one character, defaulting to a space.  Drawing
operations set individual characters, write text strings, or fill
rectangles.  The ``render()`` method returns the current display as a
bordered ASCII string.

This follows the ``Device`` protocol: ``read()`` returns the rendered
display as bytes, ``write()`` accepts text commands to draw.
"""

from py_os.io.devices import DeviceState

DEFAULT_WIDTH = 40
DEFAULT_HEIGHT = 12
_FILL_CHAR = " "


class Framebuffer:
    """Character-based display device — a simulated screen.

    The framebuffer maintains a 2D grid of characters (width x height).
    Drawing methods modify individual cells.  Out-of-bounds coordinates
    are silently ignored (no error, no wrap-around), matching how real
    GPUs clip drawing outside the visible area.
    """

    def __init__(
        self,
        *,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
    ) -> None:
        """Create a framebuffer with the given dimensions.

        Args:
            width: Number of columns (characters per row).
            height: Number of rows.

        """
        self._width = width
        self._height = height
        self._grid: list[list[str]] = [[_FILL_CHAR] * width for _ in range(height)]

    @property
    def name(self) -> str:
        """Return 'framebuffer'."""
        return "framebuffer"

    @property
    def status(self) -> DeviceState:
        """Framebuffer is always ready."""
        return DeviceState.READY

    @property
    def width(self) -> int:
        """Return the number of columns."""
        return self._width

    @property
    def height(self) -> int:
        """Return the number of rows."""
        return self._height

    def set_pixel(self, x: int, y: int, char: str) -> None:
        """Set a single character at (x, y).

        Out-of-bounds coordinates are silently ignored.

        Args:
            x: Column (0 = left).
            y: Row (0 = top).
            char: A single character to place.

        """
        if 0 <= x < self._width and 0 <= y < self._height:
            self._grid[y][x] = char[0] if char else _FILL_CHAR

    def draw_text(self, x: int, y: int, text: str) -> None:
        """Draw a text string starting at (x, y), clipping at the edge.

        Args:
            x: Starting column.
            y: Row.
            text: The string to draw (one character per cell).

        """
        if y < 0 or y >= self._height:
            return
        for i, ch in enumerate(text):
            col = x + i
            if 0 <= col < self._width:
                self._grid[y][col] = ch

    def fill_rect(
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        char: str,
    ) -> None:
        """Fill a rectangle from (x1, y1) to (x2, y2) inclusive.

        Args:
            x1: Left column.
            y1: Top row.
            x2: Right column (inclusive).
            y2: Bottom row (inclusive).
            char: Fill character.

        """
        fill = char[0] if char else _FILL_CHAR
        for row in range(max(0, y1), min(self._height, y2 + 1)):
            for col in range(max(0, x1), min(self._width, x2 + 1)):
                self._grid[row][col] = fill

    def clear(self) -> None:
        """Reset every cell to a space."""
        for row in self._grid:
            for col in range(self._width):
                row[col] = _FILL_CHAR

    def render(self) -> str:
        """Return the display as a bordered ASCII string.

        Returns:
            A multi-line string with a box-drawing border around the
            grid contents.

        """
        border = "+" + "-" * self._width + "+"
        lines = [border]
        lines.extend("|" + "".join(row) + "|" for row in self._grid)
        lines.append(border)
        return "\n".join(lines)

    def read(self, **_kwargs: int) -> bytes:
        """Return the rendered display as bytes."""
        return self.render().encode()

    def write(self, data: bytes) -> None:
        """Parse and execute a drawing command.

        Command format (space-separated tokens):
            ``pixel x y char``   — set one character
            ``text x y message`` — draw a text string
            ``rect x1 y1 x2 y2 char`` — fill a rectangle
            ``clear``            — clear the display

        Args:
            data: UTF-8 encoded command string.

        """
        text = data.decode()
        parts = text.split()
        if not parts:
            return
        cmd = parts[0]
        min_pixel_args = 4
        min_text_args = 4
        min_rect_args = 6
        match cmd:
            case "pixel" if len(parts) >= min_pixel_args:
                self.set_pixel(int(parts[1]), int(parts[2]), parts[3])
            case "text" if len(parts) >= min_text_args:
                msg = " ".join(parts[3:])
                self.draw_text(int(parts[1]), int(parts[2]), msg)
            case "rect" if len(parts) >= min_rect_args:
                self.fill_rect(
                    int(parts[1]),
                    int(parts[2]),
                    int(parts[3]),
                    int(parts[4]),
                    parts[5],
                )
            case "clear":
                self.clear()
            case _:
                pass
