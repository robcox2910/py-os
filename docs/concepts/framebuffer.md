# Framebuffer: The Screen Inside the Computer

## The Whiteboard Analogy

Imagine a whiteboard hanging on the wall. It's divided into a grid of tiny squares
-- rows and columns. Each square can hold one letter, one number, or one symbol.
When you write on the whiteboard, you're filling in squares. When you erase, you
set squares back to blank.

That whiteboard is a **framebuffer** -- a chunk of memory that holds everything
currently shown on the screen. Every character you see in a terminal, every pixel
in a game, lives somewhere in a framebuffer.

## Pixels vs Characters

In a graphical OS like Windows or macOS, each square in the framebuffer holds a
**pixel** -- a tiny dot of colour. A typical screen might be 1920 pixels wide and
1080 pixels tall. That's over two million pixels, each stored as a colour value
(red, green, blue).

PyOS keeps things simpler. Our framebuffer is a **character grid** -- each cell
holds one ASCII character. The default display is 40 columns wide and 12 rows
tall. It's like a tiny terminal window inside the OS.

## How Drawing Works

Drawing on the framebuffer means changing what's stored in the grid cells:

- **set_pixel(x, y, char)** -- put a character at one position
- **draw_text(x, y, text)** -- write a string of characters starting at a position
- **fill_rect(x1, y1, x2, y2, char)** -- fill a rectangle with one character
- **clear()** -- reset everything to spaces

When you ask the framebuffer to **render**, it reads the grid and produces a
bordered ASCII picture:

```
+----------------------------------------+
|                                        |
|  PyOS Framebuffer                      |
|                                        |
|  Hello, World!                         |
|                                        |
+----------------------------------------+
```

## Out of Bounds? No Problem

What happens if you try to draw outside the grid -- say, at column 100 when the
display is only 40 columns wide? The framebuffer silently ignores it. No error,
no crash. This is called **clipping**, and real GPUs do the same thing. If a game
draws a character that's half off the edge of the screen, the GPU just skips the
invisible part.

## GPU Memory in Real Computers

In a real computer, the framebuffer lives in **video RAM** (VRAM) on the graphics
card. The GPU reads this memory many times per second (usually 60 or more) and
sends the result to your monitor. That's why changing what's in the framebuffer
instantly changes what you see on screen.

Modern GPUs have their own processors and can draw complex 3D graphics, apply
textures, and run shader programs -- all by writing the results into the
framebuffer. But at the most basic level, it's still just a grid of values that
gets displayed on screen.

## Try It Yourself

```
fb              # Show framebuffer info (dimensions, status)
fb render       # Display the current screen contents
fb pixel 5 3 X  # Place an 'X' at column 5, row 3
fb text 2 1 Hi  # Write "Hi" starting at column 2, row 1
fb rect 0 0 9 4 #  # Fill a 10x5 rectangle with '#'
fb clear        # Wipe the screen
fb demo         # Draw a demo pattern with borders and text
```

## Where to Go Next

- [Devices and Networking](devices-and-networking.md) -- How the OS talks to hardware
- [The Shell](shell.md) -- The command-line interface to the OS
- [Memory](memory.md) -- How the OS manages RAM (the framebuffer lives in memory!)

## Key Terms

| Term | Definition |
|------|-----------|
| **Framebuffer** | A block of memory that represents every pixel on the screen |
| **Pixel** | The smallest dot on a screen -- a framebuffer stores one character per pixel |
| **Resolution** | The width and height of the screen in pixels (e.g. 80x24) |
| **Rendering** | Drawing shapes and text into the framebuffer so they appear on screen |
