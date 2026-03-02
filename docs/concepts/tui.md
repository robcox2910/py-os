# TUI Dashboard: The Control Room

## The Control Room Analogy

Imagine the control room of a power plant. There's a wall of screens and dials
showing everything that's happening: how much power each generator is producing,
which cooling systems are running, how hot things are getting. An operator sits
at a console and can type commands to adjust things.

PyOS's **TUI dashboard** is exactly that -- a live control room for the operating
system, right in your terminal. It shows:

- **Processes** -- what's running, what state each process is in
- **Memory** -- how much RAM is used and how much is free
- **Swap** -- page replacement status and fault counts
- **CPUs** -- which process is running on each CPU
- **Command input** -- type shell commands and see results immediately

All of this updates automatically every two seconds.

## TUI vs GUI vs CLI

There are three ways to interact with a computer:

### CLI (Command-Line Interface)
Type a command, get text back. Simple, fast, and works everywhere. This is what
the regular `pyos` shell does.

### GUI (Graphical User Interface)
Click buttons, drag windows, see images and animations. This is what Windows,
macOS, and most phone apps use. Requires a graphics system.

### TUI (Text User Interface)
A middle ground. It runs inside a terminal (like CLI), but it draws panels,
borders, and layouts using text characters (like GUI). Think of it as a GUI made
of text. You get visual structure without needing a graphics system.

**Why TUIs are useful:**

- They work over **SSH** -- you can monitor a remote server from anywhere
- They're fast -- no heavy graphics libraries needed
- They're accessible -- any terminal can display them
- They look great -- modern TUI frameworks like Textual make beautiful interfaces

## How It Works

The PyOS TUI dashboard uses the [Textual](https://textual.textualize.io/)
framework, which is Python's most popular library for building rich terminal
applications.

The dashboard:

1. **Boots the kernel** -- just like the regular CLI
2. **Creates panels** -- process table, memory bar, CPU status, and more
3. **Auto-refreshes** -- every 2 seconds, it fetches fresh data via syscalls
4. **Accepts commands** -- type in the bottom input box to run shell commands

## Running the Dashboard

```bash
# Install with the TUI extra
pip install pyos-learn[tui]

# Launch the dashboard
pyos-tui
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `q` | Quit the dashboard |
| `r` | Refresh all panels immediately |

## Where to Go Next

- [The Shell](shell.md) -- The regular command-line interface
- [Processes](processes.md) -- Understanding what the process table shows
- [Memory](memory.md) -- Understanding the memory bar and swap panel
- [Web UI](web-ui.md) -- The browser-based alternative

## Key Terms

| Term | Definition |
|------|-----------|
| **TUI** | Text User Interface -- a graphical-style display built from text characters in the terminal |
| **Dashboard** | A single screen that shows many pieces of information at once |
| **Widget** | One panel inside the dashboard (e.g. the process table or memory bar) |
| **Textual** | The Python library that powers the TUI dashboard |
