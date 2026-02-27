# Web UI

## What Is the Web UI?

The web UI lets you use PyOS from a **web browser** instead of the
terminal. It looks like a dark terminal window with green text on a
dark blue background -- just like computers in old movies!

## How It Works

Think of the web UI like a **TV remote for your OS**:

1. **You** type a command in the browser (press a button on the remote).
2. The browser sends that command to a **web server** running on your
   computer (the remote sends a signal to the TV).
3. The server passes the command to the PyOS **shell** (the TV processes
   the signal).
4. The shell's output travels back to the browser (the TV changes
   channel).

Behind the scenes, a small Python web framework called **Flask** handles
the communication.  Flask is like a postal worker -- it receives your
letters (HTTP requests), delivers them to the right person (the shell),
and brings back the reply (JSON responses).

## Endpoints

The web server exposes three endpoints:

| Endpoint | Method | What It Does |
|----------|--------|-------------|
| `/` | GET | Serves the HTML terminal page |
| `/api/execute` | POST | Runs a shell command and returns the output |
| `/api/status` | GET | Returns whether the OS is running plus a dashboard |

## Running the Web UI

Install the optional ``web`` extra, then start the server:

```bash
pip install py-os[web]
py-os-web
```

Open your browser to ``http://localhost:8080`` and start typing
commands -- just like the regular terminal, but in your browser!

## Why a Web UI?

A web interface makes PyOS accessible to anyone with a browser.  You
do not need to install Python or know how to use a terminal.  It is
also a great example of the **client-server model** -- the same
pattern used by every website you visit.

## Where to Go Next

- [The Shell](shell.md) -- All the commands available in the web terminal
- [Interactive Tutorials](tutorials.md) -- Try the guided lessons from your browser
- [Devices and Networking](devices-and-networking.md) -- How the client-server model works under the hood
