"""Flask application factory for the PyOS web UI.

The ``create_app`` function boots a kernel, creates a shell, and
returns a Flask app with three endpoints:

- ``GET /`` — render the terminal HTML page with the boot log.
- ``POST /api/execute`` — execute a command and return JSON.
- ``GET /api/status`` — return system running state and top summary.
"""

from __future__ import annotations

from flask import Flask, Response, jsonify, render_template, request

from py_os.kernel import Kernel, KernelState
from py_os.shell import Shell

_HTTP_BAD_REQUEST = 400


def create_app() -> Flask:
    """Create and configure the Flask application.

    Boot a kernel, create a shell, and wire up routes.

    Returns:
        A configured Flask application ready to serve.

    """
    kernel = Kernel()
    kernel.boot()
    shell = Shell(kernel=kernel)

    boot_log = "\n".join(kernel.dmesg())

    app = Flask(__name__)

    @app.route("/")
    def index() -> str:  # pyright: ignore[reportUnusedFunction]
        """Render the terminal HTML page."""
        return render_template("index.html", boot_log=boot_log)

    @app.route("/api/execute", methods=["POST"])
    def execute() -> tuple[Response, int] | Response:  # pyright: ignore[reportUnusedFunction]
        """Execute a shell command and return JSON output.

        Expects JSON body: ``{"command": "..."}``

        Returns:
            JSON with ``output`` and ``halted`` fields.

        """
        data = request.get_json(silent=True)
        if data is None or "command" not in data:
            return jsonify({"error": "Missing 'command' field"}), _HTTP_BAD_REQUEST

        if kernel.state is not KernelState.RUNNING:
            return jsonify({"output": "System halted.", "halted": True})

        command: str = data["command"]
        result = shell.execute(command)

        halted = result == Shell.EXIT_SENTINEL
        if halted:
            if kernel.state is KernelState.RUNNING:
                kernel.shutdown()
            return jsonify({"output": "System halted.", "halted": True})

        return jsonify({"output": result, "halted": False})

    @app.route("/api/status")
    def status() -> Response:  # pyright: ignore[reportUnusedFunction]
        """Return system status for status polling.

        Returns:
            JSON with ``running`` and ``status`` fields.

        """
        running = kernel.state is KernelState.RUNNING
        status_text = shell.execute("top") if running else "System halted."
        return jsonify({"running": running, "status": status_text})

    return app


def main() -> None:
    """Run the web UI development server.

    This is the ``py-os-web`` console entry point.
    """
    app = create_app()
    app.run(debug=True, port=8080)
