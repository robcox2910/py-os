"""Browser-based web UI for PyOS.

This package provides a Flask application that exposes the PyOS shell
through a web browser.  It is an **optional** extra — install with::

    pip install py-os[web]

The ``create_app`` factory in ``app.py`` boots a kernel, creates a
shell, and serves three endpoints:

- ``GET /`` — HTML terminal page.
- ``POST /api/execute`` — execute a shell command and return JSON.
- ``GET /api/status`` — system status for live dashboard polling.
"""
