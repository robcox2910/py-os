"""Tests for the browser-based web UI.

The web UI provides a Flask-based terminal interface for PyOS,
exposing the shell via HTTP endpoints.  Tests use ``pytest.importorskip``
so they are skipped gracefully when Flask is not installed.
"""

from __future__ import annotations

from typing import Any

import pytest

flask = pytest.importorskip("flask")

from py_os.web.app import create_app  # noqa: E402

HTTP_OK = 200
HTTP_BAD_REQUEST = 400


def _create_client() -> Any:
    """Create a test client from a fresh app."""
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# -- Cycle 1: App creation and index page -----------------------------------


class TestAppCreation:
    """Verify app factory and landing page."""

    def test_create_app_returns_flask(self) -> None:
        """create_app should return a Flask application."""
        app = create_app()
        assert isinstance(app, flask.Flask)

    def test_index_returns_html(self) -> None:
        """GET / should return HTML containing 'PyOS'."""
        client = _create_client()
        response = client.get("/")
        assert response.status_code == HTTP_OK
        assert b"PyOS" in response.data

    def test_index_content_type(self) -> None:
        """GET / should return text/html content type."""
        client = _create_client()
        response = client.get("/")
        assert "text/html" in response.content_type


# -- Cycle 2: Execute endpoint ----------------------------------------------


class TestExecuteEndpoint:
    """Verify the /api/execute POST endpoint."""

    def test_help_returns_output(self) -> None:
        """POST /api/execute with 'help' should return command output."""
        client = _create_client()
        response = client.post("/api/execute", json={"command": "help"})
        assert response.status_code == HTTP_OK
        data = response.get_json()
        assert "output" in data
        assert len(data["output"]) > 0

    def test_ls_root_works(self) -> None:
        """POST /api/execute with 'ls /' should work."""
        client = _create_client()
        response = client.post("/api/execute", json={"command": "ls /"})
        assert response.status_code == HTTP_OK
        data = response.get_json()
        assert "output" in data

    def test_unknown_command_returns_error(self) -> None:
        """POST /api/execute with unknown command should return error text."""
        client = _create_client()
        response = client.post("/api/execute", json={"command": "nonexistent_cmd"})
        assert response.status_code == HTTP_OK
        data = response.get_json()
        assert "output" in data
        assert "unknown" in data["output"].lower() or "error" in data["output"].lower()

    def test_halted_false_normally(self) -> None:
        """Normal commands should return halted=False."""
        client = _create_client()
        response = client.post("/api/execute", json={"command": "help"})
        data = response.get_json()
        assert data["halted"] is False


# -- Cycle 3: Status endpoint -----------------------------------------------


class TestStatusEndpoint:
    """Verify the /api/status GET endpoint."""

    def test_status_returns_running(self) -> None:
        """GET /api/status should report running=True."""
        client = _create_client()
        response = client.get("/api/status")
        assert response.status_code == HTTP_OK
        data = response.get_json()
        assert data["running"] is True

    def test_status_includes_dashboard(self) -> None:
        """GET /api/status should include a dashboard string."""
        client = _create_client()
        response = client.get("/api/status")
        data = response.get_json()
        assert "dashboard" in data
        assert isinstance(data["dashboard"], str)


# -- Cycle 4: Exit handling -------------------------------------------------


class TestExitHandling:
    """Verify that 'exit' halts the system properly."""

    def test_exit_returns_halted(self) -> None:
        """POST /api/execute with 'exit' should return halted=True."""
        client = _create_client()
        response = client.post("/api/execute", json={"command": "exit"})
        data = response.get_json()
        assert data["halted"] is True

    def test_commands_after_exit_report_halted(self) -> None:
        """Commands after exit should indicate the system is halted."""
        client = _create_client()
        client.post("/api/execute", json={"command": "exit"})
        response = client.post("/api/execute", json={"command": "help"})
        data = response.get_json()
        assert data["halted"] is True


# -- Cycle 5: Error handling ------------------------------------------------


class TestErrorHandling:
    """Verify error responses for malformed requests."""

    def test_missing_command_field(self) -> None:
        """POST /api/execute without 'command' should return 400."""
        client = _create_client()
        response = client.post("/api/execute", json={"wrong_field": "help"})
        assert response.status_code == HTTP_BAD_REQUEST

    def test_no_json_body(self) -> None:
        """POST /api/execute with no JSON should return 400."""
        client = _create_client()
        response = client.post("/api/execute", data="not json")
        assert response.status_code == HTTP_BAD_REQUEST
