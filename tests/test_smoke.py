"""Smoke test to verify the project is set up correctly."""

import py_os


def test_package_is_importable() -> None:
    """Verify that py_os can be imported."""
    assert py_os.__doc__ is not None
