"""Smoke test to verify the project is set up correctly."""

from py_os import __doc__


def test_package_is_importable() -> None:
    """Verify that py_os can be imported."""
    assert __doc__ is not None
