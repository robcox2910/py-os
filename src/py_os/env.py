"""Environment variables — process configuration via key-value pairs.

In Unix, every process has an environment: a set of ``KEY=VALUE`` string
pairs inherited from its parent.  Common examples include ``PATH``
(where to find executables), ``HOME`` (the user's home directory), and
``USER`` (current username).

Key design properties:
    - **Copy-on-fork** — a child process gets a *copy* of its parent's
      environment.  Changes in the child don't affect the parent.
    - **Strings only** — both keys and values are strings (no types).
    - **Convention over enforcement** — uppercase names, no spaces in
      keys, but these are conventions, not hard rules.

Our ``Environment`` class wraps a plain dict and provides the standard
operations: get, set, delete, list, and copy.
"""


class Environment:
    """A key-value store for environment variables.

    Each instance is an independent copy — modifying one does not
    affect any other.  This mirrors how Unix processes each have
    their own environment block.
    """

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        """Create an environment, optionally pre-populated.

        Args:
            initial: Starting variables (copied, not referenced).

        """
        self._vars: dict[str, str] = dict(initial) if initial else {}

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return the value for *key*, or *default* if not set."""
        return self._vars.get(key, default)

    def set(self, key: str, value: str) -> None:
        """Set *key* to *value* (creates or overwrites)."""
        self._vars[key] = value

    def delete(self, key: str) -> None:
        """Remove *key* from the environment.

        Raises:
            KeyError: If *key* does not exist.

        """
        del self._vars[key]

    def items(self) -> list[tuple[str, str]]:
        """Return all (key, value) pairs."""
        return list(self._vars.items())

    def copy(self) -> "Environment":
        """Return an independent copy of this environment."""
        return Environment(initial=self._vars)

    def __len__(self) -> int:
        """Return the number of variables."""
        return len(self._vars)
