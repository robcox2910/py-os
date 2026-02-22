"""Filesystem journaling — write-ahead log for crash recovery.

Before changing the filesystem, we log *what we're about to do*.  If a
crash happens mid-operation, we replay the log on recovery to bring the
filesystem back to a consistent state.

Key concepts:

- **Write-ahead logging (WAL)** — log the operation *before* applying it.
- **Transaction** — a group of entries that succeed or fail as a unit.
- **Checkpoint** — a snapshot of the filesystem at a known-good point.
- **Recovery** — restore from checkpoint, then replay committed transactions.

Why composition instead of subclassing ``FileSystem``?  The journal is a
*layer* on top of the filesystem, not a different filesystem.  Composition
keeps concerns cleanly separated — ``FileSystem`` knows nothing about
journals, and ``Journal`` knows nothing about inodes.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic
from typing import Any

from py_os.fs.filesystem import FileSystem


class JournalOp(StrEnum):
    """Represent the type of filesystem mutation being logged."""

    CREATE_FILE = "create_file"
    CREATE_DIR = "create_dir"
    WRITE = "write"
    WRITE_AT = "write_at"
    DELETE = "delete"
    LINK = "link"
    SYMLINK = "symlink"


class TransactionState(StrEnum):
    """Represent the lifecycle state of a transaction."""

    ACTIVE = "active"
    COMMITTED = "committed"
    ABORTED = "aborted"


@dataclass
class JournalEntry:
    """A single logged operation within a transaction.

    Args capture exactly the keyword arguments the filesystem method
    receives.  For ``write``/``write_at``, the ``data`` value stores
    base64-encoded bytes for serialization.
    """

    op: JournalOp
    args: dict[str, Any]
    timestamp: float


@dataclass
class Transaction:
    """Group journal entries into an atomic unit.

    Each transaction is identified by a unique ``txn_id`` and moves
    through ACTIVE → COMMITTED or ACTIVE → ABORTED.
    """

    txn_id: int
    state: TransactionState = TransactionState.ACTIVE
    entries: list[JournalEntry] = field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]


class Journal:
    """The write-ahead log itself.

    Manages transactions: begin, append entries, commit or abort.
    After a checkpoint, committed and aborted transactions can be
    cleared to free space.
    """

    def __init__(self) -> None:
        """Create an empty journal."""
        self._transactions: list[Transaction] = []
        self._next_txn_id: int = 0

    def begin(self) -> Transaction:
        """Begin a new ACTIVE transaction.

        Returns:
            The newly created transaction.

        """
        txn = Transaction(txn_id=self._next_txn_id)
        self._next_txn_id += 1
        self._transactions.append(txn)
        return txn

    def append(self, txn: Transaction, entry: JournalEntry) -> None:
        """Append an entry to an ACTIVE transaction.

        Args:
            txn: The transaction to append to.
            entry: The journal entry to add.

        Raises:
            ValueError: If the transaction is not ACTIVE.

        """
        if txn.state is not TransactionState.ACTIVE:
            msg = f"Cannot append to {txn.state} transaction"
            raise ValueError(msg)
        txn.entries.append(entry)

    def commit(self, txn: Transaction) -> None:
        """Mark an ACTIVE transaction as COMMITTED.

        Args:
            txn: The transaction to commit.

        Raises:
            ValueError: If the transaction is not ACTIVE.

        """
        if txn.state is not TransactionState.ACTIVE:
            msg = f"Cannot commit {txn.state} transaction"
            raise ValueError(msg)
        txn.state = TransactionState.COMMITTED

    def abort(self, txn: Transaction) -> None:
        """Mark an ACTIVE transaction as ABORTED.

        Args:
            txn: The transaction to abort.

        Raises:
            ValueError: If the transaction is not ACTIVE.

        """
        if txn.state is not TransactionState.ACTIVE:
            msg = f"Cannot abort {txn.state} transaction"
            raise ValueError(msg)
        txn.state = TransactionState.ABORTED

    def active_transactions(self) -> list[Transaction]:
        """Return all ACTIVE transactions."""
        return [t for t in self._transactions if t.state is TransactionState.ACTIVE]

    def committed_transactions(self) -> list[Transaction]:
        """Return all COMMITTED transactions."""
        return [t for t in self._transactions if t.state is TransactionState.COMMITTED]

    @property
    def transactions(self) -> list[Transaction]:
        """Return all transactions (read-only snapshot)."""
        return list(self._transactions)

    def clear(self) -> None:
        """Remove all COMMITTED and ABORTED transactions.

        Called after a checkpoint to reclaim journal space.  Only
        ACTIVE transactions survive (they represent in-flight work).
        """
        self._transactions = [t for t in self._transactions if t.state is TransactionState.ACTIVE]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the journal to a dictionary."""
        return {
            "next_txn_id": self._next_txn_id,
            "transactions": [
                {
                    "txn_id": txn.txn_id,
                    "state": txn.state.value,
                    "entries": [
                        {
                            "op": entry.op.value,
                            "args": entry.args,
                            "timestamp": entry.timestamp,
                        }
                        for entry in txn.entries
                    ],
                }
                for txn in self._transactions
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Journal:
        """Deserialize a journal from a dictionary.

        Args:
            data: Dict produced by ``to_dict()``.

        Returns:
            A reconstructed Journal instance.

        """
        journal = cls()
        journal._next_txn_id = data["next_txn_id"]
        for txn_data in data["transactions"]:
            txn = Transaction(
                txn_id=txn_data["txn_id"],
                state=TransactionState(txn_data["state"]),
                entries=[
                    JournalEntry(
                        op=JournalOp(e["op"]),
                        args=e["args"],
                        timestamp=e["timestamp"],
                    )
                    for e in txn_data["entries"]
                ],
            )
            journal._transactions.append(txn)
        return journal


def _encode_bytes_arg(data: bytes) -> str:
    """Encode bytes as base64 string for journal serialization."""
    return base64.b64encode(data).decode("ascii")


def _decode_bytes_arg(data: str) -> bytes:
    """Decode base64 string back to bytes."""
    return base64.b64decode(data)


class JournaledFileSystem:
    """Wrap a FileSystem to intercept every mutation with WAL logging.

    Read-only operations are delegated directly.  Mutating operations
    follow the pattern: begin → log → apply → commit.

    If a crash happens between log and commit, the transaction stays
    ACTIVE.  On recovery, active transactions are aborted and the
    filesystem is restored from the last checkpoint.
    """

    def __init__(self, fs: FileSystem | None = None) -> None:
        """Create a journaled filesystem.

        Args:
            fs: Optional existing filesystem to wrap.  A fresh one
                is created if not provided.

        """
        self._fs: FileSystem = fs or FileSystem()
        self._journal: Journal = Journal()
        self._checkpoint: dict[str, Any] | None = None

    @property
    def journal(self) -> Journal:
        """Return the underlying journal (for inspection/testing)."""
        return self._journal

    # -- Delegated read-only methods ----------------------------------------

    def read(self, path: str) -> bytes:
        """Read the contents of a file."""
        return self._fs.read(path)

    def read_at(self, path: str, *, offset: int, count: int) -> bytes:
        """Read bytes from a file at a given offset."""
        return self._fs.read_at(path, offset=offset, count=count)

    def stat(self, path: str) -> Any:
        """Return metadata for the given path."""
        return self._fs.stat(path)

    def lstat(self, path: str) -> Any:
        """Return metadata without following the final symlink."""
        return self._fs.lstat(path)

    def list_dir(self, path: str) -> list[str]:
        """List the names in a directory."""
        return self._fs.list_dir(path)

    def exists(self, path: str) -> bool:
        """Check whether a path exists."""
        return self._fs.exists(path)

    def readlink(self, path: str) -> str:
        """Return the target path stored in a symbolic link."""
        return self._fs.readlink(path)

    # -- Journaled mutating methods -----------------------------------------

    def create_file(self, path: str) -> None:
        """Create an empty file with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.CREATE_FILE,
                args={"path": path},
                timestamp=monotonic(),
            ),
        )
        self._fs.create_file(path)
        self._journal.commit(txn)

    def create_dir(self, path: str) -> None:
        """Create a directory with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.CREATE_DIR,
                args={"path": path},
                timestamp=monotonic(),
            ),
        )
        self._fs.create_dir(path)
        self._journal.commit(txn)

    def write(self, path: str, data: bytes) -> None:
        """Write data to a file with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.WRITE,
                args={"path": path, "data": _encode_bytes_arg(data)},
                timestamp=monotonic(),
            ),
        )
        self._fs.write(path, data)
        self._journal.commit(txn)

    def write_at(self, path: str, *, offset: int, data: bytes) -> None:
        """Write data at offset with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.WRITE_AT,
                args={
                    "path": path,
                    "offset": offset,
                    "data": _encode_bytes_arg(data),
                },
                timestamp=monotonic(),
            ),
        )
        self._fs.write_at(path, offset=offset, data=data)
        self._journal.commit(txn)

    def delete(self, path: str) -> None:
        """Delete a file or empty directory with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.DELETE,
                args={"path": path},
                timestamp=monotonic(),
            ),
        )
        self._fs.delete(path)
        self._journal.commit(txn)

    def link(self, target_path: str, link_path: str) -> None:
        """Create a hard link with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.LINK,
                args={"target_path": target_path, "link_path": link_path},
                timestamp=monotonic(),
            ),
        )
        self._fs.link(target_path, link_path)
        self._journal.commit(txn)

    def symlink(self, target_path: str, link_path: str) -> None:
        """Create a symbolic link with WAL logging."""
        txn = self._journal.begin()
        self._journal.append(
            txn,
            JournalEntry(
                op=JournalOp.SYMLINK,
                args={"target_path": target_path, "link_path": link_path},
                timestamp=monotonic(),
            ),
        )
        self._fs.symlink(target_path, link_path)
        self._journal.commit(txn)

    # -- Journal control ----------------------------------------------------

    def checkpoint(self) -> None:
        """Take a snapshot of the current filesystem state.

        Store the snapshot and clear committed/aborted transactions.
        This is the "known-good state" we can recover to.
        """
        self._checkpoint = self._fs.to_dict()
        self._journal.clear()

    def simulate_crash(self) -> None:
        """Simulate a power failure.

        Abort all ACTIVE transactions, then restore the filesystem
        from the last checkpoint.  Uncommitted work is lost.
        """
        for txn in self._journal.active_transactions():
            self._journal.abort(txn)

        if self._checkpoint is not None:
            self._fs = FileSystem.from_dict(self._checkpoint)
        else:
            self._fs = FileSystem()

    def recover(self) -> int:
        """Replay committed transactions after a crash.

        1. Restore from checkpoint (already done by simulate_crash).
        2. Replay all COMMITTED transactions in order.
        3. Clear the replayed transactions from the journal.

        Returns:
            The number of transactions replayed.

        """
        committed = self._journal.committed_transactions()
        for txn in committed:
            for entry in txn.entries:
                self._replay_entry(entry)
        self._journal.clear()
        return len(committed)

    def _replay_entry(self, entry: JournalEntry) -> None:
        """Replay a single journal entry against the filesystem."""
        match entry.op:
            case JournalOp.CREATE_FILE:
                self._fs.create_file(entry.args["path"])
            case JournalOp.CREATE_DIR:
                self._fs.create_dir(entry.args["path"])
            case JournalOp.WRITE:
                data = _decode_bytes_arg(entry.args["data"])
                self._fs.write(entry.args["path"], data)
            case JournalOp.WRITE_AT:
                data = _decode_bytes_arg(entry.args["data"])
                self._fs.write_at(
                    entry.args["path"],
                    offset=entry.args["offset"],
                    data=data,
                )
            case JournalOp.DELETE:
                self._fs.delete(entry.args["path"])
            case JournalOp.LINK:
                self._fs.link(
                    entry.args["target_path"],
                    entry.args["link_path"],
                )
            case JournalOp.SYMLINK:
                self._fs.symlink(
                    entry.args["target_path"],
                    entry.args["link_path"],
                )

    def journal_status(self) -> dict[str, Any]:
        """Return a summary of journal transaction counts.

        Returns:
            Dict with total, active, committed, and aborted counts.

        """
        txns = self._journal.transactions
        active = sum(1 for t in txns if t.state is TransactionState.ACTIVE)
        committed = sum(1 for t in txns if t.state is TransactionState.COMMITTED)
        aborted = sum(1 for t in txns if t.state is TransactionState.ABORTED)
        return {
            "total": len(txns),
            "active": active,
            "committed": committed,
            "aborted": aborted,
        }

    # -- Serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize the journaled filesystem to a dictionary."""
        return {
            "fs": self._fs.to_dict(),
            "journal": self._journal.to_dict(),
            "checkpoint": self._checkpoint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JournaledFileSystem:
        """Deserialize a journaled filesystem from a dictionary.

        Args:
            data: Dict produced by ``to_dict()``.

        Returns:
            A reconstructed JournaledFileSystem instance.

        """
        jfs = object.__new__(cls)
        jfs._fs = FileSystem.from_dict(data["fs"])
        jfs._journal = Journal.from_dict(data["journal"])
        jfs._checkpoint = data.get("checkpoint")
        return jfs
