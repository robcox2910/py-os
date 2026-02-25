"""Tests for filesystem journaling — write-ahead log for crash recovery."""

from pathlib import Path
from time import monotonic

import pytest

from py_os.fs.filesystem import FileType
from py_os.fs.journal import (
    Journal,
    JournaledFileSystem,
    JournalEntry,
    JournalOp,
    Transaction,
    TransactionState,
)
from py_os.fs.persistence import dump_journaled_filesystem, load_journaled_filesystem
from py_os.kernel import ExecutionMode, Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallNumber

# Named constants for magic values in tests (PLR2004)
TRANSACTION_STATE_COUNT = 3
EXAMPLE_TXN_ID = 42
EXAMPLE_TIMESTAMP = 1234.5
EXPECTED_TXN_ID_AFTER_TWO = 2
EXPECTED_COMMITTED_TWO = 2
EXPECTED_COMMITTED_THREE = 3
EXPECTED_REPLAYED_TWO = 2
EXPECTED_REPLAYED_THREE = 3
SYS_JOURNAL_STATUS_NUM = 130
SYS_JOURNAL_CHECKPOINT_NUM = 131
SYS_JOURNAL_RECOVER_NUM = 132
SYS_JOURNAL_CRASH_NUM = 133


# ---------------------------------------------------------------------------
# TDD Cycle 1: Data Structures
# ---------------------------------------------------------------------------


class TestJournalOp:
    """Verify the JournalOp enum covers all mutating filesystem operations."""

    def test_journal_op_is_str_enum(self) -> None:
        """JournalOp members are usable as strings."""
        assert JournalOp.CREATE_FILE == "create_file"

    def test_all_ops_present(self) -> None:
        """Every mutating filesystem method has a corresponding op."""
        expected = {
            "create_file",
            "create_dir",
            "write",
            "write_at",
            "delete",
            "link",
            "symlink",
        }
        actual = {op.value for op in JournalOp}
        assert actual == expected


class TestTransactionState:
    """Verify the TransactionState enum."""

    def test_states_are_strings(self) -> None:
        """TransactionState members are usable as strings."""
        assert TransactionState.ACTIVE == "active"
        assert TransactionState.COMMITTED == "committed"
        assert TransactionState.ABORTED == "aborted"

    def test_all_states_present(self) -> None:
        """All three lifecycle states exist."""
        assert len(TransactionState) == TRANSACTION_STATE_COUNT


class TestJournalEntry:
    """Verify JournalEntry dataclass construction."""

    def test_create_entry(self) -> None:
        """Create a JournalEntry with all required fields."""
        ts = monotonic()
        entry = JournalEntry(
            op=JournalOp.CREATE_FILE,
            args={"path": "/foo.txt"},
            timestamp=ts,
        )
        assert entry.op is JournalOp.CREATE_FILE
        assert entry.args == {"path": "/foo.txt"}
        assert entry.timestamp == ts

    def test_entry_stores_arbitrary_args(self) -> None:
        """Args dict can hold any serializable values."""
        entry = JournalEntry(
            op=JournalOp.WRITE,
            args={"path": "/data", "data": "aGVsbG8="},
            timestamp=monotonic(),
        )
        assert entry.args["data"] == "aGVsbG8="


class TestTransaction:
    """Verify Transaction dataclass defaults and structure."""

    def test_default_state_is_active(self) -> None:
        """New transactions start in the ACTIVE state."""
        txn = Transaction(txn_id=0)
        assert txn.state is TransactionState.ACTIVE

    def test_default_entries_empty(self) -> None:
        """New transactions start with an empty entry list."""
        txn = Transaction(txn_id=1)
        assert txn.entries == []

    def test_txn_id_stored(self) -> None:
        """Transaction ID is stored correctly."""
        txn = Transaction(txn_id=EXAMPLE_TXN_ID)
        assert txn.txn_id == EXAMPLE_TXN_ID


# ---------------------------------------------------------------------------
# TDD Cycle 2: Journal Class
# ---------------------------------------------------------------------------


class TestJournal:
    """Verify Journal begin/append/commit/abort and queries."""

    def test_begin_creates_active_transaction(self) -> None:
        """begin() returns a new ACTIVE transaction."""
        journal = Journal()
        txn = journal.begin()
        assert txn.state is TransactionState.ACTIVE
        assert txn.txn_id == 0

    def test_begin_increments_txn_id(self) -> None:
        """Each begin() allocates a unique, incrementing ID."""
        journal = Journal()
        t0 = journal.begin()
        t1 = journal.begin()
        assert t0.txn_id == 0
        assert t1.txn_id == 1

    def test_append_adds_entry(self) -> None:
        """append() adds an entry to the transaction's list."""
        journal = Journal()
        txn = journal.begin()
        entry = JournalEntry(
            op=JournalOp.CREATE_FILE,
            args={"path": "/a.txt"},
            timestamp=monotonic(),
        )
        journal.append(txn, entry)
        assert len(txn.entries) == 1
        assert txn.entries[0] is entry

    def test_append_rejects_committed(self) -> None:
        """append() raises if the transaction is already COMMITTED."""
        journal = Journal()
        txn = journal.begin()
        journal.commit(txn)
        entry = JournalEntry(op=JournalOp.DELETE, args={"path": "/x"}, timestamp=monotonic())
        with pytest.raises(ValueError, match="committed"):
            journal.append(txn, entry)

    def test_append_rejects_aborted(self) -> None:
        """append() raises if the transaction is already ABORTED."""
        journal = Journal()
        txn = journal.begin()
        journal.abort(txn)
        entry = JournalEntry(op=JournalOp.DELETE, args={"path": "/x"}, timestamp=monotonic())
        with pytest.raises(ValueError, match="aborted"):
            journal.append(txn, entry)

    def test_commit_marks_committed(self) -> None:
        """commit() transitions ACTIVE → COMMITTED."""
        journal = Journal()
        txn = journal.begin()
        journal.commit(txn)
        assert txn.state is TransactionState.COMMITTED

    def test_commit_rejects_non_active(self) -> None:
        """commit() raises if already COMMITTED."""
        journal = Journal()
        txn = journal.begin()
        journal.commit(txn)
        with pytest.raises(ValueError, match="committed"):
            journal.commit(txn)

    def test_abort_marks_aborted(self) -> None:
        """abort() transitions ACTIVE → ABORTED."""
        journal = Journal()
        txn = journal.begin()
        journal.abort(txn)
        assert txn.state is TransactionState.ABORTED

    def test_abort_rejects_non_active(self) -> None:
        """abort() raises if already ABORTED."""
        journal = Journal()
        txn = journal.begin()
        journal.abort(txn)
        with pytest.raises(ValueError, match="aborted"):
            journal.abort(txn)

    def test_active_transactions(self) -> None:
        """active_transactions() returns only ACTIVE ones."""
        journal = Journal()
        t0 = journal.begin()
        t1 = journal.begin()
        journal.commit(t0)
        assert journal.active_transactions() == [t1]

    def test_committed_transactions(self) -> None:
        """committed_transactions() returns only COMMITTED ones."""
        journal = Journal()
        t0 = journal.begin()
        t1 = journal.begin()
        journal.commit(t0)
        journal.abort(t1)
        assert journal.committed_transactions() == [t0]

    def test_clear_removes_committed_and_aborted(self) -> None:
        """clear() keeps only ACTIVE transactions."""
        journal = Journal()
        t0 = journal.begin()
        t1 = journal.begin()
        t2 = journal.begin()
        journal.commit(t0)
        journal.abort(t1)
        journal.clear()
        assert journal.active_transactions() == [t2]
        assert journal.committed_transactions() == []


# ---------------------------------------------------------------------------
# TDD Cycle 3: Journal Serialization
# ---------------------------------------------------------------------------


class TestJournalSerialization:
    """Verify Journal.to_dict/from_dict round-trip."""

    def test_empty_journal_round_trip(self) -> None:
        """An empty journal survives serialization."""
        journal = Journal()
        data = journal.to_dict()
        restored = Journal.from_dict(data)
        assert restored.active_transactions() == []
        assert restored.committed_transactions() == []

    def test_round_trip_preserves_transactions(self) -> None:
        """Transactions and their entries survive serialization."""
        journal = Journal()
        txn = journal.begin()
        entry = JournalEntry(
            op=JournalOp.CREATE_FILE,
            args={"path": "/foo.txt"},
            timestamp=EXAMPLE_TIMESTAMP,
        )
        journal.append(txn, entry)
        journal.commit(txn)

        data = journal.to_dict()
        restored = Journal.from_dict(data)
        committed = restored.committed_transactions()
        assert len(committed) == 1
        assert committed[0].txn_id == 0
        assert len(committed[0].entries) == 1
        assert committed[0].entries[0].op is JournalOp.CREATE_FILE
        assert committed[0].entries[0].args == {"path": "/foo.txt"}
        assert committed[0].entries[0].timestamp == EXAMPLE_TIMESTAMP

    def test_round_trip_preserves_next_txn_id(self) -> None:
        """The next_txn_id counter survives round-trip."""
        journal = Journal()
        journal.begin()
        journal.begin()
        data = journal.to_dict()
        restored = Journal.from_dict(data)
        # The next begin() should get id=2
        txn = restored.begin()
        assert txn.txn_id == EXPECTED_TXN_ID_AFTER_TWO

    def test_round_trip_preserves_mixed_states(self) -> None:
        """Active, committed, and aborted transactions all survive."""
        journal = Journal()
        t0 = journal.begin()
        t1 = journal.begin()
        journal.begin()  # t2 stays active
        journal.commit(t0)
        journal.abort(t1)

        data = journal.to_dict()
        restored = Journal.from_dict(data)
        assert len(restored.committed_transactions()) == 1
        assert len(restored.active_transactions()) == 1

    def test_to_dict_contains_expected_keys(self) -> None:
        """to_dict() produces the expected top-level keys."""
        journal = Journal()
        data = journal.to_dict()
        assert "next_txn_id" in data
        assert "transactions" in data


# ---------------------------------------------------------------------------
# TDD Cycle 4: JournaledFileSystem — Read-Only Delegation
# ---------------------------------------------------------------------------


class TestJournaledFileSystemReadOnly:
    """Verify read-only methods delegate without journaling."""

    def _make_jfs(self) -> JournaledFileSystem:
        """Create a JournaledFileSystem with some test data."""
        jfs = JournaledFileSystem()
        jfs.create_file("/hello.txt")
        jfs.write("/hello.txt", b"Hello, world!")
        jfs.create_dir("/docs")
        jfs.checkpoint()  # clear journal so we start clean
        return jfs

    def test_read_delegates(self) -> None:
        """read() returns file contents from the inner filesystem."""
        jfs = self._make_jfs()
        assert jfs.read("/hello.txt") == b"Hello, world!"

    def test_read_at_delegates(self) -> None:
        """read_at() returns a byte slice from the inner filesystem."""
        jfs = self._make_jfs()
        assert jfs.read_at("/hello.txt", offset=0, count=5) == b"Hello"

    def test_stat_delegates(self) -> None:
        """stat() returns inode metadata."""
        jfs = self._make_jfs()
        info = jfs.stat("/hello.txt")
        assert info.size == len(b"Hello, world!")

    def test_lstat_delegates(self) -> None:
        """lstat() returns metadata without following symlinks."""
        jfs = self._make_jfs()
        jfs.symlink("/hello.txt", "/link")
        info = jfs.lstat("/link")
        assert info.file_type is FileType.SYMLINK

    def test_list_dir_delegates(self) -> None:
        """list_dir() returns directory contents."""
        jfs = self._make_jfs()
        entries = jfs.list_dir("/")
        assert "hello.txt" in entries
        assert "docs" in entries

    def test_exists_delegates(self) -> None:
        """exists() checks path presence."""
        jfs = self._make_jfs()
        assert jfs.exists("/hello.txt") is True
        assert jfs.exists("/nope.txt") is False

    def test_readlink_delegates(self) -> None:
        """readlink() returns the symlink target."""
        jfs = self._make_jfs()
        jfs.symlink("/hello.txt", "/shortcut")
        assert jfs.readlink("/shortcut") == "/hello.txt"


# ---------------------------------------------------------------------------
# TDD Cycle 5: JournaledFileSystem — Mutating Methods
# ---------------------------------------------------------------------------


class TestJournaledFileSystemMutations:
    """Verify all 7 mutating methods log + commit + apply."""

    def test_create_file_journals(self) -> None:
        """create_file() logs a CREATE_FILE op and creates the file."""
        jfs = JournaledFileSystem()
        jfs.create_file("/a.txt")
        assert jfs.exists("/a.txt")
        status = jfs.journal_status()
        assert status["committed"] == 1

    def test_create_dir_journals(self) -> None:
        """create_dir() logs a CREATE_DIR op and creates the directory."""
        jfs = JournaledFileSystem()
        jfs.create_dir("/stuff")
        assert jfs.exists("/stuff")
        status = jfs.journal_status()
        assert status["committed"] == 1

    def test_write_journals(self) -> None:
        """write() logs a WRITE op and writes data."""
        jfs = JournaledFileSystem()
        jfs.create_file("/f.txt")
        jfs.write("/f.txt", b"data")
        assert jfs.read("/f.txt") == b"data"
        assert jfs.journal_status()["committed"] == EXPECTED_COMMITTED_TWO  # create + write

    def test_write_at_journals(self) -> None:
        """write_at() logs a WRITE_AT op and writes at offset."""
        jfs = JournaledFileSystem()
        jfs.create_file("/f.txt")
        jfs.write("/f.txt", b"AAAA")
        jfs.write_at("/f.txt", offset=2, data=b"BB")
        assert jfs.read("/f.txt") == b"AABB"
        assert jfs.journal_status()["committed"] == EXPECTED_COMMITTED_THREE

    def test_delete_journals(self) -> None:
        """delete() logs a DELETE op and removes the file."""
        jfs = JournaledFileSystem()
        jfs.create_file("/gone.txt")
        jfs.delete("/gone.txt")
        assert not jfs.exists("/gone.txt")
        assert jfs.journal_status()["committed"] == EXPECTED_COMMITTED_TWO  # create + delete

    def test_link_journals(self) -> None:
        """link() logs a LINK op and creates a hard link."""
        jfs = JournaledFileSystem()
        jfs.create_file("/original.txt")
        jfs.write("/original.txt", b"shared")
        jfs.link("/original.txt", "/alias.txt")
        assert jfs.read("/alias.txt") == b"shared"
        assert jfs.journal_status()["committed"] == EXPECTED_COMMITTED_THREE

    def test_symlink_journals(self) -> None:
        """symlink() logs a SYMLINK op and creates a symbolic link."""
        jfs = JournaledFileSystem()
        jfs.create_file("/target.txt")
        jfs.symlink("/target.txt", "/shortcut")
        assert jfs.readlink("/shortcut") == "/target.txt"
        assert jfs.journal_status()["committed"] == EXPECTED_COMMITTED_TWO

    def test_journal_grows_with_mutations(self) -> None:
        """Each mutation adds exactly one committed transaction."""
        jfs = JournaledFileSystem()
        assert jfs.journal_status()["total"] == 0
        jfs.create_file("/a")
        assert jfs.journal_status()["total"] == 1
        jfs.create_file("/b")
        assert jfs.journal_status()["total"] == EXPECTED_COMMITTED_TWO

    def test_failed_mutation_leaves_active_transaction(self) -> None:
        """A mutation that fails leaves an uncommitted transaction."""
        jfs = JournaledFileSystem()
        with pytest.raises(FileNotFoundError):
            jfs.create_file("/no/parent/file.txt")
        # The txn was begun but the fs op failed, so commit didn't happen
        status = jfs.journal_status()
        assert status["active"] == 1
        assert status["committed"] == 0

    def test_journal_entry_stores_correct_op(self) -> None:
        """Verify the journal entry's op matches the method called."""
        jfs = JournaledFileSystem()
        jfs.create_dir("/mydir")
        committed = jfs.journal.committed_transactions()
        assert committed[0].entries[0].op is JournalOp.CREATE_DIR


# ---------------------------------------------------------------------------
# TDD Cycle 6: Checkpoint
# ---------------------------------------------------------------------------


class TestCheckpoint:
    """Verify checkpoint saves state and clears journal."""

    def test_checkpoint_clears_committed(self) -> None:
        """checkpoint() removes committed transactions."""
        jfs = JournaledFileSystem()
        jfs.create_file("/a.txt")
        assert jfs.journal_status()["committed"] == 1
        jfs.checkpoint()
        assert jfs.journal_status()["committed"] == 0

    def test_checkpoint_preserves_filesystem(self) -> None:
        """Filesystem state is unchanged after checkpoint."""
        jfs = JournaledFileSystem()
        jfs.create_file("/data.txt")
        jfs.write("/data.txt", b"important")
        jfs.checkpoint()
        assert jfs.read("/data.txt") == b"important"

    def test_checkpoint_stores_snapshot(self) -> None:
        """After checkpoint, internal snapshot is not None."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        assert jfs._checkpoint is not None

    def test_multiple_checkpoints(self) -> None:
        """Each checkpoint replaces the previous snapshot."""
        jfs = JournaledFileSystem()
        jfs.create_file("/v1.txt")
        jfs.checkpoint()
        jfs.create_file("/v2.txt")
        jfs.checkpoint()
        assert jfs.exists("/v1.txt")
        assert jfs.exists("/v2.txt")
        assert jfs.journal_status()["total"] == 0

    def test_checkpoint_then_mutate_leaves_journal(self) -> None:
        """Mutations after checkpoint appear in the journal."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        jfs.create_file("/new.txt")
        assert jfs.journal_status()["committed"] == 1


# ---------------------------------------------------------------------------
# TDD Cycle 7: Simulate Crash + Recover
# ---------------------------------------------------------------------------


class TestSimulateCrash:
    """Verify simulate_crash() rolls back uncommitted work."""

    def test_crash_without_checkpoint_gives_empty_fs(self) -> None:
        """Crash with no checkpoint restores to a fresh filesystem."""
        jfs = JournaledFileSystem()
        jfs.create_file("/lost.txt")
        jfs.simulate_crash()
        assert not jfs.exists("/lost.txt")

    def test_crash_restores_to_checkpoint(self) -> None:
        """Crash restores filesystem to the last checkpoint state."""
        jfs = JournaledFileSystem()
        jfs.create_file("/saved.txt")
        jfs.write("/saved.txt", b"safe")
        jfs.checkpoint()
        jfs.create_file("/unsaved.txt")
        jfs.simulate_crash()
        assert jfs.exists("/saved.txt")
        assert not jfs.exists("/unsaved.txt")
        assert jfs.read("/saved.txt") == b"safe"

    def test_crash_aborts_active_transactions(self) -> None:
        """simulate_crash() aborts all ACTIVE transactions."""
        jfs = JournaledFileSystem()
        jfs.create_file("/ok.txt")
        jfs.checkpoint()
        # Create file that will commit
        jfs.create_file("/post.txt")
        # Force an active transaction by calling begin manually
        jfs.journal.begin()
        jfs.simulate_crash()
        assert jfs.journal_status()["active"] == 0

    def test_crash_keeps_committed_for_recovery(self) -> None:
        """Committed transactions survive crash for later replay."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        jfs.create_file("/committed.txt")
        jfs.simulate_crash()
        # Committed txn should still be in the journal
        assert jfs.journal_status()["committed"] == 1


class TestRecover:
    """Verify recover() replays committed transactions."""

    def test_recover_replays_committed(self) -> None:
        """recover() replays committed transactions onto the checkpoint."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        jfs.create_file("/recovered.txt")
        jfs.write("/recovered.txt", b"back!")
        jfs.simulate_crash()
        # After crash, fs is at checkpoint state (no /recovered.txt)
        assert not jfs.exists("/recovered.txt")
        count = jfs.recover()
        assert count == EXPECTED_REPLAYED_TWO  # create + write
        assert jfs.exists("/recovered.txt")
        assert jfs.read("/recovered.txt") == b"back!"

    def test_recover_returns_count(self) -> None:
        """recover() returns the number of replayed transactions."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        jfs.create_file("/a")
        jfs.create_file("/b")
        jfs.create_file("/c")
        jfs.simulate_crash()
        assert jfs.recover() == EXPECTED_REPLAYED_THREE

    def test_recover_clears_journal(self) -> None:
        """recover() clears the journal after replay."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        jfs.create_file("/temp_file")
        jfs.simulate_crash()
        jfs.recover()
        assert jfs.journal_status()["total"] == 0

    def test_recover_with_no_committed_is_noop(self) -> None:
        """recover() with no committed transactions replays nothing."""
        jfs = JournaledFileSystem()
        jfs.checkpoint()
        jfs.simulate_crash()
        assert jfs.recover() == 0

    def test_end_to_end_crash_recovery(self) -> None:
        """Full scenario: create, checkpoint, mutate, crash, recover."""
        jfs = JournaledFileSystem()

        # Phase 1: Build initial state and checkpoint
        jfs.create_dir("/data")
        jfs.create_file("/data/config.txt")
        jfs.write("/data/config.txt", b"v1")
        jfs.checkpoint()

        # Phase 2: More mutations (these get committed to journal)
        jfs.write("/data/config.txt", b"v2")
        jfs.create_file("/data/log.txt")
        jfs.write("/data/log.txt", b"entry1")

        # Phase 3: Simulate crash
        jfs.simulate_crash()

        # After crash: back at checkpoint state
        assert jfs.read("/data/config.txt") == b"v1"
        assert not jfs.exists("/data/log.txt")

        # Phase 4: Recover
        count = jfs.recover()
        assert count == EXPECTED_REPLAYED_THREE  # write + create + write
        assert jfs.read("/data/config.txt") == b"v2"
        assert jfs.read("/data/log.txt") == b"entry1"

    def test_recover_replays_link_operations(self) -> None:
        """Recovery replays link and symlink operations."""
        jfs = JournaledFileSystem()
        jfs.create_file("/target.txt")
        jfs.write("/target.txt", b"data")
        jfs.checkpoint()

        jfs.link("/target.txt", "/hard.txt")
        jfs.symlink("/target.txt", "/soft.txt")
        jfs.simulate_crash()

        assert not jfs.exists("/hard.txt")
        assert not jfs.exists("/soft.txt")

        jfs.recover()
        assert jfs.read("/hard.txt") == b"data"
        assert jfs.readlink("/soft.txt") == "/target.txt"

    def test_recover_replays_write_at(self) -> None:
        """Recovery replays write_at operations correctly."""
        jfs = JournaledFileSystem()
        jfs.create_file("/f.txt")
        jfs.write("/f.txt", b"ABCD")
        jfs.checkpoint()

        jfs.write_at("/f.txt", offset=1, data=b"XX")
        jfs.simulate_crash()
        jfs.recover()
        assert jfs.read("/f.txt") == b"AXXD"

    def test_recover_replays_delete(self) -> None:
        """Recovery replays delete operations."""
        jfs = JournaledFileSystem()
        jfs.create_file("/temp.txt")
        jfs.checkpoint()

        jfs.delete("/temp.txt")
        jfs.simulate_crash()
        assert jfs.exists("/temp.txt")  # back at checkpoint

        jfs.recover()
        assert not jfs.exists("/temp.txt")  # delete replayed


# ---------------------------------------------------------------------------
# TDD Cycle 8: JournaledFileSystem Serialization
# ---------------------------------------------------------------------------


class TestJournaledFsSerialization:
    """Verify JournaledFileSystem to_dict/from_dict round-trip."""

    def test_round_trip_empty(self) -> None:
        """An empty journaled filesystem survives serialization."""
        jfs = JournaledFileSystem()
        data = jfs.to_dict()
        restored = JournaledFileSystem.from_dict(data)
        assert restored.list_dir("/") == []

    def test_round_trip_with_data(self) -> None:
        """Filesystem contents survive serialization."""
        jfs = JournaledFileSystem()
        jfs.create_file("/test.txt")
        jfs.write("/test.txt", b"content")
        data = jfs.to_dict()
        restored = JournaledFileSystem.from_dict(data)
        assert restored.read("/test.txt") == b"content"

    def test_round_trip_preserves_journal(self) -> None:
        """The journal state survives serialization."""
        jfs = JournaledFileSystem()
        jfs.create_file("/a.txt")
        data = jfs.to_dict()
        restored = JournaledFileSystem.from_dict(data)
        assert restored.journal_status()["committed"] == 1

    def test_round_trip_preserves_checkpoint(self) -> None:
        """The checkpoint snapshot survives serialization."""
        jfs = JournaledFileSystem()
        jfs.create_file("/saved.txt")
        jfs.checkpoint()
        data = jfs.to_dict()
        restored = JournaledFileSystem.from_dict(data)
        assert restored._checkpoint is not None

    def test_to_dict_keys(self) -> None:
        """to_dict() includes fs, journal, and checkpoint."""
        jfs = JournaledFileSystem()
        data = jfs.to_dict()
        assert set(data.keys()) == {"fs", "journal", "checkpoint"}


# ---------------------------------------------------------------------------
# TDD Cycle 9: Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    """Verify dump/load for journaled filesystem."""

    def test_dump_and_load_round_trip(self, tmp_path: Path) -> None:
        """A journaled filesystem survives dump + load."""
        jfs = JournaledFileSystem()
        jfs.create_file("/doc.txt")
        jfs.write("/doc.txt", b"persisted")
        path = tmp_path / "jfs.json"
        dump_journaled_filesystem(jfs, path)
        restored = load_journaled_filesystem(path)
        assert restored.read("/doc.txt") == b"persisted"

    def test_dump_creates_file(self, tmp_path: Path) -> None:
        """dump_journaled_filesystem() creates a JSON file on disk."""
        jfs = JournaledFileSystem()
        path = tmp_path / "out.json"
        dump_journaled_filesystem(jfs, path)
        assert path.exists()

    def test_load_preserves_journal_state(self, tmp_path: Path) -> None:
        """Journal state survives dump + load."""
        jfs = JournaledFileSystem()
        jfs.create_file("/x.txt")
        path = tmp_path / "jfs.json"
        dump_journaled_filesystem(jfs, path)
        restored = load_journaled_filesystem(path)
        assert restored.journal_status()["committed"] == 1

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        """Loading from a nonexistent path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_journaled_filesystem(tmp_path / "nope.json")


# ---------------------------------------------------------------------------
# TDD Cycle 10: Kernel Integration
# ---------------------------------------------------------------------------


class TestKernelJournal:
    """Verify kernel boots with JournaledFileSystem and journal methods."""

    def _booted_kernel(self) -> Kernel:
        """Return a booted kernel."""
        k = Kernel()
        k.boot()
        k._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
        return k

    def test_kernel_filesystem_is_journaled(self) -> None:
        """After boot, the filesystem is a JournaledFileSystem."""
        k = self._booted_kernel()
        assert isinstance(k.filesystem, JournaledFileSystem)

    def test_journal_status(self) -> None:
        """journal_status() returns a dict with transaction counts."""
        k = self._booted_kernel()
        status = k.journal_status()
        assert status["total"] == 0
        assert status["active"] == 0

    def test_journal_checkpoint(self) -> None:
        """journal_checkpoint() takes a checkpoint."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/test.txt")
        k.journal_checkpoint()
        status = k.journal_status()
        assert status["committed"] == 0

    def test_journal_crash_and_recover(self) -> None:
        """journal_crash() + journal_recover() round-trips."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/saved.txt")
        k.journal_checkpoint()
        k.filesystem.create_file("/recovered.txt")
        k.journal_crash()
        assert not k.filesystem.exists("/recovered.txt")
        count = k.journal_recover()
        assert count == 1  # committed txn replayed
        assert k.filesystem.exists("/recovered.txt")

    def test_journal_recover_replays_committed(self) -> None:
        """Committed transactions survive crash and replay."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.journal_checkpoint()
        k.filesystem.create_file("/important.txt")
        k.journal_crash()
        count = k.journal_recover()
        assert count == 1
        assert k.filesystem.exists("/important.txt")

    def test_journal_status_after_operations(self) -> None:
        """Status reflects filesystem mutations."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/a.txt")
        k.filesystem.create_file("/b.txt")
        status = k.journal_status()
        assert status["committed"] == EXPECTED_COMMITTED_TWO


# ---------------------------------------------------------------------------
# TDD Cycle 11: Syscalls
# ---------------------------------------------------------------------------


class TestJournalSyscalls:
    """Verify journal syscall dispatch."""

    def _booted_kernel(self) -> Kernel:
        """Return a booted kernel."""
        k = Kernel()
        k.boot()
        k._execution_mode = ExecutionMode.KERNEL  # tests run as kernel code
        return k

    def test_sys_journal_status(self) -> None:
        """SYS_JOURNAL_STATUS returns status dict."""
        k = self._booted_kernel()
        result: dict[str, int] = k.syscall(SyscallNumber.SYS_JOURNAL_STATUS)
        assert "total" in result
        assert "active" in result

    def test_sys_journal_checkpoint(self) -> None:
        """SYS_JOURNAL_CHECKPOINT takes a checkpoint."""
        k = self._booted_kernel()
        k.syscall(SyscallNumber.SYS_JOURNAL_CHECKPOINT)
        status: dict[str, int] = k.syscall(SyscallNumber.SYS_JOURNAL_STATUS)
        assert status["committed"] == 0

    def test_sys_journal_crash(self) -> None:
        """SYS_JOURNAL_CRASH simulates a crash."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.filesystem.create_file("/temp.txt")
        k.syscall(SyscallNumber.SYS_JOURNAL_CHECKPOINT)
        k.filesystem.create_file("/gone.txt")
        k.syscall(SyscallNumber.SYS_JOURNAL_CRASH)
        assert not k.filesystem.exists("/gone.txt")

    def test_sys_journal_recover(self) -> None:
        """SYS_JOURNAL_RECOVER replays committed transactions."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.syscall(SyscallNumber.SYS_JOURNAL_CHECKPOINT)
        k.filesystem.create_file("/recovered.txt")
        k.syscall(SyscallNumber.SYS_JOURNAL_CRASH)
        result: dict[str, int] = k.syscall(SyscallNumber.SYS_JOURNAL_RECOVER)
        assert result["replayed"] == 1

    def test_sys_journal_recover_clears_journal(self) -> None:
        """After recovery, journal is cleared."""
        k = self._booted_kernel()
        assert k.filesystem is not None
        k.syscall(SyscallNumber.SYS_JOURNAL_CHECKPOINT)
        k.filesystem.create_file("/x.txt")
        k.syscall(SyscallNumber.SYS_JOURNAL_CRASH)
        k.syscall(SyscallNumber.SYS_JOURNAL_RECOVER)
        status: dict[str, int] = k.syscall(SyscallNumber.SYS_JOURNAL_STATUS)
        assert status["total"] == 0

    def test_sys_journal_status_number(self) -> None:
        """Verify syscall numbers are in the 130 range."""
        assert SyscallNumber.SYS_JOURNAL_STATUS == SYS_JOURNAL_STATUS_NUM
        assert SyscallNumber.SYS_JOURNAL_CHECKPOINT == SYS_JOURNAL_CHECKPOINT_NUM
        assert SyscallNumber.SYS_JOURNAL_RECOVER == SYS_JOURNAL_RECOVER_NUM
        assert SyscallNumber.SYS_JOURNAL_CRASH == SYS_JOURNAL_CRASH_NUM


# ---------------------------------------------------------------------------
# TDD Cycle 12: Shell
# ---------------------------------------------------------------------------


class TestShellJournal:
    """Verify shell journal command with subcommands."""

    def _make_shell(self) -> Shell:
        """Return a shell with a booted kernel."""
        k = Kernel()
        k.boot()
        return Shell(kernel=k)

    def test_journal_status_output(self) -> None:
        """'journal status' shows transaction counts."""
        shell = self._make_shell()
        output = shell.execute("journal status")
        assert "Transactions:" in output
        assert "0 total" in output

    def test_journal_checkpoint_output(self) -> None:
        """'journal checkpoint' confirms creation."""
        shell = self._make_shell()
        output = shell.execute("journal checkpoint")
        assert output == "Checkpoint created"

    def test_journal_crash_output(self) -> None:
        """'journal crash' confirms simulation."""
        shell = self._make_shell()
        shell.execute("journal checkpoint")
        output = shell.execute("journal crash")
        assert "Crash simulated" in output

    def test_journal_recover_output(self) -> None:
        """'journal recover' shows replayed count."""
        shell = self._make_shell()
        shell.execute("journal checkpoint")
        shell.execute("touch /post.txt")
        shell.execute("journal crash")
        output = shell.execute("journal recover")
        assert "Recovery complete" in output
        assert "1" in output

    def test_journal_unknown_subcommand(self) -> None:
        """'journal foo' shows usage help."""
        shell = self._make_shell()
        output = shell.execute("journal foo")
        assert "Usage:" in output

    def test_journal_no_subcommand(self) -> None:
        """'journal' with no args shows usage help."""
        shell = self._make_shell()
        output = shell.execute("journal")
        assert "Usage:" in output
