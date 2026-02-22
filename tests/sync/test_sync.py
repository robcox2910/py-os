"""Tests for the synchronization module.

Synchronization primitives coordinate access to shared resources among
concurrent threads and processes.  A Mutex provides mutual exclusion
(one holder at a time), a Semaphore limits concurrent access to N,
a Condition Variable lets threads wait until notified, and a
ReadWriteLock allows multiple readers OR one exclusive writer.

Real-world analogies:
    - **Mutex**: A bathroom lock — only one person at a time.
    - **Semaphore**: A parking lot with limited spaces.
    - **Condition Variable**: A waiting room where you sit until your
      name is called.
    - **ReadWriteLock**: A museum exhibit — visitors (readers) can
      look together, but a restorer (writer) needs the room cleared.
"""

import pytest

from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.sync.primitives import Condition, Mutex, ReadWriteLock, Semaphore, SyncManager
from py_os.syscalls import SyscallError, SyscallNumber

# Named constants to satisfy PLR2004
SEMAPHORE_COUNT_3 = 3
SEMAPHORE_COUNT_2 = 2
SEMAPHORE_MAX_5 = 5
TID_1 = 1
TID_2 = 2
TID_3 = 3
TID_4 = 4
NUM_PAGES = 2


# -- Helpers -----------------------------------------------------------------


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create a booted kernel and shell for testing."""
    kernel = Kernel()
    kernel.boot()
    return kernel, Shell(kernel=kernel)


# -- Mutex Tests -------------------------------------------------------------


class TestMutex:
    """Verify basic mutex creation, acquire, release, and owner tracking."""

    def test_create_mutex(self) -> None:
        """Create a mutex with a name."""
        mutex = Mutex(name="lock1")
        assert mutex.name == "lock1"

    def test_new_mutex_is_unlocked(self) -> None:
        """A freshly created mutex should be unlocked."""
        mutex = Mutex(name="lock1")
        assert not mutex.is_locked

    def test_new_mutex_has_no_owner(self) -> None:
        """A freshly created mutex should have no owner."""
        mutex = Mutex(name="lock1")
        assert mutex.owner is None

    def test_acquire_locks_mutex(self) -> None:
        """Acquiring a mutex should lock it."""
        mutex = Mutex(name="lock1")
        result = mutex.acquire(TID_1)
        assert result is True
        assert mutex.is_locked

    def test_acquire_sets_owner(self) -> None:
        """Acquiring a mutex should set the owner to the acquiring TID."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        assert mutex.owner == TID_1

    def test_double_acquire_fails(self) -> None:
        """A second acquire by a different TID should fail (return False)."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        result = mutex.acquire(TID_2)
        assert result is False

    def test_release_unlocks_mutex(self) -> None:
        """Releasing a mutex should unlock it."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        mutex.release(TID_1)
        assert not mutex.is_locked

    def test_release_clears_owner(self) -> None:
        """Releasing a mutex should clear the owner."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        mutex.release(TID_1)
        assert mutex.owner is None

    def test_release_without_acquire_raises(self) -> None:
        """Releasing a mutex that is not held should raise ValueError."""
        mutex = Mutex(name="lock1")
        with pytest.raises(ValueError, match="not locked"):
            mutex.release(TID_1)

    def test_release_by_non_owner_raises(self) -> None:
        """Only the holder can release the mutex."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        with pytest.raises(ValueError, match="not the owner"):
            mutex.release(TID_2)

    def test_repr(self) -> None:
        """Repr should show name and locked state."""
        mutex = Mutex(name="lock1")
        assert "lock1" in repr(mutex)
        assert "unlocked" in repr(mutex)

    def test_repr_locked(self) -> None:
        """Repr of a locked mutex should show locked and owner."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        assert "locked" in repr(mutex)
        assert str(TID_1) in repr(mutex)


class TestMutexContention:
    """Verify mutex wait queue behaviour under contention."""

    def test_acquire_adds_to_wait_queue(self) -> None:
        """A failed acquire should add the TID to the wait queue."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        mutex.acquire(TID_2)  # fails, TID_2 queued
        assert mutex.wait_queue_size == 1

    def test_release_returns_next_waiter(self) -> None:
        """Releasing should return the next TID from the wait queue."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        mutex.acquire(TID_2)
        next_tid = mutex.release(TID_1)
        assert next_tid == TID_2

    def test_release_grants_to_next_waiter(self) -> None:
        """After release, the next waiter should become the owner."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        mutex.acquire(TID_2)
        mutex.release(TID_1)
        assert mutex.owner == TID_2
        assert mutex.is_locked

    def test_fifo_wait_queue_ordering(self) -> None:
        """Wait queue should be FIFO — first waiter gets the lock first."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        mutex.acquire(TID_2)
        mutex.acquire(TID_3)
        # Release TID_1 → TID_2 gets it
        mutex.release(TID_1)
        assert mutex.owner == TID_2
        # Release TID_2 → TID_3 gets it
        mutex.release(TID_2)
        assert mutex.owner == TID_3

    def test_release_with_empty_wait_queue_returns_none(self) -> None:
        """Releasing with no waiters should return None."""
        mutex = Mutex(name="lock1")
        mutex.acquire(TID_1)
        result = mutex.release(TID_1)
        assert result is None


# -- Semaphore Tests ---------------------------------------------------------


class TestSemaphore:
    """Verify basic semaphore creation, acquire, release, and count tracking."""

    def test_create_semaphore(self) -> None:
        """Create a semaphore with an initial count."""
        sem = Semaphore(name="sem1", count=SEMAPHORE_COUNT_3)
        assert sem.name == "sem1"
        assert sem.count == SEMAPHORE_COUNT_3

    def test_acquire_decrements_count(self) -> None:
        """Acquiring a semaphore should decrement the count."""
        sem = Semaphore(name="sem1", count=SEMAPHORE_COUNT_3)
        result = sem.acquire(TID_1)
        assert result is True
        assert sem.count == SEMAPHORE_COUNT_2

    def test_multiple_acquires(self) -> None:
        """Multiple acquires decrement the count each time."""
        sem = Semaphore(name="sem1", count=SEMAPHORE_COUNT_3)
        sem.acquire(TID_1)
        sem.acquire(TID_2)
        sem.acquire(TID_3)
        expected_count = 0
        assert sem.count == expected_count

    def test_zero_count_blocks(self) -> None:
        """Acquiring when count is zero should fail (return False)."""
        sem = Semaphore(name="sem1", count=1)
        sem.acquire(TID_1)
        result = sem.acquire(TID_2)
        assert result is False

    def test_release_increments_count(self) -> None:
        """Releasing a semaphore should increment the count."""
        sem = Semaphore(name="sem1", count=SEMAPHORE_COUNT_3)
        sem.acquire(TID_1)
        sem.release()
        assert sem.count == SEMAPHORE_COUNT_3

    def test_negative_initial_count_rejected(self) -> None:
        """A negative initial count should be rejected."""
        with pytest.raises(ValueError, match="non-negative"):
            Semaphore(name="sem1", count=-1)

    def test_zero_count_adds_to_wait_queue(self) -> None:
        """A blocked acquire should add the TID to the wait queue."""
        sem = Semaphore(name="sem1", count=1)
        sem.acquire(TID_1)
        sem.acquire(TID_2)
        assert sem.wait_queue_size == 1

    def test_release_wakes_waiter(self) -> None:
        """Releasing when waiters exist should wake the first waiter."""
        sem = Semaphore(name="sem1", count=1)
        sem.acquire(TID_1)
        sem.acquire(TID_2)  # blocked
        next_tid = sem.release()
        assert next_tid == TID_2

    def test_repr(self) -> None:
        """Repr should show name and count."""
        sem = Semaphore(name="sem1", count=SEMAPHORE_COUNT_3)
        assert "sem1" in repr(sem)
        assert str(SEMAPHORE_COUNT_3) in repr(sem)


class TestSemaphoreBounded:
    """Verify semaphore max count enforcement."""

    def test_bounded_semaphore_rejects_over_max(self) -> None:
        """Release beyond max_count should raise ValueError."""
        sem = Semaphore(name="bounded", count=SEMAPHORE_COUNT_2, max_count=SEMAPHORE_COUNT_2)
        with pytest.raises(ValueError, match="max count"):
            sem.release()

    def test_bounded_semaphore_allows_release_after_acquire(self) -> None:
        """Release after acquire should succeed for a bounded semaphore."""
        sem = Semaphore(name="bounded", count=SEMAPHORE_COUNT_2, max_count=SEMAPHORE_COUNT_2)
        sem.acquire(TID_1)
        sem.release()
        assert sem.count == SEMAPHORE_COUNT_2

    def test_binary_semaphore_behaves_like_mutex(self) -> None:
        """A binary semaphore (count=1, max=1) should only allow one holder."""
        sem = Semaphore(name="binary", count=1, max_count=1)
        result1 = sem.acquire(TID_1)
        result2 = sem.acquire(TID_2)
        assert result1 is True
        assert result2 is False

    def test_max_count_less_than_count_rejected(self) -> None:
        """Max count less than initial count should raise ValueError."""
        with pytest.raises(ValueError, match="max_count"):
            Semaphore(name="bad", count=SEMAPHORE_COUNT_3, max_count=1)


# -- Condition Variable Tests ------------------------------------------------


class TestCondition:
    """Verify condition variable creation, wait, notify, and notify_all."""

    def test_create_condition(self) -> None:
        """Create a condition variable with an associated mutex."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        assert cond.name == "cv1"
        assert cond.mutex is mutex

    def test_wait_adds_to_queue(self) -> None:
        """Wait should add the TID to the condition's wait queue."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        mutex.acquire(TID_1)
        cond.wait(TID_1)
        assert cond.wait_queue_size == 1

    def test_wait_releases_mutex(self) -> None:
        """Wait should release the associated mutex."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        mutex.acquire(TID_1)
        cond.wait(TID_1)
        assert not mutex.is_locked

    def test_wait_without_holding_mutex_raises(self) -> None:
        """Wait without holding the mutex should raise ValueError."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        with pytest.raises(ValueError, match="must hold the mutex"):
            cond.wait(TID_1)

    def test_wait_by_non_owner_raises(self) -> None:
        """Wait by a thread that does not own the mutex should raise."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        mutex.acquire(TID_1)
        with pytest.raises(ValueError, match="must hold the mutex"):
            cond.wait(TID_2)

    def test_notify_wakes_one(self) -> None:
        """Notify should wake exactly one waiter."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        mutex.acquire(TID_1)
        cond.wait(TID_1)
        mutex.acquire(TID_2)
        cond.wait(TID_2)
        woken = cond.notify()
        assert woken == TID_1

    def test_notify_on_empty_queue_returns_none(self) -> None:
        """Notify with no waiters should return None."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        result = cond.notify()
        assert result is None

    def test_notify_all_wakes_all(self) -> None:
        """Notify_all should wake every waiter."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        mutex.acquire(TID_1)
        cond.wait(TID_1)
        mutex.acquire(TID_2)
        cond.wait(TID_2)
        mutex.acquire(TID_3)
        cond.wait(TID_3)
        woken = cond.notify_all()
        expected_count = 3
        assert len(woken) == expected_count
        assert woken == [TID_1, TID_2, TID_3]

    def test_notify_all_on_empty_returns_empty(self) -> None:
        """Notify_all with no waiters should return an empty list."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        assert cond.notify_all() == []

    def test_repr(self) -> None:
        """Repr should show name and number of waiters."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        assert "cv1" in repr(cond)
        assert "0 waiters" in repr(cond)

    def test_repr_with_waiters(self) -> None:
        """Repr with waiters should show the count."""
        mutex = Mutex(name="cv_lock")
        cond = Condition(name="cv1", mutex=mutex)
        mutex.acquire(TID_1)
        cond.wait(TID_1)
        assert "1 waiter" in repr(cond)


# -- SyncManager Tests -------------------------------------------------------


class TestSyncManager:
    """Verify the sync manager registry for mutexes, semaphores, and conditions."""

    def test_create_mutex(self) -> None:
        """Create a mutex via the manager."""
        mgr = SyncManager()
        mutex = mgr.create_mutex("lock1")
        assert mutex.name == "lock1"

    def test_get_mutex(self) -> None:
        """Retrieve a mutex by name."""
        mgr = SyncManager()
        mgr.create_mutex("lock1")
        mutex = mgr.get_mutex("lock1")
        assert mutex.name == "lock1"

    def test_destroy_mutex(self) -> None:
        """Destroy a mutex and verify it is removed."""
        mgr = SyncManager()
        mgr.create_mutex("lock1")
        mgr.destroy_mutex("lock1")
        with pytest.raises(KeyError, match="lock1"):
            mgr.get_mutex("lock1")

    def test_duplicate_mutex_rejected(self) -> None:
        """Creating a mutex with a duplicate name should raise ValueError."""
        mgr = SyncManager()
        mgr.create_mutex("lock1")
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_mutex("lock1")

    def test_get_nonexistent_mutex_raises(self) -> None:
        """Getting a non-existent mutex should raise KeyError."""
        mgr = SyncManager()
        with pytest.raises(KeyError, match="nope"):
            mgr.get_mutex("nope")

    def test_create_semaphore(self) -> None:
        """Create a semaphore via the manager."""
        mgr = SyncManager()
        sem = mgr.create_semaphore("sem1", count=SEMAPHORE_COUNT_3)
        assert sem.name == "sem1"
        assert sem.count == SEMAPHORE_COUNT_3

    def test_get_semaphore(self) -> None:
        """Retrieve a semaphore by name."""
        mgr = SyncManager()
        mgr.create_semaphore("sem1", count=SEMAPHORE_COUNT_3)
        sem = mgr.get_semaphore("sem1")
        assert sem.name == "sem1"

    def test_destroy_semaphore(self) -> None:
        """Destroy a semaphore and verify it is removed."""
        mgr = SyncManager()
        mgr.create_semaphore("sem1", count=1)
        mgr.destroy_semaphore("sem1")
        with pytest.raises(KeyError, match="sem1"):
            mgr.get_semaphore("sem1")

    def test_duplicate_semaphore_rejected(self) -> None:
        """Creating a semaphore with a duplicate name should raise ValueError."""
        mgr = SyncManager()
        mgr.create_semaphore("sem1", count=1)
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_semaphore("sem1", count=1)

    def test_create_condition(self) -> None:
        """Create a condition variable via the manager."""
        mgr = SyncManager()
        mgr.create_mutex("cv_lock")
        cond = mgr.create_condition("cv1", mutex_name="cv_lock")
        assert cond.name == "cv1"

    def test_destroy_condition(self) -> None:
        """Destroy a condition variable and verify it is removed."""
        mgr = SyncManager()
        mgr.create_mutex("cv_lock")
        mgr.create_condition("cv1", mutex_name="cv_lock")
        mgr.destroy_condition("cv1")
        with pytest.raises(KeyError, match="cv1"):
            mgr.get_condition("cv1")

    def test_create_condition_missing_mutex_raises(self) -> None:
        """Creating a condition for a non-existent mutex should raise KeyError."""
        mgr = SyncManager()
        with pytest.raises(KeyError, match="nope"):
            mgr.create_condition("cv1", mutex_name="nope")

    def test_list_mutexes(self) -> None:
        """List all mutex names."""
        mgr = SyncManager()
        mgr.create_mutex("a")
        mgr.create_mutex("b")
        names = mgr.list_mutexes()
        assert sorted(names) == ["a", "b"]

    def test_list_semaphores(self) -> None:
        """List all semaphore names."""
        mgr = SyncManager()
        mgr.create_semaphore("x", count=1)
        mgr.create_semaphore("y", count=1)
        names = mgr.list_semaphores()
        assert sorted(names) == ["x", "y"]

    def test_list_conditions(self) -> None:
        """List all condition variable names."""
        mgr = SyncManager()
        mgr.create_mutex("m")
        mgr.create_condition("c1", mutex_name="m")
        mgr.create_condition("c2", mutex_name="m")
        names = mgr.list_conditions()
        assert sorted(names) == ["c1", "c2"]


# -- Kernel Integration Tests ------------------------------------------------


class TestKernelSync:
    """Verify the kernel's synchronization manager integration."""

    def test_sync_manager_available_after_boot(self) -> None:
        """The sync manager should be accessible after boot."""
        kernel = _booted_kernel()
        assert kernel.sync_manager is not None

    def test_sync_manager_none_before_boot(self) -> None:
        """The sync manager should be None before boot."""
        kernel = Kernel()
        assert kernel.sync_manager is None

    def test_sync_manager_none_after_shutdown(self) -> None:
        """The sync manager should be None after shutdown."""
        kernel = _booted_kernel()
        kernel.shutdown()
        assert kernel.sync_manager is None

    def test_create_mutex_via_kernel(self) -> None:
        """Create a mutex through the kernel's delegation method."""
        kernel = _booted_kernel()
        mutex = kernel.create_mutex("test_lock")
        assert mutex.name == "test_lock"

    def test_acquire_and_release_mutex_via_kernel(self) -> None:
        """Acquire and release a mutex through the kernel."""
        kernel = _booted_kernel()
        kernel.create_mutex("test_lock")
        acquired = kernel.acquire_mutex("test_lock", tid=TID_1)
        assert acquired is True
        kernel.release_mutex("test_lock", tid=TID_1)

    def test_create_semaphore_via_kernel(self) -> None:
        """Create a semaphore through the kernel's delegation method."""
        kernel = _booted_kernel()
        sem = kernel.create_semaphore("test_sem", count=SEMAPHORE_COUNT_3)
        assert sem.count == SEMAPHORE_COUNT_3


# -- Syscall Tests -----------------------------------------------------------


class TestSyncSyscalls:
    """Verify sync-related system calls through the dispatch table."""

    def test_sys_create_mutex(self) -> None:
        """SYS_CREATE_MUTEX should create a mutex."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="mylock")
        assert "mylock" in result
        assert "created" in result

    def test_sys_acquire_mutex(self) -> None:
        """SYS_ACQUIRE_MUTEX should acquire a mutex."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="mylock")
        result = kernel.syscall(SyscallNumber.SYS_ACQUIRE_MUTEX, name="mylock", tid=TID_1)
        assert "acquired" in result

    def test_sys_release_mutex(self) -> None:
        """SYS_RELEASE_MUTEX should release a mutex."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="mylock")
        kernel.syscall(SyscallNumber.SYS_ACQUIRE_MUTEX, name="mylock", tid=TID_1)
        result = kernel.syscall(SyscallNumber.SYS_RELEASE_MUTEX, name="mylock", tid=TID_1)
        assert "released" in result

    def test_sys_create_semaphore(self) -> None:
        """SYS_CREATE_SEMAPHORE should create a semaphore."""
        kernel = _booted_kernel()
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_SEMAPHORE, name="mysem", count=SEMAPHORE_COUNT_3
        )
        assert "mysem" in result
        assert "created" in result

    def test_sys_acquire_semaphore(self) -> None:
        """SYS_ACQUIRE_SEMAPHORE should acquire a semaphore."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_SEMAPHORE, name="mysem", count=SEMAPHORE_COUNT_3)
        result = kernel.syscall(SyscallNumber.SYS_ACQUIRE_SEMAPHORE, name="mysem", tid=TID_1)
        assert "acquired" in result

    def test_sys_release_semaphore(self) -> None:
        """SYS_RELEASE_SEMAPHORE should release a semaphore."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_SEMAPHORE, name="mysem", count=SEMAPHORE_COUNT_3)
        kernel.syscall(SyscallNumber.SYS_ACQUIRE_SEMAPHORE, name="mysem", tid=TID_1)
        result = kernel.syscall(SyscallNumber.SYS_RELEASE_SEMAPHORE, name="mysem")
        assert "released" in result

    def test_sys_acquire_nonexistent_mutex_raises(self) -> None:
        """Acquiring a non-existent mutex should raise SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="nope"):
            kernel.syscall(SyscallNumber.SYS_ACQUIRE_MUTEX, name="nope", tid=TID_1)

    def test_sys_create_condition(self) -> None:
        """SYS_CREATE_CONDITION should create a condition variable."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="cv_lock")
        result = kernel.syscall(
            SyscallNumber.SYS_CREATE_CONDITION, name="cv1", mutex_name="cv_lock"
        )
        assert "cv1" in result
        assert "created" in result

    def test_sys_condition_notify(self) -> None:
        """SYS_CONDITION_NOTIFY should notify a condition variable."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_MUTEX, name="cv_lock")
        kernel.syscall(SyscallNumber.SYS_CREATE_CONDITION, name="cv1", mutex_name="cv_lock")
        result = kernel.syscall(SyscallNumber.SYS_CONDITION_NOTIFY, name="cv1")
        assert "notified" in result


# -- Shell Tests -------------------------------------------------------------


class TestShellSync:
    """Verify shell commands for mutex and semaphore management."""

    def test_mutex_create(self) -> None:
        """'mutex create <name>' should create a mutex."""
        _kernel, shell = _booted_shell()
        result = shell.execute("mutex create mylock")
        assert "created" in result.lower()

    def test_mutex_list(self) -> None:
        """'mutex list' should show created mutexes."""
        _kernel, shell = _booted_shell()
        shell.execute("mutex create mylock")
        result = shell.execute("mutex list")
        assert "mylock" in result

    def test_semaphore_create(self) -> None:
        """'semaphore create <name> <count>' should create a semaphore."""
        _kernel, shell = _booted_shell()
        result = shell.execute("semaphore create mysem 3")
        assert "created" in result.lower()

    def test_semaphore_list(self) -> None:
        """'semaphore list' should show created semaphores."""
        _kernel, shell = _booted_shell()
        shell.execute("semaphore create mysem 3")
        result = shell.execute("semaphore list")
        assert "mysem" in result

    def test_mutex_missing_subcommand(self) -> None:
        """'mutex' without a subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("mutex")
        assert "usage" in result.lower()

    def test_semaphore_missing_subcommand(self) -> None:
        """'semaphore' without a subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("semaphore")
        assert "usage" in result.lower()


# -- ReadWriteLock Tests (Cycle 1) -------------------------------------------


class TestReadWriteLock:
    """Verify basic RWLock creation, acquire, release, and properties."""

    def test_create_rwlock(self) -> None:
        """Create a reader-writer lock with a name."""
        rwl = ReadWriteLock(name="db_lock")
        assert rwl.name == "db_lock"

    def test_new_rwlock_has_no_readers(self) -> None:
        """A freshly created lock should have zero readers."""
        rwl = ReadWriteLock(name="db_lock")
        assert rwl.reader_count == 0

    def test_new_rwlock_is_not_writing(self) -> None:
        """A freshly created lock should not be in write mode."""
        rwl = ReadWriteLock(name="db_lock")
        assert not rwl.is_writing
        assert rwl.writer_tid is None

    def test_acquire_and_release_read(self) -> None:
        """Acquire read, verify reader count, release back to zero."""
        rwl = ReadWriteLock(name="db_lock")
        acquired = rwl.acquire_read(TID_1)
        assert acquired is True
        assert rwl.reader_count == 1
        woken = rwl.release_read(TID_1)
        assert woken == []
        assert rwl.reader_count == 0

    def test_acquire_and_release_write(self) -> None:
        """Acquire write, verify writer state, release."""
        rwl = ReadWriteLock(name="db_lock")
        acquired = rwl.acquire_write(TID_1)
        assert acquired is True
        assert rwl.is_writing
        assert rwl.writer_tid == TID_1
        woken = rwl.release_write(TID_1)
        assert woken == []
        assert not rwl.is_writing

    def test_release_read_not_held_raises(self) -> None:
        """Releasing a read lock not held should raise ValueError."""
        rwl = ReadWriteLock(name="db_lock")
        with pytest.raises(ValueError, match="not a reader"):
            rwl.release_read(TID_1)

    def test_release_write_not_held_raises(self) -> None:
        """Releasing write when not the writer should raise ValueError."""
        rwl = ReadWriteLock(name="db_lock")
        with pytest.raises(ValueError, match="not the writer"):
            rwl.release_write(TID_1)

    def test_release_write_wrong_tid_raises(self) -> None:
        """Releasing write with the wrong TID should raise ValueError."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_write(TID_1)
        with pytest.raises(ValueError, match="not the writer"):
            rwl.release_write(TID_2)

    def test_repr_idle(self) -> None:
        """Repr of an idle lock should show name and 'idle'."""
        rwl = ReadWriteLock(name="db_lock")
        assert "db_lock" in repr(rwl)
        assert "idle" in repr(rwl)

    def test_repr_readers(self) -> None:
        """Repr with active readers should show the count."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_read(TID_1)
        assert "1 reader" in repr(rwl)

    def test_repr_writing(self) -> None:
        """Repr with an active writer should show 'writing'."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_write(TID_1)
        assert "writing" in repr(rwl)


# -- ReadWriteLock Contention Tests (Cycle 2) --------------------------------


class TestReadWriteLockContention:
    """Verify contention: blocking, queueing, writer-preference, batch wake."""

    def test_multiple_concurrent_readers(self) -> None:
        """Multiple readers can hold the lock simultaneously."""
        rwl = ReadWriteLock(name="db_lock")
        assert rwl.acquire_read(TID_1) is True
        assert rwl.acquire_read(TID_2) is True
        assert rwl.acquire_read(TID_3) is True
        expected_readers = 3
        assert rwl.reader_count == expected_readers

    def test_writer_blocks_new_readers(self) -> None:
        """When a writer holds the lock, new readers must queue."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_write(TID_1)
        assert rwl.acquire_read(TID_2) is False
        assert rwl.wait_queue_size == 1

    def test_reader_blocks_writer(self) -> None:
        """When readers hold the lock, a writer must queue."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_read(TID_1)
        assert rwl.acquire_write(TID_2) is False
        assert rwl.wait_queue_size == 1

    def test_writer_blocks_writer(self) -> None:
        """When a writer holds the lock, another writer must queue."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_write(TID_1)
        assert rwl.acquire_write(TID_2) is False
        assert rwl.wait_queue_size == 1

    def test_writer_preference(self) -> None:
        """New readers queue behind a waiting writer (writer-preference).

        Scenario:
        1. TID_1 holds read
        2. TID_2 requests write → queued
        3. TID_3 requests read → queued behind TID_2 (NOT granted)
        """
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_read(TID_1)
        rwl.acquire_write(TID_2)  # queued
        result = rwl.acquire_read(TID_3)
        assert result is False
        expected_queue_size = 2
        assert rwl.wait_queue_size == expected_queue_size

    def test_batch_reader_wake_after_writer(self) -> None:
        """When a writer releases, consecutive queued readers all wake.

        Scenario:
        1. TID_1 holds write
        2. TID_2 queues read
        3. TID_3 queues read
        4. TID_4 queues write
        5. TID_1 releases → TID_2 and TID_3 both wake (batch),
           TID_4 stays queued.
        """
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_write(TID_1)
        rwl.acquire_read(TID_2)
        rwl.acquire_read(TID_3)
        rwl.acquire_write(TID_4)

        woken = rwl.release_write(TID_1)
        assert woken == [TID_2, TID_3]
        expected_readers = 2
        assert rwl.reader_count == expected_readers
        assert rwl.wait_queue_size == 1  # TID_4 still waiting

    def test_writer_wakes_after_all_readers_release(self) -> None:
        """A queued writer wakes only after ALL readers release."""
        rwl = ReadWriteLock(name="db_lock")
        rwl.acquire_read(TID_1)
        rwl.acquire_read(TID_2)
        rwl.acquire_write(TID_3)  # queued

        woken1 = rwl.release_read(TID_1)
        assert woken1 == []  # TID_2 still reading

        woken2 = rwl.release_read(TID_2)
        assert woken2 == [TID_3]  # now writer can go
        assert rwl.is_writing
        assert rwl.writer_tid == TID_3


# -- SyncManager RWLock Tests (Cycle 3) -------------------------------------


class TestSyncManagerRWLock:
    """Verify SyncManager registry for reader-writer locks."""

    def test_create_rwlock(self) -> None:
        """Create an RWLock via the manager."""
        mgr = SyncManager()
        rwl = mgr.create_rwlock("db_lock")
        assert rwl.name == "db_lock"

    def test_get_rwlock(self) -> None:
        """Retrieve an RWLock by name."""
        mgr = SyncManager()
        mgr.create_rwlock("db_lock")
        rwl = mgr.get_rwlock("db_lock")
        assert rwl.name == "db_lock"

    def test_destroy_rwlock(self) -> None:
        """Destroy an RWLock and verify it is removed."""
        mgr = SyncManager()
        mgr.create_rwlock("db_lock")
        mgr.destroy_rwlock("db_lock")
        with pytest.raises(KeyError, match="db_lock"):
            mgr.get_rwlock("db_lock")

    def test_duplicate_rwlock_rejected(self) -> None:
        """Creating an RWLock with a duplicate name should raise ValueError."""
        mgr = SyncManager()
        mgr.create_rwlock("db_lock")
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_rwlock("db_lock")

    def test_list_rwlocks(self) -> None:
        """List all RWLock names."""
        mgr = SyncManager()
        mgr.create_rwlock("a")
        mgr.create_rwlock("b")
        names = mgr.list_rwlocks()
        assert sorted(names) == ["a", "b"]


# -- RWLock Integration Tests (Cycle 4) -------------------------------------


class TestRWLockIntegration:
    """Verify kernel delegation, syscalls, and shell commands for RWLock."""

    def test_create_rwlock_via_kernel(self) -> None:
        """Create an RWLock through the kernel's delegation method."""
        kernel = _booted_kernel()
        rwl = kernel.create_rwlock("test_rw")
        assert rwl.name == "test_rw"

    def test_acquire_and_release_via_kernel(self) -> None:
        """Acquire and release read/write locks through the kernel."""
        kernel = _booted_kernel()
        kernel.create_rwlock("test_rw")
        assert kernel.acquire_read_lock("test_rw", tid=TID_1) is True
        kernel.release_read_lock("test_rw", tid=TID_1)
        assert kernel.acquire_write_lock("test_rw", tid=TID_2) is True
        kernel.release_write_lock("test_rw", tid=TID_2)

    def test_sys_create_rwlock(self) -> None:
        """SYS_CREATE_RWLOCK should create an RWLock."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name="myrw")
        assert "myrw" in result
        assert "created" in result

    def test_sys_acquire_read_lock(self) -> None:
        """SYS_ACQUIRE_READ_LOCK should acquire read access."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name="myrw")
        result = kernel.syscall(SyscallNumber.SYS_ACQUIRE_READ_LOCK, name="myrw", tid=TID_1)
        assert "acquired" in result

    def test_sys_release_read_lock(self) -> None:
        """SYS_RELEASE_READ_LOCK should release read access."""
        kernel = _booted_kernel()
        kernel.syscall(SyscallNumber.SYS_CREATE_RWLOCK, name="myrw")
        kernel.syscall(SyscallNumber.SYS_ACQUIRE_READ_LOCK, name="myrw", tid=TID_1)
        result = kernel.syscall(SyscallNumber.SYS_RELEASE_READ_LOCK, name="myrw", tid=TID_1)
        assert "released" in result

    def test_shell_rwlock_create(self) -> None:
        """'rwlock create <name>' should create an RWLock."""
        _kernel, shell = _booted_shell()
        result = shell.execute("rwlock create myrw")
        assert "created" in result.lower()

    def test_shell_rwlock_list(self) -> None:
        """'rwlock list' should show created RWLocks."""
        _kernel, shell = _booted_shell()
        shell.execute("rwlock create myrw")
        result = shell.execute("rwlock list")
        assert "myrw" in result

    def test_shell_rwlock_missing_subcommand(self) -> None:
        """'rwlock' without a subcommand should show usage."""
        _kernel, shell = _booted_shell()
        result = shell.execute("rwlock")
        assert "usage" in result.lower()
