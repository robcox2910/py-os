"""Synchronization primitives — mutex, semaphore, condition variable, rwlock.

In a real OS, multiple threads share memory and must coordinate access
to prevent data races.  The four classical primitives are:

    **Mutex** (mutual exclusion lock): Only one thread can hold it at
    a time.  Think of a bathroom lock — you lock the door, do your
    business, then unlock.  If someone else tries the handle while
    you're inside, they wait.

    **Semaphore** (counting semaphore): A generalised lock that allows
    up to *N* concurrent holders.  Think of a parking lot with N
    spaces — each car that enters decrements the available count, each
    car that leaves increments it.  When the lot is full, new arrivals
    wait.

    **Condition variable**: A signalling mechanism that lets threads
    wait until some condition becomes true.  Think of a waiting room —
    you sit down (wait) and the receptionist calls your name (notify)
    when the doctor is ready.

    **Reader-writer lock** (RWLock): Allows multiple concurrent readers
    OR one exclusive writer.  Think of a museum exhibit — any number of
    visitors can look at the painting, but when a restorer needs to work
    on it, they close the room.

All four use a FIFO wait queue so that blocked threads are woken in
the order they arrived — preventing starvation.
"""

from collections import deque


class Mutex:
    """Mutual exclusion lock — only one thread can hold it at a time.

    The mutex tracks its owner (by TID) and maintains a FIFO wait
    queue for threads that attempted to acquire while it was held.

    When the holder releases, the next waiter is automatically granted
    ownership — the ``release`` method returns that waiter's TID so the
    caller (e.g. the scheduler) can wake it.
    """

    def __init__(self, *, name: str) -> None:
        """Create an unlocked mutex with the given name."""
        self._name = name
        self._owner: int | None = None
        self._locked = False
        self._wait_queue: deque[int] = deque()

    @property
    def name(self) -> str:
        """Return the mutex name."""
        return self._name

    @property
    def is_locked(self) -> bool:
        """Return whether the mutex is currently held."""
        return self._locked

    @property
    def owner(self) -> int | None:
        """Return the TID of the current holder, or None."""
        return self._owner

    @property
    def wait_queue_size(self) -> int:
        """Return the number of threads waiting to acquire."""
        return len(self._wait_queue)

    @property
    def waiters(self) -> list[int]:
        """Return TIDs currently waiting to acquire (in FIFO order)."""
        return list(self._wait_queue)

    def acquire(self, tid: int) -> bool:
        """Attempt to acquire the mutex.

        If the mutex is free, lock it and set the owner.  If it is
        already held, add the TID to the wait queue.

        Args:
            tid: Thread ID of the caller.

        Returns:
            True if acquired, False if already held (caller is queued).

        """
        if not self._locked:
            self._locked = True
            self._owner = tid
            return True
        self._wait_queue.append(tid)
        return False

    def release(self, tid: int) -> int | None:
        """Release the mutex.

        If the wait queue is non-empty, grant the lock to the next
        waiter and return its TID.  Otherwise, unlock and return None.

        Args:
            tid: Thread ID of the caller (must be the current owner).

        Returns:
            The TID of the next waiter granted ownership, or None.

        Raises:
            ValueError: If the mutex is not locked or the caller is
                not the owner.

        """
        if not self._locked:
            msg = f"Mutex '{self._name}' is not locked"
            raise ValueError(msg)
        if self._owner != tid:
            msg = f"Thread {tid} is not the owner of mutex '{self._name}'"
            raise ValueError(msg)

        if self._wait_queue:
            next_tid = self._wait_queue.popleft()
            self._owner = next_tid
            return next_tid

        self._locked = False
        self._owner = None
        return None

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        state = f"locked by {self._owner}" if self._locked else "unlocked"
        return f"Mutex('{self._name}', {state})"


class Semaphore:
    """Counting semaphore — limit concurrent access to N.

    The semaphore maintains an integer count and a FIFO wait queue.
    ``acquire`` decrements; ``release`` increments.  When the count
    reaches zero, further acquires queue the caller.  An optional
    ``max_count`` enforces an upper bound (bounded semaphore).
    """

    def __init__(
        self,
        *,
        name: str,
        count: int,
        max_count: int | None = None,
    ) -> None:
        """Create a semaphore with the given initial count.

        Args:
            name: Human-readable name.
            count: Initial (and current) available count.
            max_count: Optional upper bound on the count.

        Raises:
            ValueError: If count is negative or max_count < count.

        """
        if count < 0:
            msg = f"Semaphore count must be non-negative, got {count}"
            raise ValueError(msg)
        if max_count is not None and max_count < count:
            msg = f"max_count ({max_count}) must be >= count ({count})"
            raise ValueError(msg)
        self._name = name
        self._count = count
        self._max_count = max_count
        self._wait_queue: deque[int] = deque()

    @property
    def name(self) -> str:
        """Return the semaphore name."""
        return self._name

    @property
    def count(self) -> int:
        """Return the current available count."""
        return self._count

    @property
    def wait_queue_size(self) -> int:
        """Return the number of threads waiting to acquire."""
        return len(self._wait_queue)

    def acquire(self, tid: int) -> bool:
        """Attempt to acquire (decrement) the semaphore.

        Args:
            tid: Thread ID of the caller.

        Returns:
            True if acquired, False if count was zero (caller is queued).

        """
        if self._count > 0:
            self._count -= 1
            return True
        self._wait_queue.append(tid)
        return False

    def release(self) -> int | None:
        """Release (increment) the semaphore.

        If waiters are queued, wake the first one (count stays the same
        because the woken thread immediately consumes the slot).
        Otherwise increment count.

        Returns:
            The TID of the woken waiter, or None.

        Raises:
            ValueError: If releasing would exceed max_count.

        """
        if self._wait_queue:
            return self._wait_queue.popleft()

        if self._max_count is not None and self._count >= self._max_count:
            msg = f"Semaphore '{self._name}' would exceed max count ({self._max_count})"
            raise ValueError(msg)
        self._count += 1
        return None

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        bound = f"/{self._max_count}" if self._max_count is not None else ""
        return f"Semaphore('{self._name}', count={self._count}{bound})"


class Condition:
    """Condition variable — threads wait until notified.

    A condition variable is always associated with a mutex.  A thread
    that calls ``wait`` must hold the mutex; wait atomically releases
    the mutex and adds the thread to the wait queue.  ``notify`` wakes
    one waiter; ``notify_all`` wakes every waiter.
    """

    def __init__(self, *, name: str, mutex: Mutex) -> None:
        """Create a condition variable associated with the given mutex."""
        self._name = name
        self._mutex = mutex
        self._wait_queue: deque[int] = deque()

    @property
    def name(self) -> str:
        """Return the condition variable name."""
        return self._name

    @property
    def mutex(self) -> Mutex:
        """Return the associated mutex."""
        return self._mutex

    @property
    def wait_queue_size(self) -> int:
        """Return the number of threads waiting."""
        return len(self._wait_queue)

    def wait(self, tid: int) -> None:
        """Release the mutex and wait for a notification.

        The caller must hold the associated mutex.  This method
        atomically releases the mutex and adds the TID to the wait
        queue.

        Args:
            tid: Thread ID of the caller.

        Raises:
            ValueError: If the caller does not hold the mutex.

        """
        if not self._mutex.is_locked or self._mutex.owner != tid:
            msg = f"Thread {tid} must hold the mutex to wait on '{self._name}'"
            raise ValueError(msg)
        self._mutex.release(tid)
        self._wait_queue.append(tid)

    def notify(self) -> int | None:
        """Wake one waiting thread.

        Returns:
            The TID of the woken thread, or None if no one was waiting.

        """
        if self._wait_queue:
            return self._wait_queue.popleft()
        return None

    def notify_all(self) -> list[int]:
        """Wake all waiting threads.

        Returns:
            List of TIDs that were woken (may be empty).

        """
        woken = list(self._wait_queue)
        self._wait_queue.clear()
        return woken

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        n = len(self._wait_queue)
        waiter_word = "waiter" if n == 1 else "waiters"
        return f"Condition('{self._name}', {n} {waiter_word})"


class ReadWriteLock:
    """Reader-writer lock — multiple readers OR one exclusive writer.

    Writer-preference: when a writer is waiting, new readers queue
    behind it rather than jumping ahead.

    Analogy: a museum exhibit.  Any number of visitors (readers) can
    look at the painting at once.  But when a restorer (writer) needs
    to work on it, they close the room — visitors already inside can
    finish, but no new visitors enter until the restorer is done.
    """

    def __init__(self, *, name: str) -> None:
        """Create an unlocked reader-writer lock with the given name."""
        self._name = name
        self._readers: set[int] = set()
        self._writer: int | None = None
        self._wait_queue: deque[tuple[int, str]] = deque()

    @property
    def name(self) -> str:
        """Return the lock name."""
        return self._name

    @property
    def reader_count(self) -> int:
        """Return the number of active readers."""
        return len(self._readers)

    @property
    def is_writing(self) -> bool:
        """Return whether a writer currently holds the lock."""
        return self._writer is not None

    @property
    def writer_tid(self) -> int | None:
        """Return the TID of the active writer, or None."""
        return self._writer

    @property
    def wait_queue_size(self) -> int:
        """Return the number of threads waiting to acquire."""
        return len(self._wait_queue)

    def _has_waiting_writer(self) -> bool:
        """Return True if a writer is waiting in the queue."""
        return any(mode == "write" for _, mode in self._wait_queue)

    def acquire_read(self, tid: int) -> bool:
        """Attempt to acquire read access.

        Succeeds if there is no active writer AND no writer waiting
        in the queue (writer-preference).  Otherwise the caller is
        queued.

        Args:
            tid: Thread ID of the caller.

        Returns:
            True if acquired, False if queued.

        """
        if self._writer is None and not self._has_waiting_writer():
            self._readers.add(tid)
            return True
        self._wait_queue.append((tid, "read"))
        return False

    def acquire_write(self, tid: int) -> bool:
        """Attempt to acquire write access.

        Succeeds only if there are no active readers AND no active
        writer.  Otherwise the caller is queued.

        Args:
            tid: Thread ID of the caller.

        Returns:
            True if acquired, False if queued.

        """
        if self._writer is None and not self._readers:
            self._writer = tid
            return True
        self._wait_queue.append((tid, "write"))
        return False

    def release_read(self, tid: int) -> list[int]:
        """Release read access and potentially wake queued threads.

        Args:
            tid: Thread ID of the caller.

        Returns:
            List of TIDs that were promoted from the wait queue.

        Raises:
            ValueError: If the TID is not an active reader.

        """
        if tid not in self._readers:
            msg = f"Thread {tid} is not a reader of '{self._name}'"
            raise ValueError(msg)
        self._readers.discard(tid)
        if not self._readers:
            return self._wake_next()
        return []

    def release_write(self, tid: int) -> list[int]:
        """Release write access and promote queued threads.

        Args:
            tid: Thread ID of the caller.

        Returns:
            List of TIDs that were promoted from the wait queue.

        Raises:
            ValueError: If the TID is not the active writer.

        """
        if self._writer != tid:
            msg = f"Thread {tid} is not the writer of '{self._name}'"
            raise ValueError(msg)
        self._writer = None
        return self._wake_next()

    def _wake_next(self) -> list[int]:
        """Promote the next waiter(s) from the queue.

        - If the front is a writer → promote it alone.
        - If the front is a reader → promote it AND all consecutive
          readers behind it (batch wake).
        - If the queue is empty → return [].
        """
        if not self._wait_queue:
            return []

        tid, mode = self._wait_queue[0]
        if mode == "write":
            self._wait_queue.popleft()
            self._writer = tid
            return [tid]

        # Batch-wake consecutive readers from the front
        woken: list[int] = []
        while self._wait_queue and self._wait_queue[0][1] == "read":
            reader_tid, _ = self._wait_queue.popleft()
            self._readers.add(reader_tid)
            woken.append(reader_tid)
        return woken

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        if self._writer is not None:
            state = f"writing by {self._writer}"
        elif self._readers:
            n = len(self._readers)
            word = "reader" if n == 1 else "readers"
            state = f"{n} {word}"
        else:
            state = "idle"
        return f"ReadWriteLock('{self._name}', {state})"


class SyncManager:
    """Registry for all synchronization primitives.

    The sync manager owns mutexes, semaphores, condition variables, and
    reader-writer locks by name.  It enforces uniqueness — you cannot
    create two primitives of the same type with the same name.

    The kernel creates a SyncManager during boot and tears it down on
    shutdown, just like every other subsystem.
    """

    def __init__(self) -> None:
        """Create an empty sync manager."""
        self._mutexes: dict[str, Mutex] = {}
        self._semaphores: dict[str, Semaphore] = {}
        self._conditions: dict[str, Condition] = {}
        self._rwlocks: dict[str, ReadWriteLock] = {}

    # -- Mutex operations ----------------------------------------------------

    def create_mutex(self, name: str) -> Mutex:
        """Create and register a new mutex.

        Args:
            name: Unique name for the mutex.

        Returns:
            The newly created Mutex.

        Raises:
            ValueError: If a mutex with the same name already exists.

        """
        if name in self._mutexes:
            msg = f"Mutex '{name}' already exists"
            raise ValueError(msg)
        mutex = Mutex(name=name)
        self._mutexes[name] = mutex
        return mutex

    def get_mutex(self, name: str) -> Mutex:
        """Return a mutex by name.

        Raises:
            KeyError: If no mutex with the given name exists.

        """
        if name not in self._mutexes:
            msg = f"Mutex '{name}' not found"
            raise KeyError(msg)
        return self._mutexes[name]

    def destroy_mutex(self, name: str) -> None:
        """Remove a mutex from the registry.

        Raises:
            KeyError: If no mutex with the given name exists.

        """
        if name not in self._mutexes:
            msg = f"Mutex '{name}' not found"
            raise KeyError(msg)
        del self._mutexes[name]

    def list_mutexes(self) -> list[str]:
        """Return names of all registered mutexes."""
        return list(self._mutexes)

    # -- Semaphore operations ------------------------------------------------

    def create_semaphore(
        self,
        name: str,
        *,
        count: int,
        max_count: int | None = None,
    ) -> Semaphore:
        """Create and register a new semaphore.

        Args:
            name: Unique name for the semaphore.
            count: Initial available count.
            max_count: Optional upper bound on the count.

        Returns:
            The newly created Semaphore.

        Raises:
            ValueError: If a semaphore with the same name already exists.

        """
        if name in self._semaphores:
            msg = f"Semaphore '{name}' already exists"
            raise ValueError(msg)
        sem = Semaphore(name=name, count=count, max_count=max_count)
        self._semaphores[name] = sem
        return sem

    def get_semaphore(self, name: str) -> Semaphore:
        """Return a semaphore by name.

        Raises:
            KeyError: If no semaphore with the given name exists.

        """
        if name not in self._semaphores:
            msg = f"Semaphore '{name}' not found"
            raise KeyError(msg)
        return self._semaphores[name]

    def destroy_semaphore(self, name: str) -> None:
        """Remove a semaphore from the registry.

        Raises:
            KeyError: If no semaphore with the given name exists.

        """
        if name not in self._semaphores:
            msg = f"Semaphore '{name}' not found"
            raise KeyError(msg)
        del self._semaphores[name]

    def list_semaphores(self) -> list[str]:
        """Return names of all registered semaphores."""
        return list(self._semaphores)

    # -- Condition operations ------------------------------------------------

    def create_condition(self, name: str, *, mutex_name: str) -> Condition:
        """Create and register a new condition variable.

        Args:
            name: Unique name for the condition.
            mutex_name: Name of the mutex to associate with.

        Returns:
            The newly created Condition.

        Raises:
            ValueError: If a condition with the same name already exists.
            KeyError: If the specified mutex does not exist.

        """
        if name in self._conditions:
            msg = f"Condition '{name}' already exists"
            raise ValueError(msg)
        mutex = self.get_mutex(mutex_name)
        cond = Condition(name=name, mutex=mutex)
        self._conditions[name] = cond
        return cond

    def get_condition(self, name: str) -> Condition:
        """Return a condition variable by name.

        Raises:
            KeyError: If no condition with the given name exists.

        """
        if name not in self._conditions:
            msg = f"Condition '{name}' not found"
            raise KeyError(msg)
        return self._conditions[name]

    def destroy_condition(self, name: str) -> None:
        """Remove a condition variable from the registry.

        Raises:
            KeyError: If no condition with the given name exists.

        """
        if name not in self._conditions:
            msg = f"Condition '{name}' not found"
            raise KeyError(msg)
        del self._conditions[name]

    def list_conditions(self) -> list[str]:
        """Return names of all registered condition variables."""
        return list(self._conditions)

    # -- ReadWriteLock operations --------------------------------------------

    def create_rwlock(self, name: str) -> ReadWriteLock:
        """Create and register a new reader-writer lock.

        Args:
            name: Unique name for the lock.

        Returns:
            The newly created ReadWriteLock.

        Raises:
            ValueError: If an RWLock with the same name already exists.

        """
        if name in self._rwlocks:
            msg = f"ReadWriteLock '{name}' already exists"
            raise ValueError(msg)
        rwl = ReadWriteLock(name=name)
        self._rwlocks[name] = rwl
        return rwl

    def get_rwlock(self, name: str) -> ReadWriteLock:
        """Return a reader-writer lock by name.

        Raises:
            KeyError: If no RWLock with the given name exists.

        """
        if name not in self._rwlocks:
            msg = f"ReadWriteLock '{name}' not found"
            raise KeyError(msg)
        return self._rwlocks[name]

    def destroy_rwlock(self, name: str) -> None:
        """Remove a reader-writer lock from the registry.

        Raises:
            KeyError: If no RWLock with the given name exists.

        """
        if name not in self._rwlocks:
            msg = f"ReadWriteLock '{name}' not found"
            raise KeyError(msg)
        del self._rwlocks[name]

    def list_rwlocks(self) -> list[str]:
        """Return names of all registered reader-writer locks."""
        return list(self._rwlocks)
