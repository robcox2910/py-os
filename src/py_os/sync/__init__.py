"""Synchronization subsystem — mutexes, semaphores, conditions, rwlocks, deadlock.

Re-exports public symbols so callers can write::

    from py_os.sync import Mutex, Semaphore, ReadWriteLock, ResourceManager
"""

from py_os.sync.deadlock import ResourceManager
from py_os.sync.primitives import (
    Condition,
    Mutex,
    ReadWriteLock,
    Semaphore,
    SyncManager,
)

__all__ = [
    "Condition",
    "Mutex",
    "ReadWriteLock",
    "ResourceManager",
    "Semaphore",
    "SyncManager",
]
