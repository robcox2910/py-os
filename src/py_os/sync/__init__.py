"""Synchronization subsystem — mutexes, semaphores, conditions, deadlock.

Re-exports public symbols so callers can write::

    from py_os.sync import Mutex, Semaphore, ResourceManager
"""

from py_os.sync.deadlock import ResourceManager
from py_os.sync.primitives import Condition, Mutex, Semaphore, SyncManager

__all__ = [
    "Condition",
    "Mutex",
    "ResourceManager",
    "Semaphore",
    "SyncManager",
]
