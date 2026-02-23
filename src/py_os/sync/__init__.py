"""Synchronization subsystem — mutexes, semaphores, conditions, rwlocks, deadlock, PI, ordering.

Re-exports public symbols so callers can write::

    from py_os.sync import Mutex, Semaphore, ReadWriteLock, ResourceManager
"""

from py_os.sync.deadlock import ResourceManager
from py_os.sync.inheritance import PriorityInheritanceManager
from py_os.sync.ordering import OrderingMode, OrderingViolation, ResourceOrderingManager
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
    "OrderingMode",
    "OrderingViolation",
    "PriorityInheritanceManager",
    "ReadWriteLock",
    "ResourceManager",
    "ResourceOrderingManager",
    "Semaphore",
    "SyncManager",
]
