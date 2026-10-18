"""Model check -- MemoryManager must keep its frames exactly as a plain dict says.

A property test checks one rule for many inputs. A *model check* goes
further: Hypothesis invents a random *story* -- give process 3 two frames,
share a frame with process 1, free process 3, run out of memory -- and plays
it on two things at once:

- the real ``MemoryManager``;
- a **model**: a plain ``dict`` from each PID to the list of frames in its
  page table, which we already trust to be right.

Everything else the manager reports can be worked out from that dict: how
many processes hold each frame (its refcount), and how many frames nobody
holds (the free count). After every step the two must agree. If they ever
disagree, Hypothesis shrinks the story to the shortest list of steps that
still goes wrong.

The model is deliberately *not* a copy of ``MemoryManager``'s code: it has no
free set and no refcount table, it just counts. So when the two disagree,
the manager is the one to suspect.

See ``docs/property-testing.md`` for the walk-through.
"""

import unittest
from collections import Counter
from typing import cast

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    MultipleResults,
    RuleBasedStateMachine,
    invariant,
    multiple,
    rule,
)

from py_os.memory.manager import MemoryManager, OutOfMemoryError

# -- Named constants (PLR2004) ------------------------------------------------

# A small memory, so stories run out of frames and share them often.
TOTAL_FRAMES = 8
# A handful of PIDs, so stories keep coming back to the same processes.
HIGHEST_PID = 4

# -- Strategies: recipes for random inputs ------------------------------------


def pids() -> st.SearchStrategy[int]:
    """Make a process ID from a small handful, so the same process comes up again."""
    return st.integers(min_value=1, max_value=HIGHEST_PID)


def page_counts() -> st.SearchStrategy[int]:
    """Make a number of pages to ask for: none, some, or more than memory holds."""
    # "Number of frames to allocate" (MemoryManager.allocate) is never negative.
    return st.integers(min_value=0, max_value=TOTAL_FRAMES + 1)


def any_frames() -> st.SearchStrategy[int]:
    """Make any frame number in memory, whether or not anyone holds it."""
    return st.integers(min_value=0, max_value=TOTAL_FRAMES - 1)


# -- The machine: one story, played on the manager and on a dict ---------------


# why: 20 steps find the same bugs, 50 (the default) is most of the run time
@settings(stateful_step_count=20)
class MemoryManagerMachine(RuleBasedStateMachine):
    """Play random allocates, shares, unshares and frees on a MemoryManager and a dict."""

    # Frames handed out earlier in the story. A random frame number is often
    # free, so rules also pick from here to share or unshare a frame that
    # really is (or was) in use.
    frames = Bundle("frames")

    def __init__(self) -> None:
        """Start with all frames free and nobody holding anything."""
        super().__init__()
        self.memory = MemoryManager(total_frames=TOTAL_FRAMES)
        self.model: dict[int, list[int]] = {}

    def frames_in_use(self) -> Counter[int]:
        """Count how many page-table entries point at each frame, according to the dict."""
        return Counter(frame for table in self.model.values() for frame in table)

    @rule(target=frames, pid=pids(), num_pages=page_counts())
    def allocate(self, pid: int, num_pages: int) -> MultipleResults[int]:
        """Give a process some new frames, or refuse with OutOfMemoryError if too few are free."""
        free = TOTAL_FRAMES - len(self.frames_in_use())
        if num_pages > free:
            with pytest.raises(OutOfMemoryError):
                self.memory.allocate(pid, num_pages=num_pages)
            return multiple()
        new = self.memory.allocate(pid, num_pages=num_pages)
        assert len(new) == num_pages
        assert len(set(new)) == num_pages
        assert not set(new) & set(self.frames_in_use())
        self.model.setdefault(pid, []).extend(new)
        return multiple(*new)

    @rule(target=frames, pid=pids())
    def allocate_one(self, pid: int) -> MultipleResults[int]:
        """Give a process one new frame, or refuse with OutOfMemoryError if none is free."""
        if len(self.frames_in_use()) == TOTAL_FRAMES:
            with pytest.raises(OutOfMemoryError):
                self.memory.allocate_one(pid)
            return multiple()
        frame = self.memory.allocate_one(pid)
        assert frame not in self.frames_in_use()
        self.model.setdefault(pid, []).append(frame)
        return multiple(frame)

    @rule(pid=pids(), frame=st.one_of(frames, any_frames()))
    def share(self, pid: int, frame: int) -> None:
        """Share a frame with a process (as fork does); a frame nobody holds can't be shared."""
        if frame not in self.frames_in_use():
            with pytest.raises(ValueError, match="not allocated"):
                self.memory.increment_refcount(frame)
            return
        self.memory.increment_refcount(frame)
        self.memory.share_frame(pid=pid, frame=frame)
        self.model.setdefault(pid, []).append(frame)

    @rule(pid=pids(), frame=st.one_of(frames, any_frames()))
    def unshare(self, pid: int, frame: int) -> None:
        """Take one frame away from a process; unsharing a frame it doesn't hold changes nothing."""
        if frame not in self.model.get(pid, []):
            self.memory.unshare_frame(pid=pid, frame=frame)
            return
        self.memory.decrement_refcount(frame)
        self.memory.unshare_frame(pid=pid, frame=frame)
        self.model[pid].remove(frame)

    @rule(pid=pids())
    def free(self, pid: int) -> None:
        """Free everything a process holds (as exit does); freeing an unknown PID changes nothing."""
        self.memory.free(pid)
        self.model.pop(pid, None)

    @invariant()
    def frames_match_the_dict(self) -> None:
        """After every step, page tables, refcounts and the free count all match the dict."""
        in_use = self.frames_in_use()
        for pid in range(HIGHEST_PID + 1):
            assert self.memory.pages_for(pid) == self.model.get(pid, [])
        for frame in range(TOTAL_FRAMES):
            assert self.memory.refcount(frame) == in_use[frame]
        assert self.memory.free_frames == TOTAL_FRAMES - len(in_use)
        assert self.memory.shared_frame_count == sum(1 for n in in_use.values() if n > 1)


# pytest runs this like any other test class: one run plays 100 random stories.
# (Hypothesis doesn't say what type ``TestCase`` is, so ``cast`` tells pyright.)
TestMemoryManagerModel = cast(
    "type[unittest.TestCase]",
    MemoryManagerMachine.TestCase,  # pyright: ignore[reportUnknownMemberType]
)
