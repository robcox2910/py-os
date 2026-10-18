"""Property-based tests -- rules that must hold for *every* input.

An ordinary test checks one example someone thought of: "write ``hello``
into a slab slot, read it back, and it's still ``hello``". A property test
states a rule instead, such as "whatever bytes you write into whichever
slots, each slot reads back exactly its own bytes", and lets Hypothesis
invent hundreds of inputs to try to break it. If one breaks the rule,
Hypothesis *shrinks* it down to the smallest input that still fails, and
shows you that.

Each test below says its rule in plain English in its docstring. The
strategies at the top are recipes for making random inputs; each one is
named for what it makes. Every test here calls the code directly: no
kernel boot, no clock, no waiting.

The step-by-step check of ``MemoryManager`` against a plain dict lives in
``tests/test_model.py``. See ``docs/property-testing.md`` for the walk-through.
"""

from collections import deque
from operator import attrgetter

from hypothesis import given
from hypothesis import strategies as st

from py_os.io.disk import CSCANPolicy, DiskPolicy, FCFSPolicy, SCANPolicy, SSTFPolicy
from py_os.memory.manager import MemoryManager
from py_os.memory.slab import SlabAllocator
from py_os.process.pcb import Process
from py_os.process.scheduler import PriorityPolicy

# -- Named constants (PLR2004) ------------------------------------------------

# One frame holds this many bytes, the same as the kernel's frames.
PAGE_SIZE = 256
KERNEL_PID = 0
# A slab test writes at most this many objects. Enough to fill several
# frames when the objects are big, small enough to stay fast.
MOST_OBJECTS = 20
# Plenty of frames, so a slab test never runs out of memory: in the worst
# case every object is a whole frame.
TOTAL_FRAMES = MOST_OBJECTS
# SCANPolicy and CSCANPolicy default to a disk with cylinders 0 to 199.
HIGHEST_CYLINDER = 199
# Every disk-arm policy, by a name Hypothesis can print when a test fails.
DISK_POLICIES: dict[str, DiskPolicy] = {
    "FCFS": FCFSPolicy(),
    "SSTF": SSTFPolicy(),
    "SCAN up": SCANPolicy(direction="up"),
    "SCAN down": SCANPolicy(direction="down"),
    "C-SCAN up": CSCANPolicy(direction="up"),
    "C-SCAN down": CSCANPolicy(direction="down"),
}
# A ready queue in a test holds at most this many processes.
MOST_PROCESSES = 20

# -- Strategies: recipes for random inputs ------------------------------------


def object_sizes() -> st.SearchStrategy[int]:
    """Make a slab object size: from 1 byte up to a whole frame."""
    # SlabAllocator.create_cache accepts 1 to page_size bytes (see its docstring).
    return st.integers(min_value=1, max_value=PAGE_SIZE)


@st.composite
def objects_of_one_size(draw: st.DrawFn) -> tuple[int, list[bytes]]:
    """Make an object size, plus a list of byte strings that each fit in it."""
    obj_size = draw(object_sizes())
    # Slab.write refuses data longer than the slot, so each object fits.
    one_object = st.binary(max_size=obj_size)
    objects = draw(st.lists(one_object, max_size=MOST_OBJECTS))
    return obj_size, objects


def cylinders() -> st.SearchStrategy[int]:
    """Make a cylinder number somewhere on the disk."""
    return st.integers(min_value=0, max_value=HIGHEST_CYLINDER)


@st.composite
def requests_and_head(draw: st.DrawFn) -> tuple[list[int], int]:
    """Make a list of cylinder requests, and a head position that is often one of them."""
    requests = draw(st.lists(cylinders()))
    # The arm already sitting on a requested cylinder is a classic edge case,
    # but with 200 cylinders a random head only rarely lands on one. So half
    # the time, put the head on a request on purpose.
    if requests and draw(st.booleans()):
        return requests, draw(st.sampled_from(requests))
    return requests, draw(cylinders())


def disk_policy_names() -> st.SearchStrategy[str]:
    """Pick the name of one of the disk-arm policies, sweeping up or down."""
    return st.sampled_from(list(DISK_POLICIES))


def priorities() -> st.SearchStrategy[int]:
    """Make a scheduling priority: any whole number, higher is more important."""
    return st.integers()


# -- Slab write and read: every slot keeps its own bytes ----------------------


@given(size_and_objects=objects_of_one_size())
def test_slab_write_then_read_gives_back_each_objects_bytes(
    size_and_objects: tuple[int, list[bytes]],
) -> None:
    """Write each object into its own new slot; each slot reads back its bytes, padded with zeros."""
    obj_size, objects = size_and_objects
    memory = MemoryManager(total_frames=TOTAL_FRAMES)
    slabs = SlabAllocator(memory=memory, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
    slabs.create_cache("things", obj_size=obj_size)

    handles = [slabs.allocate("things") for _ in objects]
    for handle, data in zip(handles, objects, strict=True):
        slabs.write(*handle, data)

    for handle, data in zip(handles, objects, strict=True):
        read_back = slabs.read(*handle)
        # bytes, not a bytearray view of the slab that a later write could change.
        assert type(read_back) is bytes
        # A fresh slot is all zero bytes, and a write only covers its own length.
        assert read_back == data + bytes(obj_size - len(data))


# -- Slab caches give back every frame they took ------------------------------


@given(obj_size=object_sizes(), how_many=st.integers(min_value=0, max_value=MOST_OBJECTS))
def test_destroying_a_slab_cache_gives_back_every_frame(obj_size: int, how_many: int) -> None:
    """After a cache is destroyed, memory looks exactly as it did before the cache was made."""
    memory = MemoryManager(total_frames=TOTAL_FRAMES)
    slabs = SlabAllocator(memory=memory, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)

    slabs.create_cache("things", obj_size=obj_size)
    for _ in range(how_many):
        slabs.allocate("things")
    slabs.destroy_cache("things")

    assert memory.free_frames == TOTAL_FRAMES
    assert memory.pages_for(KERNEL_PID) == []


# -- Disk scheduling: every request is served exactly once --------------------


@given(policy_name=disk_policy_names(), requests_and_head=requests_and_head())
def test_disk_policies_serve_every_request_exactly_once(
    policy_name: str, requests_and_head: tuple[list[int], int]
) -> None:
    """Whatever the policy and wherever the arm starts, it visits each request once: none lost, none added."""
    requests, head = requests_and_head
    order = DISK_POLICIES[policy_name].schedule(list(requests), head=head)
    assert sorted(order) == sorted(requests)


# -- Priority scheduling: most important first, oldest first on a tie ---------


@given(priority_list=st.lists(priorities(), max_size=MOST_PROCESSES))
def test_priority_policy_picks_most_important_first_and_oldest_on_ties(
    priority_list: list[int],
) -> None:
    """Picking until the queue is empty gives the processes in priority order, oldest first on a tie."""
    processes = [Process(name=f"p{i}", priority=p) for i, p in enumerate(priority_list)]
    ready_queue = deque(processes)
    policy = PriorityPolicy()

    picked: list[Process] = []
    while (process := policy.select(ready_queue)) is not None:
        picked.append(process)

    # Python's sort is "stable": processes with equal priority stay in the
    # order they arrived, even with reverse=True. That's the tie rule we want.
    expected = sorted(processes, key=attrgetter("priority"), reverse=True)
    assert [p.pid for p in picked] == [p.pid for p in expected]
