# Property Testing (The Caretaker Who Checks Every Locker)

## The School Caretaker

Remember the school from [Memory](concepts/memory.md)? Lockers in a long
hallway (frames), handed out to students (processes) by the principal (the
OS), and a supply closet split into little compartments (the slab
allocator). Let's give the school a lift too, like the elevator in
[disk scheduling](concepts/devices-and-networking.md): it has to stop at
every floor someone pressed (the disk arm and its cylinders).

How would you check the school works? The usual way: give one student two
lockers, see two lockers with their name on, and smile. That's an
**example test**. It's useful, but it only tells you about the one
student you thought of.

Now imagine a caretaker. All night they play out thousands of made-up school
days: a student with no lockers, a student who asks for more lockers than
exist, two students sharing one, the lift called to the floor it's on. For
each one they check a single rule, such as:

> Whatever floors are pressed, the lift stops at every one of them exactly once.

That rule is a **property**. It doesn't say which floor comes first. It says
something that must be true for *every* set of button presses.

When the caretaker finds something that breaks the rule, they don't just
write "something went wrong on Tuesday, with forty students". They play the
day again with less and less -- fewer students, fewer buttons, smaller
numbers -- checking it still goes wrong each time, until it's as simple as it
can be. That boiling-down is called **shrinking**, and it's the best part:
the smallest failing input usually points straight at the bug.

In Python, the caretaker is a library called
[Hypothesis](https://hypothesis.readthedocs.io/). PyOS's property tests live
in `tests/test_properties.py`, next to the ordinary example tests, and the
model check (more on that below) is in `tests/test_model.py`.

## A Property from PyOS

PyOS has four disk scheduling policies: FCFS, SSTF, SCAN and C-SCAN (SCAN
and C-SCAN can each start by sweeping up or down, so that's six to test).
Each one picks a different *order* for the disk arm to visit the cylinders
it's been asked for. But whatever the order, no
request may be lost and none may be made up. Here's the property:

```python
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


@given(policy_name=disk_policy_names(), requests_and_head=requests_and_head())
def test_disk_policies_serve_every_request_exactly_once(
    policy_name: str, requests_and_head: tuple[list[int], int]
) -> None:
    """Whatever the policy and wherever the arm starts, it visits each request once: none lost, none added."""
    requests, head = requests_and_head
    order = DISK_POLICIES[policy_name].schedule(list(requests), head=head)
    assert sorted(order) == sorted(requests)
```

Line by line:

- **`cylinders()`, `requests_and_head()` and `disk_policy_names()`** are
  **strategies**: recipes for making random inputs. Each one is a named
  function with a docstring, so the test reads like a sentence.
  `st.integers(min_value=0, max_value=199)` makes any cylinder on the disk,
  and `st.lists(...)` makes a list of them: empty, one request, the same
  cylinder twice, forty of them.
- **`DISK_POLICIES`** gives each policy a name like `"SCAN up"`. Hypothesis
  picks a *name*, so when a test fails it can print which policy it was.
- **`@st.composite`** lets one strategy use another. `requests_and_head()`
  first draws the list of requests, then picks the head. The comment says
  why: half the time, it puts the head *on* one of the requests. One
  version of this test, with a plain random head, missed the bug in
  "Try It Yourself" below in its normal 100-example run, because a random
  head hardly ever lands on a requested cylinder. **A property only finds
  what its strategy can make.**
- **`@given(...)`** runs the test many times (100 in a normal run), each
  time with a fresh policy, list and head.
- **The docstring** says the rule in plain English. If you can't say the rule
  in one sentence, it probably isn't a good property yet.
- **The `assert`** is the rule itself. Sorting both lists throws away the
  order, so what's left is "the same cylinders, the same number of times".
  `sorted` is Python's own sort, which we already trust, and it's not how
  any of the policies work.

Notice what the test *doesn't* say. It never says "with the head at 53, SSTF
goes to 65 first". It doesn't need to know any answers. It only needs a rule
that's always true. That also means FCFS, which just keeps the arrival order,
passes it, and that's fine: being *clever* is a different rule. **A
do-nothing scheduler that returns an empty list fails as soon as there's one
request.**

PyOS has three more properties:

| Rule | Test |
|---|---|
| Write each object into its own new slot; each slot reads back its bytes, padded with zeros | `test_slab_write_then_read_gives_back_each_objects_bytes` |
| After a cache is destroyed, memory looks exactly as it did before the cache was made | `test_destroying_a_slab_cache_gives_back_every_frame` |
| Picking until the queue is empty gives the processes in priority order, oldest first on a tie | `test_priority_policy_picks_most_important_first_and_oldest_on_ties` |

The first is a **round-trip**: what you write in, you read back out. The last
checks the [priority scheduler](concepts/processes.md) against Python's
`sorted`, with no kernel boot, no clock and no waiting.

## Checking Against a Model

A property checks one action. But the memory manager is something you change
step by step: hand out frames, share one when a process forks, take one back,
free everything when a process exits. Bugs often hide in the *order* of
steps -- freeing a process that never had any memory, or sharing a frame
that's already been given back.

So the caretaker has a second trick. They carry a clipboard, and write down
by hand which student holds which locker. After every single step in the
hallway, they compare the lockers with the clipboard. If the hallway ever
disagrees with the clipboard, something's wrong with the principal.

That clipboard is a **model**: something simple that we already trust. For
`MemoryManager`, the model is a plain Python `dict` from each PID to the list
of frames in its page table. Here's the heart of `tests/test_model.py`:

```python
@settings(stateful_step_count=20)
class MemoryManagerMachine(RuleBasedStateMachine):
    frames = Bundle("frames")

    def __init__(self) -> None:
        """Start with all frames free and nobody holding anything."""
        super().__init__()
        self.memory = MemoryManager(total_frames=TOTAL_FRAMES)
        self.model: dict[int, list[int]] = {}

    def frames_in_use(self) -> Counter[int]:
        return Counter(frame for table in self.model.values() for frame in table)

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

    @invariant()
    def frames_match_the_dict(self) -> None:
        """After every step, page tables, refcounts and the free count all match the dict."""
        in_use = self.frames_in_use()
        for pid in range(HIGHEST_PID + 1):
            assert self.memory.pages_for(pid) == self.model.get(pid, [])
        for frame in range(TOTAL_FRAMES):
            assert self.memory.refcount(frame) == in_use[frame]
        assert self.memory.free_frames == TOTAL_FRAMES - len(in_use)


TestMemoryManagerModel = cast(
    "type[unittest.TestCase]",
    MemoryManagerMachine.TestCase,  # pyright: ignore[reportUnknownMemberType]
)
```

Piece by piece:

- **`RuleBasedStateMachine`** is Hypothesis's tool for testing things that
  change step by step. Hypothesis makes up a random **story** of steps and
  plays it.
- **`self.memory` and `self.model`** are the hallway and the clipboard. Every
  story starts with all 8 frames free and an empty dict.
- **`frames_in_use()`** works out everything else from the clipboard. If
  process 1 and process 2 both list frame 3, frame 3's refcount must be 2. A
  frame nobody lists must be free.
- **Each `@rule`** is one kind of step. It does the same thing to the
  manager and to the dict. `allocate_one` also checks the manager's *answer*:
  the frame it hands out must be one nobody holds. And when memory is full,
  `pytest.raises` checks that the manager refuses with `OutOfMemoryError`.
  The real file has rules to allocate several frames at once, share a frame
  (as `fork` does), unshare one, and free a whole process.
- **`frames = Bundle("frames")`** is a bag of frame numbers handed out
  earlier in the story. `allocate_one` puts its frame in the bag
  (`target=frames`, and `multiple(frame)` means "add this one";
  `multiple()` means "add nothing"). The share and unshare rules pick either
  a frame from the bag or any frame at all, so they try frames that are in
  use *and* frames that aren't.
- **The `@invariant()`** runs after every single step and compares
  everything: every process's page table, every frame's refcount, and the
  free count. (The real one also checks `shared_frame_count`.)
- **`TestMemoryManagerModel = ...TestCase`** turns the machine into a test
  that pytest can find and run. One run plays 100 random stories. The
  `@settings(stateful_step_count=20)` above the class keeps each story to
  20 steps: they find the same bugs as Hypothesis's default of 50, in a
  fraction of the time.

The `dict` is a good model because it's obviously right and it's *not*
`MemoryManager`'s code. The real manager keeps a free set and a refcount
table; the clipboard keeps neither, it just counts. If we built the model by
copying the manager, any bug would be in both, and they'd agree perfectly
about the wrong answer.

## Try It Yourself

Let's break the SCAN policy on purpose and watch the caretaker find it.

Open `src/py_os/io/disk.py`, find `SCANPolicy.schedule`, and change the
first line of the "up" sweep, as if you'd typed `>` instead of `>=`:

```python
            up = sorted(r for r in requests if r > head)  # was: r >= head
```

Run the property tests and the model check:

```bash
uv run pytest tests/test_properties.py tests/test_model.py --no-cov
```

Hypothesis reports this (trimmed to the interesting part):

```
policy_name = 'SCAN up', requests_and_head = ([0], 0)

    @given(policy_name=disk_policy_names(), requests_and_head=requests_and_head())
    def test_disk_policies_serve_every_request_exactly_once(
        policy_name: str, requests_and_head: tuple[list[int], int]
    ) -> None:
        """Whatever the policy and wherever the arm starts, it visits each request once: none lost, none added."""
        requests, head = requests_and_head
        order = DISK_POLICIES[policy_name].schedule(list(requests), head=head)
>       assert sorted(order) == sorted(requests)
E       assert [] == [0]
E
E         Right contains one more item: 0
E       Failing test case: test_disk_policies_serve_every_request_exactly_once(
E           policy_name='SCAN up',
E           requests_and_head=([0], 0),
E       )
```

Look at how small that is. Hypothesis tried long lists of requests on all six
policies, then shrank the failure all the way down to **one request, on the
cylinder the arm is already sitting on**. The lift is on floor 0, someone on
floor 0 presses the button, and the lift never opens its doors. The `up`
sweep now takes only requests *above* the head, the `down` sweep only those
*below* it, and a request *at* the head falls in the gap.

Only `test_disk_policies_serve_every_request_exactly_once` fails. The other
properties and the model check stay green: they never touch the disk.
**The example tests all still pass. Only the property notices.** Every
example in `tests/io/test_disk_scheduling.py` uses a head that isn't one of
the requests, like the textbook's head at 53.

Put the line back to `r >= head` and run the tests again. They pass.

!!! tip "Older Hypothesis versions"
    Older versions of Hypothesis print `Falsifying example:` instead of
    `Failing test case:`. It means the same thing.

## A Bug We Found

When we first ran `test_destroying_a_slab_cache_gives_back_every_frame`, it
failed on PyOS's real code -- no deliberate bug needed:

```
E       assert [0] == []
E
E         Left contains one more item: 0
E       Failing test case: test_destroying_a_slab_cache_gives_back_every_frame(
E           obj_size=1,  # or any other generated value
E           how_many=1,
E       )
```

Make a slab cache, allocate **one** object, destroy the cache, and the
kernel's page table still lists frame 0, whatever the object size.

Here's why. A slab cache borrows its frames from the memory manager,
charged to the kernel's PID. `destroy_cache` gave each one back by dropping
its refcount, which put the frame back on the free list. But it never took
the frame out of the kernel's page table. So frame 0 was free *and* claimed
by the kernel at the same time: a locker that's empty on the principal's
list but still has the kernel's name on the door. If the kernel's memory
were ever freed, it would "free" frame 0 again, even if a process had been
given it in the meantime.

The example test did check that frames came back:
`mm.free_frames > free_before`. And they did! The free count was right. What
was wrong was a *different* part of the picture, which no example asked
about. The property's rule was "memory looks exactly as it did before", so
it checked both.

The fix was one line, the same pair of calls that shared memory already
uses when it gives frames back:

```python
            self._memory.decrement_refcount(frame)
            self._memory.unshare_frame(pid=self._kernel_pid, frame=frame)  # was: missing
```

The shrunk input also became an ordinary example test in
`tests/memory/test_slab.py`, so this bug can never sneak back in, even if
someone deletes the property:

```python
    def test_destroy_cache_removes_frames_from_kernel_page_table(self) -> None:
        mm = MemoryManager(total_frames=TOTAL_FRAMES)
        alloc = SlabAllocator(memory=mm, page_size=PAGE_SIZE, kernel_pid=KERNEL_PID)
        alloc.create_cache("tmp", obj_size=1)
        alloc.allocate("tmp")
        alloc.destroy_cache("tmp")
        assert mm.pages_for(KERNEL_PID) == []
        mm.free(KERNEL_PID)
        assert mm.free_frames == TOTAL_FRAMES
```

Hunting for more bugs like it turned up a second one with the same missing
`unshare_frame`, in copy-on-write after `fork`. That one is fixed now too.

## Run It Yourself

Run just the property tests and the model check (100 examples each, the same
every time):

```bash
uv run pytest tests/test_properties.py tests/test_model.py --no-cov
```

The `--no-cov` turns off the coverage check, which expects the *whole* test
suite to run and would fail on two files.

Run them the long way (2,000 random examples each, different every run) to
hunt for rarer bugs. It takes about 40 seconds:

```bash
uv run pytest tests/test_properties.py tests/test_model.py --no-cov --hypothesis-profile=thorough
```

The normal run uses a fixed seed, so it tries the same inputs every time and a
passing build means the same thing on every computer. The thorough run is
random, so each time you run it the caretaker plays a brand-new set of school
days. Both settings live in `conftest.py` at the top of the project.

## Your Turn

Try writing your own property. SSTF ("shortest seek time first") always goes
to the nearest request next. So: whatever the requests and wherever the head
starts, SSTF's *first* stop is as close to the head as any request. What's
the strategy? What's the `assert`? (Careful: an empty list has no first
stop.) Then break `SSTFPolicy` on purpose and see what Hypothesis shrinks it
to.
