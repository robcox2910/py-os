# Interrupts and Timers

Imagine you are reading a book. Suddenly the doorbell rings. You stop reading, put a bookmark in, answer the door, and then come back and pick up where you left off. That is exactly how a **hardware interrupt** works.

---

## What Is an Interrupt?

An **interrupt** is a signal from a piece of hardware saying "pay attention to me!" When the CPU receives an interrupt, it pauses whatever it was doing, handles the event, and then goes back to its previous work.

Without interrupts, the CPU would have to keep checking every device over and over: "Keyboard, did you get a key press? Disk, are you done reading? Timer, is it time yet?" This wasteful checking is called **polling**, and it is like constantly peeking out the window to see if anyone is at the door.

With interrupts, the devices ring the doorbell *only when something actually happens*. The CPU can focus on useful work the rest of the time.

## The Interrupt Controller

In a real computer, a chip called the **interrupt controller** sits between the devices and the CPU. It has a list of **interrupt vectors** -- numbered slots, one for each kind of event.

| Vector | Device | Priority |
|--------|--------|----------|
| 0 | Timer | High |
| 16 | I/O completion | Normal |

When a device needs attention, it sends a signal to the controller. The controller adds the request to a queue. When the CPU is ready, it asks the controller "what needs handling?" and the controller serves requests **in priority order** -- urgent ones first.

In PyOS, the `InterruptController` class does exactly this:

```
interrupt list

VEC  TYPE      PRI  MASKED  PENDING  HANDLER
  0  timer       3      no        0  yes
 16  io          2      no        0  yes
```

## Interrupt Masking

Sometimes the OS needs to do something without being interrupted -- like updating a shared data structure. It can **mask** (silence) certain vectors temporarily. Masked interrupts still get queued, but they are not delivered until the vector is **unmasked**.

Think of it like putting your phone on silent. Calls still come in (you see them later), but your phone does not ring while you are concentrating.

```
interrupt mask 0        # Silence the timer
tick 5                  # Ticks happen, but timer interrupts queue silently
interrupt unmask 0      # Resume -- queued interrupts are delivered
```

## The Timer

The **timer** is a special device that ticks at a regular rate. Every N ticks, it fires an interrupt. The OS uses this for three things:

1. **Preemption** -- giving each process a fair time slice, then switching to the next one.
2. **Timekeeping** -- tracking how long things take.
3. **Timeouts** -- knowing when to retry a network request.

In PyOS, the timer is a `TimerDevice` that plugs into the interrupt controller. You can check its status and change how often it fires:

```
timer info

Timer device:
  Interval:     5 ticks
  Current tick: 0
  Total ticks:  0
  Total fires:  0

timer set 3             # Fire every 3 ticks instead of 5
```

## Ticking the System Clock

In a real computer, the timer ticks automatically based on a crystal oscillator. In PyOS, we advance time manually with the `tick` command:

```
tick 10

Ticked 10 time(s)
  Current tick: 10
  Interrupts serviced: 2
```

Each tick:

1. Advances the timer counter by one.
2. If the counter reaches the interval, the timer **fires** -- it sends an interrupt to the controller.
3. The controller delivers all pending interrupts to their handlers.
4. The timer handler checks if the current process has used up its time slice. If so, it **preempts** the process (moves it to the back of the ready queue) and lets the next process run.

## Timer-Driven Preemption

Without a timer, a process could hog the CPU forever. The timer makes **preemptive scheduling** possible:

1. The scheduler gives a process a **quantum** (a fixed number of ticks to run).
2. The timer counts ticks.
3. When ticks reach the quantum, the timer fires and the kernel switches to the next process.

This is how Round Robin, MLFQ, and CFS schedulers ensure fairness -- no single process can monopolise the CPU.

## How Interrupts Fit in the Big Picture

```
┌─────────────────────────────────────────────────┐
│                    Kernel                        │
│                                                  │
│   Timer  ──fire──▶  Interrupt   ──dispatch──▶   │
│  Device             Controller      Handler      │
│                                                  │
│   Disk   ──done──▶  (queue by  ──dispatch──▶   │
│   NIC                priority)      Handler      │
│                                                  │
└─────────────────────────────────────────────────┘
```

Devices raise interrupts. The controller queues them by priority. Handlers process them. The kernel keeps running.

## Try It Yourself

Boot PyOS and run the interactive lesson:

```
learn interrupts
```

Or experiment manually:

```
timer info              # See the timer's state
tick 5                  # Advance 5 ticks (timer fires once at default interval)
interrupt list          # See all registered vectors
interrupt mask 0        # Silence the timer
tick 5                  # Timer queues but doesn't fire
interrupt unmask 0      # Resume delivery
tick 1                  # Queued interrupt is now serviced
```

---

**Next:** Learn about reliable network delivery in [TCP: Reliable Delivery](tcp.md).
