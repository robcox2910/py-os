# TCP: Reliable Delivery

Imagine sending a jigsaw puzzle to a friend through the post. You cannot fit the whole puzzle in one envelope, so you split it into numbered pieces and send each piece in its own envelope. Your friend checks the numbers, puts the pieces in order, and tells you which ones arrived safely. If any go missing, you send them again. That is TCP.

---

## What Is TCP?

**TCP** (Transmission Control Protocol) sits between the application layer (HTTP, DNS) and the network layer (IP). It turns unreliable, unordered network delivery into a reliable, ordered byte stream.

TCP gives you four guarantees:

1. **Reliable delivery** -- lost segments are detected and retransmitted.
2. **Ordered delivery** -- segments arrive in the correct sequence.
3. **Flow control** -- the receiver tells the sender how much room it has.
4. **Congestion control** -- the sender slows down when the network is busy.

Without TCP, applications would have to handle all of this themselves. With TCP, they just send and receive bytes.

## The Three-Way Handshake

Before two computers can exchange data, they need to agree to start a conversation. TCP uses a **three-way handshake**:

```
Client                         Server
  |                              |
  |--- SYN (seq=0) ------------>|   "Hey, want to talk?"
  |                              |
  |<-- SYN+ACK (seq=0, ack=1) --|   "Sure, let's talk!"
  |                              |
  |--- ACK (ack=1) ------------>|   "Great, we're connected!"
  |                              |
```

- **SYN** -- "synchronise" -- the client proposes a starting sequence number.
- **SYN+ACK** -- the server agrees and proposes its own sequence number.
- **ACK** -- the client acknowledges. Both sides are now **ESTABLISHED**.

In PyOS:

```
tcp listen 80
tcp connect 5000 80
```

## Sequence Numbers and Acknowledgements

Every byte of data has a **sequence number**. When the receiver gets data, it sends back an **ACK** with the next sequence number it expects. This is how the sender knows what arrived safely.

```
Sender                           Receiver
  |                                |
  |--- data (seq=1, 5 bytes) ---->|
  |                                |
  |<-- ACK (ack=6) ---------------|   "Got it, send byte 6 next"
  |                                |
```

If the sender does not get an ACK within a timeout, it **retransmits** the data.

## Flow Control: The Sliding Window

The receiver advertises a **receive window** -- the number of segments it can accept right now. The sender must not send more than this window allows.

Think of it like a mailbox with limited space. If the mailbox is full, the postman waits until you empty it before delivering more.

```
Receiver says: "window_size = 8"
→ Sender can have at most 8 segments in flight at once
```

## Congestion Control: Don't Flood the Network

Even if the receiver has room, the network might be busy. TCP uses **congestion control** to avoid overwhelming the network:

### Slow Start

Start slow and ramp up quickly:

1. Begin with a **congestion window** (cwnd) of 1 segment.
2. For each ACK received, increase cwnd by 1.
3. This means cwnd doubles every round trip -- exponential growth!
4. Keep growing until cwnd reaches the **slow-start threshold** (ssthresh).

### Congestion Avoidance (AIMD)

Once cwnd reaches ssthresh, switch to cautious growth:

- **Additive Increase** -- increase cwnd by 1 per round trip (linear growth).
- **Multiplicative Decrease** -- on timeout, set ssthresh = cwnd / 2 and reset cwnd to 1.

This "AIMD" pattern creates a sawtooth shape: cwnd grows slowly, drops sharply on loss, then grows again.

```
cwnd
  ^
  |    /\      /\      /\
  |   /  \    /  \    /  \
  |  /    \  /    \  /    \
  | /      \/      \/      \
  +----------------------------> time
```

In PyOS, you can see the congestion state:

```
tcp info 1

Connection 1:
  State:            ESTABLISHED
  cwnd:             4
  ssthresh:         16
  effective_window: 4
  unacked:          0
```

## The Effective Window

The sender's actual limit is the **effective window**: the smaller of cwnd and the receiver's advertised window.

```
effective_window = min(cwnd, peer_recv_window)
```

This ensures the sender respects both the receiver's capacity and the network's capacity.

## Retransmission

If a segment is not acknowledged within a timeout period, the sender assumes it was lost and retransmits:

1. Start a timer when a segment is sent.
2. If the timer expires before an ACK arrives, retransmit the oldest unacknowledged segment.
3. Apply multiplicative decrease: ssthresh = cwnd / 2, cwnd = 1.

In PyOS, retransmission is driven by `kernel.tick()`. The default timeout is 10 ticks.

## Graceful Close

When both sides are done, they close the connection with a **four-way close**:

```
Client                         Server
  |                              |
  |--- FIN ---------------------->|   "I'm done sending"
  |<-- ACK ----------------------|   "OK, I heard you"
  |                              |
  |<-- FIN ----------------------|   "I'm done too"
  |--- ACK ---------------------->|   "OK, goodbye"
  |                              |
```

After the final ACK, the connection enters **TIME_WAIT** briefly to handle any delayed segments, then closes.

## TCP State Machine

A TCP connection moves through 11 states:

| State | Meaning |
|-------|---------|
| CLOSED | No connection |
| LISTEN | Waiting for incoming SYN |
| SYN_SENT | SYN sent, waiting for SYN+ACK |
| SYN_RECEIVED | SYN received, SYN+ACK sent |
| ESTABLISHED | Connected, data flows |
| FIN_WAIT_1 | FIN sent, waiting for ACK |
| FIN_WAIT_2 | FIN acknowledged, waiting for peer's FIN |
| TIME_WAIT | Both FINs acknowledged, waiting before close |
| CLOSE_WAIT | Peer's FIN received, waiting to close |
| LAST_ACK | FIN sent, waiting for final ACK |
| CLOSING | Both sides sent FIN simultaneously |

## Try It Yourself

Boot PyOS and run the interactive lesson:

```
learn tcp
```

Or experiment manually:

```
tcp listen 80              # Server listens on port 80
tcp connect 5000 80        # Client connects from port 5000
tcp send 2 "Hello!"        # Send data on connection 2
tcp recv 3                 # Receive data on connection 3
tcp info 2                 # See congestion/flow control state
tcp close 2                # Graceful close
tcp list                   # See all connections
```

Or run the built-in demo:

```
tcp demo
```

---

**Previous:** Learn about hardware events in [Interrupts and Timers](interrupts.md).
