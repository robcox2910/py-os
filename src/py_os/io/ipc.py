"""Inter-process communication (IPC) mechanisms.

Processes are isolated by design, but they often need to exchange data.
This module provides two fundamental IPC paradigms:

**Pipe** — a one-way byte stream (like a Unix pipe ``|``).
    One process writes bytes in; another reads them out.  FIFO order.
    Once closed, no more writes are accepted, but remaining data can
    still be read (draining).  This is stream-based IPC.

**MessageQueue** — a named mailbox for discrete, typed messages.
    Any process can send; any process can receive.  Messages are kept
    whole (not split into bytes) and delivered FIFO.  This is
    message-based IPC.  The queue is generic over the message type ``T``,
    so you get full type safety: ``MessageQueue[str]`` only accepts and
    returns strings.

Why two mechanisms?
    Pipes are simple and efficient for streaming data (like piping
    command output).  Message queues are better when you need discrete,
    structured messages with many-to-many communication.
"""

from collections import deque


class Pipe:
    """A one-way byte stream between processes.

    Models a Unix pipe: one end writes, the other reads.  Data flows
    FIFO.  Closing the write end signals EOF — remaining data can
    still be drained, but no new data is accepted.
    """

    def __init__(self) -> None:
        """Create an open, empty pipe."""
        self._buffer: deque[bytes] = deque()
        self._closed: bool = False

    def is_empty(self) -> bool:
        """Return True if the pipe has no data to read."""
        return len(self._buffer) == 0

    def is_closed(self) -> bool:
        """Return True if the pipe has been closed for writing."""
        return self._closed

    def write(self, data: bytes) -> None:
        """Write data into the pipe.

        Args:
            data: The bytes to write.

        Raises:
            BrokenPipeError: If the pipe has been closed.

        """
        if self._closed:
            msg = "Cannot write to a closed pipe"
            raise BrokenPipeError(msg)
        self._buffer.append(data)

    def read(self) -> bytes | None:
        """Read the next chunk of data from the pipe.

        Returns:
            The next bytes chunk, or None if the pipe is empty.

        """
        if not self._buffer:
            return None
        return self._buffer.popleft()

    def close(self) -> None:
        """Close the pipe for writing.

        Data already in the buffer can still be read (drained),
        but no new writes are accepted.
        """
        self._closed = True


class MessageQueue[T]:
    """A named, typed message queue for inter-process communication.

    Unlike a pipe (unstructured bytes), a message queue handles
    discrete, typed messages.  The generic parameter ``T`` ensures
    type safety: a ``MessageQueue[str]`` only accepts and returns
    strings.

    The queue is named so that unrelated processes can find it by
    name (like a System V message queue or a POSIX mq).
    """

    def __init__(self, *, name: str) -> None:
        """Create an empty, named message queue.

        Args:
            name: Identifier for this queue.

        """
        self._name: str = name
        self._messages: deque[T] = deque()

    @property
    def name(self) -> str:
        """Return the queue name."""
        return self._name

    @property
    def size(self) -> int:
        """Return the number of messages in the queue."""
        return len(self._messages)

    def is_empty(self) -> bool:
        """Return True if the queue has no messages."""
        return len(self._messages) == 0

    def send(self, message: T) -> None:
        """Send a message to the queue.

        Args:
            message: The message to enqueue.

        """
        self._messages.append(message)

    def receive(self) -> T | None:
        """Receive the next message from the queue.

        Returns:
            The next message, or None if the queue is empty.

        """
        if not self._messages:
            return None
        return self._messages.popleft()
