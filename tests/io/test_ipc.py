"""Tests for inter-process communication (IPC) module.

IPC provides mechanisms for processes to exchange data:
- Pipes: one-way byte streams between a writer and a reader.
- Message queues: named mailboxes for discrete message passing.
"""

import pytest

from py_os.io.ipc import MessageQueue, Pipe


class TestPipeCreation:
    """Verify pipe initialisation."""

    def test_new_pipe_is_empty(self) -> None:
        """A new pipe should have no data to read."""
        pipe = Pipe()
        assert pipe.is_empty()

    def test_new_pipe_is_not_closed(self) -> None:
        """A new pipe should be open for writing."""
        pipe = Pipe()
        assert not pipe.is_closed()


class TestPipeWriteAndRead:
    """Verify writing to and reading from pipes."""

    def test_write_then_read(self) -> None:
        """Data written to a pipe should be readable."""
        pipe = Pipe()
        pipe.write(b"hello")
        assert pipe.read() == b"hello"

    def test_pipe_is_fifo(self) -> None:
        """Multiple writes should be read back in order."""
        pipe = Pipe()
        pipe.write(b"first")
        pipe.write(b"second")
        assert pipe.read() == b"first"
        assert pipe.read() == b"second"

    def test_read_empty_pipe_returns_none(self) -> None:
        """Reading an empty, open pipe returns None (non-blocking)."""
        pipe = Pipe()
        assert pipe.read() is None

    def test_pipe_not_empty_after_write(self) -> None:
        """A pipe with data should not report as empty."""
        pipe = Pipe()
        pipe.write(b"data")
        assert not pipe.is_empty()

    def test_pipe_empty_after_all_reads(self) -> None:
        """A pipe should be empty once all data has been read."""
        pipe = Pipe()
        pipe.write(b"data")
        pipe.read()
        assert pipe.is_empty()


class TestPipeClose:
    """Verify pipe closing behaviour."""

    def test_close_marks_pipe_closed(self) -> None:
        """After closing, the pipe should report as closed."""
        pipe = Pipe()
        pipe.close()
        assert pipe.is_closed()

    def test_write_to_closed_pipe_raises(self) -> None:
        """Writing to a closed pipe should raise."""
        pipe = Pipe()
        pipe.close()
        with pytest.raises(BrokenPipeError, match="closed"):
            pipe.write(b"data")

    def test_read_remaining_data_after_close(self) -> None:
        """Data written before close should still be readable."""
        pipe = Pipe()
        pipe.write(b"last_message")
        pipe.close()
        assert pipe.read() == b"last_message"

    def test_read_closed_empty_pipe_returns_none(self) -> None:
        """Reading a closed, empty pipe returns None (EOF)."""
        pipe = Pipe()
        pipe.close()
        assert pipe.read() is None


class TestMessageQueueCreation:
    """Verify message queue initialisation."""

    def test_new_queue_is_empty(self) -> None:
        """A new message queue should have no messages."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        assert queue.is_empty()

    def test_queue_stores_name(self) -> None:
        """The queue name should be accessible."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        assert queue.name == "events"

    def test_queue_size_starts_at_zero(self) -> None:
        """A new queue should have size zero."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        expected_size = 0
        assert queue.size == expected_size


class TestMessageQueueSendAndReceive:
    """Verify sending and receiving messages."""

    def test_send_then_receive(self) -> None:
        """A sent message should be receivable."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        queue.send("hello")
        assert queue.receive() == "hello"

    def test_queue_is_fifo(self) -> None:
        """Messages should be received in the order sent."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        queue.send("first")
        queue.send("second")
        assert queue.receive() == "first"
        assert queue.receive() == "second"

    def test_receive_empty_queue_returns_none(self) -> None:
        """Receiving from an empty queue returns None."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        assert queue.receive() is None

    def test_size_increases_on_send(self) -> None:
        """Each send should increase the queue size."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        queue.send("a")
        queue.send("b")
        expected_size = 2
        assert queue.size == expected_size

    def test_size_decreases_on_receive(self) -> None:
        """Each receive should decrease the queue size."""
        queue: MessageQueue[str] = MessageQueue(name="events")
        queue.send("a")
        queue.send("b")
        queue.receive()
        expected_size = 1
        assert queue.size == expected_size

    def test_queue_handles_typed_messages(self) -> None:
        """Queues should work with any message type."""
        queue: MessageQueue[dict[str, int]] = MessageQueue(name="metrics")
        msg = {"cpu": 42, "mem": 80}
        queue.send(msg)
        assert queue.receive() == msg
