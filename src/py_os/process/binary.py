r"""Binary loader — parse and execute PyBin programs.

A real OS stores programs as **binary files** — sequences of bytes that
the CPU can decode and execute.  Formats like ELF (Linux) and PE (Windows)
define headers, sections, and instruction encodings so the OS knows how
to load a program into memory and run it.

Our PyBin format is a simplified version of this idea:

- A **magic number** identifies the file as a valid PyBin program
  (just like ``\x7fELF`` marks a Linux binary).
- A **header** tells the loader the program's name and how many
  instructions it contains.
- A sequence of **instructions** (bytecodes) that the loader can
  interpret and execute.

Think of it like recipe cards vs knowing recipes by heart:

- A **built-in program** (like ``hello``) is a recipe you've memorised.
- A **binary file** is a recipe written on a card — you have to read
  the card, understand the steps, and then follow them.

The loader is the cook: it reads the card (parses the binary), verifies
it looks right (checks the magic number), and follows the steps
(executes the instructions).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class BinaryLoaderError(Exception):
    """Raise when binary loading or parsing fails."""


PYBIN_MAGIC = b"PYBN"
PYBIN_VERSION = 1

# Type tags for serialized arguments
_ARG_TYPE_INT = 0
_ARG_TYPE_STRING = 1


class Opcode(IntEnum):
    """Bytecode instruction opcodes for PyBin programs.

    Each opcode tells the interpreter what to do with the arguments
    that follow it, just like assembly instructions on a real CPU.
    """

    PRINT = 1
    SET = 2
    ADD = 3
    SUB = 4
    LOAD = 5
    CONCAT = 6
    LOOP = 7
    HALT = 8


@dataclass(frozen=True)
class Instruction:
    """A single bytecode instruction — an opcode with its arguments."""

    opcode: Opcode
    args: tuple[str | int, ...]


@dataclass(frozen=True)
class PyBinHeader:
    """Header metadata from a parsed PyBin binary."""

    magic: bytes
    version: int
    name: str
    num_instructions: int


class BinaryBuilder:
    """Fluent API to create PyBin programs.

    Chain method calls to build a program, then call ``.build()``
    to serialize it into the binary format::

        data = BinaryBuilder("hello").print("Hello from PyBin!").halt().build()
    """

    def __init__(self, name: str = "program") -> None:
        """Create a builder for a named program."""
        self._name = name
        self._instructions: list[Instruction] = []

    def print(self, message: str) -> BinaryBuilder:
        """Add a PRINT instruction."""
        self._instructions.append(Instruction(Opcode.PRINT, (message,)))
        return self

    def set(self, var: str, value: int) -> BinaryBuilder:
        """Add a SET instruction (set variable to integer)."""
        self._instructions.append(Instruction(Opcode.SET, (var, value)))
        return self

    def add(self, dest: str, a: str, b: str) -> BinaryBuilder:
        """Add an ADD instruction (dest = a + b)."""
        self._instructions.append(Instruction(Opcode.ADD, (dest, a, b)))
        return self

    def sub(self, dest: str, a: str, b: str) -> BinaryBuilder:
        """Add a SUB instruction (dest = a - b)."""
        self._instructions.append(Instruction(Opcode.SUB, (dest, a, b)))
        return self

    def load(self, var: str, value: str) -> BinaryBuilder:
        """Add a LOAD instruction (load string into variable)."""
        self._instructions.append(Instruction(Opcode.LOAD, (var, value)))
        return self

    def concat(self, dest: str, a: str, b: str) -> BinaryBuilder:
        """Add a CONCAT instruction (dest = a + b for strings)."""
        self._instructions.append(Instruction(Opcode.CONCAT, (dest, a, b)))
        return self

    def loop(self, count: int) -> BinaryBuilder:
        """Add a LOOP instruction (repeat next N instructions)."""
        self._instructions.append(Instruction(Opcode.LOOP, (count,)))
        return self

    def halt(self) -> BinaryBuilder:
        """Add a HALT instruction (stop execution)."""
        self._instructions.append(Instruction(Opcode.HALT, ()))
        return self

    def build(self) -> bytes:
        """Serialize the program into PyBin binary format.

        Layout (little-endian):
        - 4 bytes: magic (b"PYBN")
        - 2 bytes: version
        - 2 bytes: name length, followed by name as UTF-8
        - 4 bytes: number of instructions
        - Per instruction:
          - 1 byte: opcode
          - 1 byte: number of arguments
          - Per argument:
            - 1 byte: type tag (0=int, 1=string)
            - If int: 4 bytes (little-endian signed)
            - If string: 2 bytes length + UTF-8 bytes
        """
        buf = bytearray()
        # Header
        buf.extend(PYBIN_MAGIC)
        buf.extend(struct.pack("<H", PYBIN_VERSION))
        name_bytes = self._name.encode("utf-8")
        buf.extend(struct.pack("<H", len(name_bytes)))
        buf.extend(name_bytes)
        buf.extend(struct.pack("<I", len(self._instructions)))
        # Instructions
        for inst in self._instructions:
            buf.append(inst.opcode)
            buf.append(len(inst.args))
            for arg in inst.args:
                if isinstance(arg, int):
                    buf.append(_ARG_TYPE_INT)
                    buf.extend(struct.pack("<i", arg))
                else:
                    buf.append(_ARG_TYPE_STRING)
                    arg_bytes = str(arg).encode("utf-8")
                    buf.extend(struct.pack("<H", len(arg_bytes)))
                    buf.extend(arg_bytes)
        return bytes(buf)


class BinaryLoader:
    """Parse and execute PyBin binaries."""

    @staticmethod
    def parse(data: bytes) -> tuple[PyBinHeader, list[Instruction]]:
        """Parse a PyBin binary into a header and instruction list.

        Args:
            data: The raw binary data.

        Returns:
            A tuple of (header, instructions).

        Raises:
            BinaryLoaderError: If the data is invalid.

        """
        if len(data) < len(PYBIN_MAGIC):
            msg = "Data too short to be a valid PyBin binary"
            raise BinaryLoaderError(msg)
        magic = data[: len(PYBIN_MAGIC)]
        if magic != PYBIN_MAGIC:
            msg = f"Invalid magic: expected {PYBIN_MAGIC!r}, got {magic!r}"
            raise BinaryLoaderError(msg)
        offset = len(PYBIN_MAGIC)
        try:
            header, offset = _parse_header(data, offset)
            instructions = _parse_instructions(data, offset, header.num_instructions)
        except struct.error as e:
            msg = f"Truncated or corrupt binary: {e}"
            raise BinaryLoaderError(msg) from e
        return header, instructions

    @staticmethod
    def to_callable(instructions: list[Instruction]) -> Callable[[], str]:
        """Create a callable that interprets the instruction list.

        Returns:
            A closure that executes the instructions and returns output.

        """

        def run() -> str:
            variables: dict[str, int | str] = {}
            output: list[str] = []
            _execute_instructions(instructions, variables, output)
            return "\n".join(output)

        return run

    @staticmethod
    def load(data: bytes) -> Callable[[], str]:
        """Parse a binary and return a callable in one step."""
        _header, instructions = BinaryLoader.parse(data)
        return BinaryLoader.to_callable(instructions)


def _parse_header(data: bytes, offset: int) -> tuple[PyBinHeader, int]:
    """Parse the PyBin header after the magic bytes."""
    (version,) = struct.unpack_from("<H", data, offset)
    offset += 2
    (name_len,) = struct.unpack_from("<H", data, offset)
    offset += 2
    name = data[offset : offset + name_len].decode("utf-8")
    offset += name_len
    (num_instructions,) = struct.unpack_from("<I", data, offset)
    offset += 4
    header = PyBinHeader(
        magic=PYBIN_MAGIC,
        version=version,
        name=name,
        num_instructions=num_instructions,
    )
    return header, offset


def _parse_arg(data: bytes, offset: int) -> tuple[str | int, int]:
    """Parse a single instruction argument."""
    type_tag = data[offset]
    offset += 1
    if type_tag == _ARG_TYPE_INT:
        (value,) = struct.unpack_from("<i", data, offset)
        return value, offset + 4
    if type_tag == _ARG_TYPE_STRING:
        (str_len,) = struct.unpack_from("<H", data, offset)
        offset += 2
        value_str = data[offset : offset + str_len].decode("utf-8")
        return value_str, offset + str_len
    msg = f"Unknown argument type tag: {type_tag}"
    raise BinaryLoaderError(msg)


def _parse_instructions(data: bytes, offset: int, count: int) -> list[Instruction]:
    """Parse a sequence of instructions from the binary."""
    instructions: list[Instruction] = []
    for _ in range(count):
        opcode = Opcode(data[offset])
        num_args = data[offset + 1]
        offset += 2
        args: list[str | int] = []
        for _ in range(num_args):
            arg, offset = _parse_arg(data, offset)
            args.append(arg)
        instructions.append(Instruction(opcode=opcode, args=tuple(args)))
    return instructions


def _execute_instructions(
    instructions: list[Instruction],
    variables: dict[str, int | str],
    output: list[str],
) -> None:
    """Interpret and execute a list of instructions."""
    ip = 0
    max_iterations = 10000
    iterations = 0
    while ip < len(instructions) and iterations < max_iterations:
        iterations += 1
        inst = instructions[ip]
        match inst.opcode:
            case Opcode.PRINT:
                msg = str(inst.args[0])
                # If the argument is a variable name, print its value
                if msg in variables:
                    output.append(str(variables[msg]))
                else:
                    output.append(msg)
            case Opcode.SET:
                var_name = str(inst.args[0])
                variables[var_name] = int(inst.args[1])
            case Opcode.ADD:
                dest = str(inst.args[0])
                a_val = _resolve_int(variables, inst.args[1])
                b_val = _resolve_int(variables, inst.args[2])
                variables[dest] = a_val + b_val
            case Opcode.SUB:
                dest = str(inst.args[0])
                a_val = _resolve_int(variables, inst.args[1])
                b_val = _resolve_int(variables, inst.args[2])
                variables[dest] = a_val - b_val
            case Opcode.LOAD:
                var_name = str(inst.args[0])
                variables[var_name] = str(inst.args[1])
            case Opcode.CONCAT:
                dest = str(inst.args[0])
                a_str = _resolve_str(variables, inst.args[1])
                b_str = _resolve_str(variables, inst.args[2])
                variables[dest] = a_str + b_str
            case Opcode.LOOP:
                count = int(inst.args[0])
                # Execute the next 'count' instructions repeatedly
                loop_body = instructions[ip + 1 : ip + 1 + count]
                _execute_instructions(loop_body, variables, output)
                ip += count
            case Opcode.HALT:
                return
        ip += 1


def _resolve_int(variables: dict[str, int | str], arg: str | int) -> int:
    """Resolve an argument to an integer value."""
    if isinstance(arg, int):
        return arg
    return int(variables.get(arg, 0))


def _resolve_str(variables: dict[str, int | str], arg: str | int) -> str:
    """Resolve an argument to a string value."""
    key = str(arg)
    if key in variables:
        return str(variables[key])
    return key


# -- Demo programs ------------------------------------------------------------


def _build_hello() -> bytes:
    """Build the 'hello' demo program."""
    return BinaryBuilder("hello").print("Hello from PyBin!").halt().build()


def _build_counter() -> bytes:
    """Build the 'counter' demo program (counts 1 to 5)."""
    builder = BinaryBuilder("counter")
    for i in range(1, 6):
        builder.set("i", i)
        builder.print("i")
    builder.halt()
    return builder.build()


def _build_adder() -> bytes:
    """Build the 'adder' demo program (demonstrates SET + ADD)."""
    return (
        BinaryBuilder("adder")
        .set("a", 10)
        .set("b", 25)
        .add("result", "a", "b")
        .print("result")
        .halt()
        .build()
    )


DEMO_PROGRAMS: dict[str, Callable[[], bytes]] = {
    "hello": _build_hello,
    "counter": _build_counter,
    "adder": _build_adder,
}
