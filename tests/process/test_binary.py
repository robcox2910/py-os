"""Tests for the PyBin binary loader — format, parsing, and execution."""

import pytest

from py_os.kernel import ExecutionMode, Kernel
from py_os.process.binary import (
    DEMO_PROGRAMS,
    PYBIN_MAGIC,
    PYBIN_VERSION,
    BinaryBuilder,
    BinaryLoader,
    BinaryLoaderError,
    Opcode,
)
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

_ADDER_RESULT = 35
_COUNTER_LINES = 5
_HALT_OPCODE_VALUE = 8


def _booted_kernel() -> Kernel:
    """Create and boot a kernel for testing."""
    kernel = Kernel()
    kernel.boot()
    kernel._execution_mode = ExecutionMode.KERNEL
    return kernel


def _booted_shell() -> tuple[Kernel, Shell]:
    """Create booted kernel + shell for testing."""
    kernel = _booted_kernel()
    return kernel, Shell(kernel=kernel)


# -- Opcode tests -------------------------------------------------------------


class TestOpcode:
    """Verify Opcode enum values."""

    def test_print_value(self) -> None:
        """PRINT opcode has value 1."""
        assert Opcode.PRINT == 1

    def test_halt_value(self) -> None:
        """HALT opcode has value 8."""
        assert Opcode.HALT == _HALT_OPCODE_VALUE

    def test_all_opcodes_exist(self) -> None:
        """All expected opcodes are defined."""
        expected = {"PRINT", "SET", "ADD", "SUB", "LOAD", "CONCAT", "LOOP", "HALT"}
        actual = {op.name for op in Opcode}
        assert expected == actual


# -- BinaryBuilder tests -------------------------------------------------------


class TestBinaryBuilder:
    """Verify the fluent builder API."""

    def test_build_produces_bytes_with_magic(self) -> None:
        """Build produces bytes starting with the magic number."""
        data = BinaryBuilder("test").halt().build()
        assert data[:4] == PYBIN_MAGIC

    def test_fluent_chaining(self) -> None:
        """Builder methods return self for chaining."""
        builder = BinaryBuilder("test")
        result = builder.print("hello").set("x", 1).halt()
        assert result is builder

    def test_empty_program(self) -> None:
        """An empty program (no instructions) can be built and parsed."""
        data = BinaryBuilder("empty").build()
        header, instructions = BinaryLoader.parse(data)
        assert header.name == "empty"
        assert instructions == []


class TestBinaryBuilderInstructions:
    """Verify each opcode serializes correctly."""

    def test_print_instruction(self) -> None:
        """PRINT instruction serializes with a string argument."""
        data = BinaryBuilder("test").print("hi").halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.PRINT
        assert instructions[0].args == ("hi",)

    def test_set_instruction(self) -> None:
        """SET instruction serializes with a variable name and int value."""
        data = BinaryBuilder("test").set("x", 42).halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.SET

    def test_add_instruction(self) -> None:
        """ADD instruction serializes with three variable names."""
        data = BinaryBuilder("test").add("c", "a", "b").halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.ADD

    def test_sub_instruction(self) -> None:
        """SUB instruction serializes correctly."""
        data = BinaryBuilder("test").sub("c", "a", "b").halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.SUB

    def test_load_instruction(self) -> None:
        """LOAD instruction serializes with variable and string value."""
        data = BinaryBuilder("test").load("msg", "hello").halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.LOAD

    def test_concat_instruction(self) -> None:
        """CONCAT instruction serializes with three variable names."""
        data = BinaryBuilder("test").concat("c", "a", "b").halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.CONCAT

    def test_loop_instruction(self) -> None:
        """LOOP instruction serializes with a count argument."""
        data = BinaryBuilder("test").loop(3).halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.LOOP

    def test_halt_instruction(self) -> None:
        """HALT instruction serializes with no arguments."""
        data = BinaryBuilder("test").halt().build()
        _header, instructions = BinaryLoader.parse(data)
        assert instructions[0].opcode is Opcode.HALT
        assert instructions[0].args == ()


# -- BinaryLoader tests -------------------------------------------------------


class TestBinaryLoader:
    """Verify parsing valid and invalid binaries."""

    def test_parse_valid(self) -> None:
        """Parse a valid binary returns header and instructions."""
        data = BinaryBuilder("hello").print("Hello!").halt().build()
        header, instructions = BinaryLoader.parse(data)
        assert header.magic == PYBIN_MAGIC
        assert header.version == PYBIN_VERSION
        assert header.name == "hello"
        assert len(instructions) == 2  # noqa: PLR2004

    def test_parse_invalid_magic_raises(self) -> None:
        """Invalid magic number raises BinaryLoaderError."""
        data = b"XXXX" + b"\x00" * 20
        with pytest.raises(BinaryLoaderError, match="Invalid magic"):
            BinaryLoader.parse(data)

    def test_parse_truncated_raises(self) -> None:
        """Truncated data raises BinaryLoaderError."""
        with pytest.raises(BinaryLoaderError):
            BinaryLoader.parse(b"PY")

    def test_parse_empty_raises(self) -> None:
        """Empty data raises BinaryLoaderError."""
        with pytest.raises(BinaryLoaderError):
            BinaryLoader.parse(b"")


# -- Execution tests -----------------------------------------------------------


class TestBinaryExecution:
    """Verify program execution produces correct output."""

    def test_hello_output(self) -> None:
        """Hello program outputs the greeting message."""
        data = BinaryBuilder("hello").print("Hello from PyBin!").halt().build()
        program = BinaryLoader.load(data)
        output = program()
        assert "Hello from PyBin!" in output

    def test_counter_counts(self) -> None:
        """Counter program outputs numbers 1 through 5."""
        data = DEMO_PROGRAMS["counter"]()
        program = BinaryLoader.load(data)
        output = program()
        lines = output.strip().split("\n")
        assert len(lines) == _COUNTER_LINES
        assert lines[0] == "1"
        assert lines[-1] == "5"

    def test_adder_adds(self) -> None:
        """Adder program computes 10 + 25 = 35."""
        data = DEMO_PROGRAMS["adder"]()
        program = BinaryLoader.load(data)
        output = program()
        assert str(_ADDER_RESULT) in output


# -- Round-trip tests ----------------------------------------------------------


class TestBinaryRoundTrip:
    """Verify build -> parse -> execute round-trip."""

    def test_roundtrip_hello(self) -> None:
        """Build, parse, and execute a hello program."""
        data = BinaryBuilder("test").print("Round trip!").halt().build()
        header, instructions = BinaryLoader.parse(data)
        program = BinaryLoader.to_callable(instructions)
        output = program()
        assert "Round trip!" in output
        assert header.name == "test"


# -- Demo program tests --------------------------------------------------------


class TestDemoPrograms:
    """Verify each demo program loads and executes without error."""

    def test_hello_demo(self) -> None:
        """Hello demo loads and executes."""
        data = DEMO_PROGRAMS["hello"]()
        program = BinaryLoader.load(data)
        output = program()
        assert len(output) > 0

    def test_counter_demo(self) -> None:
        """Counter demo loads and executes."""
        data = DEMO_PROGRAMS["counter"]()
        program = BinaryLoader.load(data)
        output = program()
        assert len(output) > 0

    def test_adder_demo(self) -> None:
        """Adder demo loads and executes."""
        data = DEMO_PROGRAMS["adder"]()
        program = BinaryLoader.load(data)
        output = program()
        assert len(output) > 0


# -- Syscall tests -------------------------------------------------------------


class TestSyscallLoadBinary:
    """Verify binary-related syscalls."""

    def test_load_valid_binary(self) -> None:
        """Load a valid binary from /bin returns metadata."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LOAD_BINARY, path="/bin/hello")
        assert result["name"] == "hello"
        assert result["version"] == PYBIN_VERSION

    def test_load_nonexistent_raises(self) -> None:
        """Load from a nonexistent path raises SyscallError."""
        kernel = _booted_kernel()
        with pytest.raises(SyscallError, match="not found"):
            kernel.syscall(SyscallNumber.SYS_LOAD_BINARY, path="/bin/nope")

    def test_load_no_execute_permission_raises(self) -> None:
        """Load a binary without execute permission raises SyscallError."""
        kernel = _booted_kernel()
        # Create a file without execute permission
        kernel.syscall(SyscallNumber.SYS_CREATE_FILE, path="/nox.bin")
        data = DEMO_PROGRAMS["hello"]()
        kernel.syscall(SyscallNumber.SYS_WRITE_FILE, path="/nox.bin", data=data)
        kernel.syscall(SyscallNumber.SYS_CHMOD, path="/nox.bin", mode="rw-r--r--")
        # Switch to non-root user
        kernel.syscall(SyscallNumber.SYS_CREATE_USER, username="bob")
        kernel.syscall(SyscallNumber.SYS_SWITCH_USER, uid=1)
        with pytest.raises(SyscallError, match="Execute permission denied"):
            kernel.syscall(SyscallNumber.SYS_LOAD_BINARY, path="/nox.bin")


class TestSyscallListPrograms:
    """Verify SYS_LIST_PROGRAMS syscall."""

    def test_lists_builtins(self) -> None:
        """Built-in demo programs are listed."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LIST_PROGRAMS)
        assert "hello" in result["builtins"]
        assert "counter" in result["builtins"]
        assert "adder" in result["builtins"]

    def test_lists_filesystem_binaries(self) -> None:
        """Binaries in /bin are listed."""
        kernel = _booted_kernel()
        result = kernel.syscall(SyscallNumber.SYS_LIST_PROGRAMS)
        assert "hello" in result["filesystem"]


# -- Shell command tests -------------------------------------------------------


class TestShellRunBinary:
    """Verify running binaries from the shell."""

    def test_run_binary_path(self) -> None:
        """Run a binary from a path produces output."""
        _kernel, shell = _booted_shell()
        output = shell.execute("run /bin/hello")
        assert "Hello from PyBin!" in output

    def test_run_nonexistent_binary(self) -> None:
        """Run a nonexistent binary shows error."""
        _kernel, shell = _booted_shell()
        output = shell.execute("run /bin/nope")
        assert "Error" in output


class TestShellCompile:
    """Verify the compile command."""

    def test_compile_list(self) -> None:
        """Compile list shows available demos."""
        _kernel, shell = _booted_shell()
        output = shell.execute("compile list")
        assert "hello" in output
        assert "counter" in output

    def test_compile_creates_binary(self) -> None:
        """Compile creates a binary file in /bin."""
        _kernel, shell = _booted_shell()
        output = shell.execute("compile hello")
        assert "Compiled hello" in output
        assert "bytes" in output

    def test_compile_unknown_demo(self) -> None:
        """Compile an unknown demo shows error."""
        _kernel, shell = _booted_shell()
        output = shell.execute("compile nope")
        assert "Unknown demo" in output


class TestShellHexdump:
    """Verify the hexdump command."""

    def test_hexdump_shows_magic(self) -> None:
        """Hexdump shows the PyBin magic bytes."""
        _kernel, shell = _booted_shell()
        output = shell.execute("hexdump /bin/hello")
        assert "PYBN" in output
        assert "PyBin binary" in output

    def test_hexdump_nonexistent(self) -> None:
        """Hexdump of nonexistent file shows error."""
        _kernel, shell = _booted_shell()
        output = shell.execute("hexdump /nope")
        assert "Error" in output

    def test_hexdump_usage(self) -> None:
        """Hexdump without args shows usage."""
        _kernel, shell = _booted_shell()
        output = shell.execute("hexdump")
        assert "Usage:" in output
