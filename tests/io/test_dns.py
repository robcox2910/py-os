"""Tests for the DNS simulation module.

DNS (Domain Name System) is like a phone book for the internet.
These tests verify that the phone book works correctly: registering
entries, looking up names, removing records, and integrating with
the kernel, syscalls, and shell.
"""

import dataclasses

import pytest

from py_os.completer import Completer
from py_os.io.dns import DnsError, DnsRecord, DnsResolver
from py_os.kernel import Kernel
from py_os.shell import Shell
from py_os.syscalls import SyscallError, SyscallNumber

EXPECTED_LIST_COUNT = 2
EXPECTED_FLUSH_COUNT = 2
EXPECTED_LIST_AFTER_REGISTER = 2


# ---------------------------------------------------------------------------
# Cycle 1: DnsRecord dataclass and DnsError
# ---------------------------------------------------------------------------


class TestDnsRecordAndError:
    """Verify the DnsRecord frozen dataclass and DnsError exception."""

    def test_record_fields(self) -> None:
        """DnsRecord stores hostname and address."""
        record = DnsRecord(hostname="localhost", address="127.0.0.1")
        assert record.hostname == "localhost"
        assert record.address == "127.0.0.1"

    def test_record_is_frozen(self) -> None:
        """DnsRecord is immutable — assignments raise FrozenInstanceError."""
        record = DnsRecord(hostname="localhost", address="127.0.0.1")
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.hostname = "other"  # type: ignore[misc]

    def test_dns_error_is_exception(self) -> None:
        """DnsError is a standard Exception subclass."""
        err = DnsError("not found")
        assert isinstance(err, Exception)
        assert str(err) == "not found"


# ---------------------------------------------------------------------------
# Cycle 2: DnsResolver register and lookup
# ---------------------------------------------------------------------------


class TestDnsResolverRegisterLookup:
    """Verify register and lookup operations on the resolver."""

    def test_register_returns_record(self) -> None:
        """Register creates and returns a DnsRecord."""
        resolver = DnsResolver()
        record = resolver.register("example.com", "93.184.216.34")
        assert isinstance(record, DnsRecord)
        assert record.hostname == "example.com"
        assert record.address == "93.184.216.34"

    def test_lookup_returns_address(self) -> None:
        """Lookup resolves a registered hostname to its IP."""
        resolver = DnsResolver()
        resolver.register("example.com", "93.184.216.34")
        assert resolver.lookup("example.com") == "93.184.216.34"

    def test_duplicate_register_raises(self) -> None:
        """Duplicate hostname registration raises DnsError."""
        resolver = DnsResolver()
        resolver.register("example.com", "93.184.216.34")
        with pytest.raises(DnsError, match="already registered"):
            resolver.register("example.com", "1.2.3.4")

    def test_lookup_unknown_raises(self) -> None:
        """Lookup of unregistered hostname raises DnsError."""
        resolver = DnsResolver()
        with pytest.raises(DnsError, match="not found"):
            resolver.lookup("nope.example.com")


# ---------------------------------------------------------------------------
# Cycle 3: DnsResolver management (remove, list, flush)
# ---------------------------------------------------------------------------


class TestDnsResolverManagement:
    """Verify remove, list_records, and flush operations."""

    def test_remove_deletes_record(self) -> None:
        """Remove makes a hostname unresolvable."""
        resolver = DnsResolver()
        resolver.register("example.com", "93.184.216.34")
        resolver.remove("example.com")
        with pytest.raises(DnsError, match="not found"):
            resolver.lookup("example.com")

    def test_remove_unknown_raises(self) -> None:
        """Remove of non-existent hostname raises DnsError."""
        resolver = DnsResolver()
        with pytest.raises(DnsError, match="not found"):
            resolver.remove("nope.example.com")

    def test_list_records_sorted(self) -> None:
        """List returns all records sorted by hostname."""
        resolver = DnsResolver()
        resolver.register("beta.com", "2.2.2.2")
        resolver.register("alpha.com", "1.1.1.1")
        records = resolver.list_records()
        assert len(records) == EXPECTED_LIST_COUNT
        assert records[0].hostname == "alpha.com"
        assert records[1].hostname == "beta.com"

    def test_flush_clears_all(self) -> None:
        """Flush removes all records and returns the count."""
        resolver = DnsResolver()
        resolver.register("a.com", "1.1.1.1")
        resolver.register("b.com", "2.2.2.2")
        count = resolver.flush()
        assert count == EXPECTED_FLUSH_COUNT
        assert resolver.list_records() == []

    def test_flush_empty_returns_zero(self) -> None:
        """Flush on an empty resolver returns 0."""
        resolver = DnsResolver()
        assert resolver.flush() == 0


# ---------------------------------------------------------------------------
# Cycle 4: Kernel DNS integration
# ---------------------------------------------------------------------------


class TestKernelDns:
    """Verify kernel boot pre-seeds localhost and delegates to DnsResolver."""

    def test_boot_preseeds_localhost(self) -> None:
        """Kernel boot registers localhost -> 127.0.0.1."""
        kernel = Kernel()
        kernel.boot()
        try:
            assert kernel.dns_lookup("localhost") == "127.0.0.1"
        finally:
            kernel.shutdown()

    def test_register_and_lookup(self) -> None:
        """Kernel dns_register + dns_lookup round-trip."""
        kernel = Kernel()
        kernel.boot()
        try:
            record = kernel.dns_register("example.com", "93.184.216.34")
            assert record.hostname == "example.com"
            assert kernel.dns_lookup("example.com") == "93.184.216.34"
        finally:
            kernel.shutdown()

    def test_dns_list_includes_localhost(self) -> None:
        """Dns_list returns a dict-list that includes the pre-seeded localhost."""
        kernel = Kernel()
        kernel.boot()
        try:
            records = kernel.dns_list()
            hostnames = [r["hostname"] for r in records]
            assert "localhost" in hostnames
        finally:
            kernel.shutdown()

    def test_shutdown_clears_resolver(self) -> None:
        """After shutdown, the DNS resolver is None."""
        kernel = Kernel()
        kernel.boot()
        kernel.shutdown()
        # Attempting dns_lookup on a shut-down kernel should raise
        with pytest.raises(RuntimeError, match="not running"):
            kernel.dns_lookup("localhost")


# ---------------------------------------------------------------------------
# Cycle 5: DNS syscalls
# ---------------------------------------------------------------------------


class TestDnsSyscalls:
    """Verify syscall wrappers for DNS operations."""

    def test_register_syscall(self) -> None:
        """SYS_DNS_REGISTER creates a record via the kernel."""
        kernel = Kernel()
        kernel.boot()
        try:
            result = kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname="test.local",
                address="10.0.0.1",
            )
            assert result["hostname"] == "test.local"
            assert result["address"] == "10.0.0.1"
        finally:
            kernel.shutdown()

    def test_lookup_syscall(self) -> None:
        """SYS_DNS_LOOKUP resolves a hostname via the kernel."""
        kernel = Kernel()
        kernel.boot()
        try:
            kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname="test.local",
                address="10.0.0.1",
            )
            result = kernel.syscall(
                SyscallNumber.SYS_DNS_LOOKUP,
                hostname="test.local",
            )
            assert result == "10.0.0.1"
        finally:
            kernel.shutdown()

    def test_full_roundtrip(self) -> None:
        """Register, list, remove, flush via syscalls."""
        kernel = Kernel()
        kernel.boot()
        try:
            # Register
            kernel.syscall(
                SyscallNumber.SYS_DNS_REGISTER,
                hostname="a.com",
                address="1.1.1.1",
            )
            # List — should have localhost + a.com
            records = kernel.syscall(SyscallNumber.SYS_DNS_LIST)
            assert len(records) == EXPECTED_LIST_AFTER_REGISTER

            # Remove
            kernel.syscall(SyscallNumber.SYS_DNS_REMOVE, hostname="a.com")
            records = kernel.syscall(SyscallNumber.SYS_DNS_LIST)
            assert len(records) == 1

            # Flush
            result = kernel.syscall(SyscallNumber.SYS_DNS_FLUSH)
            assert result == 1  # only localhost was left
        finally:
            kernel.shutdown()

    def test_error_wrapping(self) -> None:
        """DnsError is wrapped as SyscallError at the boundary."""
        kernel = Kernel()
        kernel.boot()
        try:
            with pytest.raises(SyscallError, match="not found"):
                kernel.syscall(
                    SyscallNumber.SYS_DNS_LOOKUP,
                    hostname="nope.example.com",
                )
        finally:
            kernel.shutdown()


# ---------------------------------------------------------------------------
# Cycle 6: Shell dns command
# ---------------------------------------------------------------------------


class TestDnsShell:
    """Verify the shell 'dns' command and its subcommands."""

    def test_register_and_lookup(self) -> None:
        """Register and lookup round-trip via shell."""
        kernel = Kernel()
        kernel.boot()
        try:
            shell = Shell(kernel=kernel)
            reg_out = shell.execute("dns register example.com 93.184.216.34")
            assert "example.com" in reg_out
            assert "93.184.216.34" in reg_out

            lookup_out = shell.execute("dns lookup example.com")
            assert "93.184.216.34" in lookup_out
        finally:
            kernel.shutdown()

    def test_list_shows_localhost(self) -> None:
        """Dns list includes the pre-seeded localhost entry."""
        kernel = Kernel()
        kernel.boot()
        try:
            shell = Shell(kernel=kernel)
            out = shell.execute("dns list")
            assert "localhost" in out
            assert "127.0.0.1" in out
        finally:
            kernel.shutdown()

    def test_demo_runs(self) -> None:
        """Dns demo produces output without errors."""
        kernel = Kernel()
        kernel.boot()
        try:
            shell = Shell(kernel=kernel)
            out = shell.execute("dns demo")
            assert "DNS" in out or "dns" in out.lower()
            # Demo should show the query/answer flow
            assert "QUERY" in out
            assert "ANSWER" in out
        finally:
            kernel.shutdown()

    def test_bad_subcommand_shows_usage(self) -> None:
        """Unknown subcommand returns usage message."""
        kernel = Kernel()
        kernel.boot()
        try:
            shell = Shell(kernel=kernel)
            out = shell.execute("dns bogus")
            assert "Usage" in out
        finally:
            kernel.shutdown()


# ---------------------------------------------------------------------------
# Cycle 7: Tab completion
# ---------------------------------------------------------------------------


class TestDnsCompleter:
    """Verify tab completion for the dns command."""

    def test_subcommand_completion(self) -> None:
        """Typing 'dns ' offers all subcommands."""
        kernel = Kernel()
        kernel.boot()
        try:
            shell = Shell(kernel=kernel)
            comp = Completer(shell)
            candidates = comp.completions("", "dns ")
            expected = {"demo", "flush", "list", "lookup", "register", "remove"}
            assert set(candidates) == expected
        finally:
            kernel.shutdown()

    def test_partial_prefix_filtering(self) -> None:
        """Typing 'dns re' filters to register and remove."""
        kernel = Kernel()
        kernel.boot()
        try:
            shell = Shell(kernel=kernel)
            comp = Completer(shell)
            candidates = comp.completions("re", "dns re")
            assert set(candidates) == {"register", "remove"}
        finally:
            kernel.shutdown()
