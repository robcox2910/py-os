"""Simulated DNS — translate hostnames into IP addresses.

DNS (Domain Name System) is like a phone book for the internet.
When you type "www.example.com" into a browser, your computer
doesn't know where to go — it only understands numeric IP addresses
like "93.184.216.34".  So it asks a DNS server: "What's the phone
number for www.example.com?"

Our simulation models this with a local phone book that the kernel
owns.  Each entry maps a hostname to an IP address.  The kernel
pre-seeds the phone book with ``localhost → 127.0.0.1`` at boot.
"""

from dataclasses import dataclass


class DnsError(Exception):
    """Raise when a DNS operation fails."""


@dataclass(frozen=True)
class DnsRecord:
    """An A record — one hostname-to-IP mapping.

    Frozen because once registered, a record should not be silently
    mutated.  Remove and re-register to change the IP.
    """

    hostname: str
    """The human-readable name (e.g. 'localhost')."""

    address: str
    """The IP address (e.g. '127.0.0.1')."""


class DnsResolver:
    """A local DNS phone book — register, look up, and manage hostname records."""

    def __init__(self) -> None:
        """Create an empty resolver with no records."""
        self._records: dict[str, DnsRecord] = {}

    def register(self, hostname: str, address: str) -> DnsRecord:
        """Add an A record.

        Args:
            hostname: The human-readable name to register.
            address: The IP address to map to.

        Returns:
            The newly created DnsRecord.

        Raises:
            DnsError: If the hostname is already registered.

        """
        if hostname in self._records:
            msg = f"Hostname '{hostname}' is already registered"
            raise DnsError(msg)
        record = DnsRecord(hostname=hostname, address=address)
        self._records[hostname] = record
        return record

    def lookup(self, hostname: str) -> str:
        """Resolve hostname → IP.

        Args:
            hostname: The hostname to look up.

        Returns:
            The IP address string.

        Raises:
            DnsError: If the hostname is not found.

        """
        record = self._records.get(hostname)
        if record is None:
            msg = f"Hostname '{hostname}' not found"
            raise DnsError(msg)
        return record.address

    def remove(self, hostname: str) -> None:
        """Remove a record.

        Args:
            hostname: The hostname to remove.

        Raises:
            DnsError: If the hostname is not found.

        """
        if hostname not in self._records:
            msg = f"Hostname '{hostname}' not found"
            raise DnsError(msg)
        del self._records[hostname]

    def list_records(self) -> list[DnsRecord]:
        """Return all records sorted by hostname."""
        return sorted(self._records.values(), key=lambda r: r.hostname)

    def flush(self) -> int:
        """Remove all records.

        Returns:
            The number of records removed.

        """
        count = len(self._records)
        self._records.clear()
        return count
