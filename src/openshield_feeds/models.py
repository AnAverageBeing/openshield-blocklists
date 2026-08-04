"""Core typed data model shared across the pipeline.

Everything here is stdlib-only and immutable-ish (dataclasses) so future
extensions (reputation scoring, ASN/geo enrichment, expirations) can hang
new fields off these types without reworking the pipeline.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Union

IpAny = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
NetAny = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
EntryAny = Union[IpAny, NetAny]

#: The four published feed formats. File names are fixed by convention:
#: feeds/<category>/<format>.txt — formats are NEVER mixed in one file.
FEED_FORMATS = ("ipv4", "ipv6", "ipv4-cidrs", "ipv6-cidrs")


@dataclass
class EntrySet:
    """A bucket of validated entries, one set per published format."""

    ipv4: set[ipaddress.IPv4Address] = field(default_factory=set)
    ipv6: set[ipaddress.IPv6Address] = field(default_factory=set)
    cidr4: set[ipaddress.IPv4Network] = field(default_factory=set)
    cidr6: set[ipaddress.IPv6Network] = field(default_factory=set)

    def add(self, entry: EntryAny) -> None:
        if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            (self.cidr4 if entry.version == 4 else self.cidr6).add(entry)
        elif entry.version == 4:
            self.ipv4.add(entry)  # type: ignore[arg-type]
        else:
            self.ipv6.add(entry)  # type: ignore[arg-type]

    def merge(self, other: "EntrySet") -> None:
        self.ipv4 |= other.ipv4
        self.ipv6 |= other.ipv6
        self.cidr4 |= other.cidr4
        self.cidr6 |= other.cidr6

    def counts(self) -> dict[str, int]:
        return {
            "ipv4": len(self.ipv4),
            "ipv6": len(self.ipv6),
            "cidr4": len(self.cidr4),
            "cidr6": len(self.cidr6),
        }

    def total(self) -> int:
        return sum(self.counts().values())


@dataclass
class ParseResult:
    """Outcome of parsing one source body."""

    entries: EntrySet = field(default_factory=EntrySet)
    candidates: int = 0  # tokens that parsed as an IP/CIDR
    invalid: int = 0     # candidates rejected by validation (non-global, broad prefix, ...)


@dataclass
class SourceResult:
    """Full per-source accounting that ends up in feed metadata."""

    name: str
    category: str
    url: str
    priority: int = 100
    status: str = "pending"  # ok | cache | stale-cache | failed | skipped | warning
    detail: str = ""
    fetched: bool = False       # actually hit the network this run
    raw_bytes: int = 0
    candidates: int = 0
    invalid: int = 0            # discarded by validation
    within_source_dupes: int = 0
    entries: EntrySet = field(default_factory=EntrySet)
    duration_ms: int = 0

    def stats_dict(self) -> dict:
        counts = self.entries.counts()
        return {
            "name": self.name,
            "category": self.category,
            "url": self.url,
            "priority": self.priority,
            "status": self.status,
            "detail": self.detail,
            "fetched": self.fetched,
            "raw_bytes": self.raw_bytes,
            "candidates": self.candidates,
            "invalid_discarded": self.invalid,
            "within_source_duplicates": self.within_source_dupes,
            "ipv4": counts["ipv4"],
            "ipv6": counts["ipv6"],
            "cidrs_v4": counts["cidr4"],
            "cidrs_v6": counts["cidr6"],
            "total": self.entries.total(),
            "duration_ms": self.duration_ms,
        }
