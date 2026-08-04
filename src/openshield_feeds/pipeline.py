"""Aggregation pipeline: cross-source dedupe, subnet collapse, coverage
subtraction, deterministic ordering.

Determinism contract: identical inputs always produce byte-identical output
lists. Timestamps and other volatile data live exclusively in metadata/.
"""

from __future__ import annotations

import bisect
import ipaddress

from .models import EntrySet


def aggregate(entry_sets: list[EntrySet]) -> tuple[EntrySet, int]:
    """Merge per-source sets. Returns (merged, duplicates_removed)."""
    merged = EntrySet()
    supplied = 0
    for es in entry_sets:
        supplied += es.total()
        merged.merge(es)
    return merged, supplied - merged.total()


def _collapse(nets):
    """Merge overlapping/adjacent networks into a minimal sorted set."""
    return list(ipaddress.collapse_addresses(sorted(nets)))


def _subtract_covered(ips, collapsed_nets):
    """Drop single IPs already contained in a blocked subnet (redundant)."""
    if not collapsed_nets:
        return list(ips)
    spans = sorted((int(n.network_address), int(n.broadcast_address)) for n in collapsed_nets)
    starts = [s for s, _ in spans]
    out = []
    for ip in ips:
        x = int(ip)
        i = bisect.bisect_right(starts, x) - 1
        if i < 0 or spans[i][1] < x:
            out.append(ip)
    return out


def finalize(entries: EntrySet) -> dict[str, list[str]]:
    """Produce the four deterministic, format-pure output lists."""
    n4 = _collapse(entries.cidr4)
    n6 = _collapse(entries.cidr6)
    return {
        "ipv4": [str(ip) for ip in _subtract_covered(sorted(entries.ipv4), n4)],
        "ipv6": [str(ip) for ip in _subtract_covered(sorted(entries.ipv6), n6)],
        "ipv4-cidrs": [str(n) for n in n4],
        "ipv6-cidrs": [str(n) for n in n6],
    }
