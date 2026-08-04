"""Entry validation.

Default policy: only globally-routable, unicast entries survive.

Rejected by default (via ipaddress.is_global):
  loopback, private (RFC1918 etc.), link-local, multicast, unspecified,
  reserved, CGNAT shared space (100.64/10), documentation ranges
  (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32), benchmarking
  (198.18/15) — none of these can be a legitimate source at an internet
  edge XDP hook.

Subnet entries additionally get minimum-prefix guards so a malformed feed
can never turn into a catastrophic over-block. A source may opt out of the
global check (validation.allow_non_global) but never of the prefix guards.
"""

from __future__ import annotations

import ipaddress

from .models import EntryAny

#: Minimum accepted prefix lengths. Anything broader is almost certainly a
#: feed formatting error.
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 32


def _is_public(addr) -> bool:
    # is_global alone is NOT sufficient: CPython treats multicast (and some
    # reserved) space as "global" because it isn't private. Reject every
    # special-use shape explicitly.
    return (
        addr.is_global
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
        and not addr.is_loopback
        and not addr.is_link_local
    )


def keep(entry: EntryAny, *, allow_non_global: bool = False) -> bool:
    """True if the entry may be published."""
    if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        if entry.version == 4 and entry.prefixlen < MIN_PREFIX_V4:
            return False
        if entry.version == 6 and entry.prefixlen < MIN_PREFIX_V6:
            return False
        if allow_non_global:
            return True
        # Both ends must be public so ranges straddling special-use space
        # (e.g. 9.0.0.0/8 spanning into 10.0.0.0/8) are refused too.
        return _is_public(entry.network_address) and _is_public(entry.broadcast_address)
    if allow_non_global:
        return True
    return _is_public(entry)
