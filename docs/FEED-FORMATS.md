# Feed Formats

## Layout

Every category publishes exactly four files. Formats are never mixed.

```
feeds/<category>/ipv4.txt        one IPv4 address per line
feeds/<category>/ipv6.txt        one IPv6 address per line
feeds/<category>/ipv4-cidrs.txt  one IPv4 CIDR per line
feeds/<category>/ipv6-cidrs.txt  one IPv6 CIDR per line
```

## File format

```
# openshield-blocklists :: <category> :: <format label>
# category: <name> | one entry per line | spec: docs/FEED-FORMATS.md
# entries: <n>
<entry>
<entry>
...
```

Rules consumers can rely on:

- one entry per line, no inline comments, no blank lines in the body
- `#` lines are a 3-line header and only ever appear at the top
- entries are sorted numerically (by integer address, not lexicographically)
- entries are unique within a file
- single-IP files never contain an IP already covered by the category's
  CIDR file (redundancy is subtracted at build time)
- CIDR files are minimal: overlapping/adjacent ranges are collapsed
- no ports anywhere — proxy feeds are stripped to bare source addresses
- only publicly routable, unicast space (no private/loopback/multicast/
  reserved/documentation/benchmark ranges; v4 subnets ≥ /8, v6 subnets ≥ /32)
- **no timestamps** — identical content means identical bytes; file content
  hash (`metadata/<category>.json → files.<fmt>.sha256`) is the version

## Metadata

`metadata/<category>.json`:

```jsonc
{
  "schema": 1,
  "feed": "c2",
  "name": "C2 Infrastructure",
  "status": "active",                 // active | planned
  "generated": "2026-08-04T12:00:00Z", // last content change
  "version": "sha256:…",               // content-addressed, reproducible
  "sources": {
    "count": 5,
    "by_status": {"ok": 4, "stale-cache": 1},
    "stats": [ /* per-source: entries, invalid_discarded, duplicates, duration_ms, … */ ]
  },
  "totals": {"ipv4": 0, "ipv6": 0, "cidrs_v4": 0, "cidrs_v6": 0, "all": 0},
  "processing": {
    "duplicates_removed": 0,
    "invalid_discarded": 0,
    "duration_ms": 0
  },
  "files": {
    "ipv4": {"path": "feeds/c2/ipv4.txt", "url": "https://raw…/ipv4.txt",
             "entries": 0, "sha256": "…", "bytes": 0}
    // ipv6, ipv4-cidrs, ipv6-cidrs
  }
}
```

`metadata/manifest.json` is the global index: generator version, grand
totals, per-feed summary (version, totals, file URLs). Machine consumers
should start there.

## Versioning

- `version` = `sha256` over the four file hashes → same content, same version.
- `generated` = timestamp of the last run that changed the content.
- `schema` = metadata schema version; bumped on breaking changes.
