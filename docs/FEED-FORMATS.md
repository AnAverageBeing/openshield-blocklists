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

## L7 pattern feeds

`feeds/l7-patterns/` is a **hand-curated, non-IP feed** — it is not built
from remote sources and is not listed in the manifest. It carries L7
drop signatures for OpenShield-XDP's kernel signature engine
(`l7_sig_map`, 16 slots), one signature per line:

```
name|proto|port|port_is_src|offset|min_payload|max_payload|pattern_hex|mask_hex
```

| field | rules |
| --- | --- |
| `name` | 1-64 chars of `[A-Za-z0-9._-]`, unique within the file |
| `proto` | `udp` or `tcp` |
| `port` | 1-65535 |
| `port_is_src` | `1` = match the SOURCE port (response-side signatures), `0` = destination |
| `offset` | 0-255, payload-relative (after the L4 header). Note the engine reads 8 bytes from `offset`, so offsets > 248 can never match |
| `min_payload` | 0-65535, minimum L4 payload length |
| `max_payload` | 0 = no cap, otherwise >= `min_payload` |
| `pattern_hex` | 1-8 bytes of hex |
| `mask_hex` | empty (= exact match, all-`ff`) or the same byte length as `pattern_hex` |

Engine semantics: a packet matches when proto, port (src or dst per
`port_is_src`) and payload-length bounds match AND, for every pattern byte
i, `(payload[offset+i] & mask[i]) == pattern[i]`. A signature with an empty
pattern never matches, so patterns are mandatory. Pattern bits outside the
mask can never match and are rejected at validation.

Rules consumers can rely on:

- one signature per line; blank lines ignored
- `#` comment lines may appear anywhere (this feed documents the byte-level
  rationale and the exclusion reasons for unsafe candidates inline)
- entries are sorted in a stable, editorial order (by protocol class)
- signature names are unique
- **no timestamps** — identical content means identical bytes; the file hash
  (`metadata/l7-patterns.json → files.patterns.sha256`) is the version

Admission policy: only highest-accuracy reflection/amplification classes,
only as response-side signatures (`port_is_src=1`) with a confident fixed
byte marker. Candidates without one (e.g. chargen, SNMP, portmap) are
excluded and documented at the bottom of the feed file.

Validate with `openshield-feeds validate-patterns`; `openshield-feeds
verify` also checks the file set, format and metadata hash.


## Versioning

- `version` = `sha256` over the four file hashes → same content, same version.
- `generated` = timestamp of the last run that changed the content.
- `schema` = metadata schema version; bumped on breaking changes.
