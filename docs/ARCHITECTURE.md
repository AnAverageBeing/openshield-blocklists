# Architecture

## Design goals

1. **Deterministic** — identical inputs produce byte-identical feed files.
2. **Incremental** — scheduled runs only re-fetch stale sources; parsing is
   cached by content hash.
3. **Configuration-driven** — sources and categories live in `configs/` only;
   no source is ever hardcoded.
4. **Fail-safe** — a source outage falls back to last-good data; a mass outage
   refuses to publish.
5. **Extensible** — every future feature below has a designated seam.

## Data flow

```
configs/sources.json ──┐
configs/categories.json┴─► config.py (validate)
                              │
                              ▼
                    fetcher.py  ◄── raw/ cache (last-good bodies)
                    (intervals, retries, fallback)
                              │
                              ▼
                    parser.py ──► validator.py ──► models.EntrySet
                    (normalize, strip ports)   (drop non-public, broad prefixes)
                              │
                       processed/ cache (keyed by raw sha256)
                              │
                              ▼
                    pipeline.py (merge, cross-source dedupe, collapse
                                 subnets, subtract covered IPs, sort)
                              │
                              ▼
                    output.py ──► feeds/<category>/{ipv4,ipv6,ipv4-cidrs,ipv6-cidrs}.txt
                    (atomic, write-if-changed)
                              │
                              ▼
                    metadata.py ──► metadata/<category>.json + manifest.json
                              │
                              ▼
                    cli.py verify (offline integrity re-check in CI)
```

## Module map (`src/openshield_feeds/`)

| Module | Responsibility |
| --- | --- |
| `config.py` | Load + validate `configs/*.json`; typed `Source`/`Category`. |
| `models.py` | `EntrySet`, `SourceResult`, published-format constants. |
| `fetcher.py` | Concurrent HTTP, update intervals, retry, cache fallback, auth. |
| `parser.py` | Line → candidate IPs/CIDRs (all upstream shapes, ports stripped). |
| `validator.py` | Publication policy: public ranges only, prefix guards. |
| `cache.py` | `RawCache` (fetch bodies) and `ProcessedCache` (parsed entries). |
| `pipeline.py` | Cross-source dedupe, subnet collapse, coverage subtraction, ordering. |
| `output.py` | Deterministic, atomic, write-if-changed feed files. |
| `metadata.py` | Per-feed metadata, global manifest, content-addressed versions. |
| `cli.py` | `build` / `verify` / `validate-config` / `list-sources`. |

## Storage layout

| Path | Committed | Purpose |
| --- | --- | --- |
| `feeds/` | yes | Published feed files (the product). |
| `metadata/` | yes | Per-feed metadata + `manifest.json`. |
| `raw/*.txt` | yes | Last-good fetch bodies (outage fallback). |
| `raw/*.json` | **no** | Freshness sidecars (runner-local timestamps). |
| `processed/` | yes | Parsed entries keyed by raw hash — content-derived, deterministic. |

## Extension seams (future features)

| Feature | Where it plugs in |
| --- | --- |
| Reputation scoring / confidence | `Source.priority` already exists; scoring aggregates in `pipeline.py`, emitted via `metadata.py` and (later) an enriched per-entry writer in `output.py`. |
| ASN / country info | New enrichment stage between `pipeline.py` and `output.py`; extra JSON columns in metadata; text feeds stay unchanged. |
| Threat tags per entry | `EntrySet` → per-entry record type; `parser.py` keeps producing candidates, a mapper annotates them. |
| Expiration timestamps | `Source` gains `ttl`; entries carry expiry into metadata; writers prune. |
| Digital signatures | `output.py` already computes sha256 per file; signing adds `.sig`/`.asc` siblings in the same atomic write. |
| Delta updates | Deterministic ordering makes diffs trivial; a `deltas/` writer diffs against the previously committed `feeds/`. |
| Binary export (e.g. ipset, nft, BPF map blobs) | New writer modules alongside `output.py`, consuming the same finalized lists. |
| API generation / CDN | `metadata/manifest.json` is already the API index; publish via `gh-pages` or release assets without touching the pipeline. |
| Community reports | New `community-reports` category exists; add a submission intake that writes a source file consumed like any other. |

## Failure policy

- Source fails → `stale-cache` (last good) or `failed` (no cache) — never fatal.
- Source yields suspiciously few entries → `warning` status in metadata.
- Grand total below the sanity floor → **nothing is published**, exit 1.
- `verify` fails in CI → the update workflow stops before committing.
