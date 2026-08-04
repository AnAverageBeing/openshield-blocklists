# Source Policy

Everything about a source is declared in **`configs/sources.json`** — the
only file you ever edit to add, remove, or tune a feed. Categories are
declared in **`configs/categories.json`**.

## Schema

```jsonc
{
  "name": "unique_id",              // used for cache files + metadata
  "url": "https://…",               // http(s) or file:// (tests)
  "category": "abuse",              // must exist in categories.json
  "format": "auto",                 // auto | dshield | abuseipdb (default auto)
  "update_interval": 10800,         // seconds between refetches (default 3h)
  "priority": 100,                  // lower = more trusted; reserved for scoring
  "enabled": true,                  // false keeps config but ignores the source
  "validation": {                   // optional
    "min_entries": 100,             // warn when a fetch yields fewer
    "allow_non_global": false       // keep private/reserved ranges (rare!)
  }
}
```

## Format handlers

| `format` | Input shape |
| --- | --- |
| `auto` | Bare IPs, `ip:port`, `[v6]:port`, CIDRs, URLs with literal-IP hosts, `ip<TAB>count`, `#`/`;` comments. Handles ~all plain-text feeds. |
| `dshield` | `start_ip end_ip prefix_len …` rows (dshield.org block list). |
| `abuseipdb` | AbuseIPDB API plaintext blacklist (needs `ABUSEIPDB_API_KEY`). |

New handlers: add to `FORMATS` in `config.py` and a branch in `parser.py`,
with tests. Most feeds never need one.

## Rules for new sources

1. **Prefer primary sources** over re-aggregations; prefer maintained feeds
   (check the last-update timestamp before submitting).
2. Set a realistic `update_interval` — match the upstream's actual update
   cadence; don't hammer slow-moving lists.
3. Set `min_entries` when a source has a known typical size, so a broken
   upstream shows up as a `warning` in metadata instead of silently
   shrinking the feed.
4. One category per source. If a feed mixes types, put it in the dominant
   category and note it in the PR.
5. Never add sources of private/loopback/reserved space — the validator
   drops them anyway; if a source legitimately needs them, justify
   `allow_non_global` in the PR.
6. Paid/licensed feeds must allow redistribution of the derived IP list.

## Categories

New category = one entry in `configs/categories.json`:

```jsonc
{ "id": "dns-abuse", "name": "DNS Abuse", "description": "…", "status": "active" }
```

Use `status: "planned"` to reserve a category that has no sources yet —
it publishes valid empty feeds so consumers can subscribe early.
