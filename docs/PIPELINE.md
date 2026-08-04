# Update Pipeline

Stage-by-stage description of `openshield-feeds build`.

## 1. Configure

`configs/categories.json` and `configs/sources.json` are loaded and
cross-validated (unique names, known categories, known formats, sane
intervals). Any error aborts the run before any network traffic.

## 2. Fetch (incremental)

- Sources are fetched concurrently (16 workers, 30s timeout, one retry).
- A source is only re-fetched when its `update_interval` has elapsed;
  otherwise the committed `raw/` body is reused.
- On failure (or empty body), the last-good cached body is used and the
  source is marked `stale-cache`.
- `format: abuseipdb` sources need the `ABUSEIPDB_API_KEY` env var;
  without it they are `skipped`.

## 3. Parse

Every line is normalized (trimmed, comments removed) and candidates are
extracted — bare IPs, `ip:port`, `[v6]:port`, CIDRs, URLs (host kept only
when it is a literal IP), `ip<TAB>count` rows, DShield `start end prefix`
rows, plus a regex sweep for embedded junk. **Ports are always stripped.**
Parsing results are cached in `processed/` keyed by the raw body hash, so
unchanged sources are never re-parsed.

## 4. Validate

- Only publicly routable unicast entries survive: private, loopback,
  link-local, multicast, unspecified, reserved, CGNAT, documentation and
  benchmarking ranges are all discarded.
- Subnets must be ≥ /8 (v4) or ≥ /32 (v6).
- Per-source escape hatch: `validation.allow_non_global` (prefix guards
  always stay on).
- Every discarded candidate is counted into `invalid_discarded`.

## 5. Aggregate

- Exact de-duplication across all sources of a category.
- Overlapping/adjacent subnets are collapsed (`collapse_addresses`).
- Single IPs already covered by a blocked subnet are subtracted.
- `duplicates_removed` is reported per category and globally.

## 6. Publish (deterministic, atomic)

- The four lists per category are sorted numerically and written via
  tmp-file + rename; unchanged files are not touched.
- Feed files carry no timestamps → byte-reproducible.
- A sanity floor (default 10 000 total entries) makes publication
  all-or-nothing: below it, nothing is written and the run fails.

## 7. Metadata + verify

- `metadata/<category>.json` per feed, `metadata/manifest.json` globally.
- Metadata is only rewritten when non-volatile content changes (timestamps
  and per-run statuses are excluded from the comparison), so quiet runs
  produce **zero commits**.
- `openshield-feeds verify` re-checks everything offline: every line parses
  and matches its declared family/format, files are sorted and unique,
  counts and sha256 match metadata, manifest totals match the feeds.
  The update workflow runs it before committing.

## Scheduling

`.github/workflows/update.yml` runs every 3 hours (cron `41 */3 * * *`) and
on manual dispatch (optional `--force` refetch, optional release creation).
`.github/workflows/ci.yml` runs the test suite + config validation on
pushes and PRs that touch code, tests, or configs.
