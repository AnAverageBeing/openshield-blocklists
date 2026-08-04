"""Command-line interface.

  openshield-feeds build            fetch + process + publish all feeds
  openshield-feeds verify           offline integrity check of published feeds
  openshield-feeds validate-config  check configs/*.json for errors
  openshield-feeds list-sources     print the source registry

Everything is idempotent: repeated builds with unchanged inputs produce
zero file changes.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .cache import ProcessedCache, RawCache
from .config import ConfigError, Source, load
from .fetcher import fetch_all
from .metadata import build_manifest, category_metadata, write_json
from .models import FEED_FORMATS, SourceResult
from .output import write_feed
from .parser import parse_text
from .pipeline import aggregate, finalize

log = logging.getLogger("openshield-feeds")

#: Refuse to publish when the grand total falls below this floor — protects
#: against mass feed outages or a parsing regression wiping the outputs.
MIN_TOTAL_ENTRIES = 10_000


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── build ───────────────────────────────────────────────────────────────────

def process_source(src: Source, fetch_result, proc_cache: ProcessedCache) -> SourceResult:
    sr = SourceResult(name=src.name, category=src.category, url=src.url, priority=src.priority)
    sr.fetched = fetch_result.fetched
    sr.raw_bytes = len(fetch_result.body or b"")

    if fetch_result.body is None:
        sr.status = fetch_result.status
        sr.detail = fetch_result.detail
        return sr

    t0 = time.perf_counter()
    parsed = proc_cache.read(src.name, fetch_result.raw_sha256, src.format, src.allow_non_global)
    if parsed is None:
        parsed = parse_text(
            fetch_result.body.decode("utf-8", "replace"),
            src.format,
            allow_non_global=src.allow_non_global,
        )
        proc_cache.write(src.name, fetch_result.raw_sha256, src.format, src.allow_non_global, parsed)
    sr.duration_ms = int((time.perf_counter() - t0) * 1000)

    sr.entries = parsed.entries
    sr.candidates = parsed.candidates
    sr.invalid = parsed.invalid
    sr.within_source_dupes = max(0, (parsed.candidates - parsed.invalid) - parsed.entries.total())
    sr.status = fetch_result.status
    sr.detail = fetch_result.detail

    if src.min_entries and parsed.entries.total() < src.min_entries:
        sr.status = "warning"
        note = f"below min_entries ({parsed.entries.total()} < {src.min_entries})"
        sr.detail = f"{sr.detail}; {note}".lstrip("; ")
    return sr


def cmd_build(args) -> int:
    t0 = time.perf_counter()
    root = args.root
    cfg = load(root / "configs")

    sources = [s for s in cfg.sources if s.enabled]
    if args.only:
        wanted = set(args.only.split(","))
        unknown = wanted - {s.name for s in sources}
        if unknown:
            log.error("unknown source(s): %s", ", ".join(sorted(unknown)))
            return 2
        sources = [s for s in sources if s.name in wanted]

    log.info("building feeds: %d sources, %d categories", len(sources), len(cfg.categories))

    raw_cache = RawCache(root / "raw")
    proc_cache = ProcessedCache(root / "processed")
    fetches = fetch_all(sources, raw_cache, force=args.force, no_network=args.no_network)

    results: dict[str, SourceResult] = {}
    for src in sources:
        sr = process_source(src, fetches[src.name], proc_cache)
        results[src.name] = sr
        log.info("[%s] %s: %d entries %s", sr.status, src.name, sr.entries.total(),
                 f"({sr.detail})" if sr.detail else "")

    # ── Aggregate per category (in memory first — publish is all-or-nothing) ──
    generated = utcnow()
    per_category: dict[str, dict] = {}
    grand_total = 0
    for cat_id, cat in cfg.categories.items():
        cat_sources = [results[s.name] for s in cfg.sources_for(cat_id) if s.name in results]
        merged, dupes = aggregate([sr.entries for sr in cat_sources])
        lists = finalize(merged)
        invalid = sum(sr.invalid for sr in cat_sources)
        per_category[cat_id] = {
            "category": cat,
            "sources": cat_sources,
            "lists": lists,
            "duplicates_removed": dupes,
            "invalid_discarded": invalid,
        }
        grand_total += sum(len(v) for v in lists.values())

    if grand_total < args.min_total:
        log.error(
            "grand total %d is below the sanity floor (%d) — refusing to publish; "
            "existing feeds/ left untouched",
            grand_total, args.min_total,
        )
        return 1

    # ── Publish ──
    feeds_dir = root / "feeds"
    metadata_dir = root / "metadata"
    feed_metas = []
    changed_files = 0
    for cat_id in sorted(per_category):
        data = per_category[cat_id]
        t_cat = time.perf_counter()
        records = [
            write_feed(feeds_dir, root, cat_id, data["category"].name, fmt, data["lists"][fmt])
            for fmt in FEED_FORMATS
        ]
        changed_files += sum(1 for r in records if r.changed)
        meta = category_metadata(
            data["category"], generated, records, data["sources"],
            data["duplicates_removed"], data["invalid_discarded"],
            int((time.perf_counter() - t_cat) * 1000),
        )
        if write_json(metadata_dir / f"{cat_id}.json", meta):
            changed_files += 1
        feed_metas.append(meta)
        log.info(
            "feed %-24s %8d entries (%d sources, %d dupes removed)",
            cat_id, meta["totals"]["all"], len(data["sources"]), data["duplicates_removed"],
        )

    manifest = build_manifest(generated, feed_metas, list(results.values()),
                              int((time.perf_counter() - t0) * 1000))
    if write_json(metadata_dir / "manifest.json", manifest):
        changed_files += 1

    log.info(
        "done in %.1fs: %s total entries across %d feeds, %d file(s) changed",
        time.perf_counter() - t0, f"{grand_total:,}", len(feed_metas), changed_files,
    )
    return 0


# ─── verify ──────────────────────────────────────────────────────────────────

def _verify_file(path: Path, fmt: str, problems: list[str]) -> tuple[int, str] | None:
    """Validate one feed file. Returns (entry_count, sha256) or None."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        problems.append(f"{path}: unreadable: {exc}")
        return None
    digest = hashlib.sha256(data).hexdigest()

    is_cidr = fmt.endswith("-cidrs")
    version = 6 if fmt.startswith("ipv6") else 4
    prev = -1
    seen: set[str] = set()
    count = 0
    for lineno, raw in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if is_cidr:
                obj = ipaddress.ip_network(line, strict=False)
            else:
                obj = ipaddress.ip_address(line)
        except ValueError:
            problems.append(f"{path}:{lineno}: unparseable entry '{line}'")
            continue
        if ("/" in line) != is_cidr:
            problems.append(f"{path}:{lineno}: wrong shape for format {fmt}: '{line}'")
        if obj.version != version:
            problems.append(f"{path}:{lineno}: wrong family for format {fmt}: '{line}'")
        if line in seen:
            problems.append(f"{path}:{lineno}: duplicate entry '{line}'")
        seen.add(line)
        key = int(obj.network_address if is_cidr else obj)
        if key < prev:
            problems.append(f"{path}:{lineno}: ordering violated at '{line}'")
        prev = key
        count += 1
    return count, digest


def cmd_verify(args) -> int:
    root = args.root
    feeds_dir = root / "feeds"
    metadata_dir = root / "metadata"
    problems: list[str] = []

    manifest_path = metadata_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.error("manifest unreadable: %s", exc)
        return 1

    manifest_feeds = {f["category"]: f for f in manifest.get("feeds", [])}
    on_disk = sorted(p.name for p in feeds_dir.iterdir() if p.is_dir()) if feeds_dir.exists() else []

    for cat in sorted(set(manifest_feeds) | set(on_disk)):
        cat_dir = feeds_dir / cat
        if cat not in manifest_feeds:
            problems.append(f"feeds/{cat}: present on disk but missing from manifest")
            continue
        if not cat_dir.is_dir():
            problems.append(f"feeds/{cat}: in manifest but missing on disk")
            continue

        files = sorted(p.name for p in cat_dir.iterdir() if p.suffix == ".txt")
        expected = sorted(f"{fmt}.txt" for fmt in FEED_FORMATS)
        if files != expected:
            problems.append(f"feeds/{cat}: unexpected file set {files} (expected {expected})")

        meta_path = metadata_dir / f"{cat}.json"
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"metadata/{cat}.json: unreadable: {exc}")
            continue

        for fmt in FEED_FORMATS:
            path = cat_dir / f"{fmt}.txt"
            if not path.exists():
                continue
            result = _verify_file(path, fmt, problems)
            if result is None:
                continue
            count, digest = result
            fmeta = meta.get("files", {}).get(fmt, {})
            if fmeta.get("entries") != count:
                problems.append(
                    f"feeds/{cat}/{fmt}.txt: metadata entries {fmeta.get('entries')} != actual {count}"
                )
            if fmeta.get("sha256") != digest:
                problems.append(f"feeds/{cat}/{fmt}.txt: sha256 mismatch with metadata")

    # Manifest totals consistency.
    sums = {"ipv4": 0, "ipv6": 0, "cidrs_v4": 0, "cidrs_v6": 0, "all": 0}
    for f in manifest_feeds.values():
        for key in sums:
            sums[key] += f.get("totals", {}).get(key, 0)
    for key, want in sums.items():
        got = manifest.get("totals", {}).get(key)
        if got != want:
            problems.append(f"manifest totals.{key}: {got} != sum of feeds {want}")

    if problems:
        log.error("verification FAILED with %d problem(s):", len(problems))
        for p in problems:
            log.error("  - %s", p)
        return 1
    log.info("verification OK: %d feeds, %d total entries", len(manifest_feeds), sums["all"])
    return 0


# ─── misc commands ───────────────────────────────────────────────────────────

def cmd_validate_config(args) -> int:
    cfg = load(args.root / "configs")
    active = [s for s in cfg.sources if s.enabled]
    log.info(
        "config OK: %d categories (%d active, %d planned), %d sources (%d enabled)",
        len(cfg.categories),
        sum(1 for c in cfg.categories.values() if c.status == "active"),
        sum(1 for c in cfg.categories.values() if c.status == "planned"),
        len(cfg.sources),
        len(active),
    )
    return 0


def cmd_list_sources(args) -> int:
    cfg = load(args.root / "configs")
    for src in sorted(cfg.sources, key=lambda s: (s.category, s.priority, s.name)):
        state = "on " if src.enabled else "off"
        print(f"{src.category:<24} {src.name:<28} {state} {src.format:<9} "
              f"every {src.update_interval:>6}s  p{src.priority:<4} {src.url}")
    return 0


# ─── entry point ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openshield-feeds", description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(os.environ.get("OPENSHIELD_FEEDS_ROOT", ".")).resolve(),
        help="repository root (default: cwd or $OPENSHIELD_FEEDS_ROOT)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("build", help="fetch sources and publish feeds")
    p.add_argument("--force", action="store_true", help="ignore update intervals, refetch everything")
    p.add_argument("--no-network", action="store_true", help="build from caches only")
    p.add_argument("--only", metavar="a,b,c", help="build only these sources")
    p.add_argument("--min-total", type=int, default=MIN_TOTAL_ENTRIES,
                   help="sanity floor for total published entries (default %(default)s)")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("verify", help="offline integrity check of published feeds")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("validate-config", help="validate configs/*.json")
    p.set_defaults(func=cmd_validate_config)

    p = sub.add_parser("list-sources", help="print the source registry")
    p.set_defaults(func=cmd_list_sources)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    try:
        return args.func(args)
    except ConfigError as exc:
        log.error("config error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
