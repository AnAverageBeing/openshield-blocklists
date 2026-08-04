"""Per-feed metadata and the global manifest.

Metadata files carry all volatile data (timestamps, durations) so feed
files stay byte-reproducible. To keep quiet runs commit-free, a metadata
file is only rewritten when its non-volatile content actually changed.

Every feed gets a content-addressed version ("sha256:...") derived from its
four file hashes — identical content always yields the identical version.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__
from .config import Category
from .models import FEED_FORMATS, SourceResult
from .output import FileRecord

SCHEMA = 1
REPO_URL = "https://github.com/AnAverageBeing/openshield-blocklists"
RAW_BASE = "https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main"

#: Key paths excluded from the change comparison (always written on real writes).
#: Per-run fetch status (ok/cache/stale) and timings fluctuate without any
#: content change, so they must not dirty the repository on quiet runs.
_VOLATILE = (
    ("generated",),
    ("processing", "duration_ms"),
    ("processing", "by_status"),
    ("sources", "by_status"),
    ("sources", "stats", "status"),
    ("sources", "stats", "detail"),
    ("sources", "stats", "fetched"),
    ("sources", "stats", "duration_ms"),
)


def _strip_volatile(node, path=()):
    if isinstance(node, dict):
        return {
            k: _strip_volatile(v, path + (k,))
            for k, v in node.items()
            if path + (k,) not in _VOLATILE
        }
    if isinstance(node, list):
        return [_strip_volatile(v, path) for v in node]
    return node


def write_json(path: Path, payload: dict) -> bool:
    """Write only when non-volatile content changed. Returns changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        old = json.loads(path.read_text())
        if _strip_volatile(old) == _strip_volatile(payload):
            return False
    except (OSError, json.JSONDecodeError):
        pass
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    tmp.replace(path)
    return True


def feed_version(records: list[FileRecord]) -> str:
    """Content-addressed feed version (ordered by FEED_FORMATS)."""
    h = hashlib.sha256()
    for rec in records:
        h.update(rec.format.encode())
        h.update(b"\0")
        h.update(rec.sha256.encode())
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def category_metadata(
    category: Category,
    generated: str,
    records: list[FileRecord],
    sources: list[SourceResult],
    duplicates_removed: int,
    invalid_discarded: int,
    duration_ms: int,
) -> dict:
    files = {
        rec.format: {
            "path": rec.path,
            "url": f"{RAW_BASE}/{rec.path}",
            "entries": rec.entries,
            "sha256": rec.sha256,
            "bytes": rec.bytes,
        }
        for rec in records
    }
    status_counts: dict[str, int] = {}
    for sr in sources:
        status_counts[sr.status] = status_counts.get(sr.status, 0) + 1
    totals = {
        "ipv4": files["ipv4"]["entries"],
        "ipv6": files["ipv6"]["entries"],
        "cidrs_v4": files["ipv4-cidrs"]["entries"],
        "cidrs_v6": files["ipv6-cidrs"]["entries"],
    }
    return {
        "schema": SCHEMA,
        "feed": category.id,
        "name": category.name,
        "description": category.description,
        "status": category.status,
        "generated": generated,
        "version": feed_version(records),
        "sources": {
            "count": len(sources),
            "by_status": status_counts,
            "stats": [
                sr.stats_dict() for sr in sorted(sources, key=lambda s: (s.priority, s.name))
            ],
        },
        "totals": {**totals, "all": sum(totals.values())},
        "processing": {
            "duplicates_removed": duplicates_removed,
            "invalid_discarded": invalid_discarded,
            "duration_ms": duration_ms,
        },
        "files": files,
    }


def build_manifest(
    generated: str,
    feed_metas: list[dict],
    all_sources: list[SourceResult],
    duration_ms: int,
) -> dict:
    totals = {"ipv4": 0, "ipv6": 0, "cidrs_v4": 0, "cidrs_v6": 0, "all": 0}
    for meta in feed_metas:
        for key in totals:
            totals[key] += meta["totals"][key]

    status_counts: dict[str, int] = {}
    for sr in all_sources:
        status_counts[sr.status] = status_counts.get(sr.status, 0) + 1

    return {
        "schema": SCHEMA,
        "generator": f"openshield-feeds/{__version__}",
        "generated": generated,
        "repository": REPO_URL,
        "feed_count": len(feed_metas),
        "totals": totals,
        "processing": {
            "sources": len(all_sources),
            "by_status": status_counts,
            "duplicates_removed": sum(m["processing"]["duplicates_removed"] for m in feed_metas),
            "invalid_discarded": sum(m["processing"]["invalid_discarded"] for m in feed_metas),
            "duration_ms": duration_ms,
        },
        "feeds": [
            {
                "category": m["feed"],
                "name": m["name"],
                "description": m["description"],
                "status": m["status"],
                "version": m["version"],
                "totals": m["totals"],
                "sources": m["sources"]["count"],
                "metadata": f"metadata/{m['feed']}.json",
                "files": m["files"],
            }
            for m in sorted(feed_metas, key=lambda m: m["feed"])
        ],
    }
