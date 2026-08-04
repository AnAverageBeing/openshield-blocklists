"""Deterministic, atomic feed file writers.

Feed files contain no volatile data (no timestamps), so identical inputs
produce byte-identical files and quiet runs create no git churn. Writes are
atomic (tmp + rename) and skipped entirely when content is unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

FORMAT_LABELS = {
    "ipv4": "IPv4 addresses",
    "ipv6": "IPv6 addresses",
    "ipv4-cidrs": "IPv4 CIDR ranges",
    "ipv6-cidrs": "IPv6 CIDR ranges",
}


@dataclass
class FileRecord:
    format: str
    path: str       # repo-relative
    entries: int
    sha256: str
    bytes: int
    changed: bool


def write_feed(
    feeds_dir: Path,
    repo_root: Path,
    category: str,
    category_name: str,
    fmt: str,
    items: list[str],
) -> FileRecord:
    path = feeds_dir / category / f"{fmt}.txt"
    header = (
        f"# openshield-blocklists :: {category} :: {FORMAT_LABELS[fmt]}\n"
        f"# category: {category_name} | one entry per line | spec: docs/FEED-FORMATS.md\n"
        f"# entries: {len(items)}\n"
    )
    body = header + ("".join(f"{item}\n" for item in items))
    data = body.encode()
    digest = hashlib.sha256(data).hexdigest()

    path.parent.mkdir(parents=True, exist_ok=True)
    changed = True
    try:
        changed = path.read_bytes() != data
    except OSError:
        changed = True
    if changed:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    return FileRecord(fmt, str(path.relative_to(repo_root)), len(items), digest, len(data), changed)
