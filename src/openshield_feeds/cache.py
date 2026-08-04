"""On-disk caches enabling incremental updates.

raw/        last successfully fetched body per source (committed as the
            last-good fallback) + JSON freshness sidecar (runner-local,
            git-ignored — committing timestamps would dirty every run)
processed/  parsed entries per source, keyed by the raw body hash
            (fully content-derived, committed)

On a fresh checkout no sidecar exists, so every source is fetched once;
afterwards sources are only re-fetched once their update_interval has
elapsed. A temporary upstream outage always falls back to the cached body.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from pathlib import Path

from .models import EntrySet, ParseResult


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RawCache:
    def __init__(self, raw_dir: Path):
        self.dir = raw_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def _body(self, name: str) -> Path:
        return self.dir / f"{name}.txt"

    def _meta(self, name: str) -> Path:
        return self.dir / f"{name}.json"

    def meta(self, name: str) -> dict:
        try:
            return json.loads(self._meta(name).read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def age(self, name: str) -> float | None:
        """Seconds since the cached body was fetched; None if never fetched."""
        ts = self.meta(name).get("fetched_at")
        return None if ts is None else time.time() - float(ts)

    def read(self, name: str) -> tuple[bytes | None, dict]:
        try:
            return self._body(name).read_bytes(), self.meta(name)
        except OSError:
            return None, {}

    def write(self, name: str, body: bytes, url: str) -> str:
        digest = sha256_bytes(body)
        tmp = self._body(name).with_suffix(".tmp")
        tmp.write_bytes(body)
        tmp.replace(self._body(name))
        self._meta(name).write_text(
            json.dumps(
                {"url": url, "fetched_at": int(time.time()), "sha256": digest, "bytes": len(body)},
                indent=2,
            )
            + "\n"
        )
        return digest


class ProcessedCache:
    """Skips re-parsing when a source's raw body hasn't changed."""

    def __init__(self, processed_dir: Path):
        self.dir = processed_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.json"

    @staticmethod
    def _key(raw_sha256: str, fmt: str, allow_non_global: bool) -> str:
        return sha256_bytes(f"{raw_sha256}|{fmt}|{allow_non_global}".encode())

    def read(self, name: str, raw_sha256: str | None, fmt: str, allow_non_global: bool) -> ParseResult | None:
        if not raw_sha256:
            return None
        try:
            data = json.loads(self._path(name).read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if data.get("key") != self._key(raw_sha256, fmt, allow_non_global):
            return None
        try:
            entries = EntrySet(
                ipv4={ipaddress.ip_address(x) for x in data["entries"]["ipv4"]},
                ipv6={ipaddress.ip_address(x) for x in data["entries"]["ipv6"]},
                cidr4={ipaddress.ip_network(x) for x in data["entries"]["cidr4"]},
                cidr6={ipaddress.ip_network(x) for x in data["entries"]["cidr6"]},
            )
        except (KeyError, ValueError):
            return None
        return ParseResult(entries=entries, candidates=data.get("candidates", 0), invalid=data.get("invalid", 0))

    def write(self, name: str, raw_sha256: str | None, fmt: str, allow_non_global: bool, result: ParseResult) -> None:
        if not raw_sha256:
            return
        payload = {
            "key": self._key(raw_sha256, fmt, allow_non_global),
            "candidates": result.candidates,
            "invalid": result.invalid,
            "entries": {
                "ipv4": sorted(str(x) for x in result.entries.ipv4),
                "ipv6": sorted(str(x) for x in result.entries.ipv6),
                "cidr4": sorted(str(x) for x in result.entries.cidr4),
                "cidr6": sorted(str(x) for x in result.entries.cidr6),
            },
        }
        tmp = self._path(name).with_suffix(".tmp")
        tmp.write_text(json.dumps(payload))
        tmp.replace(self._path(name))
