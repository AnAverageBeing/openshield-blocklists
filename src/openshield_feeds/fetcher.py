"""Concurrent, cache-aware source fetching.

Policy:
  * a source is only re-fetched once its update_interval has elapsed
    (otherwise the committed raw/ cache is reused) — incremental updates;
  * on fetch failure the last-good cached body is used (stale-cache);
  * an empty body is treated as a soft failure;
  * format-specific auth (AbuseIPDB) lives here, not in the parser.
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import time
from dataclasses import dataclass
from urllib.request import Request, urlopen

from .cache import RawCache
from .config import Source

USER_AGENT = "openshield-feeds/1.0 (+https://github.com/AnAverageBeing/openshield-blocklists)"
TIMEOUT = 30
WORKERS = 16


class FetchError(Exception):
    pass


@dataclass
class FetchResult:
    status: str                 # ok | cache | stale-cache | failed | skipped
    body: bytes | None
    detail: str = ""
    fetched: bool = False       # True when the network was actually hit
    raw_sha256: str | None = None


def _http_get(url: str, headers: dict) -> bytes:
    req = Request(url, headers=headers)
    last = "unknown error"
    for attempt in (1, 2):
        try:
            with urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read()
        except Exception as exc:  # HTTPError, URLError, timeout, ...
            last = f"{type(exc).__name__}: {exc}"
            if attempt == 1:
                time.sleep(2)
    raise FetchError(last)


def _from_cache(src: Source, cache: RawCache, status: str, detail: str, fetched: bool) -> FetchResult:
    body, meta = cache.read(src.name)
    if body is not None:
        return FetchResult(status, body, detail, fetched=fetched, raw_sha256=meta.get("sha256"))
    return FetchResult("failed", None, detail + " (no cache available)", fetched=fetched)


def fetch_one(src: Source, cache: RawCache, *, force: bool = False, no_network: bool = False) -> FetchResult:
    if src.format == "abuseipdb" and not os.environ.get("ABUSEIPDB_API_KEY"):
        return FetchResult("skipped", None, "ABUSEIPDB_API_KEY not set")

    age = cache.age(src.name)
    if not force and age is not None and age < src.update_interval:
        return _from_cache(src, cache, "cache", f"fresh cache ({int(age)}s old < interval {src.update_interval}s)", fetched=False)

    if no_network:
        return _from_cache(src, cache, "cache", "network disabled, using cache", fetched=False)

    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain, */*"}
    if src.format == "abuseipdb":
        headers["Key"] = os.environ["ABUSEIPDB_API_KEY"]

    try:
        body = _http_get(src.url, headers)
    except FetchError as exc:
        return _from_cache(src, cache, "stale-cache", f"fetch failed ({exc}); using stale cache", fetched=True)

    if not body.strip():
        return _from_cache(src, cache, "stale-cache", "empty response; using stale cache", fetched=True)

    digest = cache.write(src.name, body, src.url)
    return FetchResult("ok", body, "", fetched=True, raw_sha256=digest)


def fetch_all(
    sources: list[Source],
    cache: RawCache,
    *,
    force: bool = False,
    no_network: bool = False,
    workers: int = WORKERS,
) -> dict[str, FetchResult]:
    results: dict[str, FetchResult] = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(fetch_one, src, cache, force=force, no_network=no_network): src
            for src in sources
        }
        for fut in cf.as_completed(futures):
            results[futures[fut].name] = fut.result()
    return results
