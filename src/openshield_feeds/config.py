"""Configuration loading and validation.

Two JSON files drive everything:

  configs/categories.json — category registry (id, name, description, status)
  configs/sources.json    — source registry (one edit = one new feed)

No source is ever hardcoded in the codebase.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

#: Parser format handlers. "auto" handles plain IPs, ip:port, [v6]:port,
#: CIDRs, URLs (host kept only if it is an IP) and ip<TAB>count rows.
FORMATS = frozenset({"auto", "dshield", "abuseipdb"})

CATEGORY_STATUSES = frozenset({"active", "planned"})


class ConfigError(Exception):
    """Raised for any invalid configuration."""


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    category: str
    format: str = "auto"
    update_interval: int = 10_800  # seconds between refetches
    priority: int = 100            # lower = more trusted (reserved for scoring)
    enabled: bool = True
    min_entries: int = 0           # warn if a fetch yields fewer
    allow_non_global: bool = False  # escape hatch: keep private/reserved ranges

    @classmethod
    def from_dict(cls, raw: dict, *, index: int) -> "Source":
        if not isinstance(raw, dict):
            raise ConfigError(f"sources[{index}]: must be an object")
        name = raw.get("name")
        url = raw.get("url")
        category = raw.get("category")
        if not name or not isinstance(name, str):
            raise ConfigError(f"sources[{index}]: missing or invalid 'name'")
        if not url or not isinstance(url, str):
            raise ConfigError(f"source '{name}': missing or invalid 'url'")
        scheme = urlsplit(url).scheme
        if scheme not in ("http", "https", "file"):
            raise ConfigError(f"source '{name}': unsupported url scheme '{scheme}'")
        if not category or not isinstance(category, str):
            raise ConfigError(f"source '{name}': missing or invalid 'category'")

        fmt = raw.get("format", "auto")
        if fmt not in FORMATS:
            raise ConfigError(f"source '{name}': unknown format '{fmt}' (one of {sorted(FORMATS)})")

        interval = raw.get("update_interval", 10_800)
        if not isinstance(interval, int) or interval < 0:
            raise ConfigError(f"source '{name}': update_interval must be a non-negative integer")

        priority = raw.get("priority", 100)
        if not isinstance(priority, int):
            raise ConfigError(f"source '{name}': priority must be an integer")

        validation = raw.get("validation", {}) or {}
        if not isinstance(validation, dict):
            raise ConfigError(f"source '{name}': validation must be an object")
        min_entries = validation.get("min_entries", 0)
        if not isinstance(min_entries, int) or min_entries < 0:
            raise ConfigError(f"source '{name}': validation.min_entries must be a non-negative integer")

        return cls(
            name=name,
            url=url,
            category=category,
            format=fmt,
            update_interval=interval,
            priority=priority,
            enabled=bool(raw.get("enabled", True)),
            min_entries=min_entries,
            allow_non_global=bool(validation.get("allow_non_global", False)),
        )


@dataclass(frozen=True)
class Category:
    id: str
    name: str
    description: str = ""
    status: str = "active"  # active | planned

    @classmethod
    def from_dict(cls, raw: dict, *, index: int) -> "Category":
        if not isinstance(raw, dict):
            raise ConfigError(f"categories[{index}]: must be an object")
        cid = raw.get("id")
        if not cid or not isinstance(cid, str):
            raise ConfigError(f"categories[{index}]: missing or invalid 'id'")
        status = raw.get("status", "active")
        if status not in CATEGORY_STATUSES:
            raise ConfigError(f"category '{cid}': unknown status '{status}'")
        return cls(
            id=cid,
            name=raw.get("name", cid),
            description=raw.get("description", ""),
            status=status,
        )


@dataclass
class Config:
    categories: dict[str, Category] = field(default_factory=dict)
    sources: list[Source] = field(default_factory=list)

    def sources_for(self, category_id: str) -> list[Source]:
        return [s for s in self.sources if s.category == category_id and s.enabled]


def load(configs_dir: Path) -> Config:
    """Load and cross-validate both config files."""
    cfg = Config()

    categories_file = configs_dir / "categories.json"
    sources_file = configs_dir / "sources.json"
    try:
        categories_raw = json.loads(categories_file.read_text())["categories"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise ConfigError(f"cannot load {categories_file}: {exc}") from exc
    try:
        sources_raw = json.loads(sources_file.read_text())["sources"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise ConfigError(f"cannot load {sources_file}: {exc}") from exc

    for i, raw in enumerate(categories_raw):
        cat = Category.from_dict(raw, index=i)
        if cat.id in cfg.categories:
            raise ConfigError(f"duplicate category id '{cat.id}'")
        cfg.categories[cat.id] = cat

    seen: set[str] = set()
    for i, raw in enumerate(sources_raw):
        src = Source.from_dict(raw, index=i)
        if src.name in seen:
            raise ConfigError(f"duplicate source name '{src.name}'")
        seen.add(src.name)
        if src.category not in cfg.categories:
            raise ConfigError(
                f"source '{src.name}': unknown category '{src.category}' "
                f"(declare it in categories.json first)"
            )
        cfg.sources.append(src)

    return cfg
