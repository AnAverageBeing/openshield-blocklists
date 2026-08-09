"""L7 attack-pattern feed validation.

``feeds/l7-patterns/patterns.txt`` is a HAND-CURATED feed (not built from
remote sources by the pipeline): one drop signature per line,
pipe-separated:

  name|proto|port|port_is_src|offset|min_payload|max_payload|pattern_hex|mask_hex

OpenShield-XDP loads these into the kernel l7_sig_map (16 slots) and drops
matching packets at XDP. A wrong byte pattern false-positives on legitimate
servers, so validation here is strict and mirrors the kernel engine
semantics exactly:

  proto        ``udp`` | ``tcp``
  port         1-65535; matched against the SOURCE port when port_is_src=1,
               else the destination port
  port_is_src  ``0`` | ``1``
  offset       0-255 payload-relative (the engine can only match offsets
               0-248 because it reads 8 bytes from offset; 249-255 are
               accepted by the format but can never fire)
  min_payload  0-65535
  max_payload  0 (no cap) or >= min_payload, <= 65535
  pattern_hex  1-8 bytes of hex (2-16 chars)
  mask_hex     empty (= exact match, all-ff) or the same byte length as
               pattern_hex. The engine tests (byte & mask) == pattern, so
               pattern bits outside the mask can never match and are
               rejected as an authoring error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

FIELD_COUNT = 9
MAX_PATTERN_BYTES = 8


@dataclass(frozen=True)
class Pattern:
    name: str
    proto: str
    port: int
    port_is_src: bool
    offset: int
    min_payload: int
    max_payload: int
    pattern: bytes
    mask: bytes  # empty = exact match (all-ff)


def _parse_int(field: str, value: str, lo: int, hi: int) -> int:
    try:
        n = int(value, 10)
    except ValueError:
        raise ValueError(f"{field} {value!r} is not an integer")
    if not lo <= n <= hi:
        raise ValueError(f"{field} {n} out of range ({lo}-{hi})")
    return n


def _parse_hex(field: str, value: str) -> bytes:
    if len(value) % 2 != 0 or not HEX_RE.match(value):
        raise ValueError(f"{field} {value!r} is not even-length hex")
    return bytes.fromhex(value)


def parse_line(line: str) -> Pattern:
    """Parse and strictly validate one signature line. Raises ValueError."""
    fields = line.split("|")
    if len(fields) != FIELD_COUNT:
        raise ValueError(f"expected {FIELD_COUNT} pipe-separated fields, got {len(fields)}")
    name, proto, port, port_is_src, offset, min_pl, max_pl, pattern_hex, mask_hex = (
        f.strip() for f in fields
    )

    if not NAME_RE.match(name):
        raise ValueError(f"name {name!r} must be 1-64 chars of [A-Za-z0-9._-]")
    if proto not in ("udp", "tcp"):
        raise ValueError(f"proto {proto!r} must be udp or tcp")
    if port_is_src not in ("0", "1"):
        raise ValueError(f"port_is_src {port_is_src!r} must be 0 or 1")

    pattern = _parse_hex("pattern_hex", pattern_hex)
    if not 1 <= len(pattern) <= MAX_PATTERN_BYTES:
        raise ValueError(f"pattern must be 1-{MAX_PATTERN_BYTES} bytes, got {len(pattern)}")

    mask = b""
    if mask_hex != "":
        mask = _parse_hex("mask_hex", mask_hex)
        if len(mask) != len(pattern):
            raise ValueError(
                f"mask length {len(mask)} != pattern length {len(pattern)}"
            )
        for i, (p, m) in enumerate(zip(pattern, mask)):
            if p & m != p:
                raise ValueError(
                    f"pattern byte {i} (0x{p:02x}) has bits outside mask (0x{m:02x}) "
                    "— the engine compares (byte & mask) == pattern, so this can never match"
                )

    sig = Pattern(
        name=name,
        proto=proto,
        port=_parse_int("port", port, 1, 65535),
        port_is_src=port_is_src == "1",
        offset=_parse_int("offset", offset, 0, 255),
        min_payload=_parse_int("min_payload", min_pl, 0, 65535),
        max_payload=_parse_int("max_payload", max_pl, 0, 65535),
        pattern=pattern,
        mask=mask,
    )
    if sig.max_payload != 0 and sig.max_payload < sig.min_payload:
        raise ValueError(
            f"max_payload {sig.max_payload} < min_payload {sig.min_payload}"
        )
    return sig


def validate_text(text: str) -> tuple[list[Pattern], list[str]]:
    """Validate a feed body. Returns (patterns, problems-with-line-numbers)."""
    patterns: list[Pattern] = []
    problems: list[str] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            sig = parse_line(line)
        except ValueError as exc:
            problems.append(f"line {lineno}: {exc}")
            continue
        if sig.name in seen:
            problems.append(f"line {lineno}: duplicate signature name {sig.name!r}")
            continue
        seen.add(sig.name)
        patterns.append(sig)
    return patterns, problems


def validate_file(path: Path) -> tuple[list[Pattern], list[str]]:
    """Validate a patterns feed file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"{path}: unreadable: {exc}"]
    return validate_text(text)
