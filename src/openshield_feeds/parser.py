"""Line-oriented feed parsing.

Extracts IP/CIDR candidates from arbitrary upstream text formats, always
stripping ports — only the source address matters for XDP blocking.

Supported shapes (format "auto"):
  1.2.3.4                     bare IPv4
  2001:db8::1                 bare IPv6
  1.2.3.4:8080                IPv4 with port (port stripped)
  [2001:db8::1]:443           IPv6 with port (port stripped)
  1.2.3.0/24                  CIDR
  https://1.2.3.4/path        URL — host kept only if it is a literal IP
  1.2.3.4<TAB>7               ipsum-style "ip count"
  # comment / ; comment       full-line and inline comments
  anything else               ignored; an IPv4 regex fallback sweeps
                              lines with embedded junk

Special formats:
  dshield    "start_ip end_ip prefix_len as name country" rows
  abuseipdb  plaintext body, one IP per line (API key handled by fetcher)
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .models import EntrySet, ParseResult
from .validator import keep

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:/[0-9]{1,2})?\b"
)


def _candidate(tok: str):
    """Parse one token into an IP/network object, or return None."""
    if not tok:
        return None

    if "://" in tok:
        try:
            host = urlsplit(tok).hostname
        except ValueError:
            return None
        if not host:
            return None
        tok = host

    tok = tok.strip().strip(",;\"'")
    if not tok:
        return None

    if tok.startswith("["):
        end = tok.find("]")
        tok = tok[1:end] if end > 0 else tok[1:]
    elif tok.count(":") == 1:
        host, _, port = tok.rpartition(":")
        if port.isdigit() and host:
            tok = host

    if not tok:
        return None

    try:
        if "/" in tok:
            return ipaddress.ip_network(tok, strict=False)
        return ipaddress.ip_address(tok)
    except ValueError:
        return None


def _tokens(line: str, fmt: str):
    if fmt == "dshield":
        fields = line.split()
        if len(fields) >= 3 and fields[2].isdigit():
            yield f"{fields[0]}/{fields[2]}"
        return
    for tok in re.split(r"[\s,|]+", line):
        yield tok
    # Fallback sweep for embedded junk the tokenizer may have missed.
    for m in IPV4_RE.finditer(line):
        yield m.group(0)


def parse_text(text: str, fmt: str = "auto", *, allow_non_global: bool = False) -> ParseResult:
    result = ParseResult()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        for marker in ("#", ";"):
            idx = line.find(marker)
            if idx > 0:
                line = line[:idx]
        line = line.strip()
        if not line:
            continue
        seen_in_line: set[str] = set()
        for tok in _tokens(line, fmt):
            cand = _candidate(tok)
            if cand is None:
                continue
            # The tokenizer and the regex fallback both match clean IPv4
            # lines — count each distinct candidate once per line.
            key = str(cand)
            if key in seen_in_line:
                continue
            seen_in_line.add(key)
            result.candidates += 1
            if keep(cand, allow_non_global=allow_non_global):
                result.entries.add(cand)
            else:
                result.invalid += 1
    return result
