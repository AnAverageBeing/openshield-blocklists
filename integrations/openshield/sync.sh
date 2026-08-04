#!/usr/bin/env bash
# sync.sh — pull OpenShield feed categories and load them into a running
# OpenShield-XDP instance.
#
# Downloads the published per-category lists and bulk-imports them with
#   openshield blacklist add <file> [ttl_seconds]
# (bulk file import requires OpenShield >= 2.1.1).
#
# Bans are written with a TTL slightly longer than the sync interval, so if
# syncing stops the blocklist expires on its own (fail-open). Feeds upstream
# are rebuilt every 3 hours; syncing every 6 hours is plenty.
#
# Usage:
#   sudo ./sync.sh
#   BLOCKLIST_CATEGORIES="c2 botnets" sudo ./sync.sh
#
# Optional env:
#   BLOCKLIST_REPO_RAW    base raw URL of the repo       (default: this repo)
#   BLOCKLIST_WORKDIR     where lists are staged locally (default /etc/openshield/blocklists)
#   BLOCKLIST_TTL         ban TTL in seconds             (default 86400)
#   BLOCKLIST_CATEGORIES  space-separated category ids   (default: all active)
#   OPENSHIELD_BIN        path to the openshield CLI     (default openshield)
set -euo pipefail

REPO_RAW="${BLOCKLIST_REPO_RAW:-https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main}"
WORKDIR="${BLOCKLIST_WORKDIR:-/etc/openshield/blocklists}"
TTL="${BLOCKLIST_TTL:-86400}"
OPENSHIELD_BIN="${OPENSHIELD_BIN:-openshield}"
CATEGORIES="${BLOCKLIST_CATEGORIES:-botnets malware c2 scanners abuse spam bruteforce ssh-attackers rdp-attackers credential-stuffing web-exploit-scanners exploited-infrastructure high-risk-networks http-proxies socks4-proxies socks5-proxies tor-exit-nodes}"

mkdir -p "$WORKDIR"
V4="$WORKDIR/.sync-ipv4.txt"
V6="$WORKDIR/.sync-ipv6.txt"
: >"$V4"
: >"$V6"

for cat in $CATEGORIES; do
  for fmt in ipv4 ipv4-cidrs; do
    if curl -fsSL --retry 3 --connect-timeout 15 "$REPO_RAW/feeds/$cat/$fmt.txt" >>"$V4" 2>/dev/null; then
      :
    else
      echo "[sync] warn: $cat/$fmt.txt fetch failed (skipped)" >&2
    fi
  done
  for fmt in ipv6 ipv6-cidrs; do
    if curl -fsSL --retry 3 --connect-timeout 15 "$REPO_RAW/feeds/$cat/$fmt.txt" >>"$V6" 2>/dev/null; then
      :
    else
      echo "[sync] warn: $cat/$fmt.txt fetch failed (skipped)" >&2
    fi
  done
done

# The CLI skips '#' comment lines and anything it cannot parse.
echo "[sync] importing $(grep -cv '^#' "$V4" || true) IPv4 + $(grep -cv '^#' "$V6" || true) IPv6 entries (ttl=${TTL}s)"
"$OPENSHIELD_BIN" blacklist add "$V4" "$TTL"
"$OPENSHIELD_BIN" blacklist add "$V6" "$TTL"

echo "[sync] done"
