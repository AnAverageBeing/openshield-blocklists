# Consuming the Feeds

## Discovery

Start at `metadata/manifest.json` — it lists every feed with totals,
content version, and direct download URLs:

```
https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/metadata/manifest.json
```

Direct file URLs follow the pattern:

```
https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/feeds/<category>/<format>.txt
```

e.g. `…/feeds/c2/ipv4.txt`, `…/feeds/socks5-proxies/ipv4.txt`.

## Rules of thumb

- **Cache locally.** Poll at most every 1–3 hours; use the `sha256` in the
  manifest to skip no-op downloads.
- **Pick categories deliberately.** `tor-exit-nodes` and the proxy
  categories also block legitimate privacy users; `abuse` is broad and may
  contain shared hosting. Combine what matches your threat model.
- **Keep an emergency whitelist** for your own infrastructure.
- Load `ipv4.txt`/`ipv6.txt` into hash maps and `*-cidrs.txt` into an LPM
  trie — never expand large CIDRs into individual addresses.

## OpenShield-XDP

`integrations/openshield/sync.sh` downloads the active categories and
bulk-loads them into the XDP ban maps:

```bash
sudo curl -fsSL https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/integrations/openshield/sync.sh \
  -o /usr/local/bin/openshield-blocklist-sync
sudo chmod +x /usr/local/bin/openshield-blocklist-sync
sudo openshield-blocklist-sync
```

- Requires OpenShield ≥ 2.1.1 (`openshield blacklist add <file>` bulk import).
- Bans get a TTL (`BLOCKLIST_TTL`, default 24h) refreshed on every sync —
  stop syncing and the blocklist expires by itself (fail-open).
- `BLOCKLIST_CATEGORIES="c2 botnets"` overrides which categories load.
- A systemd timer pair (`openshield-blocklist-sync.service` / `.timer`)
  runs the sync every 6 hours:

```bash
sudo cp integrations/openshield/openshield-blocklist-sync.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now openshield-blocklist-sync.timer
```

## Generic firewall (shell example)

```bash
#!/usr/bin/env bash
BASE=https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/feeds
for cat in c2 botnets bruteforce; do
  curl -fsSL "$BASE/$cat/ipv4.txt" | grep -v '^#'
done >> /etc/my-xdp-loader/banned.txt
```

## Rate limits

`raw.githubusercontent.com` is a CDN — fine for thousands of deployments
polling hourly. Do not poll more than once per hour; the feeds rebuild at
most every 3 hours.
