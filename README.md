# OpenShield Blocklists

Production-grade **threat-intelligence feeds** for
[OpenShield-XDP](https://github.com/AnAverageBeing/OpenShield-XDP) and any other
firewall, XDP/eBPF program, or edge filter that needs clean "block these
sources" lists.

![update](https://github.com/AnAverageBeing/openshield-blocklists/actions/workflows/update.yml/badge.svg)
![CI](https://github.com/AnAverageBeing/openshield-blocklists/actions/workflows/ci.yml/badge.svg)
![entries](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FAnAverageBeing%2Fopenshield-blocklists%2Fmain%2Fmetadata%2Fmanifest.json&query=%24.totals.all&label=entries)

**Rebuilt every 3 hours** by GitHub Actions from 75 sources. Every run
normalizes, validates, de-duplicates and splits everything into
**per-category, format-pure feeds** (IPv4 / IPv6 / IPv4-CIDR / IPv6-CIDR are
never mixed), with full machine-readable metadata. Deterministic: identical
inputs produce byte-identical feeds.

Quick start — grab the global index:

```
https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/metadata/manifest.json
```

…or any feed file directly:

```
https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/feeds/c2/ipv4.txt
```

## Feeds

| Category | Description | Status |
| --- | --- | --- |
| [`c2`](feeds/c2/) | Botnet & malware command-and-control servers | active |
| [`botnets`](feeds/botnets/) | Infected hosts / bot agents | active |
| [`malware`](feeds/malware/) | Malware distribution IPs | active |
| [`scanners`](feeds/scanners/) | Internet-wide scanners, probes, top attackers | active |
| [`abuse`](feeds/abuse/) | Generic abusers, compromised hosts, reported attackers | active |
| [`spam`](feeds/spam/) | Forum/blog/web-form spam sources | active |
| [`bruteforce`](feeds/bruteforce/) | Multi-service brute-force sources | active |
| [`ssh-attackers`](feeds/ssh-attackers/) | SSH password guessing / scanning | active |
| [`rdp-attackers`](feeds/rdp-attackers/) | RDP attackers | planned |
| [`credential-stuffing`](feeds/credential-stuffing/) | Web login brute-force / credential stuffing | active |
| [`web-exploit-scanners`](feeds/web-exploit-scanners/) | Web vulnerability scanners/exploit attempts | active |
| [`exploited-infrastructure`](feeds/exploited-infrastructure/) | Confirmed compromised machines | active |
| [`high-risk-networks`](feeds/high-risk-networks/) | Hijacked/criminal netblocks (Spamhaus DROP) | active |
| [`http-proxies`](feeds/http-proxies/) | Open HTTP/HTTPS proxies | active |
| [`socks4-proxies`](feeds/socks4-proxies/) | Open SOCKS4 proxies | active |
| [`socks5-proxies`](feeds/socks5-proxies/) | Open SOCKS5 proxies | active |
| [`tor-exit-nodes`](feeds/tor-exit-nodes/) | Tor exit relays | active |
| [`ddos-sources`](feeds/ddos-sources/) | DDoS participants | planned |
| [`vpn-endpoints`](feeds/vpn-endpoints/) | Public VPN exits | planned |
| [`residential-proxies`](feeds/residential-proxies/) | Residential proxy exits | planned |
| [`hosting-providers`](feeds/hosting-providers/) | Hosting/cloud ranges (scoring aid) | planned |
| [`honeypot-hits`](feeds/honeypot-hits/) | OpenShield honeypot hits | planned |
| [`community-reports`](feeds/community-reports/) | Community submissions | planned |
| [`l7-patterns`](feeds/l7-patterns/) | L7 reflection-flood payload signatures (curated, not an IP list) | active |

Each IP category directory contains `ipv4.txt`, `ipv6.txt`, `ipv4-cidrs.txt`,
`ipv6-cidrs.txt`. Live counts per feed: [`metadata/manifest.json`](metadata/manifest.json).
The curated `l7-patterns` feed is a single `patterns.txt` of pipe-separated
L7 drop signatures (spec: [docs/FEED-FORMATS.md](docs/FEED-FORMATS.md)).

## Why these feeds are safe to consume

- **source IPs only** — ports stripped from every proxy/IOC feed
- **validated** — every entry parsed; private, loopback, multicast, reserved,
  documentation, benchmark and unspecified ranges removed; subnets bounded
  (v4 ≥ /8, v6 ≥ /32)
- **de-duplicated** — exact dupes across 77 sources, subnet coverage
  subtraction, CIDR collapsing
- **deterministic ordering** — numeric sort, byte-reproducible files
- **fail-safe** — per-source last-good caching, sanity floor before publish,
  post-build offline verification in CI

## Documentation

- [Architecture & future extension seams](docs/ARCHITECTURE.md)
- [Feed file & metadata format spec](docs/FEED-FORMATS.md)
- [Update pipeline](docs/PIPELINE.md)
- [Source policy — how to add a feed](docs/SOURCES.md)
- [Consumption guide & integrations](docs/CONSUMPTION.md)
- [Contributing](CONTRIBUTING.md)

## OpenShield-XDP integration

```bash
sudo curl -fsSL https://raw.githubusercontent.com/AnAverageBeing/openshield-blocklists/main/integrations/openshield/sync.sh \
  -o /usr/local/bin/openshield-blocklist-sync
sudo chmod +x /usr/local/bin/openshield-blocklist-sync
sudo openshield-blocklist-sync   # loads all active categories into the XDP ban maps
```

See [docs/CONSUMPTION.md](docs/CONSUMPTION.md) for the systemd timer and
generic firewall examples.

## Adding a source

One entry in [`configs/sources.json`](configs/sources.json) — nothing else.
See [docs/SOURCES.md](docs/SOURCES.md).

## Disclaimer

Feeds aggregate **third-party** data; false positives happen. Choose
categories deliberately (Tor/proxy lists block legitimate privacy users),
keep a whitelist, and test before production enforcement. No warranty.
Upstream feeds retain their own licenses.

## License

MIT — see [LICENSE](LICENSE).
