"""Pipeline unit tests — dedupe, collapse, coverage, determinism."""

import ipaddress
import unittest

from openshield_feeds.models import EntrySet
from openshield_feeds.pipeline import aggregate, finalize


def es(ipv4=(), ipv6=(), cidr4=(), cidr6=()):
    return EntrySet(
        ipv4={ipaddress.ip_address(x) for x in ipv4},
        ipv6={ipaddress.ip_address(x) for x in ipv6},
        cidr4={ipaddress.ip_network(x) for x in cidr4},
        cidr6={ipaddress.ip_network(x) for x in cidr6},
    )


class TestAggregate(unittest.TestCase):
    def test_cross_source_dedupe_count(self):
        a = es(ipv4=["1.1.1.1", "2.2.2.2"])
        b = es(ipv4=["2.2.2.2", "3.3.3.3"])
        merged, dupes = aggregate([a, b])
        self.assertEqual(dupes, 1)
        self.assertEqual(len(merged.ipv4), 3)


class TestFinalize(unittest.TestCase):
    def test_collapse_merges_adjacent(self):
        out = finalize(es(cidr4=["1.2.3.0/25", "1.2.3.128/25"]))
        self.assertEqual(out["ipv4-cidrs"], ["1.2.3.0/24"])

    def test_covered_ips_subtracted(self):
        out = finalize(es(ipv4=["5.6.7.8", "9.9.9.9"], cidr4=["5.6.7.0/24"]))
        self.assertEqual(out["ipv4"], ["9.9.9.9"])
        self.assertEqual(out["ipv4-cidrs"], ["5.6.7.0/24"])

    def test_numeric_ordering(self):
        out = finalize(es(ipv4=["9.9.9.9", "1.1.1.1", "200.1.1.1"]))
        self.assertEqual(out["ipv4"], ["1.1.1.1", "9.9.9.9", "200.1.1.1"])

    def test_determinism_regardless_of_input_order(self):
        a = finalize(es(ipv4=["9.9.9.9", "1.1.1.1"], cidr4=["5.6.7.128/25", "5.6.7.0/25"]))
        b = finalize(es(ipv4=["1.1.1.1", "9.9.9.9"], cidr4=["5.6.7.0/25", "5.6.7.128/25"]))
        self.assertEqual(a, b)

    def test_formats_never_mixed(self):
        out = finalize(es(ipv4=["1.1.1.1"], ipv6=["2001:4860:4860::8888"],
                          cidr4=["5.6.7.0/24"], cidr6=["2001:4860::/32"]))
        for key, items in out.items():
            for item in items:
                self.assertEqual("/" in item, key.endswith("-cidrs"))
                self.assertEqual(":" in item, key.startswith("ipv6"))


if __name__ == "__main__":
    unittest.main()
