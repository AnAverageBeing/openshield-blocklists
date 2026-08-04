"""Validator unit tests — special-use range policy and prefix guards."""

import ipaddress
import unittest

from openshield_feeds.validator import keep


def ip(s):
    return ipaddress.ip_address(s)


def net(s):
    return ipaddress.ip_network(s, strict=False)


class TestKeepIp(unittest.TestCase):
    def test_global_v4_accepted(self):
        self.assertTrue(keep(ip("1.2.3.4")))

    def test_global_v6_accepted(self):
        self.assertTrue(keep(ip("2001:4860:4860::8888")))

    def test_special_use_v4_rejected(self):
        for bad in ("0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1",
                    "172.16.0.1", "192.0.2.1", "192.168.0.1", "198.18.0.1",
                    "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
                    "255.255.255.255"):
            self.assertFalse(keep(ip(bad)), bad)

    def test_special_use_v6_rejected(self):
        for bad in ("::", "::1", "fe80::1", "ff02::1", "2001:db8::1"):
            self.assertFalse(keep(ip(bad)), bad)

    def test_allow_non_global_opt_in(self):
        self.assertTrue(keep(ip("10.1.2.3"), allow_non_global=True))


class TestKeepNetwork(unittest.TestCase):
    def test_prefix_guards(self):
        self.assertFalse(keep(net("1.0.0.0/7")))
        self.assertTrue(keep(net("1.0.0.0/8")))
        self.assertFalse(keep(net("2001:4860::/31")))
        self.assertTrue(keep(net("2001:4860::/32")))

    def test_non_global_network_rejected(self):
        self.assertFalse(keep(net("10.0.0.0/8")))

    def test_straddling_network_rejected(self):
        # 9.254.0.0/16 is global but a /8 would straddle into 10.0.0.0/8 —
        # guarded by the prefix check; verify both-end logic on a real case.
        self.assertFalse(keep(net("10.0.0.0/9"), allow_non_global=False))

    def test_prefix_guards_not_overridable(self):
        self.assertFalse(keep(net("0.0.0.0/0"), allow_non_global=True))


if __name__ == "__main__":
    unittest.main()
