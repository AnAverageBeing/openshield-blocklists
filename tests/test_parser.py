"""Parser unit tests — every accepted/rejected input shape."""

import ipaddress
import unittest

from openshield_feeds.parser import parse_text


def parse(text, fmt="auto", **kw):
    return parse_text(text, fmt, **kw)


def all_entries(result):
    e = result.entries
    return {str(x) for x in e.ipv4 | e.ipv6 | e.cidr4 | e.cidr6}


class TestAutoFormat(unittest.TestCase):
    def test_bare_ipv4(self):
        r = parse("1.2.3.4\n")
        self.assertEqual(all_entries(r), {"1.2.3.4"})

    def test_ipv4_with_port_is_stripped(self):
        r = parse("1.2.3.4:8080\n")
        self.assertEqual(all_entries(r), {"1.2.3.4"})

    def test_ipv6_bare_and_bracketed_port(self):
        r = parse("2001:4860:4860::8888\n[2606:4700:4700::1111]:443\n")
        self.assertEqual(
            all_entries(r),
            {"2001:4860:4860::8888", "2606:4700:4700::1111"},
        )

    def test_cidr(self):
        r = parse("5.6.7.0/24\n")
        self.assertEqual(all_entries(r), {"5.6.7.0/24"})

    def test_url_with_ip_host_kept(self):
        r = parse("https://1.1.1.1/malware.exe\n")
        self.assertEqual(all_entries(r), {"1.1.1.1"})

    def test_url_with_domain_host_dropped(self):
        r = parse("https://evil.example.com/payload\n")
        self.assertEqual(all_entries(r), set())
        self.assertEqual(r.candidates, 0)

    def test_ipsum_tab_format(self):
        r = parse("1.2.3.4\t7\n")
        self.assertEqual(all_entries(r), {"1.2.3.4"})

    def test_full_line_and_inline_comments(self):
        r = parse("# comment\n; another\n1.2.3.4 # trailing\n5.6.7.8 ; trailing\n")
        self.assertEqual(all_entries(r), {"1.2.3.4", "5.6.7.8"})

    def test_junk_lines_ignored(self):
        r = parse("hello world\n---\n()\n")
        self.assertEqual(all_entries(r), set())
        self.assertEqual(r.candidates, 0)

    def test_whitespace_normalization(self):
        r = parse("   1.2.3.4   \n\t5.6.7.8\t\n")
        self.assertEqual(all_entries(r), {"1.2.3.4", "5.6.7.8"})

    def test_cidr_normalized_to_network(self):
        r = parse("5.6.7.9/24\n")
        self.assertEqual(all_entries(r), {"5.6.7.0/24"})


class TestValidationRejects(unittest.TestCase):
    def test_private_rejected(self):
        r = parse("10.0.0.5\n172.16.0.1\n192.168.1.1\n")
        self.assertEqual(all_entries(r), set())
        self.assertEqual(r.invalid, 3)

    def test_loopback_multicast_doc_benchmark_rejected(self):
        r = parse("127.0.0.1\n224.0.0.1\n203.0.113.9\n198.18.0.1\n0.0.0.0\n")
        self.assertEqual(all_entries(r), set())
        self.assertEqual(r.invalid, 5)

    def test_overbroad_prefix_rejected(self):
        r = parse("0.0.0.0/0\n1.0.0.0/7\n")
        self.assertEqual(all_entries(r), set())
        self.assertEqual(r.invalid, 2)

    def test_v6_special_rejected(self):
        r = parse("::1\nfe80::1\nff02::1\n2001:db8::1\n")
        self.assertEqual(all_entries(r), set())
        self.assertEqual(r.invalid, 4)

    def test_allow_non_global_opt_in(self):
        r = parse("10.0.0.5\n", allow_non_global=True)
        self.assertEqual(all_entries(r), {"10.0.0.5"})
        # prefix guards still apply even with the escape hatch
        r2 = parse("0.0.0.0/0\n", allow_non_global=True)
        self.assertEqual(all_entries(r2), set())


class TestDshieldFormat(unittest.TestCase):
    def test_start_end_prefix(self):
        r = parse("1.2.3.0\t1.2.3.255\t24\t1234\tExample\tUS\n", "dshield")
        self.assertEqual(all_entries(r), {"1.2.3.0/24"})

    def test_comment_skipped(self):
        r = parse("# comment\n", "dshield")
        self.assertEqual(r.candidates, 0)


class TestResultAccounting(unittest.TestCase):
    def test_candidates_and_invalid_counts(self):
        r = parse("1.2.3.4\n10.0.0.1\njunk\n")
        self.assertEqual(r.candidates, 2)
        self.assertEqual(r.invalid, 1)
        self.assertEqual(r.entries.total(), 1)


if __name__ == "__main__":
    unittest.main()
