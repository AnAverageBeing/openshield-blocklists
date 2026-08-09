"""Tests for the curated L7 pattern feed validator."""

from __future__ import annotations

import unittest

from openshield_feeds.patterns import parse_line, validate_text


def line(**over) -> str:
    fields = {
        "name": "ntp-monlist",
        "proto": "udp",
        "port": "123",
        "port_is_src": "1",
        "offset": "0",
        "min_payload": "100",
        "max_payload": "0",
        "pattern": "87",
        "mask": "87",
    }
    fields.update(over)
    return "|".join(fields.values())


class TestParseLine(unittest.TestCase):
    def test_valid(self):
        sig = parse_line(line())
        self.assertEqual(sig.name, "ntp-monlist")
        self.assertEqual(sig.proto, "udp")
        self.assertEqual(sig.port, 123)
        self.assertTrue(sig.port_is_src)
        self.assertEqual(sig.pattern, bytes([0x87]))
        self.assertEqual(sig.mask, bytes([0x87]))

    def test_empty_mask_means_exact_match(self):
        sig = parse_line(line(mask=""))
        self.assertEqual(sig.mask, b"")

    def test_eight_byte_pattern_ok(self):
        sig = parse_line(line(pattern="485454502f312e31", mask="ffffffffffffffff"))
        self.assertEqual(len(sig.pattern), 8)

    def test_bad_field_count(self):
        with self.assertRaises(ValueError):
            parse_line("a|b|c")

    def test_bad_proto(self):
        with self.assertRaisesRegex(ValueError, "proto"):
            parse_line(line(proto="icmp"))

    def test_bad_port(self):
        for bad in ("0", "65536", "abc"):
            with self.assertRaises(ValueError):
                parse_line(line(port=bad))

    def test_bad_port_is_src(self):
        with self.assertRaisesRegex(ValueError, "port_is_src"):
            parse_line(line(port_is_src="yes"))

    def test_bad_offset(self):
        with self.assertRaises(ValueError):
            parse_line(line(offset="256"))

    def test_pattern_too_long(self):
        with self.assertRaisesRegex(ValueError, "pattern"):
            parse_line(line(pattern="00" * 9, mask="ff" * 9))

    def test_pattern_empty(self):
        with self.assertRaises(ValueError):
            parse_line(line(pattern="", mask=""))

    def test_odd_hex(self):
        with self.assertRaises(ValueError):
            parse_line(line(pattern="8", mask="f"))

    def test_mask_length_mismatch(self):
        with self.assertRaisesRegex(ValueError, "mask length"):
            parse_line(line(pattern="8788", mask="ff"))

    def test_pattern_bits_outside_mask(self):
        with self.assertRaisesRegex(ValueError, "outside mask"):
            parse_line(line(pattern="87", mask="80"))

    def test_max_below_min(self):
        with self.assertRaisesRegex(ValueError, "max_payload"):
            parse_line(line(min_payload="512", max_payload="100"))

    def test_bad_name(self):
        for bad in ("has space", "", "pipe|x", "-leading-dash"):
            with self.assertRaises(ValueError):
                parse_line(line(name=bad))


class TestValidateText(unittest.TestCase):
    def test_comments_and_blanks_skipped(self):
        text = "# header\n\n" + line() + "\n# trailing comment\n"
        patterns, problems = validate_text(text)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(problems, [])

    def test_problems_carry_line_numbers(self):
        text = line() + "\n" + line(proto="bogus") + "\n"
        patterns, problems = validate_text(text)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("line 2", problems[0])

    def test_duplicate_names_rejected(self):
        text = line() + "\n" + line() + "\n"
        patterns, problems = validate_text(text)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("duplicate", problems[0])

    def test_shipped_feed_is_valid(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        feed = root / "feeds" / "l7-patterns" / "patterns.txt"
        patterns, problems = validate_text(feed.read_text())
        self.assertEqual(problems, [])
        self.assertEqual(len(patterns), 10)
        # Every shipped signature must be response-side (port_is_src=1):
        # a match means "traffic FROM an amplifier service port".
        for sig in patterns:
            self.assertTrue(sig.port_is_src, sig.name)


if __name__ == "__main__":
    unittest.main()
