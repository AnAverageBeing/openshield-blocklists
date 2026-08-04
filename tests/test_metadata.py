"""Metadata unit tests — schema shape, content-addressed versions, quiet writes."""

import json
import tempfile
import unittest
from pathlib import Path

from openshield_feeds.config import Category
from openshield_feeds.metadata import (
    build_manifest,
    category_metadata,
    feed_version,
    write_json,
)
from openshield_feeds.output import FileRecord


def rec(fmt, entries, digest):
    return FileRecord(fmt, f"feeds/cat/{fmt}.txt", entries, digest, 100, True)


RECS = [
    rec("ipv4", 2, "a" * 64),
    rec("ipv6", 1, "b" * 64),
    rec("ipv4-cidrs", 1, "c" * 64),
    rec("ipv6-cidrs", 0, "d" * 64),
]


class TestFeedVersion(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(feed_version(RECS), feed_version(RECS))
        self.assertTrue(feed_version(RECS).startswith("sha256:"))

    def test_changes_with_content(self):
        other = [rec("ipv4", 2, "z" * 64)] + RECS[1:]
        self.assertNotEqual(feed_version(RECS), feed_version(other))


class TestCategoryMetadata(unittest.TestCase):
    def test_schema_shape(self):
        meta = category_metadata(
            Category("cat", "Cat", "desc", "active"),
            "2026-01-01T00:00:00Z", RECS, [], 5, 3, 42,
        )
        self.assertEqual(meta["schema"], 1)
        self.assertEqual(meta["totals"], {"ipv4": 2, "ipv6": 1, "cidrs_v4": 1, "cidrs_v6": 0, "all": 4})
        self.assertEqual(meta["processing"]["duplicates_removed"], 5)
        self.assertEqual(meta["processing"]["invalid_discarded"], 3)
        self.assertIn("url", meta["files"]["ipv4"])
        self.assertEqual(set(meta["files"]), {"ipv4", "ipv6", "ipv4-cidrs", "ipv6-cidrs"})


class TestManifest(unittest.TestCase):
    def test_totals_aggregated(self):
        meta_a = category_metadata(Category("a", "A"), "t", RECS, [], 0, 0, 0)
        meta_b = category_metadata(Category("b", "B"), "t", RECS, [], 0, 0, 0)
        manifest = build_manifest("t", [meta_a, meta_b], [], 10)
        self.assertEqual(manifest["totals"]["ipv4"], 4)
        self.assertEqual(manifest["totals"]["all"], 8)
        self.assertEqual(manifest["feed_count"], 2)
        self.assertEqual([f["category"] for f in manifest["feeds"]], ["a", "b"])


class TestWriteJson(unittest.TestCase):
    def test_quiet_when_only_volatile_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.json"
            payload = {"generated": "t1", "x": 1, "processing": {"duration_ms": 5, "n": 2}}
            self.assertTrue(write_json(path, payload))
            # Same content, new timestamp/duration -> no rewrite.
            payload2 = {"generated": "t2", "x": 1, "processing": {"duration_ms": 9, "n": 2}}
            self.assertFalse(write_json(path, payload2))
            self.assertEqual(json.loads(path.read_text())["generated"], "t1")
            # Real change -> rewrite.
            payload3 = {"generated": "t3", "x": 2, "processing": {"duration_ms": 1, "n": 2}}
            self.assertTrue(write_json(path, payload3))


if __name__ == "__main__":
    unittest.main()
