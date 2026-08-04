"""End-to-end integration test: build from fixture sources, verify,
idempotency, and byte-level determinism across fresh checkouts."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from openshield_feeds.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def make_root(base: Path) -> Path:
    root = base / "repo"
    (root / "configs").mkdir(parents=True)
    (root / "configs" / "categories.json").write_text(json.dumps({"categories": [
        {"id": "test-abuse", "name": "Test Abuse", "status": "active"},
        {"id": "test-planned", "name": "Test Planned", "status": "planned"},
    ]}))
    (root / "configs" / "sources.json").write_text(json.dumps({"sources": [
        {"name": "fixture_a", "url": f"file://{FIXTURES / 'sample_a.txt'}",
         "category": "test-abuse", "update_interval": 86400},
        {"name": "fixture_b", "url": f"file://{FIXTURES / 'sample_b.txt'}",
         "category": "test-abuse", "update_interval": 86400},
    ]}))
    return root


def data_lines(path: Path) -> list[str]:
    return [
        ln.strip() for ln in path.read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


def tree_bytes(root: Path, sub: str) -> dict[str, bytes]:
    base = root / sub
    return {
        str(p.relative_to(base)): p.read_bytes()
        for p in sorted(base.rglob("*")) if p.is_file()
    }


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_root(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, root):
        return main(["--root", str(root), "build", "--min-total", "0"])

    def test_full_pipeline(self):
        self.assertEqual(self.build(self.root), 0)

        feeds = self.root / "feeds" / "test-abuse"
        self.assertEqual(data_lines(feeds / "ipv4.txt"), ["1.2.3.4", "8.8.8.8"])
        self.assertEqual(data_lines(feeds / "ipv6.txt"),
                         ["2001:4860:4860::8888", "2606:4700:4700::1111"])
        self.assertEqual(data_lines(feeds / "ipv4-cidrs.txt"), ["5.6.7.0/24"])
        self.assertEqual(data_lines(feeds / "ipv6-cidrs.txt"), [])

        # Planned category publishes empty (but valid) feeds.
        planned = self.root / "feeds" / "test-planned"
        for fmt in ("ipv4", "ipv6", "ipv4-cidrs", "ipv6-cidrs"):
            self.assertEqual(data_lines(planned / f"{fmt}.txt"), [])

        meta = json.loads((self.root / "metadata" / "test-abuse.json").read_text())
        self.assertEqual(meta["totals"]["all"], 5)
        self.assertEqual(meta["processing"]["duplicates_removed"], 1)
        self.assertEqual(meta["processing"]["invalid_discarded"], 2)
        self.assertEqual(meta["sources"]["count"], 2)
        self.assertTrue(meta["version"].startswith("sha256:"))

        manifest = json.loads((self.root / "metadata" / "manifest.json").read_text())
        self.assertEqual(manifest["feed_count"], 2)
        self.assertEqual(manifest["totals"]["all"], 5)
        self.assertEqual(manifest["processing"]["sources"], 2)

        # Offline verification passes.
        self.assertEqual(main(["--root", str(self.root), "verify"]), 0)

    def test_idempotent_second_run(self):
        self.assertEqual(self.build(self.root), 0)
        before = {**tree_bytes(self.root, "feeds"), **tree_bytes(self.root, "metadata")}
        self.assertEqual(self.build(self.root), 0)
        after = {**tree_bytes(self.root, "feeds"), **tree_bytes(self.root, "metadata")}
        self.assertEqual(before, after)

    def test_deterministic_across_checkouts(self):
        self.assertEqual(self.build(self.root), 0)
        other_base = Path(self.tmp.name) / "second"
        other_root = make_root(other_base)
        self.assertEqual(self.build(other_root), 0)
        self.assertEqual(tree_bytes(self.root, "feeds"), tree_bytes(other_root, "feeds"))


if __name__ == "__main__":
    unittest.main()
