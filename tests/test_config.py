"""Config loader unit tests."""

import json
import tempfile
import unittest
from pathlib import Path

from openshield_feeds.config import ConfigError, load


def write_configs(root: Path, categories, sources):
    cfg = root / "configs"
    cfg.mkdir(parents=True)
    (cfg / "categories.json").write_text(json.dumps({"categories": categories}))
    (cfg / "sources.json").write_text(json.dumps({"sources": sources}))


CATS = [{"id": "abuse", "name": "Abuse"}, {"id": "tor-exit-nodes", "name": "Tor", "status": "planned"}]
SRC = {"name": "s1", "url": "https://example.com/list.txt", "category": "abuse"}


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_minimal(self):
        write_configs(self.root, CATS, [SRC])
        cfg = load(self.root / "configs")
        self.assertEqual(len(cfg.categories), 2)
        self.assertEqual(len(cfg.sources), 1)
        src = cfg.sources[0]
        self.assertEqual(src.format, "auto")
        self.assertEqual(src.update_interval, 10_800)
        self.assertEqual(src.priority, 100)
        self.assertTrue(src.enabled)

    def test_duplicate_source_name_rejected(self):
        write_configs(self.root, CATS, [SRC, SRC])
        with self.assertRaises(ConfigError):
            load(self.root / "configs")

    def test_unknown_category_rejected(self):
        write_configs(self.root, CATS, [{**SRC, "category": "nope"}])
        with self.assertRaises(ConfigError):
            load(self.root / "configs")

    def test_unknown_format_rejected(self):
        write_configs(self.root, CATS, [{**SRC, "format": "yaml"}])
        with self.assertRaises(ConfigError):
            load(self.root / "configs")

    def test_missing_url_rejected(self):
        bad = dict(SRC)
        del bad["url"]
        write_configs(self.root, CATS, [bad])
        with self.assertRaises(ConfigError):
            load(self.root / "configs")

    def test_bad_scheme_rejected(self):
        write_configs(self.root, CATS, [{**SRC, "url": "ftp://example.com/x"}])
        with self.assertRaises(ConfigError):
            load(self.root / "configs")

    def test_negative_interval_rejected(self):
        write_configs(self.root, CATS, [{**SRC, "update_interval": -5}])
        with self.assertRaises(ConfigError):
            load(self.root / "configs")

    def test_validation_block_parsed(self):
        write_configs(self.root, CATS, [{**SRC, "validation": {"min_entries": 10, "allow_non_global": True}}])
        cfg = load(self.root / "configs")
        self.assertEqual(cfg.sources[0].min_entries, 10)
        self.assertTrue(cfg.sources[0].allow_non_global)

    def test_broken_json_rejected(self):
        cfg_dir = self.root / "configs"
        cfg_dir.mkdir()
        (cfg_dir / "categories.json").write_text("{not json")
        (cfg_dir / "sources.json").write_text("{}")
        with self.assertRaises(ConfigError):
            load(cfg_dir)


if __name__ == "__main__":
    unittest.main()
