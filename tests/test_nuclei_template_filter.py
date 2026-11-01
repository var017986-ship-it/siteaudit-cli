from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from siteaudit.external_nuclei import _prepare_templates


class NucleiTemplateFilterTests(unittest.TestCase):
    def test_safe_templates_are_copied_and_network_dsl_templates_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siteaudit-nuclei-test-") as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "filtered"
            source.mkdir()
            (source / "safe.yaml").write_text("id: safe\nhttp:\n  - method: GET\n", encoding="utf-8")
            (source / "network.yaml").write_text("id: network\nflow: resolve(Hostname)\n", encoding="utf-8")

            copied, blocked = _prepare_templates(source, destination)

            self.assertEqual((copied, blocked), (1, 1))
            self.assertTrue((destination / "safe.yaml").is_file())
            self.assertFalse((destination / "network.yaml").exists())
            (source / "safe.yaml").write_text("id: changed\n", encoding="utf-8")
            self.assertIn("id: safe", (destination / "safe.yaml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
