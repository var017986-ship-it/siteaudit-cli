from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from siteaudit.cli import run_scan


def _args(*, external_only: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        target="https://example.com/",
        max_pages=10,
        max_depth=1,
        delay=1.0,
        timeout=5.0,
        allow_private=False,
        passive=False,
        post_probes=False,
        sqli_probes=False,
        graphql_probe=False,
        templates_file=None,
        engine=["nuclei"] if external_only else [],
        engine_timeout=60,
        nuclei_templates=None,
        nuclei_auto_scan=False,
        zap_active=False,
        external_only=external_only,
    )


def _context(*, request_limit_reached: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="https://example.com/",
        findings=[],
        discovered_urls=[],
        discovered_responses=[],
        response_cache_limited=False,
        request_count=10,
        request_limit_reached=request_limit_reached,
        request_limit_blocked_attempts=1 if request_limit_reached else 0,
    )


class ScanStatusTests(unittest.TestCase):
    def test_builtin_request_limit_marks_report_partial(self) -> None:
        ctx = _context(request_limit_reached=True)
        with patch("siteaudit.cli.ScanContext", return_value=ctx), patch("siteaudit.template_engine.prepare"), patch(
            "siteaudit.cli.run_core"
        ), patch("siteaudit.cli.run_plugins", return_value=({}, [])), patch(
            "siteaudit.cli.run_external_engines", return_value={}
        ):
            report = run_scan(_args())

        self.assertEqual(report["status"], "partial")
        self.assertIn("built_in_request_limit_reached", report["summary"]["partial_reasons"])
        self.assertTrue(report["summary"]["request_limit_reached"])

    def test_incomplete_upstream_engine_marks_report_partial(self) -> None:
        ctx = _context()
        with patch("siteaudit.cli.ScanContext", return_value=ctx), patch(
            "siteaudit.cli.run_external_engines", return_value={"nuclei": {"status": "partial"}}
        ):
            report = run_scan(_args(external_only=True))

        self.assertEqual(report["status"], "partial")
        self.assertIn("external_engine_nuclei_partial", report["summary"]["partial_reasons"])


if __name__ == "__main__":
    unittest.main()
