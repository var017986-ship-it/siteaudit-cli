from __future__ import annotations

import threading
import unittest
import ipaddress
from types import SimpleNamespace
from unittest.mock import patch

from siteaudit.http_client import ScanContext
from siteaudit.plugins import PluginSpec, run_plugins
from siteaudit.external_scope_proxy import ScopeProxy, _safe_authority
from siteaudit.external_zap import _automation_plan, _result


class ScopeBudgetTests(unittest.TestCase):
    def test_http_target_allows_only_same_host_default_https_upgrade(self) -> None:
        ctx = ScanContext.__new__(ScanContext)
        ctx.base_url = "http://example.com/"
        ctx.hostname = "example.com"

        self.assertEqual(ctx._check_scope("https://example.com/account"), ("https", "example.com", 443))
        with self.assertRaisesRegex(ValueError, "outside the selected host and port"):
            ctx._check_scope("https://example.com:8443/account")
        with self.assertRaisesRegex(ValueError, "outside the selected host and port"):
            ctx._check_scope("https://other.example/account")

    def test_https_target_rejects_downgrade(self) -> None:
        ctx = ScanContext.__new__(ScanContext)
        ctx.base_url = "https://example.com/"
        ctx.hostname = "example.com"

        with self.assertRaisesRegex(ValueError, "outside the selected host and port"):
            ctx._check_scope("http://example.com/")

    def test_scope_proxy_allows_only_the_explicit_http_upgrade(self) -> None:
        proxy = ScopeProxy.__new__(ScopeProxy)
        proxy.scheme = "http"
        proxy.hostname = "example.com"
        proxy.port = 80
        proxy.allow_https_upgrade = True

        proxy._check_origin("example.com", 443, scheme="https")
        with self.assertRaisesRegex(ValueError, "outside the selected host and port"):
            proxy._check_origin("other.example", 443, scheme="https")
        with self.assertRaisesRegex(ValueError, "outside the selected host and port"):
            proxy._check_origin("example.com", 8443, scheme="https")

    def test_wsl_proxy_without_auth_accepts_only_the_exact_scanner_ip(self) -> None:
        proxy = ScopeProxy.__new__(ScopeProxy)
        proxy.remote_access = True
        proxy.remote_auth_required = False
        proxy._allowed_remote_clients = (ipaddress.ip_network("172.30.64.200/32"),)

        self.assertTrue(proxy._matches_auth(None))
        self.assertTrue(proxy._remote_client_allowed("172.30.64.200"))
        self.assertFalse(proxy._remote_client_allowed("172.30.64.201"))

    def test_remote_docker_proxy_requires_random_auth(self) -> None:
        proxy = ScopeProxy.__new__(ScopeProxy)
        proxy.remote_access = True
        proxy.remote_auth_required = True
        proxy.username = "siteaudit"
        proxy.password = "per-run-secret"

        self.assertFalse(proxy._matches_auth(None))
        self.assertTrue(proxy._matches_auth("Basic c2l0ZWF1ZGl0OnBlci1ydW4tc2VjcmV0"))

    def test_zap_zero_depth_plan_requests_only_the_root(self) -> None:
        ctx = SimpleNamespace(base_url="http://example.com/", hostname="example.com", options={"max_depth": 0})
        plan = _automation_plan(
            ctx,
            "http://example.com/",
            report_dir="/tmp",
            proxy_host="127.0.0.1",
            proxy_port=12345,
            active=False,
            max_pages=10,
            engine_timeout=120,
            delay=1,
        )

        jobs = plan["jobs"]
        self.assertFalse(any(job["type"] == "spider" for job in jobs))
        requestor = next(job for job in jobs if job["type"] == "requestor")
        self.assertEqual(requestor["requests"], [{"url": "http://example.com/", "method": "GET", "name": "SiteAudit root-only request"}])

    def test_zap_result_reports_requested_depth(self) -> None:
        ctx = SimpleNamespace(options={"max_depth": 0})
        process = SimpleNamespace(returncode=0, duration_seconds=1.0, stderr="", stdout="")

        result = _result(
            ctx=ctx,
            findings=0,
            process=process,
            mode="passive",
            max_pages=10,
            engine_timeout=120,
            execution="wsl",
        )

        self.assertEqual(result["max_depth_requested"], 0)
        self.assertEqual(result["max_depth_effective"], 0)

    def test_blocked_authority_omits_path_query_and_credentials(self) -> None:
        self.assertEqual(
            _safe_authority("https://secret:password@outside.example:8443/path?token=secret"),
            "https://outside.example:8443",
        )

    def test_request_budget_records_blocked_attempt(self) -> None:
        ctx = ScanContext.__new__(ScanContext)
        ctx.options = {"max_requests": 1, "delay": 0}
        ctx.base_url = "https://example.com/"
        ctx.hostname = "example.com"
        ctx._request_count = 1
        ctx._request_limit_reached = False
        ctx._request_limit_blocked_attempts = 0
        ctx._last_request_at = 0.0
        ctx._lock = threading.Lock()
        ctx._validate_host = lambda _url: "203.0.113.10"

        result = ctx.request("GET", "https://example.com/")

        self.assertIn("Request limit reached", result.error or "")
        self.assertTrue(ctx.request_limit_reached)
        self.assertEqual(ctx.request_limit_blocked_attempts, 1)
        self.assertEqual(ctx.request_count, 1)

    def test_active_plugins_are_skipped_after_budget_exhaustion(self) -> None:
        ctx = SimpleNamespace(
            findings=[],
            request_limit_reached=False,
            request_limit_blocked_attempts=0,
        )

        def passive_runner(_ctx):
            _ctx.request_limit_reached = True
            _ctx.request_limit_blocked_attempts = 1
            return {"status": "completed", "requests_sent": 1}

        specs = (
            PluginSpec("passive_mock", "mock", "passive"),
            PluginSpec("active_mock", "mock", "active"),
        )
        with patch("siteaudit.plugins.PLUGIN_REGISTRY", specs), patch(
            "siteaudit.plugins.import_module",
            return_value=SimpleNamespace(run=passive_runner),
        ) as import_module:
            results, _ = run_plugins(ctx, include_active=True)

        self.assertEqual(results["passive_mock"]["status"], "partial")
        self.assertEqual(results["active_mock"]["status"], "skipped")
        self.assertEqual(import_module.call_count, 1)


if __name__ == "__main__":
    unittest.main()
