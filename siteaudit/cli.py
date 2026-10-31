from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .context import ScanContext
from .core_checks import run as run_core
from .models import redact_url
from .plugins import PluginExecutionError, run_plugins


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="siteaudit", description="Bounded HTTP security checks for authorized web targets.")
    parser.add_argument("target", help="Target URL or domain (for example, https://example.com)")
    parser.add_argument("--output", "-o", default="siteaudit-report.json", help="JSON report path (default: siteaudit-report.json)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum HTML pages to crawl (1-500, default: 50)")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (0-8, default: 2)")
    parser.add_argument("--delay", type=float, default=0.5, help="Minimum delay between requests in seconds (0.1-10, default: 0.5)")
    parser.add_argument("--timeout", type=float, default=10, help="HTTP timeout in seconds (1-60, default: 10)")
    parser.add_argument("--passive", action="store_true", help="Skip active templates and probes; crawl and inspect fetched responses only")
    parser.add_argument("--post-probes", action="store_true", help="Send one inert marker POST per discovered form; may change target data and requires authorization")
    parser.add_argument("--allow-private", action="store_true", help="Allow private/loopback IP targets (use only on your own lab network)")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= args.max_pages <= 500:
        parser.error("--max-pages must be between 1 and 500")
    if not 0 <= args.max_depth <= 8:
        parser.error("--max-depth must be between 0 and 8")
    if not 0.1 <= args.delay <= 10:
        parser.error("--delay must be between 0.1 and 10 seconds")
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if args.passive and args.post_probes:
        parser.error("--post-probes cannot be used with --passive")


def run_scan(args: argparse.Namespace) -> dict:
    started = datetime.now(timezone.utc)
    options = {
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "delay": args.delay,
        "timeout": args.timeout,
        "allow_private": args.allow_private,
        "passive": args.passive,
        "allow_post_probes": args.post_probes,
        "max_response_bytes": 131072,
        "max_requests": max(80, args.max_pages * 8),
        "max_cached_responses": 100,
        "max_cached_response_bytes": 2_000_000,
    }
    ctx = ScanContext(args.target, options)

    # The core discovery phase builds the bounded URL/form scope shared by the plugins.
    run_core(ctx)
    plugin_results, plugins_enabled = run_plugins(ctx, include_active=not args.passive)
    options["plugins_enabled"] = plugins_enabled

    finished = datetime.now(timezone.utc)
    findings = sorted(ctx.findings, key=lambda item: ("critical high medium low info".split().index(item.severity.lower()) if item.severity.lower() in "critical high medium low info".split() else 5, item.id, item.url))
    counts = {level: sum(1 for item in findings if item.severity.lower() == level) for level in ("critical", "high", "medium", "low", "info")}
    return {
        "tool": {"name": "SiteAudit", "version": __version__},
        "target": redact_url(ctx.base_url),
        "started_at": started.isoformat(),
        "completed_at": finished.isoformat(),
        "settings": options,
        "summary": {"findings": len(findings), "severity_counts": counts, "pages_visited": len(ctx.discovered_urls), "requests_sent": ctx.request_count, "responses_cached": len(ctx.discovered_responses), "response_cache_limited": ctx.response_cache_limited, "plugin_results": plugin_results},
        "findings": [item.to_dict() for item in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)
    try:
        report = run_scan(args)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (PluginExecutionError, ValueError, OSError) as exc:
        print(f"siteaudit: {exc}", file=sys.stderr)
        return 2
    print(f"Scanned {report['target']}: {report['summary']['findings']} findings, {report['summary']['pages_visited']} pages")
    print(f"JSON report: {output.resolve()}")
    return 0
