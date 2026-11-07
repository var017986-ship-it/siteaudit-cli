from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .context import ScanContext
from .core_checks import run as run_core
from .external_engines import run as run_external_engines
from .engine_status import get_engine_status
from .models import redact_url
from .plugins import PluginExecutionError, run_plugins


class ProgressReporter:
    """Terminal progress display with a rough ETA derived from completed work."""

    def __init__(self, args: argparse.Namespace):
        self._is_tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        self._started = time.monotonic()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._progress = 0.0
        self._label = "Подготовка сканирования"
        self._last_line_length = 0
        self._eta: float | None = None
        external_count = 5 if "all" in args.engine else len(set(args.engine))
        self._external_count = external_count
        self._external_timeout = float(args.engine_timeout)
        self._external_started_at: float | None = None
        self._external_completed = 0
        self._external_total = external_count
        self._weights = {"crawl": 0.35, "plugins": 0.65}
        if getattr(args, "external_only", False):
            self._weights = {"external": 1.0} if external_count else {}
        elif external_count:
            self._weights = {"crawl": 0.25, "plugins": 0.5, "external": 0.25}
        self._starts: dict[str, float] = {}
        offset = 0.0
        for stage, weight in self._weights.items():
            self._starts[stage] = offset
            offset += weight

    def start(self) -> None:
        print(
            "             .-----------------.\n"
            "          .-'   .---------.     '-.\n"
            "         /     /  .-----.  \\      \\ \n"
            "        /     |  /  .-.  \\  |      \\ \n"
            "       |      | |  ( o )  | |       |\n"
            "       |      |  \\  ^  /  |        |\n"
            "       |       \\  '---'  /         |\n"
            "       |    .---'-.   .-'---.       |\n"
            "       |   /   .---( O )---.  \\      |\n"
            "       |   \\   '-----------' /      |\n"
            "        \\   '-.           .-'      /\n"
            "         '-.    '---------'      .-'\n"
            "            '-------------------'\n"
            "                 SITEAUDIT",
            flush=True,
        )
        if self._is_tty:
            self._thread = threading.Thread(target=self._render_loop, daemon=True)
            self._thread.start()
        else:
            self._print_line()

    def crawl(self, stage: str, current: int, total: int, url: str) -> None:
        fraction = current / max(total, 1)
        self.update(stage, fraction, f"Обход {current}/{total} страниц")

    def plugin(self, state: str, current: int, total: int, name: str) -> None:
        fraction = current / max(total, 1)
        label = f"Плагин {current}/{total}: {name[:18]}"
        self.update("plugins", fraction, label)

    def external(self, state: str, current: int, total: int, name: str) -> None:
        fraction = current / max(total, 1)
        label = f"Движок {current}/{total}: {name[:22]}"
        with self._lock:
            self._external_total = total
            self._external_completed = current
            self._external_started_at = time.monotonic() if state == "start" else None
        self.update("external", fraction, label)

    def update(self, stage: str, fraction: float, label: str) -> None:
        if stage in self._starts:
            absolute = self._starts[stage] + self._weights[stage] * min(max(fraction, 0.0), 1.0)
            with self._lock:
                self._progress = max(self._progress, min(absolute, 0.999))
                self._label = label
                self._update_eta_locked()
        else:
            with self._lock:
                self._label = label
        if not self._is_tty:
            self._print_line()

    def finish_stage(self, stage: str, label: str) -> None:
        self.update(stage, 1.0, label)

    def finish(self, success: bool) -> None:
        with self._lock:
            self._progress = 1.0 if success else self._progress
            self._label = "Сканирование завершено" if success else "Сканирование остановлено с ошибкой"
            self._eta = 0.0 if success else None
            if success:
                self._external_completed = self._external_total
                self._external_started_at = None
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self._print_line(newline=True)

    def _update_eta_locked(self) -> None:
        elapsed = time.monotonic() - self._started
        if self._progress < 0.03 or elapsed < 1:
            return
        estimate = elapsed * (1.0 - self._progress) / self._progress
        if self._eta is None:
            self._eta = estimate
        else:
            self._eta = 0.65 * self._eta + 0.35 * estimate

    def _render_loop(self) -> None:
        while not self._stop.wait(0.5):
            self._print_line()

    def _print_line(self, *, newline: bool = False) -> None:
        with self._lock:
            progress = self._progress
            label = self._label
            eta = self._eta
            external_started_at = self._external_started_at
            external_completed = self._external_completed
            external_total = self._external_total
        elapsed = time.monotonic() - self._started
        current_engine_elapsed = 0.0
        if self._external_count and external_started_at is not None:
            current_engine_elapsed = time.monotonic() - external_started_at
            external_fraction = (
                external_completed
                + min(current_engine_elapsed / max(self._external_timeout, 1.0), 0.95)
            ) / max(external_total, 1)
            external_progress = self._starts["external"] + self._weights["external"] * external_fraction
            progress = max(progress, external_progress)
        width = 12
        filled = min(width, round(progress * width))
        bar = "#" * filled + "-" * (width - filled)
        eta_prefix = "~"
        if self._external_count and external_started_at is not None:
            current_engine_left = max(1.0, self._external_timeout - current_engine_elapsed)
            eta = current_engine_left + max(0, external_total - external_completed - 1) * self._external_timeout
            eta_prefix = "≤"
        elif self._external_count and external_completed < self._external_count:
            if progress >= 0.03 and elapsed >= 1:
                eta = elapsed * (1.0 - progress) / progress
            eta = (eta or 0.0) + (self._external_count - external_completed) * self._external_timeout
            eta_prefix = "≤"
        elif progress >= 0.03 and elapsed >= 1:
            eta = elapsed * (1.0 - progress) / progress
        eta_text = "считаю" if eta is None else _format_duration(max(0, eta))
        line = f"[{bar}] {progress * 100:3.0f}% | {label[:30]} | t+{_format_duration(elapsed)} | ETA {eta_prefix}{eta_text}"
        if self._is_tty:
            padding = " " * max(0, self._last_line_length - len(line))
            sys.stdout.write("\r" + line + padding + ("\n" if newline else ""))
            sys.stdout.flush()
            self._last_line_length = len(line)
        else:
            print(line, flush=True)


def _format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="siteaudit", description="Bounded HTTP security checks for authorized web targets.")
    parser.add_argument("target", nargs="?", help="Target URL or domain (for example, https://example.com)")
    parser.add_argument("--output", "-o", default="siteaudit-report.json", help="JSON report path (default: siteaudit-report.json)")
    parser.add_argument("--max-pages", type=int, default=50, help="Built-in crawl page cap and per-engine tuning input (1-500, default: 50)")
    parser.add_argument("--max-depth", type=int, default=2, help="Built-in crawl depth and per-engine tuning input (0-8, default: 2)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay for built-in requests; upstream engines apply it where supported (0.1-10, default: 0.5)")
    parser.add_argument("--timeout", type=float, default=10, help="HTTP timeout in seconds (1-60, default: 10)")
    parser.add_argument("--passive", action="store_true", help="Skip active templates and probes; crawl and inspect fetched responses only")
    parser.add_argument("--post-probes", action="store_true", help="Send one inert marker POST per discovered form; may change target data and requires authorization")
    parser.add_argument("--sqli-probes", action="store_true", help="Run repeated boolean checks on up to two numeric GET parameters; may change GET query behavior")
    parser.add_argument("--graphql-probe", action="store_true", help="Send a bounded read-only GraphQL introspection query to up to three same-host endpoints")
    parser.add_argument("--templates-file", help="Load safe JSON or restricted Nuclei YAML templates from a local file")
    parser.add_argument("--engine", action="append", choices=("all", "nuclei", "nikto", "wapiti", "zap", "w3af"), default=[], help="Also run an installed upstream scanner; repeat or use 'all'")
    parser.add_argument("--engine-timeout", type=int, default=300, help="Scan budget per upstream engine in seconds (30-1800; ZAP baseline/active need 120/180+, default: 300)")
    parser.add_argument("--nuclei-templates", help="Use and filter local Nuclei templates (default: managed engine pack, then ~/nuclei-templates)")
    parser.add_argument("--nuclei-tags", help="Run only Nuclei templates with these comma-separated tags (for example: misconfig,exposure)")
    parser.add_argument("--nuclei-auto-scan", action="store_true", help="Let Nuclei select a narrower template set from detected web technologies")
    parser.add_argument("--zap-active", action="store_true", help="Use ZAP full active scan instead of passive baseline; may change target behavior")
    parser.add_argument("--allow-private", action="store_true", help="Allow private/loopback IP targets (use only on your own lab network)")
    parser.add_argument("--doctor", action="store_true", help="Check whether upstream scanners and their local prerequisites are ready; does not scan a target")
    parser.add_argument("--doctor-json", action="store_true", help="Print the read-only upstream engine readiness report as JSON")
    parser.add_argument("--external-only", action="store_true", help="Skip SiteAudit's built-in crawl and checks; run only the selected upstream engines")
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
    if not 30 <= args.engine_timeout <= 1800:
        parser.error("--engine-timeout must be between 30 and 1800 seconds")
    if args.passive and args.engine:
        parser.error("--engine cannot be used with --passive")
    if args.external_only and not args.engine:
        parser.error("--external-only requires at least one --engine")
    if args.external_only and args.passive:
        parser.error("--external-only cannot be combined with --passive")
    if args.external_only and (args.post_probes or args.sqli_probes or args.graphql_probe or args.templates_file):
        parser.error("--external-only cannot be combined with SiteAudit-only probes or --templates-file")
    if args.nuclei_templates and "nuclei" not in args.engine and "all" not in args.engine:
        parser.error("--nuclei-templates requires --engine nuclei")
    if args.nuclei_auto_scan and "nuclei" not in args.engine and "all" not in args.engine:
        parser.error("--nuclei-auto-scan requires --engine nuclei")
    if args.nuclei_tags is not None:
        if "nuclei" not in args.engine and "all" not in args.engine:
            parser.error("--nuclei-tags requires --engine nuclei")
        if args.nuclei_auto_scan:
            parser.error("--nuclei-tags cannot be combined with --nuclei-auto-scan")
        tags = [item.strip().lower() for item in args.nuclei_tags.split(",")]
        if not 1 <= len(tags) <= 50 or any(not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item) for item in tags):
            parser.error("--nuclei-tags must be a comma-separated list of 1-50 simple tag names")
        args.nuclei_tags = ",".join(dict.fromkeys(tags))
    if args.nuclei_templates:
        nuclei_templates = Path(args.nuclei_templates).expanduser()
        if not nuclei_templates.exists() or not (nuclei_templates.is_file() or nuclei_templates.is_dir()):
            parser.error("--nuclei-templates must point to an existing local template file or directory")
    if args.zap_active and "zap" not in args.engine and "all" not in args.engine:
        parser.error("--zap-active requires --engine zap")
    if args.passive and args.post_probes:
        parser.error("--post-probes cannot be used with --passive")
    if args.passive and args.sqli_probes:
        parser.error("--sqli-probes cannot be used with --passive")
    if args.passive and args.graphql_probe:
        parser.error("--graphql-probe cannot be used with --passive")
    if args.passive and args.templates_file:
        parser.error("--templates-file requires active scanning and cannot be used with --passive")


def run_scan(args: argparse.Namespace, progress: ProgressReporter | None = None) -> dict:
    started = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    options = {
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "delay": args.delay,
        "timeout": args.timeout,
        "allow_private": args.allow_private,
        "passive": args.passive,
        "allow_post_probes": args.post_probes,
        "allow_sqli_probes": args.sqli_probes,
        "allow_graphql_probe": args.graphql_probe,
        "templates_file": args.templates_file,
        "external_engines": args.engine,
        "external_engine_timeout": args.engine_timeout,
        "nuclei_templates": args.nuclei_templates,
        "nuclei_tags": args.nuclei_tags,
        "nuclei_auto_scan": args.nuclei_auto_scan,
        "zap_active": args.zap_active,
        "external_only": args.external_only,
        "max_response_bytes": 131072,
        "max_requests": max(80, args.max_pages * 8),
        "max_cached_responses": 100,
        "max_cached_response_bytes": 2_000_000,
    }
    ctx = ScanContext(args.target, options)

    if not args.passive and not args.external_only:
        from .template_engine import prepare as prepare_templates
        prepare_templates(ctx)

    if args.external_only:
        plugin_results: dict[str, Any] = {}
        plugins_enabled: list[str] = []
    else:
        # The core discovery phase builds the bounded URL/form scope shared by the plugins.
        if progress:
            progress.update("prepare", 0, "Обход и сбор страниц")
        run_core(ctx, progress=progress.crawl if progress else None)
        if progress:
            progress.finish_stage("crawl", f"Обход завершён: {len(ctx.discovered_urls)} страниц")
        plugin_results, plugins_enabled = run_plugins(
            ctx,
            include_active=not args.passive,
            progress=progress.plugin if progress else None,
        )
        if progress:
            progress.finish_stage("plugins", "Проверки SiteAudit завершены")
    external_results = run_external_engines(ctx, progress=progress.external if progress else None)
    if progress and "external" in progress._weights:
        progress.finish_stage("external", "Внешние сканеры завершены")
    if external_results:
        plugin_results["external_engines"] = external_results
        plugins_enabled.extend(f"external_{name}" for name in external_results)
    options["plugins_enabled"] = plugins_enabled

    finished = datetime.now(timezone.utc)
    findings = sorted(ctx.findings, key=lambda item: ("critical high medium low info".split().index(item.severity.lower()) if item.severity.lower() in "critical high medium low info".split() else 5, item.id, item.url))
    counts = {level: sum(1 for item in findings if item.severity.lower() == level) for level in ("critical", "high", "medium", "low", "info")}
    partial_reasons: list[str] = []
    if ctx.request_limit_reached:
        partial_reasons.append("built_in_request_limit_reached")
    for plugin_name, plugin_result in plugin_results.items():
        if plugin_name == "external_engines" and isinstance(plugin_result, dict):
            for engine_name, engine_result in plugin_result.items():
                if isinstance(engine_result, dict) and engine_result.get("status") in {"partial", "error", "unavailable"}:
                    partial_reasons.append(f"external_engine_{engine_name}_{engine_result['status']}")
        elif isinstance(plugin_result, dict) and plugin_result.get("status") == "partial":
            partial_reasons.append(f"plugin_{plugin_name}_partial")
    scan_status = "partial" if partial_reasons else "completed"
    return {
        "tool": {"name": "SiteAudit", "version": __version__},
        "status": scan_status,
        "target": redact_url(ctx.base_url),
        "started_at": started.isoformat(),
        "completed_at": finished.isoformat(),
        "duration_seconds": round(time.monotonic() - started_monotonic, 3),
        "settings": {
            **{key: value for key, value in options.items() if key not in {"templates_file", "nuclei_templates"}},
            "built_in_crawl_limits": {"max_pages": args.max_pages, "max_depth": args.max_depth},
            "external_page_limits_are_engine_specific": True,
            "custom_templates_enabled": bool(args.templates_file),
        },
        "summary": {
            "status": scan_status,
            "partial_reasons": partial_reasons,
            "findings": len(findings),
            "severity_counts": counts,
            "pages_visited": len(ctx.discovered_urls),
            "requests_sent": ctx.request_count,
            "request_limit_reached": ctx.request_limit_reached,
            "request_limit_blocked_attempts": ctx.request_limit_blocked_attempts,
            "responses_cached": len(ctx.discovered_responses),
            "response_cache_limited": ctx.response_cache_limited,
            "plugin_results": plugin_results,
        },
        "findings": [item.to_dict() for item in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.doctor or args.doctor_json:
        status = get_engine_status({"nuclei_templates": args.nuclei_templates})
        if args.doctor_json:
            print(json.dumps(status, indent=2, ensure_ascii=False))
        else:
            print("SiteAudit upstream engine readiness (read-only):")
            for name, details in status.items():
                state = str(details.get("status", "unknown")).upper()
                print(f"[{state}] {name}: {details.get('summary', '')}")
                if state != "READY":
                    print(f"         Next: {details.get('next_step', '')}")
            ready_count = sum(details.get("status") == "ready" for details in status.values())
            print(f"Ready: {ready_count}/{len(status)} upstream engines")
        return 0 if all(details.get("status") == "ready" for details in status.values()) else 1
    if not args.target:
        args.target = os.environ.get("SITEAUDIT_TARGET")
    if not args.target:
        parser.error("provide a target URL/domain or set SITEAUDIT_TARGET")
    _validate_args(parser, args)
    progress = ProgressReporter(args) if sys.stdout.isatty() else None
    if progress:
        progress.start()
    try:
        report = run_scan(args, progress=progress)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (PluginExecutionError, ValueError, OSError) as exc:
        if progress:
            progress.finish(False)
        print(f"siteaudit: {exc}", file=sys.stderr)
        return 2
    if progress:
        progress.finish(True)
    print(f"Scan {report['status']}: {report['target']} — {report['summary']['findings']} findings, {report['summary']['pages_visited']} built-in pages")
    print(f"JSON report: {output.resolve()}")
    return 1 if report["status"] == "partial" else 0
