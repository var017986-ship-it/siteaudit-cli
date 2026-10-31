"""Optional adapter for the upstream Wapiti command-line scanner."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .external_support import (
    EngineRunError,
    add_engine_finding,
    find_executable,
    run_command,
    scoped_url,
)


_SAFE_MODULES = ("cookieflags", "csp", "http_header", "http_headers", "nikto", "sql", "crlf")
_WAPITI_LEVELS = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def _read_json_report(report_path: Path) -> dict[str, Any]:
    try:
        if not report_path.is_file():
            raise EngineRunError("Wapiti did not create its JSON report")
        if report_path.stat().st_size > 16_000_000:
            raise EngineRunError("Wapiti JSON report exceeded 16 MB")
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngineRunError(f"Could not read Wapiti JSON report: {exc}") from exc
    if not isinstance(payload, dict):
        raise EngineRunError("Wapiti JSON report has an invalid root object")
    return payload


def _available_safe_modules(executable: str, timeout: float) -> list[str]:
    result = run_command([executable, "--list-modules"], timeout=min(timeout, 15.0))
    if result.returncode != 0:
        raise EngineRunError("Wapiti could not list its installed attack modules")

    available_names: set[str] = set()
    for line in f"{result.stdout}\n{result.stderr}".splitlines():
        candidate = line.strip().lstrip("-* ").lower()
        match = re.match(r"(?:mod_)?([a-z0-9_]+)(?:\s|:|$)", candidate)
        if match:
            available_names.add(match.group(1))
    available = [
        module for module in _SAFE_MODULES
        if module in available_names
    ]
    if not available:
        raise EngineRunError("Wapiti has none of the supported low-impact modules installed")
    return available


def _version(executable: str, timeout: float) -> str | None:
    result = run_command([executable, "--version"], timeout=min(timeout, 10.0))
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.strip():
            return line.strip()[:120]
    return None


def _items(section: Any):
    if isinstance(section, dict):
        for category, entries in section.items():
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        yield str(category), entry
    elif isinstance(section, list):
        for entry in section:
            if isinstance(entry, dict):
                yield "Wapiti finding", entry


def _severity(value: Any, default: str) -> str:
    if isinstance(value, bool):
        return default
    normalized = str(value).strip().lower()
    return _WAPITI_LEVELS.get(normalized, normalized if normalized in {"critical", "high", "medium", "low", "info"} else default)


def _finding_url(ctx: Any, value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return scoped_url(ctx, ctx.base_url)
    candidate = urljoin(ctx.base_url, value.strip())
    return scoped_url(ctx, candidate)


def _import_report(ctx: Any, report: dict[str, Any]) -> int:
    added = 0
    sections = (
        ("vulnerabilities", "medium"),
        ("anomalies", "low"),
        ("additionals", "info"),
        ("infos", "info"),
    )
    for section_name, default_severity in sections:
        for category, item in _items(report.get(section_name)):
            matched_url = _finding_url(ctx, item.get("path") or item.get("url"))
            if matched_url is None:
                # Never relabel an upstream out-of-scope URL as a target finding.
                continue
            parameter = item.get("parameter")
            method = item.get("method")
            info = item.get("info")
            detail_parts = [f"Wapiti section: {section_name}", f"module/category: {category}"]
            if isinstance(method, str) and method.strip():
                detail_parts.append(f"method: {method.strip()[:12]}")
            if isinstance(parameter, str) and parameter.strip():
                detail_parts.append(f"parameter: {parameter.strip()[:100]}")
            if isinstance(info, str) and info.strip():
                detail_parts.append(info.strip())

            issue_id = item.get("type") or item.get("id") or f"{section_name}.{category}"
            title = item.get("name") or item.get("vulnerability") or category
            references = item.get("references") or item.get("reference")
            if not references:
                references = []
            if isinstance(references, dict):
                references = [value for value in references.values() if isinstance(value, str)]

            if add_engine_finding(
                ctx,
                engine="wapiti",
                issue_id=issue_id,
                title=title,
                severity=_severity(item.get("level"), default_severity),
                url=matched_url,
                evidence="; ".join(detail_parts),
                recommendation=item.get("solution") or item.get("remediation"),
                references=references,
                confidence="medium",
            ):
                added += 1
    return added


def run(ctx: Any) -> dict[str, Any]:
    """Run Wapiti with its bounded, same-folder, non-OAST module selection."""
    executable = find_executable("wapiti", "wapiti3")
    options = getattr(ctx, "options", {}) or {}
    engine_timeout = min(max(float(options.get("external_engine_timeout", 300)), 15.0), 1800.0)
    request_timeout = min(max(float(options.get("timeout", 10)), 1.0), 60.0)
    max_depth = min(max(int(options.get("max_depth", 2)), 0), 8)
    max_pages = min(max(int(options.get("max_pages", 50)), 1), 500)
    modules = _available_safe_modules(executable, engine_timeout)
    version = _version(executable, engine_timeout)

    with tempfile.TemporaryDirectory(prefix="siteaudit-wapiti-") as temp_directory:
        temp_path = Path(temp_directory)
        report_path = temp_path / "wapiti-report.json"
        session_path = temp_path / "wapiti-session"
        link_limit = min(max_pages, 20)
        file_limit = min(max_pages, 50)
        max_scan_time = max(1.0, engine_timeout - 5.0)
        command = [
            executable,
            "--url", ctx.base_url,
            "--scope", "folder",
            "--module", ",".join(modules),
            "--depth", str(max_depth),
            "--max-links-per-page", str(link_limit),
            "--max-files-per-dir", str(file_limit),
            "--max-parameters", "8",
            "--max-scan-time", f"{max_scan_time:g}",
            "--max-attack-time", f"{max_scan_time:g}",
            "--scan-force", "polite",
            "--tasks", "1",
            "--timeout", str(int(request_timeout)),
            "--verify-ssl", "1",
            "--no-bugreport",
            "--flush-session",
            "--store-session", str(session_path),
            "--format", "json",
            "--output", str(report_path),
        ]
        result = run_command(
            command,
            timeout=engine_timeout,
            cwd=temp_path,
            monitored_paths=[report_path, session_path],
        )
        if not report_path.exists():
            raise EngineRunError(f"Wapiti exited with code {result.returncode} without a JSON report")
        report = _read_json_report(report_path)
        imported = _import_report(ctx, report)

    return {
        "status": "completed" if result.returncode == 0 else "partial",
        "version": version,
        "exit_code": result.returncode,
        "duration_seconds": result.duration_seconds,
        "requests_sent": None,
        "findings_imported": imported,
        "modules": modules,
        "scope": "folder (rooted at the supplied URL)",
        "scope_note": "Imported findings are checked against host and port; upstream redirects are not intercepted by SiteAudit.",
        "rate_control": "one task with polite scan force; Wapiti has no global requests-per-second flag",
        "report_format": "json",
    }
