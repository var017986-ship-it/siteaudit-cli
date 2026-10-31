"""Optional, bounded adapter for the legacy upstream W3AF console scanner.

W3AF's script interface and XML schema are documented/implemented at:
https://docs.w3af.org/en/stable/scripts.html
https://github.com/andresriancho/w3af/blob/master/w3af/plugins/output/xml_file/finding.tpl
"""

from __future__ import annotations

import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .external_support import (
    EngineRunError,
    EngineUnavailable,
    add_engine_finding,
    find_executable,
    run_command,
    scoped_url,
)


_MAX_REPORT_BYTES = 16_000_000
_CONFIGURED_PLUGINS = {
    "xss",
    "sqli",
    "ssl_certificate",
    "csp",
    "html_comments",
    "click_jacking",
    "directory_indexing",
    "form_cleartext_password",
    "form_autocomplete",
    "cache_control",
    "xss_protection_header",
    "path_disclosure",
    "error_500",
    "code_disclosure",
}
_SEVERITIES = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "informational": "info",
    "info": "info",
}


def _bounded_option(options: dict[str, Any], key: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(options.get(key, default))
    except (TypeError, ValueError, OverflowError):
        value = default
    return min(max(value, lower), upper)


def _safe_target(ctx: Any) -> tuple[str, str, str]:
    target = getattr(ctx, "base_url", None)
    if not isinstance(target, str) or not target or any(ch.isspace() or ord(ch) < 32 for ch in target):
        raise EngineRunError("W3AF target cannot be represented safely in its line-based script")
    if any(ch in target for ch in ";'\"\\"):
        raise EngineRunError("W3AF target contains characters that are unsafe in its console script")

    try:
        ctx._check_scope(target)
        parts = urlsplit(target)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("target is not an absolute HTTP(S) URL")
        if parts.username or parts.password:
            raise ValueError("embedded credentials are not allowed")
        port = parts.port
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EngineRunError(f"Invalid W3AF target: {exc}") from exc

    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    origin = f"{parts.scheme.lower()}://{netloc}"
    return target, origin, parts.path or "/"


def _same_origin_depth_regex(origin: str, base_path: str, max_depth: int) -> str:
    """Build an anchored allow-list for only the requested origin and path depth."""
    segments = [segment for segment in base_path.split("/") if segment]
    prefix = "/" + "/".join(segments) if segments else ""
    path_pattern = re.escape(prefix)
    remainder = rf"(?:/[^/?#]+){{0,{max_depth}}}/?"
    return rf"^{re.escape(origin)}{path_pattern}{remainder}(?:\?[^#]*)?$"


def _script(
    target: str,
    origin_filter: str,
    report_path: Path,
    request_timeout: int,
    discovery_seconds: int,
    proxy_host: str,
    proxy_port: int,
) -> str:
    # W3AF documents one console command per line. Only the crawl, audit, grep,
    # and XML-output groups are configured; exploit/bruteforce/evasion/mangle
    # are never entered.
    lines = [
        "plugins",
        "output xml_file",
        "output config xml_file",
        f"set output_file {report_path}",
        "back",
        "crawl web_spider",
        "crawl config web_spider",
        "set only_forward False",
        f"set follow_regex {origin_filter}",
        "back",
        "audit xss, sqli, ssl_certificate",
        "audit config xss",
        "set persistent_xss False",
        "back",
        "grep csp, html_comments, click_jacking, directory_indexing, form_cleartext_password, form_autocomplete, cache_control, xss_protection_header, path_disclosure, error_500, code_disclosure",
        "back",
        "back",
        "target",
        f"set target {target}",
        "back",
        "http-settings",
        f"set timeout {request_timeout}",
        "set max_requests_per_second 1",
        f"set proxy_address {proxy_host}",
        f"set proxy_port {proxy_port}",
        "back",
        "misc-settings",
        f"set max_discovery_time {discovery_seconds}",
        "back",
        "start",
        "exit",
    ]
    return "\n".join(lines) + "\n"


def _read_report(path: Path) -> ET.Element:
    try:
        if not path.is_file():
            raise EngineRunError("W3AF did not create its XML report")
        if path.stat().st_size > _MAX_REPORT_BYTES:
            raise EngineRunError("W3AF XML report exceeded 16 MB")
        payload = path.read_bytes()
    except OSError as exc:
        raise EngineRunError(f"Could not read W3AF XML report: {exc}") from exc

    upper_payload = payload.upper()
    if b"<!DOCTYPE" in upper_payload or b"<!ENTITY" in upper_payload:
        raise EngineRunError("W3AF XML report contains a prohibited DTD or entity declaration")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise EngineRunError(f"Could not parse W3AF XML report: {exc}") from exc
    if root.tag != "w3af-run":
        raise EngineRunError("W3AF XML report has an unexpected root element")
    return root


def _import_findings(ctx: Any, root: ET.Element) -> int:
    added = 0
    for item in root.findall("vulnerability"):
        plugin = (item.get("plugin") or "").strip().lower()
        if plugin not in _CONFIGURED_PLUGINS:
            continue

        url = scoped_url(ctx, item.get("url"))
        if url is None:
            # Do not turn an out-of-scope or malformed URL into a target finding.
            continue

        parameter = (item.get("var") or "").strip()
        method = (item.get("method") or "").strip().upper()
        evidence_parts = [f"W3AF plugin: {plugin}"]
        if method and re.fullmatch(r"[A-Z]{1,12}", method):
            evidence_parts.append(f"method: {method}")
        if parameter and not any(ord(ch) < 32 for ch in parameter):
            evidence_parts.append(f"parameter: {parameter[:100]}")

        references = [
            reference.get("url", "")
            for reference in item.findall("./references/reference")
            if reference.get("url", "").startswith("https://")
        ]
        severity = _SEVERITIES.get((item.get("severity") or "").strip().lower(), "info")
        if add_engine_finding(
            ctx,
            engine="w3af",
            issue_id=item.get("id") or f"{plugin}.{item.get('name') or 'finding'}",
            title=item.get("name") or f"W3AF {plugin} finding",
            severity=severity,
            url=url,
            evidence="; ".join(evidence_parts),
            recommendation="Review the affected endpoint and apply the recommended secure coding or configuration fix.",
            references=references,
            confidence="medium",
        ):
            added += 1
    return added


def run(ctx: Any) -> dict[str, Any]:
    """Run W3AF with exact-origin scope and bounded discovery/runtime settings."""
    if os.name == "nt":
        raise EngineUnavailable(
            "W3AF does not support Windows; its official installation targets Linux/macOS and legacy Python 2.7 environments"
        )

    executable = find_executable("w3af_console")
    target, origin, base_path = _safe_target(ctx)
    options = getattr(ctx, "options", {}) or {}
    engine_timeout = _bounded_option(options, "external_engine_timeout", 300, 30, 1800)
    request_timeout = _bounded_option(options, "timeout", 10, 1, 60)
    max_depth = _bounded_option(options, "max_depth", 2, 0, 8)
    max_pages = _bounded_option(options, "max_pages", 50, 1, 500)
    proxy_url = options.get("external_proxy_url")
    if not isinstance(proxy_url, str) or not proxy_url:
        raise EngineRunError("W3AF requires the SiteAudit scope proxy")
    proxy_parts = urlsplit(proxy_url)
    if proxy_parts.hostname != "127.0.0.1" or proxy_parts.port is None or proxy_parts.username:
        raise EngineRunError("W3AF requires a local unauthenticated scope proxy")

    # W3AF has no hard page-count option. The path-depth regex and discovery
    # deadline constrain crawl breadth; the outer timeout bounds the whole run.
    discovery_seconds = min(max(1, max_pages * 2), max(1, engine_timeout // 2))
    origin_filter = _same_origin_depth_regex(origin, base_path, max_depth)

    with tempfile.TemporaryDirectory(prefix="siteaudit-w3af-") as temp_directory:
        temp_path = Path(temp_directory)
        report_path = temp_path / "w3af-report.xml"
        script_path = temp_path / "w3af-scan.script"
        if any(ch.isspace() or ch in ";'\"\\" for ch in str(report_path) + str(script_path)):
            raise EngineRunError("Temporary path cannot be represented safely in a W3AF script")
        try:
            script_path.write_text(
                _script(
                    target,
                    origin_filter,
                    report_path,
                    request_timeout,
                    discovery_seconds,
                    proxy_parts.hostname,
                    proxy_parts.port,
                ),
                encoding="utf-8",
                newline="\n",
            )
        except OSError as exc:
            raise EngineRunError(f"Could not create W3AF temporary script: {exc}") from exc

        result = run_command(
            [executable, "-s", str(script_path)],
            timeout=engine_timeout,
            cwd=temp_path,
            monitored_paths=[report_path],
        )
        root = _read_report(report_path)
        imported = _import_findings(ctx, root)
        error_count = len(root.findall("error"))
        version_node = root.find("w3af-version")
        version = " ".join((version_node.text or "").split())[:120] if version_node is not None else None
        if not version:
            raise EngineRunError("W3AF XML report is missing its version marker")

    completed = result.returncode == 0 and error_count == 0
    return {
        "status": "completed" if completed else "partial",
        "version": version,
        "exit_code": result.returncode,
        "duration_seconds": result.duration_seconds,
        "findings_imported": imported,
        "plugins": ["web_spider", "xss", "sqli", "ssl_certificate", "selected passive grep plugins"],
        "scope": "discovered links are filtered to the exact target origin and configured path depth; imported findings are scope-checked",
        "scope_note": "The scope proxy restricts HTTP requests and HTTPS tunnels to the selected host and port and pins the IP; HTTPS Host headers inside TLS are not inspected. Smart-filled forms may submit data.",
        "max_depth": max_depth,
        "max_pages": max_pages,
        "max_pages_enforced": False,
        "rate_limit_requests_per_second": 1,
        "discovery_timeout_seconds": discovery_seconds,
        "report_format": "xml_file",
        "report_errors": error_count,
        "raw_http_content_imported": False,
        "limitations": [
            "W3AF does not expose a hard max-pages option; discovery time and path depth are bounded instead.",
            "The W3AF crawler smart-fills discovered forms, so form submissions can change application state; use only on a staging target prepared for testing.",
            "HTTPS Host headers are encrypted inside CONNECT tunnels and cannot be checked by the scope proxy.",
            "The upstream project is legacy and is not supported on Windows.",
        ],
    }
