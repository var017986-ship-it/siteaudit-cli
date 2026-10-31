"""Low-impact, Nikto-inspired checks for common web-server exposures.

This module intentionally does not ship or copy Nikto's signature database.
It performs a short list of metadata-only checks using HEAD and OPTIONS.
Sensitive file contents are never requested or included in findings.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


# Keep this list small and focused. HEAD avoids downloading potentially
# sensitive files while still identifying paths that appear to be published.
_SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/.env", "Environment configuration file may be reachable", "high"),
    ("/.git/HEAD", "Git metadata file may be reachable", "medium"),
    ("/.svn/entries", "Subversion metadata file may be reachable", "medium"),
    ("/.DS_Store", "Filesystem metadata file may be reachable", "low"),
    ("/wp-config.php", "WordPress configuration path may be reachable", "high"),
    ("/web.config", "Web server configuration path may be reachable", "high"),
    ("/config.php", "Configuration file path may be reachable", "high"),
    ("/config.json", "Configuration file path may be reachable", "high"),
    ("/phpinfo.php", "PHP diagnostic page may be reachable", "medium"),
    ("/server-status", "Apache server status page may be reachable", "medium"),
    ("/server-info", "Apache server information page may be reachable", "low"),
    ("/backup.zip", "Archive backup path may be reachable", "high"),
    ("/backup.tar.gz", "Archive backup path may be reachable", "high"),
    ("/db.sql", "Database dump path may be reachable", "critical"),
    ("/dump.sql", "Database dump path may be reachable", "critical"),
    ("/composer.json", "Dependency manifest path may be reachable", "info"),
    ("/package.json", "Dependency manifest path may be reachable", "info"),
)

_REPORTABLE = {200, 206}


def _origin(base_url: str) -> str:
    """Return just the target origin, so probes always start at its root."""
    parsed = urlsplit(base_url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _header(headers, name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value).strip()
    return ""


def _head(ctx, url: str):
    """Issue a bodyless request through the shared bounded client."""
    try:
        return ctx.request("HEAD", url, max_bytes=0)
    except Exception:
        # Network errors are already collected by the shared context. One
        # unavailable probe should not stop the remainder of the scan.
        return None


def _metadata_findings(ctx) -> None:
    """Report version banners as informational hardening observations."""
    response = _head(ctx, ctx.base_url)
    if response is None or getattr(response, "status_code", 0) == 0:
        return

    server = _header(response.headers, "server")
    powered_by = _header(response.headers, "x-powered-by")
    for header_name, value in (("Server", server), ("X-Powered-By", powered_by)):
        if not value:
            continue
        # Limit reflected data in the report and prevent multiline/header junk.
        safe_value = " ".join(value.replace("\r", " ").replace("\n", " ").split())[:120]
        ctx.add_finding(
            id=f"nikto.banner.{header_name.lower().replace('-', '_')}",
            title=f"{header_name} response header discloses implementation details",
            severity="info",
            confidence="high",
            url=ctx.base_url,
            evidence=f"Response header {header_name}: {safe_value}",
            recommendation="If practical, suppress detailed product/version banners at the web server or application layer.",
            category="server_disclosure",
        )


def _check_sensitive_paths(ctx, origin: str) -> None:
    for path, title, severity in _SENSITIVE_PATHS:
        url = origin + path
        response = _head(ctx, url)
        if response is None:
            continue

        status = getattr(response, "status_code", 0)
        if status not in _REPORTABLE:
            continue

        content_type = _header(getattr(response, "headers", {}), "content-type")
        content_length = _header(getattr(response, "headers", {}), "content-length")
        evidence_parts = [f"HEAD returned HTTP {status}"]
        if content_type:
            evidence_parts.append(f"Content-Type: {content_type[:100]}")
        if content_length.isdigit():
            evidence_parts.append(f"Content-Length: {content_length} bytes")
        evidence_parts.append("Response body was not requested; verify manually")

        ctx.add_finding(
            id="nikto.exposed_path." + path.strip("/").replace("/", ".").replace(".", "_"),
            title=title,
            severity=severity,
            confidence="low",
            url=url,
            evidence="; ".join(evidence_parts),
            recommendation=(
                "Confirm that this resource is intentionally public. Remove it from the web root or deny access; "
                "rotate any credentials if sensitive data was exposed. A 200 response alone can be a catch-all route."
            ),
            category="server_exposure",
        )


def _check_allowed_methods(ctx) -> None:
    try:
        response = ctx.request("OPTIONS", ctx.base_url, max_bytes=0)
    except Exception:
        return
    if response is None or getattr(response, "status_code", 0) == 0:
        return

    allow = _header(getattr(response, "headers", {}), "allow")
    if not allow:
        return

    methods = {method.strip().upper() for method in allow.split(",") if method.strip()}
    unusual = sorted(methods & {"TRACE", "PUT", "DELETE", "CONNECT"})
    if not unusual:
        return

    ctx.add_finding(
        id="nikto.http.unusual_methods",
        title="OPTIONS advertises potentially risky HTTP methods",
        severity="low",
        confidence="medium",
        url=ctx.base_url,
        evidence=f"Allow header lists: {', '.join(unusual)}. OPTIONS is advisory and does not prove these methods work.",
        recommendation="Disable methods the application does not need, and verify the policy at the origin server and application layer.",
        category="server_configuration",
    )


def run(ctx) -> int:
    """Run bounded metadata-only web-server checks and append findings."""
    requests_before = ctx.request_count
    origin = _origin(ctx.base_url)
    _check_sensitive_paths(ctx, origin)
    _check_allowed_methods(ctx)
    return ctx.request_count - requests_before
