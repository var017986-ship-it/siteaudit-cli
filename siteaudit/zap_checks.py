"""OWASP ZAP-inspired passive checks for already-fetched responses.

This module sends no requests. It only inspects the bounded response cache
created by the normal same-host crawler and records concise indicators.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


_REFERENCES = {
    "mixed_content": "https://www.w3.org/TR/mixed-content/",
    "csp": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "cors": "https://fetch.spec.whatwg.org/#cors-protocol-and-credentials",
}


class _ResourceParser(HTMLParser):
    """Collect only resource-bearing attributes that can create mixed content."""

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.insecure: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        candidates: list[tuple[str, str]] = []

        if tag == "script":
            candidates.append(("script", attributes.get("src", "")))
        elif tag in {"iframe", "frame"}:
            candidates.append(("frame", attributes.get("src", "")))
        elif tag == "object":
            candidates.append(("object", attributes.get("data", "")))
        elif tag == "embed":
            candidates.append(("embed", attributes.get("src", "")))
        elif tag == "img":
            candidates.append(("image", attributes.get("src", "")))
        elif tag in {"audio", "video", "source", "track"}:
            candidates.append(("media", attributes.get("src", "")))
            if tag == "video":
                candidates.append(("video poster", attributes.get("poster", "")))
        elif tag == "link":
            rel = {token.lower() for token in attributes.get("rel", "").split()}
            if "stylesheet" in rel:
                candidates.append(("stylesheet", attributes.get("href", "")))
            elif rel & {"preload", "modulepreload"}:
                candidates.append(("preloaded resource", attributes.get("href", "")))
        elif tag == "form":
            candidates.append(("form", attributes.get("action", "")))

        for resource_type, raw_url in candidates:
            if not raw_url.strip():
                continue
            resolved = urljoin(self.page_url, raw_url.strip())
            try:
                scheme = urlsplit(resolved).scheme.lower()
            except ValueError:
                continue
            if scheme == "http":
                self.insecure.append((resource_type, resolved))


def _add(ctx, *, finding_id: str, title: str, severity: str, confidence: str,
         url: str, evidence: str, recommendation: str, category: str,
         reference: str) -> None:
    ctx.add_finding(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=confidence,
        url=url,
        evidence=evidence,
        recommendation=recommendation,
        category=category,
        references=[reference],
    )


def _sanitize_destination(value: str) -> str:
    """Retain destination host/path for triage, dropping userinfo/query/fragment."""
    try:
        parts = urlsplit(value)
        hostname = parts.hostname or ""
        if not hostname:
            return "<invalid destination>"
        if ":" in hostname:
            hostname = f"[{hostname}]"
        if parts.port:
            hostname = f"{hostname}:{parts.port}"
        path = parts.path[:160]
        return urlunsplit((parts.scheme.lower(), hostname, path, "", ""))
    except ValueError:
        return "<invalid destination>"


def _responses(ctx):
    cache = getattr(ctx, "discovered_responses", {})
    if isinstance(cache, dict):
        yield from cache.items()
    elif isinstance(cache, (list, tuple)):
        for response in cache:
            yield getattr(response, "url", ""), response


def _media_type(response) -> str:
    headers = getattr(response, "headers", {}) or {}
    value = next(
        (str(value) for key, value in headers.items() if str(key).lower() == "content-type"),
        "",
    )
    return value.split(";", 1)[0].strip().lower()


def _is_html_document(response) -> bool:
    return _media_type(response) in {"text/html", "application/xhtml+xml"}


def _supports_error_disclosure_check(response) -> bool:
    media_type = _media_type(response)
    return (
        media_type in {
            "text/html", "application/xhtml+xml", "application/json",
            "application/problem+json", "text/plain", "application/xml", "text/xml",
        }
        or (media_type.startswith("application/") and media_type.endswith(("+json", "+xml")))
    )


def _check_mixed_content(ctx, page_url: str, response) -> None:
    if urlsplit(page_url).scheme.lower() != "https":
        return
    if "html" not in str(response.headers.get("content-type", "")).lower():
        return

    parser = _ResourceParser(page_url)
    try:
        parser.feed(response.text)
    except Exception:
        return
    if not parser.insecure:
        return

    resource_types = sorted({kind for kind, _ in parser.insecure})
    urls = sorted({_sanitize_destination(url) for _, url in parser.insecure})
    visible_urls = urls[:3]
    remaining = len(urls) - len(visible_urls)
    url_evidence = ", ".join(visible_urls)
    if remaining:
        url_evidence += f", and {remaining} more"
    _add(
        ctx,
        finding_id="zap.passive.mixed-content",
        title="HTTPS page references resources or forms over HTTP",
        severity="medium",
        confidence="high",
        url=page_url,
        evidence=(
            f"Found {len(urls)} insecure HTTP destination(s) for: "
            f"{', '.join(resource_types)}. Affected destinations: {url_evidence}. "
            "Query values, fragments, and URL credentials are omitted."
        ),
        recommendation=(
            "Serve referenced scripts, frames, stylesheets, and form actions over HTTPS, "
            "or remove unused references. Review each destination before changing it."
        ),
        category="mixed-content",
        reference=_REFERENCES["mixed_content"],
    )


def _check_csp(ctx, page_url: str, headers: dict[str, str]) -> None:
    policy = headers.get("content-security-policy", "")
    if not policy:
        return  # Missing CSP is already reported by the core scanner.

    directives: dict[str, list[str]] = {}
    for raw_directive in policy.split(";"):
        parts = raw_directive.strip().split()
        if parts:
            directives.setdefault(parts[0].lower(), [part.lower() for part in parts[1:]])

    weak: list[str] = []
    fallback = directives.get("default-src", [])
    for directive in ("script-src", "style-src"):
        values = directives.get(directive, fallback)
        has_nonce_or_hash = any(value.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for value in values)
        unsafe_inline = "'unsafe-inline'" in values and not has_nonce_or_hash
        if unsafe_inline or "'unsafe-eval'" in values:
            weak.append(f"{directive} permits unsafe inline/eval content")
        if "*" in values:
            weak.append(f"{directive} allows any source")
    if "*" in directives.get("default-src", []):
        weak.append("default-src allows any source")
    if "*" in directives.get("object-src", []):
        weak.append("object-src allows any source")
    if not weak:
        return

    _add(
        ctx,
        finding_id="zap.passive.weak-csp",
        title="Content Security Policy contains permissive directives",
        severity="low",
        confidence="high",
        url=page_url,
        evidence="; ".join(weak[:4]) + ". This weakens CSP protection but does not prove an XSS vulnerability.",
        recommendation=(
            "Remove unsafe-inline/unsafe-eval and broad wildcard sources where possible. "
            "Use nonces or hashes for required inline code and restrict each directive to trusted origins."
        ),
        category="security-policy",
        reference=_REFERENCES["csp"],
    )


def _check_cors(ctx, page_url: str, headers: dict[str, str]) -> None:
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    allow_credentials = headers.get("access-control-allow-credentials", "").strip()
    if allow_origin != "*" or allow_credentials != "true":
        return

    # Browsers reject wildcard ACAO when credentials are enabled. This is an
    # inconsistent policy, not evidence that credentialed cross-origin access works.
    _add(
        ctx,
        finding_id="zap.passive.cors-wildcard-credentials",
        title="CORS headers combine wildcard origin with credentials",
        severity="info",
        confidence="high",
        url=page_url,
        evidence="The response sets Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true; browsers reject this combination for credentialed reads.",
        recommendation=(
            "Choose an explicit origin allowlist if credentialed cross-origin access is required. "
            "This header pair alone does not establish cross-origin data exposure."
        ),
        category="cors-configuration",
        reference=_REFERENCES["cors"],
    )


def _check_error_disclosure(ctx, page_url: str, response) -> None:
    text = response.text.lower()
    markers: list[str] = []
    if "traceback (most recent call last)" in text and 'file "' in text and "line " in text:
        markers.append("Python traceback and source-file details")
    if "fatal error:" in text and " on line " in text and " in " in text:
        markers.append("PHP fatal error with file/line details")
    if "java.lang." in text and text.count("\n\tat ") >= 2:
        markers.append("Java exception stack trace")
    if not markers:
        return

    _add(
        ctx,
        finding_id="zap.passive.stack-trace",
        title="Response exposes detailed application error information",
        severity="medium",
        confidence="high",
        url=page_url,
        evidence="Detected: " + "; ".join(markers) + ". Stack contents are not copied into the report.",
        recommendation=(
            "Return a generic error page to clients and keep stack traces in protected server logs. "
            "Check whether the response was generated by an unexpected debug configuration."
        ),
        category="error-disclosure",
        reference="https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
    )


def run(ctx) -> int:
    """Inspect cached crawl responses only; never sends network requests."""
    checked = 0
    for page_url, response in _responses(ctx):
        if not isinstance(page_url, str) or not page_url:
            continue
        if getattr(response, "error", None) or getattr(response, "status_code", None) is None:
            continue
        checked += 1
        headers = getattr(response, "headers", {}) or {}
        _check_mixed_content(ctx, page_url, response)
        if _is_html_document(response):
            _check_csp(ctx, page_url, headers)
        _check_cors(ctx, page_url, headers)
        if _supports_error_disclosure_check(response):
            _check_error_disclosure(ctx, page_url, response)
    return checked
