from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .http_client import ScanContext, ScanResponse


class _PageParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in {"a", "area", "iframe", "script", "link"}:
            destination = attributes.get("href") or attributes.get("src")
            if destination:
                self.links.append(urljoin(self.page_url, destination.strip()))
        if tag == "form":
            method = (attributes.get("method") or "GET").upper()
            action = urljoin(self.page_url, attributes.get("action") or self.page_url)
            self._form = {"action": action, "method": method, "inputs": [], "source_url": self.page_url}
        elif self._form is not None and tag in {"input", "textarea", "select"}:
            name = attributes.get("name")
            kind = (attributes.get("type") or "text").lower() if tag == "input" else tag
            if name and kind not in {"password", "file", "submit", "button", "image", "reset"} and not attributes.get("disabled"):
                self._form["inputs"].append({"name": name, "value": attributes.get("value") or "", "type": kind})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            if self._form["method"] in {"GET", "POST"} and self._form["inputs"]:
                self.forms.append(self._form)
            self._form = None


def _safe_page_url(ctx: ScanContext, candidate: str) -> bool:
    try:
        ctx._check_scope(candidate)
    except ValueError:
        return False
    return True


def _finding(ctx: ScanContext, finding_id: str, title: str, severity: str, confidence: str, url: str, evidence: str, recommendation: str, category: str = "configuration") -> None:
    ctx.add_finding(id=finding_id, title=title, severity=severity, confidence=confidence, url=url, evidence=evidence, recommendation=recommendation, category=category)


def _media_type(headers: dict[str, str]) -> str:
    content_type = headers.get("content-type", "")
    return content_type.split(";", 1)[0].strip().lower()


def _check_headers(ctx: ScanContext, response: ScanResponse, *, is_root: bool = False) -> None:
    if response.error or response.status_code is None:
        return
    headers = response.headers
    url = response.url
    https = urlsplit(url).scheme == "https"
    is_document = _media_type(headers) in {"text/html", "application/xhtml+xml"}
    checks = [("x-content-type-options", "Missing X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff.")]
    if is_document:
        checks.extend([
            ("content-security-policy", "Missing Content-Security-Policy", "medium", "Set a policy that limits script, style, frame, and object sources; begin with Report-Only if needed."),
            ("referrer-policy", "Missing Referrer-Policy", "low", "Set a policy such as strict-origin-when-cross-origin."),
            ("permissions-policy", "Missing Permissions-Policy", "info", "Set a Permissions-Policy that disables browser features the site does not use."),
        ])
    for name, title, severity, recommendation in checks:
        if name not in headers:
            _finding(ctx, f"header.{name}", title, severity, "high", url, f"HTTP response did not include {name}.", recommendation)
    if is_document and "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        _finding(ctx, "header.frame-protection", "Missing clickjacking frame protection", "low", "medium", url, "Neither X-Frame-Options nor CSP frame-ancestors was present.", "Set Content-Security-Policy frame-ancestors, or X-Frame-Options for legacy browser support.")
    if is_root and not https:
        _finding(ctx, "transport.http", "Target is served over HTTP", "high", "high", url, "The selected page URL uses HTTP, so the connection is not encrypted.", "Serve the site over HTTPS and redirect HTTP requests to HTTPS.", "transport")
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server or powered:
        details = "; ".join(f"{key}: {value[:120]}" for key, value in (("Server", server), ("X-Powered-By", powered)) if value)
        duplicate = any(item.id == "header.version-disclosure" and item.evidence == details for item in ctx.findings)
        if not duplicate:
            _finding(ctx, "header.version-disclosure", "Server technology disclosed in response headers", "info", "high", url, details, "Remove or generalize version-bearing server and framework headers where practical.")


def _check_hsts(ctx: ScanContext, response: ScanResponse) -> None:
    if response.error or response.status_code is None:
        return
    if urlsplit(response.url).scheme != "https" or "strict-transport-security" in response.headers:
        return
    _finding(
        ctx,
        "header.hsts",
        "Missing Strict-Transport-Security",
        "medium",
        "high",
        response.url,
        "HTTPS response from the origin root did not include Strict-Transport-Security.",
        "After confirming HTTPS works across the site, set an appropriate HSTS max-age; include subdomains only if they support HTTPS.",
    )


def _check_cookies(ctx: ScanContext, response: ScanResponse) -> None:
    for raw_cookie in response.headers.get("set-cookie", "").split("\n"):
        if not raw_cookie.strip():
            continue
        parts = [part.strip() for part in raw_cookie.split(";")]
        name = parts[0].partition("=")[0].strip() or "(unnamed)"
        attributes = {part.partition("=")[0].strip().lower() for part in parts[1:]}
        missing = []
        if urlsplit(response.url).scheme == "https" and "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            _finding(ctx, f"cookie.flags.{name}", f"Cookie {name} is missing security attributes", "low", "medium", response.url, f"Set-Cookie omitted: {', '.join(missing)}.", "Set Secure on HTTPS cookies, HttpOnly on cookies not used by JavaScript, and an appropriate SameSite value.", "cookies")


_STATE_CHANGING_WORDS = {"logout", "signout", "delete", "remove", "unsubscribe", "purchase", "checkout", "payment", "pay", "cancel", "deactivate", "reset", "transfer", "submit", "destroy", "revoke"}


def _is_stateful_url(url: str) -> bool:
    parsed = urlsplit(url)
    path = parsed.path.lower()
    if any(word in path for word in _STATE_CHANGING_WORDS):
        return True
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        key_words = set(key.lower().replace("-", "_").split("_"))
        value_words = set(value.lower().replace("-", "_").replace("/", "_").split("_"))
        if key_words & _STATE_CHANGING_WORDS or value_words & _STATE_CHANGING_WORDS:
            return True
    return False


def crawl(ctx: ScanContext) -> None:
    max_pages = int(ctx.options.get("max_pages", 50))
    max_depth = int(ctx.options.get("max_depth", 2))
    start = ctx.base_url
    queue = deque([(start, 0)])
    seen: set[str] = set()
    while queue and len(seen) < max_pages:
        current, depth = queue.popleft()
        parsed = urlsplit(current)
        current = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if current in seen or _is_stateful_url(current):
            continue
        if not _safe_page_url(ctx, current):
            continue
        seen.add(current)
        response = ctx.request("GET", current)
        ctx.record_response(response)
        ctx.discovered_urls.append(response.url)
        if depth == 0:
            _check_headers(ctx, response, is_root=True)
            _check_cookies(ctx, response)
            if urlsplit(response.url).scheme == "https":
                response_parts = urlsplit(response.url)
                if response_parts.path in {"", "/"}:
                    _check_hsts(ctx, response)
                else:
                    origin_root = urlunsplit((response_parts.scheme, response_parts.netloc, "/", "", ""))
                    try:
                        hsts_response = ctx.request("HEAD", origin_root, max_bytes=0)
                    except Exception:
                        hsts_response = None
                    if hsts_response is not None:
                        _check_hsts(ctx, hsts_response)
            if response.error:
                message = response.error
                normalized_error = message.lower()
                certificate_failure_markers = (
                    "certificate_verify_failed",
                    "certificate verify failed",
                    "certificate has expired",
                    "certificate expired",
                    "self signed certificate",
                    "self-signed certificate",
                    "unable to get local issuer certificate",
                    "unable to verify the first certificate",
                    "hostname mismatch",
                    "certificate is not valid for",
                    "ip address mismatch",
                    "doesn't match the host",
                    "does not match the host",
                )
                certificate_issue = any(marker in normalized_error for marker in certificate_failure_markers)
                tls_transport_issue = any(term in normalized_error for term in ("ssl", "tls", "handshake"))
                finding_id = "connection.tls" if certificate_issue else "connection.failed"
                title = "TLS certificate validation failed" if certificate_issue else "Could not fetch target page"
                severity = "high" if certificate_issue else "info"
                recommendation = (
                    "Fix the site's TLS certificate chain or hostname configuration."
                    if certificate_issue
                    else "Check target availability, DNS, firewall rules, and TLS/network connectivity from this machine."
                )
                if tls_transport_issue and not certificate_issue:
                    recommendation = "Check TLS negotiation and network connectivity from this machine. A timeout alone does not establish a certificate problem."
                _finding(ctx, finding_id, title, severity, "high", current, message, recommendation, "transport")
        if response.error or response.status_code is None:
            continue
        if depth > 0:
            _check_headers(ctx, response)
            _check_cookies(ctx, response)
        content_type = response.headers.get("content-type", "")
        if depth >= max_depth or "html" not in content_type.lower():
            continue
        parser = _PageParser(response.url)
        try:
            parser.feed(response.text)
        except Exception:
            continue
        for form in parser.forms:
            if _safe_page_url(ctx, form["action"]) and not _is_stateful_url(form["action"]):
                if form not in ctx.discovered_forms:
                    ctx.discovered_forms.append(form)
        for link in parser.links:
            parts = urlsplit(link)
            if parts.scheme not in {"http", "https"} or not _safe_page_url(ctx, link) or _is_stateful_url(link):
                continue
            canonical = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
            if canonical not in seen and len(seen) + len(queue) < max_pages:
                queue.append((canonical, depth + 1))
    ctx.discovered_urls = list(dict.fromkeys(ctx.discovered_urls))


def run(ctx: ScanContext) -> None:
    crawl(ctx)
