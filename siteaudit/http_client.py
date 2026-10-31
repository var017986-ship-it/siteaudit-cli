from __future__ import annotations

import ipaddress
import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from functools import partial
from urllib.request import HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .models import Finding


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to the IP validated by the scan context while retaining Host."""

    def __init__(self, host: str, *args, pinned_ip: str, **kwargs):
        super().__init__(host, *args, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP but keep the original host for TLS/SNI."""

    def __init__(self, host: str, *args, pinned_ip: str, **kwargs):
        super().__init__(host, *args, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(HTTPHandler):
    def __init__(self, pinned_ip: str):
        super().__init__()
        self._pinned_ip = pinned_ip

    def http_open(self, req):
        factory = partial(_PinnedHTTPConnection, pinned_ip=self._pinned_ip)
        return self.do_open(factory, req)


class _PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, pinned_ip: str):
        super().__init__()
        self._pinned_ip = pinned_ip

    def https_open(self, req):
        factory = partial(_PinnedHTTPSConnection, pinned_ip=self._pinned_ip)
        return self.do_open(factory, req, context=self._context, check_hostname=self._check_hostname)


@dataclass(slots=True)
class ScanResponse:
    url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    truncated: bool = False

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"
        for part in content_type.split(";")[1:]:
            key, sep, value = part.strip().partition("=")
            if sep and key.lower() == "charset":
                charset = value.strip(" \"'") or "utf-8"
                break
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class ScanContext:
    """Shared, scope-limited request context used by all scanner modules."""

    def __init__(self, base_url: str, options: dict[str, Any]):
        self.options = options
        self.base_url = self._normalize_base_url(base_url)
        parsed = urlsplit(self.base_url)
        self.host = self._host_key(parsed.hostname or "", parsed.port, parsed.scheme)
        self.hostname = self._normalize_hostname(parsed.hostname or "")
        self.findings: list[Finding] = []
        self.discovered_urls: list[str] = []
        self.discovered_forms: list[dict[str, Any]] = []
        self.discovered_responses: list[ScanResponse] = []
        self._cached_response_bytes = 0
        self.response_cache_limited = False
        self._request_count = 0
        self._last_request_at = 0.0
        self._lock = threading.Lock()
        self._validate_host(self.base_url)

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        raw = hostname.rstrip(".")
        try:
            return ipaddress.ip_address(raw).compressed.lower()
        except ValueError:
            return raw.encode("idna").decode("ascii").lower()

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        value = url.strip()
        if "://" not in value:
            value = "https://" + value
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("Target must use HTTP or HTTPS")
        if not parts.hostname or parts.username or parts.password:
            raise ValueError("Target URL must contain a hostname and no embedded credentials")
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError("Target port is outside the valid range")
        host = ScanContext._normalize_hostname(parts.hostname)
        netloc = f"[{host}]" if ":" in host else host
        if parts.port is not None:
            netloc += f":{parts.port}"
        path = parts.path or "/"
        return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))

    @staticmethod
    def _host_key(hostname: str, port: int | None, scheme: str) -> str:
        default = 443 if scheme.lower() == "https" else 80
        return f"{ScanContext._normalize_hostname(hostname)}:{port or default}"

    def _check_scope(self, url: str) -> tuple[str, str, int]:
        try:
            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            if scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError("Only absolute HTTP(S) URLs are allowed")
            if parts.username or parts.password:
                raise ValueError("URLs with embedded credentials are not allowed")
            hostname = self._normalize_hostname(parts.hostname)
            port = parts.port or (443 if scheme == "https" else 80)
        except (ValueError, UnicodeError) as exc:
            raise ValueError(f"Invalid URL: {exc}") from exc

        expected_parts = urlsplit(self.base_url)
        expected_port = expected_parts.port or (443 if expected_parts.scheme == "https" else 80)
        if hostname != self.hostname or port != expected_port:
            raise ValueError("Request is outside the selected host and port scope")
        if expected_parts.scheme == "https" and scheme != "https":
            raise ValueError("HTTPS to HTTP downgrade is blocked")
        return scheme, hostname, port

    def _validate_host(self, url: str) -> str:
        _, hostname, port = self._check_scope(url)
        if hostname in {"localhost", "localhost.localdomain"} and not self.options.get("allow_private"):
            raise ValueError("Local/private targets require --allow-private")
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValueError(f"Could not resolve target host: {exc}") from exc
        if not addresses:
            raise ValueError("Target host did not resolve to an IP address")
        parsed_addresses = []
        for address in addresses:
            try:
                parsed_addresses.append(ipaddress.ip_address(address.split("%", 1)[0]))
            except ValueError as exc:
                raise ValueError("Target resolved to an invalid IP address") from exc
        if not self.options.get("allow_private"):
            for ip in parsed_addresses:
                if not ip.is_global:
                    raise ValueError("Private, loopback, link-local and non-public targets require --allow-private")
        # Pin the connection to a validated address to prevent a second DNS
        # lookup from rebinding the target between validation and connect().
        return sorted(parsed_addresses, key=lambda ip: (ip.version, ip.packed))[0].compressed

    @staticmethod
    def _looks_stateful(url: str) -> bool:
        parsed = urlsplit(url)
        verbs = {"logout", "signout", "delete", "remove", "unsubscribe", "purchase", "checkout", "payment", "pay", "cancel", "deactivate", "reset", "transfer", "submit", "destroy", "revoke"}
        if any(word in parsed.path.lower() for word in verbs):
            return True
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            key_words = set(key.lower().replace("-", "_").split("_"))
            value_words = set(value.lower().replace("-", "_").replace("/", "_").split("_"))
            if key_words & verbs or value_words & verbs:
                return True
        return False

    def add_finding(self, **fields: Any) -> Finding:
        finding = Finding(**fields)
        identity = (finding.id, finding.url, finding.title)
        if not any((item.id, item.url, item.title) == identity for item in self.findings):
            self.findings.append(finding)
        return finding

    def record_response(self, response: ScanResponse) -> None:
        """Keep a small in-memory response sample for passive plugins only."""
        max_count = int(self.options.get("max_cached_responses", 100))
        max_bytes = int(self.options.get("max_cached_response_bytes", 2_000_000))
        if response.error or response.status_code is None:
            return
        if len(self.discovered_responses) >= max_count:
            self.response_cache_limited = True
            return
        remaining = max(0, max_bytes - self._cached_response_bytes)
        cached_body = response.body[:remaining]
        if len(cached_body) < len(response.body):
            self.response_cache_limited = True
        cached = replace(
            response,
            body=cached_body,
            truncated=response.truncated or len(cached_body) < len(response.body),
        )
        self.discovered_responses.append(cached)
        self._cached_response_bytes += len(cached_body)

    def request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | list[tuple[str, Any]] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        follow_redirects: bool = True,
    ) -> ScanResponse:
        verb = method.upper()
        if verb not in {"GET", "HEAD", "OPTIONS"}:
            return ScanResponse(url=url, error=f"HTTP method {verb} is blocked; only GET, HEAD, and OPTIONS are allowed")
        if data is not None:
            return ScanResponse(url=url, error="Request bodies are blocked; only read-only probes are allowed")

        target = url
        if params:
            parsed = urlsplit(target)
            query = parse_qsl(parsed.query, keep_blank_values=True)
            if isinstance(params, dict):
                extra = [(key, value) for key, values in params.items() for value in (values if isinstance(values, (list, tuple)) else [values])]
            else:
                extra = list(params)
            target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query + extra, doseq=True), ""))

        body_limit = max(1024, min(max_bytes or self.options.get("max_response_bytes", 131072), 1048576))
        response: ScanResponse | None = None
        for redirect_count in range(5):
            try:
                pinned_ip = self._validate_host(target)
                with self._lock:
                    cap = int(self.options.get("max_requests", 400))
                    if self._request_count >= cap:
                        return ScanResponse(url=target, error=f"Request limit reached ({cap})")
                    self._request_count += 1
                    wait_for = float(self.options.get("delay", 0.5)) - (time.monotonic() - self._last_request_at)
                    if wait_for > 0:
                        time.sleep(wait_for)
                    self._last_request_at = time.monotonic()

                request_headers = {"User-Agent": "SiteAudit/0.3.0 (+authorized security testing)", "Accept": "text/html,application/json,*/*;q=0.5"}
                if headers:
                    request_headers.update(headers)
                req = Request(target, headers=request_headers, method=verb)
                timeout = float(self.options.get("timeout", 10))
                try:
                    opener = build_opener(
                        ProxyHandler({}),
                        _NoRedirect(),
                        _PinnedHTTPHandler(pinned_ip),
                        _PinnedHTTPSHandler(pinned_ip),
                    )
                    raw = opener.open(req, timeout=timeout)
                except HTTPError as exc:
                    raw = exc
                status = getattr(raw, "code", None)
                response_headers = {key.lower(): value for key, value in raw.headers.items()}
                set_cookies = raw.headers.get_all("Set-Cookie", [])
                if set_cookies:
                    response_headers["set-cookie"] = "\n".join(set_cookies)
                if status in {301, 302, 303, 307, 308}:
                    location = response_headers.get("location")
                    raw.close()
                    if not location:
                        return ScanResponse(url=target, status_code=status, headers=response_headers)
                    next_url = urljoin(target, location)
                    if not follow_redirects:
                        return ScanResponse(url=target, status_code=status, headers=response_headers, error="Redirect following is disabled for this request")
                    try:
                        self._check_scope(next_url)
                    except ValueError:
                        return ScanResponse(url=target, status_code=status, headers=response_headers, error="Out-of-scope redirect was blocked")
                    if self._looks_stateful(next_url):
                        return ScanResponse(url=target, status_code=status, headers=response_headers, error="Potential state-changing redirect was blocked")
                    if redirect_count == 4:
                        return ScanResponse(url=target, status_code=status, headers=response_headers, error="Redirect limit reached")
                    target = next_url
                    continue

                truncated = False
                payload = b""
                if verb not in {"HEAD", "OPTIONS"}:
                    payload = raw.read(body_limit + 1)
                    if len(payload) > body_limit:
                        payload = payload[:body_limit]
                        truncated = True
                raw.close()
                response = ScanResponse(url=target, status_code=status, headers=response_headers, body=payload, truncated=truncated)
                break
            except (ValueError, OSError, URLError, TimeoutError, ssl.SSLError) as exc:
                reason = getattr(exc, "reason", None)
                error = str(reason or exc)
                response = ScanResponse(url=target, error=error[:500])
                break
            except Exception as exc:  # keep individual network failures from aborting the entire scan
                response = ScanResponse(url=target, error=f"Request failed: {type(exc).__name__}: {exc}"[:500])
                break
        return response or ScanResponse(url=target, error="Request failed")

    @property
    def request_count(self) -> int:
        return self._request_count
