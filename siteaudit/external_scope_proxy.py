"""Per-engine HTTP proxy that pins outbound connections to the selected origin."""

from __future__ import annotations

import base64
import hmac
import ipaddress
import secrets
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .external_support import EngineRunError


_MAX_HEADER_BYTES = 64_000
_MAX_REQUEST_BODY_BYTES = 1_000_000
_MAX_RESPONSE_BYTES = 2_000_000
_TUNNEL_IDLE_TIMEOUT = 30.0
_TUNNEL_MAX_BYTES = 64_000_000
_MAX_ACTIVE_PROXY_CLIENTS = 32
_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128")
)


class ScopeProxyError(EngineRunError):
    """Raised when the strict-scope proxy cannot be started safely."""


class ScopeProxy:
    """Run a temporary HTTP/CONNECT proxy for one exact host and port.

    HTTPS stays end-to-end encrypted: CONNECT is allowed only for the selected
    host and the connection is opened directly to the IP validated at startup.
    The proxy therefore blocks cross-origin redirects without trusting the
    scanner's own redirect or crawl scope implementation.
    """

    def __init__(
        self,
        ctx: Any,
        *,
        request_limit: int,
        delay: float,
        timeout: float,
        remote_access: bool = False,
        remote_auth_required: bool | None = None,
        bind_address: str | None = None,
        proxy_host: str | None = None,
        allowed_remote_clients: tuple[str, ...] | None = None,
    ) -> None:
        try:
            parsed = urlsplit(ctx.base_url)
            self.scheme = parsed.scheme.lower()
            self.hostname = _normalize_host(str(ctx.hostname))
            self.port = parsed.port if parsed.port is not None else (443 if self.scheme == "https" else 80)
            self.pinned_ip = ctx._validate_host(ctx.base_url)
            ipaddress.ip_address(self.pinned_ip)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ScopeProxyError(f"Could not pin the selected target: {exc}") from exc
        if self.scheme not in {"http", "https"} or not 1 <= self.port <= 65535:
            raise ScopeProxyError("Target must use a valid HTTP or HTTPS origin")
        self.request_limit = max(1, int(request_limit))
        self.delay = max(0.0, float(delay))
        self.timeout = min(max(float(timeout), 1.0), 60.0)
        self.remote_access = remote_access
        self.remote_auth_required = remote_access if remote_auth_required is None else bool(remote_auth_required)
        if self.remote_auth_required and not remote_access:
            raise ScopeProxyError("Remote proxy authentication requires remote proxy access")
        if bind_address is not None and not remote_access:
            raise ScopeProxyError("A non-loopback proxy bind requires authenticated remote access")
        if bind_address is not None:
            try:
                ipaddress.ip_address(bind_address)
            except ValueError as exc:
                raise ScopeProxyError("The scope proxy bind address must be an IP address") from exc
        if remote_access and not allowed_remote_clients:
            raise ScopeProxyError("Remote scope proxy access requires an explicit WSL client address or Docker bridge subnet")
        if not remote_access and allowed_remote_clients is not None:
            raise ScopeProxyError("Remote client allow-lists require authenticated remote proxy access")
        self._allowed_remote_clients: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
        if allowed_remote_clients:
            parsed_networks = []
            for value in allowed_remote_clients:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError as exc:
                    raise ScopeProxyError("A scope proxy remote client allow-list entry is invalid") from exc
                if not any(network.subnet_of(private) for private in _PRIVATE_NETWORKS):
                    raise ScopeProxyError("Remote scope proxy clients must use a private address range")
                if network.prefixlen < (16 if network.version == 4 else 48):
                    raise ScopeProxyError("Remote scope proxy client ranges must be narrowly bounded")
                parsed_networks.append(network)
            self._allowed_remote_clients = tuple(parsed_networks)
        if proxy_host is not None and (
            not proxy_host
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in proxy_host)
        ):
            raise ScopeProxyError("The scope proxy advertised host is invalid")
        self.username = "siteaudit"
        self.password = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("=")
        self._lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        self._last_authorized_at = 0.0
        self._closed = False
        self._stats = {
            "http_requests_authorized": 0,
            "https_tunnels_authorized": 0,
            "proxy_auth_headers_received": 0,
            "proxy_auth_failures": 0,
            "out_of_scope_attempts_blocked": 0,
            "unsupported_methods_blocked": 0,
            "proxy_client_limit_rejections": 0,
            "proxy_nonlocal_client_rejections": 0,
            "request_limit_reached": False,
            "http_response_byte_limit_reached": False,
        }

        bind_address = bind_address or ("0.0.0.0" if remote_access else "127.0.0.1")
        try:
            self._server = _ScopeHTTPServer((bind_address, 0), _ScopeProxyHandler)
        except OSError as exc:
            raise ScopeProxyError(f"Could not bind the local scope proxy: {exc}") from exc
        self._server.scope_proxy = self
        self.bind_address = bind_address
        self.host = proxy_host or ("host.docker.internal" if remote_access else "127.0.0.1")
        self.port_local = int(self._server.server_address[1])
        self.url = f"http://{self.host}:{self.port_local}"
        self.auth_url = (
            f"http://{self.username}:{self.password}@{self.host}:{self.port_local}"
            if self.remote_access and self.remote_auth_required
            else self.url
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            name="siteaudit-scope-proxy",
            daemon=True,
        )

    def __enter__(self) -> "ScopeProxy":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active_sockets = tuple(self._active_sockets)
        for connection in active_sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)

    def _register_socket(self, connection: socket.socket) -> bool:
        with self._lock:
            if self._closed:
                return False
            self._active_sockets.add(connection)
            return True

    def _unregister_socket(self, connection: socket.socket) -> None:
        with self._lock:
            self._active_sockets.discard(connection)

    def _remote_client_allowed(self, address: str) -> bool:
        if not self.remote_access:
            return True
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
        if getattr(parsed, "ipv4_mapped", None) is not None:
            parsed = parsed.ipv4_mapped
        return any(parsed.version == network.version and parsed in network for network in self._allowed_remote_clients)

    def authorize(self, url: str, *, kind: str) -> bool:
        """Check one URL and consume an HTTP request or CONNECT allowance."""
        try:
            self._validate_url(url)
        except (TypeError, ValueError, UnicodeError):
            with self._lock:
                self._stats["out_of_scope_attempts_blocked"] += 1
            return False

        with self._lock:
            if self._closed:
                return False
            used = self._stats["http_requests_authorized"] + self._stats["https_tunnels_authorized"]
            if used >= self.request_limit:
                self._stats["request_limit_reached"] = True
                return False
            wait_for = self.delay - (time.monotonic() - self._last_authorized_at)
            if wait_for > 0:
                time.sleep(wait_for)
            self._last_authorized_at = time.monotonic()
            key = "https_tunnels_authorized" if kind == "connect" else "http_requests_authorized"
            self._stats[key] += 1
        return True

    def _validate_url(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme.lower() != self.scheme or parts.username or parts.password:
            raise ValueError("Request scheme or credentials are not allowed")
        request_port = parts.port if parts.port is not None else (443 if self.scheme == "https" else 80)
        self._check_origin(parts.hostname, request_port)

    def _check_origin(self, hostname: str | None, port: int) -> None:
        if not hostname:
            raise ValueError("Missing request host")
        normalized = _normalize_host(hostname)
        if normalized != self.hostname or port != self.port:
            raise ValueError("Request is outside the selected host and port")

    def _matches_auth(self, value: str | None) -> bool:
        if not self.remote_access or not self.remote_auth_required:
            return True
        expected = base64.b64encode(f"{self.username}:{self.password}".encode("ascii")).decode("ascii")
        return bool(value) and hmac.compare_digest(value.strip(), f"Basic {expected}")

    def _reserve_method_block(self) -> None:
        with self._lock:
            self._stats["unsupported_methods_blocked"] += 1

    def _reserve_auth_failure(self) -> None:
        with self._lock:
            self._stats["proxy_auth_failures"] += 1

    def _reserve_auth_header(self, present: bool) -> None:
        if present:
            with self._lock:
                self._stats["proxy_auth_headers_received"] += 1

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "remote_auth_required": self.remote_auth_required,
                "proxy_transaction_limit": self.request_limit,
                "proxy_transaction_limit_unit": "HTTP request or HTTPS CONNECT tunnel; HTTPS requests inside tunnels are not counted",
                "pinned_address": self.pinned_ip,
                "selected_origin": f"{self.scheme}://{self.hostname}:{self.port}",
                "https_request_counting": "per CONNECT tunnel; HTTPS requests remain encrypted",
                "https_host_header_validation": (
                    "not inspected inside the encrypted tunnel; TLS SNI is checked, but a client can send a different HTTP Host header"
                ),
                "https_request_validation": (
                    "Host/:authority, HTTP methods, and request bodies inside TLS are not inspected"
                ),
            }


class _ScopeHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, server_address, request_handler_class):
        self._client_slots = threading.BoundedSemaphore(_MAX_ACTIVE_PROXY_CLIENTS)
        super().__init__(server_address, request_handler_class)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.scope_proxy.timeout)  # type: ignore[attr-defined]
        return request, client_address

    def process_request(self, request, client_address):
        scope = self.scope_proxy  # type: ignore[attr-defined]
        if not scope._remote_client_allowed(client_address[0]):
            with scope._lock:
                scope._stats["proxy_nonlocal_client_rejections"] += 1
            try:
                request.sendall(
                    b"HTTP/1.1 403 Local scanner clients only\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        if not scope._register_socket(request):
            self.shutdown_request(request)
            return
        if not self._client_slots.acquire(blocking=False):
            with scope._lock:
                scope._stats["proxy_client_limit_rejections"] += 1
            try:
                request.sendall(
                    b"HTTP/1.1 503 Scope proxy busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            scope._unregister_socket(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._client_slots.release()
            scope._unregister_socket(request)
            raise

    def process_request_thread(self, request, client_address):
        scope = self.scope_proxy  # type: ignore[attr-defined]
        try:
            super().process_request_thread(request, client_address)
        finally:
            scope._unregister_socket(request)
            self._client_slots.release()


class _ScopeProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SiteAuditScopeProxy/1"
    sys_version = ""

    @property
    def scope(self) -> ScopeProxy:
        return self.server.scope_proxy  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def setup(self) -> None:
        super().setup()
        self._header_timer = threading.Timer(self.scope.timeout, self._abort_connection)
        self._header_timer.daemon = True
        self._header_timer.start()

    def parse_request(self) -> bool:
        try:
            return super().parse_request()
        finally:
            self._header_timer.cancel()

    def _abort_connection(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _read_body(self, body_length: int) -> bytes:
        if not body_length:
            return b""
        timer = threading.Timer(self.scope.timeout, self._abort_connection)
        timer.daemon = True
        timer.start()
        try:
            return self.rfile.read(body_length)
        finally:
            timer.cancel()

    def do_CONNECT(self) -> None:
        scope = self.scope
        auth_header = self.headers.get("Proxy-Authorization")
        scope._reserve_auth_header(auth_header is not None)
        if not scope._matches_auth(auth_header):
            scope._reserve_auth_failure()
            self._deny(407, "Proxy authentication required", proxy_auth=True)
            return
        try:
            authority = urlsplit(f"//{self.path}")
            if authority.username or authority.password or not authority.hostname:
                raise ValueError("Invalid CONNECT authority")
            connect_port = authority.port if authority.port is not None else 443
            scope._check_origin(authority.hostname, connect_port)
            if scope.scheme != "https" or connect_port != scope.port:
                raise ValueError("HTTPS tunnel is outside the selected origin")
        except (TypeError, ValueError, UnicodeError):
            with scope._lock:
                scope._stats["out_of_scope_attempts_blocked"] += 1
            self._deny(403, "Target is outside the selected scan scope")
            return

        target_url = f"{scope.scheme}://{scope.hostname}:{scope.port}/"
        self.close_connection = True
        upstream = None
        upstream_tracked = False
        try:
            self.connection.settimeout(scope.timeout)
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            client_hello = self._read_tls_client_hello()
            if client_hello is None:
                with scope._lock:
                    scope._stats["out_of_scope_attempts_blocked"] += 1
                return
            # Do not consume the tunnel allowance for clients that fail the SNI
            # check. CONNECT has already been acknowledged, so a limit denial
            # closes the tunnel and is reflected in the proxy statistics.
            if not scope.authorize(target_url, kind="connect"):
                return
            upstream = socket.create_connection((scope.pinned_ip, scope.port), timeout=scope.timeout)
            upstream_tracked = scope._register_socket(upstream)
            if not upstream_tracked:
                upstream.close()
                return
            self.connection.settimeout(None)
            upstream.sendall(client_hello)
        except (OSError, ValueError, TimeoutError):
            if upstream is not None:
                upstream.close()
            return
        try:
            self._tunnel(upstream)
        finally:
            if upstream_tracked:
                scope._unregister_socket(upstream)

    def do_GET(self) -> None:
        self._forward_http()

    def do_HEAD(self) -> None:
        self._forward_http()

    def do_OPTIONS(self) -> None:
        self._forward_http()

    def do_POST(self) -> None:
        self._forward_http()

    def do_PUT(self) -> None:
        self._forward_http()

    def do_PATCH(self) -> None:
        self._forward_http()

    def do_DELETE(self) -> None:
        self._forward_http()

    def do_TRACE(self) -> None:
        self._forward_http()

    def do_PROPFIND(self) -> None:
        self._forward_http()

    def _forward_http(self) -> None:
        scope = self.scope
        auth_header = self.headers.get("Proxy-Authorization")
        scope._reserve_auth_header(auth_header is not None)
        if not scope._matches_auth(auth_header):
            scope._reserve_auth_failure()
            self._deny(407, "Proxy authentication required", proxy_auth=True)
            return
        if self.command.upper() not in _ALLOWED_METHODS:
            scope._reserve_method_block()
            self._deny(405, "HTTP method is not enabled for scanning")
            return
        try:
            parts = urlsplit(self.path)
            if self.scope.scheme != "http" or parts.scheme.lower() != "http" or not parts.netloc:
                raise ValueError("HTTPS targets must use a CONNECT tunnel")
            scope._validate_url(self.path)
            if parts.fragment:
                raise ValueError("Fragments are not valid in an HTTP request target")
            request_target = parts.path or "/"
            if parts.query:
                request_target += f"?{parts.query}"
            self._validate_host_header()
            content_lengths = self.headers.get_all("Content-Length", []) or []
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked request bodies are disabled")
            if len(content_lengths) > 1:
                raise ValueError("Ambiguous request body length")
            body_length = int(content_lengths[0]) if content_lengths else 0
            if body_length < 0 or body_length > _MAX_REQUEST_BODY_BYTES:
                raise ValueError("Request body exceeds the scope proxy limit")
        except (TypeError, ValueError, UnicodeError):
            with scope._lock:
                scope._stats["out_of_scope_attempts_blocked"] += 1
            self._deny(403, "Target is outside the selected scan scope")
            return

        if not scope.authorize(self.path, kind="http"):
            self._deny(429, "Scope proxy connection limit reached")
            return

        self._upstream_response_started = False
        try:
            body = self._read_body(body_length)
            if len(body) != body_length:
                self._deny(400, "Incomplete request body")
                return
            upstream = socket.create_connection((scope.pinned_ip, scope.port), timeout=scope.timeout)
            if not scope._register_socket(upstream):
                upstream.close()
                return
            try:
                upstream.settimeout(scope.timeout)
                headers = self._upstream_headers()
                request_line = f"{self.command.upper()} {request_target} HTTP/1.1\r\n".encode("ascii")
                upstream.sendall(request_line + headers + b"\r\n" + body)
                self._copy_response(upstream)
            finally:
                scope._unregister_socket(upstream)
                upstream.close()
        except (OSError, UnicodeError, TimeoutError):
            if not self._upstream_response_started:
                self._deny(502, "Could not complete the pinned target request")

    def _validate_host_header(self) -> None:
        values = self.headers.get_all("Host", []) or []
        if len(values) > 1:
            raise ValueError("Multiple Host headers are disabled")
        if not values:
            return
        authority = urlsplit(f"//{values[0]}")
        if authority.username or authority.password:
            raise ValueError("Invalid Host header")
        provided_port = authority.port
        default = 443 if self.scope.scheme == "https" else 80
        self.scope._check_origin(authority.hostname, provided_port if provided_port is not None else default)

    def _upstream_headers(self) -> bytes:
        scope = self.scope
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        }
        lines: list[bytes] = []
        has_host = False
        for name, value in self.headers.items():
            lowered = name.lower()
            if lowered in hop_by_hop:
                continue
            if lowered == "host":
                has_host = True
                value = _host_header(scope.hostname, scope.port, scope.scheme)
            lines.append(f"{name}: {value}\r\n".encode("iso-8859-1"))
        if not has_host:
            lines.append(f"Host: {_host_header(scope.hostname, scope.port, scope.scheme)}\r\n".encode("ascii"))
        lines.append(b"Connection: close\r\n")
        return b"".join(lines)

    def _copy_response(self, upstream: socket.socket) -> None:
        total = 0
        self.close_connection = True
        while total < _MAX_RESPONSE_BYTES:
            try:
                chunk = upstream.recv(min(65536, _MAX_RESPONSE_BYTES - total))
            except OSError:
                if total == 0:
                    raise
                return
            if not chunk:
                break
            self._upstream_response_started = True
            self.wfile.write(chunk)
            self.wfile.flush()
            total += len(chunk)
        if total >= _MAX_RESPONSE_BYTES:
            with self.scope._lock:
                self.scope._stats["http_response_byte_limit_reached"] = True

    def _tunnel(self, upstream: socket.socket) -> None:
        client = self.connection
        transferred = 0
        try:
            while transferred < _TUNNEL_MAX_BYTES:
                readable, _, exceptional = select.select([client, upstream], [], [client, upstream], _TUNNEL_IDLE_TIMEOUT)
                if exceptional or not readable:
                    break
                for source in readable:
                    try:
                        chunk = source.recv(65536)
                    except OSError:
                        return
                    if not chunk:
                        return
                    destination = upstream if source is client else client
                    destination.sendall(chunk)
                    transferred += len(chunk)
                    if transferred >= _TUNNEL_MAX_BYTES:
                        return
        except (OSError, ValueError):
            return
        finally:
            upstream.close()

    def _read_tls_client_hello(self) -> bytes | None:
        scope = self.scope
        records: list[bytes] = []
        handshake = bytearray()
        handshake_size: int | None = None
        while handshake_size is None or len(handshake) < handshake_size:
            header = _read_socket_exact(self.connection, 5)
            if len(header) != 5 or header[0] != 22:
                return None
            record_length = int.from_bytes(header[3:5], "big")
            if record_length < 4 or record_length > _MAX_HEADER_BYTES:
                return None
            payload = _read_socket_exact(self.connection, record_length)
            if len(payload) != record_length:
                return None
            records.append(header + payload)
            handshake.extend(payload)
            if len(handshake) >= 4 and handshake_size is None:
                if handshake[0] != 1:
                    return None
                handshake_size = 4 + int.from_bytes(handshake[1:4], "big")
                if handshake_size > _MAX_HEADER_BYTES:
                    return None

        server_names = _client_hello_server_names(bytes(handshake[:handshake_size]))
        try:
            expected_ip = ipaddress.ip_address(scope.hostname)
        except ValueError:
            expected_ip = None
        if expected_ip is None:
            if not server_names or any(_normalize_host(name) != scope.hostname for name in server_names):
                return None
        elif any(_normalize_host(name) != scope.hostname for name in server_names):
            return None
        return b"".join(records)

    def _deny(self, status: int, message: str, *, proxy_auth: bool = False) -> None:
        self.close_connection = True
        try:
            body = (message + "\n").encode("utf-8")
            self.send_response(status)
            if proxy_auth:
                self.send_header("Proxy-Authenticate", 'Basic realm="SiteAudit"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def _host_header(hostname: str, port: int, scheme: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    default = 443 if scheme == "https" else 80
    return host if port == default else f"{host}:{port}"


def _read_socket_exact(connection: socket.socket, size: int) -> bytes:
    """Read exactly a TLS record fragment without buffering bytes past it."""
    output = bytearray()
    while len(output) < size:
        chunk = connection.recv(size - len(output))
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def _normalize_host(hostname: str) -> str:
    raw = hostname.rstrip(".")
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        return raw.encode("idna").decode("ascii").lower()


def _client_hello_server_names(handshake: bytes) -> list[str]:
    """Parse SNI names from one complete TLS ClientHello handshake message."""
    if len(handshake) < 4 or handshake[0] != 1:
        raise ValueError("Expected TLS ClientHello")
    declared_size = 4 + int.from_bytes(handshake[1:4], "big")
    if declared_size > len(handshake):
        raise ValueError("Incomplete TLS ClientHello")
    body = memoryview(handshake)[4:declared_size]
    offset = 2 + 32
    if len(body) < offset + 1:
        raise ValueError("Malformed TLS ClientHello")
    session_length = body[offset]
    offset += 1 + session_length
    if len(body) < offset + 2:
        raise ValueError("Malformed TLS ClientHello")
    cipher_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + cipher_length
    if len(body) < offset + 1:
        raise ValueError("Malformed TLS ClientHello")
    compression_length = body[offset]
    offset += 1 + compression_length
    if len(body) == offset:
        return []
    if len(body) < offset + 2:
        raise ValueError("Malformed TLS extension list")
    extensions_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    end = offset + extensions_length
    if end != len(body):
        raise ValueError("Malformed TLS extension length")

    names: list[str] = []
    while offset < end:
        if offset + 4 > end:
            raise ValueError("Malformed TLS extension")
        extension_type = int.from_bytes(body[offset:offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        extension_end = offset + extension_length
        if extension_end > end:
            raise ValueError("Malformed TLS extension length")
        if extension_type == 0:
            if offset + 2 > extension_end:
                raise ValueError("Malformed TLS SNI extension")
            names_length = int.from_bytes(body[offset:offset + 2], "big")
            name_offset = offset + 2
            names_end = name_offset + names_length
            if names_end != extension_end:
                raise ValueError("Malformed TLS SNI list")
            while name_offset < names_end:
                if name_offset + 3 > names_end:
                    raise ValueError("Malformed TLS server name")
                name_type = body[name_offset]
                name_length = int.from_bytes(body[name_offset + 1:name_offset + 3], "big")
                name_offset += 3
                name_end = name_offset + name_length
                if name_end > names_end:
                    raise ValueError("Malformed TLS server name length")
                if name_type == 0:
                    try:
                        names.append(bytes(body[name_offset:name_end]).decode("ascii"))
                    except UnicodeDecodeError as exc:
                        raise ValueError("Invalid TLS server name") from exc
                name_offset = name_end
        offset = extension_end
    return names
