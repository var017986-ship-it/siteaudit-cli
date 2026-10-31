"""Small W3AF-inspired plugin suite for modular web checks.

The project is an independent implementation, not a W3AF compatibility layer.
Plugins share the bounded scan context and must keep their request budgets low.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit, urlunsplit


_PROBE_ORIGIN = "https://siteaudit.invalid"
_MAX_CORS_PAGES = 5
_MAX_RESPONSE_BYTES = 2048


@dataclass(frozen=True, slots=True)
class Plugin:
    """One self-contained check registered with the local plugin runner."""

    plugin_id: str
    title: str
    run: Callable[[object], int]


def _candidate_pages(ctx: object) -> list[str]:
    """Return a few same-host HTML/JSON application URLs without queries."""
    urls: list[str] = []
    seen: set[str] = set()
    html_pages: set[str] = set()
    for response in getattr(ctx, "discovered_responses", []) or []:
        headers = getattr(response, "headers", {}) or {}
        content_type = str(headers.get("content-type", "")).lower()
        if "html" not in content_type and "json" not in content_type:
            continue
        response_url = getattr(response, "url", "")
        if not isinstance(response_url, str) or not response_url:
            continue
        response_parts = urlsplit(response_url)
        html_pages.add(urlunsplit((response_parts.scheme, response_parts.netloc, response_parts.path or "/", "", "")))
    for raw_url in getattr(ctx, "discovered_urls", []) or []:
        if not isinstance(raw_url, str):
            continue
        try:
            parts = urlsplit(raw_url)
            if parts.query or parts.scheme not in {"http", "https"} or not parts.hostname:
                continue
            canonical = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
            if canonical not in html_pages:
                continue
            ctx._check_scope(canonical)
            if ctx._looks_stateful(canonical):
                continue
        except (ValueError, AttributeError):
            continue
        path_lower = parts.path.lower()
        if any(word in path_lower for word in ("logout", "delete", "remove", "checkout", "payment", "unsubscribe", "reset", "transfer")):
            continue
        if canonical not in seen:
            urls.append(canonical)
            seen.add(canonical)
        if len(urls) >= _MAX_CORS_PAGES:
            break
    return urls


def _cors_reflection(ctx: object) -> int:
    """Check whether the server reflects an arbitrary Origin with credentials."""
    requests_before = getattr(ctx, "request_count", 0)
    for url in _candidate_pages(ctx):
        try:
            response = ctx.request(
                "GET",
                url,
                headers={"Origin": _PROBE_ORIGIN},
                max_bytes=_MAX_RESPONSE_BYTES,
                follow_redirects=False,
            )
        except Exception:
            continue
        if response is None or getattr(response, "error", None):
            continue
        headers = {str(key).lower(): str(value).strip() for key, value in (getattr(response, "headers", {}) or {}).items()}
        allowed_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").strip()
        if allowed_origin != _PROBE_ORIGIN or allow_credentials != "true":
            continue

        ctx.add_finding(
            id="w3af.cors.arbitrary-origin-credentials",
            title="CORS reflects an arbitrary origin while allowing credentials",
            severity="medium",
            confidence="high",
            url=getattr(response, "url", url),
            evidence=(
                f"A request carrying Origin: {_PROBE_ORIGIN} received the same value in "
                "Access-Control-Allow-Origin and Access-Control-Allow-Credentials: true. "
                "The scanner sent no cookies or authorization credentials."
            ),
            recommendation=(
                "Use a strict allowlist of trusted origins. Do not reflect arbitrary Origin values, "
                "and enable credentialed CORS only for origins that require it."
            ),
            category="cors-configuration",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
        )
    return max(0, getattr(ctx, "request_count", 0) - requests_before)


def _post_form_csrf_indicator(ctx: object) -> int:
    """Flag POST forms without a recognizable token name for manual review."""
    inspected = 0
    token_markers = ("csrf", "xsrf", "nonce", "authenticity", "requestverification")
    stateful_parts = ("logout", "delete", "remove", "checkout", "payment", "unsubscribe", "reset", "transfer")
    for form in getattr(ctx, "discovered_forms", []) or []:
        if not isinstance(form, dict) or str(form.get("method", "")).upper() != "POST":
            continue
        action = str(form.get("action") or form.get("source_url") or "")
        if not action or any(part in urlsplit(action).path.lower() for part in stateful_parts):
            continue
        inputs = form.get("inputs", [])
        if not isinstance(inputs, list):
            continue
        names = [str(field.get("name", "")).lower() for field in inputs if isinstance(field, dict)]
        inspected += 1
        if any(marker in name for name in names for marker in token_markers):
            continue
        ctx.add_finding(
            id="w3af.csrf.no-recognizable-form-token",
            title="POST form has no recognizable CSRF token field",
            severity="low",
            confidence="low",
            url=action,
            evidence=(
                f"The scanned page exposed a POST form with {len(names)} named field(s) but no field name resembling a CSRF token. "
                "The scanner did not submit the form; protection may use a custom field name, request header, or SameSite cookie."
            ),
            recommendation=(
                "Verify that the server validates an unpredictable CSRF token or uses another documented CSRF defense for this action. "
                "Do not rely on this field-name heuristic alone."
            ),
            category="csrf-indicator",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
        )
    return inspected


PLUGIN_REGISTRY: tuple[Plugin, ...] = (
    Plugin(
        plugin_id="cors_reflection",
        title="Credentialed arbitrary-origin CORS reflection",
        run=_cors_reflection,
    ),
    Plugin(
        plugin_id="post-form-csrf-indicator",
        title="POST form CSRF token field-name heuristic",
        run=_post_form_csrf_indicator,
    ),
)


def run(ctx: object) -> dict[str, int]:
    """Run the bounded registered plugin set against discovered pages."""
    results: dict[str, int] = {}
    for plugin in PLUGIN_REGISTRY:
        results[plugin.plugin_id] = plugin.run(ctx)
    return results
