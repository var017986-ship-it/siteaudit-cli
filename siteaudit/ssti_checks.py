"""Bounded, arithmetic-only server-side template expression checks.

The module tests only discovered GET parameters using two inert expression
families. It never sends commands, file reads, callbacks, delays, or POSTs.
"""

from __future__ import annotations

from secrets import randbelow, token_hex
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .wapiti_checks import (
    _is_sensitive_key,
    _is_stateful_url,
    _replace_query_value,
    _response_text,
    _same_host,
)


_MAX_TARGETS = 2
_MAX_REQUESTS = 10
_MAX_RESPONSE_BYTES = 16_384
_SUPPORTED_MEDIA_TYPES = {"text/html", "application/xhtml+xml", "application/json", "text/plain"}
_REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection"


def _media_type(response: object) -> str:
    headers = getattr(response, "headers", {}) or {}
    content_type = next(
        (str(value) for key, value in headers.items() if str(key).lower() == "content-type"),
        "",
    )
    return content_type.split(";", 1)[0].strip().lower()


def _supported_response(response: object) -> bool:
    media_type = _media_type(response)
    return media_type in _SUPPORTED_MEDIA_TYPES or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _strip_sensitive_query_keys(url: str) -> str | None:
    """Remove sensitive query fields before replaying an endpoint URL."""
    try:
        parts = urlsplit(url)
        safe_pairs = [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if not _is_sensitive_key(key)
        ]
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(safe_pairs, doseq=True), ""))
    except ValueError:
        return None


def _add_candidate(
    candidates: list[tuple[str, str, str]],
    seen: set[tuple[str, str]],
    ctx: Any,
    url: str,
    key: str,
    original_value: str,
) -> None:
    key = key.strip()
    if not key or len(key) > 128 or _is_sensitive_key(key):
        return
    if not _same_host(url, ctx) or _is_stateful_url(url):
        return

    safe_url = _strip_sensitive_query_keys(url)
    if not safe_url or not _same_host(safe_url, ctx) or _is_stateful_url(safe_url):
        return

    baseline_url = _replace_query_value(safe_url, key, original_value)
    if not _same_host(baseline_url, ctx) or _is_stateful_url(baseline_url):
        return

    identity = (safe_url, key)
    if identity in seen:
        return
    seen.add(identity)
    candidates.append((safe_url, key, original_value))


def _candidate_targets(ctx: Any) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for item in getattr(ctx, "discovered_urls", []) or []:
        if isinstance(item, dict):
            item = item.get("url") or item.get("href")
        if not isinstance(item, str) or not _same_host(item, ctx):
            continue
        try:
            pairs = parse_qsl(urlsplit(item).query, keep_blank_values=True)
        except ValueError:
            continue
        for key, value in pairs:
            _add_candidate(candidates, seen, ctx, item, key, value)
            if len(candidates) >= _MAX_TARGETS:
                return candidates

    for form in getattr(ctx, "discovered_forms", []) or []:
        if not isinstance(form, dict) or str(form.get("method", "GET")).upper() != "GET":
            continue
        source_url = form.get("source_url")
        if not isinstance(source_url, str) or not _same_host(source_url, ctx):
            continue
        action = form.get("action") or source_url
        if not isinstance(action, str):
            continue
        action_url = urljoin(source_url, action)
        if not _same_host(action_url, ctx) or _is_stateful_url(action_url):
            continue
        inputs = form.get("inputs", [])
        if not isinstance(inputs, list):
            continue
        for field in inputs:
            if not isinstance(field, dict):
                continue
            input_type = str(field.get("type", "text")).strip().lower()
            if input_type not in {"text", "search", "textarea"}:
                continue
            key = str(field.get("name", "")).strip()
            value = str(field.get("value", ""))
            _add_candidate(candidates, seen, ctx, action_url, key, value)
            if len(candidates) >= _MAX_TARGETS:
                return candidates

    return candidates


def _random_products(baseline: str) -> list[tuple[int, int, int]]:
    """Choose four distinct products absent from the per-target baseline."""
    outputs: list[tuple[int, int, int]] = []
    products: list[str] = []
    for _ in range(256):
        left = randbelow(79) + 11
        right = randbelow(79) + 11
        product = left * right
        rendered = str(product)
        if (product < 100 or rendered in baseline
                or any(rendered in old or old in rendered for old in products)):
            continue
        outputs.append((left, right, product))
        products.append(rendered)
        if len(outputs) == 4:
            return outputs
    return []


def _request(ctx: Any, url: str) -> object | None:
    try:
        return ctx.request(
            "GET",
            url,
            max_bytes=_MAX_RESPONSE_BYTES,
            follow_redirects=False,
        )
    except Exception:
        return None


def _status_ok(response: object) -> bool:
    status = getattr(response, "status_code", None)
    return isinstance(status, int) and 200 <= status < 300


def _expression_probe(
    ctx: Any,
    url: str,
    key: str,
    syntax: str,
    operations: list[tuple[int, int, int]],
    baseline_text: str,
    requests_used: int,
) -> tuple[bool, int]:
    matched = True
    for left, right, product in operations:
        if requests_used >= _MAX_REQUESTS:
            return False, requests_used

        nonce = token_hex(8)
        prefix = f"siteaudit_{nonce}_"
        suffix = f"_end_{nonce}"
        if syntax == "double-brace":
            expression = f"{{{{{left}*{right}}}}}"
        else:
            expression = f"${{{left}*{right}}}"
        payload = prefix + expression + suffix
        expected = prefix + str(product) + suffix
        if expected in baseline_text:
            return False, requests_used

        probe_url = _replace_query_value(url, key, payload)
        if not _same_host(probe_url, ctx) or _is_stateful_url(probe_url):
            return False, requests_used
        response = _request(ctx, probe_url)
        requests_used += 1
        if (response is None or getattr(response, "error", None)
                or not _status_ok(response) or not _supported_response(response)):
            matched = False
            continue
        if expected not in _response_text(response):
            matched = False

    return matched, requests_used


def run(ctx: Any) -> int:
    """Check at most two GET parameters with read-only arithmetic expressions."""
    requests_before = getattr(ctx, "request_count", 0)
    requests_used = 0

    for endpoint, key, original_value in _candidate_targets(ctx):
        if requests_used >= _MAX_REQUESTS:
            break
        baseline_url = _replace_query_value(endpoint, key, original_value)
        if not _same_host(baseline_url, ctx) or _is_stateful_url(baseline_url):
            continue
        baseline = _request(ctx, baseline_url)
        requests_used += 1
        if (baseline is None or getattr(baseline, "error", None)
                or not _status_ok(baseline) or not _supported_response(baseline)):
            continue

        baseline_text = _response_text(baseline)
        products = _random_products(baseline_text)
        if len(products) != 4:
            continue

        for syntax, operations in (
            ("double-brace", products[:2]),
            ("dollar-brace", products[2:]),
        ):
            confirmed, requests_used = _expression_probe(
                ctx,
                endpoint,
                key,
                syntax,
                operations,
                baseline_text,
                requests_used,
            )
            if not confirmed:
                continue

            ctx.add_finding(
                id="ssti.arithmetic-expression-evaluated",
                title="Server-side template expression evaluated from GET input",
                severity="medium",
                confidence="high",
                url=baseline_url,
                evidence=(
                    f"Two distinct, nonce-wrapped arithmetic expressions in GET parameter {key!r} returned their exact computed markers. "
                    "This confirms server-side expression evaluation for the tested syntax; no command, file, or network operation was attempted."
                ),
                recommendation=(
                    "Do not evaluate user-controlled values as server-side templates. Use fixed templates, context-aware output encoding, "
                    "and a sandboxed template configuration where applicable. Review the affected rendering path for additional impact."
                ),
                category="server-side-template-injection",
                references=[_REFERENCE],
            )
            break

    return max(0, getattr(ctx, "request_count", 0) - requests_before)
