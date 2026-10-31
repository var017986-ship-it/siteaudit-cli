"""Opt-in, low-impact GraphQL introspection availability check.

The check sends one fixed read-only query to at most three same-origin
GraphQL endpoints. It reports only whether a query type name was returned;
schema contents and response bodies are never copied into findings.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .http_client import _GRAPHQL_INTROSPECTION_BODY

_QUERY = _GRAPHQL_INTROSPECTION_BODY
_MAX_ENDPOINTS = 3
_MAX_RESPONSE_BYTES = 4096
_FALLBACK_PATHS = ("/graphql", "/api/graphql")
_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"


def _canonical_endpoint(ctx: Any, value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("url") or value.get("href")
    if not isinstance(value, str):
        return None

    try:
        parts = urlsplit(value)
        if not parts.hostname or not parts.path.lower().rstrip("/").endswith("/graphql"):
            return None
        # Reject state-changing query selectors before removing query values.
        if ctx._looks_stateful(value):
            return None
        endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        ctx._check_scope(endpoint)
        if ctx._looks_stateful(endpoint):
            return None
        return endpoint
    except (ValueError, TypeError):
        return None


def _candidate_endpoints(ctx: Any) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    for value in getattr(ctx, "discovered_urls", []) or []:
        endpoint = _canonical_endpoint(ctx, value)
        if endpoint and endpoint not in seen:
            candidates.append(endpoint)
            seen.add(endpoint)

    base = urlsplit(ctx.base_url)
    origin = urlunsplit((base.scheme, base.netloc, "", "", ""))
    for path in _FALLBACK_PATHS:
        endpoint = origin + path
        try:
            ctx._check_scope(endpoint)
            if ctx._looks_stateful(endpoint):
                continue
        except (ValueError, TypeError):
            continue
        if endpoint not in seen:
            candidates.append(endpoint)
            seen.add(endpoint)
        if len(candidates) >= _MAX_ENDPOINTS:
            break

    return candidates[:_MAX_ENDPOINTS]


def _is_json_content_type(response: Any) -> bool:
    headers = getattr(response, "headers", {}) or {}
    content_type = next(
        (str(value) for key, value in headers.items() if str(key).lower() == "content-type"),
        "",
    ).split(";", 1)[0].strip().lower()
    return content_type == "application/json" or (
        content_type.startswith("application/") and content_type.endswith("+json")
    )


def _introspection_confirmed(response: Any) -> bool:
    if getattr(response, "status_code", None) != 200 or not _is_json_content_type(response):
        return False

    body = getattr(response, "body", b"")
    if not isinstance(body, bytes) or len(body) > _MAX_RESPONSE_BYTES or getattr(response, "truncated", False):
        return False
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False

    if not isinstance(payload, dict):
        return False
    data = payload.get("data")
    if not isinstance(data, dict):
        return False
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return False
    query_type = schema.get("queryType")
    if not isinstance(query_type, dict):
        return False
    return isinstance(query_type.get("name"), str) and bool(query_type["name"].strip())


def run(ctx: Any) -> int | dict[str, Any]:
    """Probe a few GraphQL endpoints only after explicit CLI opt-in."""
    options = getattr(ctx, "options", {}) or {}
    if not options.get("allow_graphql_probe"):
        return {"status": "skipped", "reason": "requires --graphql-probe", "requests_sent": 0}

    requests_before = getattr(ctx, "request_count", 0)
    for endpoint in _candidate_endpoints(ctx):
        try:
            response = ctx.request(
                "POST",
                endpoint,
                data=_QUERY,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                max_bytes=_MAX_RESPONSE_BYTES,
                follow_redirects=False,
            )
        except Exception:
            continue

        if response is None or getattr(response, "error", None) or not _introspection_confirmed(response):
            continue

        ctx.add_finding(
            id="graphql.introspection.enabled",
            title="GraphQL schema introspection is publicly available",
            severity="info",
            confidence="high",
            url=endpoint,
            evidence=(
                "A fixed read-only query returned the GraphQL query type name. "
                "The schema response was not included in the report; introspection may be intentional."
            ),
            recommendation=(
                "Review whether public schema introspection is required. Restrict it where appropriate, "
                "and enforce authorization on every resolver; introspection alone does not prove data exposure."
            ),
            category="api-introspection",
            references=[_REFERENCE],
        )
        # One confirmed endpoint is sufficient; avoid repeating the same observation.
        break

    return max(0, getattr(ctx, "request_count", 0) - requests_before)
