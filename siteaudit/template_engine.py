"""Safe local literal-match HTTP templates inspired by template scanners.

Templates are data only: this runner intentionally has no YAML, expression,
regex, script, payload-generation, callback, or exploit support.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit


_DATA_FILE = Path(__file__).with_name("data") / "templates.json"
_MAX_FILE_BYTES = 256_000
_MAX_TEMPLATES = 32
_MAX_BODY_BYTES = 65_536
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CONFIDENCE = {"high", "medium", "low"}
_TEMPLATE_KEYS = {
    "id", "name", "severity", "confidence", "category", "method", "path",
    "max_bytes", "match", "evidence", "remediation", "references",
}
_MATCH_KEYS = {"status", "headers", "body_contains", "body_not_contains", "condition"}


def _require_string(value: Any, label: str, *, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"Invalid template field: {label}")
    return value.strip()


def _validate_template(template: Any, index: int) -> dict[str, Any]:
    if not isinstance(template, dict) or set(template) - _TEMPLATE_KEYS:
        raise ValueError(f"Invalid template object at index {index}")
    for required in ("id", "name", "severity", "confidence", "category", "method", "path", "match", "evidence", "remediation", "references"):
        if required not in template:
            raise ValueError(f"Template {index} is missing {required!r}")

    rule_id = _require_string(template["id"], f"{index}.id", maximum=100)
    if any(not (char.isalnum() or char in "._-") for char in rule_id):
        raise ValueError(f"Template {index} has an invalid id")
    severity = _require_string(template["severity"], f"{rule_id}.severity", maximum=16).lower()
    confidence = _require_string(template["confidence"], f"{rule_id}.confidence", maximum=16).lower()
    if severity not in _SEVERITIES or confidence not in _CONFIDENCE:
        raise ValueError(f"Template {rule_id!r} has an invalid severity or confidence")

    method = _require_string(template["method"], f"{rule_id}.method", maximum=8).upper()
    if method not in {"GET", "HEAD"}:
        raise ValueError(f"Template {rule_id!r} uses a blocked method")

    path = _require_string(template["path"], f"{rule_id}.path", maximum=500)
    parts = urlsplit(path)
    decoded_path = unquote(parts.path)
    segments = decoded_path.replace("\\", "/").split("/")
    if (not path.startswith("/") or path.startswith("//") or parts.scheme or parts.netloc
            or parts.query or parts.fragment or "\\" in path or "\x00" in path
            or any(segment == ".." for segment in segments)):
        raise ValueError(f"Template {rule_id!r} path must be a fixed absolute path without query or fragment")

    max_bytes = template.get("max_bytes", _MAX_BODY_BYTES)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= _MAX_BODY_BYTES:
        raise ValueError(f"Template {rule_id!r} has an invalid max_bytes value")

    match = template["match"]
    if not isinstance(match, dict) or set(match) - _MATCH_KEYS:
        raise ValueError(f"Template {rule_id!r} has an invalid match object")
    condition = str(match.get("condition", "all")).lower()
    if condition not in {"all", "any"}:
        raise ValueError(f"Template {rule_id!r} has an invalid match condition")

    status = match.get("status", [])
    if not isinstance(status, list) or any(isinstance(code, bool) or not isinstance(code, int) or not 100 <= code <= 599 for code in status):
        raise ValueError(f"Template {rule_id!r} has invalid status matchers")

    headers = match.get("headers", [])
    if not isinstance(headers, list):
        raise ValueError(f"Template {rule_id!r} has invalid header matchers")
    normalized_headers: list[dict[str, str]] = []
    for matcher in headers:
        if not isinstance(matcher, dict) or set(matcher) != {"name", "contains"}:
            raise ValueError(f"Template {rule_id!r} has an invalid header matcher")
        name = _require_string(matcher["name"], f"{rule_id}.header.name", maximum=100).lower()
        if any(not (char.isalnum() or char in "-_") for char in name):
            raise ValueError(f"Template {rule_id!r} has an invalid header name")
        normalized_headers.append({"name": name, "contains": _require_string(matcher["contains"], f"{rule_id}.header.contains", maximum=200)})

    def string_list(key: str) -> list[str]:
        values = match.get(key, [])
        if not isinstance(values, list) or any(not isinstance(value, str) or not value or len(value) > 500 for value in values):
            raise ValueError(f"Template {rule_id!r} has invalid {key} matchers")
        return values

    body_contains = string_list("body_contains")
    body_not_contains = string_list("body_not_contains")
    if method == "HEAD" and (body_contains or body_not_contains):
        raise ValueError(f"Template {rule_id!r} cannot match a response body with HEAD")
    if not status and not normalized_headers and not body_contains:
        raise ValueError(f"Template {rule_id!r} has no useful matchers")

    raw_references = template["references"]
    if not isinstance(raw_references, list) or len(raw_references) > 5:
        raise ValueError(f"Template {rule_id!r} has invalid references")
    references = [_require_string(reference, f"{rule_id}.references", maximum=500) for reference in raw_references]
    for reference in references:
        reference_parts = urlsplit(reference)
        if reference_parts.scheme != "https" or not reference_parts.hostname or reference_parts.username or reference_parts.password:
            raise ValueError(f"Template {rule_id!r} references must be HTTPS URLs")

    return {
        "id": rule_id,
        "name": _require_string(template["name"], f"{rule_id}.name", maximum=200),
        "severity": severity,
        "confidence": confidence,
        "category": _require_string(template["category"], f"{rule_id}.category", maximum=100),
        "method": method,
        "path": path,
        "max_bytes": max_bytes,
        "match": {
            "status": status,
            "headers": normalized_headers,
            "body_contains": body_contains,
            "body_not_contains": body_not_contains,
            "condition": condition,
        },
        "evidence": _require_string(template["evidence"], f"{rule_id}.evidence", maximum=1000),
        "remediation": _require_string(template["remediation"], f"{rule_id}.remediation", maximum=1000),
        "references": references,
    }


def _load_templates() -> list[dict[str, Any]]:
    try:
        if _DATA_FILE.stat().st_size > _MAX_FILE_BYTES:
            raise ValueError("Template file exceeds the 256 KB limit")
        payload = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("Built-in template pack is missing from this installation") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load built-in templates: {exc}") from exc

    if (not isinstance(payload, dict) or isinstance(payload.get("schema_version"), bool)
            or payload.get("schema_version") != 1):
        raise ValueError("Unsupported built-in template schema")
    raw_templates = payload.get("templates")
    if not isinstance(raw_templates, list) or len(raw_templates) > _MAX_TEMPLATES:
        raise ValueError("Template set must contain no more than 32 entries")
    templates = [_validate_template(template, index) for index, template in enumerate(raw_templates)]
    ids = [template["id"] for template in templates]
    if len(ids) != len(set(ids)):
        raise ValueError("Template IDs must be unique")
    return templates


def _target_url(ctx: Any, path: str) -> str:
    base = urlsplit(ctx.base_url)
    url = urlunsplit((base.scheme, base.netloc, path, "", ""))
    # The shared context is the authoritative host+port and HTTPS scope check.
    ctx._check_scope(url)
    return url


def _match_rule(template: dict[str, Any], response: Any) -> tuple[bool, list[str]]:
    match = template["match"]
    positive_results: list[bool] = []
    observations: list[str] = []
    status = getattr(response, "status_code", None)

    if match["status"]:
        status_hit = status in match["status"]
        positive_results.append(status_hit)
        if status_hit:
            observations.append(f"HTTP {status}")

    response_headers = {str(key).lower(): str(value) for key, value in (getattr(response, "headers", {}) or {}).items()}
    for matcher in match["headers"]:
        value = response_headers.get(matcher["name"], "")
        needle = matcher["contains"].lower()
        hit = needle in value.lower()
        positive_results.append(hit)
        if hit:
            observations.append(f"Header {matcher['name']} matched configured signature")

    body = getattr(response, "text", "") or ""
    body_lower = body.lower()
    for needle in match["body_contains"]:
        hit = needle.lower() in body_lower
        positive_results.append(hit)
        if hit:
            observations.append("Response body matched configured signature")

    for needle in match["body_not_contains"]:
        if needle.lower() in body_lower:
            return False, []

    if not positive_results:
        return False, []
    matched = all(positive_results) if match["condition"] == "all" else any(positive_results)
    return matched, observations if matched else []


def run(ctx: Any) -> int:
    """Apply safe, fixed-path literal templates and append matching findings."""
    templates = _load_templates()
    if not templates:
        return 0

    attempted = 0
    for template in templates:
        target_url = _target_url(ctx, template["path"])
        attempted += 1
        response = ctx.request(
            template["method"],
            target_url,
            max_bytes=template["max_bytes"],
            follow_redirects=False,
        )
        if response is None or getattr(response, "error", None) or getattr(response, "status_code", None) is None:
            continue

        matched, observations = _match_rule(template, response)
        if not matched:
            continue

        details = "; ".join(observations[:8])
        evidence = template["evidence"]
        if details:
            evidence = f"{evidence} Observed: {details}."
        ctx.add_finding(
            id=f"template.{template['id']}",
            title=template["name"],
            severity=template["severity"],
            confidence=template["confidence"],
            url=response.url,
            evidence=evidence,
            recommendation=template["remediation"],
            category=template["category"],
            references=template["references"],
        )
    return attempted
