"""Safe local literal-match HTTP templates inspired by template scanners.

JSON rules are always available. An optional, restricted Nuclei YAML importer
accepts only fixed GET/HEAD paths and positive literal/status matchers. Neither
format supports expression evaluation, payload generation, callbacks, or code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit


_DATA_FILE = Path(__file__).with_name("data") / "templates.json"
_MAX_FILE_BYTES = 256_000
_MAX_TEMPLATES = 32
_MAX_BODY_BYTES = 65_536
_MAX_YAML_EVENTS = 20_000
_MAX_YAML_DEPTH = 64
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


def _validate_template(template: Any, index: int, *, allow_empty_matchers: bool = False) -> dict[str, Any]:
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
    if re.search(r"%[0-9a-f]{2}", decoded_path, flags=re.IGNORECASE):
        raise ValueError(f"Template {rule_id!r} path uses nested percent-encoding")
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
    if not allow_empty_matchers and not status and not normalized_headers and not body_contains:
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


def _load_template_file(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_FILE_BYTES + 1)
    except FileNotFoundError as exc:
        raise ValueError(f"Template file ({label}) does not exist: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not read template file ({label}) at {path}: {exc}") from exc
    if len(raw) > _MAX_FILE_BYTES:
        raise ValueError(f"Template file ({label}) exceeds the 256 KB limit: {path}")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return _load_nuclei_yaml(raw, path, label)

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load template file ({label}) at {path}: {exc}") from exc

    if (not isinstance(payload, dict) or set(payload) != {"schema_version", "templates"}
            or isinstance(payload.get("schema_version"), bool) or payload.get("schema_version") != 1):
        raise ValueError(f"Unsupported template schema in {label} file: {path}")
    raw_templates = payload.get("templates")
    if not isinstance(raw_templates, list) or len(raw_templates) > _MAX_TEMPLATES:
        raise ValueError(f"Template file ({label}) must contain no more than 32 entries: {path}")
    return [_validate_template(template, index) for index, template in enumerate(raw_templates)]


def _load_nuclei_yaml(raw: bytes, path: Path, label: str) -> list[dict[str, Any]]:
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            "YAML templates require the optional dependency; install with: "
            'python -m pip install -e ".[yaml]"'
        ) from exc

    class StrictSafeLoader(yaml.SafeLoader):
        def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
            if not isinstance(node, yaml.MappingNode):
                raise ValueError("YAML mapping expected")
            mapping: dict[str, Any] = {}
            for key_node, value_node in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    raise ValueError("YAML merge keys are not supported")
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise ValueError("YAML mapping keys must be strings")
                if key in mapping:
                    raise ValueError(f"Duplicate YAML key: {key}")
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    try:
        text = raw.decode("utf-8")
        depth = 0
        event_count = 0
        for event in yaml.parse(text, Loader=StrictSafeLoader):
            event_count += 1
            if event_count > _MAX_YAML_EVENTS:
                raise ValueError("YAML template contains too many parser events")
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise ValueError("YAML anchors and aliases are not supported")
            if isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                depth += 1
                if depth > _MAX_YAML_DEPTH:
                    raise ValueError("YAML template nesting exceeds the 64-level limit")
            elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                depth -= 1

        documents = list(yaml.load_all(text, Loader=StrictSafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        raise ValueError(f"Could not load restricted Nuclei YAML ({label}) at {path}: {exc}") from exc

    if not 1 <= len(documents) <= _MAX_TEMPLATES:
        raise ValueError(f"YAML template file ({label}) must contain 1 to 32 documents: {path}")

    templates: list[dict[str, Any]] = []
    for index, document in enumerate(documents):
        templates.extend(_convert_nuclei_document(document, index))
        if len(templates) > _MAX_TEMPLATES:
            raise ValueError("YAML file expands to more than 32 fixed-path rules")
    return templates


def _convert_nuclei_document(document: Any, index: int) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or set(document) != {"id", "info", "http"}:
        raise ValueError(f"Nuclei YAML document {index} must contain only id, info, and http")

    rule_id = _require_string(document["id"], f"{index}.id", maximum=80)
    if any(not (char.isalnum() or char in "._-") for char in rule_id):
        raise ValueError(f"Nuclei YAML document {index} has an invalid id")
    info = document["info"]
    allowed_info = {"name", "severity", "description", "reference", "remediation", "author", "tags", "metadata", "classification"}
    if not isinstance(info, dict) or not {"name", "severity"}.issubset(info) or set(info) - allowed_info:
        raise ValueError(f"Nuclei template {rule_id!r} has unsupported info fields")

    name = _require_string(info["name"], f"{rule_id}.name", maximum=200)
    raw_severity = _require_string(info["severity"], f"{rule_id}.severity", maximum=16).lower()
    severity = raw_severity if raw_severity in _SEVERITIES else ("info" if raw_severity == "unknown" else "")
    if not severity:
        raise ValueError(f"Nuclei template {rule_id!r} has an unsupported severity")

    for field in ("description", "remediation"):
        if field in info:
            _require_string(info[field], f"{rule_id}.{field}", maximum=2000 if field == "description" else 1000)
    _validate_ignored_metadata(info, rule_id)

    raw_references = info.get("reference", [])
    if isinstance(raw_references, str):
        raw_references = [raw_references]
    if not isinstance(raw_references, list) or len(raw_references) > 5:
        raise ValueError(f"Nuclei template {rule_id!r} has invalid references")
    references = [_require_string(value, f"{rule_id}.reference", maximum=500) for value in raw_references]
    for reference in references:
        parts = urlsplit(reference)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ValueError(f"Nuclei template {rule_id!r} references must be HTTPS URLs")

    http = document["http"]
    if not isinstance(http, list) or len(http) != 1 or not isinstance(http[0], dict):
        raise ValueError(f"Nuclei template {rule_id!r} must contain exactly one HTTP request")
    request = http[0]
    if set(request) - {"method", "path", "matchers", "matchers-condition"}:
        raise ValueError(f"Nuclei template {rule_id!r} uses unsupported HTTP request features")

    method = request.get("method", "GET")
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
        raise ValueError(f"Nuclei template {rule_id!r} uses a blocked HTTP method")
    method = method.upper()
    paths = request.get("path")
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not 1 <= len(paths) <= 3:
        raise ValueError(f"Nuclei template {rule_id!r} must have 1 to 3 fixed paths")
    normalized_paths: list[str] = []
    for path in paths:
        path = _require_string(path, f"{rule_id}.path", maximum=500)
        if not path.startswith("{{BaseURL}}"):
            raise ValueError(f"Nuclei template {rule_id!r} paths must start with {{BaseURL}}")
        suffix = path[len("{{BaseURL}}" ):]
        if suffix and not suffix.startswith("/"):
            raise ValueError(f"Nuclei template {rule_id!r} path must use only the target origin")
        if "{{" in suffix or "}}" in suffix:
            raise ValueError(f"Nuclei template {rule_id!r} uses unsupported path variables")
        normalized_paths.append(suffix or "/")

    raw_matchers = request.get("matchers")
    if not isinstance(raw_matchers, list) or not 1 <= len(raw_matchers) <= 16:
        raise ValueError(f"Nuclei template {rule_id!r} must have 1 to 16 supported matchers")
    matcher_groups = [_convert_nuclei_matcher(matcher, rule_id, matcher_index) for matcher_index, matcher in enumerate(raw_matchers)]
    matchers_condition = _condition(request.get("matchers-condition", "or"), rule_id, "matchers-condition")
    if method == "HEAD" and any(group["type"] == "word" for group in matcher_groups):
        raise ValueError(f"Nuclei template {rule_id!r} cannot match body words with HEAD")

    output: list[dict[str, Any]] = []
    for path_index, normalized_path in enumerate(normalized_paths, start=1):
        expanded_id = rule_id if len(normalized_paths) == 1 else f"{rule_id}.p{path_index}"
        if len(expanded_id) > 100:
            raise ValueError(f"Nuclei template {rule_id!r} has an ID that is too long")
        internal = {
            "id": expanded_id,
            "name": name,
            "severity": severity,
            "confidence": "medium",
            "category": "nuclei-import",
            "method": method,
            "path": normalized_path,
            "max_bytes": _MAX_BODY_BYTES,
            "match": {"status": [], "headers": [], "body_contains": [], "body_not_contains": [], "condition": "any"},
            "evidence": "Response matched the imported fixed-path Nuclei literal/status signature.",
            "remediation": _require_string(info.get("remediation", "Review whether this matched surface should be publicly accessible."), f"{rule_id}.remediation", maximum=1000),
            "references": references,
        }
        validated = _validate_template(internal, index, allow_empty_matchers=True)
        validated["nuclei_matcher_groups"] = matcher_groups
        validated["nuclei_matchers_condition"] = matchers_condition
        output.append(validated)
    return output


def _condition(value: Any, rule_id: str, label: str) -> str:
    if not isinstance(value, str) or value.lower() not in {"and", "or"}:
        raise ValueError(f"Nuclei template {rule_id!r} has an invalid {label}")
    return value.lower()


def _convert_nuclei_matcher(value: Any, rule_id: str, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Nuclei template {rule_id!r} has an invalid matcher at index {index}")
    allowed = {"type", "status", "words", "part", "condition", "case-insensitive", "negative", "internal", "name"}
    if set(value) - allowed or "type" not in value:
        raise ValueError(f"Nuclei template {rule_id!r} uses an unsupported matcher feature")
    if value.get("negative", False) is not False or value.get("internal", False) is not False:
        raise ValueError(f"Nuclei template {rule_id!r} cannot use negative or internal matchers")
    if "name" in value:
        _require_string(value["name"], f"{rule_id}.matcher.name", maximum=100)

    matcher_type = value["type"]
    condition = _condition(value.get("condition", "or"), rule_id, "matcher condition")
    if matcher_type == "status":
        if set(value) - {"type", "status", "condition", "name", "negative", "internal"}:
            raise ValueError(f"Nuclei template {rule_id!r} has invalid status matcher fields")
        codes = value.get("status")
        if not isinstance(codes, list) or not 1 <= len(codes) <= 16 or any(isinstance(code, bool) or not isinstance(code, int) or not 100 <= code <= 599 for code in codes):
            raise ValueError(f"Nuclei template {rule_id!r} has invalid status matcher codes")
        if condition != "or":
            raise ValueError(f"Nuclei template {rule_id!r} status code lists support OR matching only")
        return {"type": "status", "values": codes, "condition": "or"}

    if matcher_type == "word":
        if set(value) - {"type", "words", "part", "condition", "case-insensitive", "negative", "internal", "name"}:
            raise ValueError(f"Nuclei template {rule_id!r} has invalid word matcher fields")
        if value.get("part", "body") != "body":
            raise ValueError(f"Nuclei template {rule_id!r} can only match the response body")
        case_insensitive = value.get("case-insensitive", False)
        if not isinstance(case_insensitive, bool):
            raise ValueError(f"Nuclei template {rule_id!r} has an invalid case-insensitive flag")
        words = value.get("words")
        if not isinstance(words, list) or not 1 <= len(words) <= 32:
            raise ValueError(f"Nuclei template {rule_id!r} has invalid word matcher values")
        for word in words:
            if not isinstance(word, str) or not word.strip() or len(word) > 500:
                raise ValueError(f"Nuclei template {rule_id!r} has invalid word matcher values")
        return {"type": "word", "values": words, "condition": condition, "case_insensitive": case_insensitive}

    raise ValueError(f"Nuclei template {rule_id!r} uses an unsupported matcher type")


def _validate_ignored_metadata(info: dict[str, Any], rule_id: str) -> None:
    for field in ("author", "tags"):
        if field not in info:
            continue
        value = info[field]
        values = value if isinstance(value, list) else [value]
        if len(values) > 32:
            raise ValueError(f"Nuclei template {rule_id!r} has too many {field} values")
        for item in values:
            _require_string(item, f"{rule_id}.{field}", maximum=200)

    for field in ("metadata", "classification"):
        if field not in info:
            continue
        value = info[field]
        if not isinstance(value, dict) or len(value) > 64:
            raise ValueError(f"Nuclei template {rule_id!r} has invalid {field} metadata")
        for key, item in value.items():
            _require_string(key, f"{rule_id}.{field}.key", maximum=100)
            values = item if isinstance(item, list) else [item]
            if len(values) > 32:
                raise ValueError(f"Nuclei template {rule_id!r} has too many {field} values")
            for nested in values:
                if isinstance(nested, str):
                    _require_string(nested, f"{rule_id}.{field}.{key}", maximum=500)
                elif not isinstance(nested, (int, bool)):
                    raise ValueError(f"Nuclei template {rule_id!r} has invalid {field} metadata")


def _load_templates(ctx: Any) -> list[dict[str, Any]]:
    templates = _load_template_file(_DATA_FILE, "built-in")
    user_file = (getattr(ctx, "options", {}) or {}).get("templates_file")
    if user_file is not None:
        try:
            user_path = Path(user_file)
        except (TypeError, ValueError, OSError) as exc:
            raise ValueError("--templates-file must be a valid local filesystem path") from exc
        templates.extend(_load_template_file(user_path, "user"))

    if len(templates) > _MAX_TEMPLATES:
        raise ValueError("Combined built-in and user template set must contain no more than 32 entries")
    ids = [template["id"] for template in templates]
    if len(ids) != len(set(ids)):
        raise ValueError("Template IDs must be unique across built-in and user template files")

    for template in templates:
        target_url = _target_url(ctx, template["path"])
        target_parts = urlsplit(target_url)
        decoded_target = urlunsplit((target_parts.scheme, target_parts.netloc, unquote(target_parts.path), target_parts.query, ""))
        if ctx._looks_stateful(decoded_target):
            raise ValueError(f"Template {template['id']!r} uses a known state-changing path")
    return templates


def _target_url(ctx: Any, path: str) -> str:
    base = urlsplit(ctx.base_url)
    url = urlunsplit((base.scheme, base.netloc, path, "", ""))
    # The shared context is the authoritative host+port and HTTPS scope check.
    ctx._check_scope(url)
    return url


def _match_rule(template: dict[str, Any], response: Any) -> tuple[bool, list[str]]:
    matcher_groups = template.get("nuclei_matcher_groups")
    if matcher_groups is not None:
        status = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""
        group_results: list[bool] = []
        observations: list[str] = []
        for group in matcher_groups:
            if group["type"] == "status":
                checks = [status == code for code in group["values"]]
                hit = all(checks) if group["condition"] == "and" else any(checks)
                if hit:
                    observations.append(f"HTTP {status}")
            else:
                candidate = body.lower() if group["case_insensitive"] else body
                words = [word.lower() if group["case_insensitive"] else word for word in group["values"]]
                checks = [word in candidate for word in words]
                hit = all(checks) if group["condition"] == "and" else any(checks)
                if hit:
                    observations.append("Response body matched configured signature")
            group_results.append(hit)

        matched = all(group_results) if template["nuclei_matchers_condition"] == "and" else any(group_results)
        return matched, observations if matched else []

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


def prepare(ctx: Any) -> int:
    """Validate all active templates before the CLI sends any scan requests."""
    templates = _load_templates(ctx)
    ctx._validated_templates = templates
    return len(templates)


def run(ctx: Any) -> int:
    """Apply safe, fixed-path literal templates and append matching findings."""
    templates = getattr(ctx, "_validated_templates", None)
    if templates is None:
        templates = _load_templates(ctx)
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
