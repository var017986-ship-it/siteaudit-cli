"""Low-impact, Wapiti-inspired checks for reflected input and SQL errors.

This module deliberately limits itself to GET requests and inert marker values.
It does not attempt to prove code execution or modify application state.
"""

from __future__ import annotations

from html.parser import HTMLParser
from secrets import token_hex
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


_MAX_PAGES = 5
_MAX_PARAMS_PER_PAGE = 2
_MAX_REQUESTS = 24
_MAX_RESPONSE_BYTES = 96_000
_SENSITIVE_PARAMETER_PARTS = (
    "token", "password", "passwd", "pwd", "secret", "session", "auth",
    "csrf", "xsrf", "signature", "api_key", "apikey", "email",
)
_STATEFUL_PATH_PARTS = (
    "logout", "log-out", "delete", "remove", "purchase", "checkout", "pay",
    "unsubscribe", "reset", "transfer", "submit",
)
_STATE_CHANGING_WORDS = {"logout", "signout", "delete", "remove", "unsubscribe", "purchase", "checkout", "payment", "pay", "cancel", "deactivate", "reset", "transfer", "submit", "destroy", "revoke"}

_SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli_sql_exception",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error at or near",
    "sqlite error",
    "sqlite3.operationalerror",
    "odbc sql server driver",
    "ora-00933",
    "ora-01756",
    "sqlstate[",
)


class _GetFormParser(HTMLParser):
    """Collect only same-page GET form controls; never submits a form."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[tuple[str, list[tuple[str, str]]]] = []
        self._action: str | None = None
        self._method = "get"
        self._fields: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): (value or "") for key, value in attrs}
        if tag.lower() == "form":
            self._finish_form()
            self._method = attrs_map.get("method", "get").strip().lower()
            self._action = attrs_map.get("action", "")
            self._fields = []
            return

        if self._action is None or self._method != "get":
            return

        if tag.lower() == "input":
            name = attrs_map.get("name", "").strip()
            input_type = attrs_map.get("type", "text").strip().lower()
            if name and input_type not in {"submit", "button", "image", "file", "password", "hidden"}:
                self._fields.append((name, attrs_map.get("value", "")))
        elif tag.lower() == "textarea":
            name = attrs_map.get("name", "").strip()
            if name:
                self._fields.append((name, ""))
        elif tag.lower() == "select":
            name = attrs_map.get("name", "").strip()
            if name:
                self._fields.append((name, ""))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_form()

    def close(self) -> None:
        super().close()
        self._finish_form()

    def _finish_form(self) -> None:
        if self._action is not None and self._method == "get" and self._fields:
            self.forms.append((self._action, self._fields))
        self._action = None
        self._fields = []
        self._method = "get"


def _same_host(url: str, target: object) -> bool:
    # Reuse the context's canonical host+port and HTTPS downgrade checks.
    # `ctx.host` includes an effective port, so comparing it to urlsplit().hostname
    # would incorrectly skip every probe.
    checker = getattr(target, "_check_scope", None)
    if callable(checker):
        try:
            checker(url)
            return True
        except ValueError:
            return False
    try:
        parsed = urlsplit(url)
        expected = urlsplit(str(target))
        if not parsed.hostname or not expected.hostname or parsed.scheme not in {"http", "https"}:
            return False
        target_port = expected.port or (443 if expected.scheme == "https" else 80)
        candidate_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.hostname.lower() == expected.hostname.lower() and candidate_port == target_port
    except ValueError:
        return False


def _normalize_url(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        candidate = value.get("url") or value.get("href")
        return candidate if isinstance(candidate, str) else None
    return None


def _replace_query_value(url: str, key: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for existing_key, existing_value in pairs:
        if existing_key == key and not replaced:
            output.append((existing_key, value))
            replaced = True
        elif existing_key != key:
            output.append((existing_key, existing_value))
    if not replaced:
        output.append((key, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(output, doseq=True), parsed.fragment))


def _response_text(response: object) -> str:
    text = getattr(response, "text", "")
    if isinstance(text, str):
        return text[:_MAX_RESPONSE_BYTES]
    body = getattr(response, "body", b"")
    if isinstance(body, bytes):
        return body[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    return ""


def _status_code(response: object) -> int | None:
    try:
        return int(getattr(response, "status_code"))
    except (TypeError, ValueError, AttributeError):
        return None


def _request(ctx: object, url: str) -> object | None:
    try:
        return ctx.request("GET", url, max_bytes=_MAX_RESPONSE_BYTES, follow_redirects=False)  # type: ignore[attr-defined]
    except Exception:
        # Network and policy errors are local to this probe; other checks can continue.
        return None


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_PARAMETER_PARTS)


def _is_stateful_url(url: str) -> bool:
    parsed = urlsplit(url)
    if any(part in parsed.path.lower() for part in _STATEFUL_PATH_PARTS):
        return True
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        key_words = set(key.lower().replace("-", "_").split("_"))
        value_words = set(value.lower().replace("-", "_").replace("/", "_").split("_"))
        if key_words & _STATE_CHANGING_WORDS or value_words & _STATE_CHANGING_WORDS:
            return True
    return False


def _candidate_urls(ctx: object) -> list[str]:
    raw = getattr(ctx, "discovered_urls", []) or []
    seen: set[str] = set()
    urls: list[str] = []
    for item in raw:
        url = _normalize_url(item)
        if not url or not _same_host(url, ctx):
            continue
        parsed = urlsplit(url)
        if _is_stateful_url(canonical):
            continue
        canonical = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if canonical not in seen:
            urls.append(canonical)
            seen.add(canonical)
        if len(urls) >= _MAX_PAGES:
            break
    return urls


def _record(ctx: object, *, finding_id: str, title: str, severity: str, confidence: str,
            url: str, evidence: str, recommendation: str, category: str) -> None:
    ctx.add_finding(  # type: ignore[attr-defined]
        id=finding_id,
        title=title,
        severity=severity,
        confidence=confidence,
        url=url,
        evidence=evidence,
        recommendation=recommendation,
        category=category,
    )


def run(ctx: object) -> None:
    """Run bounded inert GET probes against discovered query parameters.

    Reflection is reported as a low-confidence HTML-injection indicator, not a
    confirmed XSS. SQL diagnostics are reported only when a quote probe produces
    a recognizable server error that was absent in the baseline response.
    """
    requests_used = 0

    for page_url in _candidate_urls(ctx):
        if requests_used >= _MAX_REQUESTS:
            break

        # A baseline is used only to distinguish pre-existing errors from ones
        # that appear after adding a single quote to a parameter.
        baseline = _request(ctx, page_url)
        requests_used += 1
        if baseline is None or getattr(baseline, "error", None):
            continue
        baseline_text = _response_text(baseline).lower()
        page_text = _response_text(baseline)

        # Parse passive GET forms from the fetched page. The scanner tests action
        # parameters via GET only; it never submits POST forms or button controls.
        parser = _GetFormParser()
        try:
            parser.feed(page_text)
            parser.close()
        except Exception:
            parser.forms = []

        forms = list(parser.forms)
        for form in getattr(ctx, "discovered_forms", []) or []:
            if not isinstance(form, dict) or str(form.get("method", "GET")).upper() != "GET":
                continue
            source_url = form.get("source_url")
            if isinstance(source_url, str):
                source = urlsplit(source_url)
                current = urlsplit(page_url)
                if (source.hostname or "").lower() != (current.hostname or "").lower() or source.path != current.path:
                    continue
            action = form.get("action") or form.get("source_url") or page_url
            inputs = form.get("inputs", [])
            if not isinstance(action, str) or not isinstance(inputs, list):
                continue
            fields: list[tuple[str, str]] = []
            for field in inputs:
                if not isinstance(field, dict):
                    continue
                name = str(field.get("name", "")).strip()
                input_type = str(field.get("type", "text")).lower()
                if name and input_type not in {"submit", "button", "image", "file", "password", "hidden"}:
                    fields.append((name, str(field.get("value", ""))))
            if fields:
                forms.append((action, fields))

        query_pairs = parse_qsl(urlsplit(page_url).query, keep_blank_values=True)
        probes: list[tuple[str, str, str]] = []
        # Input from query strings takes precedence, then the first discovered
        # same-host GET form's non-sensitive controls are added.
        for key, value in query_pairs:
            if key and not _is_sensitive_key(key):
                probes.append((page_url, key, value))
        for action, fields in forms:
            form_url = urljoin(page_url, action)
            if (not _same_host(form_url, ctx)
                    or _is_stateful_url(form_url)):
                continue
            for key, value in fields:
                if key and not _is_sensitive_key(key):
                    probes.append((form_url, key, value))

        seen_probe_keys: set[tuple[str, str]] = set()
        page_probe_count = 0
        for form_url, key, original_value in probes:
            if requests_used >= _MAX_REQUESTS or page_probe_count >= _MAX_PARAMS_PER_PAGE:
                break
            identity = (form_url, key)
            if identity in seen_probe_keys:
                continue
            seen_probe_keys.add(identity)
            page_probe_count += 1

            # Use a unique, inert custom-tag string. No script, event handler,
            # quote-breaking sequence, or executable content is sent.
            nonce = token_hex(4)
            marker = f"codexprobe_{nonce}"
            inert_markup = f"<x-{marker}>{marker}</x-{marker}>"
            marker_url = _replace_query_value(form_url, key, inert_markup)
            if not _same_host(marker_url, ctx):
                continue
            marker_response = _request(ctx, marker_url)
            requests_used += 1
            if marker_response is None or getattr(marker_response, "error", None):
                continue
            marker_body = _response_text(marker_response)
            if marker in marker_body and inert_markup in marker_body:
                _record(
                    ctx,
                    finding_id="potential-reflected-html",
                    title="Unescaped input reflected in HTML response",
                    severity="low",
                    confidence="low",
                    url=marker_url,
                    evidence=(
                        f"GET parameter {key!r} returned the inert probe marker as raw HTML "
                        f"(HTTP {_status_code(marker_response) or 'unknown'}). This indicates reflection; "
                        "the output context was not verified and this does not confirm XSS."
                    ),
                    recommendation=(
                        "Encode untrusted values for their output context and validate them on the server. "
                        "Review the affected template manually before treating this as exploitable."
                    ),
                    category="input-validation",
                )

            if requests_used >= _MAX_REQUESTS:
                break
            # A single apostrophe is an inert syntax-error indicator. No SQL
            # operators, delays, stacked statements, or data-reading payloads.
            quote_value = (original_value[:64] + "'") if original_value else "'"
            quote_url = _replace_query_value(form_url, key, quote_value)
            if not _same_host(quote_url, ctx):
                continue
            quote_response = _request(ctx, quote_url)
            requests_used += 1
            if quote_response is None or getattr(quote_response, "error", None):
                continue
            quote_body = _response_text(quote_response).lower()
            triggered = [token for token in _SQL_ERROR_MARKERS if token in quote_body and token not in baseline_text]
            if triggered:
                _record(
                    ctx,
                    finding_id="sql-error-disclosure-indicator",
                    title="Database error indicator after quote in input",
                    severity="medium",
                    confidence="low",
                    url=quote_url,
                    evidence=(
                        f"Adding one quote to GET parameter {key!r} produced a database error marker "
                        f"({triggered[0]!r}) absent from the baseline response. This may expose an input "
                        "handling issue; it is not proof of SQL injection."
                    ),
                    recommendation=(
                        "Return generic errors to clients and use parameterized database queries. "
                        "Review server-side logs and code for the affected parameter."
                    ),
                    category="error-disclosure",
                )
