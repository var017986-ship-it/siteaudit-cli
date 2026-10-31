"""Optional adapter for the upstream Nuclei command-line scanner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .external_support import EngineRunError, EngineUnavailable, add_engine_finding, find_executable, run_command


def run(ctx: Any) -> dict[str, Any]:
    """Run Nuclei against the selected origin with explicit local templates.

    Nuclei's installed default template pack is used unless the operator
    provides a reviewed local file or directory through ``--nuclei-templates``.
    """
    configured_templates = (ctx.options or {}).get("nuclei_templates")
    templates_path: Path | None = None
    if configured_templates:
        templates_path = Path(configured_templates).expanduser()
        if not templates_path.exists() or not (templates_path.is_file() or templates_path.is_dir()):
            raise ValueError(f"Nuclei template path does not exist or is not a file/directory: {templates_path}")

    executable = find_executable("nuclei", "nuclei.exe")
    timeout = float((ctx.options or {}).get("external_engine_timeout", 300))
    request_timeout = max(1, int((ctx.options or {}).get("timeout", 10)))
    delay = max(0.1, float((ctx.options or {}).get("delay", 0.5)))
    # Nuclei accepts an integer per-second rate. Floor to avoid exceeding the
    # requested rate for common sub-second delays; keep one request/second as
    # its minimum. A request delay above one second cannot be represented by
    # that option and is reported in the result metadata below.
    rate_limit = max(1, int(1 / delay))

    command = [
        executable,
        "-u", ctx.base_url,
        "-type", "http",
        "-jsonl",
        "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-disable-redirects",
        "-omit-raw",
        "-omit-template",
        "-rate-limit", str(rate_limit),
        "-bulk-size", "1",
        "-concurrency", "1",
        "-timeout", str(request_timeout),
        "-retries", "0",
        "-exclude-tags", "dos,intrusive,fuzz,bruteforce",
    ]
    if templates_path is not None:
        command.extend(["-t", str(templates_path.resolve())])
    if not (ctx.options or {}).get("allow_private"):
        command.append("-restrict-local-network-access")

    process = run_command(command, timeout=timeout)
    findings_added = 0
    out_of_scope = 0
    malformed_lines = 0
    for line in process.stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            malformed_lines += 1
            continue
        if not isinstance(item, dict):
            malformed_lines += 1
            continue

        info = item.get("info")
        if not isinstance(info, dict):
            info = {}
        matched_url = item.get("matched-at") or item.get("matched_at")
        if not isinstance(matched_url, str) or not matched_url:
            malformed_lines += 1
            continue
        if not _in_scope(ctx, matched_url):
            out_of_scope += 1
            continue

        template_id = item.get("template-id") or item.get("template_id") or "finding"
        matcher_name = item.get("matcher-name") or item.get("matcher_name")
        evidence = f"Nuclei template {str(template_id)[:120]!r} matched"
        if isinstance(matcher_name, str) and matcher_name.strip():
            evidence += f" via matcher {matcher_name.strip()[:100]!r}"
        if add_engine_finding(
            ctx,
            engine="nuclei",
            issue_id=template_id,
            title=info.get("name"),
            severity=info.get("severity"),
            url=matched_url,
            evidence=evidence,
            recommendation=info.get("remediation"),
            references=info.get("reference"),
        ):
            findings_added += 1

    version = _version(executable, timeout=min(timeout, 15))
    status = "completed" if process.returncode == 0 else ("partial" if findings_added else "error")
    result: dict[str, Any] = {
        "status": status,
        "version": version,
        "duration_seconds": process.duration_seconds,
        "findings_added": findings_added,
        "exit_code": process.returncode,
        "out_of_scope_results_ignored": out_of_scope,
        "malformed_output_lines": malformed_lines,
        "rate_limit_per_second": rate_limit,
        "concurrency": 1,
        "template_source": "custom local path" if templates_path is not None else "Nuclei installed default pack",
        "scope_note": "Only results matching the selected host and port are imported. The upstream template engine is not sandboxed to that hostname; use reviewed templates.",
    }
    if delay > 1:
        result["rate_limit_note"] = "Nuclei integer rate limit cannot enforce delays slower than one request per second."
    if process.returncode != 0 and process.stderr.strip():
        result["error"] = " ".join(process.stderr.split())[:1000]
    return result


def _in_scope(ctx: Any, url: str) -> bool:
    if len(url) > 4096:
        return False
    try:
        ctx._check_scope(url)
        parts = urlsplit(url)
        return parts.scheme in {"http", "https"} and not parts.username and not parts.password
    except (TypeError, ValueError, UnicodeError):
        return False


def _version(executable: str, timeout: float) -> str | None:
    try:
        process = run_command([executable, "-version"], timeout=timeout, output_limit=64_000)
    except (EngineUnavailable, OSError, EngineRunError):
        return None
    if process.returncode != 0:
        return None
    for line in (process.stdout + "\n" + process.stderr).splitlines():
        line = line.strip()
        if line:
            return line[:160]
    return None
