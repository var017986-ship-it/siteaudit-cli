"""Optional adapter for the upstream Nuclei command-line scanner."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .external_support import EngineRunError, EngineUnavailable, add_engine_finding, find_executable, get_engine_home, run_command
from .external_support import ProcessOutput


_NETWORK_DSL_HELPER = re.compile(rb"(?<![A-Za-z0-9_])(?:resolve|public_ip|jarm)\s*\(", re.IGNORECASE)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_TEMPLATE_EXTENSIONS = {".yaml", ".yml", ".json"}
_MAX_TEMPLATE_FILES = 20_000
_MAX_TEMPLATE_BYTES = 512_000_000
_MAX_SINGLE_TEMPLATE_BYTES = 16_000_000
_MAX_TAG_COUNT = 50
_TAG_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def _template_source(configured: Any) -> tuple[Path, str]:
    if configured:
        source = Path(configured).expanduser()
        label = "custom local path"
    else:
        managed_templates = get_engine_home() / "nuclei-templates"
        source = managed_templates if managed_templates.exists() else Path.home() / "nuclei-templates"
        label = "SiteAudit-managed templates" if source == managed_templates else "installed default template directory"
    if not source.exists() or not (source.is_file() or source.is_dir()):
        raise EngineRunError(
            f"Nuclei templates not found at {source}; set --nuclei-templates to a reviewed local file or directory"
        )
    if source.is_file() and source.suffix.lower() not in _TEMPLATE_EXTENSIONS:
        raise EngineRunError("Nuclei template files must use .yaml, .yml, or .json")
    return source.resolve(), label


def _prepare_templates(source: Path, destination: Path) -> tuple[int, int]:
    """Copy templates concurrently while excluding direct network-capable DSL helpers."""
    destination.mkdir(parents=True, exist_ok=True)
    files = [source] if source.is_file() else sorted(source.rglob("*"))
    total_bytes = 0
    candidates: list[tuple[Path, Path]] = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            continue
        relative = Path(path.name) if source.is_file() else path.relative_to(source)
        if path.name == ".nuclei-ignore":
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(path.read_bytes())
            except OSError as exc:
                raise EngineRunError(f"Could not prepare Nuclei ignore file {path}: {exc}") from exc
            continue
        if path.suffix.lower() not in _TEMPLATE_EXTENSIONS:
            continue
        candidates.append((path, relative))
        if len(candidates) > _MAX_TEMPLATE_FILES:
            raise EngineRunError(f"Nuclei template directory exceeds {_MAX_TEMPLATE_FILES} files")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise EngineRunError(f"Could not inspect Nuclei template {path}: {exc}") from exc
        total_bytes += size
        if size > _MAX_SINGLE_TEMPLATE_BYTES or total_bytes > _MAX_TEMPLATE_BYTES:
            raise EngineRunError("Nuclei template directory exceeds the local size limits")

    def copy_if_safe(item: tuple[Path, Path]) -> bool:
        path, relative = item
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise EngineRunError(f"Could not read Nuclei template {path}: {exc}") from exc
        if _NETWORK_DSL_HELPER.search(content):
            return False
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(content)
        except OSError as exc:
            raise EngineRunError(f"Could not prepare Nuclei template {path}: {exc}") from exc
        return True

    copied = 0
    workers = max(2, min(8, os.cpu_count() or 4))
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="siteaudit-nuclei-templates") as pool:
            futures = [pool.submit(copy_if_safe, item) for item in candidates]
            for future in as_completed(futures):
                copied += int(future.result())
    except EngineRunError:
        raise
    except OSError as exc:
        raise EngineRunError(f"Could not prepare Nuclei templates: {exc}") from exc

    blocked = len(candidates) - copied

    if not copied:
        if blocked:
            raise EngineRunError("All Nuclei templates were excluded because they call resolve(), public_ip(), or jarm()")
        raise EngineRunError("No Nuclei YAML or JSON templates were found in the selected path")
    return copied, blocked


def run(ctx: Any) -> dict[str, Any]:
    """Run HTTP Nuclei templates after filtering direct network DSL helpers."""
    executable = find_executable("nuclei", "nuclei.exe")
    configured_templates = (ctx.options or {}).get("nuclei_templates")
    templates_path, template_source = _template_source(configured_templates)

    timeout = float((ctx.options or {}).get("external_engine_timeout", 300))
    started_at = time.monotonic()
    version = _version(executable, timeout=min(timeout, 15))
    tags = _validated_tags((ctx.options or {}).get("nuclei_tags"))
    auto_scan = bool((ctx.options or {}).get("nuclei_auto_scan"))
    if tags and auto_scan:
        raise EngineRunError("Nuclei tag filtering cannot be combined with automatic technology scanning")
    request_timeout = max(1, int((ctx.options or {}).get("timeout", 10)))
    delay = max(0.1, float((ctx.options or {}).get("delay", 0.5)))
    # Nuclei accepts an integer per-second rate. Floor to avoid exceeding the
    # requested rate for common sub-second delays; keep one request/second as
    # its minimum. A request delay above one second cannot be represented by
    # that option and is reported in the result metadata below.
    rate_limit = max(1, int(1 / delay))
    proxy_url = (ctx.options or {}).get("external_proxy_url")
    if not isinstance(proxy_url, str) or not proxy_url:
        raise EngineRunError("Nuclei requires the SiteAudit scope proxy")

    with tempfile.TemporaryDirectory(prefix="siteaudit-nuclei-") as directory:
        safe_templates = Path(directory) / "templates"
        preparation_started = time.monotonic()
        templates_used, templates_blocked = _prepare_templates(templates_path, safe_templates)
        preparation_seconds = time.monotonic() - preparation_started
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
            "-proxy", proxy_url,
            "-proxy-internal",
            "-t", str(safe_templates),
        ]
        if tags:
            command.extend(["-tags", tags])
        if auto_scan:
            command.append("-as")
        # Route even internal references through the scope proxy. Nuclei's
        # local-network guard misclassified this publicly routable target;
        # host/port filtering and network-DSL screening are the scope controls.
        remaining_timeout = timeout - (time.monotonic() - started_at)
        if remaining_timeout <= 0:
            raise EngineRunError("Nuclei template preparation exceeded the engine time limit")
        # Let Nuclei stop on its own shortly before the process watchdog. This
        # preserves JSONL findings and avoids killing Go midway through output.
        scan_max_time_seconds = max(1, int(remaining_timeout - 3))
        command.extend(["-max-time", f"{scan_max_time_seconds}s"])
        scan_error = None
        try:
            process = run_command(command, timeout=remaining_timeout)
        except EngineRunError as exc:
            if not (exc.partial_stdout or exc.partial_stderr):
                raise
            scan_error = str(exc)
            process = ProcessOutput(
                returncode=1,
                stdout=exc.partial_stdout,
                stderr=exc.partial_stderr,
                duration_seconds=exc.duration_seconds or remaining_timeout,
            )
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

    max_time_reached = _max_time_reached(process.duration_seconds, scan_max_time_seconds)
    status = _scan_status(process.returncode, scan_error=bool(scan_error), max_time_reached=max_time_reached)
    templates_loaded = _parse_loaded_templates(process.stdout + "\n" + process.stderr)
    result: dict[str, Any] = {
        "status": status,
        "version": version,
        "duration_seconds": process.duration_seconds,
        "engine_elapsed_seconds": round(time.monotonic() - started_at, 3),
        "engine_timeout_seconds": timeout,
        "scanner_max_time_seconds": scan_max_time_seconds,
        "scanner_max_time_reached": max_time_reached,
        "template_preparation_seconds": round(preparation_seconds, 3),
        "template_scan_seconds": round(process.duration_seconds, 3),
        "findings_added": findings_added,
        "exit_code": process.returncode,
        "out_of_scope_results_ignored": out_of_scope,
        "malformed_output_lines": malformed_lines,
        "rate_limit_per_second": rate_limit,
        "concurrency": 1,
        "scan_mode": "technology-aware" if auto_scan else ("tag-filtered-http-templates" if tags else "all-selected-http-templates"),
        "template_tags_filter": tags.split(",") if tags else None,
        "input_targets": 1,
        "total_page_cap_enforced": False,
        "template_source": template_source,
        "templates_used": templates_used,
        "templates_copied_to_safe_directory": templates_used,
        "templates_loaded_by_scanner": templates_loaded,
        "templates_blocked_network_dsl": templates_blocked,
        "scope_note": "The scope proxy restricts HTTP requests and HTTPS tunnels to the selected host and port and pins the IP. HTTPS Host headers inside TLS are not inspected. Templates using resolve(), public_ip(), or jarm() are excluded because Nuclei v3.11.1 can make those calls outside the proxy.",
    }
    if delay > 1:
        result["rate_limit_note"] = "Nuclei integer rate limit cannot enforce delays slower than one request per second."
    if max_time_reached:
        result["partial_reason"] = "nuclei_scanner_max_time_reached"
        result["error"] = "Nuclei reached its scanner-side time budget; template coverage is incomplete."
    elif scan_error:
        result["partial_reason"] = "external_process_time_limit"
        result["error"] = scan_error[:1000]
    elif process.returncode != 0 and process.stderr.strip():
        result["error"] = " ".join(process.stderr.split())[:1000]
    return result


def _validated_tags(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise EngineRunError("Nuclei tags must be a comma-separated string")
    tags = [item.strip().lower() for item in value.split(",")]
    if not 1 <= len(tags) <= _MAX_TAG_COUNT or any(not _TAG_PATTERN.fullmatch(item) for item in tags):
        raise EngineRunError(f"Nuclei tags must contain 1-{_MAX_TAG_COUNT} simple tag names")
    return ",".join(dict.fromkeys(tags))


def _max_time_reached(duration_seconds: float, max_time_seconds: int) -> bool:
    tolerance = max(0.1, min(3.0, max_time_seconds * 0.05))
    return duration_seconds >= max_time_seconds - tolerance


def _scan_status(return_code: int, *, scan_error: bool, max_time_reached: bool) -> str:
    if scan_error or max_time_reached:
        return "partial"
    return "completed" if return_code == 0 else "error"


def _parse_loaded_templates(output: str) -> int | None:
    match = re.search(r"(?i)templates loaded for current scan:\s*([0-9][0-9,]*)", output)
    return int(match.group(1).replace(",", "")) if match else None


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
        clean_line = _ANSI_ESCAPE.sub("", line).strip()
        match = re.search(r"\bv?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\b", clean_line)
        if match:
            return match.group(0)[:80]
    return None
