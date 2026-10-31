"""Optional adapter for the upstream Nuclei command-line scanner."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .external_support import EngineRunError, EngineUnavailable, add_engine_finding, find_executable, run_command


_NETWORK_DSL_HELPER = re.compile(r"(?<![A-Za-z0-9_])(?:resolve|public_ip|jarm)\s*\(", re.IGNORECASE)
_TEMPLATE_EXTENSIONS = {".yaml", ".yml", ".json"}
_MAX_TEMPLATE_FILES = 20_000
_MAX_TEMPLATE_BYTES = 512_000_000
_MAX_SINGLE_TEMPLATE_BYTES = 4_000_000


def _template_source(configured: Any) -> tuple[Path, str]:
    if configured:
        source = Path(configured).expanduser()
        label = "custom local path"
    else:
        source = Path.home() / "nuclei-templates"
        label = "installed default template directory"
    if not source.exists() or not (source.is_file() or source.is_dir()):
        raise EngineRunError(
            f"Nuclei templates not found at {source}; set --nuclei-templates to a reviewed local file or directory"
        )
    if source.is_file() and source.suffix.lower() not in _TEMPLATE_EXTENSIONS:
        raise EngineRunError("Nuclei template files must use .yaml, .yml, or .json")
    return source.resolve(), label


def _prepare_templates(source: Path, destination: Path) -> tuple[int, int]:
    """Copy HTTP template inputs while excluding direct network-capable DSL helpers."""
    destination.mkdir(parents=True, exist_ok=True)
    files = [source] if source.is_file() else sorted(source.rglob("*"))
    copied = 0
    blocked = 0
    total_bytes = 0
    template_count = 0
    for path in files:
        if path.is_symlink() or not path.is_file():
            continue
        relative = Path(path.name) if source.is_file() else path.relative_to(source)
        if path.name == ".nuclei-ignore":
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            continue
        if path.suffix.lower() not in _TEMPLATE_EXTENSIONS:
            continue
        template_count += 1
        if template_count > _MAX_TEMPLATE_FILES:
            raise EngineRunError(f"Nuclei template directory exceeds {_MAX_TEMPLATE_FILES} files")
        size = path.stat().st_size
        total_bytes += size
        if size > _MAX_SINGLE_TEMPLATE_BYTES or total_bytes > _MAX_TEMPLATE_BYTES:
            raise EngineRunError("Nuclei template directory exceeds the local size limits")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise EngineRunError(f"Could not read Nuclei template {path}: {exc}") from exc
        if _NETWORK_DSL_HELPER.search(content.decode("utf-8", errors="replace")):
            blocked += 1
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(content)
        except OSError as exc:
            raise EngineRunError(f"Could not prepare Nuclei template {path}: {exc}") from exc
        copied += 1

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
        templates_used, templates_blocked = _prepare_templates(templates_path, safe_templates)
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
        "template_source": template_source,
        "templates_used": templates_used,
        "templates_blocked_network_dsl": templates_blocked,
        "scope_note": "The scope proxy restricts HTTP requests and HTTPS tunnels to the selected host and port and pins the IP. HTTPS Host headers inside TLS are not inspected. Templates using resolve(), public_ip(), or jarm() are excluded because Nuclei v3.11.1 can make those calls outside the proxy.",
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
