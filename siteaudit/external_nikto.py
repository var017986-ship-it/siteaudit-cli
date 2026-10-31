"""Optional adapter for the upstream Nikto command-line scanner."""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .external_support import (
    EngineRunError,
    EngineUnavailable,
    add_engine_finding,
    find_executable,
    run_command,
    scoped_url,
)


# Nikto tuning categories 1, 2, 3, and b cover notable files, default/misconfigured
# files, information disclosure, and software identification. Categories which
# test injection, file retrieval, DoS, command execution, uploads, and auth bypass
# stay excluded from this default adapter run.
_SAFE_TUNING = "123b"
_DOCKER_IMAGE = "ghcr.io/sullo/nikto:2.6.1"


def run(ctx: Any) -> dict[str, Any]:
    options = getattr(ctx, "options", {}) or {}
    docker_mode = False
    try:
        executable = find_executable("nikto", "nikto.pl")
        launcher = [executable]
        if Path(executable).suffix.lower() == ".pl":
            launcher = [find_executable("perl"), executable]
    except EngineUnavailable:
        docker = find_executable("docker", "docker.exe")
        image_check = run_command(
            [docker, "image", "inspect", _DOCKER_IMAGE, "--format", "{{.Id}}"],
            timeout=8,
            output_limit=4096,
        )
        if image_check.returncode != 0:
            raise EngineUnavailable(
                f"Nikto is not installed and its Docker image is missing; run `docker pull {_DOCKER_IMAGE}`"
            )
        docker_mode = True
        launcher = [docker]
        executable = _DOCKER_IMAGE
    target = str(ctx.base_url)
    # Confirm the exact supplied origin before invoking a tool that resolves it
    # independently of SiteAudit's pinned HTTP client.
    if scoped_url(ctx, target) is None:
        raise EngineRunError("Nikto target failed the selected host-and-port scope check")

    engine_timeout = max(1, int(options.get("external_engine_timeout", 300)))
    request_timeout = max(1, int(options.get("timeout", 10)))
    pause = max(0.1, float(options.get("delay", 0.5)))
    proxy_url = options.get("external_proxy_auth_url" if docker_mode else "external_proxy_url")
    if not isinstance(proxy_url, str) or not proxy_url:
        raise EngineRunError("Nikto requires the SiteAudit scope proxy")
    if docker_mode and not proxy_url.startswith("http://siteaudit:"):
        raise EngineRunError("Nikto Docker mode requires the authenticated remote scope proxy")

    with tempfile.TemporaryDirectory(prefix="siteaudit-nikto-") as directory:
        report_path = Path(directory) / "nikto.json"
        container_name = f"siteaudit-nikto-{uuid.uuid4().hex[:16]}" if docker_mode else None
        output_path = "/tmp/siteaudit/nikto.json" if docker_mode else str(report_path)
        scan_arguments = [
            "-host", target,
            "-nointeractive",
            "-nocheck",
            "-nolookup",
            "-nocookies",
            "-useproxy", proxy_url,
            "-Tuning", _SAFE_TUNING,
            "-Pause", f"{pause:.3f}",
            "-timeout", str(request_timeout),
            "-maxtime", f"{engine_timeout}s",
            "-Format", "json",
            "-output", output_path,
        ]
        if docker_mode:
            command = [
                *launcher,
                "run",
                "--rm",
                "--pull=never",
                "--name", container_name,
                "--add-host", "host.docker.internal:host-gateway",
                "--mount", f"type=bind,source={directory},target=/tmp/siteaudit",
                _DOCKER_IMAGE,
                *scan_arguments,
            ]
        else:
            command = [*launcher, *scan_arguments]
        cleanup_error = None
        try:
            process = run_command(
                command,
                timeout=engine_timeout + min(30, request_timeout),
                cwd=directory,
                monitored_paths=[report_path],
            )
        finally:
            if container_name:
                cleanup_error = _cleanup_docker_container(docker, container_name, directory)
        if not report_path.is_file():
            detail = _brief_stderr(process.stderr)
            raise EngineRunError(f"Nikto did not produce its JSON report{': ' + detail if detail else ''}")
        if report_path.stat().st_size > 16_000_000:
            raise EngineRunError("Nikto JSON report exceeded the 16 MB limit")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EngineRunError(f"Could not parse Nikto JSON report: {exc}") from exc

    hosts = report if isinstance(report, list) else [report]
    if len(hosts) > 8:
        raise EngineRunError("Nikto JSON report unexpectedly contains more than eight hosts")

    findings = 0
    for host_index, host_report in enumerate(hosts):
        if not isinstance(host_report, dict):
            continue
        vulnerabilities = host_report.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for item_index, item in enumerate(vulnerabilities[:2000]):
            if not isinstance(item, dict):
                continue
            raw_uri = item.get("url") or item.get("uri")
            if not isinstance(raw_uri, str) or not raw_uri.strip():
                continue
            candidate_url = urljoin(target, raw_uri)
            # Do not turn another host's report entry into a finding on the base
            # URL. Out-of-scope results are discarded.
            if scoped_url(ctx, candidate_url) is None:
                continue

            message = item.get("msg") or item.get("message") or "Nikto test database reported a match."
            test_id = item.get("id") or item.get("testid") or f"{host_index}-{item_index}"
            references = item.get("references") or item.get("refs") or []
            if isinstance(references, str):
                references = [references]
            if not isinstance(references, list):
                references = []

            if add_engine_finding(
                ctx,
                engine="nikto",
                issue_id=test_id,
                title=f"Nikto: {message}",
                severity="info",
                confidence="medium",
                url=candidate_url,
                evidence=f"Nikto test {test_id} matched: {message}",
                references=references,
            ):
                findings += 1

    status = "completed" if process.returncode == 0 and not cleanup_error else "partial"
    result: dict[str, Any] = {
        "status": status,
        "return_code": process.returncode,
        "duration_seconds": process.duration_seconds,
        "findings_parsed": findings,
        "tuning": _SAFE_TUNING,
        "max_scan_time_seconds": engine_timeout,
        "execution": "docker" if docker_mode else "native",
        "docker_image": _DOCKER_IMAGE if docker_mode else None,
        "container_cleanup": "failed" if cleanup_error else ("complete" if docker_mode else None),
        "pause_seconds": pause,
        "scope_note": "The scope proxy restricts HTTP requests and HTTPS tunnels to the selected host and port and pins the IP; HTTPS Host headers inside TLS are not inspected.",
    }
    if process.returncode != 0:
        detail = _brief_stderr(process.stderr)
        if detail:
            result["error"] = detail
    if cleanup_error:
        result["error"] = (result.get("error", "") + f" Docker cleanup failed: {cleanup_error}").strip()[:800]
    return result


def _cleanup_docker_container(docker: str, name: str, cwd: str) -> str | None:
    errors = []
    for action in ("stop", "rm"):
        command = [docker, action, "--time", "2", name] if action == "stop" else [docker, action, "--force", name]
        try:
            result = run_command(command, timeout=8, cwd=cwd, output_limit=4096)
            detail = result.stderr or result.stdout
            if result.returncode != 0 and "no such container" not in detail.lower():
                errors.append(_brief_stderr(detail) or f"docker {action} failed")
        except (EngineRunError, EngineUnavailable, OSError) as exc:
            errors.append(str(exc))
    return "; ".join(errors)[:500] if errors else None


def _brief_stderr(value: str) -> str:
    return " ".join(value.split())[:500]
