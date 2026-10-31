"""Optional adapter for the upstream Nikto command-line scanner."""

from __future__ import annotations

import ipaddress
import json
import os
import re
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


# Tuning 1/2/3/b covers interesting files, default/misconfigured files,
# information disclosure, and software identification. The plugin allowlist is
# also explicit because tuning does not restrict non-database plugins.
_SAFE_TUNING = "123b"
_SAFE_PLUGINS = (
    "headers;httpoptions;ssl;sitefiles;robots;paths;msgs;outdated;favicon;"
    "tests(report:500);report_json"
)
_DOCKER_IMAGE = "ghcr.io/sullo/nikto:2.6.1"
_WSL_DISTRIBUTION = "Debian"
_WSL_INSTALL_ROOT = "/opt/siteaudit/nikto-2.6.1"
_WSL_NIKTO_SCRIPT = f"{_WSL_INSTALL_ROOT}/program/nikto.pl"
_WSL_PINNED_COMMIT = "d201dac"
_WSL_PROBE_TIMEOUT = 6
_MAX_WSL_COMMAND_TIMEOUT = 900
_MAX_REPORT_BYTES = 16_000_000


def wsl_nikto_runtime() -> dict[str, Any]:
    """Probe the pinned WSL checkout and return the NAT host route for the proxy.

    The probe runs only local WSL commands; it never resolves or contacts a scan
    target. An unavailable result includes a short reason for the doctor output.
    """
    if os.name != "nt":
        return {"ready": False, "reason": "The WSL Nikto runner is Windows-only."}

    try:
        wsl = find_executable("wsl.exe", "wsl")
    except EngineUnavailable:
        return {"ready": False, "reason": "wsl.exe was not found on PATH."}

    try:
        checkout = run_command(
            [
                wsl,
                "--distribution",
                _WSL_DISTRIBUTION,
                "--user",
                "root",
                "--exec",
                "git",
                "-C",
                _WSL_INSTALL_ROOT,
                "rev-parse",
                "HEAD",
            ],
            timeout=_WSL_PROBE_TIMEOUT,
            output_limit=4096,
        )
    except (EngineRunError, EngineUnavailable, OSError) as exc:
        return {"ready": False, "reason": f"Could not query WSL Debian: {_brief_stderr(str(exc))}", "wsl_executable": wsl}
    if checkout.returncode != 0:
        return {
            "ready": False,
            "reason": f"Nikto 2.6.1 is not installed in the WSL {_WSL_DISTRIBUTION} distribution.",
            "wsl_executable": wsl,
        }
    commit = checkout.stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not commit.startswith(_WSL_PINNED_COMMIT):
        return {
            "ready": False,
            "reason": f"The WSL Nikto checkout is not pinned to upstream commit {_WSL_PINNED_COMMIT}.",
            "wsl_executable": wsl,
            "found_commit": commit[:40],
        }

    try:
        dependencies = run_command(
            [
                wsl,
                "--distribution",
                _WSL_DISTRIBUTION,
                "--exec",
                "perl",
                "-e",
                "use JSON::PP; use Net::SSLeay; use XML::Writer; use Time::Seconds;",
            ],
            timeout=_WSL_PROBE_TIMEOUT,
            output_limit=4096,
        )
    except (EngineRunError, EngineUnavailable, OSError) as exc:
        return {"ready": False, "reason": f"Could not check WSL Perl dependencies: {_brief_stderr(str(exc))}", "wsl_executable": wsl}
    if dependencies.returncode != 0:
        return {
            "ready": False,
            "reason": "Nikto's WSL Perl HTTPS/JSON modules are missing; run scripts/setup-wsl-nikto.ps1.",
            "wsl_executable": wsl,
            "diagnostic": _brief_stderr(dependencies.stderr or dependencies.stdout),
        }

    try:
        route = run_command(
            [
                wsl,
                "--distribution",
                _WSL_DISTRIBUTION,
                "--exec",
                "ip",
                "-4",
                "route",
                "show",
                "default",
            ],
            timeout=_WSL_PROBE_TIMEOUT,
            output_limit=4096,
        )
    except (EngineRunError, EngineUnavailable, OSError) as exc:
        return {"ready": False, "reason": f"Could not read WSL's default route: {_brief_stderr(str(exc))}", "wsl_executable": wsl}
    match = re.search(r"(?:^|\s)via\s+([0-9.]+)(?:\s|$)", route.stdout)
    try:
        gateway = str(ipaddress.IPv4Address(match.group(1))) if route.returncode == 0 and match else ""
    except ipaddress.AddressValueError:
        gateway = ""
    if not gateway:
        return {
            "ready": False,
            "reason": "Could not determine the Windows host gateway from the WSL default route.",
            "wsl_executable": wsl,
            "route_diagnostic": _brief_stderr(route.stderr or route.stdout),
        }

    try:
        source = run_command(
            [wsl, "--distribution", _WSL_DISTRIBUTION, "--exec", "ip", "-4", "-o", "addr", "show", "dev", "eth0"],
            timeout=_WSL_PROBE_TIMEOUT,
            output_limit=4096,
        )
    except (EngineRunError, EngineUnavailable, OSError) as exc:
        return {"ready": False, "reason": f"Could not read WSL's scanner address: {_brief_stderr(str(exc))}", "wsl_executable": wsl}
    source_match = re.search(r"\binet\s+([0-9.]+)/\d+\b", source.stdout)
    try:
        client_ip = str(ipaddress.IPv4Address(source_match.group(1))) if source.returncode == 0 and source_match else ""
    except ipaddress.AddressValueError:
        client_ip = ""
    if not client_ip or not ipaddress.ip_address(client_ip).is_private:
        return {
            "ready": False,
            "reason": "Could not determine a private WSL scanner address for the authenticated scope proxy allow-list.",
            "wsl_executable": wsl,
            "route_diagnostic": _brief_stderr(source.stderr or source.stdout),
        }

    return {
        "ready": True,
        "wsl_executable": wsl,
        "distribution": _WSL_DISTRIBUTION,
        "install_root": _WSL_INSTALL_ROOT,
        "nikto_script": _WSL_NIKTO_SCRIPT,
        "commit": commit,
        "host_gateway": gateway,
        "client_ip": client_ip,
    }


def run(ctx: Any) -> dict[str, Any]:
    options = getattr(ctx, "options", {}) or {}
    execution = "native"
    docker_mode = False
    wsl_runtime: dict[str, Any] | None = None
    docker: str | None = None
    try:
        executable = find_executable("nikto", "nikto.pl")
        launcher = [executable]
        if Path(executable).suffix.lower() == ".pl":
            launcher = [find_executable("perl"), executable]
    except EngineUnavailable:
        runtime_override = options.get("_external_nikto_wsl_runtime")
        wsl_runtime = runtime_override if isinstance(runtime_override, dict) and runtime_override.get("ready") else None
        if wsl_runtime is None:
            detected = wsl_nikto_runtime()
            wsl_runtime = detected if detected.get("ready") else None
        if wsl_runtime is not None:
            execution = "wsl"
            launcher = [
                str(wsl_runtime["wsl_executable"]),
                "--distribution",
                str(wsl_runtime["distribution"]),
                "--exec",
                "/usr/bin/timeout",
                "--signal=TERM",
                "--kill-after=5s",
            ]
            executable = str(wsl_runtime["nikto_script"])
        else:
            try:
                docker = find_executable("docker", "docker.exe")
            except EngineUnavailable as exc:
                reason = detected.get("reason", "WSL Nikto is unavailable.")
                raise EngineUnavailable(
                    f"Nikto is unavailable. {reason} Install pinned WSL Nikto with "
                    "scripts/setup-wsl-nikto.ps1, install native Nikto, or install the official Docker image."
                ) from exc
            image_check = run_command(
                [docker, "image", "inspect", _DOCKER_IMAGE, "--format", "{{.Id}}"],
                timeout=8,
                output_limit=4096,
            )
            if image_check.returncode != 0:
                raise EngineUnavailable(
                    f"Nikto is not installed; run scripts/setup-wsl-nikto.ps1 or pull {_DOCKER_IMAGE}."
                )
            docker_mode = True
            execution = "docker"
            launcher = [docker]
            executable = _DOCKER_IMAGE

    target = str(ctx.base_url)
    # Confirm the exact supplied origin before invoking a tool that resolves it
    # independently of SiteAudit's pinned HTTP client.
    if scoped_url(ctx, target) is None:
        raise EngineRunError("Nikto target failed the selected host-and-port scope check")

    engine_timeout = max(1, min(_MAX_WSL_COMMAND_TIMEOUT, int(options.get("external_engine_timeout", 300))))
    request_timeout = max(1, min(30, int(options.get("timeout", 10))))
    pause = max(0.5, min(10.0, float(options.get("delay", 0.5))))
    proxy_url = options.get("external_proxy_auth_url" if (docker_mode or execution == "wsl") else "external_proxy_url")
    if not isinstance(proxy_url, str) or not proxy_url:
        raise EngineRunError("Nikto requires the SiteAudit scope proxy")
    if (docker_mode or execution == "wsl") and not proxy_url.startswith("http://siteaudit:"):
        raise EngineRunError("Remote Nikto mode requires the authenticated SiteAudit scope proxy")

    with tempfile.TemporaryDirectory(prefix="siteaudit-nikto-") as directory:
        report_path = Path(directory) / "nikto.json"
        container_name = f"siteaudit-nikto-{uuid.uuid4().hex[:16]}" if docker_mode else None
        output_path = "/tmp/siteaudit/nikto.json" if docker_mode else str(report_path)
        if execution == "wsl":
            assert wsl_runtime is not None
            output_path = _wsl_path(str(wsl_runtime["wsl_executable"]), report_path)
        scan_arguments = [
            "-host", target,
            "-nointeractive",
            "-nocheck",
            "-nolookup",
            "-nocookies",
            "-useproxy", proxy_url,
            "-nosslkeepalive",
            "-Plugins", _SAFE_PLUGINS,
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
                "--name", container_name or "",
                "--add-host", "host.docker.internal:host-gateway",
                "--mount", f"type=bind,source={directory},target=/tmp/siteaudit",
                _DOCKER_IMAGE,
                *scan_arguments,
            ]
        elif execution == "wsl":
            command = [
                *launcher,
                f"{engine_timeout + 10}s",
                "/usr/bin/perl",
                executable,
                *scan_arguments,
            ]
        else:
            command = [*launcher, *scan_arguments]

        cleanup_error = None
        process = None
        try:
            process = run_command(
                command,
                timeout=engine_timeout + (25 if execution == "wsl" else min(30, request_timeout)),
                cwd=directory if execution != "wsl" else None,
                monitored_paths=[report_path],
            )
        finally:
            if container_name and docker:
                cleanup_error = _cleanup_docker_container(docker, container_name, directory)
        if process is None:
            raise EngineRunError("Nikto process did not return a result")
        if not report_path.is_file():
            detail = _brief_stderr(process.stderr)
            raise EngineRunError(f"Nikto did not produce its JSON report{': ' + detail if detail else ''}")
        if report_path.stat().st_size > _MAX_REPORT_BYTES:
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
        "plugins": _SAFE_PLUGINS,
        "max_scan_time_seconds": engine_timeout,
        "command_timeout_seconds": engine_timeout + (10 if execution == "wsl" else 0),
        "execution": execution,
        "docker_image": _DOCKER_IMAGE if docker_mode else None,
        "wsl_distribution": wsl_runtime.get("distribution") if wsl_runtime else None,
        "wsl_commit": wsl_runtime.get("commit") if wsl_runtime else None,
        "container_cleanup": "failed" if cleanup_error else ("complete" if docker_mode else None),
        "pause_seconds": pause,
        "scope_note": (
            "The authenticated scope proxy restricts HTTP requests and HTTPS tunnels to the selected host and port "
            "and pins the target IP. HTTPS requests inside CONNECT tunnels remain encrypted and are not inspected."
        ),
    }
    if process.returncode != 0:
        detail = _brief_stderr(process.stderr)
        if detail:
            result["error"] = detail
    if cleanup_error:
        result["error"] = (result.get("error", "") + f" Docker cleanup failed: {cleanup_error}").strip()[:800]
    return result


def _wsl_path(wsl: str, windows_path: Path) -> str:
    result = run_command(
        [wsl, "--distribution", _WSL_DISTRIBUTION, "--exec", "wslpath", "-a", str(windows_path)],
        timeout=_WSL_PROBE_TIMEOUT,
        output_limit=4096,
    )
    if result.returncode != 0:
        raise EngineRunError(f"Could not convert the Nikto report path with wslpath: {_brief_stderr(result.stderr)}")
    converted = result.stdout.strip()
    if not converted.startswith("/") or "\x00" in converted or "\n" in converted:
        raise EngineRunError("wslpath returned an invalid Nikto report path")
    return converted


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
