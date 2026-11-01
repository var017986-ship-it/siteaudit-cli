"""Run the upstream ZAP Automation Framework through SiteAudit's scope proxy."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .external_support import (
    EngineRunError,
    EngineUnavailable,
    add_engine_finding,
    find_executable,
    run_command,
    scoped_url,
)


_DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
_WSL_DISTRIBUTION = "Debian"
_WSL_INSTALL_ROOT = "/opt/siteaudit/zap-2.17.0"
_WSL_ZAP_SCRIPT = f"{_WSL_INSTALL_ROOT}/zap.sh"
_WSL_VERSION = "2.17.0"
_WSL_SHA256 = "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"
_MAX_TIMEOUT_SECONDS = 900
_MAX_REPORT_BYTES = 16_000_000
_PLAN_FILENAME = "siteaudit-zap-plan.yaml"
_REPORT_FILENAME = "zap-report.json"


def wsl_zap_runtime() -> dict[str, Any]:
    """Check pinned local WSL prerequisites without contacting a scan target."""
    try:
        return _probe_wsl_zap_runtime()
    except (EngineRunError, EngineUnavailable, OSError, ValueError) as exc:
        return {
            "ready": False,
            "reason": "The WSL ZAP readiness probe could not finish.",
            "diagnostic": _brief(exc),
        }


def _probe_wsl_zap_runtime() -> dict[str, Any]:
    if os.name != "nt":
        return {"ready": False, "reason": "The managed WSL ZAP runner is Windows-only."}
    try:
        wsl = find_executable("wsl.exe", "wsl")
    except EngineUnavailable:
        return {"ready": False, "reason": "wsl.exe was not found on PATH."}

    distro = _wsl_command(wsl, ["--list", "--verbose"], timeout=8)
    if distro.returncode != 0:
        return {"ready": False, "reason": "Could not list WSL distributions.", "wsl_executable": wsl}
    distro_text = _clean_wsl_output(distro.stdout)
    distro_match = re.search(r"(?m)^\s*\*?\s*Debian\s+\S+\s+2\s*$", distro_text)
    if not distro_match:
        return {
            "ready": False,
            "reason": "WSL Debian was not found as a WSL 2 distribution.",
            "wsl_executable": wsl,
            "diagnostic": "Install Debian under WSL 2, then run scripts/setup-wsl-zap.ps1.",
        }

    check_script = (
        "set -eu; "
        f"test -x '{_WSL_ZAP_SCRIPT}'; "
        "test -x /usr/bin/timeout; test -x /usr/bin/wslpath; "
        f"test \"$(cat '{_WSL_INSTALL_ROOT}/.siteaudit-sha256' 2>/dev/null)\" = '{_WSL_SHA256}'; "
        f"'{_WSL_ZAP_SCRIPT}' -version; java --version 2>&1"
    )
    local = _wsl_command(wsl, ["--distribution", _WSL_DISTRIBUTION, "--exec", "bash", "-lc", check_script], timeout=45)
    if local.returncode != 0:
        return {
            "ready": False,
            "reason": "Pinned ZAP, its SHA-256 marker, Java 17+, or WSL timeout helpers are missing.",
            "wsl_executable": wsl,
            "distribution": _WSL_DISTRIBUTION,
            "diagnostic": _brief(local.stderr or local.stdout),
        }
    version_match = re.search(r"(?m)^\s*(?:ZAP\s+)?(\d+\.\d+\.\d+)\s*$", local.stdout)
    java_match = re.search(r"(?im)^(?:openjdk|java)\s+(?:version\s+)?[\"']?(\d+)", local.stdout)
    # Java sometimes writes its version to stderr, which _wsl_command keeps
    # separate; query it independently so a successful version cannot hide it.
    java = _wsl_command(wsl, ["--distribution", _WSL_DISTRIBUTION, "--exec", "java", "--version"], timeout=8)
    java_match = re.search(r"(?im)^(?:openjdk|java)\s+(?:version\s+)?[\"']?(\d+)", java.stdout + "\n" + java.stderr)
    if version_match is None or version_match.group(1) != _WSL_VERSION:
        return {
            "ready": False,
            "reason": f"The WSL ZAP installation is not pinned to version {_WSL_VERSION}.",
            "wsl_executable": wsl,
            "found_version": version_match.group(1) if version_match else None,
        }
    if java.returncode != 0 or java_match is None or int(java_match.group(1)) < 17:
        return {
            "ready": False,
            "reason": "ZAP requires Java 17 or newer in WSL Debian.",
            "wsl_executable": wsl,
            "diagnostic": _brief(java.stderr or java.stdout),
        }

    addons = _wsl_command(
        wsl,
        [
            "--distribution", _WSL_DISTRIBUTION, "--exec", "bash", "-lc",
            f"find '{_WSL_INSTALL_ROOT}/plugin' -maxdepth 1 -type f -name '*.zap' -printf '%f\\n'",
        ],
        timeout=8,
    )
    if addons.returncode != 0:
        return {"ready": False, "reason": "Could not inspect the pinned ZAP add-ons.", "wsl_executable": wsl}
    addon_names = set(addons.stdout.splitlines())
    required_prefixes = ("automation-", "spider-", "pscanrules-", "reports-")
    missing = [prefix for prefix in required_prefixes if not any(name.startswith(prefix) for name in addon_names)]
    if missing:
        return {
            "ready": False,
            "reason": "The pinned ZAP distribution is missing required passive-scan Automation Framework add-ons.",
            "wsl_executable": wsl,
            "missing_addons": missing,
        }

    route = _wsl_command(wsl, ["--distribution", _WSL_DISTRIBUTION, "--exec", "ip", "-4", "route", "show", "default"], timeout=8)
    match = re.search(r"(?:^|\s)via\s+([0-9.]+)(?:\s|$)", route.stdout)
    try:
        gateway = str(ipaddress.IPv4Address(match.group(1))) if route.returncode == 0 and match else ""
    except ipaddress.AddressValueError:
        gateway = ""
    if not gateway:
        return {
            "ready": False,
            "reason": "Could not determine the Windows host gateway from the WSL Debian default route.",
            "wsl_executable": wsl,
            "route_diagnostic": _brief(route.stderr or route.stdout),
        }
    source = _wsl_command(
        wsl,
        ["--distribution", _WSL_DISTRIBUTION, "--exec", "ip", "-4", "-o", "addr", "show", "dev", "eth0"],
        timeout=8,
    )
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
            "route_diagnostic": _brief(source.stderr or source.stdout),
        }
    return {
        "ready": True,
        "wsl_executable": wsl,
        "distribution": _WSL_DISTRIBUTION,
        "install_root": _WSL_INSTALL_ROOT,
        "zap_script": _WSL_ZAP_SCRIPT,
        "version": _WSL_VERSION,
        "sha256": _WSL_SHA256,
        "host_gateway": gateway,
        "client_ip": client_ip,
    }


def run(ctx: Any) -> dict[str, Any]:
    options = getattr(ctx, "options", {}) or {}
    target = str(ctx.base_url)
    if scoped_url(ctx, target) is None:
        raise EngineRunError("ZAP target failed the selected host-and-port scope check")

    engine_timeout = max(60, min(_MAX_TIMEOUT_SECONDS, int(options.get("external_engine_timeout", 300))))
    max_pages = max(1, min(int(options.get("max_pages", 50)), 500))
    active = options.get("zap_active") is True
    mode = "active" if active else "passive"
    runtime = options.get("_external_zap_wsl_runtime")
    if not isinstance(runtime, dict) or not runtime.get("ready"):
        detected = wsl_zap_runtime() if os.name == "nt" else {"ready": False}
        runtime = detected if detected.get("ready") else None
    if runtime is not None:
        return _run_wsl(ctx, target, options, runtime, engine_timeout, max_pages, active)
    return _run_docker(ctx, target, options, engine_timeout, max_pages, active)


def _run_wsl(
    ctx: Any,
    target: str,
    options: dict[str, Any],
    runtime: dict[str, Any],
    engine_timeout: int,
    max_pages: int,
    active: bool,
) -> dict[str, Any]:
    proxy = _proxy_credentials(options, expected_host=str(runtime["host_gateway"]))
    wsl = str(runtime["wsl_executable"])
    plan_timeout = max(1, engine_timeout - 30)
    with tempfile.TemporaryDirectory(prefix="siteaudit-zap-") as directory:
        temp_dir = Path(directory)
        plan_path = temp_dir / _PLAN_FILENAME
        report_path = temp_dir / _REPORT_FILENAME
        wsl_temp = _wsl_path(wsl, temp_dir)
        wsl_plan = f"{wsl_temp}/{_PLAN_FILENAME}"
        wsl_report_dir = wsl_temp
        plan = _automation_plan(
            ctx,
            target,
            report_dir=wsl_report_dir,
            proxy_host=proxy["host"],
            proxy_port=proxy["port"],
            active=active,
            max_pages=max_pages,
            engine_timeout=plan_timeout,
            delay=float(options.get("delay", 0.5)),
        )
        plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        secret_env = (
            _wsl_secret_environment(proxy["username"], proxy["password"])
            if proxy["username"] and proxy["password"]
            else os.environ.copy()
        )
        home = f"/tmp/siteaudit-zap-run-{uuid.uuid4().hex}"
        if not re.fullmatch(r"/tmp/siteaudit-zap-run-[a-f0-9]{32}", home):
            raise EngineRunError("Generated an invalid isolated ZAP home path")
        create_home = _wsl_command(
            wsl,
            ["--distribution", _WSL_DISTRIBUTION, "--exec", "mkdir", "--mode=700", home],
            timeout=8,
        )
        if create_home.returncode != 0:
            raise EngineRunError("Could not create an isolated temporary ZAP home in WSL")
        scan_process = None
        cleanup_error = None
        try:
            base_command = [
                wsl, "--distribution", _WSL_DISTRIBUTION, "--exec", "/usr/bin/timeout",
                "--signal=TERM", "--kill-after=5s",
            ]
            preflight = run_command(
                [
                    *base_command, "20s", str(runtime["zap_script"]), "-cmd", "-silent",
                    "-dir", home, "-installdir", str(runtime["install_root"]), "-autocheck", wsl_plan,
                ],
                timeout=28,
                output_limit=1_000_000,
                env=secret_env,
            )
            if preflight.returncode not in {0, 2}:
                raise EngineRunError(
                    "ZAP rejected the local Automation Framework plan before scanning: "
                    + _brief(preflight.stderr or preflight.stdout)
                )

            scan_process = run_command(
                [
                    *base_command, f"{plan_timeout}s", str(runtime["zap_script"]), "-cmd", "-silent",
                    "-dir", home, "-installdir", str(runtime["install_root"]), "-autorun", wsl_plan,
                ],
                timeout=plan_timeout + 20,
                output_limit=_MAX_REPORT_BYTES,
                monitored_paths=[report_path],
                env=secret_env,
            )
        finally:
            remove_home = _wsl_command(
                wsl,
                ["--distribution", _WSL_DISTRIBUTION, "--exec", "rm", "-rf", "--", home],
                timeout=8,
            )
            if remove_home.returncode != 0:
                cleanup_error = _brief(remove_home.stderr or remove_home.stdout) or "WSL ZAP home cleanup failed"

        if scan_process is None:
            raise EngineRunError("ZAP process did not return a result")
        report = _read_report(
            report_path,
            diagnostic=f"exit={scan_process.returncode}; {scan_process.stderr or scan_process.stdout}",
        )
        findings = _collect_findings(ctx, target, report)
        timed_out = scan_process.returncode in {124, 137}
        status = "partial" if timed_out or cleanup_error or scan_process.returncode != 0 else "completed"
        result = _result(
            ctx=ctx,
            findings=findings,
            process=scan_process,
            mode="active" if active else "passive",
            max_pages=max_pages,
            engine_timeout=engine_timeout,
            execution="wsl",
        )
        result.update({
            "status": status,
            "wsl_distribution": runtime.get("distribution"),
            "wsl_zap_version": runtime.get("version"),
            "wsl_zap_sha256": runtime.get("sha256"),
            "wsl_host_gateway": runtime.get("host_gateway"),
            "isolated_home_cleanup": "failed" if cleanup_error else "complete",
        })
        if cleanup_error:
            result["error"] = f"{result.get('error', '')} WSL cleanup failed: {cleanup_error}".strip()[:800]
        return result


def _run_docker(
    ctx: Any,
    target: str,
    options: dict[str, Any],
    engine_timeout: int,
    max_pages: int,
    active: bool,
) -> dict[str, Any]:
    try:
        docker = find_executable("docker", "docker.exe")
    except EngineUnavailable as exc:
        raise EngineUnavailable(
            "Pinned WSL ZAP is unavailable and the Docker CLI was not found. "
            "Run scripts/setup-wsl-zap.ps1 or install Docker Desktop and the official ZAP image."
        ) from exc
    image = run_command([docker, "image", "inspect", _DOCKER_IMAGE, "--format", "{{.Id}}"], timeout=8, output_limit=4096)
    if image.returncode != 0:
        raise EngineUnavailable(f"The official ZAP image is not installed locally; run docker pull {_DOCKER_IMAGE}.")
    proxy = _proxy_credentials(options, expected_host="host.docker.internal")
    with tempfile.TemporaryDirectory(prefix="siteaudit-zap-") as directory:
        temp_dir = Path(directory)
        plan_path = temp_dir / _PLAN_FILENAME
        report_path = temp_dir / _REPORT_FILENAME
        container_name = f"siteaudit-zap-{uuid.uuid4().hex[:16]}"
        plan = _automation_plan(
            ctx,
            target,
            report_dir="/zap/wrk",
            proxy_host=proxy["host"],
            proxy_port=proxy["port"],
            active=active,
            max_pages=max_pages,
            engine_timeout=max(1, engine_timeout - 30),
            delay=float(options.get("delay", 0.5)),
            proxy_username=proxy["username"],
            proxy_password=proxy["password"],
        )
        plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        secret_env = os.environ.copy()
        secret_env["SITEAUDIT_ZAP_PROXY_USERNAME"] = proxy["username"]
        secret_env["SITEAUDIT_ZAP_PROXY_PASSWORD"] = proxy["password"]
        check_name = f"siteaudit-zap-check-{uuid.uuid4().hex[:16]}"
        check_process = None
        check_cleanup_error = None
        try:
            check_process = run_command(
                [
                    docker, "run", "--pull=never", "--name", check_name,
                    "--add-host", "host.docker.internal:host-gateway",
                    "--mount", f"type=bind,source={directory},target=/zap/wrk",
                    "--env", "SITEAUDIT_ZAP_PROXY_USERNAME",
                    "--env", "SITEAUDIT_ZAP_PROXY_PASSWORD",
                    _DOCKER_IMAGE,
                    "zap.sh", "-cmd", "-silent", "-dir", "/tmp/siteaudit-zap-check-home",
                    "-installdir", "/zap", "-autocheck", f"/zap/wrk/{_PLAN_FILENAME}",
                ],
                timeout=30,
                output_limit=1_000_000,
                env=secret_env,
            )
        finally:
            check_cleanup_error = _cleanup_docker(docker, check_name)
        if check_process is None or check_process.returncode != 0 or check_cleanup_error:
            detail = _brief((check_process.stderr or check_process.stdout) if check_process else "")
            raise EngineRunError(
                "ZAP rejected the local Docker Automation Framework plan before scanning"
                + (f": {detail}" if detail else "")
                + (f"; preflight cleanup failed: {check_cleanup_error}" if check_cleanup_error else "")
            )
        command = [
            docker, "run", "--pull=never", "--name", container_name,
            "--add-host", "host.docker.internal:host-gateway",
            "--mount", f"type=bind,source={directory},target=/zap/wrk",
            "--env", "SITEAUDIT_ZAP_PROXY_USERNAME",
            "--env", "SITEAUDIT_ZAP_PROXY_PASSWORD",
            _DOCKER_IMAGE,
            "zap.sh", "-cmd", "-silent", "-dir", "/tmp/siteaudit-zap-home",
            "-installdir", "/zap", "-autorun", f"/zap/wrk/{_PLAN_FILENAME}",
        ]
        process = None
        cleanup_error = None
        try:
            process = run_command(
                command,
                timeout=max(30, engine_timeout - 5),
                output_limit=_MAX_REPORT_BYTES,
                monitored_paths=[report_path],
                env=secret_env,
            )
        finally:
            cleanup_error = _cleanup_docker(docker, container_name)
        if process is None:
            raise EngineRunError("ZAP Docker process did not return a result")
        report = _read_report(
            report_path,
            diagnostic=f"exit={process.returncode}; {process.stderr or process.stdout}",
        )
        findings = _collect_findings(ctx, target, report)
        status = "completed" if process.returncode == 0 and not cleanup_error else "partial"
        result = _result(
            ctx=ctx,
            findings=findings,
            process=process,
            mode="active" if active else "passive",
            max_pages=max_pages,
            engine_timeout=engine_timeout,
            execution="docker",
        )
        result.update({"status": status, "docker_image": _DOCKER_IMAGE, "container_cleanup": "failed" if cleanup_error else "complete"})
        if cleanup_error:
            result["error"] = f"{result.get('error', '')} Docker cleanup failed: {cleanup_error}".strip()[:800]
        return result


def _automation_plan(
    ctx: Any,
    target: str,
    *,
    report_dir: str,
    proxy_host: str,
    proxy_port: int,
    active: bool,
    max_pages: int,
    engine_timeout: int,
    delay: float,
    proxy_username: str = "",
    proxy_password: str = "",
) -> dict[str, Any]:
    parts = urlsplit(target)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise EngineRunError("ZAP target must be an absolute HTTP(S) URL")
    default_port = 443 if scheme == "https" else 80
    port = parts.port if parts.port is not None else default_port
    host = parts.hostname.lower()
    origin_host = f"[{host}]" if ":" in host else host
    origin = f"{scheme}://{origin_host}"
    if port != default_port:
        origin += f":{port}"
    origin += "/"
    escaped_authority_host = re.escape(origin_host)
    port_pattern = f"(?::{port})?" if port == default_port else f":{port}"
    origin_patterns = [f"{re.escape(scheme)}://{escaped_authority_host}{port_pattern}"]
    if scheme == "http" and port == 80:
        origin_patterns.append(f"https://{escaped_authority_host}(?::443)?")
    origin_pattern = f"^(?:{'|'.join(origin_patterns)})/.*$"
    spider_authority = origin_host if port == default_port else f"{origin_host}:{port}"
    spider_url = urlunsplit((scheme, spider_authority, parts.path or "/", parts.query, ""))
    spider_minutes = max(1, min(3, engine_timeout // 60))
    requested_depth = min(8, max(0, int(getattr(ctx, "options", {}).get("max_depth", 5))))
    # ZAP interprets maxDepth=0 as unlimited, so a zero-depth SiteAudit run
    # omits the spider job and keeps the root as the only possible target.
    max_depth = max(1, requested_depth)
    max_children = max(1, min(10, max_pages))
    delay_ms = max(500, min(10_000, int(max(0.5, float(delay)) * 1000)))
    environment = {
        "contexts": [{
            "name": "siteaudit-selected-origin",
            "urls": [origin],
            "includePaths": [origin_pattern],
        }],
        "parameters": {
            "failOnError": True,
            "failOnWarning": False,
            "continueOnFailure": False,
            "progressToStdout": True,
        },
        "proxy": {"hostname": proxy_host, "port": proxy_port},
    }
    if proxy_username and proxy_password:
        environment["proxy"].update({
            "realm": "SiteAudit",
            "username": proxy_username,
            "password": proxy_password,
        })
    jobs: list[dict[str, Any]] = []
    if requested_depth > 0:
        jobs.append({
            "type": "spider",
            "parameters": {
                "context": "siteaudit-selected-origin",
                "url": spider_url,
                "maxDuration": spider_minutes,
                "maxDepth": max_depth,
                "maxChildren": max_children,
                "maxParseSizeBytes": 2_000_000,
                "postForm": False,
                "processForm": False,
                "threadCount": 1,
            },
        })
    else:
        jobs.append({
            "type": "requestor",
            "parameters": {},
            "requests": [{"url": spider_url, "method": "GET", "name": "SiteAudit root-only request"}],
        })
    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": max(1, min(5, engine_timeout // 60))}})
    if active:
        jobs.append({
            "type": "activeScan",
            "parameters": {
                "context": "siteaudit-selected-origin",
                "threadPerHost": 1,
                "delayInMs": delay_ms,
                "maxScanDurationInMins": max(1, min(10, engine_timeout // 60)),
                "maxRuleDurationInMins": 1,
            },
        })
        jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": max(1, min(5, engine_timeout // 60))}})
    jobs.append({
        "type": "report",
        "parameters": {
            "template": "traditional-json",
            "reportDir": report_dir,
            "reportFile": _REPORT_FILENAME.removesuffix(".json"),
            "reportTitle": "SiteAudit ZAP findings",
            "reportDescription": "ZAP findings limited to the SiteAudit selected origin.",
            "displayReport": False,
        },
    })
    return {"env": environment, "jobs": jobs}


def _proxy_credentials(options: dict[str, Any], *, expected_host: str) -> dict[str, Any]:
    value = options.get("external_proxy_auth_url")
    if not isinstance(value, str):
        raise EngineRunError("ZAP requires the SiteAudit scope proxy")
    parts = urlsplit(value)
    try:
        port = parts.port
        username = parts.username
        password = parts.password
    except ValueError as exc:
        raise EngineRunError("The authenticated SiteAudit scope proxy URL is invalid") from exc
    if (
        parts.scheme != "http"
        or (parts.hostname or "").lower() != expected_host.lower()
        or not port
        or bool(username) != bool(password)
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise EngineRunError("ZAP scope proxy is not bound to the expected gateway")
    return {"host": expected_host, "port": port, "username": username or "", "password": password or ""}


def _wsl_secret_environment(username: str, password: str) -> dict[str, str]:
    env = os.environ.copy()
    env["SITEAUDIT_ZAP_PROXY_USERNAME"] = username
    env["SITEAUDIT_ZAP_PROXY_PASSWORD"] = password
    entries = [item for item in env.get("WSLENV", "").split(":" ) if item]
    for variable in ("SITEAUDIT_ZAP_PROXY_USERNAME", "SITEAUDIT_ZAP_PROXY_PASSWORD"):
        entries = [item for item in entries if item.split("/", 1)[0] != variable]
        entries.append(f"{variable}/u")
    env["WSLENV"] = ":".join(entries)
    return env


def _wsl_path(wsl: str, path: Path) -> str:
    result = _wsl_command(
        wsl,
        ["--distribution", _WSL_DISTRIBUTION, "--exec", "wslpath", "-a", str(path)],
        timeout=8,
    )
    converted = _clean_wsl_output(result.stdout).strip()
    if result.returncode != 0 or not converted.startswith("/") or "\x00" in converted or "\n" in converted:
        raise EngineRunError("Could not safely convert a temporary ZAP path with wslpath")
    return converted.rstrip("/")


def _wsl_command(wsl: str, args: list[str], *, timeout: float) -> Any:
    return run_command([wsl, *args], timeout=timeout, output_limit=32_000)


def _clean_wsl_output(value: str) -> str:
    return value.replace("\x00", "").replace("\r", "")


def _read_report(path: Path, *, diagnostic: str = "") -> dict[str, Any]:
    if not path.is_file():
        detail = _brief(diagnostic)
        raise EngineRunError(
            "ZAP did not produce its traditional JSON report"
            + (f": {detail}" if detail else "")
        )
    if path.stat().st_size > _MAX_REPORT_BYTES:
        raise EngineRunError("ZAP JSON report exceeded the 16 MB limit")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngineRunError(f"Could not parse the ZAP JSON report: {exc}") from exc
    if not isinstance(report, dict):
        raise EngineRunError("ZAP JSON report has an unexpected top-level value")
    return report


def _collect_findings(ctx: Any, target: str, report: dict[str, Any]) -> int:
    sites = report.get("site", [])
    if not isinstance(sites, list) or len(sites) > 100:
        raise EngineRunError("ZAP report contained an invalid or excessive site list")
    findings = 0
    seen: set[tuple[str, str, str]] = set()
    for site_index, site in enumerate(sites):
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        for alert_index, alert in enumerate(alerts[:5000]):
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances", [])
            urls: list[str] = []
            if isinstance(instances, list):
                urls.extend(item.get("uri") for item in instances[:100] if isinstance(item, dict) and isinstance(item.get("uri"), str))
            if not urls and isinstance(site.get("@name"), str):
                urls.append(site["@name"])
            scoped = next((candidate for candidate in urls if scoped_url(ctx, candidate) is not None), None)
            if scoped is None:
                continue
            plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or f"{site_index}-{alert_index}")
            title = str(alert.get("alert") or alert.get("name") or f"ZAP rule {plugin_id}")
            risk_code = str(alert.get("riskcode", "0"))
            severity = {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(risk_code, "info")
            confidence = _confidence(alert.get("confidence"))
            key = (plugin_id, title, scoped)
            if key in seen:
                continue
            seen.add(key)
            risk_description = str(alert.get("riskdesc") or severity.title())
            # ZAP's request/response body fields are deliberately not copied into
            # SiteAudit's report. Findings carry the matched rule and URL only.
            evidence = f"ZAP rule {plugin_id} reported {title} ({risk_description})."
            references = alert.get("reference") or []
            if isinstance(references, str):
                references = re.findall(r"https://[^\s<>\"']+", references)[:5]
            if not isinstance(references, list):
                references = []
            if add_engine_finding(
                ctx,
                engine="zap",
                issue_id=plugin_id,
                title=f"ZAP: {title}",
                severity=severity,
                confidence=confidence,
                url=scoped,
                evidence=evidence,
                recommendation=alert.get("solution"),
                references=references,
            ):
                findings += 1
    return findings


def _result(
    *,
    ctx: Any,
    findings: int,
    process: Any,
    mode: str,
    max_pages: int,
    engine_timeout: int,
    execution: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "completed" if process.returncode == 0 else "partial",
        "return_code": process.returncode,
        "duration_seconds": process.duration_seconds,
        "findings_parsed": findings,
        "mode": mode,
        "execution": execution,
        "max_pages_per_parent": max(1, min(10, max_pages)),
        "max_depth_requested": min(8, max(0, int(getattr(ctx, "options", {}).get("max_depth", 5)))),
        "max_depth_effective": min(8, max(0, int(getattr(ctx, "options", {}).get("max_depth", 5)))),
        "global_page_cap_enforced": False,
        "max_scan_time_seconds": engine_timeout,
        "scanner_threads_per_host": 1,
        "request_response_content_in_report": False,
        "scope_note": (
            "The temporary scope proxy limits HTTP requests and HTTPS CONNECT tunnels to the selected host and port and pins its IP. "
            "WSL ZAP uses an exact WSL source-IP allow-list; Docker ZAP uses per-run proxy authentication and the inspected bridge subnet. "
            "HTTPS contents inside a CONNECT tunnel remain encrypted; tunnel counting does not equal individual encrypted requests."
        ),
        "delay_note": (
            "--delay is enforced per plain HTTP request and by ZAP's active scan delay. "
            "For HTTPS the scope proxy can delay CONNECT tunnels, not individual encrypted requests; the spider is limited to one thread."
        ),
    }
    if process.returncode != 0:
        result["error"] = _brief(process.stderr or process.stdout)
    return result


def _cleanup_docker(docker: str, name: str) -> str | None:
    errors: list[str] = []
    for action in ("stop", "rm"):
        command = [docker, action, "--time", "2", name] if action == "stop" else [docker, action, "--force", name]
        try:
            result = run_command(command, timeout=8, output_limit=4096)
            detail = result.stderr or result.stdout
            if result.returncode != 0 and "no such container" not in detail.lower():
                errors.append(_brief(detail) or f"docker {action} failed")
        except (EngineRunError, EngineUnavailable, OSError) as exc:
            errors.append(str(exc))
    return "; ".join(errors)[:500] if errors else None


def _confidence(value: Any) -> str:
    normalized = str(value or "").lower()
    if normalized.startswith("high"):
        return "high"
    if normalized.startswith("low") or normalized.startswith("false"):
        return "low"
    return "medium"


def _brief(value: Any) -> str:
    return " ".join(str(value).split())[-500:]
