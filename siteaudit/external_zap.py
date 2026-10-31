"""Optional OWASP ZAP Docker adapter (passive baseline unless active is opted in)."""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .external_support import (
    EngineRunError,
    EngineUnavailable,
    add_engine_finding,
    find_executable,
    run_command,
    scoped_url,
)


_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
_MAX_REPORT_BYTES = 16_000_000
_MAX_SITES = 64
_MAX_ALERTS_PER_SITE = 1000
_MAX_INSTANCES_PER_ALERT = 100


def run(ctx: Any) -> dict[str, Any]:
    docker = find_executable("docker", "docker.exe")
    target = str(ctx.base_url)
    if scoped_url(ctx, target) is None:
        raise EngineRunError("ZAP target failed the selected host-and-port scope check")

    options = getattr(ctx, "options", {}) or {}
    active = options.get("zap_active") is True
    mode = "full-active" if active else "baseline-passive"
    engine_timeout = max(1, int(options.get("external_engine_timeout", 300)))
    # Both upstream scripts express spider/passive waits in whole minutes. The
    # process timeout remains the hard wall-clock limit; active mode also gets
    # a ZAP-side maximum scan duration below.
    minimum_timeout = 180 if active else 120
    if engine_timeout < minimum_timeout:
        label = "ZAP full scan" if active else "ZAP baseline"
        raise EngineRunError(f"{label} requires --engine-timeout of at least {minimum_timeout} seconds")
    # Reserve most of the active-mode budget for the active scan itself; the
    # outer process timeout remains the absolute wall-clock ceiling.
    passive_wait_minutes = 1 if active else max(1, engine_timeout // 60 - 1)
    report_minutes = 1

    with tempfile.TemporaryDirectory(prefix="siteaudit-zap-") as directory:
        report_path = Path(directory) / "zap-report.json"
        mount = f"type=bind,source={directory},target=/zap/wrk"
        container_name = f"siteaudit-zap-{uuid.uuid4().hex[:16]}"
        scan_script = "zap-full-scan.py" if active else "zap-baseline.py"
        command = [
            docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "--pull=never",
            "--mount",
            mount,
            _IMAGE,
            scan_script,
            "-t",
            target,
            "-m",
            str(report_minutes),
            "-T",
            str(passive_wait_minutes),
            "-J",
            "/zap/wrk/zap-report.json",
            "-I",
            "-s",
        ]
        if active:
            # ZAP's documented command-line configuration keys are dot paths
            # from config.xml. One thread per host limits target load; the
            # two duration values bound active scans and individual rules.
            active_minutes = max(1, engine_timeout // 60 - 2)
            zap_options = (
                "-config scanner.threadPerHost=1 "
                f"-config scanner.maxScanDurationInMins={active_minutes} "
                "-config scanner.maxRuleDurationInMins=1"
            )
            command.extend(["-z", zap_options])

        process = None
        process_error = None
        cleanup_error = None
        try:
            process = run_command(
                command,
                timeout=engine_timeout,
                cwd=directory,
                monitored_paths=[report_path],
            )
        except (EngineRunError, EngineUnavailable) as exc:
            # In particular, the shared runner kills the Docker CLI on timeout.
            # Stop the uniquely named container below before the temp mount is
            # removed, so its scan cannot continue as an orphan.
            process_error = str(exc)
        finally:
            cleanup_error = _cleanup_container(docker, container_name, directory)

        report = None
        report_error = None
        if report_path.is_file():
            if report_path.stat().st_size > _MAX_REPORT_BYTES:
                report_error = "ZAP JSON report exceeded the 16 MB limit"
            else:
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    report_error = f"Could not parse ZAP JSON report: {exc}"
                if report_error is None and not isinstance(report, dict):
                    report = None
                    report_error = "ZAP JSON report must contain an object"

        if report is None:
            if process_error:
                detail = process_error
            elif report_error:
                detail = report_error
            else:
                assert process is not None
                detail = _brief_stderr(process.stderr or process.stdout)
                detail = "ZAP did not produce a JSON report" + (f": {detail}" if detail else "")
            if cleanup_error:
                detail += f"; container cleanup failed: {cleanup_error}"
            else:
                detail += f"; confirm the official image is pulled ({_IMAGE})"
            return {
                "status": "partial" if process_error else "error",
                "scan_mode": mode,
                "spider_time_minutes": report_minutes,
                "max_scan_time_minutes": active_minutes if active else None,
                "max_passive_wait_minutes": passive_wait_minutes,
                "container_cleanup": "failed" if cleanup_error else "complete",
                "error": detail[:800],
            }

    sites = report.get("site", []) if isinstance(report, dict) else []
    if not isinstance(sites, list) or len(sites) > _MAX_SITES:
        raise EngineRunError("ZAP JSON report has an invalid or excessive site list")

    parsed = 0
    alerts_seen = 0
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        alerts_seen += min(len(alerts), _MAX_ALERTS_PER_SITE)
        for alert in alerts[:_MAX_ALERTS_PER_SITE]:
            if not isinstance(alert, dict):
                continue
            alert_id = alert.get("pluginid") or alert.get("alertRef") or alert.get("alert") or "alert"
            title = alert.get("alert") or alert.get("name") or ("ZAP full-scan alert" if active else "ZAP baseline alert")
            severity = _risk_severity(alert.get("riskcode"))
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                instances = []
            locations = [item.get("uri") for item in instances[:_MAX_INSTANCES_PER_ALERT] if isinstance(item, dict)]
            if not locations:
                locations = [target]

            for location in locations:
                if scoped_url(ctx, location) is None:
                    continue
                if add_engine_finding(
                    ctx,
                    engine="zap",
                    issue_id=alert_id,
                    title=f"ZAP: {title}",
                    severity=severity,
                    confidence=_confidence(alert.get("confidence")),
                    url=location,
                    evidence=f"ZAP {mode} rule {alert_id} reported {severity} risk.",
                    recommendation=alert.get("solution"),
                ):
                    parsed += 1

    result: dict[str, Any] = {
        "duration_seconds": process.duration_seconds if process else None,
        "return_code": process.returncode if process else None,
        "scan_mode": mode,
        "spider_time_minutes": report_minutes,
        "max_scan_time_minutes": active_minutes if active else None,
        "max_passive_wait_minutes": passive_wait_minutes,
        "container_cleanup": "failed" if cleanup_error else "complete",
        "alerts_parsed": alerts_seen,
        "findings_parsed": parsed,
    }
    # Baseline uses 0 for success, 1 for FAIL alerts, 2 for WARN alerts, and 3
    # for an execution error. WARN/FAIL findings still mean the scan completed.
    result["status"] = (
        "partial"
        if process_error or cleanup_error or process is None or process.returncode not in {0, 1, 2}
        else "completed"
    )
    detail = process_error
    if process and process.returncode not in {0, 1, 2}:
        detail = _brief_stderr(process.stderr or process.stdout) or detail
    if cleanup_error:
        detail = f"{detail}; container cleanup failed: {cleanup_error}" if detail else f"Container cleanup failed: {cleanup_error}"
    if detail:
        result["error"] = detail[:800]
    return result


def _cleanup_container(docker: str, name: str, cwd: str) -> str | None:
    """Stop and remove this run's named container; ignore the normal absent case."""
    errors: list[str] = []
    try:
        stopped = run_command(
            [docker, "stop", "--time", "2", name], timeout=8, cwd=cwd, output_limit=4096
        )
        if stopped.returncode != 0 and "no such container" not in (stopped.stderr + stopped.stdout).lower():
            errors.append(_brief_stderr(stopped.stderr or stopped.stdout) or "docker stop failed")
    except (EngineRunError, EngineUnavailable) as exc:
        errors.append(str(exc))

    try:
        removed = run_command(
            [docker, "rm", "--force", name], timeout=8, cwd=cwd, output_limit=4096
        )
        if removed.returncode != 0 and "no such container" not in (removed.stderr + removed.stdout).lower():
            errors.append(_brief_stderr(removed.stderr or removed.stdout) or "docker rm failed")
    except (EngineRunError, EngineUnavailable) as exc:
        errors.append(str(exc))

    return "; ".join(errors)[:500] if errors else None


def _risk_severity(value: Any) -> str:
    return {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(value), "info")


def _confidence(value: Any) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"high", "medium", "low"}:
            return normalized
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value >= 3:
            return "high"
        if value >= 2:
            return "medium"
    return "low"


def _brief_stderr(value: str) -> str:
    return " ".join(value.split())[:500]
