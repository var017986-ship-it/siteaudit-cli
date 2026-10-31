"""Read-only readiness diagnostics for optional upstream scanner engines."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any, Mapping

from .external_support import EngineRunError, EngineUnavailable, find_executable, get_engine_home, run_command


_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
_NIKTO_IMAGE = "ghcr.io/sullo/nikto:2.6.1"
_TEMPLATE_EXTENSIONS = {".yaml", ".yml", ".json"}
_MAX_TEMPLATE_ENTRIES = 100_000
_PROBE_TIMEOUT_SECONDS = 5.0
_PROBE_OUTPUT_BYTES = 4096
_WAPITI_SAFE_MODULES = {"cookieflags", "csp", "http_header", "http_headers", "nikto", "sql", "crlf"}


def get_engine_status(options: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Return JSON-safe availability diagnostics without installing or scanning.

    ``options`` may contain ``nuclei_templates``; if omitted, the same default
    template directory as the Nuclei adapter is checked. Docker diagnostics use
    only ``docker info`` and ``docker image inspect``.
    """
    options = options if isinstance(options, Mapping) else {}
    configured_templates = options.get("nuclei_templates")
    return {
        "nuclei": _nuclei_status(configured_templates),
        "nikto": _nikto_status(),
        "wapiti": _wapiti_status(),
        "zap": _zap_status(),
        "w3af": _w3af_status(),
    }


def check_engine_status(options: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Alias for callers that prefer an explicit diagnostic verb."""
    return get_engine_status(options)


def _nuclei_status(configured_templates: Any) -> dict[str, Any]:
    try:
        executable = find_executable("nuclei", "nuclei.exe")
    except EngineUnavailable:
        return _status(
            "missing",
            "Nuclei executable was not found on PATH.",
            "Install Nuclei and reopen the terminal so its executable is on PATH.",
        )

    try:
        if configured_templates:
            templates = Path(configured_templates).expanduser()
        else:
            managed_templates = get_engine_home() / "nuclei-templates"
            templates = managed_templates if managed_templates.exists() else Path.home() / "nuclei-templates"
        templates = templates.resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return _status(
            "missing",
            f"The configured Nuclei template path is invalid: {_brief(exc)}",
            "Pass an existing local YAML/JSON template file or directory with --nuclei-templates.",
            executable=executable,
        )

    try:
        path_exists = templates.exists()
        is_file = templates.is_file() if path_exists else False
        is_directory = templates.is_dir() if path_exists else False
    except OSError as exc:
        return _status(
            "missing",
            f"The Nuclei template path could not be inspected: {_brief(exc)}",
            "Check permissions for the template path or choose another local template directory.",
            executable=executable,
            templates_path=str(templates),
        )
    if not path_exists or not (is_file or is_directory):
        return _status(
            "missing",
            "Nuclei templates were not found.",
            f"Install the Nuclei template pack or pass a local template path with --nuclei-templates. Expected path: {templates}",
            executable=executable,
            templates_path=str(templates),
        )
    if is_file:
        has_template = templates.suffix.lower() in _TEMPLATE_EXTENSIONS
    else:
        has_template = _contains_template_file(templates)
    if not has_template:
        return _status(
            "missing",
            "The Nuclei template path contains no YAML or JSON template files.",
            f"Provide a populated Nuclei template file or directory with --nuclei-templates. Checked: {templates}",
            executable=executable,
            templates_path=str(templates),
        )
    return _status(
        "ready",
        "Nuclei executable and a local template file/directory are available.",
        "No setup action needed; review templates before scanning.",
        executable=executable,
        templates_path=str(templates),
    )


def _contains_template_file(directory: Path) -> bool:
    try:
        for index, path in enumerate(directory.rglob("*")):
            if index >= _MAX_TEMPLATE_ENTRIES:
                # Fail closed when this bounded diagnostic cannot validate the
                # directory. The adapter applies separate scan-time limits.
                return False
            if path.is_symlink():
                continue
            if path.is_file() and path.suffix.lower() in _TEMPLATE_EXTENSIONS:
                return True
    except OSError:
        return False
    return False


def _nikto_status() -> dict[str, Any]:
    try:
        executable = find_executable("nikto", "nikto.pl")
    except EngineUnavailable:
        return _nikto_docker_status()
    uses_perl = Path(executable).suffix.lower() == ".pl"
    perl = shutil.which("perl") if uses_perl else None
    if uses_perl and not perl:
        docker_status = _nikto_docker_status()
        if docker_status.get("status") == "ready":
            return docker_status
        return _status(
            "missing",
            "Nikto's Perl script was found, but Perl and a ready Nikto Docker image are missing.",
            "Install Perl and add perl.exe to PATH, or start Docker Desktop and pull the official Nikto image.",
            executable=executable,
            perl_required=True,
            docker_image=_NIKTO_IMAGE,
            docker_status=docker_status.get("summary"),
        )
    return _status(
        "ready",
        "Nikto launcher is available." + (" Perl is also available." if uses_perl else ""),
        "No setup action needed.",
        executable=executable,
        perl_required=uses_perl,
        perl_executable=perl,
    )


def _nikto_docker_status() -> dict[str, Any]:
    docker = shutil.which("docker") or shutil.which("docker.exe")
    if not docker:
        return _status(
            "missing",
            "Nikto executable and Docker CLI were not found.",
            f"Install Nikto with Perl, or install Docker Desktop and run `docker pull {_NIKTO_IMAGE}`.",
            docker_image=_NIKTO_IMAGE,
        )
    daemon = _probe([docker, "info", "--format", "{{.ServerVersion}}"])
    if daemon["status"] != "ready":
        return _status(
            "missing",
            "Docker CLI is available, but the daemon is not responding for the Nikto container.",
            "Start Docker Desktop and wait until its engine is running, then retry.",
            executable=docker,
            docker_image=_NIKTO_IMAGE,
            diagnostic=daemon.get("detail"),
        )
    image = _probe([docker, "image", "inspect", _NIKTO_IMAGE, "--format", "{{.Id}}"])
    if image["status"] != "ready":
        return _status(
            "missing",
            f"Docker is running, but the Nikto image {_NIKTO_IMAGE} is not available locally.",
            f"Run `docker pull {_NIKTO_IMAGE}` before selecting a Nikto scan.",
            executable=docker,
            docker_server_version=daemon.get("value"),
            docker_image=_NIKTO_IMAGE,
            diagnostic=image.get("detail"),
        )
    return _status(
        "ready",
        "Docker daemon is running and the official Nikto image is available locally.",
        "No setup action needed.",
        executable=docker,
        docker_server_version=daemon.get("value"),
        docker_image=_NIKTO_IMAGE,
        image_id=image.get("value"),
        execution="docker",
    )


def _wapiti_status() -> dict[str, Any]:
    try:
        executable = find_executable("wapiti", "wapiti3")
    except EngineUnavailable:
        return _status(
            "missing",
            "Wapiti executable was not found on PATH.",
            "Install Wapiti in the environment used to run SiteAudit and ensure wapiti or wapiti3 is on PATH.",
        )
    wapiti_environment = os.environ.copy()
    wapiti_environment["PYTHONUTF8"] = "1"
    modules = _probe(
        [executable, "--list-modules"],
        output_limit=32_000,
        env=wapiti_environment,
    )
    if modules["status"] != "ready":
        return _status(
            "missing",
            "Wapiti is on PATH, but its attack modules could not be listed.",
            "Repair or reinstall Wapiti in the environment used by SiteAudit, then retry.",
            executable=executable,
            diagnostic=modules.get("detail"),
        )
    available_modules = _listed_wapiti_modules(modules["value"])
    if not available_modules:
        return _status(
            "missing",
            "Wapiti is on PATH, but none of SiteAudit's supported low-impact modules are installed.",
            "Install a complete Wapiti distribution with cookie/header, SQL, and CRLF modules.",
            executable=executable,
        )
    return _status(
        "ready",
        "Wapiti executable and supported low-impact modules are available.",
        "No setup action needed.",
        executable=executable,
        modules=available_modules,
    )


def _zap_status() -> dict[str, Any]:
    docker = shutil.which("docker") or shutil.which("docker.exe")
    if not docker:
        return _status(
            "missing",
            "Docker CLI was not found on PATH.",
            "Install Docker Desktop, start its daemon, and reopen the terminal.",
            image=_ZAP_IMAGE,
        )

    daemon = _probe([docker, "info", "--format", "{{.ServerVersion}}"])
    if daemon["status"] != "ready":
        return _status(
            "missing",
            "Docker CLI is installed, but the Docker daemon is not responding.",
            "Start Docker Desktop and wait until its engine is running, then retry.",
            executable=docker,
            image=_ZAP_IMAGE,
            diagnostic=daemon.get("detail"),
        )

    image = _probe([docker, "image", "inspect", _ZAP_IMAGE, "--format", "{{.Id}}"])
    if image["status"] != "ready":
        return _status(
            "missing",
            f"Docker is running, but the ZAP image {_ZAP_IMAGE} is not available locally.",
            f"Run `docker pull {_ZAP_IMAGE}` before selecting a ZAP scan.",
            executable=docker,
            docker_server_version=daemon.get("value"),
            image=_ZAP_IMAGE,
            diagnostic=image.get("detail"),
        )
    return _status(
        "ready",
        "Docker daemon is running and the ZAP image is available locally.",
        "No setup action needed.",
        executable=docker,
        docker_server_version=daemon.get("value"),
        image=_ZAP_IMAGE,
        image_id=image.get("value"),
    )


def _w3af_status() -> dict[str, Any]:
    if os.name == "nt":
        return _status(
            "unsupported",
            "The W3AF adapter does not run under native Windows Python.",
            "Run SiteAudit from a supported Linux/macOS environment with w3af_console installed; WSL is not invoked by this adapter.",
        )
    try:
        executable = find_executable("w3af_console")
    except EngineUnavailable:
        return _status(
            "missing",
            "w3af_console was not found on PATH.",
            "Install the legacy W3AF console in a supported Linux/macOS environment and add w3af_console to PATH.",
        )
    return _status(
        "ready",
        "w3af_console executable is available on this platform.",
        "No setup action needed; W3AF may still fail if its legacy runtime dependencies are missing.",
        executable=executable,
    )


def _probe(
    command: list[str],
    *,
    output_limit: int = _PROBE_OUTPUT_BYTES,
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Run a local read-only prerequisite query with strict time/output caps."""
    try:
        result = run_command(
            command,
            timeout=_PROBE_TIMEOUT_SECONDS,
            output_limit=output_limit,
            env=env,
        )
    except (EngineRunError, EngineUnavailable, OSError) as exc:
        return {"status": "missing", "detail": _brief(exc)}
    if result.returncode != 0:
        return {"status": "missing", "detail": _brief(result.stderr or result.stdout)}
    value = result.stdout.strip()[:output_limit]
    if not value:
        return {"status": "missing", "detail": "The prerequisite query returned no value."}
    return {"status": "ready", "value": value}


def _listed_wapiti_modules(output: str) -> list[str]:
    available: set[str] = set()
    for line in output.splitlines():
        candidate = line.strip().lstrip("-* ").lower()
        match = re.match(r"(?:mod_)?([a-z0-9_]+)(?:\s|:|$)", candidate)
        if match:
            available.add(match.group(1))
    return sorted(_WAPITI_SAFE_MODULES & available)


def _status(status: str, summary: str, next_step: str, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "summary": summary,
        "next_step": next_step,
    }
    result.update(details)
    return result


def _brief(value: Any) -> str:
    return " ".join(str(value).split())[:300]
