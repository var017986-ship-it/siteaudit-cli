"""Run explicitly requested upstream scanner CLIs and collect their findings."""

from __future__ import annotations

from importlib import import_module
import ipaddress
import os
from pathlib import Path
import time
from typing import Any

from .external_support import EngineRunError, EngineUnavailable, find_executable, run_command
from .external_scope_proxy import ScopeProxy


_ADAPTERS = {
    "nuclei": "external_nuclei",
    "nikto": "external_nikto",
    "wapiti": "external_wapiti",
    "zap": "external_zap",
    "w3af": "external_w3af",
}


def run(ctx: Any, progress=None) -> dict[str, dict[str, Any]]:
    requested = (getattr(ctx, "options", {}) or {}).get("external_engines", [])
    if "all" in requested:
        requested = list(_ADAPTERS)
    results: dict[str, dict[str, Any]] = {}
    names = list(dict.fromkeys(requested))
    for index, name in enumerate(names, start=1):
        if progress:
            progress("start", index - 1, len(names), str(name))
        module_name = _ADAPTERS.get(name)
        if module_name is None:
            results[str(name)] = {"status": "unsupported", "findings_added": 0}
            if progress:
                progress("done", index, len(names), str(name))
            continue
        findings_before = len(ctx.findings)
        options = getattr(ctx, "options", None)
        if not isinstance(options, dict):
            options = {}
            ctx.options = options
        max_pages = max(1, min(int(options.get("max_pages", 50)), 500))
        max_connections = max(80, min(10_000, max_pages * 20))
        nikto_wsl_runtime = None
        zap_wsl_runtime = None
        if name == "nikto" and not _nikto_native_ready():
            from .external_nikto import wsl_nikto_runtime

            detected_runtime = wsl_nikto_runtime()
            if detected_runtime.get("ready"):
                nikto_wsl_runtime = detected_runtime
                # Nikto has a lower transaction ceiling than the crawler-based
                # engines. HTTPS CONNECTs are counted per tunnel, so this is a
                # conservative cap rather than a precise encrypted request cap.
                max_connections = min(max_connections, max(80, min(1_000, max_pages * 10)))
        if name == "zap" and os.name == "nt":
            from .external_zap import wsl_zap_runtime

            detected_runtime = wsl_zap_runtime()
            if detected_runtime.get("ready"):
                zap_wsl_runtime = detected_runtime
                # HTTPS accounting is per CONNECT tunnel; keep a bounded cap,
                # while ZAP itself uses one scanner thread and delay per request.
                max_connections = min(max_connections, max(80, min(1_000, max_pages * 10)))
        previous_proxy_values = {
            key: options.get(key)
            for key in (
                "external_proxy_url",
                "external_proxy_auth_url",
                "external_proxy_username",
                "external_proxy_password",
                "_external_nikto_wsl_runtime",
                "_external_zap_wsl_runtime",
            )
        }
        scope_proxy = None
        engine_started = time.monotonic()
        try:
            adapter = import_module(f".{module_name}", package=__package__)
            remote_proxy = name == "zap" or (name == "nikto" and not _nikto_native_ready())
            proxy_options = {}
            if nikto_wsl_runtime is not None:
                options["_external_nikto_wsl_runtime"] = nikto_wsl_runtime
                proxy_options = {
                    "bind_address": nikto_wsl_runtime["host_gateway"],
                    "proxy_host": nikto_wsl_runtime["host_gateway"],
                    "allowed_remote_clients": (f"{nikto_wsl_runtime['client_ip']}/32",),
                }
            if zap_wsl_runtime is not None:
                options["_external_zap_wsl_runtime"] = zap_wsl_runtime
                proxy_options = {
                    "bind_address": zap_wsl_runtime["host_gateway"],
                    "proxy_host": zap_wsl_runtime["host_gateway"],
                    "allowed_remote_clients": (f"{zap_wsl_runtime['client_ip']}/32",),
                    "remote_auth_required": False,
                }
            elif remote_proxy and not proxy_options:
                proxy_options["allowed_remote_clients"] = _docker_bridge_allowlist()
            with ScopeProxy(
                ctx,
                request_limit=max_connections,
                delay=float(options.get("delay", 0.5)),
                timeout=float(options.get("timeout", 10)),
                remote_access=remote_proxy,
                **proxy_options,
            ) as scope_proxy:
                options["external_proxy_url"] = scope_proxy.url
                options["external_proxy_auth_url"] = scope_proxy.auth_url
                options["external_proxy_username"] = scope_proxy.username
                options["external_proxy_password"] = scope_proxy.password
                adapter_result = adapter.run(ctx)
            if not isinstance(adapter_result, dict):
                raise EngineRunError("adapter returned an invalid result")
            result = {**adapter_result, "status": adapter_result.get("status", "completed")}
        except EngineUnavailable as exc:
            result = {"status": "unavailable", "error": str(exc)[:500]}
        except (EngineRunError, OSError, ValueError) as exc:
            proxy_stats = scope_proxy.stats() if scope_proxy is not None else {}
            had_scoped_traffic = bool(
                proxy_stats.get("http_requests_authorized", 0)
                or proxy_stats.get("https_tunnels_authorized", 0)
            )
            result = {
                "status": "partial" if had_scoped_traffic else "error",
                "error": str(exc)[:500],
            }
        except Exception as exc:
            result = {"status": "error", "error": f"Unexpected adapter failure: {exc}"[:500]}
        finally:
            for key, value in previous_proxy_values.items():
                if value is None:
                    options.pop(key, None)
                else:
                    options[key] = value
        result.setdefault("engine_elapsed_seconds", round(time.monotonic() - engine_started, 3))
        if scope_proxy is not None:
            proxy_stats = scope_proxy.stats()
            result["scope_proxy"] = proxy_stats
            result["proxy_transactions_authorized"] = (
                proxy_stats["http_requests_authorized"] + proxy_stats["https_tunnels_authorized"]
            )
            result["scope_enforcement"] = (
                "HTTP requests and HTTPS CONNECT tunnels are limited to the selected host and port; "
                "the proxy connects to the pinned IP and checks HTTPS SNI. A same-host HTTP-to-HTTPS upgrade from port 80 to 443 is allowed when the scan starts with HTTP. "
                "HTTPS Host headers, methods, and bodies inside TLS are not inspected."
            )
            if (
                proxy_stats["request_limit_reached"]
                or proxy_stats["out_of_scope_attempts_blocked"]
                or proxy_stats["unsupported_methods_blocked"]
                or proxy_stats["proxy_auth_failures"]
                or proxy_stats["proxy_client_limit_rejections"]
                or proxy_stats["proxy_nonlocal_client_rejections"]
                or proxy_stats["http_response_byte_limit_reached"]
            ) and result.get("status") == "completed":
                result["status"] = "partial"
            if (
                name == "nuclei"
                and proxy_stats["http_requests_authorized"] + proxy_stats["https_tunnels_authorized"] == 0
                and result.get("status") == "completed"
            ):
                result["status"] = "error"
                result["error"] = "Nuclei completed without sending a request through the scope proxy."
            elif (
                name == "nikto"
                and proxy_stats["http_requests_authorized"] + proxy_stats["https_tunnels_authorized"] == 0
                and result.get("status") == "completed"
            ):
                result["status"] = "error"
                result["error"] = "Nikto completed without sending a request through the scope proxy."
            elif (
                name == "zap"
                and proxy_stats["http_requests_authorized"] + proxy_stats["https_tunnels_authorized"] == 0
                and result.get("status") == "completed"
            ):
                result["status"] = "error"
                result["error"] = "ZAP completed without sending a request through the scope proxy."
            elif (
                result.get("status") == "error"
                and proxy_stats["http_requests_authorized"] + proxy_stats["https_tunnels_authorized"] > 0
                and "time limit" in str(result.get("error", "")).lower()
            ):
                result["status"] = "partial"
        result["findings_added"] = len(ctx.findings) - findings_before
        results[name] = result
        if progress:
            progress("done", index, len(names), f"{name}: {result.get('status', 'unknown')}")
    return results


def _nikto_native_ready() -> bool:
    try:
        executable = find_executable("nikto", "nikto.pl")
        if Path(executable).suffix.lower() == ".pl":
            find_executable("perl")
        return True
    except EngineUnavailable:
        return False


def _docker_bridge_allowlist() -> tuple[str, ...]:
    """Return the exact private subnet used by Docker's default bridge."""
    try:
        docker = find_executable("docker", "docker.exe")
    except EngineUnavailable as exc:
        raise EngineUnavailable("Docker scanner access requires an installed Docker CLI and bridge network.") from exc
    result = run_command(
        [docker, "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Subnet}}"],
        timeout=8,
        output_limit=4096,
    )
    if result.returncode != 0:
        raise EngineUnavailable("Could not determine Docker's bridge subnet for the scanner proxy allow-list.")
    try:
        network = ipaddress.ip_network(result.stdout.strip(), strict=False)
    except ValueError as exc:
        raise EngineUnavailable("Docker returned an invalid bridge subnet; refusing to expose the scope proxy.") from exc
    private_ranges = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
    if (
        not any(network.subnet_of(private) for private in private_ranges)
        or network.prefixlen < (16 if network.version == 4 else 48)
    ):
        raise EngineUnavailable("Docker's bridge subnet is not private and narrowly bounded; refusing to expose the scope proxy.")
    return (str(network),)
