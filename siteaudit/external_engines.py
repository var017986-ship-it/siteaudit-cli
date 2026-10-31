"""Run explicitly requested upstream scanner CLIs and collect their findings."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .external_support import EngineRunError, EngineUnavailable
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
        previous_proxy_values = {
            key: options.get(key)
            for key in (
                "external_proxy_url",
                "external_proxy_auth_url",
                "external_proxy_username",
                "external_proxy_password",
            )
        }
        scope_proxy = None
        try:
            adapter = import_module(f".{module_name}", package=__package__)
            with ScopeProxy(
                ctx,
                request_limit=max_connections,
                delay=float(options.get("delay", 0.5)),
                timeout=float(options.get("timeout", 10)),
                remote_access=name == "zap",
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
            result = {"status": "error", "error": str(exc)[:500]}
        except Exception as exc:
            result = {"status": "error", "error": f"Unexpected adapter failure: {exc}"[:500]}
        finally:
            for key, value in previous_proxy_values.items():
                if value is None:
                    options.pop(key, None)
                else:
                    options[key] = value
        if scope_proxy is not None:
            proxy_stats = scope_proxy.stats()
            result["scope_proxy"] = proxy_stats
            result["scope_enforcement"] = (
                "HTTP requests and HTTPS CONNECT tunnels are limited to the selected host and port; "
                "the proxy connects to the pinned IP and checks HTTPS SNI. HTTPS Host headers, methods, and bodies inside TLS are not inspected."
            )
            if (
                proxy_stats["request_limit_reached"]
                or proxy_stats["out_of_scope_attempts_blocked"]
                or proxy_stats["unsupported_methods_blocked"]
                or proxy_stats["proxy_client_limit_rejections"]
                or proxy_stats["http_response_byte_limit_reached"]
            ) and result.get("status") == "completed":
                result["status"] = "partial"
        result["findings_added"] = len(ctx.findings) - findings_before
        results[name] = result
        if progress:
            progress("done", index, len(names), f"{name}: {result.get('status', 'unknown')}")
    return results
