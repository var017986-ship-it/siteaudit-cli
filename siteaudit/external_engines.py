"""Run explicitly requested upstream scanner CLIs and collect their findings."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .external_support import EngineRunError, EngineUnavailable


_ADAPTERS = {
    "nuclei": "external_nuclei",
    "nikto": "external_nikto",
    "wapiti": "external_wapiti",
    "zap": "external_zap",
    "w3af": "external_w3af",
}


def run(ctx: Any) -> dict[str, dict[str, Any]]:
    requested = (getattr(ctx, "options", {}) or {}).get("external_engines", [])
    if "all" in requested:
        requested = list(_ADAPTERS)
    results: dict[str, dict[str, Any]] = {}
    for name in dict.fromkeys(requested):
        module_name = _ADAPTERS.get(name)
        if module_name is None:
            results[str(name)] = {"status": "unsupported", "findings_added": 0}
            continue
        findings_before = len(ctx.findings)
        try:
            adapter = import_module(f".{module_name}", package=__package__)
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
        result["findings_added"] = len(ctx.findings) - findings_before
        results[name] = result
    return results
