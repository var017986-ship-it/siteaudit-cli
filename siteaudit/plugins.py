"""Static allowlisted scanner plugin registry for SiteAudit."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class PluginSpec:
    name: str
    module: str
    mode: Literal["passive", "active"]
    result_key: str | None = None


# Only these first-party modules can run. Plugin names are stable report keys.
PLUGIN_REGISTRY: tuple[PluginSpec, ...] = (
    PluginSpec("zap_passive", "zap_checks", "passive", "responses_inspected"),
    PluginSpec("templates", "template_engine", "active", "templates_attempted"),
    PluginSpec("nikto", "nikto_checks", "active", "requests_sent"),
    PluginSpec("wapiti", "wapiti_checks", "active", "requests_sent"),
    PluginSpec("ssti", "ssti_checks", "active", "requests_sent"),
    PluginSpec("graphql_introspection", "graphql_checks", "active", "requests_sent"),
    PluginSpec("w3af", "w3af_checks", "active"),
)


class PluginExecutionError(RuntimeError):
    """A scanner plugin failed; the report must not imply it completed."""


def run_plugins(ctx: Any, *, include_active: bool, progress=None) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Run enabled allowlisted plugins and return results plus enabled names.

    A module error is surfaced with its plugin name. No plugin is silently
    skipped, since that could make a partial scan look clean.
    """
    enabled = [spec for spec in PLUGIN_REGISTRY if spec.mode == "passive" or include_active]
    results: dict[str, dict[str, Any]] = {}

    for index, spec in enumerate(enabled, start=1):
        if progress:
            progress("start", index - 1, len(enabled), spec.name)
        if spec.mode == "active" and ctx.request_limit_reached:
            results[spec.name] = {
                "status": "skipped",
                "reason": "The built-in request budget was exhausted before this check started.",
                "request_limit_reached": True,
                "findings_added": 0,
            }
            if progress:
                progress("done", index, len(enabled), f"{spec.name} (request limit)")
            continue
        try:
            module = import_module(f".{spec.module}", package=__package__)
            runner = getattr(module, "run", None)
            if not callable(runner):
                raise TypeError("module has no callable run(ctx)")
            findings_before = len(ctx.findings)
            request_limit_before = ctx.request_limit_reached
            result = runner(ctx)
        except Exception as exc:
            raise PluginExecutionError(f"Scanner plugin {spec.name!r} failed: {exc}") from exc

        plugin_result: dict[str, Any] = {"status": "completed"}
        plugin_result["findings_added"] = len(ctx.findings) - findings_before
        if isinstance(result, int) and not isinstance(result, bool):
            plugin_result[spec.result_key or "checks_attempted"] = result
        elif isinstance(result, dict):
            plugin_result.update(result)
        if ctx.request_limit_reached:
            plugin_result["request_limit_reached"] = True
            plugin_result["request_limit_blocked_attempts"] = ctx.request_limit_blocked_attempts
            if not request_limit_before:
                plugin_result["status"] = "partial"
                plugin_result["reason"] = "The built-in request budget was exhausted during this check."
        results[spec.name] = plugin_result
        if progress:
            progress("done", index, len(enabled), spec.name)

    return results, [spec.name for spec in enabled]
