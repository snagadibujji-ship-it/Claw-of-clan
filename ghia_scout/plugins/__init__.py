from __future__ import annotations

from ghia_scout.plugins.base import PluginContext, VulnPlugin
from ghia_scout.plugins.registry import PluginRegistry, registry
from ghia_scout.plugins.result import (
    PluginFinding,
    PluginPhase,
    PluginResult,
    PluginRisk,
    PluginStage,
    RiskLevel,
)
from ghia_scout.plugins.runtime import PluginRequest, PluginRuntime
from ghia_scout.plugins.web import BUILTIN_WEB_PLUGINS


def register_builtin_plugins() -> None:
    for plugin_cls in BUILTIN_WEB_PLUGINS:
        registry.register(plugin_cls, replace=True)


def create_builtin_runtime(
    config: object = None,
    *,
    allowed_targets: set[str] | None = None,
) -> PluginRuntime:
    register_builtin_plugins()
    return PluginRuntime(registry, config=config, allowed_targets=allowed_targets)


register_builtin_plugins()

__all__ = [
    "BUILTIN_WEB_PLUGINS",
    "PluginContext",
    "PluginFinding",
    "PluginPhase",
    "PluginRegistry",
    "PluginRequest",
    "PluginResult",
    "PluginRisk",
    "PluginRuntime",
    "PluginStage",
    "RiskLevel",
    "VulnPlugin",
    "create_builtin_runtime",
    "register_builtin_plugins",
    "registry",
]
