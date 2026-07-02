from __future__ import annotations

from ghia_scout.plugins.web.headers import SecurityHeadersPlugin
from ghia_scout.plugins.web.js_endpoints import JavaScriptEndpointsPlugin
from ghia_scout.plugins.web.jwt import JWTClaimsPlugin

BUILTIN_WEB_PLUGINS = (
    SecurityHeadersPlugin,
    JWTClaimsPlugin,
    JavaScriptEndpointsPlugin,
)


__all__ = [
    "BUILTIN_WEB_PLUGINS",
    "JWTClaimsPlugin",
    "JavaScriptEndpointsPlugin",
    "SecurityHeadersPlugin",
]
