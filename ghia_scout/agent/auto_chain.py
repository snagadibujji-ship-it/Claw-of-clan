"""Auto-exploitation chain engine — maps findings to follow-up tools automatically."""

from __future__ import annotations

from typing import Any

# ── Chain definitions ─────────────────────────────────────────────────
# Each rule: (trigger_keywords, follow_up_tool, follow_up_args_template, reason)

_CHAINS: list[tuple[list[str], str, dict, str]] = [
    # SQLi found → dump schema
    (
        ["sqli", "sql injection", "union select", "error-based"],
        "generate_payloads",
        {"vuln_type": "sqli", "count": 10},
        "SQLi confirmed — generating dump payloads",
    ),
    # File upload endpoint → bypass
    (
        ["file upload", "multipart", "upload endpoint", "file parameter"],
        "file_upload_bypass",
        {"file_field": "file"},
        "File upload found — attempting extension bypass",
    ),
    # XML endpoint → XXE
    (
        ["xml", "soap", "wsdl", "content-type: application/xml", "x-www-form"],
        "xxe_inject",
        {},
        "XML endpoint detected — probing XXE",
    ),
    # JWT in response → attack
    (
        ["jwt", "eyj", "bearer", "authorization: bearer"],
        "jwt_attack",
        {},
        "JWT token found — running JWT attacks",
    ),
    # SSRF indicators
    (
        ["url parameter", "redirect", "fetch", "proxy", "webhook", "callback url"],
        "ssrf_chain",
        {"param": "url"},
        "URL parameter found — probing SSRF chain",
    ),
    # GraphQL → audit
    (
        ["graphql", "/graphql", "query {", "__schema"],
        "graphql_audit",
        {},
        "GraphQL endpoint detected — running audit",
    ),
    # SMB / port 445
    (
        ["port 445", "smb", "samba", "cifs", "ms17-010"],
        "smb_scan",
        {},
        "SMB detected — scanning for null sessions and CVEs",
    ),
    # Privesc path (after shell)
    (
        ["shell", "rce", "command execution", "id:", "uid=", "whoami"],
        "privesc_scan",
        {"target": "linux", "auto_execute": False},
        "Shell obtained — running privilege escalation checks",
    ),
    # Binary / ELF target → checksec
    (
        ["elf", ".exe", "binary", "executable", "ctf", "pwn"],
        "checksec_binary",
        {},
        "Binary target — running checksec and string analysis",
    ),
    # Subdomain found → takeover check
    (
        ["subdomain", "vhost", "virtual host", "subdomain enumeration"],
        "subdomain_takeover",
        {},
        "Subdomains found — checking for dangling DNS / takeover",
    ),
    # WebSocket endpoint → fuzz
    (
        ["websocket", "ws://", "wss://", "upgrade: websocket"],
        "websocket_fuzz",
        {},
        "WebSocket endpoint found — fuzzing for injection",
    ),
    # Template injection hint
    (
        ["template", "jinja", "twig", "freemarker", "velocity", "smarty", "reflected expression"],
        "generate_payloads",
        {"vuln_type": "ssti"},
        "Template engine detected — generating SSTI payloads",
    ),
    # Cloud metadata / AWS
    (
        ["aws", "s3", "ec2", "iam", "metadata", "169.254.169.254", "cloud"],
        "ssrf_chain",
        {"param": "url", "target_paths": ["http://169.254.169.254/latest/meta-data/iam/"]},
        "Cloud infrastructure detected — probing metadata endpoint",
    ),
    # OSINT trigger
    (
        ["domain", "target domain", "http://", "https://", "recon", "reconnaissance"],
        "dns_recon",
        {},
        "Domain target — running full DNS recon",
    ),
]

AUTO_CHAIN_TOOLS: dict[str, Any] = {
    "suggest_next_tools": {
        "description": "Based on current findings and facts, suggest and queue follow-up attack tools",
        "parameters": {
            "type": "object",
            "properties": {
                "findings_summary": {
                    "type": "string",
                    "description": "Text summary of what has been found so far",
                },
                "max_suggestions": {"type": "integer", "default": 5},
            },
            "required": ["findings_summary"],
        },
    },
    "run_attack_chain": {
        "description": "Run a predefined attack chain for a given initial finding",
        "parameters": {
            "type": "object",
            "properties": {
                "chain_name": {
                    "type": "string",
                    "enum": [
                        "web_full", "network_full", "binary_full",
                        "cloud_full", "api_full", "ctf_quick",
                    ],
                },
                "target": {"type": "string"},
                "extra_args": {"type": "object"},
            },
            "required": ["chain_name", "target"],
        },
    },
}

_PREDEFINED_CHAINS: dict[str, list[dict]] = {
    "web_full": [
        {"tool": "dns_recon", "args_key": "domain"},
        {"tool": "cert_transparency", "args_key": "domain"},
        {"tool": "dir_enum", "args_key": "target"},
        {"tool": "js_recon", "args_key": "target"},
        {"tool": "subdomain_takeover", "args_key": "domain"},
        {"tool": "ssrf_chain", "args_extra": {"param": "url"}},
        {"tool": "xxe_inject"},
    ],
    "network_full": [
        {"tool": "smb_scan", "args_key": "host"},
        {"tool": "shodan_lite", "args_key": "ip"},
        {"tool": "whois_lookup", "args_key": "target"},
    ],
    "binary_full": [
        {"tool": "checksec_binary", "args_key": "binary_path"},
        {"tool": "ropgadget_search", "args_key": "binary_path"},
        {"tool": "flag_hunter", "args_key": "binary_path"},
    ],
    "cloud_full": [
        {"tool": "ssrf_chain", "args_extra": {"param": "url", "target_paths": [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]}},
        {"tool": "subdomain_takeover"},
        {"tool": "cert_transparency", "args_key": "domain"},
    ],
    "api_full": [
        {"tool": "graphql_audit", "args_key": "url"},
        {"tool": "jwt_attack", "args_key": "url"},
        {"tool": "generate_payloads", "args_extra": {"vuln_type": "nosqli"}},
        {"tool": "ssrf_chain", "args_extra": {"param": "url"}},
    ],
    "ctf_quick": [
        {"tool": "checksec_binary", "args_key": "binary_path"},
        {"tool": "flag_hunter", "args_key": "binary_path"},
        {"tool": "ropgadget_search", "args_key": "binary_path"},
        {"tool": "z3_solve", "args_extra": {"constraints": [], "variables": {}}},
    ],
}


# ── Dispatcher ────────────────────────────────────────────────────────

async def dispatch(agent: Any, tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "suggest_next_tools":
        return execute_suggest_next(args)
    if tool_name == "run_attack_chain":
        return execute_run_chain(args)
    return None


def execute_suggest_next(args: dict[str, Any]) -> str:
    summary: str = args["findings_summary"].lower()
    max_sugg: int = args.get("max_suggestions", 5)
    results = ["[suggest_next_tools] Analysing findings..."]
    suggestions: list[tuple[str, dict, str]] = []

    for triggers, tool, tmpl_args, reason in _CHAINS:
        if any(kw in summary for kw in triggers):
            suggestions.append((tool, tmpl_args, reason))
        if len(suggestions) >= max_sugg:
            break

    if not suggestions:
        results.append("  No specific follow-up tools triggered — try recon tools or generate_payloads")
    else:
        results.append(f"  {len(suggestions)} follow-up tool(s) recommended:")
        for i, (tool, t_args, reason) in enumerate(suggestions, 1):
            results.append(f"\n  {i}. {tool}")
            results.append(f"     Reason: {reason}")
            if t_args:
                results.append(f"     Args hint: {t_args}")

    return "\n".join(results)


def execute_run_chain(args: dict[str, Any]) -> str:
    chain_name: str = args["chain_name"]
    target: str = args["target"]
    extra: dict = args.get("extra_args") or {}
    chain = _PREDEFINED_CHAINS.get(chain_name, [])
    results = [f"[run_attack_chain] chain={chain_name} target={target!r}"]

    if not chain:
        return f"[run_attack_chain] Unknown chain: {chain_name}"

    results.append(f"  Chain has {len(chain)} steps:")
    for i, step in enumerate(chain, 1):
        tool = step["tool"]
        args_key = step.get("args_key")
        args_extra = step.get("args_extra") or {}
        resolved_args = {args_key: target, **args_extra, **extra} if args_key else {**args_extra, **extra}
        results.append(f"  Step {i}: {tool}({resolved_args})")

    results.append("\n  To execute: the agent will call these tools in sequence.")
    results.append("  Queue these calls now using the tool names above.")
    return "\n".join(results)
