"""Adaptive target type classifier.

Detects what kind of target is being tested and returns the optimal recon
strategy, attack chain order, and tool recommendations for that target type.

Target types:
  web       — HTTP/HTTPS web applications (default)
  api       — Pure REST/GraphQL/gRPC API services
  cloud     — AWS/GCP/Azure/cloud infrastructure
  network   — Network services (SSH/SMB/RDP/FTP/SNMP/IoT etc.)
  binary    — Standalone binaries, CTF pwn/rev challenges
  mobile    — Android/iOS app reverse engineering
  iot       — IoT devices, embedded firmware, industrial systems
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ── Signatures used to classify targets ───────────────────────────────────────

_CLOUD_PATTERNS = [
    r"\.amazonaws\.com", r"\.s3\.amazonaws\.com", r"\.blob\.core\.windows\.net",
    r"\.azurewebsites\.net", r"\.cloudfront\.net", r"\.googleapis\.com",
    r"\.appspot\.com", r"\.run\.app", r"\.cloudfunctions\.net",
    r"\.digitaloceanspaces\.com", r"\.aliyuncs\.com", r"\.myhuaweicloud\.com",
    r"ecs\.", r"oss\.", r"rds\.", r"lambda\.", r"ec2\.",
]

_API_PATTERNS = [
    r"/api/v\d", r"/graphql", r"/rest/", r"/grpc", r"/swagger",
    r"api\.", r"service\.", r"gateway\.", r"backend\.",
    r"\.json$", r"openapi", r"swagger\.json",
]

_NETWORK_PATTERNS = [
    r"^\d{1,3}(\.\d{1,3}){3}$",  # bare IP
    r":\d{2,5}$",                 # port suffix (22, 445, 3389, 8080, etc.)
    r"smb://", r"ftp://", r"ssh://", r"rdp://", r"vnc://",
    r"ldap://", r"mongodb://", r"redis://", r"memcached://",
]

_BINARY_PATTERNS = [
    r"\.elf$", r"\.exe$", r"\.out$", r"\.bin$", r"\.so$", r"\.dll$",
    r"pwn", r"rev", r"binary", r"exploit", r"shellcode", r"rop",
    r"buffer overflow", r"heap", r"stack", r"format string",
    r"checksec", r"pwndbg", r"gdb", r"radare", r"ghidra", r"ida",
]

_MOBILE_PATTERNS = [
    r"\.apk$", r"\.ipa$", r"android", r"ios", r"adb ", r"frida",
    r"jadx", r"apktool", r"dex", r"smali", r"bundle id",
    r"com\.[a-z]+\.[a-z]+",  # Android package name
]

_IOT_PATTERNS = [
    r"firmware", r"iot", r"embedded", r"uart", r"jtag", r"spi", r"i2c",
    r"buspirate", r"openocd", r"binwalk", r"squashfs", r"uboot",
    r"telnet://", r"snmp", r"modbus", r"dnp3", r"bacnet",
]


@dataclass
class TargetProfile:
    """Comprehensive profile describing the target and optimal attack strategy."""

    target_type: str = "web"
    confidence: float = 1.0

    # Ordered list of recon dimensions to complete (most important first)
    recon_dimensions: list[str] = field(default_factory=list)

    # Ordered list of attack categories to try
    attack_chain: list[str] = field(default_factory=list)

    # Tools the agent should prefer for this target type
    preferred_tools: list[str] = field(default_factory=list)

    # Extra context injected into the agent's system prompt
    strategy_notes: str = ""

    # Whether parallel intent exploration is safe/beneficial for this type
    supports_parallel: bool = True

    # Max tool rounds per intent (network/binary need more)
    recommended_tool_rounds: int = 4

    def to_prompt_block(self) -> str:
        lines = [
            f"## 目标类型识别: {self.target_type.upper()} (confidence={self.confidence:.0%})",
            f"侦察维度优先级: {' → '.join(self.recon_dimensions)}",
            f"攻击链顺序: {' → '.join(self.attack_chain)}",
            f"推荐工具: {', '.join(self.preferred_tools)}",
        ]
        if self.strategy_notes:
            lines.append(f"策略提示: {self.strategy_notes}")
        return "\n".join(lines)


def classify_target(origin: str, goal: str = "", hints: list[str] | None = None) -> TargetProfile:
    """Detect target type from origin/goal text and return optimal strategy.

    Falls back to 'web' if nothing distinctive is found.
    """
    text = " ".join(filter(None, [origin or "", goal or ""] + (hints or []))).lower().strip()

    scores: dict[str, float] = {
        "cloud": 0.0, "api": 0.0, "network": 0.0,
        "binary": 0.0, "mobile": 0.0, "iot": 0.0, "web": 0.2,
    }

    for pat in _CLOUD_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            scores["cloud"] += 1.0

    for pat in _API_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            scores["api"] += 0.8

    for pat in _NETWORK_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            scores["network"] += 1.0

    for pat in _BINARY_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            scores["binary"] += 1.2

    for pat in _MOBILE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            scores["mobile"] += 1.0

    for pat in _IOT_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            scores["iot"] += 1.0

    # http/https strongly signals web or api
    if re.search(r"https?://", text):
        scores["web"] += 0.5
        scores["cloud"] += 0.2

    # Bare IPs lean network
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", origin.strip()):
        scores["network"] += 0.8

    best = max(scores, key=lambda k: scores[k])
    confidence = min(1.0, scores[best] / max(sum(scores.values()), 1))

    return _build_profile(best, confidence)


def _build_profile(target_type: str, confidence: float) -> TargetProfile:
    profiles: dict[str, dict[str, Any]] = {
        "web": {
            "recon_dimensions": [
                "server_fingerprint",      # Ports, OS, middleware, real IP
                "web_surface",             # Tech stack, WAF, sensitive dirs, source leaks
                "domain_intel",            # WHOIS, subdomains, DNS, cert transparency
                "api_endpoints",           # JS recon, API discovery, GraphQL
                "credentials",             # Default creds, leaked secrets, login bruteforce
            ],
            "attack_chain": [
                "passive_recon", "active_recon", "vuln_scan",
                "web_exploit", "auth_bypass", "post_exploit",
            ],
            "preferred_tools": [
                "js_recon", "dir_enum", "space_search", "subdomain_enum",
                "unauth_test", "brute_force_login", "graphql_audit", "nmap_scan",
            ],
            "strategy_notes": (
                "优先 js_recon 提取 API 端点，随后 dir_enum 目录枚举，"
                "对发现的端点做未授权测试。注意 WAF 绕过和参数污染。"
            ),
            "supports_parallel": True,
            "recommended_tool_rounds": 4,
        },
        "api": {
            "recon_dimensions": [
                "api_schema",              # OpenAPI/Swagger/GraphQL schema discovery
                "auth_model",              # JWT, OAuth, API key analysis
                "endpoint_inventory",      # All routes, methods, parameters
                "business_logic",          # IDOR, mass assignment, privilege escalation
                "rate_limits",             # Throttling, quota bypass
            ],
            "attack_chain": [
                "schema_discovery", "auth_analysis", "endpoint_fuzzing",
                "idor_test", "mass_assignment", "jwt_attack", "ssrf_test",
            ],
            "preferred_tools": [
                "js_recon", "graphql_audit", "unauth_test", "dir_enum",
                "brute_force_login", "websocket_fuzz",
            ],
            "strategy_notes": (
                "首先发现 API schema（/swagger, /openapi.json, /graphql 自省）。"
                "测试 JWT 弱密钥/算法降级、IDOR、mass assignment 和 BOLA。"
            ),
            "supports_parallel": True,
            "recommended_tool_rounds": 5,
        },
        "cloud": {
            "recon_dimensions": [
                "cloud_assets",            # S3 buckets, blob storage, cloud functions
                "iam_surface",             # IAM policies, roles, misconfigs
                "metadata_service",        # IMDS/169.254.169.254 access
                "exposed_services",        # RDS, Elasticsearch, Redis publicly exposed
                "secrets_in_code",         # Keys in env vars, source, configs
            ],
            "attack_chain": [
                "asset_discovery", "bucket_enum", "metadata_ssrf",
                "iam_enum", "privilege_escalation", "lateral_movement",
            ],
            "preferred_tools": [
                "space_search", "subdomain_enum", "js_recon",
                "dir_enum", "unauth_test", "nmap_scan",
            ],
            "strategy_notes": (
                "重点检查：S3/OSS 桶公开访问、SSRF → 元数据服务（169.254.169.254）、"
                "IAM 最小权限违规、环境变量/代码中的 AK/SK 泄露。"
            ),
            "supports_parallel": True,
            "recommended_tool_rounds": 4,
        },
        "network": {
            "recon_dimensions": [
                "port_scan",               # All open ports, service versions
                "service_fingerprint",     # Banner grabbing, version detection
                "credential_testing",      # Default credentials on services
                "protocol_vulns",          # SMB, RDP, FTP, SSH weaknesses
                "lateral_movement",        # Pivot points, tunnels
            ],
            "attack_chain": [
                "port_scan", "service_enum", "vuln_scan",
                "credential_spray", "smb_enum", "exploit",
            ],
            "preferred_tools": [
                "nmap_scan", "smb_scan", "brute_force_login", "privesc_scan",
            ],
            "strategy_notes": (
                "全端口扫描（-p-）获取完整攻击面。"
                "优先测试 SMB（445）、RDP（3389）、SSH（22）、FTP（21）、"
                "Telnet（23）默认凭证。检查 SMBGhost/BlueKeep 等已知漏洞。"
            ),
            "supports_parallel": False,
            "recommended_tool_rounds": 6,
        },
        "binary": {
            "recon_dimensions": [
                "binary_properties",       # Arch, protections (NX/PIE/RELRO/canary)
                "function_analysis",       # Main logic, input handling, dangerous functions
                "vulnerability_class",     # BOF, format string, UAF, heap etc.
                "exploit_primitives",      # Leak, control-flow hijack, shellcode
                "environment",             # libc version, ASLR, kernel version
            ],
            "attack_chain": [
                "checksec", "static_analysis", "dynamic_analysis",
                "vuln_identify", "exploit_develop", "get_shell",
            ],
            "preferred_tools": [
                "python_execute",  # pwntools, ROPgadget, angr
            ],
            "strategy_notes": (
                "使用 python_execute + pwntools 进行动态测试。"
                "先 checksec，再找 vulnerable 函数（gets/strcpy/scanf）。"
                "BOF → 找偏移 → ROP 链 → ret2libc / shellcode / SROP。"
                "泄露 libc 基址后计算 system('/bin/sh') 地址。"
            ),
            "supports_parallel": False,
            "recommended_tool_rounds": 8,
        },
        "mobile": {
            "recon_dimensions": [
                "apk_analysis",            # Manifest, permissions, components
                "static_analysis",         # Decompiled source, hardcoded secrets
                "network_traffic",         # API endpoints, cert pinning
                "dynamic_analysis",        # Frida hooks, runtime manipulation
                "backend_apis",            # The web API the app talks to
            ],
            "attack_chain": [
                "apk_decompile", "manifest_audit", "source_scan",
                "traffic_intercept", "api_test", "frida_hook",
            ],
            "preferred_tools": [
                "python_execute",  # frida, jadx, apktool via subprocess
                "js_recon", "unauth_test",
            ],
            "strategy_notes": (
                "apktool 反编译 → 检查 AndroidManifest.xml（exported components）。"
                "jadx 反编译 Dalvik → 搜索硬编码密钥/API endpoint。"
                "Frida 绕过 SSL pinning → Burp 抓包 → 测试后端 API。"
            ),
            "supports_parallel": False,
            "recommended_tool_rounds": 6,
        },
        "iot": {
            "recon_dimensions": [
                "firmware_analysis",       # Filesystem extraction, hardcoded creds
                "network_services",        # Telnet, MQTT, CoAP, HTTP admin
                "hardware_interface",      # UART, JTAG debug ports
                "protocol_vulns",          # Custom protocols, unencrypted comms
                "update_mechanism",        # OTA update integrity
            ],
            "attack_chain": [
                "firmware_extract", "filesystem_analysis",
                "service_discovery", "credential_test", "exploit",
            ],
            "preferred_tools": [
                "nmap_scan", "python_execute",
            ],
            "strategy_notes": (
                "binwalk 提取固件文件系统 → 搜索默认凭证和私钥。"
                "扫描 Telnet/HTTP 管理界面 → 测试默认账号。"
                "检查 MQTT（1883）无认证、CoAP（5683）未加密。"
            ),
            "supports_parallel": False,
            "recommended_tool_rounds": 6,
        },
    }

    cfg = profiles.get(target_type, profiles["web"])
    return TargetProfile(
        target_type=target_type,
        confidence=confidence,
        recon_dimensions=cfg["recon_dimensions"],
        attack_chain=cfg["attack_chain"],
        preferred_tools=cfg["preferred_tools"],
        strategy_notes=cfg["strategy_notes"],
        supports_parallel=cfg["supports_parallel"],
        recommended_tool_rounds=cfg["recommended_tool_rounds"],
    )


def reclassify_from_facts(profile: TargetProfile, facts: list[str]) -> TargetProfile:
    """Re-evaluate the target type as new facts arrive during the engagement.

    Call this after the first few recon intents conclude to sharpen the
    target type prediction based on what we actually discovered.
    """
    combined = " ".join(facts).lower()
    new = classify_target(combined)

    # Only upgrade if new classification has higher confidence
    if new.target_type != profile.target_type and new.confidence > profile.confidence:
        return new

    # Even if type stays the same, refresh confidence
    profile.confidence = max(profile.confidence, new.confidence)
    return profile
