"""Adaptive recon model — replaces the static 4-dimension completion tracker.

The original context.py had a hard-coded:
    recon_dimensions_completed = {"server": False, "website": False,
                                   "domain": False, "personnel": False}

This breaks on cloud targets, binary CTF challenges, API-only services, etc.

This module provides:
  - AdaptiveReconModel: a Pydantic-compatible model whose dimensions are
    populated dynamically from a TargetProfile
  - Dimension names, descriptions, and completion signals per target type
  - auto_advance(): heuristically marks dimensions complete based on facts

Usage in SessionState:
    adaptive_recon: AdaptiveReconModel = Field(default_factory=AdaptiveReconModel)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ReconDimension(BaseModel):
    """A single recon dimension with a name, description, and completion state."""

    name: str
    description: str
    completed: bool = False
    completion_evidence: list[str] = Field(default_factory=list)

    def mark_complete(self, evidence: str = "") -> None:
        self.completed = True
        if evidence and evidence not in self.completion_evidence:
            self.completion_evidence.append(evidence[:200])


# Per-target-type dimension definitions ─────────────────────────────────────────

_DIMENSION_DEFS: dict[str, list[tuple[str, str, list[str]]]] = {
    # (name, description, completion_keywords)
    "web": [
        ("server_fingerprint", "端口/OS/真实IP/中间件/数据库",
         ["端口", "port", "os", "nginx", "apache", "iis", "tomcat", "weblogic", "真实ip"]),
        ("web_surface", "技术栈/WAF/敏感目录/源码泄露/旁站",
         ["waf", "框架", "cms", "目录", "路径", "源码", "备份", ".git", "phpinfo"]),
        ("domain_intel", "WHOIS/子域名/DNS/证书透明度",
         ["子域名", "subdomain", "dns", "whois", "icp", "证书", "域名"]),
        ("api_endpoints", "JS接口/API端点/GraphQL端点",
         ["api", "endpoint", "接口", "graphql", "swagger", "路由"]),
        ("credentials", "默认凭证/密钥泄露/登录测试",
         ["凭证", "密码", "password", "token", "key", "登录", "弱口令"]),
    ],
    "api": [
        ("api_schema", "OpenAPI/Swagger/GraphQL schema发现",
         ["swagger", "openapi", "graphql", "schema", "introspection", "内省"]),
        ("auth_model", "JWT/OAuth/API Key分析",
         ["jwt", "oauth", "api key", "token", "bearer", "认证"]),
        ("endpoint_inventory", "所有路由/方法/参数枚举",
         ["endpoint", "路由", "接口", "参数", "方法", "route"]),
        ("business_logic", "IDOR/越权/mass assignment",
         ["idor", "越权", "mass", "业务逻辑", "水平", "垂直"]),
        ("rate_limits", "限流/配额绕过",
         ["rate limit", "限流", "配额", "quota", "throttle"]),
    ],
    "cloud": [
        ("cloud_assets", "S3桶/Blob存储/云函数资产",
         ["s3", "bucket", "blob", "oss", "cos", "云函数", "function"]),
        ("iam_surface", "IAM策略/角色/权限配置",
         ["iam", "role", "policy", "权限", "assume", "sts"]),
        ("metadata_service", "IMDS/元数据服务访问",
         ["169.254", "metadata", "元数据", "imds", "imdsv"]),
        ("exposed_services", "公开暴露的数据库/缓存",
         ["rds", "redis", "elasticsearch", "mongodb", "暴露", "公开"]),
        ("secrets_in_code", "代码/环境变量中的密钥",
         ["ak", "sk", "access key", "secret", "env", "密钥泄露"]),
    ],
    "network": [
        ("port_scan", "全端口扫描/服务版本",
         ["端口", "port", "nmap", "service", "version", "open"]),
        ("service_fingerprint", "Banner抓取/版本识别",
         ["banner", "版本", "version", "fingerprint", "识别"]),
        ("credential_testing", "服务默认凭证测试",
         ["默认", "default", "凭证", "credential", "暴力", "brute"]),
        ("protocol_vulns", "SMB/RDP/SSH/FTP协议漏洞",
         ["smb", "rdp", "ssh", "ftp", "ms17-010", "eternalblue", "bluekeep"]),
        ("lateral_movement", "横向移动/隧道",
         ["横向", "lateral", "pivot", "tunnel", "内网"]),
    ],
    "binary": [
        ("binary_properties", "架构/保护措施(NX/PIE/RELRO/Canary)",
         ["checksec", "nx", "pie", "relro", "canary", "arch", "64-bit", "32-bit"]),
        ("function_analysis", "主逻辑/输入处理/危险函数",
         ["function", "gets", "strcpy", "scanf", "read", "overflow", "危险函数"]),
        ("vulnerability_class", "漏洞类型识别",
         ["bof", "buffer overflow", "format string", "uaf", "heap", "rop", "漏洞类型"]),
        ("exploit_primitives", "泄露/控制流劫持",
         ["leak", "泄露", "libc", "got", "plt", "ret2", "shellcode", "rip"]),
        ("environment", "libc版本/ASLR/内核",
         ["libc", "aslr", "kernel", "内核", "glibc", "version"]),
    ],
    "mobile": [
        ("apk_analysis", "Manifest/权限/导出组件",
         ["manifest", "permission", "activity", "service", "receiver", "exported"]),
        ("static_analysis", "反编译源码/硬编码密钥",
         ["jadx", "decompile", "hardcode", "secret", "api key", "源码"]),
        ("network_traffic", "API端点/证书绑定",
         ["ssl pinning", "证书", "api", "endpoint", "traffic", "流量"]),
        ("dynamic_analysis", "Frida/运行时操纵",
         ["frida", "hook", "runtime", "动态", "bypass"]),
        ("backend_apis", "后端API测试",
         ["backend", "后端", "api", "server", "接口"]),
    ],
    "iot": [
        ("firmware_analysis", "固件文件系统提取",
         ["firmware", "固件", "binwalk", "squashfs", "filesystem"]),
        ("network_services", "Telnet/MQTT/CoAP/HTTP管理",
         ["telnet", "mqtt", "coap", "http", "admin", "management"]),
        ("hardware_interface", "UART/JTAG调试接口",
         ["uart", "jtag", "debug", "serial", "硬件"]),
        ("protocol_vulns", "协议漏洞/未加密通信",
         ["unencrypted", "protocol", "协议", "明文"]),
        ("update_mechanism", "OTA更新完整性",
         ["ota", "update", "更新", "integrity", "signature"]),
    ],
}

# Fallback dimensions (used when target type is unrecognised)
_FALLBACK_DIMS = _DIMENSION_DEFS["web"]


class AdaptiveReconModel(BaseModel):
    """Dynamic recon tracker that adapts to the detected target type."""

    target_type: str = "web"
    dimensions: list[ReconDimension] = Field(default_factory=list)
    initialized: bool = False

    def initialize(self, target_type: str) -> None:
        """Set up dimensions from the target profile. Call once after classification."""
        if self.initialized and self.target_type == target_type:
            return
        self.target_type = target_type
        dim_defs = _DIMENSION_DEFS.get(target_type, _FALLBACK_DIMS)
        # Preserve existing completion state for dimensions that already exist
        existing: dict[str, ReconDimension] = {d.name: d for d in self.dimensions}
        self.dimensions = []
        for name, desc, _ in dim_defs:
            if name in existing:
                self.dimensions.append(existing[name])
            else:
                self.dimensions.append(ReconDimension(name=name, description=desc))
        self.initialized = True

    def get_dimension(self, name: str) -> ReconDimension | None:
        return next((d for d in self.dimensions if d.name == name), None)

    def mark_complete(self, name: str, evidence: str = "") -> bool:
        """Mark a named dimension as complete. Returns True if found."""
        dim = self.get_dimension(name)
        if dim:
            dim.mark_complete(evidence)
            return True
        return False

    def all_complete(self) -> bool:
        return all(d.completed for d in self.dimensions)

    def pending_dimensions(self) -> list[ReconDimension]:
        return [d for d in self.dimensions if not d.completed]

    def completed_dimensions(self) -> list[ReconDimension]:
        return [d for d in self.dimensions if d.completed]

    def completion_ratio(self) -> float:
        if not self.dimensions:
            return 0.0
        return len(self.completed_dimensions()) / len(self.dimensions)

    def auto_advance(self, facts: list[str]) -> list[str]:
        """Heuristically mark dimensions complete based on discovered facts.

        Call after each new fact is added to the board.
        Returns list of dimension names newly marked complete.
        """
        if not self.initialized:
            return []
        combined = " ".join(facts).lower()
        target_type = self.target_type
        dim_defs = _DIMENSION_DEFS.get(target_type, _FALLBACK_DIMS)
        newly_completed: list[str] = []

        for dim, (name, _desc, keywords) in zip(self.dimensions, dim_defs):
            if dim.completed:
                continue
            matched = [kw for kw in keywords if kw.lower() in combined]
            if len(matched) >= 2:  # Require at least 2 keyword matches
                evidence = f"关键词匹配: {', '.join(matched[:3])}"
                dim.mark_complete(evidence)
                newly_completed.append(name)

        return newly_completed

    def to_prompt_block(self) -> str:
        """Render current recon completion state for the agent's system prompt."""
        if not self.dimensions:
            return ""
        lines = [f"## 侦察完成度 ({self.target_type.upper()}) [{len(self.completed_dimensions())}/{len(self.dimensions)}]"]
        for dim in self.dimensions:
            icon = "✅" if dim.completed else "⬜"
            evidence = f" — {dim.completion_evidence[0]}" if dim.completion_evidence else ""
            lines.append(f"  {icon} {dim.name}: {dim.description}{evidence}")
        if self.pending_dimensions():
            lines.append(f"\n  下一个优先侦察维度: **{self.pending_dimensions()[0].name}**")
        return "\n".join(lines)

    def get_summary(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "total": len(self.dimensions),
            "completed": len(self.completed_dimensions()),
            "pending": [d.name for d in self.pending_dimensions()],
            "ratio": self.completion_ratio(),
        }

    # Legacy compatibility with the old recon_dimensions_completed dict API
    def legacy_dict(self) -> dict[str, bool]:
        """Return a flat {name: completed} dict for backward compatibility."""
        return {d.name: d.completed for d in self.dimensions}
