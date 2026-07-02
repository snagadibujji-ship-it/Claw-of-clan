"""Cloud misconfiguration scanner: S3, GCS, Azure Blob, IAM, metadata service."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx

CLOUD_TOOLS: dict[str, Any] = {
    "s3_enum": {
        "description": "Enumerate S3 buckets for a target — public access, ACL, listing, sensitive files",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or company name to derive bucket names"},
                "bucket_names": {"type": "array", "items": {"type": "string"}, "description": "Explicit bucket names to try"},
                "region": {"type": "string", "default": "us-east-1"},
                "check_common_files": {"type": "boolean", "default": True},
            },
            "required": ["target"],
        },
    },
    "gcs_enum": {
        "description": "Enumerate Google Cloud Storage buckets for a target",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "bucket_names": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
        },
    },
    "azure_enum": {
        "description": "Enumerate Azure Blob Storage containers and Storage Accounts",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "storage_accounts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
        },
    },
    "cloud_metadata_probe": {
        "description": "Probe cloud instance metadata endpoints (AWS/GCP/Azure/DO/Alibaba) for IMDS data",
        "parameters": {
            "type": "object",
            "properties": {
                "providers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["aws", "gcp", "azure", "alibaba", "do"],
                },
            },
        },
    },
}

# ── Dispatcher ────────────────────────────────────────────────────────

async def dispatch(agent: Any, tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "s3_enum":
        return await execute_s3_enum(args)
    if tool_name == "gcs_enum":
        return await execute_gcs_enum(args)
    if tool_name == "azure_enum":
        return await execute_azure_enum(args)
    if tool_name == "cloud_metadata_probe":
        return await execute_metadata_probe(args)
    return None

# ── S3 Enumeration ────────────────────────────────────────────────────

_S3_SUFFIXES = [
    "", "-backup", "-backups", "-bak", "-dev", "-staging", "-prod",
    "-assets", "-static", "-files", "-uploads", "-data", "-logs",
    "-config", "-secrets", "-internal", "-private", "-public",
    ".com", "-cdn", "-media", "-images", "-docs", "-archive",
]
_S3_SENSITIVE_PATHS = [
    "credentials", ".env", "config.json", "secrets.json", "backup.sql",
    "database.sql", ".git/config", "wp-config.php", "settings.py",
    "keys.json", "private.pem", "id_rsa",
]

def _derive_bucket_names(target: str) -> list[str]:
    slug = re.sub(r"[^a-z0-9\-]", "-", target.lower().replace(".", "-"))
    slug = re.sub(r"-+", "-", slug).strip("-")
    return [slug + suf for suf in _S3_SUFFIXES[:8]]

async def _probe_s3(client: httpx.AsyncClient, bucket: str, region: str) -> dict:
    urls = [
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}/",
        f"https://{bucket}.s3.{region}.amazonaws.com/",
    ]
    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True)
            body = r.text
            if r.status_code == 200 and "<ListBucketResult" in body:
                keys = re.findall(r"<Key>([^<]+)</Key>", body)
                return {"bucket": bucket, "status": "PUBLIC_LISTED", "url": url, "keys": keys[:20]}
            elif r.status_code == 403:
                return {"bucket": bucket, "status": "EXISTS_PRIVATE", "url": url}
            elif r.status_code == 404:
                pass
            elif "NoSuchBucket" in body:
                pass
        except Exception:
            pass
    return {"bucket": bucket, "status": "NOT_FOUND"}

async def execute_s3_enum(args: dict[str, Any]) -> str:
    target: str = args["target"]
    explicit: list[str] = args.get("bucket_names") or []
    region: str = args.get("region", "us-east-1")
    check_files: bool = args.get("check_common_files", True)
    bucket_names = explicit or _derive_bucket_names(re.sub(r"https?://", "", target))
    results = [f"[s3_enum] {target}  testing {len(bucket_names)} bucket names"]

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        probes = await asyncio.gather(*[_probe_s3(client, b, region) for b in bucket_names], return_exceptions=True)
        for p in probes:
            if isinstance(p, Exception):
                continue
            status = p.get("status", "?")
            bucket = p.get("bucket", "?")
            url = p.get("url", "")
            if status == "PUBLIC_LISTED":
                keys = p.get("keys", [])
                results.append(f"  *** PUBLIC LISTING: {bucket}  ({len(keys)} objects)")
                for k in keys[:10]:
                    results.append(f"      {k}")
                if check_files:
                    for path in _S3_SENSITIVE_PATHS[:5]:
                        try:
                            r = await client.get(f"https://{bucket}.s3.amazonaws.com/{path}")
                            if r.status_code == 200:
                                results.append(f"    *** SENSITIVE FILE: {path}  ({len(r.text)} bytes)")
                        except Exception:
                            pass
            elif status == "EXISTS_PRIVATE":
                results.append(f"  EXISTS (private): {bucket}  {url}")
            # NOT_FOUND: skip

    return "\n".join(results)

# ── GCS Enumeration ───────────────────────────────────────────────────

def _derive_gcs_names(target: str) -> list[str]:
    slug = re.sub(r"[^a-z0-9\-]", "-", target.lower().replace(".", "-")).strip("-")
    return [slug + s for s in ["", "-backup", "-dev", "-public", "-storage", "-data"]]

async def execute_gcs_enum(args: dict[str, Any]) -> str:
    target: str = args["target"]
    explicit: list[str] = args.get("bucket_names") or []
    names = explicit or _derive_gcs_names(re.sub(r"https?://", "", target))
    results = [f"[gcs_enum] {target}  testing {len(names)} bucket names"]

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        for name in names:
            urls = [
                f"https://storage.googleapis.com/{name}/",
                f"https://{name}.storage.googleapis.com/",
            ]
            for url in urls:
                try:
                    r = await client.get(url)
                    body = r.text
                    if r.status_code == 200 and "ListBucketResult" in body:
                        keys = re.findall(r"<Key>([^<]+)</Key>", body)
                        results.append(f"  *** PUBLIC LISTING: {name}  ({len(keys)} objects)")
                        for k in keys[:10]:
                            results.append(f"    {k}")
                        break
                    elif r.status_code == 403:
                        results.append(f"  EXISTS (private): {name}")
                        break
                    elif r.status_code == 404 or "NoSuchBucket" in body:
                        pass
                except Exception:
                    pass

    return "\n".join(results)

# ── Azure Blob Enumeration ─────────────────────────────────────────────

def _derive_azure_names(target: str) -> list[str]:
    slug = re.sub(r"[^a-z0-9]", "", target.lower().replace(".", ""))
    return [slug + s for s in ["", "storage", "backup", "dev", "assets", "static"]]

async def execute_azure_enum(args: dict[str, Any]) -> str:
    target: str = args["target"]
    explicit: list[str] = args.get("storage_accounts") or []
    accounts = explicit or _derive_azure_names(re.sub(r"https?://", "", target))
    results = [f"[azure_enum] {target}  testing {len(accounts)} storage accounts"]
    containers = ["backups", "backup", "public", "files", "data", "logs", "web", "$web", "images"]

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        for acct in accounts:
            base = f"https://{acct}.blob.core.windows.net"
            for container in containers[:5]:
                url = f"{base}/{container}?restype=container&comp=list"
                try:
                    r = await client.get(url)
                    body = r.text
                    if r.status_code == 200 and "<EnumerationResults" in body:
                        blobs = re.findall(r"<Name>([^<]+)</Name>", body)
                        results.append(f"  *** PUBLIC CONTAINER: {acct}/{container}  ({len(blobs)} blobs)")
                        for b in blobs[:8]:
                            results.append(f"    {base}/{container}/{b}")
                    elif r.status_code == 403:
                        results.append(f"  EXISTS (private): {acct}/{container}")
                except Exception:
                    pass

    return "\n".join(results)

# ── Cloud Metadata Probe ──────────────────────────────────────────────

_METADATA_ENDPOINTS: dict[str, list[tuple[str, dict[str, str]]]] = {
    "aws": [
        ("http://169.254.169.254/latest/meta-data/", {}),
        ("http://169.254.169.254/latest/meta-data/iam/info", {}),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
        ("http://169.254.169.254/latest/user-data", {}),
        ("http://169.254.169.254/latest/dynamic/instance-identity/document", {}),
    ],
    "gcp": [
        ("http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"}),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id", {"Metadata-Flavor": "Google"}),
    ],
    "azure": [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", {"Metadata": "true"}),
    ],
    "alibaba": [
        ("http://100.100.100.200/latest/meta-data/", {}),
        ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", {}),
    ],
    "do": [
        ("http://169.254.169.254/metadata/v1/", {}),
        ("http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address", {}),
    ],
}

async def _metadata_probe(client: httpx.AsyncClient, provider: str, url: str, headers: dict) -> str:
    try:
        r = await client.get(url, headers={**headers, "User-Agent": "curl/7.68.0"})
        if r.status_code == 200 and len(r.text) > 0:
            snippet = r.text[:200].replace("\n", " ")
            return f"  *** HIT [{provider}] {url}\n    {snippet}"
        return f"  [{provider}] {url} → HTTP {r.status_code}"
    except httpx.TimeoutException:
        return f"  [{provider}] {url} → timeout"
    except Exception as exc:
        return f"  [{provider}] {url} → {exc}"

async def execute_metadata_probe(args: dict[str, Any]) -> str:
    providers: list[str] = args.get("providers") or ["aws", "gcp", "azure", "alibaba", "do"]
    results = [f"[cloud_metadata_probe] Probing {providers}"]

    tasks = []
    labels = []
    for provider in providers:
        for url, headers in _METADATA_ENDPOINTS.get(provider, []):
            tasks.append((provider, url, headers))

    async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=False) as client:
        gathered = await asyncio.gather(
            *[_metadata_probe(client, p, u, h) for p, u, h in tasks],
            return_exceptions=True,
        )
        for r in gathered:
            results.append(str(r))

    return "\n".join(results)
