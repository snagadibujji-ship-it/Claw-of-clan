"""OSINT tools: WHOIS, cert transparency, subdomain takeover, GitHub dorking, Shodan-lite."""

from __future__ import annotations

import asyncio
import json
import re
import socket
import subprocess
import shutil
from typing import Any

import httpx

OSINT_TOOLS: dict[str, Any] = {
    "whois_lookup": {
        "description": "WHOIS lookup for a domain or IP — registrar, nameservers, org, creation date",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    "cert_transparency": {
        "description": "Query crt.sh for all SSL certificates issued for a domain — reveals subdomains",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "include_expired": {"type": "boolean", "default": False},
            },
            "required": ["domain"],
        },
    },
    "subdomain_takeover": {
        "description": "Check a list of subdomains for dangling DNS / subdomain takeover indicators",
        "parameters": {
            "type": "object",
            "properties": {
                "subdomains": {"type": "array", "items": {"type": "string"}},
                "domain": {"type": "string", "description": "Auto-enumerate via crt.sh if no subdomains given"},
            },
            "required": [],
        },
    },
    "github_dork": {
        "description": "Search GitHub for secrets/config leaks related to a target domain or org",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "e.g. 'example.com password' or 'org:acme secret'"},
                "max_results": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    "shodan_lite": {
        "description": "Query Shodan InternetDB (no API key) for open ports, CVEs, tags on an IP",
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    "dns_recon": {
        "description": "Full DNS recon: A, AAAA, MX, NS, TXT, CNAME, SPF, DMARC, zone transfer attempt",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "try_zone_transfer": {"type": "boolean", "default": True},
            },
            "required": ["domain"],
        },
    },
}

# ── Dispatcher ────────────────────────────────────────────────────────

async def dispatch(agent: Any, tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "whois_lookup":
        return await execute_whois(args)
    if tool_name == "cert_transparency":
        return await execute_cert_transparency(args)
    if tool_name == "subdomain_takeover":
        return await execute_subdomain_takeover(args)
    if tool_name == "github_dork":
        return await execute_github_dork(args)
    if tool_name == "shodan_lite":
        return await execute_shodan_lite(args)
    if tool_name == "dns_recon":
        return await execute_dns_recon(args)
    return None

# ── WHOIS ─────────────────────────────────────────────────────────────

async def execute_whois(args: dict[str, Any]) -> str:
    target: str = args["target"].strip()
    results = [f"[whois_lookup] {target}"]
    if shutil.which("whois"):
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            text = stdout.decode(errors="replace")
            keep = []
            for line in text.splitlines():
                llow = line.lower()
                if any(k in llow for k in (
                    "registrar", "creation", "expir", "updated", "name server",
                    "org", "country", "registrant", "admin", "tech", "abuse",
                    "status", "dnssec",
                )):
                    keep.append(f"  {line.strip()}")
            results.extend(keep[:40])
        except asyncio.TimeoutError:
            results.append("  timeout")
    else:
        results.append("  whois not in PATH — using RDAP fallback")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://rdap.org/domain/{target}")
                if resp.status_code == 200:
                    data = resp.json()
                    results.append(f"  Name: {data.get('ldhName', target)}")
                    for event in data.get("events", []):
                        results.append(f"  {event['eventAction']}: {event['eventDate']}")
                    for entity in data.get("entities", [])[:3]:
                        roles = entity.get("roles", [])
                        card = entity.get("vcardArray", [None, []])[1]
                        name = next((c[3] for c in card if c[0] == "fn"), "?")
                        results.append(f"  Entity [{', '.join(roles)}]: {name}")
        except Exception as exc:
            results.append(f"  RDAP error: {exc}")
    return "\n".join(results)

# ── Certificate Transparency ──────────────────────────────────────────

async def execute_cert_transparency(args: dict[str, Any]) -> str:
    domain: str = args["domain"].strip().lstrip("*.")
    include_expired: bool = args.get("include_expired", False)
    results = [f"[cert_transparency] {domain}"]
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return f"[cert_transparency] crt.sh returned {resp.status_code}"
            certs = resp.json()
    except Exception as exc:
        return f"[cert_transparency] error: {exc}"

    subdomains: set[str] = set()
    for c in certs:
        name = c.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lstrip("*.")
            if sub and domain in sub:
                subdomains.add(sub)

    results.append(f"  Unique names: {len(subdomains)}  (from {len(certs)} cert records)")
    for sub in sorted(subdomains)[:60]:
        results.append(f"  {sub}")
    if len(subdomains) > 60:
        results.append(f"  ... and {len(subdomains) - 60} more")
    return "\n".join(results)

# ── Subdomain Takeover ────────────────────────────────────────────────

_TAKEOVER_FINGERPRINTS: list[tuple[str, str]] = [
    ("There is no app here", "Heroku"),
    ("NoSuchBucket", "AWS S3"),
    ("The specified bucket does not exist", "AWS S3"),
    ("Repository not found", "GitHub Pages"),
    ("The page you're looking for doesn't exist", "GitHub Pages"),
    ("project not found", "GitLab Pages"),
    ("Unrecognized domain", "Shopify"),
    ("Sorry, We Couldn't Find That Page", "Tumblr"),
    ("This UserVoice subdomain is currently available", "UserVoice"),
    ("This domain is not configured", "Azure"),
    ("404 Not Found", "generic-404"),
]

async def _check_takeover(client: httpx.AsyncClient, sub: str) -> str:
    try:
        ip = socket.gethostbyname(sub)
    except socket.gaierror:
        return f"  [NXDOMAIN] {sub}  ← DNS does not resolve — TAKEOVER CANDIDATE"
    try:
        r = await client.get(f"http://{sub}", follow_redirects=True)
        body = r.text
        for fingerprint, service in _TAKEOVER_FINGERPRINTS:
            if fingerprint.lower() in body.lower():
                return f"  [VULN] {sub} ({ip}) — {service} takeover pattern detected *** "
        return f"  [OK]   {sub} ({ip}) — HTTP {r.status_code}"
    except Exception:
        return f"  [ERR]  {sub} ({ip}) — connection failed"

async def execute_subdomain_takeover(args: dict[str, Any]) -> str:
    subdomains: list[str] = args.get("subdomains") or []
    domain: str = args.get("domain", "")
    if not subdomains and domain:
        ct_result = await execute_cert_transparency({"domain": domain})
        subdomains = [
            line.strip() for line in ct_result.splitlines()
            if line.strip() and not line.startswith("[") and not line.startswith(" ")
        ]
        subdomains = [s for s in subdomains if domain in s][:30]

    if not subdomains:
        return "[subdomain_takeover] No subdomains to check — provide 'subdomains' list or 'domain'"

    results = [f"[subdomain_takeover] Checking {len(subdomains)} subdomains"]
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        tasks = [_check_takeover(client, s) for s in subdomains]
        for r in await asyncio.gather(*tasks, return_exceptions=True):
            results.append(str(r))
    return "\n".join(results)

# ── GitHub Dorking ────────────────────────────────────────────────────

_DORK_QUERIES = [
    "{query} password",
    "{query} secret",
    "{query} api_key",
    "{query} token",
    "{query} .env",
    "{query} credentials",
]

async def execute_github_dork(args: dict[str, Any]) -> str:
    base_query: str = args["query"]
    max_results: int = args.get("max_results", 10)
    results = [f"[github_dork] query={base_query!r}"]

    async with httpx.AsyncClient(timeout=15, headers={
        "User-Agent": "Mozilla/5.0 (GHIA Scout/3.0)",
        "Accept": "application/vnd.github+json",
    }) as client:
        for dork_tmpl in _DORK_QUERIES[:3]:
            q = dork_tmpl.format(query=base_query)
            try:
                resp = await client.get(
                    "https://api.github.com/search/code",
                    params={"q": q, "per_page": max_results},
                )
                if resp.status_code == 403:
                    results.append(f"  [{q}] rate-limited by GitHub (unauthenticated)")
                    break
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    items = data.get("items", [])
                    results.append(f"  [{q}] {total} results:")
                    for item in items[:5]:
                        repo = item.get("repository", {}).get("full_name", "?")
                        path = item.get("path", "?")
                        url = item.get("html_url", "")
                        results.append(f"    {repo}/{path}  {url}")
                else:
                    results.append(f"  [{q}] HTTP {resp.status_code}")
            except Exception as exc:
                results.append(f"  [{q}] error: {exc}")
    return "\n".join(results)

# ── Shodan InternetDB (no API key) ────────────────────────────────────

async def execute_shodan_lite(args: dict[str, Any]) -> str:
    ip: str = args["ip"].strip()
    results = [f"[shodan_lite] {ip}"]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                results.append(f"  Open ports: {data.get('ports', [])}")
                results.append(f"  Hostnames:  {data.get('hostnames', [])}")
                results.append(f"  Tags:       {data.get('tags', [])}")
                cpes = data.get("cpes", [])
                vulns = data.get("vulns", [])
                if cpes:
                    results.append(f"  CPEs: {cpes[:5]}")
                if vulns:
                    results.append(f"  *** CVEs ({len(vulns)}): {vulns[:10]}")
            elif resp.status_code == 404:
                results.append("  No Shodan data for this IP")
            else:
                results.append(f"  HTTP {resp.status_code}")
    except Exception as exc:
        results.append(f"  error: {exc}")
    return "\n".join(results)

# ── DNS Recon ──────────────────────────────────────────────────────────

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

async def _dig(domain: str, rtype: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    proc = await asyncio.create_subprocess_exec(
        "dig", "+short", domain, rtype,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        return [l for l in stdout.decode(errors="replace").splitlines() if l.strip()]
    except asyncio.TimeoutError:
        return []

async def execute_dns_recon(args: dict[str, Any]) -> str:
    domain: str = args["domain"].strip()
    try_zt: bool = args.get("try_zone_transfer", True)
    results = [f"[dns_recon] {domain}"]

    record_tasks = [_dig(domain, rt) for rt in _DNS_RECORD_TYPES]
    record_results = await asyncio.gather(*record_tasks, return_exceptions=True)
    for rt, rr in zip(_DNS_RECORD_TYPES, record_results):
        if isinstance(rr, list) and rr:
            for rec in rr:
                results.append(f"  {rt:6} {rec}")
            # SPF / DMARC check
            if rt == "TXT":
                for rec in rr:
                    if "v=spf1" in rec.lower():
                        results.append(f"  SPF: {rec}")
            if rt == "TXT" and domain.startswith("_dmarc"):
                results.append(f"  DMARC: {rr[0]}")
        elif isinstance(rr, Exception):
            results.append(f"  {rt}: error {rr}")

    # Check _dmarc
    dmarc = await _dig(f"_dmarc.{domain}", "TXT")
    if dmarc:
        results.append(f"  DMARC: {dmarc[0]}")
    else:
        results.append("  DMARC: NOT FOUND — email spoofing may be possible")

    # Zone transfer attempt
    if try_zt and shutil.which("dig"):
        ns_records = await _dig(domain, "NS")
        for ns in ns_records[:3]:
            ns = ns.rstrip(".")
            proc = await asyncio.create_subprocess_exec(
                "dig", "AXFR", domain, f"@{ns}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                text = stdout.decode(errors="replace")
                if "Transfer failed" not in text and len(text.splitlines()) > 3:
                    results.append(f"  *** ZONE TRANSFER SUCCEEDED via {ns} ***")
                    results.extend(f"    {l}" for l in text.splitlines()[:20])
                else:
                    results.append(f"  Zone transfer refused by {ns}")
            except asyncio.TimeoutError:
                results.append(f"  Zone transfer timeout: {ns}")

    return "\n".join(results)
