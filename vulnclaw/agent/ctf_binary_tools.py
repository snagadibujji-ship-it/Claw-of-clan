"""CTF binary exploitation tools: pwntools bridge, Z3 solver, ROPgadget, checksec."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from typing import Any

# ── Public registry ─────────────────────────────────────────────────

CTF_BINARY_TOOLS: dict[str, Any] = {
    "checksec_binary": {
        "description": "Run checksec on a binary to get security mitigations (PIE, NX, RELRO, canary, FORTIFY)",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "show_sections": {"type": "boolean", "default": False},
            },
            "required": ["binary_path"],
        },
    },
    "ropgadget_search": {
        "description": "Find ROP gadgets in a binary using ROPgadget or ropper",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "filter_regex": {"type": "string", "description": "e.g. 'pop rdi'"},
                "depth": {"type": "integer", "default": 5},
                "limit": {"type": "integer", "default": 30},
            },
            "required": ["binary_path"],
        },
    },
    "z3_solve": {
        "description": "Use Z3 SMT solver to find values satisfying constraints (reverse engineering, CrackMe)",
        "parameters": {
            "type": "object",
            "properties": {
                "constraints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Python-style Z3 constraint strings, e.g. ['x + y == 42', 'x > 0']",
                },
                "variables": {
                    "type": "object",
                    "description": "Variable definitions: {name: type} where type is 'Int'|'BitVec32'|'Real'|'Bool'",
                },
                "timeout_ms": {"type": "integer", "default": 10000},
            },
            "required": ["constraints", "variables"],
        },
    },
    "pwntools_exploit": {
        "description": "Run a pwntools-based exploit script against a local binary or remote service",
        "parameters": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "Python pwntools script body"},
                "binary_path": {"type": "string"},
                "remote_host": {"type": "string"},
                "remote_port": {"type": "integer"},
                "timeout": {"type": "integer", "default": 30},
                "args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["script"],
        },
    },
    "flag_hunter": {
        "description": "Aggressively search for CTF flags in binary output, strings, and environment",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "run_with_input": {"type": "string", "description": "stdin to feed the binary"},
                "search_in_strings": {"type": "boolean", "default": True},
                "search_in_env": {"type": "boolean", "default": True},
            },
            "required": ["binary_path"],
        },
    },
}


# ── Dispatcher ────────────────────────────────────────────────────────

async def dispatch(agent: Any, tool_name: str, args: dict[str, Any]) -> str | None:
    if tool_name == "checksec_binary":
        return await execute_checksec(args)
    if tool_name == "ropgadget_search":
        return await execute_ropgadget(args)
    if tool_name == "z3_solve":
        return await execute_z3_solve(args)
    if tool_name == "pwntools_exploit":
        return await execute_pwntools(args)
    if tool_name == "flag_hunter":
        return await execute_flag_hunter(args)
    return None


# ── Helpers ───────────────────────────────────────────────────────────

async def _run(cmd: list[str], stdin: str | None = None, timeout: int = 15) -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdin_bytes = stdin.encode() if stdin else None
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(stdin_bytes), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return "", "timeout", -1
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
    except FileNotFoundError as e:
        return "", str(e), 127


# ── checksec ─────────────────────────────────────────────────────────

async def execute_checksec(args: dict[str, Any]) -> str:
    path: str = args["binary_path"]
    show_sections: bool = args.get("show_sections", False)
    results: list[str] = [f"[checksec] {path}"]

    if shutil.which("checksec"):
        out, err, rc = await _run(["checksec", "--file", path])
        if rc == 0:
            results.append(out or err)
        else:
            results.append(f"  checksec error: {err}")
    else:
        results.append("  checksec not in PATH — using readelf fallback")
        out, err, _ = await _run(["readelf", "-l", path])
        if out:
            nx = "NX enabled" if "GNU_STACK" in out and "RW " not in out else "NX disabled"
            results.append(f"  {nx}")
        out2, _, _ = await _run(["objdump", "-d", path, "--section=.plt"])
        if "__stack_chk_fail" in out2:
            results.append("  Stack canary: detected")
        else:
            results.append("  Stack canary: not detected")
        out3, _, _ = await _run(["file", path])
        if "PIE" in out3 or "shared object" in out3:
            results.append("  PIE: enabled")
        else:
            results.append("  PIE: disabled")

    if show_sections:
        out4, _, _ = await _run(["readelf", "-S", path])
        results.append(f"\n  Sections:\n{out4[:800]}")

    out_str, _, _ = await _run(["strings", "-n", "8", path])
    strings_of_interest = [
        s for s in out_str.splitlines()
        if any(kw in s.lower() for kw in ("flag", "ctf", "password", "secret", "key", "token"))
    ]
    if strings_of_interest:
        results.append(f"\n  Interesting strings ({len(strings_of_interest)}):")
        for s in strings_of_interest[:10]:
            results.append(f"    {s}")

    return "\n".join(results)


# ── ROPgadget ─────────────────────────────────────────────────────────

async def execute_ropgadget(args: dict[str, Any]) -> str:
    path: str = args["binary_path"]
    filt: str = args.get("filter_regex", "")
    depth: int = args.get("depth", 5)
    limit: int = args.get("limit", 30)
    results: list[str] = [f"[ropgadget] {path}  filter={filt!r}"]

    tool = None
    if shutil.which("ROPgadget"):
        tool = "ROPgadget"
    elif shutil.which("ropper"):
        tool = "ropper"

    if tool == "ROPgadget":
        cmd = ["ROPgadget", "--binary", path, "--depth", str(depth)]
        if filt:
            cmd += ["--re", filt]
        out, err, rc = await _run(cmd, timeout=30)
    elif tool == "ropper":
        cmd = ["ropper", "--file", path]
        if filt:
            cmd += ["--search", filt]
        out, err, rc = await _run(cmd, timeout=30)
    else:
        results.append("  ROPgadget/ropper not found — using objdump gadget extraction")
        out, err, rc = await _run(["objdump", "-d", "-M", "intel", path])
        lines = out.splitlines()
        gadgets = []
        for i, line in enumerate(lines):
            if "ret" in line:
                start = max(0, i - 4)
                block = " ; ".join(l.split("\t")[-1].strip() for l in lines[start:i+1] if "\t" in l)
                if filt and not re.search(filt, block, re.I):
                    continue
                addr_m = re.search(r"([0-9a-f]+):", lines[i])
                if addr_m:
                    gadgets.append(f"  0x{addr_m.group(1)}: {block}")
        results.extend(gadgets[:limit])
        return "\n".join(results)

    if rc != 0:
        results.append(f"  error: {err[:300]}")
    else:
        lines = [l for l in out.splitlines() if l.strip()]
        if filt:
            lines = [l for l in lines if re.search(filt, l, re.I)]
        results.append(f"  Found {len(lines)} gadgets (showing first {limit})")
        results.extend(lines[:limit])

    return "\n".join(results)


# ── Z3 Solver ─────────────────────────────────────────────────────────

async def execute_z3_solve(args: dict[str, Any]) -> str:
    constraints: list[str] = args["constraints"]
    variables: dict[str, str] = args["variables"]
    timeout_ms: int = args.get("timeout_ms", 10000)

    # Build the Z3 Python script
    lines = [
        "from z3 import *",
        "import json",
        "s = Solver()",
        f"s.set('timeout', {timeout_ms})",
    ]
    var_names: list[str] = []
    for vname, vtype in variables.items():
        vname_safe = re.sub(r"\W", "_", vname)
        var_names.append(vname_safe)
        if vtype == "Int":
            lines.append(f"{vname_safe} = Int('{vname_safe}')")
        elif vtype.startswith("BitVec"):
            bits = int(re.search(r"\d+", vtype).group() or "32")
            lines.append(f"{vname_safe} = BitVec('{vname_safe}', {bits})")
        elif vtype == "Real":
            lines.append(f"{vname_safe} = Real('{vname_safe}')")
        elif vtype == "Bool":
            lines.append(f"{vname_safe} = Bool('{vname_safe}')")
        else:
            lines.append(f"{vname_safe} = Int('{vname_safe}')")

    for i, constraint in enumerate(constraints):
        safe_c = constraint.replace("\\", "\\\\").replace('"', '\\"')
        try:
            lines.append(f"s.add({constraint})")
        except Exception:
            lines.append(f"# could not add constraint: {constraint!r}")

    lines += [
        "result = s.check()",
        "if result == sat:",
        "    m = s.model()",
        "    sol = {str(d): str(m[d]) for d in m.decls()}",
        "    print('SAT')",
        "    print(json.dumps(sol))",
        "elif result == unsat:",
        "    print('UNSAT - no solution')",
        "else:",
        "    print('UNKNOWN - timeout or undecidable')",
    ]
    script = "\n".join(lines)

    out, err, rc = await _run(["python3", "-c", script], timeout=max(timeout_ms // 1000 + 5, 15))
    results = [f"[z3_solve] {len(constraints)} constraints, {len(variables)} variables"]
    if rc == 127 or "No module named" in err:
        results.append("  z3-solver not installed. Install with: pip install z3-solver")
        return "\n".join(results)
    if out.startswith("SAT"):
        lines_out = out.strip().splitlines()
        results.append("  *** SATISFIABLE ***")
        if len(lines_out) > 1:
            solution = json.loads(lines_out[1])
            for k, v in solution.items():
                results.append(f"    {k} = {v}")
    else:
        results.append(f"  {out.strip() or err.strip()}")

    return "\n".join(results)


# ── pwntools Exploit ──────────────────────────────────────────────────

async def execute_pwntools(args: dict[str, Any]) -> str:
    script: str = args["script"]
    binary_path: str | None = args.get("binary_path")
    remote_host: str | None = args.get("remote_host")
    remote_port: int | None = args.get("remote_port")
    timeout: int = args.get("timeout", 30)
    extra_args: list[str] = args.get("args") or []
    results: list[str] = ["[pwntools_exploit]"]

    # Inject connection setup at top if not present
    preamble_lines = ["from pwn import *", "context.log_level = 'info'"]
    if binary_path and "process(" not in script and "remote(" not in script:
        preamble_lines.append(f"io = process({binary_path!r})")
    elif remote_host and remote_port and "remote(" not in script:
        preamble_lines.append(f"io = remote({remote_host!r}, {remote_port})")

    preamble = "\n".join(preamble_lines)
    full_script = preamble + "\n" + script

    out, err, rc = await _run(
        ["python3", "-c", full_script] + extra_args,
        timeout=timeout,
    )
    if rc == 127 or "No module named 'pwn'" in err:
        results.append("  pwntools not installed. Install with: pip install pwntools")
        return "\n".join(results)

    combined = (out + err).strip()
    # Search for flags in output
    flag_patterns = [
        r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"NSSCTF\{[^}]+\}",
        r"picoCTF\{[^}]+\}", r"HTB\{[^}]+\}", r"THM\{[^}]+\}",
    ]
    flags_found = []
    for pat in flag_patterns:
        flags_found += re.findall(pat, combined, re.I)
    if flags_found:
        results.append(f"  *** FLAG(S) FOUND: {flags_found} ***")
    results.append(f"  Exit code: {rc}")
    results.append(f"  Output ({len(combined)} bytes):\n{combined[:1500]}")
    return "\n".join(results)


# ── Flag Hunter ───────────────────────────────────────────────────────

_FLAG_REGEXES = [
    r"flag\{[^}]{1,64}\}",
    r"CTF\{[^}]{1,64}\}",
    r"NSSCTF\{[^}]{1,64}\}",
    r"picoCTF\{[^}]{1,64}\}",
    r"HTB\{[^}]{1,64}\}",
    r"THM\{[^}]{1,64}\}",
    r"DUCTF\{[^}]{1,64}\}",
    r"[A-Za-z0-9_]+CTF\{[^}]{1,64}\}",
]
_FLAG_RE = re.compile("|".join(_FLAG_REGEXES), re.I)


async def execute_flag_hunter(args: dict[str, Any]) -> str:
    path: str = args["binary_path"]
    stdin_input: str | None = args.get("run_with_input")
    search_strings: bool = args.get("search_in_strings", True)
    search_env: bool = args.get("search_in_env", True)
    results: list[str] = [f"[flag_hunter] {path}"]

    # 1. strings scan
    if search_strings:
        out, _, _ = await _run(["strings", "-n", "4", path])
        flags_in_strings = _FLAG_RE.findall(out)
        results.append(f"  strings scan: {len(out.splitlines())} strings, {len(flags_in_strings)} flag hits")
        for f in flags_in_strings:
            results.append(f"    *** {f}")

    # 2. run binary with optional input
    run_cmd = [path]
    env_extra = {}
    if search_env:
        import os
        env_extra = {**dict(os.environ), "FLAG": "test_flag{placeholder}"}
    try:
        proc = await asyncio.create_subprocess_exec(
            *run_cmd,
            stdin=asyncio.subprocess.PIPE if stdin_input else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env_extra or None,
        )
        try:
            stdin_bytes = stdin_input.encode() if stdin_input else None
            stdout, stderr = await asyncio.wait_for(proc.communicate(stdin_bytes), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = b"", b"timeout"
        combined = (stdout + stderr).decode(errors="replace")
        flags_in_output = _FLAG_RE.findall(combined)
        results.append(f"  runtime output: {len(combined)} bytes, {len(flags_in_output)} flag hits")
        for f in flags_in_output:
            results.append(f"    *** {f}")
        results.append(f"  sample output: {combined[:400]}")
    except PermissionError:
        results.append("  binary not executable — chmod +x first")
    except FileNotFoundError:
        results.append("  binary not found at path")

    # 3. ltrace / strace if available
    for tracer in ("ltrace", "strace"):
        if shutil.which(tracer):
            out_t, _, _ = await _run([tracer, "-e", "strcmp", path], timeout=5)
            flags_traced = _FLAG_RE.findall(out_t)
            if flags_traced:
                results.append(f"  {tracer} flags: {flags_traced}")
            break

    return "\n".join(results)
