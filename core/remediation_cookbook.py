"""
SPECTRE 1-Click Read-Only Verification Reproducer & Auto-Remediation Cookbook
=============================================================================
Generates deterministic, non-destructive verification commands (`curl`,
`openssl s_client`, `nc`) and ready-to-apply defensive configuration/code
patches for every verified finding in HTML, CLI, and SARIF reports.
"""
from __future__ import annotations

import shlex
import urllib.parse
from typing import Any


def build_safe_reproducer(finding: dict[str, Any]) -> str:
    """Builds a read-only, copy-pasteable verification command for a finding."""
    asset = str(finding.get("asset") or "").strip()
    title = str(finding.get("title") or "").lower()
    cat = str(finding.get("category") or "").lower()

    if asset.startswith(("http://", "https://")):
        q_url = shlex.quote(asset)
        if "mcp" in title and "tool server" in title:
            return (
                f"curl -i -s -k -m 8 -X POST {q_url} "
                "-H 'Content-Type: application/json' "
                "-d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'"
            )
        if "cors" in title:
            return f"curl -i -s -k -m 8 -H 'Origin: https://audit-check.example.org' {q_url}"
        if "x-forwarded-host" in title:
            return f"curl -i -s -k -m 8 -H 'X-Forwarded-Host: audit-check.example.org' {q_url}"
        if "graphql" in title and "batch" in title:
            return (
                f"curl -i -s -k -m 8 -X POST {q_url} "
                "-H 'Content-Type: application/json' "
                "-d '[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]'"
            )
        if "tls" in cat or "certificate" in title:
            p = urllib.parse.urlparse(asset)
            hp = p.netloc if ":" in p.netloc else f"{p.hostname}:{'443' if p.scheme == 'https' else '80'}"
            return f"openssl s_client -connect {shlex.quote(hp)} -servername {shlex.quote(p.hostname or '')} </dev/null"
        return f"curl -i -s -k -m 8 {q_url}"

    if ":" in asset and not asset.startswith("/") and "/" not in asset:
        host_p, port_p = asset.rsplit(":", 1)
        if port_p.isdigit() and " " not in host_p:
            qh = shlex.quote(host_p)
            if port_p == "6379":
                return f"printf 'INFO server\\r\\nQUIT\\r\\n' | nc -w 3 {qh} 6379"
            if port_p in ("22", "1022"):
                return f"ssh -vvv -o BatchMode=yes -o ConnectTimeout=4 {qh} -p {port_p} 2>&1 | grep -i kex"
            return f"nc -vz -w 3 {qh} {port_p}"

    if ":" in asset and ("/" in asset or "\\" in asset):
        fpath, ln_s = asset.rsplit(":", 1)
        if ln_s.isdigit():
            ln = int(ln_s)
            lo = max(1, ln - 3)
            hi = ln + 3
            return f"sed -n '{lo},{hi}p' {shlex.quote(fpath)}"

    if asset:
        return f"ls -la {shlex.quote(asset)}"
    return "# Passive correlation finding — inspect linked asset telemetry"


def build_fix_patch_snippet(finding: dict[str, Any]) -> str:
    """Returns a ready-to-apply secure code or infrastructure patch snippet."""
    cwe = str(finding.get("cwe") or "").upper()
    cat = str(finding.get("category") or "").lower()
    title = str(finding.get("title") or "").lower()

    if cwe == "CWE-89" or "sql injection" in title:
        return (
            "# Parameterized Query Fix (Zero SQL Concatenation):\n"
            "cursor.execute('SELECT id, role FROM accounts WHERE id = %s', (account_id,))"
        )
    if cwe == "CWE-78" or "command injection" in title:
        return (
            "# Safe Subprocess Array Execution (No Shell Interpolation):\n"
            "subprocess.run(['/usr/bin/tool', '--id', str(safe_id)], shell=False, check=True)"
        )
    if cwe == "CWE-79" or "xss" in title or "reflection" in title:
        return (
            "/* Contextual Output Encoding + CSP */\n"
            "element.textContent = untrustedInput;\n"
            "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self';"
        )
    import re as _re
    if _re.search(r"\b(?:ai|llm|mcp|rag)\b", cat) or "ollama" in title or "qdrant" in title:
        return (
            "# Bind AI/MCP Runtime to Loopback + Enforce Bearer Auth:\n"
            "OLLAMA_HOST=127.0.0.1:11434\n"
            "# Nginx Guard: if ($http_authorization = '') { return 401; }"
        )
    if "iac" in cat or cwe == "CWE-250" or "kubernetes" in title or "container" in title:
        return (
            "securityContext:\n"
            "  runAsNonRoot: true\n"
            "  privileged: false\n"
            "  allowPrivilegeEscalation: false\n"
            "  capabilities: { drop: [\"ALL\"] }"
        )
    if cwe in ("CWE-319", "CWE-326", "CWE-327", "CWE-295") or "tls" in title:
        return (
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;"
        )
    if cwe in ("CWE-1104", "CWE-1395") or "sca" in cat or "dependencies" in title or "outdated" in title:
        return (
            "# Upgrade Pinned Dependency & Gate CI Pipeline:\n"
            "pip install --upgrade <package> && pip-audit --strict"
        )
    return str(finding.get("remediation") or "Apply vendor security hardening baseline.")
