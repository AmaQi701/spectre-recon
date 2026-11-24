"""
SPECTRE Intra-Procedural AST Taint-Flow & Sanitizer-Aware SAST Engine v3
========================================================================
Eliminates single-line regex blind spots and false positives by:
  1. Tracking multi-line variable taint flow inside Python functions via `ast`;
  2. Suppressing safe parameterized SQL (`cursor.execute("... %s", (uid,))`);
  3. Suppressing sanitized DOM assignments (`DOMPurify.sanitize(...)`).
"""
from __future__ import annotations

import ast
import re
from typing import Any

_SQL_KW_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.I)
_DOM_SANITIZER_RE = re.compile(r"(?i)(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|xss)\s*\(")
_SAFE_INFRA_PARAMS = {"self", "cls", "db", "conn", "cursor", "cur", "session", "log", "logger"}


def _expr_uses_names(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(sub, ast.Name) and sub.id in names for sub in ast.walk(node))


def _expr_is_external_source(node: ast.AST) -> bool:
    src = ast.unparse(node) if hasattr(ast, "unparse") else ""
    return any(tok in src for tok in ("request.", "req.", "sys.argv", "os.environ", "input("))


def _expr_is_formatted_sql(node: ast.AST, tainted: set[str]) -> bool:
    if isinstance(node, ast.JoinedStr):
        const_part = " ".join(c.value for c in node.values if isinstance(c, ast.Constant) and isinstance(c.value, str))
        has_fv = any(isinstance(c, ast.FormattedValue) and (_expr_uses_names(c.value, tainted) or _expr_is_external_source(c.value)) for c in node.values)
        return bool(_SQL_KW_RE.search(const_part)) and has_fv
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        raw_s = ast.unparse(node) if hasattr(ast, "unparse") else ""
        return bool(_SQL_KW_RE.search(raw_s)) and (_expr_uses_names(node, tainted) or _expr_is_external_source(node))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        raw_s = ast.unparse(node.func.value) if hasattr(ast, "unparse") else ""
        return bool(_SQL_KW_RE.search(raw_s)) and any(_expr_uses_names(a, tainted) or _expr_is_external_source(a) for a in node.args + [kw.value for kw in node.keywords])
    return False


def is_sanitized_sast_line(line: str, rule_title: str) -> bool:
    if "DOM-Based XSS" in rule_title and _DOM_SANITIZER_RE.search(line):
        return True
    if "SQL Injection" in rule_title:
        if re.search(r"""(?i)(?:execute|query)\s*\(\s*['"][^'"{}+]*%s[^'"{}+]*['"]\s*,\s*[\(\[]""", line):
            return True
    return False


def analyze_python_ast_taint(src_text: str) -> tuple[list[dict[str, Any]], set[int]]:
    """Returns `(multiline_ast_findings, safe_parameterized_sql_lines)`."""
    try:
        tree = ast.parse(src_text)
    except Exception:
        return [], set()

    findings: list[dict[str, Any]] = []
    safe_sql_lines: set[int] = set()
    seen_lines: set[tuple[int, str]] = set()

    scopes: list[tuple[list[ast.stmt], set[str]]] = [(tree.body, set())]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arg_names = {a.arg for a in node.args.args if a.arg not in _SAFE_INFRA_PARAMS}
            scopes.append((node.body, arg_names))

    for stmts, init_taint in scopes:
        tainted = set(init_taint)
        sql_tainted: set[str] = set()

        for stmt in stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Assign):
                    val = sub.value
                    is_sql_t = _expr_is_formatted_sql(val, tainted)
                    is_gen_t = is_sql_t or _expr_uses_names(val, tainted) or _expr_is_external_source(val)
                    for tgt in sub.targets:
                        if isinstance(tgt, ast.Name):
                            if is_sql_t:
                                sql_tainted.add(tgt.id)
                            if is_gen_t:
                                tainted.add(tgt.id)

                elif isinstance(sub, ast.Call):
                    fn_s = ast.unparse(sub.func) if hasattr(ast, "unparse") else ""
                    attr_nm = sub.func.attr if isinstance(sub.func, ast.Attribute) else fn_s

                    if attr_nm in ("execute", "executemany") and len(sub.args) >= 2 and isinstance(sub.args[0], ast.Constant):
                        safe_sql_lines.add(sub.lineno)
                        continue

                    if attr_nm in ("execute", "raw") and sub.args and isinstance(sub.args[0], ast.Name) and sub.args[0].id in sql_tainted:
                        key = (sub.lineno, "CWE-89")
                        if key not in seen_lines:
                            seen_lines.add(key)
                            findings.append({
                                "lineno": sub.lineno,
                                "title": "Potential SQL Injection (AST Multi-Line Data-Flow)",
                                "category": "Injection (SAST)", "severity": "High", "cvss": 8.6,
                                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                                "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                                "remediation": "Parametrlangan so'rovlar (`cursor.execute(sql, (param,))`) ishlating.",
                            })

                    if (fn_s == "os.system" or (fn_s.startswith("subprocess.") and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in sub.keywords))):
                        if sub.args and isinstance(sub.args[0], ast.Name) and sub.args[0].id in tainted:
                            key = (sub.lineno, "CWE-78")
                            if key not in seen_lines:
                                seen_lines.add(key)
                                findings.append({
                                    "lineno": sub.lineno,
                                    "title": "Potential OS Command Injection Sink (AST Multi-Line Data-Flow)",
                                    "category": "RCE / Command Injection (SAST)", "severity": "Critical", "cvss": 9.8,
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "cwe": "CWE-78", "owasp": "A03:2021 - Injection",
                                    "remediation": "`shell=True` o'rniga argumentlar massivini ishlating.",
                                })

                    if fn_s in ("requests.get", "requests.post", "requests.request", "urllib.request.urlopen"):
                        if sub.args and isinstance(sub.args[0], ast.Name) and sub.args[0].id in tainted:
                            key = (sub.lineno, "CWE-918")
                            if key not in seen_lines:
                                seen_lines.add(key)
                                findings.append({
                                    "lineno": sub.lineno,
                                    "title": "Potential Server-Side Request Forgery (SSRF) Sink",
                                    "category": "SSRF (SAST)", "severity": "High", "cvss": 8.2,
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                                    "cwe": "CWE-918", "owasp": "A10:2021 - Server-Side Request Forgery",
                                    "remediation": "Chiquvchi URL manzillarini allowlist bilan tekshiring.",
                                })

    return findings, safe_sql_lines

