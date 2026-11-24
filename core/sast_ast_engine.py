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
        if re.search(r"""(?i)(?:execute|query)\s*\(\s*['"`][^'"`{}+]*(?:%s|\?|\$\d+)[^'"`{}+]*['"`]\s*,\s*[\(\[]""", line):
            return True
    return False


_JS_DECL_RE = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?\s*$")
_JS_CONST_LIT_RE = re.compile(r"""^(?:""|''|``|"[^"$+{]*"|'[^'$+{]*'|`[^`$]*`|\d+|true|false|null)$""")
_JS_REQ_SRC_RE = re.compile(r"\b(?:req\.(?:query|body|params|headers)|request\.(?:query|body|params)|ctx\.query)\b")
_JS_DOM_SRC_RE = re.compile(r"\b(?:location\.(?:search|hash|href)|window\.name|URLSearchParams|event\.data)\b")


def analyze_js_ts_taint_flow(src_text: str) -> tuple[list[dict[str, Any]], set[int]]:
    """Multi-line JS/TS taint tracker + safe literal/parameterized-query line suppressor."""
    findings: list[dict[str, Any]] = []
    safe_lines: set[int] = set()
    const_vars: set[str] = set()
    srv_tainted: set[str] = set()
    dom_tainted: set[str] = set()
    sql_tainted: set[str] = set()
    seen: set[tuple[int, str]] = set()

    for lineno, raw_ln in enumerate((src_text or "").splitlines(), start=1):
        s = raw_ln.strip()
        if not s or s.startswith(("//", "/*", "*")):
            continue
        if re.search(r"""(?i)\.(?:query|execute)\s*\(\s*['"`][^'"`+$]*(?:\?|\$\d+)[^'"`+$]*['"`]\s*,\s*\[""", s):
            safe_lines.add(lineno)
        m_decl = _JS_DECL_RE.match(s)
        if m_decl:
            vname, rhs = m_decl.group(1), m_decl.group(2).strip()
            if _JS_CONST_LIT_RE.match(rhs) or _DOM_SANITIZER_RE.search(rhs):
                const_vars.add(vname)
                continue
            uses_srv = bool(_JS_REQ_SRC_RE.search(rhs)) or any(re.search(rf"\b{re.escape(tv)}\b", rhs) for tv in srv_tainted)
            uses_dom = bool(_JS_DOM_SRC_RE.search(rhs)) or any(re.search(rf"\b{re.escape(tv)}\b", rhs) for tv in dom_tainted)
            if uses_srv:
                srv_tainted.add(vname)
                if _SQL_KW_RE.search(rhs) and ("+" in rhs or "${" in rhs):
                    sql_tainted.add(vname)
            if uses_dom or uses_srv:
                dom_tainted.add(vname)

        m_ih = re.search(r"\.(?:inner|outer)HTML\s*\+?=\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:;|$)", s)
        if m_ih:
            rhs_var = m_ih.group(1)
            if rhs_var in const_vars:
                safe_lines.add(lineno)
            elif rhs_var in dom_tainted and (lineno, "CWE-79") not in seen:
                seen.add((lineno, "CWE-79"))
                findings.append({
                    "lineno": lineno,
                    "title": "Potential DOM-Based XSS (JS Multi-Line Taint-Flow)",
                    "category": "Cross-Site Scripting (SAST)", "severity": "High", "cvss": 7.4,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "cwe": "CWE-79", "owasp": "A03:2021 - Injection",
                    "remediation": "`textContent` yoki `DOMPurify.sanitize()` ishlating.",
                })

        m_sq = re.search(r"\b(?:db|pool|client|conn|sequelize|knex)\.(?:query|execute|raw)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[\),]", s)
        if m_sq and m_sq.group(1) in sql_tainted and (lineno, "CWE-89") not in seen:
            seen.add((lineno, "CWE-89"))
            findings.append({
                "lineno": lineno,
                "title": "Potential SQL Injection (JS/Node Multi-Line Data-Flow)",
                "category": "Injection (SAST)", "severity": "High", "cvss": 8.6,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                "remediation": "Parametrlangan so'rovlar (`db.query('SELECT ... WHERE id = $1', [id])`) ishlating.",
            })

        m_ex = re.search(r"\b(?:exec|execSync)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[\),]", s)
        if m_ex and m_ex.group(1) in srv_tainted and (lineno, "CWE-78") not in seen:
            seen.add((lineno, "CWE-78"))
            findings.append({
                "lineno": lineno,
                "title": "Potential OS Command Injection Sink (JS/Node Multi-Line Data-Flow)",
                "category": "RCE / Command Injection (SAST)", "severity": "Critical", "cvss": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-78", "owasp": "A03:2021 - Injection",
                "remediation": "`child_process.execFile` va qat'iy argumentlar massividan foydalaning.",
            })

        m_ss = re.search(r"\b(?:axios\.(?:get|post|request)|fetch)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[\),]", s)
        if m_ss and m_ss.group(1) in srv_tainted and (lineno, "CWE-918") not in seen:
            seen.add((lineno, "CWE-918"))
            findings.append({
                "lineno": lineno,
                "title": "Potential Server-Side Request Forgery (JS/Node Data-Flow)",
                "category": "SSRF (SAST)", "severity": "High", "cvss": 8.2,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                "cwe": "CWE-918", "owasp": "A10:2021 - Server-Side Request Forgery",
                "remediation": "Chiquvchi domenlar uchun allowlist va ichki IP bloklovchi qo'llang.",
            })

    return findings, safe_lines


_GO_JAVA_SRC_RE = re.compile(
    r"\b(?:r\.URL\.Query\(\)\.Get|r\.FormValue|c\.(?:Query|Param|PostForm)|request\.getParameter|request\.getHeader)\s*\("
)


def analyze_go_java_taint_flow(src_text: str, ext: str) -> tuple[list[dict[str, Any]], set[int]]:
    """Multi-line Go/Java taint tracker + PreparedStatement / parameterized SQL suppressor."""
    findings: list[dict[str, Any]] = []
    safe_lines: set[int] = set()
    tainted: set[str] = set()
    sql_tainted: set[str] = set()
    seen: set[tuple[int, str]] = set()
    is_go = ext == ".go"

    for lineno, raw_ln in enumerate((src_text or "").splitlines(), start=1):
        s = raw_ln.strip()
        if not s or s.startswith(("//", "/*", "*")):
            continue
        if re.search(r"""(?i)(?:prepareStatement\s*\(|\.(?:Query|QueryRow|Exec)\s*\(\s*["`][^"`+%]*(?:\$\d+|\?)[^"`+%]*["`]\s*,)""", s):
            safe_lines.add(lineno)

        m_go = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(.+)$", s) if is_go else None
        m_jv = re.match(r"^(?:final\s+)?String\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?$", s) if not is_go else None
        m_asg = m_go or m_jv
        if m_asg:
            vname, rhs = m_asg.group(1), m_asg.group(2)
            has_ext = bool(_GO_JAVA_SRC_RE.search(rhs)) or any(re.search(rf"\b{re.escape(tv)}\b", rhs) for tv in tainted)
            if has_ext:
                tainted.add(vname)
                if _SQL_KW_RE.search(rhs) and ("+" in rhs or "fmt.Sprintf" in rhs or "String.format" in rhs):
                    sql_tainted.add(vname)

        m_sq = re.search(r"\b(?:Query|QueryRow|Exec|executeQuery|executeUpdate|execute)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\),]", s)
        if m_sq and m_sq.group(1) in sql_tainted and (lineno, "CWE-89") not in seen:
            seen.add((lineno, "CWE-89"))
            findings.append({
                "lineno": lineno,
                "title": f"Potential SQL Injection ({'Go' if is_go else 'Java'} Multi-Line Data-Flow)",
                "category": "Injection (SAST)", "severity": "High", "cvss": 8.6,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                "remediation": "`PreparedStatement` (`?`) yoki Go `$1` parametrlangan so'rov ishlating.",
            })

        m_cmd = re.search(r"""(?:exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"\s*,\s*|Runtime\.getRuntime\(\)\.exec\s*\(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*\)""", s)
        if m_cmd and m_cmd.group(1) in tainted and (lineno, "CWE-78") not in seen:
            seen.add((lineno, "CWE-78"))
            findings.append({
                "lineno": lineno,
                "title": f"Potential OS Command Injection ({'Go' if is_go else 'Java'} Multi-Line Data-Flow)",
                "category": "RCE / Command Injection (SAST)", "severity": "Critical", "cvss": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": "CWE-78", "owasp": "A03:2021 - Injection",
                "remediation": "`sh -c` va `Runtime.exec(String)` o'rniga qat'iy argumentlar massivini uzating.",
            })

    return findings, safe_lines


_PHP_SRC_RE = re.compile(r"(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[|\$request->(?:input|query|post|get)\s*\(|Request::input\s*\()")
_CS_SRC_RE = re.compile(r"(?:Request\.(?:Query|Form|Headers|RouteValues)\s*\[|HttpContext\.Request\.)")


def analyze_php_csharp_taint_flow(src_text: str, ext: str) -> tuple[list[dict[str, Any]], set[int]]:
    """Multi-line PHP (*.php) & C# (*.cs) taint tracker with PDO / SqlParameter zero-FP suppression."""
    findings: list[dict[str, Any]] = []
    safe_lines: set[int] = set()
    tainted: set[str] = set()
    sql_tainted: set[str] = set()
    seen: set[tuple[int, str]] = set()
    is_php = ext == ".php"

    for lineno, raw_ln in enumerate((src_text or "").splitlines(), start=1):
        s = raw_ln.strip()
        if not s or s.startswith(("//", "#", "/*", "*")):
            continue
        if is_php:
            if re.search(r"(?i)(?:->prepare\s*\(|bindParam\s*\(|bindValue\s*\(|htmlspecialchars\s*\(|escapeshellarg\s*\()", s):
                safe_lines.add(lineno)
            m_pa = re.match(r"^(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);\s*$", s)
            if m_pa:
                vname, rhs = m_pa.group(1), m_pa.group(2)
                if re.search(r"(?i)\b(?:intval|floatval|escapeshellarg|htmlspecialchars)\s*\(|^\(int\)", rhs):
                    tainted.discard(vname)
                    sql_tainted.discard(vname)
                    continue
                has_ext = bool(_PHP_SRC_RE.search(rhs)) or any(tv in rhs for tv in tainted)
                if has_ext:
                    tainted.add(vname)
                    if _SQL_KW_RE.search(rhs) and ("." in rhs or '"' in rhs):
                        sql_tainted.add(vname)
            m_psq = re.search(r"(?:->query|mysqli_query|pg_query|DB::select|DB::statement)\s*\(\s*(?:\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*)?(\$[A-Za-z_][A-Za-z0-9_]*)\s*[\),]", s)
            if m_psq and m_psq.group(1) in sql_tainted and (lineno, "CWE-89") not in seen:
                seen.add((lineno, "CWE-89"))
                findings.append({
                    "lineno": lineno, "title": "Potential SQL Injection (PHP Multi-Line Data-Flow)",
                    "category": "Injection (SAST)", "severity": "High", "cvss": 8.6,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                    "remediation": "PDO `$pdo->prepare('SELECT ... WHERE id = :id')` va `bindValue()` ishlating.",
                })
            m_pcmd = re.search(r"\b(?:system|passthru|proc_open|popen|exec|shell_exec)\s*\(\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*[\),]", s)
            if m_pcmd and m_pcmd.group(1) in tainted and (lineno, "CWE-78") not in seen:
                seen.add((lineno, "CWE-78"))
                findings.append({
                    "lineno": lineno, "title": "Potential OS Command Injection (PHP Multi-Line Data-Flow)",
                    "category": "RCE / Command Injection (SAST)", "severity": "Critical", "cvss": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe": "CWE-78", "owasp": "A03:2021 - Injection",
                    "remediation": "`escapeshellarg()` yoki Symfony Process massiv argumentlaridan foydalaning.",
                })
        else:
            if re.search(r"(?i)(?:Parameters\.Add(?:WithValue)?\s*\(|new\s+SqlParameter\s*\(|FromSqlInterpolated\s*\()", s):
                safe_lines.add(lineno)
            for m_fp in re.finditer(r"\[From(?:Query|Body|Route|Header)\]\s*string\s+([A-Za-z_][A-Za-z0-9_]*)", s):
                tainted.add(m_fp.group(1))
            m_ca = re.match(r"^(?:string|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);\s*$", s)
            if m_ca:
                vname, rhs = m_ca.group(1), m_ca.group(2)
                has_ext = bool(_CS_SRC_RE.search(rhs)) or any(re.search(rf"\b{re.escape(tv)}\b", rhs) for tv in tainted)
                if has_ext:
                    tainted.add(vname)
                    if _SQL_KW_RE.search(rhs) and ("+" in rhs or rhs.lstrip().startswith('$"') or "string.Format" in rhs):
                        sql_tainted.add(vname)
            m_csq = re.search(r"(?:new\s+SqlCommand|ExecuteSqlRaw(?:Async)?|QueryAsync)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\),]", s)
            if m_csq and m_csq.group(1) in sql_tainted and (lineno, "CWE-89") not in seen:
                seen.add((lineno, "CWE-89"))
                findings.append({
                    "lineno": lineno, "title": "Potential SQL Injection (C#/.NET Multi-Line Data-Flow)",
                    "category": "Injection (SAST)", "severity": "High", "cvss": 8.6,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                    "remediation": "`SqlCommand` bilan `@param` (`Parameters.AddWithValue`) yoki `FromSqlInterpolated` ishlating.",
                })
            m_ccmd = re.search(r"Process\.Start\s*\(\s*(?:\"(?:cmd|cmd\.exe|/bin/sh)\"\s*,\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[\),]", s)
            if m_ccmd and m_ccmd.group(1) in tainted and (lineno, "CWE-78") not in seen:
                seen.add((lineno, "CWE-78"))
                findings.append({
                    "lineno": lineno, "title": "Potential OS Command Injection (C#/.NET Multi-Line Data-Flow)",
                    "category": "RCE / Command Injection (SAST)", "severity": "Critical", "cvss": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe": "CWE-78", "owasp": "A03:2021 - Injection",
                    "remediation": "`ProcessStartInfo.ArgumentList` va `UseShellExecute = false` ishlating.",
                })

    return findings, safe_lines


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

