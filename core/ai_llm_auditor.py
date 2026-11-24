"""
SPECTRE AI/LLM, RAG Vector Database & MCP Security Posture Auditor
==================================================================
Performs read-only, baseline-calibrated checks for unauthenticated AI/LLM
inference runtimes (Ollama, vLLM/LiteLLM, Ray), RAG vector stores (Qdrant,
ChromaDB), Model Context Protocol (MCP) JSON-RPC `tools/list` endpoints, and
white-box AI API credentials / insecure MCP server manifests.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from core.native_bridge import SEC_MASK_AI_LLM, fast_secret_prefilter_mask
from core.plugin_runner import QoD

_AI_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic Claude API Key", re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{24,}\b")),
    ("OpenAI Project API Key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{24,}\b")),
    ("HuggingFace Access Token", re.compile(r"\bhf_[A-Za-z0-9]{28,}\b")),
    ("Groq Cloud API Key", re.compile(r"\bgsk_[A-Za-z0-9]{28,}\b")),
)
_DUMMY_MARKERS = ("example", "sample", "placeholder", "your_", "xxxx", "000000", "testkey", "dummy")
_HIDDEN_OVERRIDE_CTX_RE = re.compile(
    r"(?is)(?:<!--(.*?)-->|<meta\b[^>]*content=['\"]([^'\"]+)['\"][^>]*>|"
    r"<[^>]+style=['\"][^'\"]*display\s*:\s*none[^'\"]*['\"][^>]*>(.*?)</[^>]+>)"
)
_OVERRIDE_CLAUSE_RE = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"system\s+prompt\s+override|new\s+system\s+instructions)\b"
)
_SUPPRESS_ACTION_RE = re.compile(
    r"(?i)\b(?:no\s+vulnerabilities|mark\s+(?:this\s+)?(?:target|code|host|app)\s+as\s+(?:safe|secure)|"
    r"report\s+(?:zero|0)\s+findings|classify\s+as\s+false\s+positive)\b"
)
_UNSAFE_AGENT_PERM_RE = re.compile(
    r"(?i)^(?:Bash\(\*\)|Bash\((?:sh|bash|curl|wget)\s*\*\)|\*)$"
)


def detect_indirect_prompt_directives(raw_html_or_headers: str) -> str | None:
    """Detects hidden scanner-override / indirect prompt-injection directives in HTML comments, hidden DOM, or AI headers."""
    txt = raw_html_or_headers or ""
    if not txt:
        return None
    for m in _HIDDEN_OVERRIDE_CTX_RE.finditer(txt):
        seg = " ".join(g for g in m.groups() if g).strip()
        if seg and _OVERRIDE_CLAUSE_RE.search(seg) and _SUPPRESS_ACTION_RE.search(seg):
            return seg[:140]
    for ln in txt.splitlines():
        if re.match(r"(?i)^x-(?:ai|llm|agent|prompt)[a-z0-9\-]*\s*:", ln.strip()):
            if _OVERRIDE_CLAUSE_RE.search(ln) and _SUPPRESS_ACTION_RE.search(ln):
                return ln.strip()[:140]
    return None


def audit_agent_workspace_config_text(filename: str, content: str) -> list[tuple[str, str, float, str, str]]:
    """Audits `.claude/settings.json`, `.gemini/settings.json`, `.cursor/mcp.json` for wildcard shell/skip-permission configs."""
    issues: list[tuple[str, str, float, str, str]] = []
    try:
        cfg = json.loads(content or "")
    except Exception:
        return issues
    if not isinstance(cfg, dict):
        return issues

    if cfg.get("dangerouslySkipPermissions") is True or cfg.get("yolo") is True or cfg.get("trustAllTools") is True:
        issues.append((
            f"AI Agent Permission Guard Disabled in {filename}",
            "High", 8.5, "CWE-250",
            f"`{filename}` faylida `dangerouslySkipPermissions` / `yolo` rejimini o'chiring va minimal ruxsatlar ro'yxatini qo'llang.",
        ))

    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}
    allow_list = perms.get("allow") if isinstance(perms.get("allow"), list) else []
    auto_list = cfg.get("autoApprove") if isinstance(cfg.get("autoApprove"), list) else []
    bad_perms = [str(x) for x in (allow_list + auto_list) if isinstance(x, str) and _UNSAFE_AGENT_PERM_RE.match(x.strip())]
    if bad_perms:
        issues.append((
            f"Wildcard Shell Execution Permission in AI Agent Config ({filename})",
            "High", 8.5, "CWE-250",
            f"`{filename}` ruxsatlarida `{bad_perms[0]}` o'rniga faqat aniq xavfsiz buyruqlarni (`Bash(pytest)`) ruxsat eting.",
        ))
    return issues


def _safe_json(resp: Any) -> Any:
    if resp is None or getattr(resp, "status_code", 0) != 200:
        return None
    ctype = str(getattr(resp, "headers", {}).get("Content-Type", "")).lower()
    txt = str(getattr(resp, "text", "") or "").strip()
    if not txt or ("json" not in ctype and not txt.startswith(("{", "["))):
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None


def audit_ai_llm_web_surface(
    db: Any,
    http_engine: Any,
    project_id: int,
    http_services: list[dict[str, Any]],
    log_fn: Any,
) -> int:
    hits = 0
    seen_origins: set[str] = set()
    for svc in (http_services or [])[:24]:
        st = int(svc.get("status_code") or 0)
        raw_u = str(svc.get("url") or "").strip()
        if st in (301, 302, 303, 307, 308) or not raw_u:
            continue
        p = urllib.parse.urlparse(raw_u)
        if not p.scheme or not p.netloc:
            continue
        origin = f"{p.scheme}://{p.netloc}"
        if origin in seen_origins:
            continue
        seen_origins.add(origin)

        try:
            r_base = http_engine.request("GET", f"{origin}/spectre_ai_baseline_9918.json", timeout=(2.0, 2.8), allow_redirects=False)
            base_json = _safe_json(r_base)
        except Exception:
            continue

        # 1. Ollama LLM Registry (/api/tags)
        try:
            r_ol = http_engine.request("GET", f"{origin}/api/tags", timeout=(2.0, 2.8), allow_redirects=False)
            j_ol = _safe_json(r_ol)
            if isinstance(j_ol, dict) and isinstance(j_ol.get("models"), list) and j_ol != base_json:
                models = [str(m.get("name") or "") for m in j_ol["models"] if isinstance(m, dict) and ("digest" in m or "modified_at" in m)]
                if models or ("models" in j_ol and len(j_ol) == 1):
                    db.upsert_finding(
                        project_id, "Agent-2 (AI-Posture)", f"[CONFIRMED] Unauthenticated Ollama LLM Model Registry ({p.netloc})",
                        "AI / LLM Infrastructure Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "CWE-306", "LLM08:2025 - Excessive Agency / Unauthenticated Runtime", f"{origin}/api/tags",
                        f"GET /api/tags HTTP 200 | Exposed Models ({len(models)}): {', '.join(models[:5]) or 'empty registry'}",
                        "Ollama AI model serveri autentifikatsiyasiz tashqi tarmoqqa ochiq qoldirilgan.",
                        "`OLLAMA_HOST=127.0.0.1` o'rnating va reverse-proxy orqali mTLS / Bearer autentifikatsiya qo'llang.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
        except Exception:
            pass
        # 2. OpenAI-Compatible Inference Server (/v1/models)
        try:
            r_vm = http_engine.request("GET", f"{origin}/v1/models", timeout=(2.0, 2.8), allow_redirects=False)
            j_vm = _safe_json(r_vm)
            if isinstance(j_vm, dict) and j_vm.get("object") == "list" and isinstance(j_vm.get("data"), list) and j_vm != base_json:
                mids = [str(m.get("id") or "") for m in j_vm["data"] if isinstance(m, dict) and ("owned_by" in m or m.get("object") == "model")]
                if mids:
                    db.upsert_finding(
                        project_id, "Agent-2 (AI-Posture)", f"[CONFIRMED] Unauthenticated OpenAI-Compatible LLM Endpoint ({p.netloc})",
                        "AI / LLM Infrastructure Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        "CWE-306", "LLM08:2025 - Unauthenticated Inference Surface", f"{origin}/v1/models",
                        f"GET /v1/models HTTP 200 | Served Models ({len(mids)}): {', '.join(mids[:5])}",
                        "vLLM / LiteLLM / LocalAI xulosa chiqarish (inference) API nuqtasi API kalitisiz ochiq ishlamoqda.",
                        "`--api-key` bayrog'ini yoqing va AI shlyuzda rate-limit hamda autentifikatsiya talab qiling.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
        except Exception:
            pass

        # 3. Qdrant & ChromaDB RAG Vector Stores
        try:
            r_qd = http_engine.request("GET", f"{origin}/collections", timeout=(2.0, 2.8), allow_redirects=False)
            j_qd = _safe_json(r_qd)
            if isinstance(j_qd, dict) and j_qd.get("status") == "ok" and isinstance(j_qd.get("result"), dict) and isinstance(j_qd["result"].get("collections"), list) and j_qd != base_json:
                cols = [str(c.get("name") or "") for c in j_qd["result"]["collections"] if isinstance(c, dict)]
                db.upsert_finding(
                    project_id, "Agent-2 (AI-Posture)", f"[CONFIRMED] Unauthenticated Qdrant RAG Vector Database ({p.netloc})",
                    "AI / RAG Vector Store Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "CWE-306", "LLM06:2025 - Sensitive Information Disclosure (RAG)", f"{origin}/collections",
                    f"GET /collections HTTP 200 | Collections ({len(cols)}): {', '.join(cols[:6]) or '0'}",
                    "Qdrant RAG vektor bazasi API kalitisiz ichki embedding kolleksiyalariga ochiq ruxsat bermoqda.",
                    "`service.api_key` va TLS shifrlashni Qdrant konfiguratsiyasida majburiy qiling.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass

        try:
            r_ch = http_engine.request("GET", f"{origin}/api/v1/collections", timeout=(2.0, 2.8), allow_redirects=False)
            j_ch = _safe_json(r_ch)
            if isinstance(j_ch, list) and j_ch and all(isinstance(x, dict) and "name" in x and ("dimension" in x or "tenant" in x or "metadata" in x) for x in j_ch[:3]):
                cols = [str(c.get("name") or "") for c in j_ch[:6]]
                db.upsert_finding(
                    project_id, "Agent-2 (AI-Posture)", f"[CONFIRMED] Unauthenticated ChromaDB Vector Store ({p.netloc})",
                    "AI / RAG Vector Store Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "CWE-306", "LLM06:2025 - Sensitive Information Disclosure (RAG)", f"{origin}/api/v1/collections",
                    f"GET /api/v1/collections HTTP 200 | Collections: {', '.join(cols)}",
                    "ChromaDB vektor bazasi autentifikatsiyasiz korporativ RAG hujjat kolleksiyalarini ochiq qaytarmoqda.",
                    "`CHROMA_SERVER_AUTHN_CREDENTIALS` token autentifikatsiyasini yoqing.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass
        # 4. Ray Distributed AI Cluster (/api/version) & MCP JSON-RPC (/mcp)
        try:
            r_ray = http_engine.request("GET", f"{origin}/api/version", timeout=(2.0, 2.8), allow_redirects=False)
            j_ray = _safe_json(r_ray)
            if isinstance(j_ray, dict) and "ray_version" in j_ray and ("python_version" in j_ray or "version" in j_ray) and j_ray != base_json:
                rv = str(j_ray.get("ray_version") or "")
                db.upsert_finding(
                    project_id, "Agent-2 (AI-Posture)", f"[CONFIRMED] Unauthenticated Ray Distributed AI Cluster API ({p.netloc})",
                    "AI / Compute Cluster Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CWE-306", "LLM08:2025 - Unauthenticated Compute Cluster", f"{origin}/api/version",
                    f"GET /api/version HTTP 200 | ray_version={rv}",
                    "Ray AI klaster boshqaruv paneli autentifikatsiyasiz ochiq holatda ishlamoqda.",
                    "Ray Dashboard portini (`:8265`) faqat `127.0.0.1` yoki autentifikatsiyali ingress ortiga yoping.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass

        try:
            mcp_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            r_mcp = http_engine.request("POST", f"{origin}/mcp", json=mcp_req, timeout=(2.0, 2.8), allow_redirects=False)
            j_mcp = _safe_json(r_mcp)
            tools = j_mcp.get("result", {}).get("tools") if isinstance(j_mcp, dict) and j_mcp.get("jsonrpc") == "2.0" and isinstance(j_mcp.get("result"), dict) else None
            if isinstance(tools, list) and tools and all(isinstance(t, dict) and "name" in t for t in tools[:3]):
                tnames = [str(t.get("name") or "") for t in tools[:6]]
                db.upsert_finding(
                    project_id, "Agent-2 (AI-Posture)", f"[CONFIRMED] Unauthenticated MCP (Model Context Protocol) Tool Server ({p.netloc})",
                    "AI Agentic / MCP Exposure", "Critical", 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                    "CWE-306", "LLM08:2025 - Excessive Agency (Unauthenticated MCP)", f"{origin}/mcp",
                    f"JSON-RPC tools/list returned {len(tools)} agentic tools: {', '.join(tnames)}",
                    "MCP serveri autentifikatsiyasiz agent vositalari (`tools/list`) ro'yxatini ochiq bermoqda.",
                    "MCP transportida OAuth 2.1 / Bearer token tekshiruvini majburiy qiling.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass
        try:
            r_root = http_engine.request("GET", origin, timeout=(2.0, 2.8), allow_redirects=False)
            hdr_blob = "\n".join(f"{k}: {v}" for k, v in (getattr(r_root, "headers", {}) or {}).items())
            inj_ev = detect_indirect_prompt_directives(f"{hdr_blob}\n{str(getattr(r_root, 'text', '') or '')[:65536]}")
            if inj_ev:
                db.upsert_finding(
                    project_id, "SPECTRE-AI-Security", f"Embedded Indirect Prompt-Override Directive in Web Response ({p.netloc})",
                    "AI / Indirect Prompt Manipulation", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "CWE-74", "LLM01:2025 - Prompt Injection (Indirect)", origin,
                    f"Hidden Directive Snippet: {inj_ev}",
                    "Veb-javobning yashirin HTML izohi yoki header qismida AI skaner/agent xulosasini o'zgartirishga urinuvchi ko'rsatma aniqlandi.",
                    "Tashqi veb-tarkibni Untrusted-Content konvertida ajrating va yashirin prompt-override teglarini filtrlang.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass
    if hits and log_fn:
        log_fn(f"  [AI-POSTURE] {hits} ta ochiq AI/LLM, RAG Vector DB yoki MCP nuqtasi tasdiqlandi.")
    return hits


def audit_ai_code_and_mcp_configs(db: Any, project_id: int, code_paths: list[str], log_fn: Any) -> int:
    hits = 0
    seen_keys: set[str] = set()
    exts = {".json", ".env", ".py", ".js", ".ts", ".yaml", ".yml", ".toml"}
    for cp in (code_paths or []):
        root = Path(cp)
        if not root.exists():
            continue
        files = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file() and (p.suffix.lower() in exts or p.name.startswith(".env")) and ".git" not in p.parts and "node_modules" not in p.parts
        ][:160]
        for fp in files:
            try:
                txt = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if fast_secret_prefilter_mask(txt) & SEC_MASK_AI_LLM:
                for label, rx in _AI_KEY_PATTERNS:
                    for m in rx.finditer(txt):
                        tok = m.group(0)
                        if any(dm in tok.lower() for dm in _DUMMY_MARKERS) or tok in seen_keys:
                            continue
                        seen_keys.add(tok)
                        masked = f"{tok[:10]}...{tok[-4:]}"
                        db.upsert_finding(
                            project_id, "Agent-2 (AI-Posture)", f"Hardcoded {label} in Source/Config ({fp.name})",
                            "AI Credential Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                            "CWE-798", "LLM06:2025 - Sensitive Information Disclosure", str(fp),
                            f"Matched {label}: {masked}",
                            f"`{fp.name}` faylida ochiq AI provayder API kaliti saqlangan.",
                            "API kalitni darhol bekor qiling (revoke) va Vault / KMS muhit o'zgaruvchisiga o'tkazing.",
                            confidence=QoD.STATIC_SAST,
                        )
                        hits += 1
            rel_parts_l = [pt.lower() for pt in fp.parts]
            if fp.name in ("settings.json", "settings.local.json") and any(d in rel_parts_l for d in (".claude", ".gemini", ".cursor")):
                for title, sev, cvss, cwe, rem in audit_agent_workspace_config_text(fp.name, txt):
                    db.upsert_finding(
                        project_id, "SPECTRE-AI-Security", title,
                        "AI Agentic / MCP Misconfiguration", sev, cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                        cwe, "LLM08:2025 - Excessive Agency", str(fp),
                        f"Agent Config: {fp.parent.name}/{fp.name}",
                        f"`{fp.parent.name}/{fp.name}` agent sozlamalarida cheklanmagan buyruq ruxsati yoqilgan.",
                        rem, confidence=QoD.STATIC_SAST,
                    )
                    hits += 1
            if fp.name in ("mcp.json", "claude_desktop_config.json") or fp.name.endswith("mcp_config.json"):
                try:
                    j_cfg = json.loads(txt)
                except Exception:
                    j_cfg = None
                servers = j_cfg.get("mcpServers") if isinstance(j_cfg, dict) else None
                if isinstance(servers, dict):
                    for s_name, s_def in servers.items():
                        if not isinstance(s_def, dict):
                            continue
                        cmd_s = str(s_def.get("command") or "")
                        args_l = [str(x) for x in (s_def.get("args") or []) if isinstance(x, (str, int))]
                        joined = f"{cmd_s} {' '.join(args_l)}"
                        if ("npx" in cmd_s and "-y" in args_l and any("@" not in a.lstrip("@") for a in args_l if not a.startswith("-"))) or "0.0.0.0" in joined:
                            db.upsert_finding(
                                project_id, "Agent-2 (AI-Posture)", f"Unpinned or Publicly Bound MCP Server Config ({s_name})",
                                "AI Supply-Chain / MCP Misconfiguration", "High", 7.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                "CWE-829", "LLM03:2025 - Supply Chain Vulnerabilities", str(fp),
                                f"mcpServers.{s_name}: {joined[:120]}",
                                "MCP konfiguratsiyasida versiyasi qadalmagan (`npx -y`) paket yoki `0.0.0.0` tarmoq bog'lanishi aniqlandi.",
                                "MCP server paketlarini aniq versiya bilan qadang va `127.0.0.1` ga cheklang.",
                                confidence=QoD.STATIC_SAST,
                            )
                            hits += 1
                        env_map = s_def.get("env") if isinstance(s_def.get("env"), dict) else {}
                        for ek, ev in env_map.items():
                            ek_s, ev_s = str(ek or ""), str(ev or "").strip()
                            if (
                                re.search(r"(?i)(?:token|secret|password|api[_-]?key|private[_-]?key)", ek_s)
                                and len(ev_s) >= 12
                                and not ev_s.startswith(("${", "$", "<"))
                                and not any(dm in ev_s.lower() for dm in _DUMMY_MARKERS)
                            ):
                                db.upsert_finding(
                                    project_id, "SPECTRE-AI-Security", f"Hardcoded Secret in MCP Server Environment ({s_name}:{ek_s})",
                                    "AI Credential Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                                    "CWE-798", "LLM06:2025 - Sensitive Information Disclosure", str(fp),
                                    f"mcpServers.{s_name}.env.{ek_s} contains cleartext credential ({len(ev_s)} chars)",
                                    f"`{fp.name}` ichidagi `{s_name}` MCP server muhitida maxfiy kalit ochiq matnda yozilgan.",
                                    f"`{ek_s}` qiymatini tizim muhiti (`${{env:{ek_s}}}`) yoki OS Keychain orqali uzating.",
                                    confidence=QoD.STATIC_SAST,
                                )
                                hits += 1
    return hits
