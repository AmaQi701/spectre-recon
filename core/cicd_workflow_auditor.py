"""
SPECTRE CI/CD Workflow & Registry Credential Hygiene Auditor
============================================================
Audits GitHub Actions (`.github/workflows/*.yml`) and package registry configs
(`.npmrc`, `.pypirc`) for:
  1. `pull_request_target` + untrusted PR checkout (`pwn-request`, CWE-829);
  2. Untrusted `${{ github.event.* }}` interpolation in `run:` shell blocks (`CWE-78`);
  3. Hardcoded cleartext registry auth tokens in `.npmrc` / `.pypirc` (`CWE-798`).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.models import walk_safe_repo_files
from core.plugin_runner import QoD

_GHA_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|review\.body|head_ref|commits\[[^\]]*\]\.message)"
    r"|\$\{\{\s*github\.head_ref\s*\}\}",
    re.I,
)
_AI_GHA_ACTION_RE = re.compile(
    r"(?i)\buses\s*:\s*['\"]?(?:anthropics/claude-code-action|google-github-actions/run-gemini-cli|"
    r"google-gemini/gemini-cli-action|openai/codex-action|actions/ai-inference)(?:@|\b)"
)
_AI_BYPASS_CFG_RE = re.compile(
    r"""(?i)(?:\bdanger-full-access\b|--yolo\b|--dangerously-skip-permissions\b|\bBash\(\*\)|"""
    r"""(?:allowed_non_write_users|allow[_-]users)\s*:\s*['"]?\*['"]?)"""
)
_AI_STEP_OUTPUT_EVAL_RE = re.compile(
    r"(?i)(?:\beval\b|\b(?:sh|bash)\s+-c)\s+[^\n]*\$\{\{\s*steps\.[A-Za-z0-9_\-]+\.outputs\.[A-Za-z0-9_\-]+\s*\}\}"
)
_NPMRC_TOKEN_RE = re.compile(r"(?m)^\s*(?://[^\s=:]+/:)?(?:_[a-zA-Z]*authToken|_password)\s*=\s*([^\s$#]{10,})\s*$")
_PIPE_CURL_SH_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b")
_JENKINS_PARAM_SH_RE = re.compile(r"""\bsh\s*\(?\s*"[^"\n]*\$\{?\s*params\.[A-Za-z0-9_]+""")
_APP_SECRET_KV_RE = re.compile(
    r"""(?im)^\s*(?:spring\.datasource\.password|spring\.data\.redis\.password|jwt\.secret|app\.jwt\.secret|aws\.secret[._-]?access[._-]?key|AWS_SECRET_ACCESS_KEY|JWT_SECRET|DB_PASSWORD|SECRET_KEY)\s*[=:]\s*['"]?([^\s'"$#]{10,})['"]?\s*$"""
)
_DUMMY_SECRET_VALUES = {"changeme", "password", "password123", "secretkey", "your_secret_here", "replace_me", "example_secret", "development"}


def audit_cicd_and_app_configs(filename: str, content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    fn = filename.lower()
    txt = content or ""
    if fn == ".gitlab-ci.yml":
        if _PIPE_CURL_SH_RE.search(txt):
            issues.append((
                "Unverified Remote Script Piped to Shell in .gitlab-ci.yml",
                "High", 8.1, "CWE-829",
                "`curl ... | bash` o'rniga skriptni yuklab olib SHA-256 nazorat yig'indisini tekshiring.",
            ))
        for m_gl in _APP_SECRET_KV_RE.finditer(txt):
            val = m_gl.group(1).strip()
            if val.lower() not in _DUMMY_SECRET_VALUES and not val.startswith(("$", "${")):
                issues.append((
                    "Hardcoded Secret Variable in .gitlab-ci.yml",
                    "High", 8.2, "CWE-798",
                    "Maxfiy kalitlarni `.gitlab-ci.yml` ichida emas, GitLab Protected/Masked CI Variables bo'limida saqlang.",
                ))
                break
    elif fn == "jenkinsfile":
        if _JENKINS_PARAM_SH_RE.search(txt):
            issues.append((
                "Unsafe Groovy Parameter Interpolation in Jenkinsfile 'sh' Step",
                "High", 8.6, "CWE-78",
                "`sh \"... ${params.X}\"` o'rniga `withEnv` + bir tirnoqli `sh '... $X'` ishlating.",
            ))
    elif fn in ("application.properties", "application.yml", "application.yaml", ".env.production"):
        for m in _APP_SECRET_KV_RE.finditer(txt):
            val = m.group(1).strip()
            if val.lower() not in _DUMMY_SECRET_VALUES and not val.startswith(("$", "${", "<", "ENC(")):
                issues.append((
                    f"Hardcoded Production Credential in {filename}",
                    "High", 8.2, "CWE-798",
                    f"`{filename}` ichida ochiq parol/kalit saqlamang; Vault yoki `${{ENV_VAR}}` orqali uzating.",
                ))
                break
    return issues


def audit_github_workflow_yaml(content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    txt = content or ""
    low = txt.lower()
    if "pull_request_target" in low and "actions/checkout" in low and ("pull_request.head" in low or "github.head_ref" in low):
        issues.append((
            "GitHub Actions pull_request_target Checks Out Untrusted PR Code",
            "Critical", 9.3, "CWE-829",
            "`pull_request_target` ichida tashqi fork kodini `actions/checkout` qilmang; imtiyozsiz `pull_request` triggeridan foydalaning.",
        ))

    run_indent = -1
    for ln in txt.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        ind = len(ln) - len(ln.lstrip(" "))
        m_run = re.match(r"^(-\s*)?run\s*:\s*(.*)$", s)
        if m_run:
            run_indent = ind + (len(m_run.group(1)) if m_run.group(1) else 0)
            inline_cmd = m_run.group(2).strip()
            if inline_cmd and not inline_cmd.startswith("#") and _GHA_UNTRUSTED_EXPR_RE.search(inline_cmd):
                issues.append((
                    "GitHub Actions Untrusted Event Context Interpolated in Shell 'run:'",
                    "High", 8.6, "CWE-78",
                    "`${{ github.event.* }}` qiymatini to'g'ridan-to'g'ri `run:` qatoriga yozmang; uni `env:` o'zgaruvchisi orqali uzating.",
                ))
                break
            continue
        if run_indent >= 0:
            if ind <= run_indent:
                run_indent = -1
            elif _GHA_UNTRUSTED_EXPR_RE.search(s):
                issues.append((
                    "GitHub Actions Untrusted Event Context Interpolated in Shell 'run:'",
                    "High", 8.6, "CWE-78",
                    "`${{ github.event.* }}` qiymatini to'g'ridan-to'g'ri `run:` qatoriga yozmang; uni `env:` o'zgaruvchisi orqali uzating.",
                ))
                break

    if _AI_GHA_ACTION_RE.search(txt):
        tainted_env_vars: set[str] = set()
        for m_ev in re.finditer(r"(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*:[ \t]*([^\n]+)$", txt):
            if _GHA_UNTRUSTED_EXPR_RE.search(m_ev.group(2)):
                tainted_env_vars.add(m_ev.group(1))

        prompt_lines: list[str] = []
        prompt_indent = -1
        for raw_l in txt.splitlines():
            stripped = raw_l.strip()
            if not stripped or stripped.startswith("#"):
                continue
            ind = len(raw_l) - len(raw_l.lstrip(" "))
            if prompt_indent >= 0:
                if ind > prompt_indent:
                    prompt_lines.append(stripped)
                    continue
                prompt_indent = -1
            m_pk = re.match(r"^(?:-\s*)?(?:prompt|direct_prompt|instructions|system_prompt)\s*:\s*(.*)$", stripped, re.I)
            if m_pk:
                rest = m_pk.group(1).strip()
                if rest in ("|", ">", "|-", ">-", "|+", ">+") or not rest:
                    prompt_indent = ind
                else:
                    prompt_lines.append(rest)
        prompt_blob = "\n".join(prompt_lines)
        has_env_flow = any(
            (f"${vn}" in prompt_blob or f"${{{vn}}}" in prompt_blob or bool(re.search(rf"\$\{{\{{\s*env\.{re.escape(vn)}\s*\}}\}}", prompt_blob)))
            for vn in tainted_env_vars
        )
        if _GHA_UNTRUSTED_EXPR_RE.search(prompt_blob) or has_env_flow:
            issues.append((
                "AI-Agent GitHub Actions Workflow Prompt Receives Untrusted Event Input",
                "Critical", 9.1, "CWE-77",
                "Tashqi PR/Issue matnini (`github.event.*`) AI agent promptiga bevosita yoki `env:` orqali qo'shmang; "
                "faqat tasdiqlangan metama'lumotlar va `contents: read` ruxsatini bering.",
            ))
        if _AI_BYPASS_CFG_RE.search(txt):
            issues.append((
                "Over-Permissive AI-Agent CI Sandbox or Wildcard Trigger Allowlist",
                "High", 8.4, "CWE-250",
                "CI/CD AI agentlarida `--yolo`, `danger-full-access`, `Bash(*)` va `allowed_non_write_users: '*'` sozlamalarini o'chiring.",
            ))
        if _AI_STEP_OUTPUT_EVAL_RE.search(txt):
            issues.append((
                "Unsafe Shell Evaluation of AI-Agent Step Output in Workflow",
                "Critical", 9.3, "CWE-94",
                "AI agent chiqishini (`steps.<id>.outputs.*`) hech qachon `eval` yoki `sh -c` orqali ishga tushirmang.",
            ))
    return issues


def audit_registry_config_text(filename: str, content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    fn = filename.lower()
    if fn in (".npmrc", ".pypirc"):
        m = _NPMRC_TOKEN_RE.search(content or "")
        if m and not m.group(1).startswith(("${", "$")):
            issues.append((
                f"Hardcoded Package Registry Auth Token in {filename}",
                "High", 8.1, "CWE-798",
                f"`{filename}` ichida ochiq token saqlamang; `${{NPM_TOKEN}}` muhit o'zgaruvchisidan foydalaning.",
            ))
    return issues


def run_cicd_and_registry_audit(db: Any, project_id: int, code_paths: list[str], log_fn: Any) -> int:
    written = 0
    for cp in code_paths:
        if not cp:
            continue
        root = Path(cp)
        if not root.is_dir() or root.is_symlink():
            continue
        root_res = root.resolve()
        wf_dir = root / ".github" / "workflows"
        wf_files = (
            [f for f in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))) if f.is_file() and not f.is_symlink() and f.resolve().is_relative_to(root_res) and f.stat().st_size <= 524288]
            if wf_dir.is_dir() and not wf_dir.is_symlink()
            else []
        )
        for wf in wf_files[:30]:
            try:
                txt = wf.read_text(encoding="utf-8", errors="ignore")[:150000]
            except Exception:
                continue
            for title, sev, cvss, cwe, rem in audit_github_workflow_yaml(txt):
                db.upsert_finding(
                    project_id, "Agent-2 (CICD-Auditor)", title,
                    "CI/CD Pipeline Security", sev, cvss,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", cwe,
                    "A08:2021 - Software and Data Integrity Failures", str(wf),
                    f"Workflow: {wf.name}",
                    f"`.github/workflows/{wf.name}` CI/CD quvurida xavfli trigger yoki shell kontekst interpolyatsiyasi aniqlandi.",
                    rem, confidence=QoD.HEADER_CONFIG,
                )
                written += 1

        extra_cfg_names = {".npmrc", ".pypirc", ".gitlab-ci.yml", "jenkinsfile", "application.properties", "application.yml", "application.yaml", ".env.production"}
        for rc_file in walk_safe_repo_files(root, max_files=360, max_bytes=524288):
            fn_l = rc_file.name.lower()
            if fn_l in extra_cfg_names:
                try:
                    rtxt = rc_file.read_text(encoding="utf-8", errors="ignore")[:65536]
                except Exception:
                    continue
                combined = audit_registry_config_text(rc_file.name, rtxt) + audit_cicd_and_app_configs(rc_file.name, rtxt)
                for title, sev, cvss, cwe, rem in combined:
                    db.upsert_finding(
                        project_id, "Agent-2 (CICD-Auditor)", title,
                        "Supply-Chain / Credential Exposure", sev, cvss,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", cwe,
                        "A07:2021 - Identification and Authentication Failures", str(rc_file),
                        f"Config/Pipeline: {rc_file.name}",
                        f"`{rc_file.name}` faylida xavfli CI/CD konstruksiyasi yoki ochiq maxfiy kalit aniqlandi.",
                        rem, confidence=QoD.HEADER_CONFIG,
                    )
                    written += 1
    if written and log_fn:
        log_fn(f"  [CICD-AUDITOR] GitHub Actions va reestr konfiguratsiyasi: {written} ta muammo aniqlandi.")
    return written
