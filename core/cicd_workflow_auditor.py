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

from core.plugin_runner import QoD

_GHA_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|review\.body|head_ref|commits\[[^\]]*\]\.message)"
    r"|\$\{\{\s*github\.head_ref\s*\}\}",
    re.I,
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
        if _APP_SECRET_KV_RE.search(txt):
            val = _APP_SECRET_KV_RE.search(txt).group(1)  # type: ignore[union-attr]
            if val.lower() not in _DUMMY_SECRET_VALUES and not val.startswith(("$", "${")):
                issues.append((
                    "Hardcoded Secret Variable in .gitlab-ci.yml",
                    "High", 8.2, "CWE-798",
                    "Maxfiy kalitlarni `.gitlab-ci.yml` ichida emas, GitLab Protected/Masked CI Variables bo'limida saqlang.",
                ))
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

    in_run = False
    for ln in txt.splitlines():
        s = ln.strip()
        if re.match(r"^-?\s*run\s*:", s):
            in_run = True
        elif re.match(r"^[a-zA-Z0-9_\-]+\s*:", s) and not ln.startswith(" " * 8):
            in_run = False
        if (in_run or "run:" in s) and _GHA_UNTRUSTED_EXPR_RE.search(s):
            issues.append((
                "GitHub Actions Untrusted Event Context Interpolated in Shell 'run:'",
                "High", 8.6, "CWE-78",
                "`${{ github.event.* }}` qiymatini to'g'ridan-to'g'ri `run:` qatoriga yozmang; uni `env:` o'zgaruvchisi orqali uzating.",
            ))
            break
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
    skip_parts = ("node_modules", "__pycache__", "/tests/", "/test/", ".venv", "venv")
    written = 0
    for cp in code_paths:
        if not cp:
            continue
        root = Path(cp)
        if not root.is_dir():
            continue
        wf_dir = root / ".github" / "workflows"
        wf_files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))) if wf_dir.is_dir() else []
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
        for rc_file in sorted(root.rglob("*"))[:240]:
            if not rc_file.is_file() or any(sp in str(rc_file).replace("\\", "/") for sp in skip_parts):
                continue
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
