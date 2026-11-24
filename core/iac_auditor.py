"""
SPECTRE Cloud-Native Infrastructure-as-Code (IaC) & Container Security Auditor
==============================================================================
Deterministic offline security posture analyzer for:
  1. Multi-stage `Dockerfile` (CIS Docker Benchmark 4.1 non-root & ENV secrets);
  2. `docker-compose.yml` (`privileged: true`, `docker.sock` mount, `host` ns);
  3. Kubernetes manifests (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`);
  4. HashiCorp Terraform (`*.tf` public S3 ACL, RDS public/unencrypted, 0.0.0.0/0 SG).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from core.plugin_runner import QoD

_ENV_SECRET_RE = re.compile(
    r"(?i)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|PRIVATE_KEY|ACCESS_TOKEN)\s*[=\s]\s*['\"]?([A-Za-z0-9_\-@!#%^&*]{8,})['\"]?\s*$"
)


def audit_dockerfile_text(content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    lines = [ln.strip() for ln in (content or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not any(ln.upper().startswith("FROM ") for ln in lines):
        return issues

    stages: list[list[str]] = []
    for ln in lines:
        if ln.upper().startswith("FROM "):
            stages.append([ln])
        elif stages:
            stages[-1].append(ln)
    final_stage = stages[-1] if stages else lines
    from_stmt = final_stage[0].lower()
    if "from scratch" not in from_stmt:
        user_stmts = [ln.split(None, 1)[1].strip() for ln in final_stage if ln.upper().startswith("USER ") and len(ln.split(None, 1)) == 2]
        last_user = user_stmts[-1].split(":")[0].strip().lower() if user_stmts else "root"
        if last_user in ("root", "0", ""):
            issues.append((
                "Container Image Runs as Root User in Final Stage (CIS Docker 4.1)",
                "Medium", 5.8, "CWE-250",
                "Dockerfile yakuniy bosqichida imtiyozsiz foydalanuvchi (`USER nonroot` yoki `USER 10001`) ko'rsating.",
            ))

    stage_aliases: set[str] = set()
    for ln in lines:
        if ln.upper().startswith("FROM "):
            m_as = re.search(r"(?i)\bAS\s+([A-Za-z0-9._\-]+)", ln)
            img_ref = ln.split()[1].strip() if len(ln.split()) >= 2 else ""
            if img_ref.startswith("--"):
                parts_f = [p for p in ln.split()[1:] if not p.startswith("--")]
                img_ref = parts_f[0] if parts_f else ""
            img_low = img_ref.lower()
            if (
                img_low
                and img_low != "scratch"
                and img_low not in stage_aliases
                and "@sha256:" not in img_low
                and not img_low.startswith("$")
                and (":" not in img_low or img_low.endswith(":latest"))
            ):
                issues.append((
                    f"Dockerfile Base Image Uses Unpinned or ':latest' Tag ({img_ref})",
                    "Medium", 5.3, "CWE-1188",
                    "Konteyner bazaviy obrazini aniq versiya yoki `@sha256:` digest bilan qadang (`:latest` ishlatmang).",
                ))
            if m_as:
                stage_aliases.add(m_as.group(1).lower())

    for ln in lines:
        if ln.upper().startswith("RUN ") and re.search(r"(?i)\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba|z)?sh\b", ln):
            issues.append((
                "Dockerfile Pipes Unverified Remote Script Directly to Shell (RUN curl|sh)",
                "High", 8.2, "CWE-494",
                "Masofaviy skriptlarni SHA-256 xesh tekshiruvisiz to'g'ridan-to'g'ri `sh`/`bash` ga uzatmang.",
            ))
            break
    for ln in lines:
        if ln.upper().startswith("RUN ") and re.search(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b", ln):
            issues.append((
                "Dockerfile Grants World-Writable Permissions (chmod 777)",
                "Medium", 6.1, "CWE-732",
                "Konteyner fayllarida `chmod 777` o'rniga minimal ruxsatlar (`chmod 750` / `640`) o'rnating.",
            ))
            break

    for ln in lines:
        m_sec = _ENV_SECRET_RE.match(ln)
        if m_sec and not m_sec.group(1).startswith("$"):
            issues.append((
                "Hardcoded Credential in Dockerfile ENV/ARG Instruction",
                "High", 7.8, "CWE-798",
                "Maxfiy kalitlarni `ENV`/`ARG` qatlamlarida saqlamang; Docker BuildKit `--secret` ishlating.",
            ))
            break
    return issues


def audit_compose_yaml(content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    try:
        doc = yaml.safe_load(content) or {}
    except Exception:
        return issues
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return issues
    for svc_name, cfg in services.items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("privileged") is True:
            issues.append((
                f"Privileged Container Mode Enabled in Compose ('{svc_name}')",
                "Critical", 9.0, "CWE-250",
                f"`{svc_name}` xizmatidan `privileged: true` ni olib tashlang.",
            ))
        vols = [str(v) for v in (cfg.get("volumes") or [])]
        if any("docker.sock" in v for v in vols):
            issues.append((
                f"Host Docker Socket Mounted in Container ('{svc_name}')",
                "Critical", 9.3, "CWE-250",
                "`/var/run/docker.sock` ulanishini olib tashlang — u host root imtiyoziga chiqish imkonini beradi.",
            ))
        if str(cfg.get("network_mode") or "").lower() == "host" or str(cfg.get("pid") or "").lower() == "host":
            issues.append((
                f"Host Network/PID Namespace Shared in Compose ('{svc_name}')",
                "High", 7.5, "CWE-668",
                "`network_mode: host` / `pid: host` o'rniga izolyatsiyalangan bridge tarmog'idan foydalaning.",
            ))
        caps = [str(c).upper().removeprefix("CAP_") for c in (cfg.get("cap_add") or [])]
        bad_caps = [c for c in caps if c in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN")]
        if bad_caps:
            issues.append((
                f"Dangerous Linux Capabilities Added in Compose ('{svc_name}': {', '.join(bad_caps)})",
                "High", 8.4, "CWE-250",
                f"`{svc_name}` konteyneridan xavfli Linux capability (`{', '.join(bad_caps)}`) ruxsatlarini olib tashlang va `cap_drop: [ALL]` qo'llang.",
            ))
        sec_opts = [str(o).lower().replace(" ", "") for o in (cfg.get("security_opt") or [])]
        if any("seccomp:unconfined" in o or "seccomp=unconfined" in o or "apparmor:unconfined" in o for o in sec_opts):
            issues.append((
                f"Container Seccomp/AppArmor Confinement Disabled in Compose ('{svc_name}')",
                "High", 7.8, "CWE-250",
                "`seccomp:unconfined` / `apparmor:unconfined` ni olib tashlab, default kernel filtrini yoqing.",
            ))
    return issues


def audit_k8s_yaml(content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    k8s_kinds = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
    rbac_kinds = {"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding", "Secret"}
    try:
        docs = list(yaml.safe_load_all(content))
    except Exception:
        return issues
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = str(doc.get("kind") or "")
        res_name = str((doc.get("metadata") or {}).get("name") or kind)
        if kind in ("ClusterRole", "Role"):
            for rl in (doc.get("rules") or []):
                if not isinstance(rl, dict):
                    continue
                verbs = [str(v) for v in (rl.get("verbs") or [])]
                rsrcs = [str(r) for r in (rl.get("resources") or [])]
                if "*" in verbs and ("*" in rsrcs or "secrets" in rsrcs or "pods/exec" in rsrcs):
                    issues.append((
                        f"Kubernetes {kind} Grants Wildcard / Cluster-Admin Privileges ({res_name})",
                        "Critical", 9.1, "CWE-269",
                        f"`{res_name}` rolida `*` (wildcard) huquqlardan voz keching va eng kam imtiyoz tamoyilini qo'llang.",
                    ))
                    break
            continue
        if kind in ("ClusterRoleBinding", "RoleBinding"):
            for subj in (doc.get("subjects") or []):
                sname = str((subj or {}).get("name") or "") if isinstance(subj, dict) else ""
                if sname in ("system:unauthenticated", "system:anonymous"):
                    issues.append((
                        f"Kubernetes {kind} Binds Anonymous/Unauthenticated Principal ({res_name})",
                        "Critical", 9.8, "CWE-306",
                        f"`{res_name}` bog'lamasidan `{sname}` subyektini zudlik bilan olib tashlang.",
                    ))
                    break
            continue
        if kind == "Secret" and str(doc.get("apiVersion") or "") == "v1":
            s_data = {}
            if isinstance(doc.get("stringData"), dict):
                s_data.update(doc["stringData"])
            if isinstance(doc.get("data"), dict):
                s_data.update(doc["data"])
            if any(isinstance(v, str) and len(v.strip()) >= 10 and not v.strip().startswith(("$", "${", "<", "ENC(")) for v in s_data.values()):
                issues.append((
                    f"Cleartext Kubernetes Secret Manifest Committed in Code ({res_name})",
                    "High", 8.1, "CWE-798",
                    "Git repozitoriyda ochiq `kind: Secret` saqlamang; `SealedSecrets` yoki `ExternalSecrets` ishlating.",
                ))
            continue
        if kind == "Ingress":
            ann = (doc.get("metadata") or {}).get("annotations") or {}
            if isinstance(ann, dict):
                bad_snips = [k for k in ann if any(s in str(k).lower() for s in ("configuration-snippet", "server-snippet", "stream-snippet", "modsecurity-snippet"))]
                if bad_snips:
                    issues.append((
                        f"Kubernetes Ingress Dangerous Snippet Annotation ({res_name})",
                        "Critical", 9.0, "CWE-94",
                        "`allow-snippet-annotations: \"false\"` o'rnating va `configuration-snippet`/`server-snippet` annotatsiyalarini olib tashlang.",
                    ))
            continue
        if kind not in k8s_kinds:
            continue
        spec_root = doc.get("spec") or {}
        pod_spec = ((spec_root.get("template") or {}).get("spec") or spec_root) if isinstance(spec_root, dict) else {}
        if not isinstance(pod_spec, dict):
            continue
        if pod_spec.get("hostNetwork") is True or pod_spec.get("hostPID") is True:
            issues.append((
                f"Kubernetes Pod Shares Host Network/PID Namespace ({res_name})",
                "High", 7.8, "CWE-250",
                "Kubernetes Pod spetsifikatsiyasida `hostNetwork: false` va `hostPID: false` o'rnating.",
            ))
        for vol in (pod_spec.get("volumes") or []):
            hp = str(((vol or {}).get("hostPath") or {}).get("path") or "") if isinstance(vol, dict) else ""
            if hp in ("/", "/etc", "/var/run/docker.sock", "/proc"):
                issues.append((
                    f"Sensitive Kubernetes hostPath Volume Mounted ({res_name}: {hp})",
                    "Critical", 9.0, "CWE-250",
                    "Podlarda sezgir host kataloglarini (`hostPath`) ulashni taqiqlang.",
                ))
        for ctr in (pod_spec.get("containers") or []):
            sc = (ctr.get("securityContext") or {}) if isinstance(ctr, dict) else {}
            if isinstance(sc, dict):
                if sc.get("privileged") is True:
                    issues.append((
                        f"Kubernetes Privileged Container Specification ({res_name})",
                        "Critical", 9.1, "CWE-250",
                        "`securityContext.privileged: false` va `allowPrivilegeEscalation: false` o'rnating.",
                    ))
                caps_obj = sc.get("capabilities") if isinstance(sc.get("capabilities"), dict) else {}
                k_caps = [str(c).upper().removeprefix("CAP_") for c in (caps_obj.get("add") or [])]
                bad_k_caps = [c for c in k_caps if c in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH")]
                if bad_k_caps:
                    issues.append((
                        f"Kubernetes Container Adds High-Risk Linux Capabilities ({res_name}: {', '.join(bad_k_caps)})",
                        "High", 8.4, "CWE-250",
                        "`securityContext.capabilities.drop: [\"ALL\"]` o'rnating va `SYS_ADMIN`/`ALL` imtiyozlarini olib tashlang.",
                    ))
    return issues


def audit_terraform_hcl(content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    clean = "\n".join(ln.split("#", 1)[0].split("//", 1)[0] for ln in (content or "").splitlines())
    if re.search(r'acl\s*=\s*"public-read(?:-write)?"', clean):
        issues.append((
            "Terraform Cloud Storage Public ACL Configured",
            "High", 8.2, "CWE-284",
            "`acl = \"private\"` va `aws_s3_bucket_public_access_block` resursini yoqing.",
        ))
    if re.search(r"publicly_accessible\s*=\s*true", clean):
        issues.append((
            "Terraform Database Instance Configured as Publicly Accessible",
            "High", 7.8, "CWE-284",
            "RDS/ma'lumotlar bazasi resursida `publicly_accessible = false` o'rnating.",
        ))
    if re.search(r"storage_encrypted\s*=\s*false", clean):
        issues.append((
            "Terraform Storage Encryption Explicitly Disabled",
            "Medium", 6.5, "CWE-311",
            "Disk va ma'lumotlar omborida `storage_encrypted = true` (KMS) yoqing.",
        ))
    for blk in re.findall(r"ingress\s*\{([^}]*)\}", clean, re.S):
        if "0.0.0.0/0" in blk and re.search(r"(?:from_port|to_port)\s*=\s*(?:22|3389|3306|5432|6379|27017)\b", blk):
            issues.append((
                "Terraform Security Group Exposes Admin/DB Port to 0.0.0.0/0",
                "High", 8.2, "CWE-284",
                "SSH/RDP va ma'lumotlar bazasi portlari uchun `0.0.0.0/0` o'rniga aniq VPN CIDR belgilang.",
            ))
            break
    return issues


def audit_helm_or_ansible_yaml(filename: str, content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    fn = filename.lower()
    try:
        doc = yaml.safe_load(content)
    except Exception:
        return issues
    if fn.startswith("values") and isinstance(doc, dict):
        sc = doc.get("securityContext") or doc.get("containerSecurityContext") or {}
        if isinstance(sc, dict) and sc.get("privileged") is True:
            issues.append((
                f"Helm Chart Values Enables Privileged Container ({filename})",
                "Critical", 9.1, "CWE-250",
                "`values.yaml` da `securityContext.privileged: false` o'rnating.",
            ))
        for k, v in doc.items():
            if any(s in str(k).lower() for s in ("password", "secretkey", "apikey")) and isinstance(v, str):
                vs = v.strip()
                if len(vs) >= 8 and vs.lower() not in ("changeme", "password", "secret") and not vs.startswith(("{{", "${", "ENC(")):
                    issues.append((
                        f"Hardcoded Credential in Helm Values ({filename}: {k})",
                        "High", 8.1, "CWE-798",
                        "`values.yaml` da ochiq parol saqlamang; `existingSecret` dan foydalaning.",
                    ))
                    break
    elif isinstance(doc, list) and any(isinstance(p, dict) and ("tasks" in p or "hosts" in p) for p in doc):
        if re.search(r"(?im)^\s*validate_certs\s*:\s*(?:false|no)\b", content):
            issues.append((
                f"Ansible Playbook Disables TLS Certificate Validation ({filename})",
                "Medium", 5.9, "CWE-295",
                "Ansible vazifalarida `validate_certs: true` saqlang.",
            ))
        if re.search(r"(?im)^\s*(?:shell|command)\s*:.*?\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b", content):
            issues.append((
                f"Ansible Playbook Pipes Unverified Remote Script to Shell ({filename})",
                "High", 8.2, "CWE-829",
                "`get_url` moduli orqali `checksum:` tekshiruvi bilan yuklab oling.",
            ))
    return issues


def audit_nginx_conf_text(content: str) -> list[tuple[str, str, float, str, str]]:
    issues: list[tuple[str, str, float, str, str]] = []
    clean = "\n".join(ln.split("#", 1)[0] for ln in (content or "").splitlines())
    if re.search(r"\bautoindex\s+on\s*;", clean):
        issues.append((
            "Nginx Configuration Enables Directory Listing (autoindex on)",
            "Medium", 5.3, "CWE-548",
            "`nginx.conf` ichida `autoindex off;` o'rnating.",
        ))
    if re.search(r"\bssl_protocols\b[^;]*\bTLSv1(?:\.0\b|\.1\b|(?!\.[0-9])\b)", clean):
        issues.append((
            "Nginx Enables Deprecated TLSv1.0 / TLSv1.1 Protocols",
            "Medium", 5.9, "CWE-326",
            "`ssl_protocols TLSv1.2 TLSv1.3;` o'rnating.",
        ))
    for m_loc in re.finditer(r"location\s+(/[a-zA-Z0-9_\-]+)\s*\{([^}]*)\}", clean, re.S):
        loc_p, body = m_loc.group(1), m_loc.group(2)
        if not loc_p.endswith("/") and re.search(r"\balias\s+/[^;]+/\s*;", body):
            issues.append((
                f"Nginx Off-By-Slash Alias Path Traversal Misconfiguration ({loc_p})",
                "High", 7.5, "CWE-22",
                f"`location {loc_p}/` oxiriga `/` belgisini qo'shing (alias bilan mos bo'lsin).",
            ))
            break
    return issues


def run_iac_security_audit(db: Any, project_id: int, code_paths: list[str], log_fn: Any) -> int:
    skip_parts = ("node_modules", ".git", "__pycache__", "/tests/", "/test/", ".terraform", ".venv", "venv")
    written = 0
    for cp in code_paths:
        if not cp:
            continue
        root = Path(cp)
        if not root.is_dir():
            continue
        for fp in sorted(root.rglob("*"))[:300]:
            if not fp.is_file() or any(sp in str(fp).replace("\\", "/") for sp in skip_parts):
                continue
            fn = fp.name.lower()
            is_docker = fn == "dockerfile" or fn.startswith("dockerfile.")
            is_compose = fn in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
            is_tf = fn.endswith(".tf")
            is_nginx = fn == "nginx.conf" or (fn.endswith(".conf") and "nginx" in str(fp).lower())
            is_yaml = fn.endswith((".yml", ".yaml")) and not is_compose
            if not (is_docker or is_compose or is_tf or is_nginx or is_yaml):
                continue
            try:
                txt = fp.read_text(encoding="utf-8", errors="ignore")[:200000]
            except Exception:
                continue
            found: list[tuple[str, str, float, str, str]] = []
            if is_docker:
                found = audit_dockerfile_text(txt)
            elif is_compose:
                found = audit_compose_yaml(txt)
            elif is_tf:
                found = audit_terraform_hcl(txt)
            elif is_nginx:
                found = audit_nginx_conf_text(txt)
            elif is_yaml and "apiVersion:" in txt and "kind:" in txt:
                found = audit_k8s_yaml(txt)
            elif is_yaml:
                found = audit_helm_or_ansible_yaml(fp.name, txt)
            for title, sev, cvss, cwe, rem in found:
                db.upsert_finding(
                    project_id, "Agent-2 (IaC-Auditor)", title,
                    "Cloud & Container IaC Security", sev, cvss,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", cwe,
                    "A05:2021 - Security Misconfiguration", str(fp),
                    f"IaC File: {fp.name} | Rule verified deterministically",
                    f"`{fp.name}` infratuzilma konfiguratsiyasida konteyner yoki bulut xavfsizligi kamchiligi aniqlandi.",
                    rem, confidence=QoD.HEADER_CONFIG,
                )
                written += 1
    if written and log_fn:
        log_fn(f"  [IAC-AUDITOR] Konteyner/Kubernetes/Terraform tahlili: {written} ta IaC xavfsizlik muammosi aniqlandi.")
    return written

