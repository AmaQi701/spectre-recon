"""
SPECTRE Enterprise Compliance & DevSecOps Exporter (OASIS SARIF 2.1.0 & CycloneDX 1.5 SBOM)
===========================================================================================
Exports findings to OASIS SARIF 2.1.0 (compatible with GitHub Security, GitLab,
DefectDojo, and VS Code SARIF Viewer) and generates a CycloneDX 1.5 Software
Bill of Materials (SBOM) from discovered NIST CPE 2.3 components.
"""
from __future__ import annotations

import hashlib
import html
import json
import math
import re
from pathlib import Path
from typing import Any

from core.advisory_kb import extract_cpe_inventory
from core.native_bridge import fast_cvss31_score, fast_rust_triage_brocards_score

_XML_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xml_clean(val: object, max_len: int = 0) -> str:
    s = _XML_CTRL_RE.sub("", str(val or ""))
    if max_len > 0:
        s = s[:max_len]
    return html.escape(s, quote=True)


_CVSS31_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss31_base_score(vector: str) -> float:
    """Official FIRST.org CVSS v3.1 Base Score calculator (Rust FFI accelerated)."""
    rs_score = fast_cvss31_score(vector)
    if rs_score is not None:
        return rs_score
    v_trim = (vector or "").strip()
    if not v_trim.upper().startswith(("CVSS:3.1/", "CVSS:3.0/")):
        return 0.0
    metrics: dict[str, str] = {}
    for idx, tok in enumerate(v_trim.split("/")):
        if idx == 0:
            continue
        if ":" not in tok:
            return 0.0
        k, v = tok.split(":", 1)
        if len(v.strip()) != 1:
            return 0.0
        metrics[k.strip().upper()] = v.strip().upper()
    if not {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}.issubset(metrics):
        return 0.0
    scope_changed = metrics["S"] == "C"
    pr_map = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.50 if scope_changed else 0.27}
    try:
        av = _CVSS31_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS31_WEIGHTS["AC"][metrics["AC"]]
        pr = pr_map[metrics["PR"]]
        ui = _CVSS31_WEIGHTS["UI"][metrics["UI"]]
        c_w = _CVSS31_WEIGHTS["C"][metrics["C"]]
        i_w = _CVSS31_WEIGHTS["I"][metrics["I"]]
        a_w = _CVSS31_WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return 0.0
    iss = 1.0 - ((1.0 - c_w) * (1.0 - i_w) * (1.0 - a_w))
    if iss <= 0.0:
        return 0.0
    impact = (7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)) if scope_changed else (6.42 * iss)
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability), 10.0)
    return math.ceil(round(raw * 100000) / 10000.0) / 10.0


def build_sarif_report(bundle: dict[str, Any]) -> dict[str, Any]:
    findings = [
        f for f in bundle.get("findings", [])
        if f.get("triage_status") != "False-Positive" and f.get("severity") != "Info"
    ]
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    sev_to_level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}

    for f in findings:
        cwe = str(f.get("cwe") or "CWE-200")
        title = str(f.get("title") or "Security Finding")
        slug_t = re.sub(r"[^A-Za-z0-9._\-]", "_", title).strip("_")
        if len(slug_t) > 64:
            th = hashlib.sha256(title.encode("utf-8", errors="ignore")).hexdigest()[:8]
            slug_t = f"{slug_t[:54]}_{th}"
        rule_id = f"{cwe}_{slug_t}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": str(f.get("root_cause") or title)},
                "help": {"text": str(f.get("remediation") or "")},
                "properties": {
                    "tags": [cwe, str(f.get("owasp") or ""), str(f.get("category") or "")],
                    "security-severity": str(f.get("cvss_score") or 5.0),
                },
            }
        asset = str(f.get("asset") or "target").strip()
        phys_loc: dict[str, Any] = {"artifactLocation": {"uri": asset}}
        if not asset.startswith(("http://", "https://", "ssh://")) and ":" in asset:
            u_part, ln_part = asset.rsplit(":", 1)
            if u_part and ln_part.isdigit() and int(ln_part) >= 1 and "." in u_part.split("/")[-1]:
                phys_loc = {
                    "artifactLocation": {"uri": u_part},
                    "region": {"startLine": int(ln_part)},
                }
        conf_s = str(f.get("confidence") or "")
        m_q = re.search(r"QoD:\s*(\d+)%", conf_s)
        qod_v = int(m_q.group(1)) if m_q else 80
        broc_score = fast_rust_triage_brocards_score(
            str(f.get("severity") or "Medium"),
            cwe,
            asset,
            str(f.get("evidence") or ""),
            str(f.get("remediation") or ""),
            qod=qod_v,
        )
        results.append({
            "ruleId": rule_id,
            "level": sev_to_level.get(str(f.get("severity") or "Medium"), "warning"),
            "message": {"text": f"{title} | Evidence: {f.get('evidence', '')}"},
            "locations": [{"physicalLocation": phys_loc}],
            "properties": {
                "cvss": f.get("cvss_score"),
                "confidence": conf_s,
                "agent": f.get("agent", ""),
                "triageBrocardsScore": broc_score,
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SPECTRE Hybrid Security Studio",
                    "version": "10.0.0",
                    "informationUri": "https://github.com/AmaQi701/spectre-recon",
                    "rules": list(rules_map.values()),
                }
            },
            "results": results,
        }],
    }


def build_cyclonedx_sbom(bundle: dict[str, Any]) -> dict[str, Any]:
    proj = bundle.get("project") or {}
    cpes: set[str] = set()
    for svc in bundle.get("http_services", []):
        blob = f"{svc.get('server', '')}\n{svc.get('tech_stack', '')}"
        cpes.update(extract_cpe_inventory(blob))
    for pt in bundle.get("ports", []):
        blob_p = f"{pt.get('service', '')}\n{pt.get('version', '')}\n{pt.get('banner', '')}"
        cpes.update(extract_cpe_inventory(blob_p))

    components: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for cpe in sorted(cpes):
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 else "unknown"
        name = parts[4] if len(parts) > 4 else "component"
        ver = parts[5] if len(parts) > 5 else "*"
        seen_refs.add(cpe)
        components.append({
            "bom-ref": cpe,
            "type": "application",
            "publisher": vendor,
            "name": name,
            "version": ver,
            "cpe": cpe,
        })

    vulnerabilities: list[dict[str, Any]] = []
    seen_vulns: set[tuple[str, str]] = set()
    purl_re = re.compile(r"(pkg:[a-z0-9]+/[^\s()|]+@([^\s()|]+))")
    cve_re = re.compile(r"\b((?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9\-]{10,}))\b", re.I)

    for f in bundle.get("findings", []):
        if f.get("triage_status") == "False-Positive":
            continue
        ev = str(f.get("evidence") or "")
        title = str(f.get("title") or "")
        sev = str(f.get("severity") or "Medium").lower()
        cvss = float(f.get("cvss_score") or 5.0)
        for purl_full, p_ver in purl_re.findall(ev):
            p_name = purl_full.split("/", 1)[-1].rsplit("@", 1)[0].replace("%40", "@")
            if purl_full not in seen_refs:
                seen_refs.add(purl_full)
                components.append({
                    "bom-ref": purl_full,
                    "type": "library",
                    "name": p_name,
                    "version": p_ver,
                    "purl": purl_full,
                })
        root_app_name = str(proj.get("primary_target") or proj.get("name") or "target")
        root_bom_ref = f"app:{root_app_name}"
        ref_candidates = [m[0] for m in purl_re.findall(ev)] + [c for c in extract_cpe_inventory(ev) if c in seen_refs]
        target_ref = ref_candidates[0] if ref_candidates else root_bom_ref
        for vid in cve_re.findall(f"{title} {ev}"):
            vid_u = vid.upper()
            if (vid_u, target_ref) not in seen_vulns:
                seen_vulns.add((vid_u, target_ref))
                vulnerabilities.append({
                    "id": vid_u,
                    "ratings": [{"score": cvss, "severity": sev, "method": "CVSSv31"}],
                    "affects": [{"ref": target_ref}],
                    "description": title,
                })

    root_app_lbl = str(proj.get("primary_target") or proj.get("name") or "target")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": f"app:{root_app_lbl}",
                "type": "application",
                "name": root_app_lbl,
            }
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def map_finding_compliance_controls(finding: dict[str, Any]) -> dict[str, str]:
    cwe = str(finding.get("cwe") or "CWE-200").upper()
    cat = str(finding.get("category") or "").lower()
    owasp_2021 = str(finding.get("owasp") or "A05:2021 - Security Misconfiguration")

    if cwe in ("CWE-639", "CWE-284", "CWE-285", "CWE-269") or "bola" in cat or "access control" in cat:
        api_ctrl = "API1:2023 - Broken Object Level Authorization" if "bola" in cat or cwe == "CWE-639" else "API5:2023 - Broken Function Level Authorization"
        pci = "PCI-DSS v4.0 Req 6.2.4 & Req 7.2.2 (Access Control)"
        iso = "ISO/IEC 27001:2022 A.8.3 (Information Access Restriction)"
        nist = "NIST CSF 2.0 PR.AA-05 (Access Permissions & Authorization)"
        soc2 = "SOC 2 CC6.1 & CC6.3 (Logical Access Authorization)"
        mitre = "MITRE ATT&CK v15 T1078 / T1190 (Privilege & Access Abuse)"
    elif cwe in ("CWE-287", "CWE-306", "CWE-347", "CWE-614", "CWE-798") or "jwt" in cat or "session" in cat or "cookie" in cat or re.search(r"\b(?:ai|llm|mcp|rag)\b", cat):
        api_ctrl = "API2:2023 - Broken Authentication"
        pci = "PCI-DSS v4.0 Req 8.3 & Req 6.2.4 (Authentication & Credentials)"
        iso = "ISO/IEC 27001:2022 A.8.5 (Secure Authentication)"
        nist = "NIST CSF 2.0 PR.AA-01 (Identity & Credential Management)"
        soc2 = "SOC 2 CC6.1 (Authentication & Secret Protection)"
        mitre = "MITRE ATT&CK v15 T1552 / T1190 (Unsecured Credentials & Exposed Service)"
    elif cwe in ("CWE-208", "CWE-295", "CWE-319", "CWE-326", "CWE-327") or "tls" in cat or "ssl" in cat or "crypt" in cat:
        api_ctrl = "API8:2023 - Security Misconfiguration (Cryptography & Transport)"
        pci = "PCI-DSS v4.0 Req 4.2.1 & Req 6.2.4 (Strong Cryptography & Side-Channel Resistance)"
        iso = "ISO/IEC 27001:2022 A.8.24 (Use of Cryptography)"
        nist = "NIST CSF 2.0 PR.DS-02 (Data-in-Transit & Cryptographic Verification)"
        soc2 = "SOC 2 CC6.7 (Transmission & Cryptographic Integrity)"
        mitre = "MITRE ATT&CK v15 T1557 / T1600 (Adversary-in-the-Middle & Weaken Encryption)"
    elif cwe in ("CWE-1188", "CWE-636", "CWE-732") or "insecure default" in cat:
        api_ctrl = "API8:2023 - Security Misconfiguration (Insecure Defaults)"
        pci = "PCI-DSS v4.0 Req 2.2.2 & Req 6.2.4 (Fail-Secure Defaults & Vendor Parameters)"
        iso = "ISO/IEC 27001:2022 A.8.9 & A.8.28 (Secure Configuration & Initialization)"
        nist = "NIST CSF 2.0 PR.PS-01 (Secure Default Configuration Baseline)"
        soc2 = "SOC 2 CC6.1 & CC7.1 (Fail-Closed Access & Configuration Integrity)"
        mitre = "MITRE ATT&CK v15 T1552.001 / T1078.001 (Fallback Secrets & Default Initialization)"
    elif cwe in ("CWE-79", "CWE-89", "CWE-78", "CWE-77", "CWE-74", "CWE-94", "CWE-502", "CWE-601", "CWE-22", "CWE-362", "CWE-915", "CWE-770") or "injection" in cat or "xss" in cat or "redirect" in cat or "prompt" in cat:
        api_ctrl = "API3:2023 - Broken Object Property Level Authorization" if cwe == "CWE-915" else ("API4:2023 - Unrestricted Resource Consumption" if cwe == "CWE-770" else "API8:2023 - Security Misconfiguration / Input Validation")
        pci = "PCI-DSS v4.0 Req 6.2.4 (Injection, Concurrency & Schema Integrity)"
        iso = "ISO/IEC 27001:2022 A.8.28 (Secure Coding)"
        nist = "NIST CSF 2.0 PR.PS-05 (Secure Software Development)"
        soc2 = "SOC 2 CC8.1 & CC7.1 (Change & Input Integrity)"
        mitre = "MITRE ATT&CK v15 T1190 / T1059 (Exploit Public-Facing App & Execution)"
    elif cwe == "CWE-918" or "ssrf" in cat:
        api_ctrl = "API7:2023 - Server Side Request Forgery"
        pci = "PCI-DSS v4.0 Req 6.4.1 (Public Web App SSRF Protection)"
        iso = "ISO/IEC 27001:2022 A.8.20 (Networks Security)"
        nist = "NIST CSF 2.0 PR.IR-01 (Network Boundary Protection)"
        soc2 = "SOC 2 CC6.6 (External Network Boundary Controls)"
        mitre = "MITRE ATT&CK v15 T1090 / T1552.005 (Cloud Instance Metadata & Proxy)"
    elif cwe in ("CWE-427", "CWE-494", "CWE-506", "CWE-1104", "CWE-1395", "CWE-829") or "sca" in cat or "supply-chain" in cat or "outdated" in cat or "cve" in cat or "ci/cd" in cat:
        api_ctrl = "API9:2023 - Improper Inventory Management"
        pci = "PCI-DSS v4.0 Req 6.3.2 & Req 6.3.3 (SBOM & Patch Management)"
        iso = "ISO/IEC 27001:2022 A.8.8 (Management of Technical Vulnerabilities)"
        nist = "NIST CSF 2.0 GV.SC-07 & ID.RA-01 (Supply-Chain & Vuln Management)"
        soc2 = "SOC 2 CC7.1 & CC3.2 (Vulnerability & Dependency Management)"
        mitre = "MITRE ATT&CK v15 T1195.002 (Compromise Software Supply Chain)"
    elif cwe == "CWE-444" or "framing" in cat or "desync" in cat:
        api_ctrl = "API8:2023 - Security Misconfiguration (HTTP RFC 9112 Framing)"
        pci = "PCI-DSS v4.0 Req 6.4.1 & Req 2.2 (Reverse Proxy Protocol Hygiene)"
        iso = "ISO/IEC 27001:2022 A.8.20 (Networks Security)"
        nist = "NIST CSF 2.0 PR.IR-01 (Protocol & Proxy Boundary Integrity)"
        soc2 = "SOC 2 CC6.6 (Gateway Boundary Framing Enforcement)"
        mitre = "MITRE ATT&CK v15 T1190 / T1090 (HTTP Proxy Framing & Boundary Bypass)"
    elif cwe == "CWE-250" or "iac" in cat or "container" in cat:
        api_ctrl = "API8:2023 - Security Misconfiguration (Container/Cloud)"
        pci = "PCI-DSS v4.0 Req 2.2 (Container & Cloud Hardening)"
        iso = "ISO/IEC 27001:2022 A.8.9 (Configuration Management)"
        nist = "NIST CSF 2.0 PR.PS-01 (Cloud/IaC Baseline)"
        soc2 = "SOC 2 CC7.1 (Infrastructure Hardening)"
        mitre = "MITRE ATT&CK v15 T1610 / T1611 (Deploy Container & Escape to Host)"
    else:
        api_ctrl = "API8:2023 - Security Misconfiguration"
        pci = "PCI-DSS v4.0 Req 11.3 & Req 2.2 (System Hardening)"
        iso = "ISO/IEC 27001:2022 A.8.9 (Configuration Management)"
        nist = "NIST CSF 2.0 PR.PS-01 (Configuration Management)"
        soc2 = "SOC 2 CC7.1 (System Configuration Monitoring)"
        mitre = "MITRE ATT&CK v15 T1046 / T1592 (Network & Host Surface Discovery)"

    return {
        "owasp_2021": owasp_2021,
        "owasp_api_2023": api_ctrl,
        "pci_dss_v4": pci,
        "iso_27001_2022": iso,
        "nist_csf_2": nist,
        "soc2_tsc": soc2,
        "mitre_attack_v15": mitre,
    }


def build_compliance_matrix(bundle: dict[str, Any]) -> dict[str, Any]:
    findings = [
        f for f in bundle.get("findings", [])
        if f.get("triage_status") != "False-Positive" and f.get("severity") != "Info"
    ]
    by_framework: dict[str, dict[str, list[dict[str, Any]]]] = {
        "owasp_2021": {},
        "owasp_api_2023": {},
        "pci_dss_v4": {},
        "iso_27001_2022": {},
        "nist_csf_2": {},
        "soc2_tsc": {},
        "mitre_attack_v15": {},
    }
    penalty = 0.0
    kev_cnt = 0
    high_epss_cnt = 0
    weights = {"Critical": 18.0, "High": 9.0, "Medium": 3.5, "Low": 1.0}
    epss_re = re.compile(r"\[EPSS:\s*([0-9.]+)%\]")
    for f in findings:
        sev = str(f.get("severity") or "Low")
        ev_s = str(f.get("evidence") or "")
        penalty += weights.get(sev, 1.0)
        if "[CISA-KEV" in ev_s:
            kev_cnt += 1
            penalty += 6.0
        m_ep = epss_re.search(ev_s)
        if m_ep and float(m_ep.group(1)) >= 50.0:
            high_epss_cnt += 1
            penalty += 3.0
        mapped = map_finding_compliance_controls(f)
        entry = {
            "id": f.get("id"),
            "severity": sev,
            "cvss": f.get("cvss_score"),
            "title": f.get("title"),
            "cwe": f.get("cwe"),
            "asset": f.get("asset"),
        }
        for fw_key, ctrl_name in mapped.items():
            by_framework[fw_key].setdefault(ctrl_name, []).append(entry)

    posture_score = max(0, int(round(100.0 - min(95.0, penalty))))
    return {
        "posture_score": posture_score,
        "total_verified_findings": len(findings),
        "kev_findings_count": kev_cnt,
        "high_epss_count": high_epss_cnt,
        "frameworks": {
            fw: {ctrl: len(items) for ctrl, items in sorted(ctrls.items())}
            for fw, ctrls in by_framework.items()
        },
        "detailed_controls": by_framework,
    }


def build_junit_xml(bundle: dict[str, Any]) -> str:
    proj = bundle.get("project") or {}
    target_nm = html.escape(str(proj.get("primary_target") or proj.get("name") or "target"), quote=True)
    findings = [
        f for f in bundle.get("findings", [])
        if f.get("triage_status") != "False-Positive" and f.get("severity") != "Info"
    ]
    fail_sevs = {"Critical", "High", "Medium"}
    failures_n = sum(1 for f in findings if str(f.get("severity")) in fail_sevs)
    tests_n = max(1, len(findings))
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="SPECTRE Enterprise Security Gate" tests="{tests_n}" failures="{failures_n}">',
        f'  <testsuite name="{target_nm}" tests="{tests_n}" failures="{failures_n}">',
    ]
    if not findings:
        lines.append('    <testcase classname="spectre.baseline" name="Zero Verified Vulnerabilities"/>')
    else:
        for f in findings:
            sev = _xml_clean(f.get("severity") or "Low")
            cwe = _xml_clean(f.get("cwe") or "CWE-200")
            title = _xml_clean(f.get("title") or "Finding")
            asset = _xml_clean(f.get("asset") or "")
            ev = _xml_clean(f.get("evidence") or "", 400)
            rem = _xml_clean(f.get("remediation") or "", 300)
            lines.append(f'    <testcase classname="spectre.{cwe}" name="[{sev}] {title}">')
            if sev in fail_sevs:
                lines.append(f'      <failure type="{sev}" message="{title}">Asset: {asset} | Evidence: {ev} | Remediation: {rem}</failure>')
            else:
                lines.append(f'      <system-out>Asset: {asset} | {ev}</system-out>')
            lines.append("    </testcase>")
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines) + "\n"


def export_compliance_suite(bundle: dict[str, Any], out_dir: Path, project_id: int) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_p = out_dir / f"project_{project_id}_findings.sarif.json"
    sbom_p = out_dir / f"project_{project_id}_sbom.cdx.json"
    junit_p = out_dir / f"project_{project_id}_junit.xml"
    comp_p = out_dir / f"project_{project_id}_compliance_matrix.json"
    sarif_p.write_text(json.dumps(build_sarif_report(bundle), indent=2, ensure_ascii=False), encoding="utf-8")
    sbom_p.write_text(json.dumps(build_cyclonedx_sbom(bundle), indent=2, ensure_ascii=False), encoding="utf-8")
    junit_p.write_text(build_junit_xml(bundle), encoding="utf-8")
    comp_p.write_text(json.dumps(build_compliance_matrix(bundle), indent=2, ensure_ascii=False), encoding="utf-8")
    return {
        "sarif_json": str(sarif_p),
        "cyclonedx_sbom_json": str(sbom_p),
        "junit_xml": str(junit_p),
        "compliance_matrix_json": str(comp_p),
    }


def export_sarif_and_sbom(bundle: dict[str, Any], out_dir: Path, project_id: int) -> tuple[str, str]:
    res = export_compliance_suite(bundle, out_dir, project_id)
    return res["sarif_json"], res["cyclonedx_sbom_json"]


def ingest_external_sarif_report(
    sarif_path: str | Path,
    db: Any,
    project_id: int,
) -> dict[str, int]:
    """Ingests Semgrep/CodeQL/Trivy OASIS SARIF 2.1.0 findings via the 7-Gate Refuting Triage Pipeline."""
    from core.native_bridge import fast_rust_refute_triage_7gate

    pf = Path(sarif_path)
    if not pf.is_file() or pf.stat().st_size > (64 * 1024 * 1024):
        return {"ingested": 0, "refuted": 0}
    try:
        doc = json.loads(pf.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {"ingested": 0, "refuted": 0}

    level_to_sev = {"error": ("High", 8.1), "warning": ("Medium", 5.8), "note": ("Low", 3.5)}
    ingested = 0
    refuted = 0
    for run in (doc.get("runs") or []):
        if not isinstance(run, dict):
            continue
        drv = (run.get("tool") or {}).get("driver") or {}
        tool_name = str(drv.get("name") or "SARIF-Tool").strip()[:36]
        rule_lookup: dict[str, dict[str, Any]] = {}
        for r_item in (drv.get("rules") or []):
            if isinstance(r_item, dict) and r_item.get("id"):
                rule_lookup[str(r_item["id"])] = r_item

        for res in (run.get("results") or []):
            if not isinstance(res, dict):
                continue
            rid = str(res.get("ruleId") or "EXTERNAL-RULE")
            r_meta = rule_lookup.get(rid) or {}
            lvl = str(res.get("level") or "warning").lower()
            sev, cvss = level_to_sev.get(lvl, ("Medium", 5.8))
            props = {**(r_meta.get("properties") or {}), **(res.get("properties") or {})}
            if str(props.get("security-severity") or "").replace(".", "", 1).isdigit():
                sc_f = float(props["security-severity"])
                cvss = round(min(10.0, max(1.0, sc_f)), 1)
                sev = "Critical" if cvss >= 9.0 else ("High" if cvss >= 7.0 else ("Medium" if cvss >= 4.0 else "Low"))

            cwe = "CWE-200"
            for tg in (props.get("tags") or []):
                m_cwe = re.search(r"(CWE-\d+)", str(tg), re.I)
                if m_cwe:
                    cwe = m_cwe.group(1).upper()
                    break
            if cwe == "CWE-200":
                m_rid = re.search(r"(CWE-\d+)", rid, re.I)
                if m_rid:
                    cwe = m_rid.group(1).upper()

            locs = res.get("locations") or []
            uri = "repo-artifact"
            line_no = 0
            if locs and isinstance(locs[0], dict):
                pl = locs[0].get("physicalLocation") or {}
                uri = str((pl.get("artifactLocation") or {}).get("uri") or "repo-artifact")
                line_no = int((pl.get("region") or {}).get("startLine") or 0)
            asset = f"{uri}:{line_no}" if line_no > 0 else uri
            msg_txt = str((res.get("message") or {}).get("text") or rid).strip()[:300]
            rem_txt = str((r_meta.get("help") or {}).get("text") or "Review finding and apply parameterized/safe API pattern.").strip()[:260]
            if len(rem_txt) < 10:
                rem_txt = "Apply framework-recommended defensive remediation."

            gate = fast_rust_refute_triage_7gate(sev, cwe, asset, msg_txt, rem_txt, qod=85)
            if gate.get("verdict") == "REFUTED_FALSE_POSITIVE":
                refuted += 1
                continue
            adj_qod = int(gate.get("adjusted_qod") or 85)
            db.upsert_finding(
                project_id,
                f"SPECTRE-SAST ({tool_name})",
                f"[{tool_name}] {rid}: {msg_txt[:95]}",
                "External SARIF Static Analysis",
                sev,
                cvss,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                cwe,
                "A03:2021 - Injection",
                asset,
                msg_txt,
                f"Imported from OASIS SARIF 2.1.0 ({tool_name}, rule `{rid}`).",
                rem_txt,
                confidence=f"QoD: {adj_qod}% [7-Gate SARIF Verified]",
            )
            ingested += 1
    return {"ingested": ingested, "refuted": refuted}

