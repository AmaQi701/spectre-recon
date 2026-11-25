"""
SPECTRE Enterprise Compliance & DevSecOps Exporter (OASIS SARIF 2.1.0 & CycloneDX 1.5 SBOM)
===========================================================================================
Exports findings to OASIS SARIF 2.1.0 (compatible with GitHub Security, GitLab,
DefectDojo, and VS Code SARIF Viewer) and generates a CycloneDX 1.5 Software
Bill of Materials (SBOM) from discovered NIST CPE 2.3 components.
"""
from __future__ import annotations

import html
import json
import math
import re
from pathlib import Path
from typing import Any

from core.advisory_kb import extract_cpe_inventory
from core.native_bridge import fast_cvss31_score


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
    metrics: dict[str, str] = {}
    for tok in (vector or "").strip().split("/"):
        if ":" in tok and not tok.upper().startswith("CVSS"):
            k, v = tok.split(":", 1)
            metrics[k.upper()] = v.upper()
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
        rule_id = re.sub(r"[^A-Za-z0-9._\-]", "_", f"{cwe}_{title[:48]}").strip("_")
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
        asset = str(f.get("asset") or "target")
        results.append({
            "ruleId": rule_id,
            "level": sev_to_level.get(str(f.get("severity") or "Medium"), "warning"),
            "message": {"text": f"{title} | Evidence: {f.get('evidence', '')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": asset}}}],
            "properties": {
                "cvss": f.get("cvss_score"),
                "confidence": f.get("confidence", ""),
                "agent": f.get("agent", ""),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SPECTRE Hybrid Security Studio",
                    "version": "9.0.0",
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
        ref_candidates = [m[0] for m in purl_re.findall(ev)] + extract_cpe_inventory(ev)
        target_ref = ref_candidates[0] if ref_candidates else str(proj.get("primary_target") or "target")
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

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": str(proj.get("primary_target") or proj.get("name") or "target"),
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
            sev = str(f.get("severity") or "Low")
            cwe = html.escape(str(f.get("cwe") or "CWE-200"), quote=True)
            title = html.escape(str(f.get("title") or "Finding"), quote=True)
            asset = html.escape(str(f.get("asset") or ""), quote=True)
            ev = html.escape(str(f.get("evidence") or "")[:400], quote=True)
            rem = html.escape(str(f.get("remediation") or "")[:300], quote=True)
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
