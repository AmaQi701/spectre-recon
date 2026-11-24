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
import re
from pathlib import Path
from typing import Any

from core.advisory_kb import extract_cpe_inventory


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
                    "version": "7.0.0",
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

    if cwe in ("CWE-639", "CWE-284", "CWE-285") or "bola" in cat or "access control" in cat:
        api_ctrl = "API1:2023 - Broken Object Level Authorization" if "bola" in cat or cwe == "CWE-639" else "API5:2023 - Broken Function Level Authorization"
        pci = "PCI-DSS v4.0 Req 6.2.4 & Req 7.2.2 (Access Control)"
        iso = "ISO/IEC 27001:2022 A.8.3 (Information Access Restriction)"
        nist = "NIST CSF 2.0 PR.AA-05 (Access Permissions & Authorization)"
        soc2 = "SOC 2 CC6.1 & CC6.3 (Logical Access Authorization)"
    elif cwe in ("CWE-287", "CWE-306", "CWE-347", "CWE-614", "CWE-798") or "jwt" in cat or "session" in cat or "cookie" in cat:
        api_ctrl = "API2:2023 - Broken Authentication"
        pci = "PCI-DSS v4.0 Req 8.3 & Req 6.2.4 (Authentication & Credentials)"
        iso = "ISO/IEC 27001:2022 A.8.5 (Secure Authentication)"
        nist = "NIST CSF 2.0 PR.AA-01 (Identity & Credential Management)"
        soc2 = "SOC 2 CC6.1 (Authentication & Secret Protection)"
    elif cwe in ("CWE-295", "CWE-319", "CWE-326", "CWE-327") or "tls" in cat or "ssl" in cat or "crypt" in cat:
        api_ctrl = "API8:2023 - Security Misconfiguration (Transport TLS)"
        pci = "PCI-DSS v4.0 Req 4.2.1 (Strong Cryptography in Transit)"
        iso = "ISO/IEC 27001:2022 A.8.24 (Use of Cryptography)"
        nist = "NIST CSF 2.0 PR.DS-02 (Data-in-Transit Protection)"
        soc2 = "SOC 2 CC6.7 (Transmission Encryption)"
    elif cwe in ("CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-601") or "injection" in cat or "xss" in cat or "redirect" in cat:
        api_ctrl = "API8:2023 - Security Misconfiguration / Input Validation"
        pci = "PCI-DSS v4.0 Req 6.2.4 (Injection & XSS Prevention)"
        iso = "ISO/IEC 27001:2022 A.8.28 (Secure Coding)"
        nist = "NIST CSF 2.0 PR.PS-05 (Secure Software Development)"
        soc2 = "SOC 2 CC8.1 & CC7.1 (Change & Input Integrity)"
    elif cwe == "CWE-918" or "ssrf" in cat:
        api_ctrl = "API7:2023 - Server Side Request Forgery"
        pci = "PCI-DSS v4.0 Req 6.4.1 (Public Web App SSRF Protection)"
        iso = "ISO/IEC 27001:2022 A.8.20 (Networks Security)"
        nist = "NIST CSF 2.0 PR.IR-01 (Network Boundary Protection)"
        soc2 = "SOC 2 CC6.6 (External Network Boundary Controls)"
    elif cwe in ("CWE-1104", "CWE-1395", "CWE-829") or "sca" in cat or "outdated" in cat or "cve" in cat or "ci/cd" in cat:
        api_ctrl = "API9:2023 - Improper Inventory Management"
        pci = "PCI-DSS v4.0 Req 6.3.2 & Req 6.3.3 (SBOM & Patch Management)"
        iso = "ISO/IEC 27001:2022 A.8.8 (Management of Technical Vulnerabilities)"
        nist = "NIST CSF 2.0 GV.SC-07 & ID.RA-01 (Supply-Chain & Vuln Management)"
        soc2 = "SOC 2 CC7.1 & CC3.2 (Vulnerability & Dependency Management)"
    else:
        api_ctrl = "API8:2023 - Security Misconfiguration"
        pci = "PCI-DSS v4.0 Req 11.3 & Req 2.2 (System Hardening)"
        iso = "ISO/IEC 27001:2022 A.8.9 (Configuration Management)"
        nist = "NIST CSF 2.0 PR.PS-01 (Configuration Management)"
        soc2 = "SOC 2 CC7.1 (System Configuration Monitoring)"

    return {
        "owasp_2021": owasp_2021,
        "owasp_api_2023": api_ctrl,
        "pci_dss_v4": pci,
        "iso_27001_2022": iso,
        "nist_csf_2": nist,
        "soc2_tsc": soc2,
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
