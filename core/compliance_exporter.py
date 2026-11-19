"""
SPECTRE Enterprise Compliance & DevSecOps Exporter (OASIS SARIF 2.1.0 & CycloneDX 1.5 SBOM)
===========================================================================================
Exports findings to OASIS SARIF 2.1.0 (compatible with GitHub Security, GitLab,
DefectDojo, and VS Code SARIF Viewer) and generates a CycloneDX 1.5 Software
Bill of Materials (SBOM) from discovered NIST CPE 2.3 components.
"""
from __future__ import annotations

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
                    "version": "3.7.0",
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
    for cpe in sorted(cpes):
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 else "unknown"
        name = parts[4] if len(parts) > 4 else "component"
        ver = parts[5] if len(parts) > 5 else "*"
        components.append({
            "type": "application",
            "publisher": vendor,
            "name": name,
            "version": ver,
            "cpe": cpe,
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
    }


def export_sarif_and_sbom(bundle: dict[str, Any], out_dir: Path, project_id: int) -> tuple[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_p = out_dir / f"project_{project_id}_findings.sarif.json"
    sbom_p = out_dir / f"project_{project_id}_sbom.cdx.json"
    sarif_p.write_text(json.dumps(build_sarif_report(bundle), indent=2, ensure_ascii=False), encoding="utf-8")
    sbom_p.write_text(json.dumps(build_cyclonedx_sbom(bundle), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(sarif_p), str(sbom_p)
