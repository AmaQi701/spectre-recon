"""
SPECTRE Autonomous CISA KEV & Advisory Feed Synchronizer
========================================================
Maintains a local offline cache of the official CISA Known Exploited
Vulnerabilities (KEV) catalog (`workspaces/cisa_kev_cache.json`) and enriches
discovered CVE findings with active exploitation metadata so SPECTRE continues
to receive threat-intelligence updates autonomously without external AI APIs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
KEV_CACHE_PATH = ROOT_DIR / "workspaces" / "cisa_kev_cache.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

BUILTIN_KEV_SET: dict[str, str] = {
    "CVE-2021-41773": "Apache HTTP Server 2.4.49 Path Traversal",
    "CVE-2021-42013": "Apache HTTP Server 2.4.49/2.4.50 Path Traversal",
    "CVE-2021-43798": "Grafana Directory Traversal",
    "CVE-2022-22965": "Spring Framework Spring4Shell",
    "CVE-2023-23752": "Joomla Improper Access Check",
    "CVE-2023-34362": "Progress MOVEit Transfer SQLi",
    "CVE-2023-44487": "HTTP/2 Rapid Reset Resource Exhaustion",
    "CVE-2023-46805": "Ivanti Connect Secure Auth Bypass",
    "CVE-2023-7028": "GitLab Account Takeover via Password Reset",
    "CVE-2024-23897": "Jenkins CLI Arbitrary File Read",
    "CVE-2024-27198": "JetBrains TeamCity Auth Bypass",
    "CVE-2024-3400": "Palo Alto PAN-OS GlobalProtect",
    "CVE-2024-4577": "PHP-CGI Argument Handling",
    "CVE-2024-4956": "Sonatype Nexus Repository 3 Path Traversal",
    "CVE-2024-6387": "OpenSSH regreSSHion Signal Handler Race Condition",
}


def load_local_kev_map() -> dict[str, str]:
    kev_map = dict(BUILTIN_KEV_SET)
    if KEV_CACHE_PATH.exists():
        try:
            data = json.loads(KEV_CACHE_PATH.read_text(encoding="utf-8", errors="ignore"))
            for item in data.get("vulnerabilities", []):
                cid = str(item.get("cveID") or "").strip().upper()
                vend = str(item.get("vendorProject") or "").strip()
                prod = str(item.get("product") or "").strip()
                vname = str(item.get("vulnerabilityName") or item.get("shortDescription") or "CISA KEV").strip()
                ransom = str(item.get("knownRansomwareCampaignUse") or "").strip()
                if cid.startswith("CVE-"):
                    prefix = f"{vend} {prod}: ".strip(": ") if (vend or prod) else ""
                    r_tag = " [Ransomware-Linked]" if ransom.lower() == "known" else ""
                    kev_map[cid] = f"{prefix}{vname}{r_tag}"[:140]
        except Exception:
            pass
    return kev_map


def sync_cisa_kev_feed(timeout: float = 12.0) -> dict[str, Any]:
    """Downloads the latest official CISA KEV JSON catalog to local disk."""
    KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        r = requests.get(CISA_KEV_URL, timeout=timeout)
        if r.status_code == 200 and '"vulnerabilities"' in r.text[:2000]:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            KEV_CACHE_PATH.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            return {
                "ok": True,
                "count": len(vulns),
                "catalog_version": str(data.get("catalogVersion") or ""),
                "date_released": str(data.get("dateReleased") or ""),
                "path": str(KEV_CACHE_PATH),
            }
    except Exception as exc:
        return {"ok": False, "count": len(load_local_kev_map()), "error": str(exc), "path": str(KEV_CACHE_PATH)}
    return {"ok": False, "count": len(load_local_kev_map()), "error": "Invalid response", "path": str(KEV_CACHE_PATH)}


def enrich_project_findings_with_kev(db: Any, project_id: int, log_fn: Any = None) -> int:
    """Tags any discovered project CVE findings that appear in the CISA KEV catalog."""
    kev_map = load_local_kev_map()
    bundle = db.get_project_bundle(project_id)
    findings = bundle.get("findings", [])
    cve_re = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I)
    enriched = 0
    for f in findings:
        blob = f"{f.get('title', '')} {f.get('evidence', '')}"
        matched_kev = []
        for m in cve_re.findall(blob):
            c_up = m.upper()
            if c_up in kev_map and c_up not in matched_kev:
                matched_kev.append(c_up)
        if matched_kev and "[CISA-KEV" not in str(f.get("evidence", "")):
            kev_tag = f" | [CISA-KEV Catalog Match: {', '.join(matched_kev[:4])}]"
            db.upsert_finding(
                project_id,
                f.get("agent", "Agent-2 (CVE-Engine)"),
                f["title"],
                f.get("category", "Vulnerable & Outdated Components"),
                f.get("severity", "High"),
                float(f.get("cvss_score") or 7.5),
                f.get("cvss_vector", ""),
                f.get("cwe", "CWE-1104"),
                f.get("owasp", "A06:2021 - Vulnerable and Outdated Components"),
                f.get("asset", ""),
                str(f.get("evidence") or "") + kev_tag,
                f.get("root_cause", ""),
                f.get("remediation", ""),
                confidence=f.get("confidence", "High"),
                triage_status=f.get("triage_status", "Verified"),
            )
            enriched += 1
    if enriched and log_fn:
        log_fn(f"  [CISA-KEV] {enriched} ta CVE topilmasi CISA Known Exploited Vulnerabilities katalogida tasdiqlandi.")
    return enriched
