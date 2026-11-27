"""
SPECTRE Continuous EASM Attack-Surface Drift & Regression Diff Engine
=====================================================================
Compares two scan bundles (baseline project vs current project) to pinpoint:
  1. Newly exposed or decommissioned subdomains;
  2. Newly opened or closed TCP/UDP network ports;
  3. Newly discovered web/API endpoints;
  4. Newly introduced vs remediated security findings.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any


def _norm_asset_key(raw_asset: str) -> tuple[str, str]:
    s = (raw_asset or "").strip()
    if not s:
        return ("", "")
    if "://" in s:
        p = urllib.parse.urlsplit(s)
        return ((p.netloc or "").lower(), (p.path or "/").rstrip("/") or "/")
    return (s.lower(), "")


def _canon_finding_key(f: dict[str, Any]) -> tuple[str, str, str, str, str]:
    title = re.sub(r"\(\d+\s+(?:Hosts|Service Profiles|Server Profiles|JS Bundles|packages|libraries)\)", "", str(f.get("title") or "")).strip().lower()
    cwe = str(f.get("cwe") or "").upper()
    sev = str(f.get("severity") or "")
    a_host, a_path = _norm_asset_key(str(f.get("asset") or ""))
    return (cwe, sev, title, a_host, a_path)


def compute_project_diff(base_bundle: dict[str, Any], curr_bundle: dict[str, Any]) -> dict[str, Any]:
    b_proj = base_bundle.get("project") or {}
    c_proj = curr_bundle.get("project") or {}

    b_doms = {str(d.get("domain") or "").lower() for d in base_bundle.get("domains", []) if d.get("domain")}
    c_doms = {str(d.get("domain") or "").lower() for d in curr_bundle.get("domains", []) if d.get("domain")}
    new_domains = sorted(c_doms - b_doms)
    removed_domains = sorted(b_doms - c_doms)

    def _port_set(bnd: dict[str, Any]) -> set[str]:
        out: set[str] = set()
        for pt in bnd.get("ports", []):
            h = str(pt.get("host") or pt.get("ip") or "").lower()
            p = int(pt.get("port") or 0)
            pr = str(pt.get("protocol") or "tcp").lower()
            sv = str(pt.get("service") or "")
            if h and p:
                out.add(f"{h}:{p}/{pr}" + (f" ({sv})" if sv else ""))
        return out

    b_ports = _port_set(base_bundle)
    c_ports = _port_set(curr_bundle)
    new_ports = sorted(c_ports - b_ports)
    closed_ports = sorted(b_ports - c_ports)

    b_eps = {f"{e.get('method', 'GET')} {e.get('url', '')}" for e in base_bundle.get("endpoints", []) if e.get("url")}
    c_eps = {f"{e.get('method', 'GET')} {e.get('url', '')}" for e in curr_bundle.get("endpoints", []) if e.get("url")}
    new_eps = sorted(c_eps - b_eps)

    b_finds = {
        _canon_finding_key(f): f
        for f in base_bundle.get("findings", [])
        if f.get("triage_status") != "False-Positive" and f.get("severity") != "Info"
    }
    c_finds = {
        _canon_finding_key(f): f
        for f in curr_bundle.get("findings", [])
        if f.get("triage_status") != "False-Positive" and f.get("severity") != "Info"
    }

    new_findings = [
        {"severity": f.get("severity"), "cvss": f.get("cvss_score"), "title": f.get("title"), "asset": f.get("asset")}
        for k, f in c_finds.items() if k not in b_finds
    ]
    remediated_findings = [
        {"severity": f.get("severity"), "cvss": f.get("cvss_score"), "title": f.get("title"), "asset": f.get("asset")}
        for k, f in b_finds.items() if k not in c_finds
    ]

    has_crit = any(x["severity"] == "Critical" for x in new_findings)
    has_high = any(x["severity"] == "High" for x in new_findings)
    if has_crit:
        drift_level = "CRITICAL_DRIFT"
    elif has_high or len(new_ports) >= 3:
        drift_level = "HIGH_DRIFT"
    elif new_findings or new_domains or new_ports:
        drift_level = "MODERATE_DRIFT"
    else:
        drift_level = "STABLE"

    return {
        "baseline_project_id": b_proj.get("id"),
        "current_project_id": c_proj.get("id"),
        "target": c_proj.get("primary_target") or b_proj.get("primary_target") or "",
        "drift_level": drift_level,
        "new_domains": new_domains,
        "removed_domains": removed_domains,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "new_endpoints_count": len(new_eps),
        "sample_new_endpoints": new_eps[:25],
        "new_findings": new_findings,
        "remediated_findings": remediated_findings,
    }


def format_diff_report_text(diff: dict[str, Any]) -> str:
    lines = [
        f"[EASM SURFACE DRIFT ANALYSIS] (Project #{diff.get('baseline_project_id')} -> #{diff.get('current_project_id')})",
        "-" * 78,
        f"Nishon: {diff.get('target')}  |  Drift Darajasi: [{diff.get('drift_level')}]",
        f"Yangi Subdomenlar: +{len(diff.get('new_domains', []))}  |  Yopilgan Subdomenlar: -{len(diff.get('removed_domains', []))}",
        f"Yangi Ochiq Portlar: +{len(diff.get('new_ports', []))}  |  Yopilgan Portlar: -{len(diff.get('closed_ports', []))}",
        f"Yangi Endpointlar: +{diff.get('new_endpoints_count', 0)}",
        f"Yangi Zaifliklar: +{len(diff.get('new_findings', []))}  |  Bartaraf Etilgan (Fixed): -{len(diff.get('remediated_findings', []))}",
        "-" * 78,
    ]
    if diff.get("new_domains"):
        lines.append("[+] YANGI SUBDOMENLAR: " + ", ".join(diff["new_domains"][:15]))
    if diff.get("new_ports"):
        lines.append("[+] YANGI OCHIQ PORTLAR: " + ", ".join(diff["new_ports"][:15]))
    if diff.get("new_findings"):
        lines.append("[CRITICAL/HIGH DRIFT — YANGI TOPILGAN ZAIFLIKLAR]:")
        for nf in diff["new_findings"][:15]:
            lines.append(f"  - [{nf['severity']} | {nf['cvss']}] {nf['title']} ({nf['asset']})")
    if diff.get("remediated_findings"):
        lines.append("[REMEDIATED — YOPILGAN ZAIFLIKLAR]:")
        for rf in diff["remediated_findings"][:15]:
            lines.append(f"  * [{rf['severity']}] {rf['title']}")
    return "\n".join(lines)
