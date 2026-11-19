"""
SPECTRE Software Composition Analysis (SCA) & OSV.dev Batch Advisory Engine
===========================================================================
Audits `package.json`, `composer.json`, `requirements.txt`, and `go.mod`
manifests (from White-Box source paths, unpacked SourceMaps, or exposed web
manifests) against deterministic offline SemVer rules and cached OSV.dev batch
queries (200,000+ open-source CVEs/GHSAs).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import requests

from core.advisory_kb import version_in_range
from core.plugin_runner import QoD

ROOT_DIR = Path(__file__).resolve().parent.parent
OSV_CACHE_PATH = ROOT_DIR / "workspaces" / "osv_advisory_cache.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

OFFLINE_SCA_RULES: tuple[dict[str, Any], ...] = (
    {"eco": "npm", "pkg": "lodash", "min": "0.1.0", "max": "4.17.21", "cve": "CVE-2021-23337", "sev": "High", "cvss": 7.2},
    {"eco": "npm", "pkg": "axios", "min": "0.8.1", "max": "1.6.0", "cve": "CVE-2023-45857", "sev": "Medium", "cvss": 6.5},
    {"eco": "npm", "pkg": "express", "min": "4.0.0", "max": "4.19.2", "cve": "CVE-2024-29041", "sev": "Medium", "cvss": 6.1},
    {"eco": "npm", "pkg": "jsonwebtoken", "min": "0.1.0", "max": "9.0.0", "cve": "CVE-2022-23529", "sev": "High", "cvss": 7.6},
    {"eco": "PyPI", "pkg": "requests", "min": "2.3.0", "max": "2.31.0", "cve": "CVE-2023-32681", "sev": "Medium", "cvss": 6.1},
    {"eco": "PyPI", "pkg": "urllib3", "min": "1.20.0", "max": "2.0.7", "cve": "CVE-2023-45803", "sev": "Medium", "cvss": 4.2},
    {"eco": "PyPI", "pkg": "jinja2", "min": "2.0.0", "max": "3.1.3", "cve": "CVE-2024-22195", "sev": "Medium", "cvss": 6.1},
    {"eco": "PyPI", "pkg": "pyyaml", "min": "3.0.0", "max": "5.4.0", "cve": "CVE-2020-14343", "sev": "Critical", "cvss": 9.8},
    {"eco": "PyPI", "pkg": "cryptography", "min": "3.0.0", "max": "42.0.0", "cve": "CVE-2023-50782", "sev": "High", "cvss": 7.5},
    {"eco": "Packagist", "pkg": "guzzlehttp/guzzle", "min": "6.0.0", "max": "7.4.5", "cve": "CVE-2022-31090", "sev": "High", "cvss": 8.1},
    {"eco": "Packagist", "pkg": "firebase/php-jwt", "min": "1.0.0", "max": "6.0.0", "cve": "CVE-2021-46743", "sev": "High", "cvss": 8.1},
    {"eco": "Go", "pkg": "golang.org/x/net", "min": "0.1.0", "max": "0.23.0", "cve": "CVE-2023-45288", "sev": "High", "cvss": 7.5},
)

_CLEAN_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def parse_manifest_dependencies(filename: str, content: str) -> list[tuple[str, str, str]]:
    """Extracts `(ecosystem, package_name, clean_version)` tuples from manifest text."""
    fname = filename.lower().split("/")[-1]
    deps: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    if fname in ("package.json", "composer.json"):
        eco = "npm" if fname == "package.json" else "Packagist"
        try:
            obj = json.loads(content)
        except Exception:
            return deps
        keys = ("dependencies", "devDependencies") if eco == "npm" else ("require",)
        for k in keys:
            sec = obj.get(k)
            if isinstance(sec, dict):
                for pkg, raw_v in sec.items():
                    if pkg == "php" or str(pkg).startswith("ext-"):
                        continue
                    mv = _CLEAN_VER_RE.search(str(raw_v))
                    if mv and (eco, pkg) not in seen:
                        seen.add((eco, pkg))
                        deps.append((eco, str(pkg).strip(), mv.group(1)))
    elif fname == "requirements.txt":
        for ln in content.splitlines():
            s = ln.split("#", 1)[0].strip()
            m = re.match(r"^([a-zA-Z0-9._\-]+)\s*(?:==|~=)\s*(\d+\.\d+(?:\.\d+)?)", s)
            if m and ("PyPI", m.group(1).lower()) not in seen:
                seen.add(("PyPI", m.group(1).lower()))
                deps.append(("PyPI", m.group(1).lower(), m.group(2)))
    elif fname == "go.mod":
        for m in re.finditer(r"^\s*([a-zA-Z0-9./_\-]+\.[a-zA-Z0-9./_\-]+)\s+v(\d+\.\d+\.\d+)", content, re.M):
            if ("Go", m.group(1)) not in seen:
                seen.add(("Go", m.group(1)))
                deps.append(("Go", m.group(1), m.group(2)))
    return deps


def _load_osv_cache() -> dict[str, list[str]]:
    if OSV_CACHE_PATH.is_file():
        try:
            return json.loads(OSV_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def match_dependencies_advisories(
    deps: list[tuple[str, str, str]],
    allow_online_osv: bool = True,
) -> list[dict[str, Any]]:
    if not deps:
        return []
    hits_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for eco, pkg, ver in deps:
        for rl in OFFLINE_SCA_RULES:
            if rl["eco"] == eco and rl["pkg"] == pkg.lower() and version_in_range(ver, rl["min"], rl["max"]):
                hits_map[(eco, pkg, ver)] = {
                    "eco": eco, "pkg": pkg, "ver": ver, "cves": [rl["cve"]],
                    "sev": rl["sev"], "cvss": float(rl["cvss"]),
                }

    if allow_online_osv:
        cache = _load_osv_cache()
        uncached = [(e, p, v) for e, p, v in deps[:60] if f"{e}:{p}:{v}" not in cache]
        if uncached:
            try:
                q_list = [{"package": {"name": p, "ecosystem": e}, "version": v} for e, p, v in uncached]
                r = requests.post(OSV_BATCH_URL, json={"queries": q_list}, timeout=4.0)
                if r.status_code == 200:
                    res_arr = r.json().get("results", [])
                    for (e, p, v), r_item in zip(uncached, res_arr):
                        v_ids = [str(vo.get("id") or "") for vo in (r_item.get("vulns") or [])[:4] if vo.get("id")]
                        cache[f"{e}:{p}:{v}"] = v_ids
                    OSV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                    OSV_CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
            except Exception:
                pass
        for eco, pkg, ver in deps[:60]:
            cached_ids = cache.get(f"{eco}:{pkg}:{ver}") or []
            if cached_ids:
                cur = hits_map.get((eco, pkg, ver))
                if cur:
                    for cid in cached_ids:
                        if cid not in cur["cves"]:
                            cur["cves"].append(cid)
                else:
                    hits_map[(eco, pkg, ver)] = {
                        "eco": eco, "pkg": pkg, "ver": ver, "cves": list(cached_ids[:3]),
                        "sev": "High", "cvss": 7.5,
                    }
    return list(hits_map.values())


def run_sca_dependency_audit(
    db: Any,
    project_id: int,
    code_paths: list[str],
    log_fn: Any,
    allow_online_osv: bool = True,
) -> int:
    manifest_names = {"package.json", "composer.json", "requirements.txt", "go.mod"}
    skip_parts = ("node_modules", ".git", "__pycache__", "/tests/", "/test/", ".venv", "venv")
    total_written = 0

    for cp in code_paths:
        if not cp:
            continue
        root = Path(cp)
        if not root.is_dir():
            continue
        for mf in sorted(root.rglob("*")):
            if mf.name.lower() not in manifest_names or not mf.is_file():
                continue
            if any(sp in str(mf) for sp in skip_parts):
                continue
            try:
                raw_txt = mf.read_text(encoding="utf-8", errors="ignore")[:300000]
            except Exception:
                continue
            deps = parse_manifest_dependencies(mf.name, raw_txt)
            vuln_deps = match_dependencies_advisories(deps, allow_online_osv=allow_online_osv)
            if not vuln_deps:
                continue
            top_cvss = max(x["cvss"] for x in vuln_deps)
            top_sev = "Critical" if top_cvss >= 9.0 else ("High" if top_cvss >= 7.0 else "Medium")
            ev_items = [f"{x['pkg']}@{x['ver']} ({', '.join(x['cves'][:2])})" for x in vuln_deps[:8]]
            db.upsert_finding(
                project_id,
                "Agent-2 (SCA-Engine)",
                f"Vulnerable Open-Source Dependencies in {mf.name} ({len(vuln_deps)} packages)",
                "Software Composition Analysis (SCA)",
                top_sev,
                top_cvss,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                "CWE-1395",
                "A06:2021 - Vulnerable and Outdated Components",
                str(mf),
                f"Manifest: {mf.name} | Vulnerable Packages: {' | '.join(ev_items)}",
                f"`{mf.name}` faylida ma'lum CVE/GHSA zaifliklariga ega eskirgan kutubxona versiyalari aniqlandi.",
                "Kutubxona versiyalarini xavfsiz LTS relizlarga yangilang (`npm audit fix` / `pip install -U` / `composer update`).",
                confidence=QoD.HEADER_CONFIG,
            )
            total_written += 1
            if log_fn:
                log_fn(f"  [SCA-ENGINE] {mf.name} -> {len(vuln_deps)} ta zaif kutubxona aniqlandi: {', '.join(ev_items[:4])}")
    return total_written

