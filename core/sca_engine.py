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
from core.http_engine import get_project_js_cache_dir
from core.models import walk_safe_repo_files
from core.native_bridge import fast_rust_lookup_cve
from core.plugin_runner import QoD
from core.threat_intel_pack import query_offline_sca_advisories

ROOT_DIR = Path(__file__).resolve().parent.parent
OSV_CACHE_PATH = ROOT_DIR / "workspaces" / "osv_advisory_cache.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

OFFLINE_SCA_RULES: tuple[dict[str, Any], ...] = tuple(json.loads((ROOT_DIR / "config" / "sca_catalog.json").read_text(encoding="utf-8"))["offline_sca_rules"])

_CLEAN_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


SUPPORTED_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock",
    "requirements.txt", "pipfile.lock", "poetry.lock", "pyproject.toml",
    "go.mod", "cargo.lock", "gemfile.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "packages.lock.json",
    "pubspec.lock", "mix.lock", ".npmrc", "pip.conf",
}

CISA_KEV_CVES: frozenset[str] = frozenset({
    "CVE-2021-44228", "CVE-2022-22965", "CVE-2023-44487", "CVE-2021-44906",
    "CVE-2022-25845", "CVE-2022-42889", "CVE-2023-37466", "CVE-2023-48022",
    "CVE-2024-1597", "CVE-2024-27198", "CVE-2024-3400",
})

_SUSPICIOUS_HOOK_RE = re.compile(
    r"(?i)(?:\b(?:curl|wget|Invoke-WebRequest|iwr|powershell|pwsh|nc|ncat)\b|"
    r"\b(?:sh|bash|zsh)\s+-c\b|\bnode\s+-e\b|\bpython3?\s+-c\b|\beval\s*\(|base64\s+-d)"
)


def audit_supply_chain_manifest_risks(filename: str, content: str) -> list[tuple[str, str, float, str, str]]:
    """
    Supply-Chain Risk Auditor (`trailofbits/supply-chain-risk-auditor` parity):
      1. Malicious/risky `preinstall`/`install`/`postinstall` shell/network hooks (`CWE-506`);
      2. Dependency Confusion `--extra-index-url` / cleartext `http://` registry (`CWE-427`);
      3. Unpinned `*` / `latest` / `http://` tarball production dependencies (`CWE-1104`).
    """
    issues: list[tuple[str, str, float, str, str]] = []
    fname = (filename or "").lower().split("/")[-1]
    txt = content or ""

    if fname in ("package.json", "composer.json"):
        try:
            obj = json.loads(txt)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            scripts = obj.get("scripts") if isinstance(obj.get("scripts"), dict) else {}
            hook_keys = ("preinstall", "install", "postinstall", "preuninstall", "post-install-cmd", "post-update-cmd")
            for hk in hook_keys:
                cmd_val = scripts.get(hk)
                cmd_str = " && ".join(str(x) for x in cmd_val) if isinstance(cmd_val, list) else str(cmd_val or "")
                if cmd_str and _SUSPICIOUS_HOOK_RE.search(cmd_str):
                    issues.append((
                        f"Suspicious Package Lifecycle Hook '{hk}' Executes Shell/Network Payload ({fname})",
                        "Critical", 9.3, "CWE-506",
                        f"`{fname}` ichidagi `{hk}` lifecycle skriptini tekshiring va CI da `npm ci --ignore-scripts` rejimini yoqing.",
                    ))
                    break
            deps_sec = obj.get("dependencies") if fname == "package.json" else obj.get("require")
            if isinstance(deps_sec, dict):
                unpinned = [
                    f"{k}:{v}" for k, v in deps_sec.items()
                    if isinstance(v, str) and (v.strip() in ("*", "latest") or v.strip().startswith(("http://", "git+http://")))
                ]
                if unpinned:
                    issues.append((
                        f"Unpinned Wildcard or Insecure HTTP Dependency in {fname} ({', '.join(unpinned[:3])})",
                        "Medium", 6.5, "CWE-1104",
                        "Production bog'liqliklarda `*`/`latest`/`http://` o'rniga aniq versiya va lockfile (`package-lock.json`) ishlating.",
                    ))

    if fname in ("requirements.txt", "pip.conf", ".npmrc", "pyproject.toml"):
        clean_lines = [ln.split("#", 1)[0].strip() for ln in txt.splitlines() if ln.split("#", 1)[0].strip()]
        joined = "\n".join(clean_lines)
        if "--extra-index-url" in joined or re.search(r"(?i)(?:registry|index-url|extra-index-url)\s*[=:]?\s*http://", joined) or "--trusted-host" in joined:
            issues.append((
                f"Dependency Confusion / Unencrypted Package Index Configuration ({fname})",
                "High", 8.2, "CWE-427",
                "`--extra-index-url` va `http://` reestr o'rniga yagona HTTPS ichki proxy (`--index-url https://...`) va namespace scoping qo'llang.",
            ))

    return issues


def build_purl(eco: str, pkg: str, ver: str) -> str:
    """Builds standardized Package URL (purl)."""
    eco_map = {
        "npm": "npm", "PyPI": "pypi", "Packagist": "composer",
        "Go": "golang", "Maven": "maven", "RubyGems": "gem",
        "crates.io": "cargo", "NuGet": "nuget", "Pub": "pub", "Hex": "hex",
    }
    p_type = eco_map.get(eco, eco.lower())
    clean_p = pkg.strip()
    if p_type == "maven" and ":" in clean_p:
        clean_p = clean_p.replace(":", "/", 1)
    elif p_type == "npm" and clean_p.startswith("@"):
        clean_p = "%40" + clean_p[1:]
    return f"pkg:{p_type}/{clean_p}@{ver}"


def _parse_extra_lockfiles(fname: str, content: str, _add: Any) -> None:
    if fname == "package-lock.json":
        obj = json.loads(content)
        for p_key, meta in (obj.get("packages") or {}).items():
            if p_key and isinstance(meta, dict):
                mv = _CLEAN_VER_RE.search(str(meta.get("version") or ""))
                if mv:
                    _add("npm", str(p_key).rsplit("node_modules/", 1)[-1], mv.group(1))
        for pkg_nm, meta in (obj.get("dependencies") or {}).items():
            if isinstance(meta, dict):
                mv = _CLEAN_VER_RE.search(str(meta.get("version") or ""))
                if mv:
                    _add("npm", str(pkg_nm), mv.group(1))
    elif fname == "yarn.lock":
        for m in re.finditer(r'(?m)^"?(@?[a-zA-Z0-9._\-/]+)@[^":\n]+"?:\s*\n\s+version[:\s]+"?(\d+\.\d+\.\d+)"?', content):
            _add("npm", m.group(1), m.group(2))
    elif fname == "pnpm-lock.yaml":
        for m in re.finditer(r"(?m)^\s*['\"]?/?(@?[a-zA-Z0-9._\-/]+)@(\d+\.\d+\.\d+)['\"(]?\s*:", content):
            _add("npm", m.group(1), m.group(2))
    elif fname == "composer.lock":
        obj = json.loads(content)
        for item in (obj.get("packages") or []):
            if isinstance(item, dict) and item.get("name"):
                mv = _CLEAN_VER_RE.search(str(item.get("version") or ""))
                if mv:
                    _add("Packagist", str(item["name"]), mv.group(1))
    elif fname == "pipfile.lock":
        obj = json.loads(content)
        for sec_k in ("default", "develop"):
            for pkg_nm, meta in (obj.get(sec_k) or {}).items():
                if isinstance(meta, dict):
                    mv = _CLEAN_VER_RE.search(str(meta.get("version") or ""))
                    if mv:
                        _add("PyPI", str(pkg_nm).lower(), mv.group(1))
    elif fname in ("poetry.lock", "cargo.lock"):
        eco = "PyPI" if fname == "poetry.lock" else "crates.io"
        for blk in content.split("[[package]]")[1:]:
            mn = re.search(r'(?m)^name\s*=\s*"([^"]+)"', blk)
            mv = re.search(r'(?m)^version\s*=\s*"(\d+\.\d+(?:\.\d+)?)"', blk)
            if mn and mv:
                _add(eco, mn.group(1).lower() if eco == "PyPI" else mn.group(1), mv.group(1))
    elif fname == "gemfile.lock":
        for m in re.finditer(r"(?m)^\s{4}([a-zA-Z0-9_\-]+)\s+\((\d+\.\d+(?:\.\d+)?)\)\s*$", content):
            _add("RubyGems", m.group(1), m.group(2))
    elif fname == "pom.xml":
        for dep_blk in re.findall(r"<dependency>(.*?)</dependency>", content, re.S | re.I):
            mg = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", dep_blk, re.I)
            ma = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", dep_blk, re.I)
            mv = re.search(r"<version>\s*(\d+\.\d+(?:\.\d+)?)\s*</version>", dep_blk, re.I)
            if mg and ma and mv:
                _add("Maven", f"{mg.group(1)}:{ma.group(1)}", mv.group(1))
    elif fname in ("build.gradle", "build.gradle.kts"):
        for m in re.finditer(r"""(?:implementation|api|compileOnly|runtimeOnly)\s*\(?\s*['"]([a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-]+):(\d+\.\d+(?:\.\d+)?)['"]""", content):
            _add("Maven", m.group(1), m.group(2))
    elif fname.endswith(".csproj"):
        for m in re.finditer(r"""<PackageReference\s+[^>]*Include=["']([^"']+)["'][^>]*Version=["'](\d+\.\d+(?:\.\d+)?)["']""", content, re.I):
            _add("NuGet", m.group(1), m.group(2))
    elif fname == "packages.lock.json":
        obj = json.loads(content)
        for _fw, pkgs in (obj.get("dependencies") or {}).items():
            if isinstance(pkgs, dict):
                for p_nm, meta in pkgs.items():
                    mv = _CLEAN_VER_RE.search(str((meta or {}).get("resolved") or "")) if isinstance(meta, dict) else None
                    if mv:
                        _add("NuGet", str(p_nm), mv.group(1))
    elif fname == "pubspec.lock":
        for m in re.finditer(r'(?ms)^\s{2}([a-zA-Z0-9_]+):\s*\n(?:.*?\n)*?\s{4}version:\s*"(\d+\.\d+(?:\.\d+)?)"', content):
            _add("Pub", m.group(1), m.group(2))
    elif fname == "mix.lock":
        for m in re.finditer(r'"([a-zA-Z0-9_]+)"\s*:\s*\{:hex,\s*:[a-zA-Z0-9_]+,\s*"(\d+\.\d+(?:\.\d+)?)"', content):
            _add("Hex", m.group(1), m.group(2))


def parse_manifest_dependencies(filename: str, content: str) -> list[tuple[str, str, str]]:
    """Extracts `(ecosystem, package_name, clean_version)` tuples from 14 manifest & lockfile formats."""
    fname = filename.lower().split("/")[-1]
    deps: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(eco: str, pkg: str, ver: str) -> None:
        pk = pkg.strip()
        pk_k = pk.lower() if eco in ("PyPI", "npm", "RubyGems", "crates.io", "NuGet", "Pub", "Hex") else pk
        if pk and ver and (eco, pk_k) not in seen:
            seen.add((eco, pk_k))
            deps.append((eco, pk, ver))

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
                    if mv:
                        _add(eco, str(pkg), mv.group(1))
    elif fname in ("requirements.txt", "pyproject.toml"):
        for ln in content.splitlines():
            s = ln.split("#", 1)[0].strip().strip('"\',')
            m = re.match(r"^([a-zA-Z0-9._\-]+)\s*(?:==|~=)\s*(\d+\.\d+(?:\.\d+)?)", s)
            if m:
                _add("PyPI", m.group(1).lower(), m.group(2))
    elif fname == "go.mod":
        for m in re.finditer(r"^\s*([a-zA-Z0-9./_\-]+\.[a-zA-Z0-9./_\-]+)\s+v(\d+\.\d+\.\d+)", content, re.M):
            _add("Go", m.group(1), m.group(2))
    else:
        try:
            _parse_extra_lockfiles(fname, content, _add)
        except Exception:
            pass
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
    use_intel_db: bool = True,
) -> list[dict[str, Any]]:
    if not deps:
        return []
    hits_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for eco, pkg, ver in deps:
        for rl in OFFLINE_SCA_RULES:
            if rl["eco"] == eco and rl["pkg"] == pkg.lower() and version_in_range(ver, rl["min"], rl["max"]):
                cur = hits_map.get((eco, pkg, ver))
                if cur:
                    if rl["cve"] not in cur["cves"]:
                        cur["cves"].append(rl["cve"])
                    if float(rl["cvss"]) > cur["cvss"]:
                        cur["cvss"] = float(rl["cvss"])
                        cur["sev"] = rl["sev"]
                else:
                    hits_map[(eco, pkg, ver)] = {
                        "eco": eco, "pkg": pkg, "ver": ver, "cves": [rl["cve"]],
                        "sev": rl["sev"], "cvss": float(rl["cvss"]),
                    }

    if use_intel_db:
        db_hits = query_offline_sca_advisories(deps)
        for key_t, db_item in db_hits.items():
            cur = hits_map.get(key_t)
            if cur:
                for cid in db_item["cves"]:
                    if cid not in cur["cves"] and len(cur["cves"]) < 6:
                        cur["cves"].append(cid)
                if float(db_item["cvss"]) > cur["cvss"]:
                    cur["cvss"] = float(db_item["cvss"])
                    cur["sev"] = db_item["sev"]
                if db_item.get("kev"):
                    cur["kev"] = True
            else:
                hits_map[key_t] = dict(db_item)

    if allow_online_osv:
        cache = _load_osv_cache()
        uncached = [(e, p, v) for e, p, v in deps[:60] if (e, p, v) not in hits_map and f"{e}:{p}:{v}" not in cache]
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
    for item in hits_map.values():
        item["kev"] = bool(item.get("kev")) or any(
            str(c).upper() in CISA_KEV_CVES or bool((fast_rust_lookup_cve(str(c).upper()) or {}).get("is_kev"))
            for c in item.get("cves", [])
        )
    return list(hits_map.values())


def run_sca_dependency_audit(
    db: Any,
    project_id: int,
    code_paths: list[str],
    log_fn: Any,
    allow_online_osv: bool = True,
) -> int:
    manifest_names = SUPPORTED_MANIFEST_NAMES
    skip_parts = ("node_modules", ".git", "__pycache__", "/tests/", "/test/", ".venv", "venv")
    total_written = 0

    for cp in code_paths:
        if not cp:
            continue
        root = Path(cp)
        if not root.is_dir() or root.is_symlink():
            continue
        for mf in walk_safe_repo_files(root, max_files=400, max_bytes=1048576):
            fn_low = mf.name.lower()
            if fn_low not in manifest_names and not fn_low.endswith(".csproj"):
                continue
            try:
                raw_txt = mf.read_text(encoding="utf-8", errors="ignore")[:300000]
            except Exception:
                continue
            for sc_title, sc_sev, sc_cvss, sc_cwe, sc_rem in audit_supply_chain_manifest_risks(mf.name, raw_txt):
                db.upsert_finding(
                    project_id,
                    "SPECTRE-SCA",
                    sc_title,
                    "Software Supply-Chain Security",
                    sc_sev,
                    sc_cvss,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    sc_cwe,
                    "A08:2021 - Software and Data Integrity Failures",
                    str(mf),
                    f"Manifest: {mf.name} | Supply-chain posture rule matched",
                    f"`{mf.name}` paket manifestida ta'minot zanjiri (Supply-Chain) xavfsizligi kamchiligi aniqlandi.",
                    sc_rem,
                    confidence=QoD.HEADER_CONFIG,
                )
                total_written += 1
            deps = parse_manifest_dependencies(mf.name, raw_txt)
            vuln_deps = match_dependencies_advisories(deps, allow_online_osv=allow_online_osv)
            if not vuln_deps:
                continue
            top_cvss = max(x["cvss"] for x in vuln_deps)
            top_sev = "Critical" if top_cvss >= 9.0 else ("High" if top_cvss >= 7.0 else "Medium")
            ev_items = [
                f"{build_purl(x['eco'], x['pkg'], x['ver'])} ({', '.join(x['cves'][:2])})"
                for x in vuln_deps[:8]
            ]
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


_JS_BANNER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jquery", re.compile(r"(?i)jquery\s+v?([123]\.\d+\.\d+)")),
    ("bootstrap", re.compile(r"(?i)bootstrap\s+v?([234]\.\d+\.\d+)")),
    ("lodash", re.compile(r"(?i)lodash(?:\.js)?\s+v?(4\.\d+\.\d+)")),
    ("underscore", re.compile(r"(?i)underscore(?:\.js)?\s+v?(1\.\d+\.\d+)")),
    ("handlebars", re.compile(r"(?i)handlebars(?:\.js)?\s+v?([1-4]\.\d+\.\d+)")),
    ("dompurify", re.compile(r"(?i)dompurify\s+v?([12]\.\d+\.\d+)")),
    ("moment", re.compile(r"(?i)moment(?:\.js)?\s+v?(2\.\d+\.\d+)")),
    ("angular", re.compile(r"(?i)angularjs\s+v?(1\.\d+\.\d+)")),
    ("axios", re.compile(r"(?i)axios\s+v?(0\.\d+\.\d+|1\.[0-5]\.\d+)")),
)


def extract_js_bundle_libraries(js_text: str) -> list[tuple[str, str, str]]:
    head = (js_text or "")[:16384]
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pkg, rx in _JS_BANNER_PATTERNS:
        m = rx.search(head)
        if m:
            ver = m.group(1)
            if (pkg, ver) not in seen:
                seen.add((pkg, ver))
                found.append(("npm", pkg, ver))
    return found


def run_web_and_js_sca_audit(
    db: Any,
    http_engine: Any,
    project_id: int,
    endpoints: list[dict[str, Any]],
    log_fn: Any,
    allow_online_osv: bool = True,
) -> int:
    written = 0
    js_cache = get_project_js_cache_dir(project_id)
    js_deps: list[tuple[str, str, str]] = []
    if js_cache.is_dir() and not js_cache.is_symlink():
        js_files = sorted(list(js_cache.glob("*.js")) + list(js_cache.glob("*.cache")))
        for jf in js_files[:35]:
            if jf.is_symlink():
                continue
            try:
                js_deps.extend(extract_js_bundle_libraries(jf.read_text(encoding="utf-8", errors="ignore")[:16384]))
            except Exception:
                pass
    dedup_js_deps = list(dict.fromkeys(js_deps))
    if dedup_js_deps:
        js_vulns = match_dependencies_advisories(dedup_js_deps, allow_online_osv=allow_online_osv)
        if js_vulns:
            top_c = max(x["cvss"] for x in js_vulns)
            top_s = "Critical" if top_c >= 9.0 else ("High" if top_c >= 7.0 else "Medium")
            ev_s = " | ".join(
                f"{build_purl(x['eco'], x['pkg'], x['ver'])} ({', '.join(x['cves'][:2])})"
                for x in js_vulns[:8]
            )
            db.upsert_finding(
                project_id,
                "Agent-2 (JS-SCA)",
                f"Outdated Client-Side JavaScript Libraries ({len(js_vulns)} libraries)",
                "Software Composition Analysis (SCA)",
                top_s,
                top_c,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "CWE-1395",
                "A06:2021 - Vulnerable and Outdated Components",
                f"Project #{project_id} JS Bundles",
                f"Detected Vulnerable JS Libraries: {ev_s}",
                "Veb-sahifada yuklangan mijoz JavaScript kutubxonalarida ma'lum CVE zaifliklariga ega eski versiyalar ishlatilgan.",
                "Frontend kutubxonalarni zamonaviy xavfsiz relizlariga yangilang.",
                confidence=QoD.HEADER_CONFIG,
            )
            written += 1

    manifest_eps = [
        str(e.get("url") or "") for e in (endpoints or [])
        if str(e.get("url") or "").lower().endswith(
            ("/package.json", "/package-lock.json", "/composer.json", "/composer.lock")
        )
    ][:6]
    for mu in manifest_eps:
        if http_engine.is_host_dead(mu):
            continue
        try:
            rm = http_engine.request("GET", mu, timeout=(2.2, 3.0), allow_redirects=False, max_bytes=131072)
            if rm.status_code == 200 and rm.text.lstrip().startswith("{"):
                mname = mu.rsplit("/", 1)[-1]
                m_deps = parse_manifest_dependencies(mname, rm.text)
                m_vulns = match_dependencies_advisories(m_deps, allow_online_osv=allow_online_osv)
                if m_vulns:
                    tc = max(x["cvss"] for x in m_vulns)
                    ts = "Critical" if tc >= 9.0 else ("High" if tc >= 7.0 else "Medium")
                    ev_m = " | ".join(f"{x['pkg']}@{x['ver']} ({', '.join(x['cves'][:2])})" for x in m_vulns[:8])
                    db.upsert_finding(
                        project_id, "Agent-2 (Web-SCA)",
                        f"Vulnerable Dependencies in Exposed {mname} ({len(m_vulns)} packages)",
                        "Software Composition Analysis (SCA)", ts, tc,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "CWE-1395",
                        "A06:2021 - Vulnerable and Outdated Components", mu,
                        f"Exposed Manifest: {mu} | Vulnerable Packages: {ev_m}",
                        "Ochiq veb-manifest faylidan eskirgan va zaif paket versiyalari aniqlandi.",
                        "Manifest fayliga tashqi HTTP kirishni yoping va zaif kutubxonalarni yangilang.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    written += 1
        except Exception:
            pass
    return written


