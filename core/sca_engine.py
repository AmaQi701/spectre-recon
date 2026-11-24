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
    {"eco": "npm", "pkg": "jquery", "min": "1.0.0", "max": "3.5.0", "cve": "CVE-2020-11022", "sev": "Medium", "cvss": 6.1},
    {"eco": "npm", "pkg": "bootstrap", "min": "2.0.0", "max": "4.3.1", "cve": "CVE-2019-8331", "sev": "Medium", "cvss": 6.1},
    {"eco": "npm", "pkg": "underscore", "min": "1.3.0", "max": "1.13.6", "cve": "CVE-2021-23358", "sev": "High", "cvss": 7.2},
    {"eco": "npm", "pkg": "handlebars", "min": "1.0.0", "max": "4.7.7", "cve": "CVE-2021-23369", "sev": "Critical", "cvss": 9.8},
    {"eco": "npm", "pkg": "dompurify", "min": "0.5.0", "max": "2.4.2", "cve": "CVE-2023-47122", "sev": "Medium", "cvss": 6.1},
    {"eco": "npm", "pkg": "moment", "min": "2.0.0", "max": "2.29.4", "cve": "CVE-2022-31129", "sev": "High", "cvss": 7.5},
    {"eco": "npm", "pkg": "angular", "min": "1.0.0", "max": "1.8.0", "cve": "CVE-2022-25869", "sev": "Medium", "cvss": 6.1},
    {"eco": "npm", "pkg": "minimist", "min": "0.0.1", "max": "1.2.6", "cve": "CVE-2021-44906", "sev": "Critical", "cvss": 9.8},
    {"eco": "npm", "pkg": "semver", "min": "6.0.0", "max": "7.5.2", "cve": "CVE-2022-25883", "sev": "High", "cvss": 7.5},
    {"eco": "npm", "pkg": "ws", "min": "7.0.0", "max": "8.17.1", "cve": "CVE-2024-37890", "sev": "High", "cvss": 7.5},
    {"eco": "npm", "pkg": "socket.io-parser", "min": "3.0.0", "max": "4.2.3", "cve": "CVE-2023-32695", "sev": "High", "cvss": 7.5},
    {"eco": "npm", "pkg": "xml2js", "min": "0.1.0", "max": "0.5.0", "cve": "CVE-2023-0842", "sev": "Medium", "cvss": 5.3},
    {"eco": "npm", "pkg": "tough-cookie", "min": "2.0.0", "max": "4.1.3", "cve": "CVE-2023-26136", "sev": "Medium", "cvss": 6.5},
    {"eco": "npm", "pkg": "postcss", "min": "7.0.0", "max": "8.4.31", "cve": "CVE-2023-44270", "sev": "Medium", "cvss": 5.3},
    {"eco": "npm", "pkg": "ejs", "min": "2.0.0", "max": "3.1.10", "cve": "CVE-2022-29078", "sev": "Critical", "cvss": 9.8},
    {"eco": "npm", "pkg": "serialize-javascript", "min": "1.0.0", "max": "3.1.0", "cve": "CVE-2020-7660", "sev": "High", "cvss": 8.1},
    {"eco": "npm", "pkg": "vm2", "min": "3.0.0", "max": "3.9.20", "cve": "CVE-2023-37466", "sev": "Critical", "cvss": 9.8},
    {"eco": "npm", "pkg": "next", "min": "13.4.0", "max": "14.1.1", "cve": "CVE-2024-34351", "sev": "High", "cvss": 7.5},
    {"eco": "PyPI", "pkg": "requests", "min": "2.3.0", "max": "2.31.0", "cve": "CVE-2023-32681", "sev": "Medium", "cvss": 6.1},
    {"eco": "PyPI", "pkg": "urllib3", "min": "1.20.0", "max": "2.0.7", "cve": "CVE-2023-45803", "sev": "Medium", "cvss": 4.2},
    {"eco": "PyPI", "pkg": "jinja2", "min": "2.0.0", "max": "3.1.3", "cve": "CVE-2024-22195", "sev": "Medium", "cvss": 6.1},
    {"eco": "PyPI", "pkg": "pyyaml", "min": "3.0.0", "max": "5.4.0", "cve": "CVE-2020-14343", "sev": "Critical", "cvss": 9.8},
    {"eco": "PyPI", "pkg": "cryptography", "min": "3.0.0", "max": "42.0.0", "cve": "CVE-2023-50782", "sev": "High", "cvss": 7.5},
    {"eco": "Packagist", "pkg": "guzzlehttp/guzzle", "min": "6.0.0", "max": "7.4.5", "cve": "CVE-2022-31090", "sev": "High", "cvss": 8.1},
    {"eco": "Packagist", "pkg": "firebase/php-jwt", "min": "1.0.0", "max": "6.0.0", "cve": "CVE-2021-46743", "sev": "High", "cvss": 8.1},
    {"eco": "Go", "pkg": "golang.org/x/net", "min": "0.1.0", "max": "0.23.0", "cve": "CVE-2023-45288", "sev": "High", "cvss": 7.5},
    {"eco": "Go", "pkg": "golang.org/x/crypto", "min": "0.1.0", "max": "0.17.0", "cve": "CVE-2023-48795", "sev": "Medium", "cvss": 5.9},
    {"eco": "Go", "pkg": "github.com/gin-gonic/gin", "min": "1.0.0", "max": "1.9.0", "cve": "CVE-2023-26125", "sev": "Medium", "cvss": 5.3},
    {"eco": "PyPI", "pkg": "django", "min": "3.2.0", "max": "4.2.11", "cve": "CVE-2024-27351", "sev": "High", "cvss": 7.5},
    {"eco": "PyPI", "pkg": "werkzeug", "min": "2.0.0", "max": "3.0.3", "cve": "CVE-2024-34069", "sev": "High", "cvss": 7.5},
    {"eco": "PyPI", "pkg": "pillow", "min": "8.0.0", "max": "10.2.0", "cve": "CVE-2023-50447", "sev": "High", "cvss": 8.1},
    {"eco": "PyPI", "pkg": "aiohttp", "min": "3.0.0", "max": "3.9.2", "cve": "CVE-2024-23334", "sev": "High", "cvss": 7.5},
    {"eco": "PyPI", "pkg": "tornado", "min": "5.0.0", "max": "6.3.3", "cve": "CVE-2023-28370", "sev": "Medium", "cvss": 5.3},
    {"eco": "PyPI", "pkg": "paramiko", "min": "2.0.0", "max": "3.4.0", "cve": "CVE-2023-48795", "sev": "Medium", "cvss": 5.9},
    {"eco": "PyPI", "pkg": "lxml", "min": "4.0.0", "max": "4.9.1", "cve": "CVE-2022-2309", "sev": "High", "cvss": 7.5},
    {"eco": "PyPI", "pkg": "gunicorn", "min": "19.0.0", "max": "22.0.0", "cve": "CVE-2024-1135", "sev": "High", "cvss": 7.5},
    {"eco": "Packagist", "pkg": "symfony/http-kernel", "min": "4.4.0", "max": "6.4.3", "cve": "CVE-2024-24598", "sev": "High", "cvss": 7.5},
    {"eco": "Packagist", "pkg": "laravel/framework", "min": "8.0.0", "max": "9.52.16", "cve": "CVE-2024-29291", "sev": "High", "cvss": 7.5},
    {"eco": "Packagist", "pkg": "monolog/monolog", "min": "1.0.0", "max": "2.8.0", "cve": "CVE-2022-41267", "sev": "High", "cvss": 7.5},
    {"eco": "Packagist", "pkg": "phpmailer/phpmailer", "min": "5.0.0", "max": "6.5.0", "cve": "CVE-2021-3603", "sev": "High", "cvss": 7.0},
    {"eco": "Maven", "pkg": "org.apache.logging.log4j:log4j-core", "min": "2.0.0", "max": "2.17.1", "cve": "CVE-2021-44228", "sev": "Critical", "cvss": 10.0},
    {"eco": "Maven", "pkg": "org.springframework:spring-beans", "min": "5.0.0", "max": "5.3.18", "cve": "CVE-2022-22965", "sev": "Critical", "cvss": 9.8},
    {"eco": "Maven", "pkg": "com.alibaba:fastjson", "min": "1.1.0", "max": "1.2.83", "cve": "CVE-2022-25845", "sev": "Critical", "cvss": 9.8},
    {"eco": "Maven", "pkg": "org.apache.commons:commons-text", "min": "1.5.0", "max": "1.10.0", "cve": "CVE-2022-42889", "sev": "Critical", "cvss": 9.8},
    {"eco": "Maven", "pkg": "com.fasterxml.jackson.core:jackson-databind", "min": "2.0.0", "max": "2.13.4", "cve": "CVE-2022-42003", "sev": "High", "cvss": 7.5},
    {"eco": "Maven", "pkg": "org.apache.shiro:shiro-core", "min": "1.0.0", "max": "1.6.0", "cve": "CVE-2020-1957", "sev": "Critical", "cvss": 9.8},
    {"eco": "Maven", "pkg": "org.yaml:snakeyaml", "min": "1.0.0", "max": "2.0.0", "cve": "CVE-2022-1471", "sev": "High", "cvss": 8.3},
    {"eco": "RubyGems", "pkg": "rails", "min": "6.0.0", "max": "7.0.4", "cve": "CVE-2023-22795", "sev": "High", "cvss": 7.5},
    {"eco": "RubyGems", "pkg": "nokogiri", "min": "1.8.0", "max": "1.13.9", "cve": "CVE-2022-29181", "sev": "High", "cvss": 7.5},
    {"eco": "RubyGems", "pkg": "rack", "min": "2.0.0", "max": "2.2.6", "cve": "CVE-2023-27530", "sev": "High", "cvss": 7.5},
    {"eco": "crates.io", "pkg": "hyper", "min": "0.12.0", "max": "0.14.25", "cve": "CVE-2023-26964", "sev": "High", "cvss": 7.5},
    {"eco": "crates.io", "pkg": "h2", "min": "0.1.0", "max": "0.3.26", "cve": "CVE-2024-32650", "sev": "High", "cvss": 7.5},
    {"eco": "NuGet", "pkg": "newtonsoft.json", "min": "1.0.0", "max": "13.0.1", "cve": "CVE-2024-21907", "sev": "High", "cvss": 7.5},
    {"eco": "NuGet", "pkg": "system.text.json", "min": "4.6.0", "max": "8.0.5", "cve": "CVE-2024-43485", "sev": "High", "cvss": 7.5},
    {"eco": "NuGet", "pkg": "bouncycastle.cryptography", "min": "1.0.0", "max": "2.3.1", "cve": "CVE-2024-29857", "sev": "High", "cvss": 7.5},
    {"eco": "NuGet", "pkg": "microsoft.data.sqlclient", "min": "1.0.0", "max": "5.1.4", "cve": "CVE-2024-0056", "sev": "High", "cvss": 8.7},
    {"eco": "NuGet", "pkg": "restsharp", "min": "100.0.0", "max": "112.0.0", "cve": "CVE-2024-45302", "sev": "Medium", "cvss": 5.3},
    {"eco": "Maven", "pkg": "io.netty:netty-codec-http2", "min": "4.1.0", "max": "4.1.100", "cve": "CVE-2023-44487", "sev": "High", "cvss": 7.5},
    {"eco": "Maven", "pkg": "org.springframework.security:spring-security-web", "min": "5.6.0", "max": "6.2.3", "cve": "CVE-2024-22257", "sev": "High", "cvss": 8.2},
    {"eco": "Maven", "pkg": "org.postgresql:postgresql", "min": "42.0.0", "max": "42.7.2", "cve": "CVE-2024-1597", "sev": "Critical", "cvss": 9.8},
    {"eco": "Maven", "pkg": "org.apache.tomcat.embed:tomcat-embed-core", "min": "9.0.0", "max": "10.1.19", "cve": "CVE-2024-24549", "sev": "High", "cvss": 7.5},
    {"eco": "Go", "pkg": "google.golang.org/grpc", "min": "1.20.0", "max": "1.58.3", "cve": "CVE-2023-44487", "sev": "High", "cvss": 7.5},
    {"eco": "Go", "pkg": "github.com/golang-jwt/jwt", "min": "3.0.0", "max": "3.2.2", "cve": "CVE-2020-26160", "sev": "High", "cvss": 7.5},
    {"eco": "npm", "pkg": "tar", "min": "4.0.0", "max": "6.2.1", "cve": "CVE-2024-28863", "sev": "Medium", "cvss": 6.5},
    {"eco": "PyPI", "pkg": "fastapi", "min": "0.60.0", "max": "0.109.1", "cve": "CVE-2024-24762", "sev": "High", "cvss": 7.5},
    {"eco": "crates.io", "pkg": "rustls", "min": "0.20.0", "max": "0.22.4", "cve": "CVE-2024-32650", "sev": "High", "cvss": 7.5},
)

_CLEAN_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


SUPPORTED_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock",
    "requirements.txt", "pipfile.lock", "poetry.lock", "pyproject.toml",
    "go.mod", "cargo.lock", "gemfile.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "packages.lock.json",
}


def build_purl(eco: str, pkg: str, ver: str) -> str:
    """Builds standardized Package URL (purl)."""
    eco_map = {
        "npm": "npm", "PyPI": "pypi", "Packagist": "composer",
        "Go": "golang", "Maven": "maven", "RubyGems": "gem",
        "crates.io": "cargo", "NuGet": "nuget",
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


def parse_manifest_dependencies(filename: str, content: str) -> list[tuple[str, str, str]]:
    """Extracts `(ecosystem, package_name, clean_version)` tuples from 14 manifest & lockfile formats."""
    fname = filename.lower().split("/")[-1]
    deps: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(eco: str, pkg: str, ver: str) -> None:
        pk = pkg.strip()
        pk_k = pk.lower() if eco in ("PyPI", "npm", "RubyGems", "crates.io", "NuGet") else pk
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
    manifest_names = SUPPORTED_MANIFEST_NAMES
    skip_parts = ("node_modules", ".git", "__pycache__", "/tests/", "/test/", ".venv", "venv")
    total_written = 0

    for cp in code_paths:
        if not cp:
            continue
        root = Path(cp)
        if not root.is_dir():
            continue
        for mf in sorted(root.rglob("*")):
            fn_low = mf.name.lower()
            if (fn_low not in manifest_names and not fn_low.endswith(".csproj")) or not mf.is_file():
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
    js_cache = Path(f"/tmp/spectre_js_cache_{project_id}")
    js_deps: list[tuple[str, str, str]] = []
    if js_cache.is_dir():
        for jf in sorted(js_cache.glob("*.js"))[:35]:
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


