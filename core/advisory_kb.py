"""SPECTRE — Rust-Accelerated Semantic Version, CPE 2.3 & Distro LSC Engine."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any
from core.native_bridge import (
    fast_compare_distro_versions,
    fast_rust_consolidate_cpe,
    fast_rust_lookup_cve,
)

_SEMVER_RE = re.compile(
    r"(?i)^(?:\d+:)?v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:p(\d+)|([a-z]{1,3})(?![a-z0-9]))?(?:[-~](rc|alpha|beta|pre|dev)(\d*))?"
)
_NOISE_BRACKETS_RE = re.compile(r"(?i)\[(?:http-title|ssl-cert|http-robots\.txt|http-favicon):[^\]]*\]")
_RAW_CAT = json.loads((Path(__file__).resolve().parent.parent / "config" / "advisory_catalog.json").read_text(encoding="utf-8"))
_PRODUCT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple((str(p), re.compile(str(pat))) for p, pat in _RAW_CAT["product_patterns"])
_CPE_VENDOR_PRODUCT: dict[str, tuple[str, str]] = {str(k): (str(v[0]), str(v[1])) for k, v in _RAW_CAT["cpe_vendor_product"].items()}
CURATED_CVE_ADVISORIES: tuple[dict[str, Any], ...] = tuple(_RAW_CAT["curated_cve_advisories"])
DISTRO_LSC_ADVISORY_TABLE: tuple[dict[str, Any], ...] = tuple(_RAW_CAT["distro_lsc_advisory_table"])

def build_cpe23(product: str, version: str) -> str:
    """Formats a canonical NIST CPE 2.3 string (`cpe:2.3:a:vendor:product:version:...`)."""
    vendor, p_slug = _CPE_VENDOR_PRODUCT.get(product, (product, product))
    clean_v = re.sub(r"[^a-zA-Z0-9._\-]", "", version or "*") or "*"
    return f"cpe:2.3:a:{vendor}:{p_slug}:{clean_v}:*:*:*:*:*:*:*"

_DISTRO_MARKER_RE = re.compile(
    r"(?i)(?:ubuntu|debian|\+deb\d+|\bdeb\d+|\.el[789]\b|\.el[789]_|\bcentos\b|\bfedora\b|\bredhat\b|\bred\s+hat\b|\brocky\b|\balmalinux\b|\bsuse\b|\bopensuse\b|\bamzn\d*|\.amzn\d*)"
)
_UBUNTU_2404_SSH_RE = re.compile(r"(?i)9\.6p1\s+ubuntu-\d+ubuntu13\.(\d+)")
_UBUNTU_2204_SSH_RE = re.compile(r"(?i)8\.9p1\s+ubuntu-\d+ubuntu0\.(\d+)")
_DEBIAN_12_SSH_RE = re.compile(r"(?i)9\.2p1[^\n]*deb12u(\d+)")


def is_openssh_cve_2024_6387_backported(raw_text: str) -> bool:
    """Checks exact Canonical Ubuntu / Debian security revision numbers for CVE-2024-6387."""
    m24 = _UBUNTU_2404_SSH_RE.search(raw_text)
    if m24 and int(m24.group(1)) >= 3:
        return True
    m22 = _UBUNTU_2204_SSH_RE.search(raw_text)
    if m22 and int(m22.group(1)) >= 10:
        return True
    md12 = _DEBIAN_12_SSH_RE.search(raw_text)
    if md12 and int(md12.group(1)) >= 3:
        return True
    return False


def parse_semver(version_str: str) -> tuple[int, int, int, int, int] | None:
    """Converts version strings (`2.4.49`, `8.9p1`, `1.0.2za`, `2.4.50-rc1`) into a 5-int tuple."""
    s = (version_str or "").strip()
    m = _SEMVER_RE.match(s)
    if not m:
        return None
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    if m.group(4):
        sub = int(m.group(4))
    elif m.group(5):
        sub = 0
        for ch in m.group(5).lower():
            sub = sub * 26 + (ord(ch) - ord("a") + 1)
    else:
        sub = 0
    if m.group(6):
        tag_l = m.group(6).lower()
        tag_base = {"dev": -400, "alpha": -300, "beta": -200, "pre": -150, "rc": -100}.get(tag_l, -100)
        tag_num = int(m.group(7)) if m.group(7) else 0
        pre = tag_base + min(tag_num, 89)
    else:
        pre = 0
    return (major, minor, patch, sub, pre)


def version_in_range(ver_str: str, min_inclusive: str, max_exclusive: str) -> bool:
    """Returns True if `min_inclusive <= ver_str < max_exclusive`."""
    cur_t = parse_semver(ver_str)
    min_t = parse_semver(min_inclusive)
    max_t = parse_semver(max_exclusive)
    if cur_t is None or min_t is None or max_t is None:
        return False
    return min_t <= cur_t < max_t


def sanitize_banner_text(raw_text: str) -> str:
    """Strips untrusted HTML `<title>` and SSL CN NSE bracket blocks so page titles never trigger CVEs."""
    if not raw_text:
        return ""
    return _NOISE_BRACKETS_RE.sub(" ", raw_text).strip()


def _extract_with_local_context(raw_text: str) -> list[tuple[str, str, str]]:
    """Extracts `(product, version, local_context_window)` isolated per header/banner segment."""
    text = sanitize_banner_text(raw_text)
    if not text:
        return []
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for seg in re.split(r"[\r\n|;]+", text):
        seg_s = seg.strip()
        if not seg_s:
            continue
        has_mariadb = "mariadb" in seg_s.lower()
        for prod, pat in _PRODUCT_PATTERNS:
            if prod == "mysql" and has_mariadb:
                continue
            for m in pat.finditer(seg_s):
                raw_v = m.group(1)
                ver = raw_v.split(":", 1)[1] if ":" in raw_v and raw_v.split(":", 1)[0].isdigit() else raw_v
                pair = (prod, ver)
                if pair not in seen:
                    seen.add(pair)
                    win = seg_s[max(0, m.start() - 24) : min(len(seg_s), m.end() + 56)]
                    found.append((prod, ver, win))
    return found


def extract_product_versions(raw_text: str) -> list[tuple[str, str]]:
    """Extracts `(product, version)` pairs from HTTP headers, tech stacks, or port banners."""
    return [(p, v) for p, v, _ in _extract_with_local_context(raw_text)]


def extract_cpe_inventory(raw_text: str) -> list[str]:
    """Returns canonical NIST CPE 2.3 identifiers for all versioned products in `raw_text`."""
    cpes = [build_cpe23(p, v) for p, v, _ in _extract_with_local_context(raw_text)]
    for rs_item in fast_rust_consolidate_cpe(sanitize_banner_text(raw_text)):
        cpe_s = str(rs_item.get("cpe23") or "")
        if cpe_s:
            cpes.append(cpe_s)
    return list(dict.fromkeys(cpes))


def match_version_advisories(raw_text: str) -> list[dict[str, Any]]:
    """
    Matches `(product, version)` pairs extracted from `raw_text` against `CURATED_CVE_ADVISORIES`.
    Evaluates OS distro backport markers strictly within each product's local segment/window
    (eliminating cross-header bleed) and attaches canonical NIST `cpe23` identifiers.
    """
    extracted = _extract_with_local_context(raw_text)
    if not extracted:
        return []

    by_product: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
    for prod, ver, local_win in extracted:
        ssh_bp = is_openssh_cve_2024_6387_backported(local_win)
        for adv in CURATED_CVE_ADVISORIES:
            if adv["product"] != prod:
                continue
            if prod == "openssh" and adv["cve"] == "CVE-2024-6387" and ssh_bp:
                continue
            if version_in_range(ver, adv["min"], adv["max"]):
                by_product.setdefault(prod, []).append((ver, local_win, adv))

    matches: list[dict[str, Any]] = []
    for prod, ver_adv_list in by_product.items():
        best_ver, best_win, best_adv = max(ver_adv_list, key=lambda x: float(x[2]["cvss"]))
        best = dict(best_adv)
        all_cves = list(dict.fromkeys(a["cve"] for v, _, a in ver_adv_list if v == best_ver))
        best["cve"] = ", ".join(all_cves)
        best["detected_version"] = best_ver
        best["cpe23"] = build_cpe23(prod, best_ver)
        for cid in all_cves:
            rs_meta = fast_rust_lookup_cve(cid)
            if rs_meta and rs_meta.get("is_kev"):
                best["is_kev"] = True
                break

        local_distro = bool(_DISTRO_MARKER_RE.search(best_win))
        ssh_bp_best = is_openssh_cve_2024_6387_backported(best_win)
        exact_unpatched_ssh = bool(
            prod == "openssh"
            and not ssh_bp_best
            and (_UBUNTU_2404_SSH_RE.search(best_win) or _UBUNTU_2204_SSH_RE.search(best_win) or _DEBIAN_12_SSH_RE.search(best_win))
        )
        is_pure_eol = all(c.startswith("EOL-") for c in all_cves)
        best["distro_backport_likely"] = bool(
            local_distro
            and not is_pure_eol
            and not exact_unpatched_ssh
            and prod in (
                "apache", "nginx", "openssh", "php", "openssl", "postfix", "exim",
                "postgresql", "mariadb", "mysql", "redis", "memcached", "proftpd", "vsftpd", "dovecot",
            )
            and "2.4.49" not in best_ver
            and "2.4.50" not in best_ver
            and "2.3.4" not in best_ver
        )
        matches.append(best)
    return matches


def _char_order_deb(ch: str | None) -> int:
    if ch == "~":
        return -2
    if ch is None:
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _cmp_deb_rpm_part(part_a: str, part_b: str) -> int:
    """Compares upstream or revision strings using Debian Policy 5.6.12 / RPM lexical+numeric rules."""
    i, j = 0, 0
    la, lb = len(part_a), len(part_b)
    while i < la or j < lb:
        while (i < la and not part_a[i].isdigit()) or (j < lb and not part_b[j].isdigit()):
            ca = part_a[i] if (i < la and not part_a[i].isdigit()) else None
            cb = part_b[j] if (j < lb and not part_b[j].isdigit()) else None
            oa, ob = _char_order_deb(ca), _char_order_deb(cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if ca is not None:
                i += 1
            if cb is not None:
                j += 1
        sa = i
        while i < la and part_a[i].isdigit():
            i += 1
        sb = j
        while j < lb and part_b[j].isdigit():
            j += 1
        va = int(part_a[sa:i]) if sa < i else 0
        vb = int(part_b[sb:j]) if sb < j else 0
        if va != vb:
            return -1 if va < vb else 1
    return 0


def parse_distro_version(ver_str: str) -> tuple[int, str, str]:
    """Splits `[epoch:]upstream_version[-distro_revision]` into `(epoch, upstream, revision)`."""
    s = (ver_str or "").strip()
    epoch = 0
    if ":" in s:
        ep_part, rest = s.split(":", 1)
        if ep_part.isdigit():
            epoch = int(ep_part)
            s = rest
    if "-" in s:
        upstream, revision = s.rsplit("-", 1)
    else:
        upstream, revision = s, ""
    return epoch, upstream, revision


def compare_distro_versions(v1: str, v2: str) -> int:
    """Returns `-1` if `v1 < v2`, `0` if `v1 == v2`, and `1` if `v1 > v2` (Rust FFI accelerated)."""
    rs_cmp = fast_compare_distro_versions(v1, v2)
    if rs_cmp is not None:
        return rs_cmp
    ep1, up1, rev1 = parse_distro_version(v1)
    ep2, up2, rev2 = parse_distro_version(v2)
    if ep1 != ep2:
        return -1 if ep1 < ep2 else 1
    c_up = _cmp_deb_rpm_part(up1, up2)
    if c_up != 0:
        return c_up
    return _cmp_deb_rpm_part(rev1, rev2)


def detect_distro_family(os_release_text: str) -> str:
    raw = os_release_text or ""
    kv: dict[str, str] = {}
    for ln in raw.splitlines():
        s = ln.strip()
        if "=" in s and not s.startswith("#"):
            k, v = s.split("=", 1)
            kv[k.strip().upper()] = v.strip().strip('"').strip("'").lower()
    if "ID" in kv:
        os_id = kv.get("ID", "")
        ver_id = kv.get("VERSION_ID", "") or kv.get("PRETTY_NAME", "")
        codename = kv.get("VERSION_CODENAME", "")
        if os_id == "ubuntu":
            if "24.04" in ver_id or codename == "noble":
                return "ubuntu:24.04"
            if "22.04" in ver_id or codename == "jammy":
                return "ubuntu:22.04"
            if "20.04" in ver_id or codename == "focal":
                return "ubuntu:20.04"
            return ""
        if os_id == "debian":
            if ver_id == "13" or ver_id.startswith("13.") or " 13" in ver_id or codename == "trixie":
                return "debian:13"
            if ver_id == "12" or ver_id.startswith("12.") or " 12" in ver_id or codename == "bookworm":
                return "debian:12"
            if ver_id == "11" or ver_id.startswith("11.") or " 11" in ver_id or codename == "bullseye":
                return "debian:11"
            return ""
        if os_id in ("rhel", "rocky", "almalinux", "centos"):
            if ver_id == "9" or ver_id.startswith("9.") or re.search(r"\b9(?:\.\d+|\b)", ver_id):
                return "rhel:9"
            if ver_id == "8" or ver_id.startswith("8.") or re.search(r"\b8(?:\.\d+|\b)", ver_id):
                return "rhel:8"
            return ""
        if os_id == "alpine":
            m_alp = re.match(r"^(\d+\.\d+)", ver_id)
            if m_alp:
                return f"alpine:v{m_alp.group(1)}"
            return ""
        return ""
    low = raw.lower()
    if "ubuntu" in low:
        if re.search(r"(?:\b24\.04\b|~24\.04|\bnoble\b)", low):
            return "ubuntu:24.04"
        if re.search(r"(?:\b22\.04\b|~22\.04|\bjammy\b)", low):
            return "ubuntu:22.04"
        return ""
    if ("debian" in low or "deb12" in low or "bookworm" in low) and re.search(
        r"(?:\bdebian\s+gnu/linux\s+12\b|\bbookworm\b|deb12(?:u\d+|\b))", low
    ):
        return "debian:12"
    if re.search(
        r"\b(?:red\s+hat(?:\s+enterprise\s+linux)?|rhel|rocky(?:\s+linux)?|alma(?:\s*linux)?|centos(?:\s+stream)?)\s+9(?:\.\d+|\b)",
        low,
    ) or re.search(r"(?:\bel9(?:_\d+|\b)|\.el9)", low):
        return "rhel:9"
    return ""


def evaluate_distro_lsc_inventory(
    os_release_text: str,
    pkg_inventory_text: str,
    include_intel_db: bool = False,
) -> tuple[list[dict[str, Any]], set[str]]:
    """
    Table-driven + `spectre_intel.db` Distro Local Security Check (LSC) evaluator.
    Compares installed `dpkg`/`rpm`/`apk` package revisions against distro security advisories.
    """
    distro_id = detect_distro_family(os_release_text)
    if not distro_id:
        return [], set()

    pkgs: dict[str, str] = {}
    for raw_ln in (pkg_inventory_text or "").splitlines():
        parts = raw_ln.strip().split()
        if len(parts) >= 2:
            p_name = parts[0].split(":", 1)[0].strip().lower()
            pkgs[p_name] = parts[1].strip()

    findings: list[dict[str, Any]] = []
    covered_products: set[str] = set()
    flagged_pkgs: set[str] = set()
    for row in DISTRO_LSC_ADVISORY_TABLE:
        if row["distro"] != distro_id:
            continue
        inst_ver = pkgs.get(row["pkg"])
        if not inst_ver:
            continue
        covered_products.add(str(row["product"]))
        if compare_distro_versions(inst_ver, str(row["fixed"])) < 0:
            item = dict(row)
            item["installed_version"] = inst_ver
            item["owasp"] = "A06:2021 - Vulnerable and Outdated Components"
            item["cpe23"] = build_cpe23(str(row["product"]), parse_distro_version(inst_ver)[1])
            findings.append(item)
            flagged_pkgs.add(str(row["pkg"]))

    if include_intel_db and pkgs:
        from core.threat_intel_pack import query_offline_distro_advisories
        rem_pkgs = {k: v for k, v in pkgs.items() if k not in flagged_pkgs}
        if rem_pkgs:
            for db_hit in query_offline_distro_advisories(distro_id, rem_pkgs):
                covered_products.add(str(db_hit["product"]))
                findings.append(db_hit)

    return findings, covered_products


def evaluate_distro_package_advisory(
    os_release_text: str,
    pkg_inventory_text: str,
    include_intel_db: bool = False,
) -> list[dict[str, Any]]:
    """Convenience wrapper returning confirmed distro LSC advisories."""
    hits, _ = evaluate_distro_lsc_inventory(os_release_text, pkg_inventory_text, include_intel_db=include_intel_db)
    return hits
