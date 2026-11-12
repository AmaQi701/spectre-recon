"""
SPECTRE v14.0 — Semantic Version Parser & Curated Vendor CVE Advisory Catalog
=============================================================================
Matches observed service/server banners and technology versions against
official vendor security advisories using deterministic semantic version bounds.
Assigned Quality of Detection: `QoD.BANNER_CVE` (75%) to account for OS backports.
"""

from __future__ import annotations

import re
from typing import Any


_SEMVER_RE = re.compile(r"(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:p(\d+))?")

_PRODUCT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("apache", re.compile(r"(?i)\bapache(?:\s+httpd|\s+http\s+server)?[/\s]+(\d+\.\d+(?:\.\d+)?)")),
    ("nginx", re.compile(r"(?i)\bnginx[/\s]+(\d+\.\d+(?:\.\d+)?)")),
    ("openssh", re.compile(r"(?i)\bopenssh[_\s/]+(\d+\.\d+(?:\.\d+)?(?:p\d+)?)")),
    ("php", re.compile(r"(?i)\bphp[/\s]+(\d+\.\d+(?:\.\d+)?)")),
    ("openssl", re.compile(r"(?i)\bopenssl[/\s]+(\d+\.\d+\.\d+)")),
    ("redis", re.compile(r"(?i)\bredis(?:\s+server)?[:/\s=v]+(\d+\.\d+(?:\.\d+)?)")),
    ("exim", re.compile(r"(?i)\bexim[/\s]+(\d+\.\d+(?:\.\d+)?)")),
    ("iis", re.compile(r"(?i)\bmicrosoft-iis[/\s]+(\d+\.\d+)")),
)


def parse_semver(version_str: str) -> tuple[int, int, int, int] | None:
    """Converts version strings such as `2.4.49` or `8.9p1` into a 4-int tuple."""
    s = (version_str or "").strip()
    m = _SEMVER_RE.match(s)
    if not m:
        return None
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    p_rel = int(m.group(4) or 0)
    return (major, minor, patch, p_rel)


def version_in_range(ver_str: str, min_inclusive: str, max_exclusive: str) -> bool:
    """Returns True if `min_inclusive <= ver_str < max_exclusive`."""
    cur_t = parse_semver(ver_str)
    min_t = parse_semver(min_inclusive)
    max_t = parse_semver(max_exclusive)
    if cur_t is None or min_t is None or max_t is None:
        return False
    return min_t <= cur_t < max_t


def extract_product_versions(raw_text: str) -> list[tuple[str, str]]:
    """Extracts `(product, version)` pairs from HTTP headers, tech stacks, or port banners."""
    text = (raw_text or "").strip()
    if not text:
        return []
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for prod, pat in _PRODUCT_PATTERNS:
        for m in pat.finditer(text):
            ver = m.group(1)
            pair = (prod, ver)
            if pair not in seen:
                seen.add(pair)
                found.append(pair)
    return found


CURATED_CVE_ADVISORIES: tuple[dict[str, Any], ...] = (
    {
        "product": "apache",
        "min": "2.4.49",
        "max": "2.4.51",
        "cve": "CVE-2021-41773 / CVE-2021-42013",
        "title": "Apache HTTP Server 2.4.49–2.4.50 Path Normalization Advisory",
        "severity": "Critical",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-22",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Apache HTTP Server paketini 2.4.62+ versiyasiga yangilang va katalog ruxsatlarini tekshiring.",
    },
    {
        "product": "apache",
        "min": "2.4.0",
        "max": "2.4.59",
        "cve": "CVE-2024-27316",
        "title": "Outdated Apache HTTP Server (< 2.4.59) Security Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Apache HTTP Server ni 2.4.62+ reliziga yoki distribyutor security-backport paketiga yangilang.",
    },
    {
        "product": "apache",
        "min": "2.0.0",
        "max": "2.3.0",
        "cve": "EOL-APACHE-2.2",
        "title": "End-of-Life Apache HTTP Server 2.2.x Unsupported Branch",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Qo'llab-quvvatlash to'xtatilgan Apache 2.2 tarmog'idan zamonaviy Apache 2.4 LTS reliziga o'ting.",
    },
    {
        "product": "nginx",
        "min": "0.6.18",
        "max": "1.20.1",
        "cve": "CVE-2021-23017",
        "title": "Outdated nginx (< 1.20.1) DNS Resolver Memory Advisory",
        "severity": "High",
        "cvss": 7.7,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-193",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "nginx serverini 1.24+ / 1.26+ barqaror versiyasiga yangilang.",
    },
    {
        "product": "nginx",
        "min": "1.20.1",
        "max": "1.25.3",
        "cve": "CVE-2023-44487",
        "title": "nginx (< 1.25.3) HTTP/2 Stream Reset Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "nginx ni 1.25.3+ / 1.26+ versiyasiga yangilang.",
    },
    {
        "product": "openssh",
        "min": "8.5p1",
        "max": "9.8p1",
        "cve": "CVE-2024-6387",
        "title": "OpenSSH (8.5p1–9.7p1) Signal Handler Race Condition Advisory (regreSSHion)",
        "severity": "High",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-362",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "OpenSSH paketini 9.8p1+ (yoki OS security-patch versiyasiga) yangilang.",
    },
    {
        "product": "openssh",
        "min": "1.0",
        "max": "8.4p1",
        "cve": "CVE-2020-14145",
        "title": "Legacy OpenSSH (< 8.4p1) Cryptographic & Host-Key Advisory",
        "severity": "Medium",
        "cvss": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-203",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "OpenSSH xizmatini zamonaviy LTS versiyasiga yangilang.",
    },
    {
        "product": "php",
        "min": "8.1.0",
        "max": "8.1.29",
        "cve": "CVE-2024-4577",
        "title": "Outdated PHP 8.1 (< 8.1.29) Runtime Security Advisory",
        "severity": "High",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PHP tarmog'ini kamida 8.1.29+ (yoki PHP 8.3+) versiyasiga yangilang va `expose_php = Off` o'rnating.",
    },
    {
        "product": "php",
        "min": "5.0.0",
        "max": "8.0.99",
        "cve": "EOL-PHP-LEGACY",
        "title": "End-of-Life PHP Runtime (5.x / 7.x / 8.0 Unsupported Branch)",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Xavfsizlik yangilanishlari to'xtatilgan PHP versiyasini PHP 8.2 / 8.3 LTS reliziga yangilang.",
    },
    {
        "product": "openssl",
        "min": "1.0.0",
        "max": "1.1.1",
        "cve": "EOL-OPENSSL-1.0",
        "title": "End-of-Life OpenSSL 1.0.x Cryptographic Library",
        "severity": "High",
        "cvss": 7.4,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-1104",
        "owasp": "A02:2021 - Cryptographic Failures",
        "remediation": "OpenSSL kutubxonasini OpenSSL 3.x LTS versiyasiga yangilang.",
    },
    {
        "product": "redis",
        "min": "2.0.0",
        "max": "6.2.7",
        "cve": "CVE-2022-0543",
        "title": "Outdated Redis Server (< 6.2.7) Security Advisory",
        "severity": "High",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Redis serverini 7.2+ versiyasiga yangilang, ACL/parol yoqing va tashqi tarmoqdan yoping.",
    },
    {
        "product": "exim",
        "min": "4.0.0",
        "max": "4.96.2",
        "cve": "CVE-2023-42115",
        "title": "Outdated Exim MTA (< 4.96.2) Memory Safety Advisory",
        "severity": "Critical",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-787",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Exim pochta serverini 4.97+ versiyasiga yangilang.",
    },
    {
        "product": "iis",
        "min": "6.0",
        "max": "8.6",
        "cve": "EOL-IIS-LEGACY",
        "title": "Legacy Microsoft-IIS (6.0–8.5) End-of-Support Server Branch",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "IIS platformasini qo'llab-quvvatlanadigan IIS 10.0+ versiyasiga migratsiya qiling.",
    },
)


def match_version_advisories(raw_text: str) -> list[dict[str, Any]]:
    """Matches `(product, version)` pairs extracted from `raw_text` against `CURATED_CVE_ADVISORIES`."""
    pairs = extract_product_versions(raw_text)
    if not pairs:
        return []
    matches: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    for prod, ver in pairs:
        for adv in CURATED_CVE_ADVISORIES:
            if adv["product"] == prod and adv["cve"] not in seen_cves:
                if version_in_range(ver, adv["min"], adv["max"]):
                    seen_cves.add(adv["cve"])
                    hit = dict(adv)
                    hit["detected_version"] = ver
                    matches.append(hit)
    return matches
