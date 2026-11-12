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


_SEMVER_RE = re.compile(r"(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:p(\d+)|([a-z])(?![a-z]))?")
_NOISE_BRACKETS_RE = re.compile(r"(?i)\[(?:http-title|ssl-cert|http-robots\.txt|http-favicon):[^\]]*\]")

_PRODUCT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("apache", re.compile(r"(?i)\bapache(?:[:/\s\-_]+(?:httpd|http[_\s\-]+server))?[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("tomcat", re.compile(r"(?i)\b(?:apache[:/\s\-_]+)?tomcat[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("nginx", re.compile(r"(?i)\bnginx[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("openssh", re.compile(r"(?i)\bopenssh(?:_for_windows)?[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?(?:p\d+)?)(?![.\d])")),
    ("php", re.compile(r"(?i)\bphp(?:[:/\s=\-_(]+v?|(?=[578]\.\d))(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("openssl", re.compile(r"(?i)\bopenssl[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?(?:[a-z](?![a-z]))?)(?![.\d])")),
    ("redis", re.compile(r"(?i)\bredis(?:\s+server)?[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("exim", re.compile(r"(?i)\bexim[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("iis", re.compile(r"(?i)\b(?:microsoft[:/\s\-_]+)?(?:iis|internet_information_services)[:/\s=\-_(]+v?(\d+\.\d+)(?![.\d])")),
    ("postgresql", re.compile(r"(?i)\bpostgres(?:ql)?[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("mariadb", re.compile(r"(?i)(?:\b\d+\.\d+\.\d+-)?\b(1\d\.\d+(?:\.\d+)?)-mariadb(?![a-z])")),
    ("mariadb", re.compile(r"(?i)\bmariadb[:/\s=\-_(]+v?(1\d\.\d+(?:\.\d+)?)(?![.\d])")),
    ("mysql", re.compile(r"(?i)\b([58]\.\d+\.\d+)-mysql(?![a-z])")),
    ("mysql", re.compile(r"(?i)\bmysql[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("postfix", re.compile(r"(?i)\bpostfix(?:\s+\([a-z0-9/._\-]+\))?[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("spring_boot", re.compile(r"(?i)\bspring[\s\-_]+boot[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("spring_framework", re.compile(r"(?i)\bspring[\s\-_]+framework[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("nextjs", re.compile(r"(?i)\bnext(?:\.js|js)[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("jquery", re.compile(r"(?i)\bjquery[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("memcached", re.compile(r"(?i)\bmemcached[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("mongodb", re.compile(r"(?i)\bmongodb[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("elasticsearch", re.compile(r"(?i)\belasticsearch[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("proftpd", re.compile(r"(?i)\bproftpd[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?(?:[a-z](?![a-z]))?)(?![.\d])")),
    ("vsftpd", re.compile(r"(?i)\bvsftpd[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("dovecot", re.compile(r"(?i)\bdovecot[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("jetty", re.compile(r"(?i)\b(?:eclipse[:/\s\-_]+)?jetty[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("nodejs", re.compile(r"(?i)\bnode(?:\.js|js)[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("wordpress", re.compile(r"(?i)\bwordpress[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
    ("drupal", re.compile(r"(?i)\bdrupal[:/\s=\-_(]+v?(\d+\.\d+(?:\.\d+)?)(?![.\d])")),
)

_CPE_VENDOR_PRODUCT: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("f5", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "php": ("php", "php"),
    "openssl": ("openssl", "openssl"),
    "redis": ("redis", "redis"),
    "exim": ("exim", "exim"),
    "iis": ("microsoft", "internet_information_services"),
    "postgresql": ("postgresql", "postgresql"),
    "mariadb": ("mariadb", "mariadb"),
    "mysql": ("oracle", "mysql"),
    "postfix": ("postfix", "postfix"),
    "spring_boot": ("vmware", "spring_boot"),
    "spring_framework": ("vmware", "spring_framework"),
    "nextjs": ("vercel", "next.js"),
    "jquery": ("jquery", "jquery"),
    "memcached": ("memcached", "memcached"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "dovecot": ("dovecot", "dovecot"),
    "jetty": ("eclipse", "jetty"),
    "nodejs": ("nodejs", "node.js"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
}


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


def parse_semver(version_str: str) -> tuple[int, int, int, int] | None:
    """Converts version strings such as `2.4.49`, `8.9p1`, or `1.1.1k` into a 4-int tuple."""
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
        sub = ord(m.group(5).lower()) - ord("a") + 1
    else:
        sub = 0
    return (major, minor, patch, sub)


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
                ver = m.group(1)
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
    return list(dict.fromkeys(build_cpe23(p, v) for p, v, _ in _extract_with_local_context(raw_text)))


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
        "min": "8.5",
        "max": "9.8",
        "cve": "CVE-2024-6387",
        "title": "OpenSSH (8.5–9.7p1) Signal Handler Race Condition Advisory (regreSSHion)",
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
        "max": "8.5",
        "cve": "CVE-2020-14145 / CVE-2021-41617",
        "title": "Legacy OpenSSH (< 8.5) Cryptographic & Privilege Escalation Advisory",
        "severity": "Medium",
        "cvss": 6.4,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
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
        "min": "8.2.0",
        "max": "8.2.20",
        "cve": "CVE-2024-4577",
        "title": "Outdated PHP 8.2 (< 8.2.20) Runtime Security Advisory",
        "severity": "High",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PHP 8.2 tarmog'ini 8.2.20+ versiyasiga yangilang va `expose_php = Off` o'rnating.",
    },
    {
        "product": "php",
        "min": "8.3.0",
        "max": "8.3.8",
        "cve": "CVE-2024-4577",
        "title": "Outdated PHP 8.3 (< 8.3.8) Runtime Security Advisory",
        "severity": "High",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PHP 8.3 tarmog'ini 8.3.8+ versiyasiga yangilang va `expose_php = Off` o'rnating.",
    },
    {
        "product": "php",
        "min": "5.0.0",
        "max": "8.1.0",
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
        "product": "openssl",
        "min": "1.1.1",
        "max": "1.1.1l",
        "cve": "CVE-2021-3711",
        "title": "OpenSSL 1.1.1 (< 1.1.1l) SM2 Decryption Buffer Overflow Advisory",
        "severity": "Critical",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-120",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "OpenSSL 1.1.1 tarmog'ini OpenSSL 3.x LTS versiyasiga yangilang.",
    },
    {
        "product": "openssl",
        "min": "1.1.1",
        "max": "1.1.2",
        "cve": "EOL-OPENSSL-1.1.1",
        "title": "End-of-Life OpenSSL 1.1.1 Cryptographic Library Branch",
        "severity": "Medium",
        "cvss": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Qo'llab-quvvatlash muddati tugagan OpenSSL 1.1.1 o'rniga OpenSSL 3.x LTS ga o'ting.",
    },

    {
        "product": "openssl",
        "min": "3.0.0",
        "max": "3.0.7",
        "cve": "CVE-2022-3602 / CVE-2022-3786",
        "title": "OpenSSL 3.0.0–3.0.6 X.509 Buffer Overflow Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-120",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "OpenSSL 3.0 kutubxonasini kamida 3.0.7+ (yoki 3.0.14+) versiyasiga yangilang.",
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
    {
        "product": "postgresql",
        "min": "9.0",
        "max": "12.18",
        "cve": "CVE-2024-0985",
        "title": "Outdated PostgreSQL (< 12.18 / Legacy Branch) Security Advisory",
        "severity": "High",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PostgreSQL serverini qo'llab-quvvatlanadigan LTS minor reliziga yangilang.",
    },
    {
        "product": "postgresql",
        "min": "13.0",
        "max": "13.14",
        "cve": "CVE-2024-0985",
        "title": "Outdated PostgreSQL 13 (< 13.14) Security Advisory",
        "severity": "High",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PostgreSQL 13 tarmog'ini 13.14+ reliziga yangilang.",
    },
    {
        "product": "postgresql",
        "min": "14.0",
        "max": "14.11",
        "cve": "CVE-2024-0985",
        "title": "Outdated PostgreSQL 14 (< 14.11) Security Advisory",
        "severity": "High",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PostgreSQL 14 tarmog'ini 14.11+ reliziga yangilang.",
    },
    {
        "product": "postgresql",
        "min": "15.0",
        "max": "15.6",
        "cve": "CVE-2024-0985",
        "title": "Outdated PostgreSQL 15 (< 15.6) Security Advisory",
        "severity": "High",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PostgreSQL 15 tarmog'ini 15.6+ reliziga yangilang.",
    },
    {
        "product": "postgresql",
        "min": "16.0",
        "max": "16.2",
        "cve": "CVE-2024-0985",
        "title": "Outdated PostgreSQL 16 (< 16.2) Security Advisory",
        "severity": "High",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "PostgreSQL 16 tarmog'ini 16.2+ reliziga yangilang.",
    },
    {
        "product": "mysql",
        "min": "5.0.0",
        "max": "5.8.0",
        "cve": "EOL-MYSQL-5.X",
        "title": "End-of-Life MySQL 5.x Unsupported Database Branch",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Qo'llab-quvvatlash to'xtatilgan MySQL 5.x tarmog'ini MySQL 8.0.36+ yoki 8.4 LTS ga yangilang.",
    },
    {
        "product": "mysql",
        "min": "8.0.0",
        "max": "8.0.36",
        "cve": "CVE-2024-20960",
        "title": "Outdated MySQL 8.0 (< 8.0.36) Critical Patch Update Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MySQL 8.0 serverini 8.0.36+ yoki 8.4 LTS reliziga yangilang.",
    },
    {
        "product": "mariadb",
        "min": "10.0.0",
        "max": "10.5.24",
        "cve": "CVE-2023-5157",
        "title": "Outdated MariaDB (< 10.5.24 / Legacy 10.x) Security Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MariaDB serverini 10.6.18+ yoki 10.11 LTS versiyasiga yangilang.",
    },
    {
        "product": "mariadb",
        "min": "10.6.0",
        "max": "10.6.17",
        "cve": "CVE-2023-5157",
        "title": "Outdated MariaDB 10.6 (< 10.6.17) Security Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MariaDB 10.6 LTS tarmog'ini 10.6.18+ reliziga yangilang.",
    },
    {
        "product": "postfix",
        "min": "2.0.0",
        "max": "3.5.24",
        "cve": "CVE-2023-51764",
        "title": "Outdated Postfix MTA (< 3.5.24) SMTP Smuggling Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-444",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Postfix paketini 3.5.24+ reliziga yangilang yoki `smtpd_forbid_bare_newline = yes` sozlamasini yoqing.",
    },
    {
        "product": "postfix",
        "min": "3.6.0",
        "max": "3.6.13",
        "cve": "CVE-2023-51764",
        "title": "Outdated Postfix 3.6 (< 3.6.13) SMTP Smuggling Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-444",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Postfix 3.6 tarmog'ini 3.6.13+ reliziga yangilang.",
    },
    {
        "product": "postfix",
        "min": "3.7.0",
        "max": "3.7.9",
        "cve": "CVE-2023-51764",
        "title": "Outdated Postfix 3.7 (< 3.7.9) SMTP Smuggling Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-444",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Postfix 3.7 tarmog'ini 3.7.9+ reliziga yangilang.",
    },
    {
        "product": "postfix",
        "min": "3.8.0",
        "max": "3.8.4",
        "cve": "CVE-2023-51764",
        "title": "Outdated Postfix 3.8 (< 3.8.4) SMTP Smuggling Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-444",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Postfix 3.8 tarmog'ini 3.8.4+ reliziga yangilang.",
    },
    {
        "product": "spring_boot",
        "min": "2.0.0",
        "max": "2.6.6",
        "cve": "CVE-2022-22965",
        "title": "Spring Boot (< 2.6.6) Data Binding Security Advisory",
        "severity": "Critical",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Spring Boot tarmog'ini 2.7.18+ yoki 3.2+ LTS versiyasiga yangilang.",
    },
    {
        "product": "spring_boot",
        "min": "2.6.6",
        "max": "2.7.18",
        "cve": "CVE-2023-34055",
        "title": "Outdated Spring Boot 2.x (< 2.7.18) End-of-OSS-Support Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Spring Boot 2.x OSS qo'llab-quvvatlashi yakunlangan — Spring Boot 3.2+ / 3.3+ ga o'ting.",
    },
    {
        "product": "spring_boot",
        "min": "3.0.0",
        "max": "3.1.6",
        "cve": "CVE-2023-34055",
        "title": "Outdated Spring Boot 3.0/3.1 (< 3.1.6) Security Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Spring Boot 3.x tarmog'ini 3.2.5+ / 3.3+ versiyasiga yangilang.",
    },
    {
        "product": "spring_framework",
        "min": "5.0.0",
        "max": "5.3.18",
        "cve": "CVE-2022-22965",
        "title": "Spring Framework (< 5.3.18) Data Binding Security Advisory",
        "severity": "Critical",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Spring Framework kutubxonasini 5.3.34+ yoki 6.1+ versiyasiga yangilang.",
    },
    {
        "product": "nextjs",
        "min": "10.0.0",
        "max": "13.5.7",
        "cve": "CVE-2024-34351",
        "title": "Outdated Next.js (< 13.5.7 / Legacy 10–13) Server-Side Handling Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-918",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Next.js freymvorkini 14.1.1+ yoki 14.2+ barqaror versiyasiga yangilang.",
    },
    {
        "product": "nextjs",
        "min": "14.0.0",
        "max": "14.1.1",
        "cve": "CVE-2024-34351",
        "title": "Next.js 14 (< 14.1.1) Server-Side Redirect Handling Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-918",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Next.js 14 tarmog'ini 14.1.1+ yoki 14.2+ reliziga yangilang.",
    },
    {
        "product": "tomcat",
        "min": "7.0.0",
        "max": "9.0.86",
        "cve": "CVE-2024-24549 / CVE-2024-23672",
        "title": "Outdated Apache Tomcat (< 9.0.86 / Legacy 7.x–8.5.x) Security Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Apache Tomcat serverini 9.0.86+, 10.1.19+ yoki 11.x barqaror versiyasiga yangilang.",
    },
    {
        "product": "tomcat",
        "min": "10.0.0",
        "max": "10.1.19",
        "cve": "CVE-2024-24549",
        "title": "Outdated Apache Tomcat 10 (< 10.1.19) HTTP/2 Header Handling Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Apache Tomcat 10 tarmog'ini 10.1.19+ versiyasiga yangilang.",
    },
    {
        "product": "jquery",
        "min": "1.0.0",
        "max": "3.5.0",
        "cve": "CVE-2020-11022 / CVE-2020-11023",
        "title": "Outdated jQuery (< 3.5.0) DOM HTML Prefilter Advisory",
        "severity": "Medium",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Frontend jQuery kutubxonasini 3.7.1+ versiyasiga yangilang.",
    },
    {
        "product": "memcached",
        "min": "1.0.0",
        "max": "1.6.22",
        "cve": "CVE-2023-46852",
        "title": "Outdated Memcached (< 1.6.22) Buffer Handling Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-120",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Memcached xizmatini 1.6.22+ versiyasiga yangilang va lokal interfeysga bog'lang.",
    },
    {
        "product": "mongodb",
        "min": "2.0.0",
        "max": "5.0.0",
        "cve": "EOL-MONGODB-LEGACY",
        "title": "End-of-Life MongoDB (2.x–4.x) Unsupported Database Branch",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MongoDB serverini qo'llab-quvvatlanadigan 6.0.14+ yoki 7.0.6+ LTS versiyasiga yangilang.",
    },
    {
        "product": "mongodb",
        "min": "5.0.0",
        "max": "5.0.25",
        "cve": "CVE-2024-1351",
        "title": "Outdated MongoDB 5.0 (< 5.0.25) Certificate Validation Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-295",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MongoDB 5.0 tarmog'ini 5.0.25+ yoki 7.0+ LTS ga yangilang.",
    },
    {
        "product": "mongodb",
        "min": "6.0.0",
        "max": "6.0.14",
        "cve": "CVE-2024-1351",
        "title": "Outdated MongoDB 6.0 (< 6.0.14) Certificate Validation Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-295",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MongoDB 6.0 tarmog'ini 6.0.14+ versiyasiga yangilang.",
    },
    {
        "product": "elasticsearch",
        "min": "1.0.0",
        "max": "7.17.18",
        "cve": "CVE-2024-23446",
        "title": "Outdated Elasticsearch (< 7.17.18) Security Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Elasticsearch klasterini 7.17.18+ yoki 8.12.2+ versiyasiga yangilang.",
    },
    {
        "product": "elasticsearch",
        "min": "8.0.0",
        "max": "8.12.1",
        "cve": "CVE-2024-23446",
        "title": "Outdated Elasticsearch 8 (< 8.12.1) Security Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Elasticsearch 8 tarmog'ini 8.12.2+ versiyasiga yangilang.",
    },
    {
        "product": "proftpd",
        "min": "1.0.0",
        "max": "1.3.8b",
        "cve": "CVE-2023-48795",
        "title": "Outdated ProFTPD (< 1.3.8b) Prefix Truncation Advisory",
        "severity": "Medium",
        "cvss": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-354",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "ProFTPD xizmatini 1.3.8b+ versiyasiga yangilang.",
    },
    {
        "product": "vsftpd",
        "min": "1.0.0",
        "max": "3.0.4",
        "cve": "CVE-2021-3618",
        "title": "Outdated vsFTPd (< 3.0.4) ALPACA TLS Enforcement Advisory",
        "severity": "Medium",
        "cvss": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-295",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "vsFTPd xizmatini 3.0.5+ versiyasiga yangilang yoki SFTP/SSH ga o'ting.",
    },
    {
        "product": "dovecot",
        "min": "1.0.0",
        "max": "2.3.21",
        "cve": "CVE-2022-30550",
        "title": "Outdated Dovecot (< 2.3.21) Privilege Separation Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-269",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Dovecot IMAP/POP3 serverini 2.3.21+ versiyasiga yangilang.",
    },
    {
        "product": "vsftpd",
        "min": "2.3.4",
        "max": "2.3.5",
        "cve": "CVE-2011-2523",
        "title": "Legacy vsFTPd 2.3.4 Compromised Release Advisory",
        "severity": "Critical",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-506",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "vsFTPd 2.3.4 paketini darhol rasmiy 3.0.5+ versiyasiga yoki OpenSSH SFTP ga almashtiring.",
    },
    {
        "product": "mongodb",
        "min": "7.0.0",
        "max": "7.0.6",
        "cve": "CVE-2024-1351",
        "title": "Outdated MongoDB 7.0 (< 7.0.6) Certificate Validation Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-295",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "MongoDB 7.0 tarmog'ini 7.0.6+ versiyasiga yangilang.",
    },
    {
        "product": "jetty",
        "min": "7.0.0",
        "max": "9.4.54",
        "cve": "CVE-2024-22201",
        "title": "Outdated Eclipse Jetty (< 9.4.54 / Legacy 7–9) HTTP/2 Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Eclipse Jetty serverini 9.4.54+, 10.0.20+, 11.0.20+ yoki 12.x versiyasiga yangilang.",
    },
    {
        "product": "jetty",
        "min": "10.0.0",
        "max": "10.0.20",
        "cve": "CVE-2024-22201",
        "title": "Outdated Eclipse Jetty 10 (< 10.0.20) HTTP/2 Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Eclipse Jetty 10 tarmog'ini 10.0.20+ yoki 12.x versiyasiga yangilang.",
    },
    {
        "product": "jetty",
        "min": "11.0.0",
        "max": "11.0.20",
        "cve": "CVE-2024-22201",
        "title": "Outdated Eclipse Jetty 11 (< 11.0.20) HTTP/2 Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Eclipse Jetty 11 tarmog'ini 11.0.20+ yoki 12.x versiyasiga yangilang.",
    },
    {
        "product": "nodejs",
        "min": "8.0.0",
        "max": "18.0.0",
        "cve": "EOL-NODEJS-LEGACY",
        "title": "End-of-Life Node.js (< 18.0.0) Unsupported Runtime Branch",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Node.js muhitini qo'llab-quvvatlanadigan Node.js 20 LTS yoki 22 LTS ga yangilang.",
    },
    {
        "product": "nodejs",
        "min": "18.0.0",
        "max": "18.20.1",
        "cve": "CVE-2024-27983",
        "title": "Outdated Node.js 18 (< 18.20.1) HTTP/2 Frame Handling Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Node.js 18 tarmog'ini 18.20.2+ yoki 20/22 LTS versiyasiga yangilang.",
    },
    {
        "product": "nodejs",
        "min": "20.0.0",
        "max": "20.12.1",
        "cve": "CVE-2024-27983",
        "title": "Outdated Node.js 20 (< 20.12.1) HTTP/2 Frame Handling Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Node.js 20 LTS tarmog'ini 20.12.2+ versiyasiga yangilang.",
    },
    {
        "product": "wordpress",
        "min": "3.0.0",
        "max": "6.4.3",
        "cve": "CVE-2024-31210",
        "title": "Outdated WordPress Core (< 6.4.3) Security Advisory",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "WordPress yadrosini eng so'nggi 6.5+ / 6.6+ xavfsizlik reliziga yangilang.",
    },
    {
        "product": "drupal",
        "min": "6.0.0",
        "max": "10.0.0",
        "cve": "EOL-DRUPAL-LEGACY",
        "title": "End-of-Life Drupal (6.x–9.x) Unsupported CMS Branch",
        "severity": "High",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Qo'llab-quvvatlash tugagan Drupal versiyasini Drupal 10.2.2+ yoki 11.x ga yangilang.",
    },
    {
        "product": "drupal",
        "min": "10.0.0",
        "max": "10.2.2",
        "cve": "CVE-2024-22650",
        "title": "Outdated Drupal 10 (< 10.2.2) Security Advisory",
        "severity": "Medium",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Drupal 10 tarmog'ini 10.2.2+ versiyasiga yangilang.",
    },

)


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
