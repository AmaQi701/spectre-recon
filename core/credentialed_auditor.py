"""
SPECTRE Read-Only Credentialed SSH CIS & Package Posture Auditor
================================================================
Performs non-destructive, read-only local configuration and package version
checks over an authorized `BatchMode=yes` SSH session (Nessus/OpenVAS LSC style).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from core.advisory_kb import evaluate_distro_lsc_inventory, match_version_advisories
from core.plugin_runner import QoD

_SSH_USER_RE = re.compile(r"^[a-zA-Z0-9._][a-zA-Z0-9._\-]{0,63}$")
_SSH_HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,252}$")


def _parse_ssh_target_strict(ssh_target: str) -> tuple[str, str, int] | None:
    raw = (ssh_target or "").strip()
    if not raw or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in raw):
        return None
    user = ""
    host_port = raw
    if "@" in raw:
        user, host_port = raw.rsplit("@", 1)
        if not user or user.startswith("-") or not _SSH_USER_RE.match(user):
            return None
    port_num = 22
    host_part = host_port
    if host_port.startswith("["):
        if "]" not in host_port:
            return None
        end_idx = host_port.index("]")
        host_part = host_port[1:end_idx]
        rem = host_port[end_idx + 1 :]
        if rem:
            if not rem.startswith(":") or not rem[1:].isdigit():
                return None
            port_num = int(rem[1:])
    elif host_port.count(":") == 1:
        h_cand, p_cand = host_port.rsplit(":", 1)
        if not p_cand.isdigit():
            return None
        host_part = h_cand
        port_num = int(p_cand)
    if not (1 <= port_num <= 65535) or not host_part or host_part.startswith("-"):
        return None
    try:
        ipaddress.ip_address(host_part)
    except ValueError:
        if not _SSH_HOST_RE.match(host_part):
            return None
    return user, host_part, port_num


def parse_sshd_posture(config_text: str) -> list[tuple[str, str, float, str, str]]:
    """Evaluates global `sshd_config` directives against CIS Linux SSH hardening rules."""
    issues: list[tuple[str, str, float, str, str]] = []
    directives: dict[str, str] = {}
    for raw_ln in (config_text or "").splitlines():
        ln = raw_ln.split("#", 1)[0].strip()
        if not ln:
            continue
        parts = ln.split(None, 1)
        if len(parts) == 2:
            key_l = parts[0].lower()
            if key_l == "match":
                break
            directives.setdefault(key_l, parts[1].strip().lower())

    if directives.get("permitemptypasswords") == "yes":
        issues.append((
            "[CONFIRMED] SSH PermitEmptyPasswords Enabled (CIS Benchmark)",
            "Critical", 9.8, "CWE-287",
            "sshd_config faylida `PermitEmptyPasswords no` o'rnating va sshd xizmatini qayta yuklang.",
        ))
    if directives.get("permitrootlogin") == "yes":
        issues.append((
            "[CONFIRMED] SSH Direct Root Password Login Enabled (PermitRootLogin yes)",
            "Medium", 6.5, "CWE-250",
            "sshd_config faylida `PermitRootLogin prohibit-password` yoki `no` o'rnating.",
        ))
    if directives.get("protocol") == "1" or "1" in directives.get("protocol", "").split(","):
        issues.append((
            "[CONFIRMED] Legacy SSH Protocol v1 Enabled in sshd_config",
            "High", 7.5, "CWE-327",
            "sshd_config faylida faqat `Protocol 2` qoldiring.",
        ))
    if directives.get("ignorerhosts") == "no":
        issues.append((
            "[CONFIRMED] SSH IgnoreRhosts Disabled (.rhosts Trust Enabled)",
            "High", 7.5, "CWE-287",
            "sshd_config faylida `IgnoreRhosts yes` o'rnating.",
        ))
    if directives.get("hostbasedauthentication") == "yes":
        issues.append((
            "[CONFIRMED] SSH HostbasedAuthentication Enabled (CIS Benchmark)",
            "High", 7.2, "CWE-287",
            "sshd_config faylida `HostbasedAuthentication no` o'rnating.",
        ))
    return issues


def run_credentialed_ssh_audit(
    db: Any,
    project_id: int,
    ssh_target: str,
    log_fn: Any,
    ssh_key: str = "",
) -> int:
    ssh_bin = shutil.which("ssh")
    if not ssh_bin or not ssh_target:
        return 0

    parsed_t = _parse_ssh_target_strict(ssh_target)
    if parsed_t is None:
        return 0
    user_part, host_part, port_int = parsed_t
    port_num = str(port_int)
    dest_arg = f"{user_part}@{host_part}" if user_part else host_part

    cmd = [
        ssh_bin, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=5", "-p", port_num,
    ]
    if ssh_key:
        key_clean = ssh_key.strip()
        if key_clean.startswith("-"):
            return 0
        key_pf = Path(key_clean).expanduser().resolve()
        if not key_pf.is_file():
            return 0
        cmd.extend(["-i", str(key_pf)])
    remote_probe = (
        "uname -sr; echo '===OS==='; cat /etc/os-release 2>/dev/null | head -n 12; "
        "echo '===SSHD==='; grep -hEv '^[[:space:]]*(#|$)' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null; "
        "echo '===PKGS==='; dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | "
        "grep -Ei '^(openssh-server|sudo|libc6|nginx|apache2|mysql-server|mariadb-server|postgresql|redis-server|php|exim4|postfix|squid|bind9|dnsmasq)' || "
        "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null | "
        "grep -Ei '^(openssh-server|sudo|glibc|nginx|httpd|mariadb-server|postgresql-server|redis|php|postfix|squid|bind|dnsmasq)'"
    )
    cmd.extend(["--", dest_arg, remote_probe])

    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12)
    except Exception:
        return 0
    if proc.returncode != 0 or not proc.stdout:
        return 0

    out = proc.stdout
    written = 0
    parts_os = out.split("===OS===")
    uname_s = parts_os[0].strip()[:80]
    rest1 = parts_os[1] if len(parts_os) > 1 else ""
    os_rel, rest2 = (rest1.split("===SSHD===", 1) + [""])[:2]
    sshd_txt, pkgs_txt = (rest2.split("===PKGS===", 1) + [""])[:2]

    pretty_m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', os_rel)
    os_name = pretty_m.group(1) if pretty_m else uname_s
    db.log_task(project_id, "SPECTRE-Intel", "ssh_lsc_baseline", "COMPLETED", host_part, f"OS: {os_name} | Kernel: {uname_s}")

    for title, sev, cvss, cwe, rem in parse_sshd_posture(sshd_txt):
        db.upsert_finding(
            project_id, "Agent-2 (Credentialed-SSH)", f"{title} ({host_part})",
            "CIS Benchmark / Local Security Check", sev, cvss,
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cwe,
            "A05:2021 - Security Misconfiguration", f"ssh://{host_part}:{port_num}",
            f"Authenticated SSH check on {host_part} ({os_name})",
            "Lokal sshd_config tekshiruvi xavfsizlik me'yorlariga zid sozlamani aniqladi.",
            rem, confidence=QoD.ACTIVE_VERIFIED,
        )
        written += 1

    distro_hits, covered_prods = evaluate_distro_lsc_inventory(f"{os_name}\n{os_rel}", pkgs_txt)
    for d_adv in distro_hits:
        db.upsert_finding(
            project_id, "Agent-2 (Credentialed-SSH)", f"[CONFIRMED] {d_adv['title']} ({host_part}) [{d_adv['cve']}]",
            "Authenticated Package Audit (LSC)", d_adv["severity"], float(d_adv["cvss"]), d_adv["vector"],
            d_adv["cwe"], d_adv["owasp"], f"ssh://{host_part}:{port_num}",
            f"Distro LSC revision check: {d_adv['pkg']} {d_adv['installed_version']} < {d_adv['fixed']} | {d_adv.get('cpe23', '')}",
            "Distro paket reviziyasi xavfsizlik yangilanishidan eski ekanligi aniq tasdiqlandi.",
            d_adv["remediation"], confidence=QoD.ACTIVE_VERIFIED,
        )
        written += 1

    norm_lines: list[str] = []
    for pln in pkgs_txt.splitlines():
        ps = pln.strip().split(None, 1)
        if len(ps) == 2:
            pkg_n = ps[0].replace("openssh-server", "openssh").replace("apache2", "apache").replace("httpd", "apache").replace("-server", "")
            ver_no_epoch = ps[1].split(":", 1)[-1] if re.match(r"^\d+:", ps[1]) else ps[1]
            norm_lines.append(f"{pkg_n} {ver_no_epoch}")
    norm_pkgs = "\n".join(norm_lines)
    for adv in match_version_advisories(f"{os_name}\n{norm_pkgs}"):
        if adv.get("product") in covered_prods or adv.get("distro_backport_likely"):
            continue
        db.upsert_finding(
            project_id, "Agent-2 (Credentialed-SSH)", f"[CONFIRMED] {adv['title']} ({host_part}) [{adv['cve']}]",
            "Authenticated Package Audit (LSC)", adv["severity"], float(adv["cvss"]), adv["vector"],
            adv["cwe"], adv["owasp"], f"ssh://{host_part}:{port_num}",
            f"Authenticated dpkg/rpm inventory: {adv['product']} {adv['detected_version']} | {adv.get('cpe23', '')}",
            "Lokal paket inventarizatsiyasi orqali eskirgan tizim paketi tasdiqlandi.",
            adv["remediation"], confidence=QoD.ACTIVE_VERIFIED,
        )
        written += 1

    if log_fn:
        log_fn(f"  [CREDENTIALED-SSH] {host_part} ({os_name}) tekshirildi -> {written} ta lokal CIS/paket topilmasi.")
    return written
