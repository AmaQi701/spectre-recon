import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import urllib.parse
from pathlib import Path
import requests

from core.advisory_kb import match_version_advisories
from core.database import DatabaseManager
from core.http_engine import RateLimitedHttpEngine
from core.plugin_runner import QoD, ScanContextKB, ScanPhase, run_plugin_safely


class VulnAssessmentSuperAgent:
    """
    2-SuperAgent: Vulnerability Assessment & SAST Auditor.
    1. HTTP Security Headers, CORS, TLS va Cookie bayroqlarini audit qiladi.
    2. Topilgan endpoint va parametrlarni IDOR, SSRF, Injection va Business Logic bo'yicha saralaydi.
    3. JS DOM Sink va API hujjatlaridagi xavflarni tahlil qiladi.
    4. White-box (SAST): Loyiha kodidagi xavfli funksiyalarni qatorigacha topadi.
    5. JWT Token strukturasini tekshiradi.
    """

    SAST_RULES = [
        {
            "title": "Potential SQL Injection (Raw Query Concatenation)",
            "category": "Injection (SAST)",
            "severity": "High",
            "cvss": 8.6,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "pattern": re.compile(r"""(?i)(execute|query|raw)\s*\(\s*f?['"`]\s*(SELECT|INSERT|UPDATE|DELETE).*(\{|\+|\%s|\$[a-zA-Z_])"""),
            "remediation": "Parametrlangan so'rovlar (Prepared Statements / ORM parameter binding) ishlating.",
        },
        {
            "title": "Potential OS Command Injection Sink",
            "category": "RCE / Command Injection (SAST)",
            "severity": "Critical",
            "cvss": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
            "pattern": re.compile(r"""(?i)(os\.system|subprocess\.(?:popen|call|run).*shell\s*=\s*True|exec\s*\(|shell_exec\s*\(|child_process\.exec)"""),
            "remediation": "shell=True ishlatmang; foydalanuvchi kiritmasini argumentlar ro'yxati sifatida uzating va oq ro'yxat (allowlist) bilan tekshiring.",
        },
        {
            "title": "Unsafe Deserialization / Code Eval Sink",
            "category": "Insecure Deserialization (SAST)",
            "severity": "High",
            "cvss": 8.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
            "cwe": "CWE-502",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "pattern": re.compile(r"""(?i)(pickle\.loads|yaml\.load\s*\([^,)]*\)|unserialize\s*\(|eval\s*\()"""),
            "remediation": "yaml.safe_load() yoki JSON formatidan foydalaning; ishonchsiz ma'lumotlarda eval/pickle ishlatmang.",
        },
        {
            "title": "Hardcoded Credential or Secret Key in Source",
            "category": "Cryptographic / Secret Exposure (SAST)",
            "severity": "High",
            "cvss": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "pattern": re.compile(r"""(?i)(api_key|secret_key|jwt_secret|password|private_key)\s*=\s*['"][a-zA-Z0-9_\-\.!@#\$%\^&\*]{10,}['"]"""),
            "remediation": "Maxfiy kalitlarni kod ichida emas, Environment Variables (.env / Vault) orqali yuklang.",
        },
        {
            "title": "Potential Server-Side Request Forgery (SSRF) Sink",
            "category": "SSRF (SAST)",
            "severity": "High",
            "cvss": 8.2,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "pattern": re.compile(r"""(?i)(requests\.(?:get|post|request)|urllib\.request\.urlopen|curl_exec|file_get_contents|http\.Get)\s*\(\s*(?:request\.|req\.|\$_(?:GET|POST|REQUEST)|params\[)"""),
            "remediation": "Foydalanuvchi kiritgan URL manzillarini oq ro'yxat (allowlist) bilan tekshiring va ichki IP (127.0.0.1, 169.254.169.254, RFC1918) manzillarni bloklang.",
        },
        {
            "title": "Potential Local File Inclusion / Path Traversal Sink",
            "category": "LFI / Path Traversal (SAST)",
            "severity": "High",
            "cvss": 7.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
            "pattern": re.compile(r"""(?i)(send_file|open|include|require|include_once|require_once|readFileSync)\s*\(\s*.*(?:request\.|req\.|\$_(?:GET|POST|REQUEST))"""),
            "remediation": "Fayl yo'llarini os.path.basename() yoki realpath() orqali asosiy katalog ichida ekanligini tekshiring.",
        },
        {
            "title": "Server-Side Template Injection (SSTI) Sink",
            "category": "Injection / SSTI (SAST)",
            "severity": "Critical",
            "cvss": 9.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-1336",
            "owasp": "A03:2021 - Injection",
            "pattern": re.compile(r"""(?i)(render_template_string|Template\s*\(\s*(?:request\.|req\.)|Twig_Loader_String)"""),
            "remediation": "Foydalanuvchi kiritmasini shablon kodi sifatida kompilatsiya qilmang; statik shablon fayllariga kontekst o'zgaruvchisi sifatida uzating.",
        },
        {
            "title": "Weak Cryptographic Hash Algorithm (MD5 / SHA1) for Security",
            "category": "Cryptographic Failure (SAST)",
            "severity": "Medium",
            "cvss": 5.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": "CWE-328",
            "owasp": "A02:2021 - Cryptographic Failures",
            "pattern": re.compile(r"""(?i)(hashlib\.(?:md5|sha1)\s*\(|md5\s*\(\s*\$_(?:POST|GET|REQUEST)|sha1\s*\(\s*\$_)"""),
            "remediation": "Parollar uchun Argon2id yoki bcrypt, xeshlar uchun SHA-256 / SHA-3 ishlating.",
        },
        {
            "title": "DOM-Based XSS Sink in Source Code (innerHTML / dangerouslySetInnerHTML)",
            "category": "Cross-Site Scripting (SAST)",
            "severity": "High",
            "cvss": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "pattern": re.compile(r"""(?i)(\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=)"""),
            "remediation": "innerHTML o'rniga textContent ishlating yoki DOMPurify orqali HTML kiritmani sanitizatsiya qiling.",
        },
    ]

    def __init__(self, db: DatabaseManager):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SPECTRE-VulnAgent/13.0"})
        self.http_engine = RateLimitedHttpEngine(self.session, max_rps_per_host=10.0, fail_threshold=4)
        self.role_a_headers: dict[str, str] = {}
        self.role_b_headers: dict[str, str] = {}

    @staticmethod
    def _parse_auth_header(raw_auth: str) -> dict[str, str]:
        s = (raw_auth or "").strip()
        if not s:
            return {}
        if ":" in s:
            k, v = s.split(":", 1)
            return {k.strip(): v.strip()}
        return {"Cookie": s}

    def configure_context(self, primary_auth: str = "", secondary_auth: str = "", proxy_url: str = "") -> None:
        self.role_a_headers = self._parse_auth_header(primary_auth)
        self.role_b_headers = self._parse_auth_header(secondary_auth)
        self.session.proxies.clear()
        if proxy_url.strip():
            self.session.proxies.update({"http": proxy_url.strip(), "https": proxy_url.strip()})

    def audit_jwt_token(self, token: str) -> dict:
        parts = token.strip().split(".")
        if len(parts) < 2:
            return {"valid": False, "error": "Noto'g'ri JWT format"}
        def _b64_dec(s: str) -> dict:
            pad = "=" * ((4 - len(s) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(s + pad).decode("utf-8", errors="ignore"))
        try:
            header = _b64_dec(parts[0])
            payload = _b64_dec(parts[1])
            issues = []
            alg = str(header.get("alg", "")).lower()
            if alg in ("none", ""):
                issues.append("CRITICAL: 'alg: none' ruxsat etilgan bo'lishi mumkin (Authentication Bypass xavfi).")
            if alg in ("hs256", "hs384", "hs512"):
                issues.append("MEDIUM: Simmetrik HMAC algoritmi ('" + alg.upper() + "') ishlatilgan — zaif JWT secret kalitga sezgir.")
            if "exp" not in payload:
                issues.append("MEDIUM: Token muddati ('exp' claim) belgilanmagan — token doimiy amal qilishi mumkin.")
            if any(k in str(payload).lower() for k in ("password", "secret", "ssn", "private")):
                issues.append("HIGH: JWT payload ichida sezgir ma'lumotlar ochiq (Base64) saqlangan.")
            if "jku" in header or "x5u" in header or "kid" in header:
                issues.append("INFO/HIGH: Headerda 'kid'/'jku'/'x5u' mavjud — Path Traversal yoki SSRF/Key Injection tekshiruvi tavsiya etiladi.")
            return {"valid": True, "header": header, "payload": payload, "issues": issues}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _audit_http_services(self, project_id: int, http_services: list[dict], log_fn):
        seen_header_sigs: set[tuple[str, str]] = set()
        cors_dead_hosts: set[str] = set()
        for svc in http_services:
            url = svc["url"]
            sec = json.loads(svc.get("security_headers_json") or "{}")
            cookies = json.loads(svc.get("cookies_json") or "[]")

            acao = sec.get("Access-Control-Allow-Origin", "")
            acac = sec.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "*" and acac == "true":
                self.db.upsert_finding(
                    project_id, "Agent-2 (VulnAudit)", "Critical CORS Misconfiguration (Wildcard + Credentials)",
                    "CORS / Access Control", "High", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    "CWE-942", "A05:2021 - Security Misconfiguration", url,
                    f"Access-Control-Allow-Origin: {acao} | Allow-Credentials: {acac}",
                    "Server barcha tashqi domenlarga autentifikatsiya ma'lumotlari bilan so'rov yuborishga ruxsat bermoqda.",
                    "Access-Control-Allow-Origin qiymatini faqat ishonchli domenlar oq ro'yxati bilan cheklang.",
                )
            elif acao == "*":
                self.db.upsert_finding(
                    project_id, "Agent-2 (VulnAudit)", "Permissive CORS Policy (Access-Control-Allow-Origin: *)",
                    "Security Misconfiguration", "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-942", "A05:2021 - Security Misconfiguration", url,
                    "Header: Access-Control-Allow-Origin: *",
                    "Barcha tashqi originlar uchun javoblarni o'qish ruxsat etilgan.",
                    "Agar API ommaviy bo'lmasa, ruxsat berilgan originlarni qat'iy belgilang.",
                )

            # Active Dynamic Origin Reflection Probe (single non-duplicated check with host timeout guard)
            host_only = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
            if host_only not in cors_dead_hosts:
                try:
                    r_cors = self.session.get(url, headers={"Origin": "https://cors-check.example.org"}, timeout=3.5, verify=False, allow_redirects=False)
                    ref_acao = r_cors.headers.get("Access-Control-Allow-Origin", "")
                    ref_acac = r_cors.headers.get("Access-Control-Allow-Credentials", "").lower()
                    if ref_acao == "https://cors-check.example.org":
                        sev_c = "Critical" if ref_acac == "true" else "Medium"
                        cvss_c = 8.8 if ref_acac == "true" else 5.3
                        self.db.upsert_finding(
                            project_id, "Agent-2 (Active-CORS)", f"[CONFIRMED] Arbitrary CORS Origin Reflection ({url})",
                            "CORS Origin Reflection", sev_c, cvss_c, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                            "CWE-942", "A05:2021 - Security Misconfiguration", url,
                            f"Sent Origin: https://cors-check.example.org -> Reflected ACAO: {ref_acao} | ACAC: {ref_acac}",
                            "Server har qanday tashqi Origin sarlavhasini Access-Control-Allow-Origin ichida aks ettirmoqda.",
                            "Origin sarlavhasini avtomatik aks ettirmang; qat'iy oq ro'yxat (allowlist) tekshiruvini o'rnating.",
                            confidence=QoD.ACTIVE_VERIFIED,
                        )
                except requests.exceptions.RequestException:
                    cors_dead_hosts.add(host_only)
                except Exception:
                    pass

            missing_headers = [
                h for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")
                if not sec.get(h)
            ]
            hdr_sig = (svc.get("server", ""), ",".join(missing_headers))
            if missing_headers and hdr_sig not in seen_header_sigs:
                seen_header_sigs.add(hdr_sig)
                self.db.upsert_finding(
                    project_id, "Agent-2 (VulnAudit)", "Missing HTTP Security Hardening Headers",
                    "Security Misconfiguration", "Low", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    "CWE-693", "A05:2021 - Security Misconfiguration", url,
                    f"Yetishmayotgan headerlar: {', '.join(missing_headers)}",
                    "Veb-server javobida himoya headerlari (CSP, HSTS, XFO, XCTO) sozlanmagan.",
                    "Nginx/Apache yoki ilova darajasida HSTS, CSP, X-Frame-Options: DENY va X-Content-Type-Options: nosniff qo'shing.",
                )

            for ck in cookies:
                if not ck.get("httponly") or not ck.get("secure"):
                    self.db.upsert_finding(
                        project_id, "Agent-2 (VulnAudit)", f"Insecure Cookie Flags ({ck.get('name', 'session')})",
                        "Session Management", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "CWE-614", "A07:2021 - Identification and Authentication Failures", url,
                        f"Cookie: {ck.get('raw', '')}",
                        "Session cookie'da HttpOnly yoki Secure bayrog'i o'rnatilmagan.",
                        "Set-Cookie headeriga 'HttpOnly; Secure; SameSite=Strict' atributlarini qo'shing.",
                    )

            # Server Version Disclosure
            srv = svc.get("server", "")
            if srv and re.search(r"\d+\.\d+", srv):
                self.db.upsert_finding(
                    project_id, "Agent-2 (VulnAudit)", f"Web Server Version Information Disclosure ({srv})",
                    "Information Disclosure", "Low", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", url,
                    f"Server Header: {srv}",
                    "Veb-server o'zining aniq versiyasini HTTP javob headerida oshkor qilmoqda.",
                    "Nginx da 'server_tokens off;' yoki Apache da 'ServerTokens Prod' sozlamasini yoqing.",
                )
        log_fn(f"  [+] {len(http_services)} ta HTTP servis, Server versiyalari va Active CORS Reflection tekshirildi.")

    def _audit_open_ports(self, project_id: int, ports: list[dict], log_fn):
        data_store_ports = {
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            11211: "Memcached", 27017: "MongoDB", 9200: "Elasticsearch",
        }
        legacy_cleartext_ports = {21: "FTP", 23: "Telnet", 873: "Rsync"}
        for pt in ports:
            pnum = int(pt.get("port", 0))
            host = pt.get("host", "")
            svc = pt.get("service", "")
            ver = pt.get("version", "")
            banner = pt.get("banner", "")
            b_low = f"{svc} {ver} {banner}".lower()
            if pnum == 22:
                self.db.upsert_finding(
                    project_id, "Agent-2 (NetworkAudit)", f"Publicly Exposed SSH Service ({host}:22)",
                    "Network Exposure", "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{host}:22",
                    f"Port 22/tcp open | Service: {svc} {ver} {banner}".strip(),
                    "SSH boshqaruv porti tashqi internet uchun ochiq qoldirilgan.",
                    "SSH portini faqat VPN yoki ma'muriy IP manzillar (Firewall allowlist) uchun oching va PasswordAuthentication ni o'chiring.",
                    confidence=QoD.HEADER_CONFIG,
                )
                if any(wk in b_low for wk in ("ssh-1.99", "ssh-1.5", "arcfour", "diffie-hellman-group1-sha1", "ssh-dss", "3des-cbc")):
                    self.db.upsert_finding(
                        project_id, "Agent-2 (ProtocolAudit)", f"[CONFIRMED] Weak / Legacy SSH Protocol or Algorithm ({host}:22)",
                        "Cryptographic Failure", "Medium", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "CWE-327", "A02:2021 - Cryptographic Failures", f"{host}:22",
                        f"SSH Banner / Negotiated Info: {svc} {ver} {banner}".strip(),
                        "SSH xizmatida eskirgan protokol yoki zaif shifrlash algoritmi yoqilgan.",
                        "sshd_config ichida zamonaviy Curve25519 KEX va ChaCha20-Poly1305 / AES-GCM shifrlarini qoldiring.",
                        confidence=QoD.PROTOCOL_VERIFIED,
                    )
            elif pnum in data_store_ports:
                ds_name = data_store_ports[pnum]
                self.db.upsert_finding(
                    project_id, "Agent-2 (ProtocolAudit)", f"Exposed Backend Data Store Port ({ds_name} on {host}:{pnum})",
                    "Database / Cache Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{host}:{pnum}",
                    f"Port {pnum}/tcp ({ds_name}) open | Banner: {svc} {ver} {banner}".strip(),
                    f"{ds_name} ma'lumotlar ombori porti tashqi tarmoq interfeysida ochiq qoldirilgan.",
                    f"{ds_name} xizmatini `127.0.0.1` / ichki VPC ga bog'lang, kuchli autentifikatsiya va TLS yoqing.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
            elif pnum in legacy_cleartext_ports:
                pr_name = legacy_cleartext_ports[pnum]
                self.db.upsert_finding(
                    project_id, "Agent-2 (ProtocolAudit)", f"Cleartext Legacy Service Exposed ({pr_name} on {host}:{pnum})",
                    "Cleartext Transmission / Network Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-319", "A02:2021 - Cryptographic Failures", f"{host}:{pnum}",
                    f"Port {pnum}/tcp ({pr_name}) open | Banner: {svc} {ver} {banner}".strip(),
                    f"Shifrlanmagan {pr_name} protokoli tashqi tarmoq uchun ochiq qoldirilgan.",
                    f"{pr_name} o'rniga SFTP/SSH ishlating va portni tashqi interfeysdan Firewall orqali yoping.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
            elif pnum in (137, 139, 445, 3389, 5900):
                self.db.upsert_finding(
                    project_id, "Agent-2 (NetworkAudit)", f"Exposed Critical Management / SMB Port ({host}:{pnum})",
                    "Network Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{host}:{pnum}",
                    f"Port {pnum}/tcp open | Service: {svc} {ver}",
                    "SMB/RDP/VNC boshqaruv porti tashqi internet uchun ochiq qoldirilgan.",
                    "Ushbu portni tashqi interfeysdan Firewall orqali yoping (faqat VPN orqali ruxsat bering).",
                    confidence=QoD.HEADER_CONFIG,
                )

    def _audit_version_cve_advisories(self, project_id: int, http_services: list[dict], ports: list[dict], log_fn):
        seen_adv: set[tuple[str, str]] = set()
        hits = 0
        for svc in http_services:
            url = svc.get("url", "")
            host_k = (urllib.parse.urlparse(url).hostname or url).lower()
            hdrs = json.loads(svc.get("headers_json") or "{}")
            techs = " ".join(json.loads(svc.get("tech_stack") or "[]"))
            combined = f"{svc.get('server', '')} {hdrs.get('X-Powered-By', '')} {hdrs.get('x-powered-by', '')} {techs}"
            for adv in match_version_advisories(combined):
                sig = (host_k, adv["cve"])
                if sig in seen_adv:
                    continue
                seen_adv.add(sig)
                hits += 1
                self.db.upsert_finding(
                    project_id, "Agent-2 (CVE-Engine)", f"{adv['title']} [{adv['cve']}]",
                    "Vulnerable & Outdated Components", adv["severity"], adv["cvss"], adv["vector"],
                    adv["cwe"], adv["owasp"], url,
                    f"Detected: {adv['product']} {adv['detected_version']} (Range: >= {adv['min']}, < {adv['max']}) | Banner: {combined.strip()[:120]}",
                    f"HTTP servis bannerida eskirgan '{adv['product']} {adv['detected_version']}' versiyasi aniqlandi ({adv['cve']}).",
                    adv["remediation"],
                    confidence=QoD.BANNER_CVE,
                )
        for pt in ports:
            host_k = str(pt.get("host") or pt.get("ip") or "").lower()
            pnum = int(pt.get("port") or 0)
            combined = f"{pt.get('service', '')} {pt.get('version', '')} {pt.get('banner', '')}".strip()
            for adv in match_version_advisories(combined):
                sig = (host_k, adv["cve"])
                if sig in seen_adv:
                    continue
                seen_adv.add(sig)
                hits += 1
                self.db.upsert_finding(
                    project_id, "Agent-2 (CVE-Engine)", f"{adv['title']} [{adv['cve']}]",
                    "Vulnerable & Outdated Components", adv["severity"], adv["cvss"], adv["vector"],
                    adv["cwe"], adv["owasp"], f"{host_k}:{pnum}",
                    f"Detected: {adv['product']} {adv['detected_version']} on {host_k}:{pnum} | Banner: {combined[:120]}",
                    f"Tarmoq porti bannerida eskirgan '{adv['product']} {adv['detected_version']}' versiyasi aniqlandi ({adv['cve']}).",
                    adv["remediation"],
                    confidence=QoD.BANNER_CVE,
                )
        if hits:
            log_fn(f"  [CVE-ENGINE] Semantic Version tahlili orqali {hits} ta eskirgan komponent / CVE tavsiyasi aniqlandi.")

    def _audit_tls_and_cache_posture(self, project_id: int, http_services: list[dict], log_fn):
        seen_tls: set[str] = set()
        for svc in http_services:
            url = svc.get("url", "")
            host_k = (urllib.parse.urlparse(url).hostname or url).lower()
            tls = json.loads(svc.get("tls_json") or "{}")
            hdrs = {str(k).lower(): str(v) for k, v in json.loads(svc.get("headers_json") or "{}").items()}
            proto_ver = str(tls.get("protocol") or tls.get("version") or "")
            if proto_ver and any(lp in proto_ver.upper() for lp in ("SSL", "TLSV1.0", "TLSV1.1")) and host_k not in seen_tls:
                seen_tls.add(host_k)
                self.db.upsert_finding(
                    project_id, "Agent-2 (TLS-Audit)", f"[CONFIRMED] Deprecated TLS Protocol Negotiated ({proto_ver})",
                    "Cryptographic Failure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "CWE-326", "A02:2021 - Cryptographic Failures", url,
                    f"Negotiated TLS Version: {proto_ver}",
                    "Server eskirgan TLSv1.0/TLSv1.1 yoki SSL protokolini qo'llab-quvvatlamoqda.",
                    "Faqat TLSv1.2 va TLSv1.3 protokollarini qoldiring (`ssl_protocols TLSv1.2 TLSv1.3;`).",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
            acao = hdrs.get("access-control-allow-origin", "")
            vary = hdrs.get("vary", "")
            if acao and acao != "*" and "origin" not in vary.lower():
                self.db.upsert_finding(
                    project_id, "Agent-2 (Cache-Audit)", "Dynamic CORS Header Without 'Vary: Origin' Cache Isolation",
                    "Cache & CORS Misconfiguration", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    "CWE-525", "A05:2021 - Security Misconfiguration", url,
                    f"Access-Control-Allow-Origin: {acao} | Vary: {vary or '(missing)'}",
                    "Dinamik ACAO sarlavhasi qaytarilganda 'Vary: Origin' ko'rsatilmagan — kesh noto'g'ri Origin javobini saqlab qolishi mumkin.",
                    "Dinamik CORS javoblariga har doim 'Vary: Origin' sarlavhasini qo'shing.",
                    confidence=QoD.HEADER_CONFIG,
                )



    def _audit_endpoints_and_js(self, project_id: int, endpoints: list[dict], js_assets: list[dict], log_fn):
        import urllib.parse

        idor_by_host: dict[str, list[str]] = {}
        ssrf_by_host: dict[str, list[str]] = {}
        biz_by_host: dict[str, list[str]] = {}

        for ep in endpoints:
            tags = json.loads(ep.get("risk_tags_json") or "[]")
            params = json.loads(ep.get("params_json") or "[]")
            url = ep["url"]
            host = urllib.parse.urlparse(url).hostname or url
            entry_str = f"[{ep['method']}] {url}" + (f" (params: {', '.join(params[:5])})" if params else "")
            if "IDOR_Candidate" in tags:
                idor_by_host.setdefault(host, []).append(entry_str)
            if "SSRF_or_Redirect_Candidate" in tags:
                ssrf_by_host.setdefault(host, []).append(entry_str)
            if "Business_Logic_Candidate" in tags:
                biz_by_host.setdefault(host, []).append(entry_str)

        for host, routes in idor_by_host.items():
            self.db.upsert_finding(
                project_id, "Agent-2 (ManualTestGuide)", f"High-Priority IDOR / BOLA Testing Points ({len(routes)} routes on {host})",
                "Access Control (Manual Verification)", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "CWE-639", "A01:2021 - Broken Access Control", host,
                " | ".join(routes[:10]),
                "Ushbu endpointlar obyekt identifikatorini qabul qiladi — avtorizatsiya tekshiruvi yo'qligi IDOR/BOLA ga olib kelishi mumkin.",
                "Har bir so'rovda foydalanuvchining obyektga egalik huquqini server tomonida tekshiring.",
                confidence="Manual-Review",
            )
        for host, routes in ssrf_by_host.items():
            self.db.upsert_finding(
                project_id, "Agent-2 (ManualTestGuide)", f"SSRF / Open Redirect Candidate Parameters ({len(routes)} routes on {host})",
                "SSRF / Redirect (Manual Verification)", "High", 7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
                "CWE-918", "A10:2021 - Server-Side Request Forgery", host,
                " | ".join(routes[:10]),
                "Tashqi manzil yoki yo'naltirish qabul qiluvchi parametrlar aniqlandi.",
                "URL manzillarini oq ro'yxat asosida tekshiring va ichki IP diapazonlarini bloklang.",
                confidence="Manual-Review",
            )
        for host, routes in biz_by_host.items():
            self.db.upsert_finding(
                project_id, "Agent-2 (ManualTestGuide)", f"Business Logic / Mass Assignment Testing Points ({len(routes)} routes on {host})",
                "Business Logic (Manual Verification)", "Medium", 6.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                "CWE-840", "A04:2021 - Insecure Design", host,
                " | ".join(routes[:10]),
                "Narx, miqdor, chegirma yoki foydalanuvchi roli bilan bog'liq parametrlar aniqlandi.",
                "Moliya va rolga oid qiymatlarni mijoz so'rovidan emas, faqat server bazasidan hisoblang.",
                confidence="Manual-Review",
            )

        for js in js_assets:
            sinks = json.loads(js.get("sinks_json") or "[]")
            secrets = json.loads(js.get("secrets_hints_json") or "[]")
            if sinks:
                self.db.upsert_finding(
                    project_id, "Agent-2 (JS-Auditor)", f"DOM XSS Sink in {js['js_url'].split('/')[-1]}",
                    "Cross-Site Scripting (DOM Review)", "Medium", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "CWE-79", "A03:2021 - Injection", js["js_url"],
                    f"Topilgan xavfli DOM sinklar: {', '.join(sinks)}",
                    "JavaScript faylda ma'lumotlarni DOM ga xavfsiz tozalashsiz yozishi mumkin bo'lgan metodlar ishlatilgan.",
                    "innerHTML/document.write o'rniga textContent ishlating yoki DOMPurify orqali sanitizatsiya qiling.",
                )
            if secrets:
                self.db.upsert_finding(
                    project_id, "Agent-2 (JS-Auditor)", f"Sensitive Config / API Key Pattern in {js['js_url'].split('/')[-1]}",
                    "Sensitive Data Exposure in JS", "Medium", 5.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "CWE-312", "A02:2021 - Cryptographic Failures", js["js_url"],
                    f"Topilgan kalit/konfiguratsiya satrlari: {', '.join(secrets[:5])}",
                    "Mijozga yuklanadigan JS bundle ichida API baseURL, token yoki konfiguratsiya kalitlari aniqlandi.",
                    "JS bundle ichida maxfiy tokenlar yo'qligini tekshiring va ularni backend proksi orqali yashiring.",
                )


    def _run_sast_scan(self, project_id: int, code_path_str: str, log_fn):
        if not code_path_str:
            return
        root = Path(code_path_str)
        if not root.exists():
            log_fn(f"  [!] SAST: Ko'rsatilgan kod papkasi topilmadi ({code_path_str})")
            return
        log_fn(f"[SAST] White-box Source Code tahlili boshlandi: {root}")
        exts = {".py", ".php", ".js", ".ts", ".tsx", ".jsx", ".vue", ".go", ".java", ".rb", ".env"}
        files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts and "node_modules" not in str(p) and ".git" not in str(p)]
        hits = 0
        for fpath in files[:150]:
            try:
                lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                for idx, line in enumerate(lines, start=1):
                    s_line = line.strip()
                    if not s_line or len(s_line) > 900 or s_line.startswith(("//", "#", "/*", "*")):
                        continue
                    for rule in self.SAST_RULES:
                        if rule["pattern"].search(line):
                            self.db.upsert_finding(
                                project_id, "Agent-2 (WhiteBox-SAST)", rule["title"],
                                rule["category"], rule["severity"], rule["cvss"], rule["vector"],
                                rule["cwe"], rule["owasp"], f"{fpath}:{idx}",
                                f"Line {idx}: {line.strip()[:160]}",
                                f"Kodning {idx}-qatorida xavfli konstruksiya aniqlandi.",
                                rule["remediation"],
                                confidence=QoD.STATIC_SAST,
                            )
                            hits += 1
            except Exception:
                pass
        log_fn(f"  [+] SAST yakunlandi: {len(files[:150])} ta fayl tekshirildi, {hits} ta xavfli qator topildi.")

    def _audit_http_methods_and_overrides(self, project_id: int, http_services: list[dict], log_fn):
        for svc in http_services[:10]:
            url = svc["url"]
            if self.http_engine.is_host_dead(url):
                continue
            try:
                r_opt = self.http_engine.request("OPTIONS", url, allow_redirects=False)
                allow_hdr = (r_opt.headers.get("Allow") or r_opt.headers.get("Public") or "").upper()
                allowed_set = {x.strip() for x in allow_hdr.split(",") if x.strip()}
                risky = [m for m in ("PUT", "DELETE", "TRACE") if m in allowed_set]
                if risky:
                    self.db.upsert_finding(
                        project_id, "Agent-2 (Method-Audit)", f"Unsafe HTTP Methods Advertised ({', '.join(risky)})",
                        "HTTP Protocol Configuration", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        "CWE-749", "A05:2021 - Security Misconfiguration", url,
                        f"OPTIONS Allow Header: {allow_hdr}",
                        "Veb-server root yo'lida xavfli HTTP metodlar (PUT/DELETE/TRACE) ruxsat etilgan sifatida e'lon qilingan.",
                        "Veb-serverda keraksiz PUT, DELETE va TRACE metodlarini o'chiring.",
                    )
            except Exception:
                pass

    def _audit_safe_differential_verifiers(self, project_id: int, endpoints: list[dict], log_fn):
        redir_params = {"url", "redirect", "redirect_uri", "next", "return", "returnurl", "return_to", "goto", "dest", "destination"}
        canary = "spectrecheck9182"
        for ep in endpoints[:35]:
            u = ep["url"]
            if self.http_engine.is_host_dead(u):
                continue
            params = json.loads(ep.get("params_json") or "[]")
            if not params:
                continue
            p_parsed = urllib.parse.urlparse(u)
            for p_name in params[:2]:
                qs = urllib.parse.parse_qs(p_parsed.query, keep_blank_values=True)
                if p_name.lower() in redir_params:
                    qs[p_name] = ["https://example.org/spectre_check"]
                    test_u = urllib.parse.urlunparse(p_parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
                    try:
                        r = self.http_engine.request("GET", test_u, headers=self.role_a_headers or None, allow_redirects=False)
                        loc = r.headers.get("Location", "")
                        if r.status_code in (301, 302, 303, 307, 308) and urllib.parse.urlparse(loc).hostname == "example.org":
                            self.db.upsert_finding(
                                project_id, "Agent-2 (Differential-Verifier)", f"[CONFIRMED] Verified Open Redirect via '{p_name}' Parameter",
                                "Open Redirect (Validated PoC)", "Medium", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                "CWE-601", "A01:2021 - Broken Access Control", u,
                                f"Parameter: {p_name} -> HTTP {r.status_code} Location: {loc}",
                                f"'{p_name}' parametri tashqi domenga tekshiruvsiz yo'naltirishi tasdiqlandi.",
                                "Yo'naltirish parametrlarini qat'iy ichki yo'llar oq ro'yxati bilan cheklang.",
                                confidence=QoD.ACTIVE_VERIFIED,
                            )
                            log_fn(f"  [CONFIRMED REDIRECT] {u} ({p_name}) -> {loc}")
                    except Exception:
                        pass
                else:
                    qs[p_name] = [canary]
                    test_u = urllib.parse.urlunparse(p_parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
                    try:
                        r = self.http_engine.request("GET", test_u, headers=self.role_a_headers or None, allow_redirects=False)
                        if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "").lower() and canary in r.text:
                            self.db.upsert_finding(
                                project_id, "Agent-2 (Differential-Verifier)", f"Unfiltered HTML Parameter Reflection ('{p_name}')",
                                "Input Reflection / XSS Candidate", "Medium", 5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                "CWE-79", "A03:2021 - Injection", u,
                                f"Alphanumeric canary '{canary}' reflected verbatim in text/html response via '{p_name}'.",
                                "Foydalanuvchi parametri HTML sahifa tanasida aks etmoqda — kontekstli encoding tekshiruvi zarur.",
                                "HTML/JS kontekstida chiqish ma'lumotlarini kontekstli kodlang va CSP o'rnating.",
                            )
                    except Exception:
                        pass

    def _audit_multi_role_access_control(self, project_id: int, endpoints: list[dict], log_fn):
        if not self.role_a_headers:
            return
        api_cands = [
            e for e in endpoints
            if e.get("method", "GET") == "GET"
            and (e.get("category") in ("api_endpoint", "high_value_endpoint") or "IDOR_Candidate" in (e.get("risk_tags_json") or ""))
        ][:16]
        if not api_cands:
            return
        log_fn(f"[Agent-2 -> Multi-Role Authz Matrix] {len(api_cands)} ta API/IDOR route da avtorizatsiya matritsasi solishtirilmoqda...")
        err_markers = ('"unauthorized"', '"unauthenticated"', '"forbidden"', '"access denied"', '"error":true', '"status":401', '"status":403')
        public_ignore = ("/health", "/ping", "/version", "/config", "/public", "/openapi", "/swagger", "/i18n", "/locale")

        for ep in api_cands:
            u = ep["url"].replace("{param}", "1")
            if any(pi in u.lower() for pi in public_ignore) or self.http_engine.is_host_dead(u):
                continue
            try:
                r_a = self.http_engine.request("GET", u, headers=self.role_a_headers, allow_redirects=False)
                if r_a.status_code != 200 or "application/json" not in r_a.headers.get("Content-Type", "").lower() or len(r_a.text) < 25:
                    continue
                if any(em in r_a.text.lower() for em in err_markers):
                    continue
                obj_a = r_a.json()
                keys_a = sorted(obj_a.keys()) if isinstance(obj_a, dict) else ["_list"]

                r_guest = self.http_engine.request("GET", u, headers={}, allow_redirects=False)
                if r_guest.status_code == 200 and "application/json" in r_guest.headers.get("Content-Type", "").lower():
                    if abs(len(r_guest.text) - len(r_a.text)) < 40 and not any(em in r_guest.text.lower() for em in err_markers):
                        if any(priv_k in u.lower() for priv_k in ("/admin", "/internal", "/users", "/account", "/orders", "/profile", "/me")):
                            self.db.upsert_finding(
                                project_id, "Agent-2 (Authz-Matrix)", f"[CONFIRMED] Unauthenticated Access to Sensitive API Route ({u})",
                                "Missing Function-Level Access Control", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "CWE-306", "A01:2021 - Broken Access Control", u,
                                f"Role-A HTTP 200 ({len(r_a.text)}B, keys={keys_a[:6]}) == Guest HTTP 200 ({len(r_guest.text)}B)",
                                "Sezgir API yo'li avtorizatsiya sarlavhasisiz (Guest) ham Role-A bilan bir xil JSON ma'lumot qaytarmoqda.",
                                "Ushbu route ustiga autentifikatsiya va rol tekshiruvi (RBAC middleware) o'rnating.",
                                confidence=QoD.ACTIVE_VERIFIED,
                            )
                            log_fn(f"  [CONFIRMED AUTHZ BYPASS] {u} -> Guest == Role-A (HTTP 200 JSON)")
                            continue

                if self.role_b_headers and r_guest.status_code in (401, 403):
                    r_b = self.http_engine.request("GET", u, headers=self.role_b_headers, allow_redirects=False)
                    if r_b.status_code == 200 and "application/json" in r_b.headers.get("Content-Type", "").lower() and not any(em in r_b.text.lower() for em in err_markers):
                        obj_b = r_b.json()
                        keys_b = sorted(obj_b.keys()) if isinstance(obj_b, dict) else ["_list"]
                        if keys_a == keys_b and ("IDOR_Candidate" in (ep.get("risk_tags_json") or "") or any(ch.isdigit() for ch in urllib.parse.urlparse(u).path)):
                            self.db.upsert_finding(
                                project_id, "Agent-2 (BOLA-Matrix)", f"[CONFIRMED] Cross-Role BOLA / IDOR Data Exposure ({u})",
                                "Broken Object Level Authorization (BOLA)", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                "CWE-639", "A01:2021 - Broken Access Control", u,
                                f"Guest={r_guest.status_code} | Role-A=200 ({len(r_a.text)}B) | Role-B=200 ({len(r_b.text)}B, keys={keys_b[:6]})",
                                "Guest uchun yopiq (401/403) bo'lgan obyekt endpointi ikkinchi foydalanuvchi (Role-B) sessiyasi orqali ham bir xil JSON strukturani qaytarmoqda.",
                                "Backendda obyekt egasini joriy foydalanuvchi identifikatori bilan qat'iy solishtiring.",
                                confidence=QoD.ACTIVE_VERIFIED,
                            )
                            log_fn(f"  [CONFIRMED BOLA] {u} -> Guest {r_guest.status_code}, lekin Role-B 200 JSON oldi!")
            except Exception:
                pass

    def _run_cli_vuln_scanners(self, project_id: int, bundle: dict, log_fn, enable_cli: bool = True):
        if not enable_cli:
            return
        env = os.environ.copy()
        env["PATH"] = "/home/amaqi/go/bin:/home/amaqi/.local/bin:/usr/local/bin:/usr/bin:" + env.get("PATH", "")
        nuc_bin = shutil.which("nuclei", path=env["PATH"])
        svcs = [
            s["url"] for s in bundle.get("http_services", [])
            if int(s.get("status_code") or 0) in (200, 401, 403) and not self.http_engine.is_host_dead(s["url"])
            and urllib.parse.urlparse(s["url"]).hostname not in ("127.0.0.1", "localhost")
        ][:6]
        if nuc_bin and svcs:
            nuc_file = f"/tmp/spectre_v13_nuclei_{project_id}.txt"
            Path(nuc_file).write_text("\n".join(svcs) + "\n", encoding="utf-8")
            log_fn(f"[Agent-2 -> Nuclei Audit] {len(svcs)} ta faol veb-servisda miskonfiguratsiya va CVE shablonlari tekshirilmoqda...")
            try:
                proc = subprocess.run(
                    [nuc_bin, "-l", nuc_file, "-tags", "exposure,misconfig,panel,token", "-severity", "low,medium,high,critical", "-silent", "-jsonl", "-timeout", "4", "-c", "20"],
                    capture_output=True, text=True, timeout=45, env=env,
                )
                for nl in (proc.stdout or "").splitlines():
                    if nl.strip().startswith("{"):
                        nobj = json.loads(nl.strip())
                        t_id = nobj.get("template-id", "nuclei-hit")
                        info = nobj.get("info", {})
                        n_name = info.get("name", t_id)
                        n_sev = str(info.get("severity", "medium")).capitalize()
                        matched_at = nobj.get("matched-at", svcs[0])
                        cvss_map = {"Critical": 9.3, "High": 8.1, "Medium": 6.1, "Low": 3.7}
                        if n_sev in cvss_map:
                            self.db.upsert_finding(
                                project_id, "Agent-2 (Nuclei)", f"[CONFIRMED] Nuclei: {n_name} ({t_id})",
                                "Nuclei Template Verification", n_sev, cvss_map[n_sev], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                                "CWE-200", "A05:2021 - Security Misconfiguration", matched_at,
                                f"Template: {t_id} | Matched: {matched_at}",
                                info.get("description") or f"Nuclei '{t_id}' shabloni bo'yicha zaiflik tasdiqlandi.",
                                info.get("remediation") or "Nuclei tavsiyasiga asosan konfiguratsiya kamchiligini bartaraf eting.",
                                confidence="Confirmed-PoC",
                            )
                            log_fn(f"  [NUCLEI HIT] [{n_sev}] {n_name} -> {matched_at}")
                self.db.log_task(project_id, "SPECTRE-Agent2", "nuclei", "COMPLETED", f"nuclei ({len(svcs)} targets)", "Completed active template verification")
            except Exception:
                pass

    def run_assessment(self, project_id: int, log_fn, enable_cli: bool = True):
        bundle = self.db.get_project_bundle(project_id)
        proj = bundle.get("project", {})
        if not proj:
            log_fn("[ERR] Loyiha topilmadi.")
            return
        self.http_engine.reset()
        self.db.update_project_status(project_id, "RUNNING_VULN_AUDIT")

        kb = ScanContextKB(project_id, str(proj.get("primary_target", "")))
        kb.hydrate_from_bundle(bundle, has_auth_a=bool(self.role_a_headers), has_auth_b=bool(self.role_b_headers))

        log_fn(f"═══ 2-SUPERAGENT (v14.0 NASL-TITAN): KB-GATED CVE, POSTURE & BOLA AUDIT ({proj['name']}) ═══")
        http_svcs = bundle.get("http_services", [])
        ports = bundle.get("ports", [])
        eps = bundle.get("endpoints", [])
        js_list = bundle.get("js_assets", [])

        run_plugin_safely(self.db, project_id, "nvt_http_headers_cors", self._audit_http_services, project_id, http_svcs, log_fn, log_fn=log_fn, kb=kb, require_keys=["Services/www"], phase=ScanPhase.ACT_GATHER_INFO)
        run_plugin_safely(self.db, project_id, "nvt_tls_cache_posture", self._audit_tls_and_cache_posture, project_id, http_svcs, log_fn, log_fn=log_fn, kb=kb, require_keys=["Services/www"], phase=ScanPhase.ACT_GATHER_INFO)
        run_plugin_safely(self.db, project_id, "nvt_http_methods", self._audit_http_methods_and_overrides, project_id, http_svcs, log_fn, log_fn=log_fn, kb=kb, require_keys=["Services/www"], phase=ScanPhase.ACT_VERIFY)
        run_plugin_safely(self.db, project_id, "nvt_network_ports", self._audit_open_ports, project_id, ports, log_fn, log_fn=log_fn, kb=kb, require_keys=["Ports/tcp"], phase=ScanPhase.ACT_GATHER_INFO)
        run_plugin_safely(self.db, project_id, "nvt_semantic_cve_engine", self._audit_version_cve_advisories, project_id, http_svcs, ports, log_fn, log_fn=log_fn, kb=kb, phase=ScanPhase.ACT_GATHER_INFO)
        run_plugin_safely(self.db, project_id, "nvt_endpoints_js_sinks", self._audit_endpoints_and_js, project_id, eps, js_list, log_fn, log_fn=log_fn, kb=kb, phase=ScanPhase.ACT_GATHER_INFO)
        run_plugin_safely(self.db, project_id, "nvt_multi_role_bola", self._audit_multi_role_access_control, project_id, eps, log_fn, log_fn=log_fn, kb=kb, require_keys=["Auth/role_a", "Endpoints/api"], phase=ScanPhase.ACT_VERIFY)
        run_plugin_safely(self.db, project_id, "nvt_differential_verifier", self._audit_safe_differential_verifiers, project_id, eps, log_fn, log_fn=log_fn, kb=kb, require_keys=["Endpoints/parameterized"], phase=ScanPhase.ACT_VERIFY)
        run_plugin_safely(self.db, project_id, "nvt_cli_scanners", self._run_cli_vuln_scanners, project_id, bundle, log_fn, enable_cli=enable_cli, log_fn=log_fn, kb=kb, phase=ScanPhase.ACT_VERIFY)

        if proj.get("source_code_path"):
            run_plugin_safely(self.db, project_id, "nvt_whitebox_sast", self._run_sast_scan, project_id, proj["source_code_path"], log_fn, log_fn=log_fn, kb=kb, require_keys=["Source/local_path"], phase=ScanPhase.ACT_GATHER_INFO)
        smap_dir = Path(__file__).resolve().parent.parent / "workspaces" / "sourcemaps" / f"project_{project_id}"
        if smap_dir.is_dir() and any(smap_dir.rglob("*")):
            log_fn(f"  [SOURCEMAP->SAST] 1-SuperAgent tiklagan asl manba kodlari ({smap_dir.name}) White-Box SAST orqali tekshirilmoqda...")
            self._run_sast_scan(project_id, str(smap_dir), log_fn)

        log_fn(f"  [KB-GATEKEEPER] Executed Plugins: {kb.executed_plugins} | Skipped by KB Gate (0 ms): {kb.skipped_plugins}")
        self.db.update_project_status(project_id, "VULN_AUDIT_COMPLETED")
        log_fn("═══ 2-SUPERAGENT: ZAIFLIKLAR VA AVTORIZATSIYA TAHLILI YAKUNLANDI ═══")



