import base64
import json
import re
from pathlib import Path
import requests

from core.database import DatabaseManager


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
    ]

    def __init__(self, db: DatabaseManager):
        self.db = db

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

            # Active Dynamic Origin Reflection & HTTP Methods Probe on top services
            try:
                r_cors = requests.get(url, headers={"Origin": "https://evil.spectre-audit.org", "User-Agent": "SPECTRE-VulnAgent/8.5"}, timeout=4.0, verify=False, allow_redirects=False)
                ref_acao = r_cors.headers.get("Access-Control-Allow-Origin", "")
                ref_acac = r_cors.headers.get("Access-Control-Allow-Credentials", "").lower()
                if ref_acao == "https://evil.spectre-audit.org":
                    sev_c = "Critical" if ref_acac == "true" else "Medium"
                    cvss_c = 8.8 if ref_acac == "true" else 5.3
                    self.db.upsert_finding(
                        project_id, "Agent-2 (Active-CORS)", f"[CONFIRMED] Arbitrary CORS Origin Reflection ({url})",
                        "CORS Origin Reflection", sev_c, cvss_c, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                        "CWE-942", "A05:2021 - Security Misconfiguration", url,
                        f"Sent Origin: https://evil.spectre-audit.org -> Reflected ACAO: {ref_acao} | ACAC: {ref_acac}",
                        "Server har qanday tashqi Origin sarlavhasini Access-Control-Allow-Origin ichida aks ettirmoqda.",
                        "Origin sarlavhasini avtomatik aks ettirmang; qat'iy oq ro'yxat (allowlist) tekshiruvini o'rnating.",
                        confidence="Confirmed-PoC",
                    )
            except Exception:
                pass

            missing_headers = [
                h for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")
                if not sec.get(h)
            ]
            if missing_headers:
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

            # Active Safe CORS Origin Reflection Test
            try:
                test_origin = "https://evil-cors-audit.example.com"
                r_cors = requests.get(url, headers={"Origin": test_origin, "User-Agent": "APEX-ASM-Audit/2.0"}, timeout=6, verify=False)
                ref_acao = r_cors.headers.get("Access-Control-Allow-Origin", "")
                ref_acac = r_cors.headers.get("Access-Control-Allow-Credentials", "").lower()
                if ref_acao == test_origin:
                    sev = "High" if ref_acac == "true" else "Medium"
                    score = 8.3 if ref_acac == "true" else 5.3
                    self.db.upsert_finding(
                        project_id, "Agent-2 (Active-CORS)", "Arbitrary CORS Origin Reflection Detected",
                        "CORS Misconfiguration", sev, score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                        "CWE-942", "A05:2021 - Security Misconfiguration", url,
                        f"Sent Origin: {test_origin} -> Reflected ACAO: {ref_acao} | ACAC: {ref_acac}",
                        "Server tashqaridan yuborilgan ixtiyoriy Origin headerini tekshirmasdan Access-Control-Allow-Origin da aks ettirmoqda.",
                        "Origin headerini dinamik aks ettirish o'rniga qat'iy tasdiqlangan domenlar ro'yxati bilan solishtiring.",
                    )
            except Exception:
                pass
        log_fn(f"  [+] {len(http_services)} ta HTTP servis, Server versiyalari va Active CORS Reflection tekshirildi.")

    def _audit_open_ports(self, project_id: int, ports: list[dict], log_fn):
        for pt in ports:
            pnum = int(pt.get("port", 0))
            host = pt.get("host", "")
            svc = pt.get("service", "")
            ver = pt.get("version", "")
            if pnum == 22:
                self.db.upsert_finding(
                    project_id, "Agent-2 (NetworkAudit)", f"Publicly Exposed SSH Service ({host}:22)",
                    "Network Exposure", "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{host}:22",
                    f"Port 22/tcp open | Service: {svc} {ver}",
                    "SSH boshqaruv porti tashqi internet uchun ochiq qoldirilgan.",
                    "SSH portini faqat VPN yoki ma'lum ma'muriy IP manzillar (Firewall allowlist) uchun oching va PasswordAuthentication ni o'chiring.",
                )
            elif pnum in (21, 23, 137, 139, 445, 3306, 3389, 5432, 5900, 6379, 11211, 27017, 9200):
                self.db.upsert_finding(
                    project_id, "Agent-2 (NetworkAudit)", f"Exposed Critical Network Service / Port ({host}:{pnum})",
                    "Network Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{host}:{pnum}",
                    f"Port {pnum}/tcp open | Service: {svc} {ver}",
                    "SMB/FTP/DB/RDP kabi sezgir tarmoq porti tashqi internet uchun ochiq qoldirilgan.",
                    "Ushbu portni tashqi interfeysdan Firewall orqali yoping (faqat ichki VLAN yoki VPN orqali ruxsat bering).",
                )



    def _audit_endpoints_and_js(self, project_id: int, endpoints: list[dict], js_assets: list[dict], log_fn):
        for ep in endpoints:
            tags = json.loads(ep.get("risk_tags_json") or "[]")
            params = json.loads(ep.get("params_json") or "[]")
            url = ep["url"]
            if "IDOR_Candidate" in tags:
                self.db.upsert_finding(
                    project_id, "Agent-2 (ManualTestGuide)", "High-Priority IDOR / BOLA Testing Point",
                    "Access Control (Manual Verification)", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-639", "A01:2021 - Broken Access Control", url,
                    f"Method: {ep['method']} | Obyekt parametrlari: {', '.join(params)}",
                    "Endpoint obyekt identifikatorini qabul qiladi — avtorizatsiya tekshiruvi yo'qligi IDOR ga olib kelishi mumkin.",
                    "Har bir so'rovda foydalanuvchining obyektga egalik huquqini server tomonida tekshiring.",
                    confidence="Manual-Review",
                )
            if "SSRF_or_Redirect_Candidate" in tags:
                self.db.upsert_finding(
                    project_id, "Agent-2 (ManualTestGuide)", "SSRF / Open Redirect Candidate Parameter",
                    "SSRF / Redirect (Manual Verification)", "High", 7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
                    "CWE-918", "A10:2021 - Server-Side Request Forgery", url,
                    f"Method: {ep['method']} | URL/Redirect parametrlari: {', '.join(params)}",
                    "Tashqi manzil yoki yo'naltirish qabul qiluvchi parametr aniqlandi.",
                    "URL manzillarini oq ro'yxat asosida tekshiring va ichki IP diapazonlarini bloklang.",
                    confidence="Manual-Review",
                )
            if "Business_Logic_Candidate" in tags:
                self.db.upsert_finding(
                    project_id, "Agent-2 (ManualTestGuide)", "Business Logic / Mass Assignment Testing Point",
                    "Business Logic (Manual Verification)", "Medium", 6.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                    "CWE-840", "A04:2021 - Insecure Design", url,
                    f"Method: {ep['method']} | Biznes parametrlari: {', '.join(params)}",
                    "Narx, miqdor, chegirma yoki foydalanuvchi roli bilan bog'liq parametr aniqlandi.",
                    "Moliya va rolga oid qiymatlarni mijoz so'rovidan emas, faqat server bazasidan hisoblang.",
                    confidence="Manual-Review",
                )

        for js in js_assets:
            sinks = json.loads(js.get("sinks_json") or "[]")
            secrets = json.loads(js.get("secrets_hints_json") or "[]")
            eps = json.loads(js.get("endpoints_json") or "[]")
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
            if eps:
                self.db.upsert_finding(
                    project_id, "Agent-2 (JS-Auditor)", f"Extracted {len(eps)} Backend API / Stream Routes from {js['js_url'].split('/')[-1]}",
                    "API Attack Surface (Manual Verification)", "Low", 3.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-200", "A01:2021 - Broken Access Control", js["js_url"],
                    f"Routes: {', '.join(eps[:8])}",
                    "SPA JavaScript fayli ichidan backend API va media route'lar ajratib olindi.",
                    "Har bir API route'da autentifikatsiya va rate-limiting mavjudligini tekshiring.",
                    confidence="Manual-Review",
                )


    def _run_sast_scan(self, project_id: int, code_path_str: str, log_fn):
        if not code_path_str:
            return
        root = Path(code_path_str)
        if not root.exists():
            log_fn(f"  [!] SAST: Ko'rsatilgan kod papkasi topilmadi ({code_path_str})")
            return
        log_fn(f"[SAST] White-box Source Code tahlili boshlandi: {root}")
        exts = {".py", ".php", ".js", ".ts", ".go", ".java", ".rb", ".env"}
        files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts and "node_modules" not in str(p) and ".git" not in str(p)]
        hits = 0
        for fpath in files[:150]:
            try:
                lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                for idx, line in enumerate(lines, start=1):
                    for rule in self.SAST_RULES:
                        if rule["pattern"].search(line):
                            self.db.upsert_finding(
                                project_id, "Agent-2 (WhiteBox-SAST)", rule["title"],
                                rule["category"], rule["severity"], rule["cvss"], rule["vector"],
                                rule["cwe"], rule["owasp"], f"{fpath}:{idx}",
                                f"Line {idx}: {line.strip()[:160]}",
                                f"Kodning {idx}-qatorida xavfli konstruksiya aniqlandi.",
                                rule["remediation"],
                            )
                            hits += 1
            except Exception:
                pass
        log_fn(f"  [+] SAST yakunlandi: {len(files[:150])} ta fayl tekshirildi, {hits} ta xavfli qator topildi.")

    def run_assessment(self, project_id: int, log_fn):
        bundle = self.db.get_project_bundle(project_id)
        proj = bundle.get("project", {})
        if not proj:
            log_fn("[ERR] Loyiha topilmadi.")
            return
        self.db.update_project_status(project_id, "RUNNING_VULN_AUDIT")
        log_fn(f"═══ 🔍 2-SUPERAGENT: VULNERABILITY ASSESSMENT & SAST BOSHLANDI ({proj['name']}) ═══")
        self._audit_http_services(project_id, bundle.get("http_services", []), log_fn)
        self._audit_open_ports(project_id, bundle.get("ports", []), log_fn)
        self._audit_endpoints_and_js(project_id, bundle.get("endpoints", []), bundle.get("js_assets", []), log_fn)
        if proj.get("source_code_path"):
            self._run_sast_scan(project_id, proj["source_code_path"], log_fn)
        self.db.update_project_status(project_id, "VULN_AUDIT_COMPLETED")
        log_fn("═══ ✅ 2-SUPERAGENT: ZAIFLIKLAR TAHLILI YAKUNLANDI ═══")



