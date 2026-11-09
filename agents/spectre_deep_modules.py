import base64
import concurrent.futures
import hashlib
import hmac
import json
import re
import time
import urllib.parse
import warnings
from pathlib import Path
import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
urllib3_disable = getattr(requests.packages, "urllib3", None)
if urllib3_disable:
    urllib3_disable.disable_warnings()


# ================= #7 FAVICON MURMURHASH3 (SHODAN COMPATIBLE) =================
FAVICON_SIGNATURES = {
    116323821: "Spring Boot",
    81586312: "Jenkins",
    1278323681: "GitLab",
    1624375939: "Zimbra Web Client",
    1768726119: "Microsoft OWA (Exchange)",
    945408572: "FortiGate SSL VPN",
    -1293291541: "Plesk Panel",
    1485257654: "Roundcube Webmail",
    -305179312: "Grafana",
    708578229: "Bitrix CMS",
    -1581907337: "Keycloak SSO",
}


def murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x3

    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | ((data[i + 3] & 0xFF) << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    val = length & 0x3
    if val == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if val in (2, 3):
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if val in (1, 2, 3):
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def fingerprint_favicon(session, base_url: str, db, project_id: int, log_fn) -> tuple[int | None, str]:
    fav_url = urllib.parse.urljoin(base_url, "/favicon.ico")
    try:
        r = session.get(fav_url, timeout=6, verify=False)
        if r.status_code == 200 and len(r.content) > 40 and "text/html" not in r.headers.get("Content-Type", "").lower():
            b64_data = base64.encodebytes(r.content)
            f_hash = murmur3_32(b64_data)
            matched_tech = FAVICON_SIGNATURES.get(f_hash, "")
            log_fn(f"  [+] Favicon Hash ({base_url}): http.favicon.hash:{f_hash} {f'[{matched_tech}]' if matched_tech else ''}")
            if matched_tech:
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (Favicon)", f"Technology Identified via Favicon Hash: {matched_tech}",
                    "Technology Fingerprinting", "Low", 2.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", fav_url,
                    f"Shodan Query: http.favicon.hash:{f_hash} -> {matched_tech}",
                    "Favicon MurmurHash3 xeshi orqali serverdagi tizim aniqlandi.",
                    "Maxfiy admin panellarda standart favicon.ico faylini o'zgartiring.",
                )
            return f_hash, matched_tech
    except Exception:
        pass
    return None, ""


# ================= #1 NON-STANDARD WEB PORT PROBER =================
WEB_CANDIDATE_PORTS = {
    81, 3000, 4443, 5000, 5601, 7001, 8000, 8008, 8080, 8081,
    8083, 8086, 8087, 8088, 8443, 8888, 9000, 9001, 9080, 9090, 9200, 9443, 9999, 10000
}


def probe_nonstandard_web_ports(db, session, project_id: int, log_fn):
    ports = db.get_project_bundle(project_id).get("ports", [])
    targets = []
    seen = set()
    for pt in ports:
        pnum = int(pt.get("port", 0))
        host = pt.get("host") or pt.get("ip")
        if pnum in WEB_CANDIDATE_PORTS and host and (host, pnum) not in seen:
            seen.add((host, pnum))
            targets.append((host, pnum))

    if not targets:
        return
    log_fn(f"[SPECTRE Non-Standard Web Prober] {len(targets)} ta nostandart ochiq portda HTTP/HTTPS panellar tekshirilmoqda...")

    def check_port(item):
        host, pnum = item
        schemes = ("https", "http") if pnum in (4443, 8443, 9443, 10000) else ("http", "https")
        for sch in schemes:
            url = f"{sch}://{host}:{pnum}"
            try:
                r = session.get(url, timeout=(3.0, 3.5), verify=False, allow_redirects=True, stream=True)
                chunk = next(r.iter_content(chunk_size=24576), b"")
                r.close()
                text_sample = chunk.decode("utf-8", errors="ignore")
                soup = BeautifulSoup(text_sample, "html.parser")
                title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
                srv = r.headers.get("Server", "")
                db.upsert_http_service(
                    project_id, url, r.status_code, title=title[:120], server=srv,
                    tech_stack=[srv] if srv else ["Custom-Port-Web"],
                    content_length=len(chunk), priority_score=85, source=f"port_{pnum}_probe"
                )
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (PortWeb)", f"Exposed Web Interface on Non-Standard Port ({url})",
                    "Exposed Management / Web Port", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", url,
                    f"HTTP {r.status_code} | Title: '{title[:60]}' | Server: {srv} | Sample: {len(chunk)}B",
                    f"Nostandart {pnum}-portda ochiq HTTP/HTTPS servis yoki boshqaruv paneli aniqlandi.",
                    f"{pnum}-portni tashqi internetdan Firewall orqali yoping.",
                )
                log_fn(f"  [🔥 PORT-WEB] {url} -> HTTP {r.status_code} | Title: '{title[:45]}' | Server: {srv}")
                break
            except Exception:
                pass


    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(check_port, targets))


# ================= #2 VHOST & ORIGIN IP HUNTER =================
VHOST_PREFIXES = ["admin", "internal", "dev", "stage", "test", "api", "backend", "cp", "panel", "crm", "erp", "old", "git"]


def hunt_virtual_hosts(db, session, project_id: int, apex_domain: str, log_fn):
    domains = db.get_project_bundle(project_id).get("domains", [])
    existing_hosts = {d["domain"] for d in domains}
    unique_ips = sorted({d["ip"] for d in domains if d.get("ip") and not d.get("cdn_waf")})[:5]
    if not unique_ips:
        return

    log_fn(f"[SPECTRE VHost Hunter] {len(unique_ips)} ta asosiy IP serverda DNS'da yo'q yashirin VirtualHost'lar parallel tekshirilmoqda...")
    for ip in unique_ips:
        base_url = f"https://{ip}"
        try:
            r_base = session.get(base_url, headers={"Host": f"nonexistent-99182.{apex_domain}"}, timeout=3.5, verify=False, allow_redirects=False)
            base_status = r_base.status_code
            base_len = len(r_base.content)
        except Exception:
            continue

        def check_vhost(pref: str):
            cand_vhost = f"{pref}.{apex_domain}"
            if cand_vhost in existing_hosts:
                return
            try:
                r = session.get(base_url, headers={"Host": cand_vhost}, timeout=3.5, verify=False, allow_redirects=False)
                if r.status_code == 200 and (r.status_code != base_status or abs(len(r.content) - base_len) > 250):
                    soup = BeautifulSoup(r.text[:15000], "html.parser")
                    title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
                    db.upsert_domain(project_id, cand_vhost, ip=ip, source="vhost_fuzz")
                    db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (VHost)", f"Hidden VirtualHost Discovered ({cand_vhost} on {ip})",
                        "Hidden Infrastructure (VHost)", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "CWE-200", "A05:2021 - Security Misconfiguration", f"{ip} (Host: {cand_vhost})",
                        f"HTTP {r.status_code} | Len: {len(r.content)} (Baseline: {base_len}) | Title: {title[:50]}",
                        "Ommaviy DNS'da yo'q bo'lgan, lekin serverda sozlangan yashirin VirtualHost aniqlandi.",
                        "Ichki VirtualHost'larni faqat ichki IP interfeyslarida tinglaydigan qiling.",
                    )
                    log_fn(f"  [🚨 HIDDEN VHOST] {cand_vhost} @ {ip} -> HTTP {r.status_code} (Title: {title[:40]})")
            except Exception:
                pass

        ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        futs = [ex.submit(check_vhost, p) for p in VHOST_PREFIXES]
        concurrent.futures.wait(futs, timeout=6.0)
        ex.shutdown(wait=False, cancel_futures=True)


# ================= #4 CLOUD STORAGE, UPLOAD & OPEN DIRECTORY HUNTER =================
def hunt_cloud_and_storage_buckets(db, session, project_id: int, apex_domain: str, log_fn):
    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    storage_hosts = [
        d["domain"] for d in domains
        if any(k in d["domain"] for k in ("upload", "media", "static", "files", "s3", "minio", "vod", "content", "album", "cdn", "storage"))
    ][:8]

    tasks = [(shost, path) for shost in storage_hosts for path in ("/", "/uploads/", "/files/", "/media/")]
    if not tasks:
        return

    def check_storage(item):
        shost, path = item
        url = f"https://{shost}{path}"
        try:
            r = session.get(url, timeout=(2.5, 3.0), verify=False, stream=True)
            chunk = next(r.iter_content(chunk_size=16384), b"").decode("utf-8", errors="ignore")
            r.close()
            if r.status_code == 200 and any(sig in chunk for sig in ("Index of /", "<ListBucketResult", "Directory listing for", "<EnumerationResults")):
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (StorageHunter)", f"Open Directory / Bucket Listing ({url})",
                    "Storage / Bucket Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-548", "A05:2021 - Security Misconfiguration", url,
                    "Response contains open directory or S3/MinIO XML bucket listing.",
                    "Fayl yoki media serverda kataloglar ro'yxati (autoindex / public bucket list) ochiq qolgan.",
                    "Nginx da 'autoindex off;' qiling yoki S3/MinIO bucket Public List ruxsatini yoping.",
                )
                log_fn(f"  [🚨 BUCKET/DIR] Ochiq katalog aniqlandi: {url}")
        except Exception:
            pass

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    futs = [ex.submit(check_storage, t) for t in tasks]
    concurrent.futures.wait(futs, timeout=7.0)
    ex.shutdown(wait=False, cancel_futures=True)




# ================= #5 BADSECRETS (JWT/HMAC CRACKER) & CROSS-SUBDOMAIN COOKIE SCOPE =================
WEAK_SECRETS = [
    "secret", "123456", "12345678", "password", "admin", "jwt_secret", "changeme",
    "key", "supersecret", "laravel", "django", "secretkey", "mysecret", "test", "dev", "default"
]


def verify_jwt_weak_secret(token: str) -> str | None:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    sig = parts[2]
    for sec in WEAK_SECRETS:
        digest = hmac.new(sec.encode("utf-8"), signing_input, hashlib.sha256).digest()
        calc = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        if hmac.compare_digest(calc, sig):
            return sec
    return None


def analyze_badsecrets_and_cookies(db, project_id: int, apex_domain: str, log_fn):
    http_svcs = db.get_project_bundle(project_id).get("http_services", [])
    jwt_regex = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}")
    for svc in http_svcs:
        url = svc["url"]
        cookies = json.loads(svc.get("cookies_json") or "[]")
        headers_blob = svc.get("headers_json") or "{}"
        for ck in cookies:
            raw = ck.get("raw", "")
            if f"domain=.{apex_domain}" in raw.lower() or f"domain={apex_domain}" in raw.lower():
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (CookieScope)", f"Cross-Subdomain Wildcard Cookie Scope (.{apex_domain})",
                    "Session Management / Subdomain Risk", "Medium", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "CWE-565", "A07:2021 - Identification and Authentication Failures", url,
                    f"Cookie shared across all *.{apex_domain} subdomains: {raw[:140]}",
                    f"Cookie Domain=.{apex_domain} qilib belgilangani sababli barcha subdomenlarga yuboriladi.",
                    "Sessiya cookie'larida Domain atributini faqat aniq host uchun cheklang (HostOnly cookie).",
                )
                log_fn(f"  [!] Wildcard Cookie Scope (.{apex_domain}) aniqlandi: {url}")

        for cand_jwt in jwt_regex.findall(headers_blob):
            cracked = verify_jwt_weak_secret(cand_jwt)
            if cracked:
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (BadSecrets)", f"JWT Signed with Weak Default Secret ('{cracked}')",
                    "Cryptographic Failure (BadSecrets)", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CWE-798", "A02:2021 - Cryptographic Failures", url,
                    f"Cracked HMAC-SHA256 Secret: '{cracked}' | Token: {cand_jwt[:60]}...",
                    "JWT token ma'lum standart/zaif kalit bilan imzolangan — har qanday foydalanuvchi nomidan token yasash (Account Takeover) mumkin.",
                    "Kamida 256-bitli kriptografik tasodifiy kalit yoki RS256/ES256 asimmetrik kalit juftligidan foydalaning.",
                )
                log_fn(f"  [🚨 BADSECRETS] JWT zaif kaliti topildi ({url}): '{cracked}'!")



# ================= #8 CUSTOM WORDLIST & PARAMETER MINER =================
def build_custom_wordlist_and_params(db, project_id: int, apex_domain: str, log_fn) -> str:
    bundle = db.get_project_bundle(project_id)
    words = set()
    params = set()
    for d in bundle.get("domains", []):
        for part in d["domain"].replace("." + apex_domain, "").split("."):
            if len(part) > 2:
                words.add(part)
    for e in bundle.get("endpoints", []):
        parsed = urllib.parse.urlparse(e["url"])
        for seg in parsed.path.split("/"):
            clean_seg = re.sub(r"[^a-zA-Z0-9_\-]", "", seg)
            if 2 < len(clean_seg) < 32 and not clean_seg.isdigit():
                words.add(clean_seg)
        for p in json.loads(e.get("params_json") or "[]"):
            params.add(p)
    for j in bundle.get("js_assets", []):
        for p in json.loads(j.get("params_json") or "[]"):
            params.add(p)

    w_dir = Path("/home/amaqi/projects/apex-pentest-gui/workspaces")
    w_path = w_dir / f"project_{project_id}_custom_wordlist.txt"
    combined = sorted(words | params)
    w_path.write_text("\n".join(combined), encoding="utf-8")
    log_fn(f"[SPECTRE Wordlist Miner] Nishonga xos {len(combined)} ta unikal so'z va parametr lug'ati yaratildi: {w_path}")
    return str(w_path)


# ================= #9 CORPORATE EMAIL & OSINT HARVESTER =================
def harvest_emails_and_osint(db, project_id: int, apex_domain: str, text_blobs: list[str], log_fn):
    email_regex = re.compile(rf"[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+\.)*{re.escape(apex_domain)}", re.IGNORECASE)
    found_emails = set()
    for blob in text_blobs:
        for em in email_regex.findall(blob or ""):
            found_emails.add(em.lower())
    if found_emails:
        sorted_em = sorted(found_emails)
        db.upsert_finding(
            project_id, "SPECTRE-Agent1 (OSINT-Email)", f"Corporate Email Addresses Harvested ({len(sorted_em)} emails)",
            "OSINT / Reconnaissance", "Low", 2.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "CWE-200", "A05:2021 - Security Misconfiguration", apex_domain,
            f"Emails: {', '.join(sorted_em[:15])}",
            "Veb-sayt va JS kodlar ichidan tashkilotning korporativ elektron pochta manzillari yig'ildi.",
            "Korporativ pochta hisoblarida 2FA va SPF/DKIM/DMARC himoyasini kuchaytiring.",
        )
        log_fn(f"  [📧 OSINT EMAILS] {len(sorted_em)} ta korporativ email topildi: {', '.join(sorted_em[:6])}")


# ================= #3 INCREMENTAL DIFFING ENGINE (PERSISTENT SQLITE SNAPSHOTS) =================
def take_recon_snapshot(db, project_id: int) -> dict:
    prev = db.get_latest_snapshot(project_id) if hasattr(db, "get_latest_snapshot") else None
    if prev:
        return {
            "domains": set(json.loads(prev.get("domains_json") or "[]")),
            "ports": {tuple(x) for x in json.loads(prev.get("ports_json") or "[]")},
            "endpoints": set(json.loads(prev.get("endpoints_json") or "[]")),
            "from_db": True,
            "snapshot_date": prev.get("created_at", ""),
        }
    b = db.get_project_bundle(project_id)
    return {
        "domains": {d["domain"] for d in b.get("domains", [])},
        "ports": {(p["host"], p["port"]) for p in b.get("ports", [])},
        "endpoints": {e["url"] for e in b.get("endpoints", [])},
        "from_db": False,
        "snapshot_date": "Current Session",
    }


def log_incremental_diff(before: dict, db, project_id: int, log_fn):
    b = db.get_project_bundle(project_id)
    curr_doms = {d["domain"] for d in b.get("domains", [])}
    curr_ports = {(p["host"], p["port"]) for p in b.get("ports", [])}
    curr_eps = {e["url"] for e in b.get("endpoints", [])}

    new_doms = sorted(curr_doms - before["domains"])
    new_ports = sorted(curr_ports - before["ports"])
    new_eps = sorted(curr_eps - before["endpoints"])
    if new_doms or new_ports or new_eps:
        log_fn(f"[SPECTRE Persistent Diff vs {before.get('snapshot_date')}] 🆕 Yangi subdomenlar: +{len(new_doms)} | Yangi portlar: +{len(new_ports)} | Yangi endpointlar: +{len(new_eps)}")
        for nd in new_doms[:8]:
            log_fn(f"  [🆕 NEW SUBDOMAIN] {nd}")
        for nh, np in new_ports[:8]:
            log_fn(f"  [🆕 NEW PORT] {nh}:{np}")

    if hasattr(db, "save_scan_snapshot"):
        db.save_scan_snapshot(project_id, sorted(curr_doms), [list(x) for x in sorted(curr_ports)], sorted(curr_eps))



# ================= #10 PENTESTING TASK TREE (PTT) & TARGET DOSSIER =================
def build_target_dossier(db, project_id: int, selected_domain: str = "") -> str:
    b = db.get_project_bundle(project_id)
    domains = b.get("domains", [])
    ports = b.get("ports", [])
    https = b.get("http_services", [])
    findings = b.get("findings", [])
    endpoints = b.get("endpoints", [])

    if not selected_domain and domains:
        selected_domain = domains[0]["domain"]

    dom_obj = next((d for d in domains if d["domain"] == selected_domain), {})
    ip = dom_obj.get("ip", "")
    co_hosted = [d["domain"] for d in domains if d.get("ip") == ip and ip and d["domain"] != selected_domain]
    host_ports = [p for p in ports if p["host"] == selected_domain or (ip and p.get("ip") == ip)]
    host_https = [h for h in https if selected_domain in h["url"] or (ip and ip in h["url"])]
    host_finds = [f for f in findings if selected_domain in f["asset"] or (ip and ip in f["asset"])]

    lines = [
        f"╔══ 🎯 SPECTRE TARGET DOSSIER & PENTESTING TASK TREE (PTT): {selected_domain} ══╗",
        f"• IP Manzil: {ip or 'N/A'} | CNAME: {dom_obj.get('cname') or 'N/A'} | Manba: {dom_obj.get('source', '')}",
        f"• Shu IP dagi Qo'shni Subdomenlar (Co-Hosted VHosts - {len(co_hosted)} ta): {', '.join(co_hosted[:10]) or 'Yo`q'}",
        f"• DNS Yozuvlari: {dom_obj.get('records_json', '{}')}",
        "",
        f"── 🔌 OCHIQ PORTLAR VA SERVISLAR ({len(host_ports)} ta) ──",
    ]
    for p in host_ports:
        lines.append(f"  [{p['port']}/{p['protocol']}] {p['service']} | {p['version']} ({p['source']})")

    lines.append(f"\n── 🌐 FAOL HTTP/HTTPS PANELLAR ({len(host_https)} ta) ──")
    for h in host_https:
        lines.append(f"  [{h['status_code']}] {h['url']} — Title: '{h['title']}' | Server: {h['server']}")

    lines.append(f"\n── 🚨 ANIQLANGAN TOPILMALAR VA CVE'LAR ({len(host_finds)} ta) ──")
    for f in host_finds:
        lines.append(f"  [{f['severity']} | CVSS {f['cvss_score']}] {f['title']} -> {f['evidence'][:140]}")

    lines.append("\n── 🧠 PENTESTING TASK TREE (KEYINGI AMALIY QADAMLAR / PTT) ──")
    port_nums = {int(p["port"]) for p in host_ports}
    if 21 in port_nums:
        lines.append(f"  1. [FTP Port 21 Open] Anonymous FTP tekshiruvi: nmap -p 21 --script ftp-anon {ip or selected_domain}")
    if 445 in port_nums or 137 in port_nums:
        lines.append(f"  2. [SMB Port 445 Open] Null-session va ulashilgan papkalar: nxc smb {ip or selected_domain} -u '' -p '' --shares")
    if port_nums & WEB_CANDIDATE_PORTS:
        custom_p = sorted(port_nums & WEB_CANDIDATE_PORTS)
        lines.append(f"  3. [Custom Web Ports {custom_p}] Boshqaruv panellarini tekshirish: {', '.join(f'http://{selected_domain}:{cp}' for cp in custom_p)}")
    api_list = [e["url"] for e in endpoints if e.get("category") in ("api_endpoint", "high_value_endpoint")][:4]
    if api_list:
        lines.append(f"  4. [API BOLA/IDOR Audit] Burp Suite orqali tekshiriladigan API route'lar: {', '.join(api_list)}")
    lines.append(f"  5. [Custom Wordlist Fuzzing] ffuf -u https://{selected_domain}/FUZZ -w /home/amaqi/projects/apex-pentest-gui/workspaces/project_{project_id}_custom_wordlist.txt -mc 200,401,403")
    return "\n".join(lines)


# ================= #3 API VERSION SHADOW TWINS & WAYBACK GHOST PROBER =================
def probe_api_versions_and_ghost_endpoints(db, project_id: int, log_fn):
    bundle = db.get_project_bundle(project_id)
    endpoints = bundle.get("endpoints", [])

    versioned_eps = [e["url"] for e in endpoints if re.search(r"/v[1-3]/", e["url"])][:10]
    shadow_candidates = []
    for u in versioned_eps:
        for repl in ("/v0/", "/v1/", "/v2/", "/v3/", "/internal/", "/admin/"):
            mut_u = re.sub(r"/v[1-3]/", repl, u, count=1).replace("{param}", "1")
            if mut_u != u and mut_u not in shadow_candidates:
                shadow_candidates.append((mut_u, u))

    wayback_eps = [e["url"] for e in endpoints if e.get("source") == "wayback" and not e["url"].endswith(".js")][:15]
    if not shadow_candidates and not wayback_eps:
        return
    log_fn(f"[SPECTRE API Shadow & Ghost Prober] {len(shadow_candidates)} ta API versiya egizaklari va {len(wayback_eps)} ta tarixiy URL tekshirilmoqda...")

    # Calibrate each origin against a nonexistent /v999 path to filter out catch-all 401/403/200 API gateways
    host_cal: dict[str, tuple[int, int]] = {}
    for mut_u, _ in shadow_candidates:
        p_u = urllib.parse.urlparse(mut_u)
        origin = f"{p_u.scheme}://{p_u.netloc}"
        if origin and origin not in host_cal:
            try:
                rc = requests.get(f"{origin}/v999_nonexistent_spectre/check", headers={"User-Agent": "SPECTRE-Recon/11.2"}, timeout=3.0, verify=False, allow_redirects=False)
                host_cal[origin] = (rc.status_code, len(rc.content))
            except Exception:
                host_cal[origin] = (-1, -1)

    def check_shadow(item):
        mut_url, orig_url = item
        p_u = urllib.parse.urlparse(mut_url)
        origin = f"{p_u.scheme}://{p_u.netloc}"
        cal_stat, cal_len = host_cal.get(origin, (-1, -1))
        try:
            r = requests.get(mut_url, headers={"User-Agent": "SPECTRE-Recon/11.2"}, timeout=(2.5, 3.0), verify=False, allow_redirects=False, stream=True)
            chunk = next(r.iter_content(chunk_size=8192), b"").decode("utf-8", errors="ignore")
            r.close()
            if r.status_code == cal_stat and abs(len(chunk) - cal_len) < 40:
                return
            if r.status_code == 200 and len(chunk) > 20 and "text/html" not in r.headers.get("Content-Type", "").lower():
                low_c = chunk.lower()
                if '"not found"' in low_c or '"status":404' in low_c or '"status":401' in low_c:
                    return
                db.upsert_endpoint(project_id, mut_url, method="GET", category="api_endpoint", risk_tags=["API_Shadow_Twin"], status_code=r.status_code, source="shadow_twin")
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (ShadowAPI)", f"Active Shadow / Alternate API Version ({mut_url})",
                    "API Version Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "CWE-200", "A09:2021 - Security Logging and Monitoring Failures", mut_url,
                    f"HTTP {r.status_code} on alternate version of {orig_url} | Sample: {chunk[:100]}",
                    "API endpointning boshqa versiyasi (v0/v2/v3/internal) serverda faol holatda javob qaytarmoqda.",
                    "Eskirgan yoki test API versiyalarini production gateway darajasida o'chiring.",
                )
                log_fn(f"  [🧬 SHADOW API] {mut_url} -> HTTP {r.status_code}")
        except Exception:
            pass

    def check_ghost(wb_url: str):
        try:
            r = requests.get(wb_url, headers={"User-Agent": "SPECTRE-Recon/4.0"}, timeout=(2.5, 3.0), verify=False, allow_redirects=False, stream=True)
            r.close()
            if r.status_code in (200, 401, 403, 405):
                db.upsert_endpoint(project_id, wb_url, method="GET", category="high_value_endpoint", risk_tags=["Zombie_Ghost_Endpoint"], status_code=r.status_code, source="wayback_verified")
                log_fn(f"  [👻 GHOST ENDPOINT] Tarixiy URL hali ham tirik ({r.status_code}): {wb_url}")
        except Exception:
            pass

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    futs = [ex.submit(check_shadow, sc) for sc in shadow_candidates] + [ex.submit(check_ghost, wu) for wu in wayback_eps]
    concurrent.futures.wait(futs, timeout=7.0)
    ex.shutdown(wait=False, cancel_futures=True)


# ================= #5A & #6B AUTH PORTAL CLASSIFIER & MASS-ASSIGNMENT SCHEMA =================
DEFAULT_STUB_TITLES = ("welcome to nginx", "domain default page", "apache2 ubuntu default page", "404 not found", "403 forbidden")


def classify_auth_portals_and_schema(db, project_id: int, log_fn):
    bundle = db.get_project_bundle(project_id)
    for svc in bundle.get("http_services", []):
        u = svc["url"]
        t = (svc.get("title") or "").strip()
        t_low = t.lower()
        if any(stub in t_low for stub in DEFAULT_STUB_TITLES):
            continue
        if any(k in t_low for k in ("log in", "login", "sign in", "signin", "admin", "hosting", "panel", "auth", "sso")) or (
            any(k in u.lower() for k in ("login", "admin", "auth", "sso", ":8443")) and int(svc.get("status_code") or 0) == 200 and t
        ):
            db.upsert_finding(
                project_id, "SPECTRE-Agent1 (AuthPortal)", f"Authentication / Login Portal Identified ({u})",
                "Entry Point / Auth Surface", "Low", 3.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-287", "A07:2021 - Identification and Authentication Failures", u,
                f"URL: {u} | Title: '{t}' | Server: {svc.get('server')}",
                "Tashkilotning haqiqiy kirish / boshqaruv portali aniqlandi (2FA, Rate-limit va Default Creds tekshiruvi uchun asosiy nuqta).",
                "Barcha kirish portallarida MFA/2FA, Rate-Limiting va CAPTCHA himoyasini yoqing.",
            )
            log_fn(f"  [🚪 AUTH PORTAL] Kirish darvozasi tasniflandi: {u} ('{t}')")


    priv_keys = set()
    priv_patterns = ("role", "admin", "is_admin", "isadmin", "permission", "priv", "balance", "status", "verified", "org", "tenant", "group", "type", "level", "access")
    for js in bundle.get("js_assets", []):
        for p in json.loads(js.get("params_json") or "[]"):
            if any(pk in p.lower() for pk in priv_patterns):
                priv_keys.add(p)
    if priv_keys:
        sorted_pk = sorted(priv_keys)
        db.upsert_finding(
            project_id, "SPECTRE-Agent1 (SchemaMiner)", f"Reconstructed Privileged / Mass-Assignment Parameters ({len(sorted_pk)} keys)",
            "Mass Assignment / Data Schema (Manual Guide)", "Medium", 6.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
            "CWE-915", "A04:2021 - Insecure Design", bundle.get("project", {}).get("primary_target", ""),
            f"Candidate Mass-Assignment JSON Keys: {', '.join(sorted_pk[:20])}",
            "JS bundle fayllaridan foydalanuvchi huquqi, holati yoki tashkilotga oid JSON parametr nomlari tiklandi.",
            "POST/PUT/PATCH so'rovlarida DTO / White-list schema validatsiyasini qo'llang.",
            confidence="Manual-Review",
        )
        log_fn(f"  [🧩 SCHEMA MINER] Mass-Assignment uchun {len(sorted_pk)} ta imtiyozli parametr tiklandi: {', '.join(sorted_pk[:10])}")





