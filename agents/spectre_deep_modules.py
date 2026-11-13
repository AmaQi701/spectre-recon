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
    81, 1500, 1501, 2083, 2087, 3000, 4443, 5000, 5601, 7001, 8000, 8006, 8008, 8080, 8081,
    8083, 8086, 8087, 8088, 8090, 8181, 8443, 8444, 8880, 8888, 9000, 9001, 9080, 9090, 9200, 9443, 9999, 10000
}


def probe_nonstandard_web_ports(db, session, project_id: int, log_fn):
    ports = db.get_project_bundle(project_id).get("ports", [])
    targets = []
    seen_ip_port = set()
    for pt in ports:
        pnum = int(pt.get("port", 0))
        host = (pt.get("host") or pt.get("ip") or "").strip()
        ip_key = (pt.get("ip") or host).strip()
        if pnum in WEB_CANDIDATE_PORTS and host and (ip_key, pnum) not in seen_ip_port:
            seen_ip_port.add((ip_key, pnum))
            targets.append((host, pnum))

    if not targets:
        return
    log_fn(f"[SPECTRE Non-Standard Web Prober] {len(targets)} ta nostandart ochiq portda HTTP/HTTPS panellar tekshirilmoqda...")

    def check_port(item):
        host, pnum = item
        schemes = ("https", "http") if pnum in (1500, 2083, 2087, 4443, 8006, 8443, 8444, 9443, 10000) else ("http", "https")
        for sch in schemes:
            url = f"{sch}://{host}:{pnum}"
            try:
                r = session.get(url, timeout=(3.0, 3.5), verify=False, allow_redirects=False)
                code = r.status_code
                text_sample = (r.text or "")[:24576]
                if code == 400 and "plain http request was sent to https port" in text_sample.lower():
                    continue
                if code in (301, 302, 307, 308):
                    loc = r.headers.get("Location", "")
                    if loc.startswith(("http://", "https://")) and f":{pnum}" not in loc:
                        continue
                if code not in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405):
                    continue
                soup = BeautifulSoup(text_sample, "html.parser")
                title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
                srv = r.headers.get("Server", "")
                t_low = title.lower()
                if any(ch_kw in t_low for ch_kw in ("one moment, please", "just a moment", "attention required", "ddos-guard", "security check")):
                    break
                db.upsert_http_service(
                    project_id, url, code, title=title[:120], server=srv,
                    tech_stack=[srv] if srv else ["Custom-Port-Web"],
                    content_length=len(r.content), priority_score=85, source=f"port_{pnum}_probe"
                )
                is_std_hosting = pnum in (1500, 2082, 2083, 2086, 2087, 2095, 2096) or "login" in t_low
                sev_pw = "Low" if is_std_hosting else "Medium"
                cvss_pw = 3.7 if is_std_hosting else 6.5
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (PortWeb)", f"Exposed Web Interface on Non-Standard Port ({url})",
                    "Exposed Management / Web Port", sev_pw, cvss_pw, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", url,
                    f"HTTP {code} | Title: '{title[:60]}' | Server: {srv} | Size: {len(r.content)}B",
                    f"Nostandart {pnum}-portda ochiq HTTP/HTTPS servis yoki boshqaruv paneli aniqlandi.",
                    f"{pnum}-portni tashqi internetdan Firewall orqali cheklang.",
                )
                log_fn(f"  [🔥 PORT-WEB] {url} -> HTTP {code} | Title: '{title[:45]}' | Server: {srv}")
                break
            except Exception:
                pass


    ex_pw = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futs_pw = [ex_pw.submit(check_port, t_item) for t_item in targets]
    concurrent.futures.wait(futs_pw, timeout=12)
    ex_pw.shutdown(wait=False, cancel_futures=True)


# ================= #2 VHOST & ORIGIN IP HUNTER =================
VHOST_PREFIXES = ["admin", "internal", "dev", "stage", "test", "api", "backend", "cp", "panel", "crm", "erp", "old", "git"]


def hunt_virtual_hosts(db, session, project_id: int, apex_domain: str, log_fn):
    domains = db.get_project_bundle(project_id).get("domains", [])
    existing_hosts = {d["domain"] for d in domains}
    cdn_tokens = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri", "ddos-guard")
    unique_ips = sorted({
        d["ip"] for d in domains
        if d.get("ip") and not any(c in str(d.get("cdn_waf", "")).lower() for c in cdn_tokens)
    })[:5]
    if not unique_ips:
        return

    log_fn(f"[SPECTRE VHost Hunter] {len(unique_ips)} ta asosiy IP serverda DNS'da yo'q yashirin VirtualHost'lar parallel tekshirilmoqda...")
    for ip in unique_ips:
        base_url = ""
        base_status = 0
        base_len = 0
        for sch in ("https", "http"):
            try:
                r_base = session.get(f"{sch}://{ip}", headers={"Host": f"nonexistent-99182.{apex_domain}"}, timeout=3.5, verify=False, allow_redirects=False)
                base_url = f"{sch}://{ip}"
                base_status = r_base.status_code
                base_len = len(r_base.content)
                break
            except Exception:
                continue
        if not base_url:
            continue
        main_len = -1
        main_title = ""
        try:
            r_main = session.get(base_url, headers={"Host": apex_domain}, timeout=3.5, verify=False, allow_redirects=False)
            main_len = len(r_main.content)
            soup_m = BeautifulSoup(r_main.text[:15000], "html.parser")
            main_title = soup_m.title.string.strip() if (soup_m.title and soup_m.title.string) else ""
        except Exception:
            pass

        def check_vhost(pref: str):
            cand_vhost = f"{pref}.{apex_domain}"
            if cand_vhost in existing_hosts:
                return
            try:
                r = session.get(base_url, headers={"Host": cand_vhost}, timeout=3.5, verify=False, allow_redirects=False)
                if r.status_code == 200 and (r.status_code != base_status or abs(len(r.content) - base_len) > 250):
                    soup = BeautifulSoup(r.text[:15000], "html.parser")
                    title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
                    if main_len > 0 and abs(len(r.content) - main_len) < 180 and title == main_title:
                        return
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
            with session.get(url, timeout=(2.5, 3.0), verify=False, stream=True) as r:
                chunk = next(r.iter_content(chunk_size=16384), b"").decode("utf-8", errors="ignore")
                status_c = r.status_code
            if status_c == 200 and any(sig in chunk for sig in ("Index of /", "<ListBucketResult", "Directory listing for", "<EnumerationResults")):
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
    for svc in http_svcs:
        url = svc["url"]
        cookies = json.loads(svc.get("cookies_json") or "[]")
        for ck in cookies:
            raw = ck.get("raw", "")
            if f"domain=.{apex_domain}" in raw.lower() or f"domain={apex_domain}" in raw.lower():
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (CookieScope)", f"Cross-Subdomain Wildcard Cookie Scope (.{apex_domain})",
                    "Session Management / Subdomain Risk", "Medium", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "CWE-565", "A07:2021 - Identification and Authentication Failures", apex_domain,
                    f"Sample Host: {url} | Cookie shared across all *.{apex_domain} subdomains: {raw[:140]}",
                    f"Cookie Domain=.{apex_domain} qilib belgilangani sababli barcha subdomenlarga yuboriladi.",
                    "Sessiya cookie'larida Domain atributini faqat aniq host uchun cheklang (HostOnly cookie).",
                )
                log_fn(f"  [!] Wildcard Cookie Scope (.{apex_domain}) aniqlandi: {url}")



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

    rec_raw = dom_obj.get("records_json") or "{}"
    try:
        rec_dict = json.loads(rec_raw) if isinstance(rec_raw, str) else (rec_raw or {})
    except Exception:
        rec_dict = {}
    asn_info = rec_dict.get("asn_intel") if isinstance(rec_dict, dict) else None
    asn_str = "Aniqlanmagan"
    if isinstance(asn_info, dict) and asn_info.get("asn"):
        asn_str = f"{asn_info.get('asn')}  •  {str(asn_info.get('isp', '')).replace('\"', '')}  •  {asn_info.get('location', '')} ({asn_info.get('subnet', '')})"
    dns_types = [k for k in rec_dict.keys() if k != "asn_intel"] if isinstance(rec_dict, dict) else []

    lines = [
        f"◈ NISHON TEXNIK PASPORTI: {selected_domain}",
        "─" * 68,
        f"  IP Manzil       : {ip or 'Aniqlanmagan'}",
        f"  CNAME Yozuvi    : {dom_obj.get('cname') or 'Yo‘q'}   |   Manba: {dom_obj.get('source', '-')}",
        f"  Tarmoq / ASN    : {asn_str}",
        f"  Qo‘shni Hostlar : {len(co_hosted)} ta ({', '.join(co_hosted[:6]) or 'Yo‘q'})",
    ]
    if dns_types:
        lines.append(f"  DNS Yozuvlari   : {', '.join(dns_types)}")

    lines.append(f"\n◈ OCHIQ TARMOQ PORTLARI ({len(host_ports)} ta)")
    lines.append("─" * 68)
    if host_ports:
        for p in sorted(host_ports, key=lambda x: int(x.get("port", 0))):
            p_lbl = f"{p['port']}/{p['protocol']}"
            ver_s = (p.get("version") or "").split(",")[0][:36]
            lines.append(f"  • {p_lbl.ljust(10)} {str(p.get('service') or '-').ljust(15)} {ver_s}  [{p.get('source', '')}]")
    else:
        lines.append("  • Ochiq TCP/UDP portlar qayd etilmagan.")

    lines.append(f"\n◈ FAOL VEB SERVISLAR ({len(host_https)} ta)")
    lines.append("─" * 68)
    if host_https:
        for h in host_https:
            lines.append(f"  • [{h['status_code']}] {h['url']}  —  '{h['title'] or '-'}'  ({h['server'] or '-'})")
    else:
        lines.append("  • Standart portlarda faol veb-servis topilmadi.")

    lines.append(f"\n◈ XAVFSIZLIK TOPILMALARI ({len(host_finds)} ta)")
    lines.append("─" * 68)
    if host_finds:
        for f in host_finds:
            lines.append(f"  • [{f['severity'].upper()} | CVSS {f['cvss_score']}] {f['title']}")
            lines.append(f"    Dalil: {f['evidence'][:120]}")
    else:
        lines.append("  • Ushbu xostda hozircha zaiflik qayd etilmagan.")

    lines.append("\n◈ AMALIY PENTEST REJASI (TASK TREE)")
    lines.append("─" * 68)
    port_nums = {int(p["port"]) for p in host_ports}
    if 21 in port_nums:
        lines.append(f"  1. [FTP 21/tcp] Anonim kirishni tekshirish: nmap -p 21 --script ftp-anon {ip or selected_domain}")
    if 445 in port_nums or 137 in port_nums:
        lines.append(f"  2. [SMB 445/tcp] Null-session tekshiruvi: nxc smb {ip or selected_domain} -u '' -p '' --shares")
    if port_nums & WEB_CANDIDATE_PORTS:
        custom_p = sorted(port_nums & WEB_CANDIDATE_PORTS)
        lines.append(f"  3. [Boshqaruv Portlari {custom_p}] Admin panellarni ko‘zdan kechirish")
    api_list = [e["url"] for e in endpoints if e.get("category") in ("api_endpoint", "high_value_endpoint")][:4]
    if api_list:
        lines.append(f"  4. [API BOLA/IDOR] Repeater orqali avtorizatsiyani sinash: {', '.join(api_list[:2])}")
    lines.append(f"  5. [Fuzzing] ffuf -u https://{selected_domain}/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt -ac")
    return "\n".join(lines)


# ================= #3 API VERSION SHADOW TWINS & WAYBACK GHOST PROBER =================
def probe_api_versions_and_ghost_endpoints(db, project_id: int, log_fn, session: requests.Session | None = None):
    bundle = db.get_project_bundle(project_id)
    endpoints = bundle.get("endpoints", [])

    versioned_eps = [e["url"] for e in endpoints if re.search(r"/v[1-3]/", e["url"])][:10]
    shadow_candidates = []
    for u in versioned_eps:
        for repl in ("/v0/", "/v1/", "/v2/", "/v3/", "/internal/", "/admin/"):
            mut_u = re.sub(r"/v[1-3]/", repl, u, count=1).replace("{param}", "1")
            if mut_u != u and (mut_u, u) not in shadow_candidates:
                shadow_candidates.append((mut_u, u))

    wayback_eps = [e["url"] for e in endpoints if e.get("source") == "wayback" and not e["url"].endswith(".js")][:15]
    if not shadow_candidates and not wayback_eps:
        return
    log_fn(f"[SPECTRE API Shadow & Ghost Prober] {len(shadow_candidates)} ta API versiya egizaklari va {len(wayback_eps)} ta tarixiy URL tekshirilmoqda...")

    http_client = session or requests
    req_hdrs = None if session is not None else {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }

    def _read_capped(resp, cap: int = 16384) -> tuple[bytes, str]:
        buf = bytearray()
        for part in resp.iter_content(chunk_size=4096):
            if not part:
                break
            buf.extend(part)
            if len(buf) >= cap:
                break
        b_out = bytes(buf[:cap])
        h_sig = hashlib.sha256(b_out[:4096]).hexdigest()[:16] if b_out else ""
        return b_out, h_sig

    # Calibrate each origin against a nonexistent path (Status + Capped Length + SHA-256 Hash)
    host_cal: dict[str, tuple[int, int, str]] = {}
    all_probe_urls = [mut_u for mut_u, _ in shadow_candidates] + list(wayback_eps)
    for probe_u in all_probe_urls:
        p_u = urllib.parse.urlparse(probe_u)
        origin = f"{p_u.scheme}://{p_u.netloc}"
        if origin and p_u.netloc and origin not in host_cal:
            try:
                with http_client.get(f"{origin}/spectre-nonexistent-99182", headers=req_hdrs, timeout=3.0, verify=False, allow_redirects=False, stream=True) as rc:
                    cal_b, cal_h = _read_capped(rc)
                    host_cal[origin] = (rc.status_code, len(cal_b), cal_h)
            except Exception:
                host_cal[origin] = (-1, -1, "")

    def check_shadow(item):
        mut_url, orig_url = item
        p_u = urllib.parse.urlparse(mut_url)
        origin = f"{p_u.scheme}://{p_u.netloc}"
        cal_stat, cal_len, cal_hash = host_cal.get(origin, (-1, -1, ""))
        try:
            with http_client.get(mut_url, headers=req_hdrs, timeout=(2.5, 3.0), verify=False, allow_redirects=False, stream=True) as r:
                chunk_b, chunk_h = _read_capped(r)
                ctype = r.headers.get("Content-Type", "").lower()
                code = r.status_code
            if code == cal_stat and ((cal_hash and chunk_h == cal_hash) or abs(len(chunk_b) - cal_len) < 80):
                return
            chunk = chunk_b.decode("utf-8", errors="ignore")
            if code == 200 and len(chunk) > 20 and "text/html" not in ctype:
                low_c = chunk.lower()
                if '"not found"' in low_c or '"status":404' in low_c or '"status":401' in low_c:
                    return
                db.upsert_endpoint(project_id, mut_url, method="GET", category="api_endpoint", risk_tags=["API_Shadow_Twin"], status_code=code, source="shadow_twin")
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (ShadowAPI)", f"Active Shadow / Alternate API Version ({mut_url})",
                    "API Version Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "CWE-200", "A09:2021 - Security Logging and Monitoring Failures", mut_url,
                    f"HTTP {code} on alternate version of {orig_url} | Sample: {chunk[:100]}",
                    "API endpointning boshqa versiyasi (v0/v2/v3/internal) serverda faol holatda javob qaytarmoqda.",
                    "Eskirgan yoki test API versiyalarini production gateway darajasida o'chiring.",
                )
                log_fn(f"  [🧬 SHADOW API] {mut_url} -> HTTP {code}")
        except Exception:
            pass

    def check_ghost(wb_url: str):
        p_u = urllib.parse.urlparse(wb_url)
        origin = f"{p_u.scheme}://{p_u.netloc}"
        cal_stat, cal_len, cal_hash = host_cal.get(origin, (-1, -1, ""))
        try:
            with http_client.get(wb_url, headers=req_hdrs, timeout=(2.5, 3.0), verify=False, allow_redirects=False, stream=True) as r:
                chunk_b, chunk_h = _read_capped(r)
                code = r.status_code
            if code == cal_stat and ((cal_hash and chunk_h == cal_hash) or abs(len(chunk_b) - cal_len) < 80):
                return
            if code in (200, 401, 403, 405):
                db.upsert_endpoint(project_id, wb_url, method="GET", category="high_value_endpoint", risk_tags=["Zombie_Ghost_Endpoint"], status_code=code, source="wayback_verified")
                log_fn(f"  [👻 GHOST ENDPOINT] Tarixiy URL hali ham tirik ({code}): {wb_url}")
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





