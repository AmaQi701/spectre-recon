import concurrent.futures
import csv
import datetime
import json
import socket
import ssl
import subprocess
import urllib.parse
from pathlib import Path
import requests


# ================= #1 ASN, ISP, SUBNET (/24) & GEOLOCATION MAPPER =================
def enrich_asn_and_isp_intel(db, project_id: int, log_fn):
    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    unique_ips = sorted({d["ip"] for d in domains if d.get("ip")})
    if not unique_ips:
        return

    log_fn(f"[SPECTRE v5 ASN/ISP Mapper] {len(unique_ips)} ta server IP manzili bo'yicha ASN, Provayder va /24 Subnet aniqlanmoqda...")
    ip_info_map = {}
    try:
        r = requests.post("http://ip-api.com/batch?fields=status,query,country,city,isp,org,as", json=unique_ips[:90], timeout=8)
        if r.status_code == 200:
            for item in r.json():
                if item.get("status") == "success":
                    q_ip = item.get("query", "")
                    asn_str = item.get("as", "").split()[0] if item.get("as") else ""
                    isp_str = item.get("isp") or item.get("org") or ""
                    city = item.get("city", "")
                    subnet = ".".join(q_ip.split(".")[:3]) + ".0/24" if q_ip.count(".") == 3 else ""
                    ip_info_map[q_ip] = {
                        "asn": asn_str,
                        "isp": isp_str,
                        "location": f"{item.get('country', '')}/{city}".strip("/"),
                        "subnet": subnet,
                        "label": f"{asn_str} ({isp_str[:22]})" if asn_str else isp_str[:25],
                    }
                    log_fn(f"  [🌐 ASN] {q_ip} ({subnet}) -> {asn_str} | ISP: {isp_str} | {city}")
    except Exception as e:
        log_fn(f"  [!] ASN lookup ogohlantirish: {e}")

    for d in domains:
        ip = d.get("ip", "")
        if ip and ip in ip_info_map:
            info = ip_info_map[ip]
            recs = json.loads(d.get("records_json") or "{}")
            recs["asn_intel"] = info
            cdn_label = d.get("cdn_waf") or info["label"]
            db.upsert_domain(project_id, d["domain"], ip=ip, cname=d.get("cname", ""), records=recs, cdn_waf=cdn_label, source=d.get("source", ""))


# ================= #2 SSL/TLS DEEP CERTIFICATE & EXPIRY AUDITOR =================
def audit_ssl_certificates_deep(db, project_id: int, log_fn):
    bundle = db.get_project_bundle(project_id)
    https_urls = [s["url"] for s in bundle.get("http_services", []) if s["url"].startswith("https://")]
    if not https_urls:
        return

    log_fn(f"[SPECTRE v5 SSL/TLS Auditor] {len(https_urls)} ta HTTPS servisda sertifikat muddati va imzosi tekshirilmoqda...")

    def inspect_cert(url: str):
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=4.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_ver = ssock.version() or ""
                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.datetime.utcnow()).days
                        if days_left < 0:
                            db.upsert_finding(
                                project_id, "SPECTRE-v5 (TLS-Audit)", f"Expired SSL/TLS Certificate ({host}:{port})",
                                "Cryptographic Failure (TLS)", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                "CWE-298", "A02:2021 - Cryptographic Failures", url,
                                f"Expired on: {not_after_str} ({abs(days_left)} days ago)",
                                "Serverning SSL/TLS sertifikati muddati tugagan.",
                                "Let's Encrypt yoki CA orqali SSL sertifikatni yangilang.",
                            )
                    if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                        db.upsert_finding(
                            project_id, "SPECTRE-v5 (TLS-Audit)", f"Deprecated TLS Protocol Enabled ({tls_ver} on {host}:{port})",
                            "Cryptographic Failure (TLS)", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "CWE-326", "A02:2021 - Cryptographic Failures", url,
                            f"Negotiated Protocol: {tls_ver}",
                            "Eskirgan TLS protokoli yoqilgan.",
                            "Faqat TLSv1.2 va TLSv1.3 protokollariga ruxsat bering.",
                        )
        except ssl.SSLCertVerificationError as ssl_err:
            err_msg = str(ssl_err)
            db.upsert_finding(
                project_id, "SPECTRE-v5 (TLS-Audit)", f"Untrusted / Self-Signed / Mismatched SSL Certificate ({host}:{port})",
                "Cryptographic / Certificate Misconfiguration", "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-295", "A02:2021 - Cryptographic Failures", url,
                f"SSL Verification Error: {err_msg[:160]}",
                "Serverda o'z-o'ziga imzolangan (Self-Signed), muddati o'tgan yoki boshqa domenga tegishli SSL sertifikat o'rnatilgan.",
                "Rasmiy CA tomonidan imzolangan va barcha subdomenlarni (SAN) qamrab oluvchi sertifikat o'rnating.",
            )
            log_fn(f"  [🔐 TLS ALERT] {url} -> {err_msg[:90]}")
        except Exception:
            pass

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futs = [ex.submit(inspect_cert, u) for u in https_urls[:20]]
    concurrent.futures.wait(futs, timeout=8.0)
    ex.shutdown(wait=False, cancel_futures=True)


# ================= #3 DOMAIN-AWARE BACKUP & ARCHIVE EXPOSURE AUDITOR =================
def audit_domain_backup_exposure(db, project_id: int, apex_domain: str, log_fn):
    base_word = apex_domain.split(".")[0]
    candidates = [
        f"/{base_word}.zip", f"/{base_word}.tar.gz", f"/{base_word}.sql",
        "/backup.zip", "/backup.tar.gz", "/db.sql", "/www.zip",
    ]
    base_url = f"https://www.{apex_domain}"
    log_fn(f"[SPECTRE v5 Backup Auditor] Domen nomiga mos arxiv/backup fayllar ({base_word}.zip/.sql) tekshirilmoqda...")

    def check_archive(path: str):
        url = urllib.parse.urljoin(base_url, path)
        try:
            r = requests.get(url, headers={"User-Agent": "SPECTRE-Recon/5.0"}, timeout=(2.5, 3.0), verify=False, allow_redirects=False, stream=True)
            magic = next(r.iter_content(chunk_size=64), b"")
            r.close()
            ctype = r.headers.get("Content-Type", "").lower()
            is_zip_or_gzip = magic.startswith(b"PK\x03\x04") or magic.startswith(b"\x1f\x8b")
            is_sql = b"CREATE TABLE" in magic or b"-- MySQL dump" in magic or "application/sql" in ctype
            if r.status_code == 200 and (is_zip_or_gzip or is_sql):
                db.upsert_finding(
                    project_id, "SPECTRE-v5 (BackupAudit)", f"Exposed Backup / Database Archive ({url})",
                    "Critical Backup Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-530", "A05:2021 - Security Misconfiguration", url,
                    f"HTTP 200 | Content-Type: {ctype} | Magic Bytes Verified",
                    "Veb-server ildiz katalogida ochiq arxiv yoki ma'lumotlar bazasi nusxasi qolib ketgan.",
                    "Arxiv va .sql fayllarni veb-server katalogidan darhol o'chiring.",
                )
                log_fn(f"  [🚨 BACKUP LEAK] Tasdiqlangan arxiv topildi: {url}")
        except Exception:
            pass

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    futs = [ex.submit(check_archive, c) for c in candidates]
    concurrent.futures.wait(futs, timeout=5.0)
    ex.shutdown(wait=False, cancel_futures=True)


# ================= #4 ONE-CLICK MULTI-FORMAT EXPORTER (BURP, NUCLEI, CSV, JSON) =================
def export_project_artifacts(db, project_id: int, reports_dir: str = "/home/amaqi/projects/apex-pentest-gui/reports") -> dict:
    out_dir = Path(reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    b = db.get_project_bundle(project_id)
    domains = b.get("domains", [])
    http_svcs = b.get("http_services", [])
    findings = b.get("findings", [])

    subs_path = out_dir / f"project_{project_id}_subdomains.txt"
    subs_path.write_text("\n".join(sorted({d["domain"] for d in domains})), encoding="utf-8")

    urls_path = out_dir / f"project_{project_id}_live_urls.txt"
    urls_path.write_text("\n".join(sorted({s["url"] for s in http_svcs})), encoding="utf-8")

    burp_inc = [{"enabled": True, "file": "^/.*", "host": "^" + d["domain"].replace(".", "\\.") + "$", "protocol": "any"} for d in domains]
    burp_scope = {"target": {"scope": {"advanced_mode": True, "exclude": [], "include": burp_inc}}}
    burp_path = out_dir / f"project_{project_id}_burp_scope.json"
    burp_path.write_text(json.dumps(burp_scope, indent=2), encoding="utf-8")

    csv_path = out_dir / f"project_{project_id}_findings.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f_csv:
        writer = csv.writer(f_csv)
        writer.writerow(["ID", "Severity", "CVSS", "Title", "Category", "CWE", "OWASP", "Asset", "Evidence", "Remediation", "Triage"])
        for f in findings:
            writer.writerow([f["id"], f["severity"], f["cvss_score"], f["title"], f["category"], f["cwe"], f["owasp"], f["asset"], f["evidence"], f["remediation"], f["triage_status"]])

    json_path = out_dir / f"project_{project_id}_full_export.json"
    json_path.write_text(json.dumps(b, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "subdomains_txt": str(subs_path),
        "live_urls_txt": str(urls_path),
        "burp_scope_json": str(burp_path),
        "findings_csv": str(csv_path),
        "full_json": str(json_path),
    }


# ================= #5 IN-APP HTTP REQUEST/RESPONSE INSPECTOR (FULL INTERACTIVE REPEATER) =================
def send_repeater_request(method: str, url: str, auth_header: str = "", proxy_url: str = "", custom_headers_raw: str = "", req_body: str = "") -> str:
    headers = {"User-Agent": "SPECTRE-Studio-Repeater/6.0", "Accept": "*/*"}
    if auth_header.strip():
        if ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            headers["Cookie"] = auth_header.strip()

    for line in (custom_headers_raw or "").splitlines():
        if ":" in line:
            hk, hv = line.split(":", 1)
            headers[hk.strip()] = hv.strip()

    body_data = req_body.encode("utf-8") if req_body and method.upper() in ("POST", "PUT", "PATCH", "DELETE") else None
    if body_data and "Content-Type" not in headers and req_body.lstrip().startswith(("{", "[")):
        headers["Content-Type"] = "application/json"

    proxies = {"http": proxy_url.strip(), "https": proxy_url.strip()} if proxy_url.strip() else None
    try:
        t0 = datetime.datetime.now()
        r = requests.request(method.upper(), url.strip(), headers=headers, data=body_data, proxies=proxies, timeout=10, verify=False, allow_redirects=False, stream=True)
        body_bytes = next(r.iter_content(chunk_size=24576), b"")
        r.close()
        elapsed_ms = int((datetime.datetime.now() - t0).total_seconds() * 1000)
        hdr_lines = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_text = body_bytes.decode("utf-8", errors="ignore")
        try:
            body_text = json.dumps(json.loads(body_text), indent=2, ensure_ascii=False)
        except Exception:
            pass
        return (
            f"╔══ ⚡ SPECTRE INTERACTIVE REPEATER ({elapsed_ms} ms) ══╗\n"
            f"▶ REQUEST: {method.upper()} {url.strip()}\n"
            f"◀ STATUS : HTTP/1.1 {r.status_code} {r.reason}\n"
            f"{hdr_lines}\n\n"
            f"── 📄 RESPONSE BODY ({len(body_bytes)} bytes) ──\n"
            f"{body_text[:5000]}"
        )
    except Exception as e:
        return f"[HTTP REPEATER ERROR] So'rov yuborishda xatolik: {e}"



# ================= #7 AI & HEURISTIC TACTICAL ANALYST =================
def generate_ai_tactical_analysis(db, project_id: int, selected_domain: str = "") -> str:
    b = db.get_project_bundle(project_id)
    domains = b.get("domains", [])
    if not selected_domain and domains:
        selected_domain = domains[0]["domain"]
    dom_obj = next((d for d in domains if d["domain"] == selected_domain), {})
    ip = dom_obj.get("ip", "")
    recs = json.loads(dom_obj.get("records_json") or "{}")
    asn_info = recs.get("asn_intel", {})
    host_ports = [p for p in b.get("ports", []) if p["host"] == selected_domain or (ip and p.get("ip") == ip)]
    host_finds = [f for f in b.get("findings", []) if selected_domain in f["asset"] or (ip and ip in f["asset"])]

    pnums = sorted({int(p["port"]) for p in host_ports})
    direct_ips = []
    for d in domains:
        d_ip = d.get("ip", "")
        d_rec = json.loads(d.get("records_json") or "{}").get("asn_intel", {})
        if d_ip and "cloudflare" not in str(d_rec.get("isp", "")).lower() and "cloudflare" not in str(d.get("cdn_waf", "")).lower():
            direct_ips.append(f"{d['domain']} ({d_ip} - {d_rec.get('isp', '')})")

    summary_lines = [
        f"╔══ 🧠 SPECTRE AI TACTICAL ANALYST REPORT: {selected_domain} ══╗",
        f"• Host: {selected_domain} | IP: {ip or 'N/A'} | ASN/ISP: {asn_info.get('asn', '')} {asn_info.get('isp', '')} ({asn_info.get('subnet', '')})",
        f"• Noyob Ochiq Portlar: {pnums} | Aniqlangan Zaifliklar: {len(host_finds)} ta",
    ]
    if direct_ips:
        summary_lines.append(f"• 🎯 WAF/Cloudflare Ortidan Tashqaridagi To'g'ridan-to'g'ri (Direct) Serverlar: {', '.join(direct_ips[:6])}")
    summary_lines.extend(["", "── 🎯 EKSPERT XAVFSIZLIK BAHOSI VA HUJUM VEKTORLARI ──"])

    if 445 in pnums or 137 in pnums:
        summary_lines.append("1. [CRITICAL RISK - SMB/NetBIOS Exposed] Tashqi internetda 445/137 portlar ochiq. SMB signing, Null-Session va eskirgan Samba/Windows CVE'larini darhol tekshiring.")
    if 21 in pnums:
        summary_lines.append("2. [HIGH RISK - FTP Service] 21-port ochiq. Anonymous FTP login hamda ProFTPD/vsftpd versiya zaifliklarini (masalan, mod_copy) tekshiring.")
    if any(p in pnums for p in (8080, 8086, 8087, 8443, 9080, 10000)):
        summary_lines.append("3. [HIGH VALUE - Management Panels] Nostandart portlarda (8080/8443/8086/9080) boshqaruv panellari (Plesk, Tomcat, Wowza) aniqlandi — Default Credentials va CVE'larni tekshiring.")
    for f in host_finds[:6]:
        summary_lines.append(f"• [{f['severity']} | CVSS {f['cvss_score']}] {f['title']} -> {f['remediation']}")

    # Try local Ollama if running on 127.0.0.1:11434
    try:
        r_tags = requests.get("http://127.0.0.1:11434/api/tags", timeout=1.5)
        if r_tags.status_code == 200 and r_tags.json().get("models"):
            model_name = r_tags.json()["models"][0]["name"]
            prompt = f"O'zbek tilida qisqa pentest tahlili yoz: Host={selected_domain}, IP={ip}, Ports={list(pnums)}, Findings={[f['title'] for f in host_finds[:5]]}"
            r_gen = requests.post("http://127.0.0.1:11434/api/generate", json={"model": model_name, "prompt": prompt, "stream": False}, timeout=12)
            if r_gen.status_code == 200:
                summary_lines.append(f"\n── 🤖 LOCAL OLLAMA ({model_name}) AI XULOSASI ──\n" + r_gen.json().get("response", ""))
    except Exception:
        pass

    return "\n".join(summary_lines)



