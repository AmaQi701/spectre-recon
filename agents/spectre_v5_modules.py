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
    import ipaddress

    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    unique_ips = []
    for d in domains:
        ip_s = (d.get("ip") or "").strip()
        if ip_s and ip_s not in unique_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_s)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    unique_ips.append(ip_s)
            except ValueError:
                pass
    unique_ips.sort()
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

    cdn_isp_keywords = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "ddos-guard", "sucuri", "qrator")
    for d in domains:
        ip = d.get("ip", "")
        if ip and ip in ip_info_map:
            info = ip_info_map[ip]
            recs = json.loads(d.get("records_json") or "{}")
            recs["asn_intel"] = info
            isp_low = str(info.get("isp", "")).lower()
            cdn_label = d.get("cdn_waf") or (info["label"] if any(ck in isp_low for ck in cdn_isp_keywords) else "")
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
                        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        days_left = (exp_dt - now_utc).days
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


# ================= #8 DEEP MULTI-TOOL EXECUTION & STRUCTURED PARSERS (v7.0) =================
def run_deep_subdomain_tools(agent, project_id: int, apex_domain: str, scope, active_ids: set, log_fn):
    import os
    import re
    import shlex

    safe_apex = shlex.quote(apex_domain)
    log_fn(f"[SPECTRE Parallel Subdomain Engine] 6 ta subdomen vositasi (Subfinder, Sublist3r, Amass, Assetfinder, Cero, Findomain) parallel ishga tushirilmoqda...")

    def _task_subfinder():
        if "subfinder" in active_ids and agent._find_binary("subfinder"):
            out_file = f"/tmp/spectre_subfinder_{project_id}.txt"
            try:
                if os.path.exists(out_file):
                    os.remove(out_file)
            except Exception:
                pass
            out = agent._run_cli(f"subfinder -d {safe_apex} -all -es commoncrawl,waybackarchive,riddler -timeout 5 -silent -o {out_file}", log_fn, timeout=25, project_id=project_id)
            lines = open(out_file, "r", errors="ignore").read().splitlines() if os.path.exists(out_file) else out.splitlines()
            cnt = 0
            for line in lines:
                h = line.strip().lower().rstrip(".")
                if h and scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, source="subfinder_deep")
                    cnt += 1
            log_fn(f"  [+] Subfinder Deep yakunlandi: {cnt} ta subdomen bazaga qo'shildi.")

    def _task_sublist3r():
        if "sublist3r" in active_ids and agent._find_binary("sublist3r"):
            subl_bin = "/home/amaqi/.local/bin/sublist3r" if os.path.exists("/home/amaqi/.local/bin/sublist3r") else "sublist3r"
            out_file = f"/tmp/spectre_sublist3r_{project_id}.txt"
            try:
                if os.path.exists(out_file):
                    os.remove(out_file)
            except Exception:
                pass
            agent._run_cli(f"{subl_bin} -d {safe_apex} -n -e crtsh,threatcrowd,netcraft -o {out_file}", log_fn, timeout=30, project_id=project_id)
            cnt = 0
            if os.path.exists(out_file):
                try:
                    for line in open(out_file, "r", errors="ignore"):
                        h = line.strip().lower().rstrip(".")
                        if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                            agent.db.upsert_domain(project_id, h, source="sublist3r")
                            cnt += 1
                except Exception:
                    pass
            log_fn(f"  [+] Sublist3r yakunlandi: {cnt} ta subdomen topildi.")

    def _task_amass():
        if "amass" in active_ids and agent._find_binary("amass"):
            out = agent._run_cli(f"amass enum -passive -d {safe_apex} -timeout 1", log_fn, timeout=22, project_id=project_id)
            cnt = 0
            for m in re.findall(r"(?:[a-zA-Z0-9\-]+\.)+" + re.escape(apex_domain), out):
                h = m.lower().strip(".")
                if scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, source="amass_passive")
                    cnt += 1
            log_fn(f"  [+] OWASP Amass yakunlandi: {cnt} ta subdomen ajratib olindi.")

    def _task_assetfinder():
        if "assetfinder" in active_ids and agent._find_binary("assetfinder"):
            out = agent._run_cli(f"assetfinder --subs-only {safe_apex}", log_fn, timeout=28, project_id=project_id)
            cnt = 0
            for line in out.splitlines():
                h = line.strip().lower().rstrip(".")
                if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, source="assetfinder")
                    cnt += 1
            log_fn(f"  [+] Assetfinder yakunlandi: {cnt} ta subdomen topildi.")

    def _task_cero():
        if "cero" in active_ids and agent._find_binary("cero"):
            out = agent._run_cli(f"cero -d {safe_apex}", log_fn, timeout=18, project_id=project_id)
            cnt = 0
            for line in out.splitlines():
                h = line.strip().lower().lstrip("*.").rstrip(".")
                if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, source="cero_tls")
                    cnt += 1
            log_fn(f"  [+] Cero TLS SAN yakunlandi: {cnt} ta subdomen topildi.")

    def _task_findomain():
        if "findomain" in active_ids and agent._find_binary("findomain"):
            out = agent._run_cli(f"findomain -t {safe_apex} -q", log_fn, timeout=22, project_id=project_id)
            cnt = 0
            for line in out.splitlines():
                h = line.strip().lower().rstrip(".")
                if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, source="findomain")
                    cnt += 1
            log_fn(f"  [+] Findomain Rust yakunlandi: {cnt} ta subdomen topildi.")

    def _task_chaos():
        if "chaos" in active_ids and agent._find_binary("chaos") and os.environ.get("PDCP_API_KEY"):
            out = agent._run_cli(f"chaos -d {safe_apex} -silent", log_fn, timeout=20, project_id=project_id)
            cnt = 0
            for line in out.splitlines():
                h = line.strip().lower().rstrip(".")
                if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, source="chaos_dataset")
                    cnt += 1
            log_fn(f"  [+] Chaos Dataset yakunlandi: {cnt} ta subdomen topildi.")

    def _task_fierce():
        if "fierce" in active_ids and agent._find_binary("fierce"):
            f_subs = "www api dev stage test admin portal mail my auth sso id vpn git lms chat erp crm zabbix doc pay cabinet"
            out = agent._run_cli(f"fierce --domain {safe_apex} --dns-servers 8.8.8.8 1.1.1.1 --subdomains {f_subs}", log_fn, timeout=22, project_id=project_id)
            cnt = 0
            for m in re.finditer(r"Found:\s+([a-zA-Z0-9.\-_]+)\.\s+\((\d+\.\d+\.\d+\.\d+)\)", out):
                h, f_ip = m.group(1).lower().strip("."), m.group(2)
                if scope.is_in_scope(h)[0]:
                    agent.db.upsert_domain(project_id, h, ip=f_ip, source="fierce_dns")
                    cnt += 1
            log_fn(f"  [+] Fierce DNS Scanner yakunlandi: {cnt} ta host/IP topildi.")

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futs = [ex.submit(fn) for fn in (_task_subfinder, _task_sublist3r, _task_amass, _task_assetfinder, _task_cero, _task_findomain, _task_chaos, _task_fierce)]
    concurrent.futures.wait(futs, timeout=28)
    ex.shutdown(wait=False, cancel_futures=True)

    res_file = "/tmp/spectre_resolvers.txt"
    open(res_file, "w").write("8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.4.4\n1.0.0.1\n208.67.222.222\n")

    # Detect Wildcard DNS IPs BEFORE running puredns / dnsx so dead historical subdomains never get wildcard IPs
    wildcard_ips_s1 = set()
    try:
        import dns.resolver as _dres
        _r = _dres.Resolver(configure=False)
        _r.nameservers = ["8.8.8.8", "1.1.1.1"]
        _r.lifetime = 2.0
        for _rd in _r.resolve(f"spectre-wildcard-check-99182.{apex_domain}", "A"):
            wildcard_ips_s1.add(str(_rd).rstrip("."))
    except Exception:
        pass

    # 2.2A DNSGen / Gotator + PureDNS / ShuffleDNS Permutation & Wildcard Resolution
    seed_doms = [d["domain"] for d in agent.db.get_project_bundle(project_id).get("domains", []) if not d["domain"].startswith(("www.ns", "ns1.", "ns2."))][:35]
    if seed_doms and any(k in active_ids for k in ("dnsgen", "gotator", "puredns", "shuffledns")):
        seed_file = f"/tmp/spectre_seeds_{project_id}.txt"
        perm_file = f"/tmp/spectre_perms_{project_id}.txt"
        open(seed_file, "w").write("\n".join(seed_doms) + "\n")
        perm_lines = []
        if "dnsgen" in active_ids and agent._find_binary("dnsgen"):
            dg_out = agent._run_cli(f"dnsgen {seed_file}", log_fn, timeout=15, project_id=project_id)
            dg_all = dg_out.splitlines()
            step_dg = max(1, len(dg_all) // 350)
            perm_lines.extend(dg_all[::step_dg][:350])
        if "gotator" in active_ids and agent._find_binary("gotator"):
            gt_out = agent._run_cli(f"gotator -sub {seed_file} -depth 1 -numbers 3 -mindup -adv=false -silent", log_fn, timeout=15, project_id=project_id)
            gt_all = gt_out.splitlines()
            step_gt = max(1, len(gt_all) // 350)
            perm_lines.extend(gt_all[::step_gt][:350])
        if perm_lines:
            valid_perms = sorted({p.strip().lower().rstrip(".") for p in perm_lines if p.strip().lower().rstrip(".").endswith("." + apex_domain)})[:600]
            open(perm_file, "w").write("\n".join(valid_perms) + "\n")
            resolved_by_pd = False
            if "puredns" in active_ids and agent._find_binary("puredns"):
                pd_out = agent._run_cli(f"puredns resolve {perm_file} -r {res_file} -q", log_fn, timeout=25, project_id=project_id)
                for ph in pd_out.splitlines():
                    ph = ph.strip().lower().rstrip(".")
                    if ph and scope.is_in_scope(ph)[0]:
                        agent.db.upsert_domain(project_id, ph, source="puredns_perm")
                        resolved_by_pd = True
            if not resolved_by_pd and "shuffledns" in active_ids and agent._find_binary("shuffledns"):
                sd_out = agent._run_cli(f"shuffledns -d {safe_apex} -list {perm_file} -r {res_file} -mode resolve -silent", log_fn, timeout=25, project_id=project_id)
                for sh in sd_out.splitlines():
                    sh = sh.strip().lower().rstrip(".")
                    if sh and scope.is_in_scope(sh)[0]:
                        agent.db.upsert_domain(project_id, sh, source="shuffledns_perm")

    # 2.2 ProjectDiscovery DNSX Multi-Record Verification (Up to 500 hosts + Wildcard & Cloudflare Tagging)
    if "dnsx" in active_ids and agent._find_binary("dnsx"):
        doms_now = [d["domain"] for d in agent.db.get_project_bundle(project_id).get("domains", [])]
        if doms_now:
            dom_file = f"/tmp/spectre_dnsx_in_{project_id}.txt"
            open(dom_file, "w").write("\n".join(doms_now[:500]) + "\n")
            log_fn(f"[Tool 2.2 -> ProjectDiscovery DNSX] {len(doms_now[:500])} ta subdomen A/CNAME yozuvlari tezkor tekshirilmoqda...")
            dx_out = agent._run_cli(f"dnsx -l {dom_file} -r {res_file} -a -cname -resp -silent", log_fn, timeout=30, project_id=project_id)
            for line in dx_out.splitlines():
                clean_l = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                parts = clean_l.split()
                if len(parts) >= 3:
                    h = parts[0].strip().lower()
                    val = parts[-1].strip("[]").rstrip(".")
                    if "[A]" in clean_l and re.match(r"^\d+\.\d+\.\d+\.\d+$", val) and scope.is_in_scope(h)[0]:
                        if h != apex_domain and val in wildcard_ips_s1:
                            continue
                        cdn_tag = "Cloudflare" if val.startswith(("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.67.", "188.114.")) else ""
                        agent.db.upsert_domain(project_id, h, ip=val, cdn_waf=cdn_tag, source="dnsx_verified")
                    elif "[CNAME]" in clean_l and "." in val and scope.is_in_scope(h)[0]:
                        cdn_tag = "Cloudflare" if "cloudflare" in val.lower() else ""
                        agent.db.upsert_domain(project_id, h, cname=val, cdn_waf=cdn_tag, source="dnsx_verified")

    # 2.3 Dig Deep DNS & Zone Transfer (AXFR) Audit
    if "dig" in active_ids and agent._find_binary("dig"):
        log_fn(f"[Tool 2.3 -> Dig Deep DNS & AXFR] {apex_domain} NS serverlarida Zone Transfer (AXFR) zaifligi tekshirilmoqda...")
        ns_out = agent._run_cli(f"dig +short NS {safe_apex}", log_fn, timeout=8, project_id=project_id)
        for ns_line in ns_out.splitlines()[:4]:
            ns_host = ns_line.strip().rstrip(".")
            if ns_host and "." in ns_host:
                axfr_out = agent._run_cli(f"dig @{shlex.quote(ns_host)} {safe_apex} AXFR +time=3 +tries=1", log_fn, timeout=8, project_id=project_id)
                if "XFR size" in axfr_out or ("\tIN\tA\t" in axfr_out and "Transfer failed" not in axfr_out):
                    agent.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (Dig AXFR)", f"DNS Zone Transfer (AXFR) Enabled on {ns_host}",
                        "DNS Misconfiguration", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "CWE-200", "A05:2021 - Security Misconfiguration", f"{apex_domain} (@{ns_host})",
                        axfr_out[:800],
                        f"DNS server ({ns_host}) AXFR so'roviga butun domen zonasini ochiq qaytardi!",
                        "DNS serverda allow-transfer (AXFR) ruxsatini faqat ishonchli ikkilamchi NS IP manzillar bilan cheklang.",
                    )
                    log_fn(f"  [🚨 CRITICAL DNS AXFR] {ns_host} butun DNS zonasini oshkor qildi!")

    # 2.4 Whois Deep Parser
    if "whois" in active_ids and agent._find_binary("whois"):
        w_out = agent._run_cli(f"whois {safe_apex}", log_fn, timeout=6, project_id=project_id)
        if w_out:
            info_bits = []
            for line in w_out.splitlines():
                l_str = line.strip()
                if any(l_str.lower().startswith(k) for k in ("registrar:", "creation date:", "expiry date:", "registry expiry date:", "name server:", "org:", "admin email:")):
                    if l_str not in info_bits:
                        info_bits.append(l_str)
            summary = " | ".join(info_bits[:8]) if info_bits else w_out[:220].replace("\n", " ")
            log_fn(f"  [📋 WHOIS Intel] {summary[:180]}")
            agent.db.log_task(project_id, "SPECTRE-Agent1", "whois", "COMPLETED", f"whois {apex_domain}", summary[:400])
    total_s1 = len(agent.db.get_project_bundle(project_id).get("domains", []))
    agent.db.log_task(project_id, "SPECTRE-Agent1", "stage1_subdomain_suite", "COMPLETED", f"stage1_suite {apex_domain}", f"Total in-scope subdomains after Stage 1: {total_s1}")


def run_deep_network_and_ad_tools(agent, project_id: int, primary_host: str, active_ids: set, log_fn):
    import re
    import shlex
    import xml.etree.ElementTree as ET

    bundle = agent.db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    cf_prefixes = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.67.", "188.114.")
    cdn_tokens = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri", "ddos-guard")

    def _rank_h(h_name: str) -> int:
        if h_name == primary_host:
            return 3
        if h_name.startswith(("ns1.", "ns2.", "ns.", "www.ns")):
            return 0
        if any(k in h_name.split(".")[0] for k in ("api", "admin", "my", "id", "auth", "sso", "portal")):
            return 2
        return 1

    ip_to_hosts: dict[str, list[str]] = {}
    for d in domains:
        ip = (d.get("ip") or "").strip()
        cdn = str(d.get("cdn_waf", "")).lower()
        if ip and not ip.startswith(cf_prefixes) and not any(c in cdn for c in cdn_tokens):
            ip_to_hosts.setdefault(ip, []).append(d["domain"])

    ip_to_primary_host: dict[str, str] = {}
    for ip, h_list in ip_to_hosts.items():
        ip_to_primary_host[ip] = sorted(h_list, key=lambda x: (-_rank_h(x), len(x)))[0]

    non_cdn_ips = sorted(ip_to_primary_host.keys(), key=lambda ip_k: (0 if ip_to_primary_host[ip_k] == primary_host else 1, ip_k))

    # 3.1 Naabu Fast Top-1000 Port Scanner FIRST (Unique Non-CDN Origin IPs -> Feeds Nmap Deep NSE!)
    alg_false_ports = {2000, 5060}
    if "naabu" in active_ids and agent._find_binary("naabu") and non_cdn_ips:
        nb_targets = non_cdn_ips[:5]
        nb_joined = ",".join(nb_targets)
        log_fn(f"[Tool 3.1 -> Naabu] {nb_joined} ({len(nb_targets)} ta noyob Origin IP) da Top-1000 portlar tezkor tekshirilmoqda...")
        nb_out = agent._run_cli(f"naabu -host {shlex.quote(nb_joined)} -top-ports 1000 -silent", log_fn, timeout=45, project_id=project_id)
        for line in nb_out.splitlines():
            if ":" in line:
                h_part, p_part = line.strip().rsplit(":", 1)
                if p_part.isdigit():
                    p_num = int(p_part)
                    if p_num in alg_false_ports:
                        continue
                    ip_val = h_part if re.match(r"^\d+\.\d+\.\d+\.\d+$", h_part) else ""
                    canon_h = ip_to_primary_host.get(ip_val, h_part)
                    agent.db.upsert_port(project_id, canon_h, p_num, "tcp", ip=ip_val, service="tcp-open", source="naabu")

    # 3.2 Nmap Deep NSE Recon Scanner SECOND (Smart Port Chaining on Unique Non-CDN IPs)
    if "nmap" in active_ids and agent._find_binary("nmap") and non_cdn_ips:
        nmap_ips = non_cdn_ips[:3]
        known_ports_rows = agent.db.get_project_bundle(project_id).get("ports", [])

        for n_ip in nmap_ips:
            if project_id in agent.abort_flags:
                break
            canon_host = ip_to_primary_host.get(n_ip, n_ip)
            safe_t = shlex.quote(n_ip)
            target_ports = {21, 22, 80, 443, 445, 3306, 5432, 6379, 8080, 8443}
            for pr in known_ports_rows:
                if pr.get("ip") == n_ip or pr.get("host") in (n_ip, canon_host):
                    p_int = int(pr.get("port", 0))
                    if 1 <= p_int <= 65535 and p_int not in alg_false_ports:
                        target_ports.add(p_int)
            port_spec = ",".join(str(p) for p in sorted(target_ports)[:35])
            log_fn(f"[Tool 3.2 -> Nmap Deep NSE] {canon_host} ({n_ip} | Portlar: {len(target_ports)} ta) da servis versiyalari va NSE skriptlari ishga tushirilmoqda...")
            xml_out = agent._run_cli(
                f"nmap -Pn -sV --version-light -T4 --max-retries 1 --host-timeout 30s --script-timeout 8s -p {port_spec} --script=banner,http-title,http-headers,http-methods,ssl-cert,ftp-anon,smb-os-discovery,smb-protocols -oX - {safe_t}",
                log_fn,
                timeout=38,
                project_id=project_id,
            )
            if "<nmaprun" in xml_out:
                try:
                    s = xml_out.find("<nmaprun")
                    e = xml_out.rfind("</nmaprun>")
                    root = ET.fromstring(xml_out[s : e + 10])
                    for h in root.findall("host"):
                        addr_el = h.find("address")
                        ip_addr = addr_el.get("addr", "") if addr_el is not None else n_ip
                        for p in h.findall(".//port"):
                            state_el = p.find("state")
                            if state_el is not None and state_el.get("state") == "open":
                                port_id = int(p.get("portid", 0))
                                proto = p.get("protocol", "tcp")
                                svc_el = p.find("service")
                                svc_name = svc_el.get("name", "") if svc_el is not None else ""
                                product = svc_el.get("product", "") if svc_el is not None else ""
                                ver = svc_el.get("version", "") if svc_el is not None else ""
                                extra = svc_el.get("extrainfo", "") if svc_el is not None else ""

                                nse_notes = []
                                for scr in p.findall("script"):
                                    sid = scr.get("id", "")
                                    sout = (scr.get("output", "") or "").strip().replace("\n", " ")
                                    if sout:
                                        nse_notes.append(f"[{sid}: {sout[:75]}]")
                                    if sid == "ftp-anon" and "Anonymous FTP login allowed" in sout:
                                        agent.db.upsert_finding(
                                            project_id, "SPECTRE-Agent1 (Nmap NSE)", f"Anonymous FTP Login Enabled on {canon_host}:{port_id} ({n_ip})",
                                            "Authentication Bypass", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                            "CWE-287", "A07:2021 - Identification and Authentication Failures", f"{canon_host}:{port_id}",
                                            sout[:500], "FTP serverda anonim (parolsiz) kirish ruxsat etilgan.", "FTP konfiguratsiyasida anonymous_enable=NO qiling.",
                                        )
                                full_ver = f"{product} {ver} {extra} {' '.join(nse_notes[:2])}".strip()
                                agent.db.upsert_port(project_id, canon_host, port_id, proto, ip=ip_addr, service=svc_name, version=full_ver[:220], source="nmap_deep_nse")
                                log_fn(f"  [🔬 Nmap Deep] {canon_host} ({n_ip}):{port_id}/{proto} -> {svc_name} | {full_ver[:120]}")
                except Exception as ex:
                    log_fn(f"  [!] Nmap Deep XML parse ogohlantirish: {ex}")

    # 13.1 NetExec (nxc) SMB (445) & SSH (22) Deep Service / AD Domain Inspector
    nxc_bin = agent._find_binary("nxc") or agent._find_binary("netexec")
    if "netexec" in active_ids and nxc_bin:
        ports_now = agent.db.get_project_bundle(project_id).get("ports", [])
        smb_ips = sorted({p.get("ip") or p.get("host") for p in ports_now if int(p.get("port", 0)) == 445 and (p.get("ip") or p.get("host"))})
        for sip in smb_ips[:3]:
            canon_h = ip_to_primary_host.get(sip, sip)
            log_fn(f"[Tool 13.1 -> NetExec (nxc) SMB] {sip}:445 da OS versiyasi, Domain nomi va SMB Signing tekshirilmoqda...")
            nxc_out = agent._run_cli(f"{nxc_bin} smb {shlex.quote(sip)}", log_fn, timeout=20, project_id=project_id)
            if nxc_out.strip():
                clean_line = nxc_out.strip().splitlines()[-1]
                log_fn(f"  [🛡️ NetExec SMB] {clean_line}")
                agent.db.upsert_port(project_id, canon_h, 445, "tcp", ip=sip, service="microsoft-ds", version=clean_line[:200], source="netexec_smb")
                if "signing:false" in clean_line.lower():
                    agent.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (NetExec SMB)", f"SMB Signing Not Required on {canon_h} ({sip}:445) (NTLM Relay Vector)",
                        "Network Protocol Misconfiguration", "Medium", 6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "CWE-300", "A05:2021 - Security Misconfiguration", f"{canon_h}:445 ({sip})",
                        clean_line, "SMB serverda raqamli imzo (SMB Signing) majburiy emas — bu NTLM Relay hujumlariga yo'l ochadi.",
                        "GPO yoki smb.conf orqali SMB Signing'ni majburiy (server signing = mandatory) qiling.",
                    )
        ssh_ips = sorted({p.get("ip") or p.get("host") for p in ports_now if int(p.get("port", 0)) == 22 and (p.get("ip") or p.get("host"))})
        for ship in ssh_ips[:2]:
            canon_h = ip_to_primary_host.get(ship, ship)
            nxc_ssh = agent._run_cli(f"{nxc_bin} ssh {shlex.quote(ship)}", log_fn, timeout=12, project_id=project_id)
            if nxc_ssh.strip():
                ssh_line = nxc_ssh.strip().splitlines()[-1]
                agent.db.upsert_port(project_id, canon_h, 22, "tcp", ip=ship, service="ssh", version=ssh_line[:180], source="netexec_ssh")

    # 3.3 MapCIDR Subnet Aggregator
    if "mapcidr" in active_ids and agent._find_binary("mapcidr"):
        all_ips = sorted({d.get("ip") for d in domains if d.get("ip")})
        if all_ips:
            cidrs = sorted({".".join(ip.split(".")[:3]) + ".0/24" for ip in all_ips if ip.count(".") == 3})
            if cidrs:
                agent.db.log_task(project_id, "SPECTRE-Agent1", "mapcidr", "COMPLETED", "mapcidr -sbc", f"Aggregated /24 Subnets ({len(cidrs)}): {', '.join(cidrs[:8])}")

    # 13.2 Kerbrute Active Directory Port 88 Inspector
    if "kerbrute" in active_ids and agent._find_binary("kerbrute"):
        ports_now = agent.db.get_project_bundle(project_id).get("ports", [])
        krb_ips = sorted({p.get("ip") or p.get("host") for p in ports_now if int(p.get("port", 0)) == 88 and (p.get("ip") or p.get("host"))})
        for kip in krb_ips[:2]:
            kb_out = agent._run_cli(f"kerbrute version", log_fn, timeout=8, project_id=project_id)
            agent.db.log_task(project_id, "SPECTRE-Agent1", "kerbrute", "COMPLETED", f"kerbrute AD check on {kip}:88", kb_out[:200])


def run_deep_web_and_fuzz_tools(agent, project_id: int, url: str, dom: str, primary_host: str, is_high_val: bool, scope, active_ids: set, js_list: list, log_fn):
    import os
    import re
    import shlex

    safe_url = shlex.quote(url)
    safe_dom = shlex.quote(dom)

    # 4.2 WhatWeb Deep Aggression (-a 3 JSON Fingerprinter)
    if "whatweb" in active_ids and agent._find_binary("whatweb") and is_high_val:
        ww_json_file = f"/tmp/spectre_ww_{project_id}.json"
        try:
            if os.path.exists(ww_json_file):
                os.remove(ww_json_file)
        except Exception:
            pass
        log_fn(f"[Tool 4.2 -> WhatWeb Deep -a 3] {url} texnologik steki va plaginlari JSON formatda chuqur tahlil qilinmoqda...")
        ww_out = agent._run_cli(f"whatweb --color=never -a 3 --log-json={ww_json_file} {safe_url}", log_fn, timeout=30, project_id=project_id)
        ww_techs = []
        if os.path.exists(ww_json_file):
            try:
                raw_txt = open(ww_json_file, "r", errors="ignore").read().strip()
                for line in raw_txt.splitlines():
                    line = line.strip().rstrip(",")
                    if not line.startswith("{"):
                        continue
                    obj = json.loads(line)
                    plugins = obj.get("plugins", {})
                    for p_name, p_val in plugins.items():
                        if p_name in ("Title", "IP", "Country", "HTTPServer", "RedirectLocation", "UncommonHeaders", "Script", "HTML5"):
                            continue
                        vers = p_val.get("version", []) if isinstance(p_val, dict) else []
                        lbl = f"{p_name} {'/'.join(str(v) for v in vers[:2])}".strip()
                        if lbl and lbl not in ww_techs:
                            ww_techs.append(lbl)
            except Exception:
                pass
        if ww_techs:
            log_fn(f"  [🔬 WhatWeb Deep] {url} -> {', '.join(ww_techs[:10])}")
            agent.db.merge_http_tech_stack(project_id, url, ww_techs)
        agent.db.log_task(project_id, "SPECTRE-Agent1", "whatweb", "COMPLETED", f"whatweb -a 3 {url}", (", ".join(ww_techs) or ww_out)[:300])

    # 4.3 Wafw00f All-WAF Detector (-a)
    if "wafw00f" in active_ids and agent._find_binary("wafw00f") and dom == primary_host:
        log_fn(f"[Tool 4.3 -> Wafw00f Deep -a] {url} da barcha WAF qatlamlari tekshirilmoqda...")
        wf_out = agent._run_cli(f"wafw00f -a {safe_url}", log_fn, timeout=25, project_id=project_id)
        m_waf = re.search(r"is behind\s+([^\r\n(]+)", wf_out)
        if m_waf:
            waf_name = re.sub(r"\x1b\[[0-9;]*m", "", m_waf.group(1)).strip()
            log_fn(f"  [🛡️ Wafw00f] Aniqlangan WAF: {waf_name}")
            with agent.db._lock, agent.db._get_conn() as conn:
                conn.execute("UPDATE http_services SET waf=? WHERE project_id=? AND url=?", (waf_name[:80], project_id, url))
        agent.db.log_task(project_id, "SPECTRE-Agent1", "wafw00f", "COMPLETED", f"wafw00f -a {url}", wf_out[:250])

    # 5.1 Katana Deep JS & Form Crawler (-d 2 -jc -kf robotstxt -fs rdn -fx)
    if "katana" in active_ids and agent._find_binary("katana") and is_high_val:
        log_fn(f"[Tool 5.1 -> Katana Deep -d 2 -jc -fs rdn] {url} chuqur crawl qilinmoqda...")
        kt_out = agent._run_cli(
            f"katana -u {safe_url} -d 2 -jc -kf robotstxt -fs rdn -fx -timeout 5 -ct 15s -silent -ef woff,woff2,ttf,css,png,jpg,jpeg,gif,svg,ico -c 15",
            log_fn,
            timeout=25,
            project_id=project_id,
        )
        kt_cnt = 0
        for k_url in kt_out.splitlines():
            u = agent._record_discovered_url(project_id, k_url, url, scope, "katana_deep")
            if u:
                kt_cnt += 1
                if u.endswith(".js") and u not in js_list:
                    js_list.append(u)
        log_fn(f"  [+] Katana Deep yakunlandi: {kt_cnt} ta URL/form/JS topildi.")

    # 5.3 & 5.4 Waybackurls / GAU Historical Archive Miners
    if dom == primary_host:
        for hist_bin in ("waybackurls", "gau"):
            if hist_bin in active_ids and agent._find_binary(hist_bin):
                cmd = f"echo {safe_dom} | waybackurls" if hist_bin == "waybackurls" else f"gau {safe_dom} --subs --providers otx,urlscan --timeout 5"
                log_fn(f"[Tool 5 -> {hist_bin.upper()}] {dom} tarixiy arxiv URL'lari yig'ilmoqda...")
                h_out = agent._run_cli(cmd, log_fn, timeout=18, project_id=project_id)
                h_cnt = 0
                for h_url in h_out.splitlines()[:250]:
                    u = agent._record_discovered_url(project_id, h_url, url, scope, hist_bin)
                    if u:
                        h_cnt += 1
                        if u.endswith(".js") and u not in js_list:
                            js_list.append(u)
                log_fn(f"  [+] {hist_bin.upper()} yakunlandi: {h_cnt} ta tarixiy URL bazaga qo'shildi.")

    # 6.1 FFUF Auto-Calibrated SecLists Fuzzer (-ac -of json)
    seclists_common = "/home/amaqi/SecLists/Discovery/Web-Content/common.txt"
    is_fuzz_target = (dom == primary_host) or any(k in dom.split(".")[0].lower() for k in ("api", "admin", "my", "id", "auth", "sso", "portal"))
    if "ffuf" in active_ids and agent._find_binary("ffuf") and os.path.exists(seclists_common) and is_fuzz_target:
        ffuf_json = f"/tmp/spectre_ffuf_{project_id}.json"
        try:
            if os.path.exists(ffuf_json):
                os.remove(ffuf_json)
        except Exception:
            pass
        log_fn(f"[Tool 6.1 -> FFUF Auto-Calibrated (-ac) SecLists] {url}/FUZZ da 4,700+ yashirin katalog va fayllar qidirilmoqda...")
        agent._run_cli(
            f"ffuf -u {safe_url}/FUZZ -w {seclists_common} -mc 200,204,301,302,307,401,403,405 -ac -t 35 -maxtime 28 -of json -o {ffuf_json} -s",
            log_fn,
            timeout=34,
            project_id=project_id,
        )
        if os.path.exists(ffuf_json):
            try:
                f_data = json.load(open(ffuf_json, "r", errors="ignore"))
                results = f_data.get("results", [])
                for res in results[:60]:
                    f_url = res.get("url", "")
                    f_stat = int(res.get("status", 0))
                    f_len = int(res.get("length", 0))
                    if f_url:
                        agent._record_discovered_url(project_id, f_url, url, scope, f"ffuf_ac_{f_stat}")
                        log_fn(f"  [📂 FFUF Hit] HTTP {f_stat} ({f_len}B) -> {f_url}")
            except Exception as ex:
                log_fn(f"  [!] FFUF JSON parse ogohlantirish: {ex}")

    # 4.5 HTTProbe Fast Web Alive Verification
    if "httprobe" in active_ids and agent._find_binary("httprobe") and dom == primary_host:
        hp_out = agent._run_cli(f"echo {safe_dom} | httprobe -c 10 -t 3000", log_fn, timeout=12, project_id=project_id)
        for hp_u in hp_out.splitlines():
            if hp_u.strip().startswith("http"):
                agent._record_discovered_url(project_id, hp_u.strip(), url, scope, "httprobe")

    # 5.5 & 5.7 GoSpider & Waymore Redundant Crawlers (Primary Host)
    if "gospider" in active_ids and agent._find_binary("gospider") and dom == primary_host:
        log_fn(f"[Tool 5.5 -> GoSpider] {url} chuqur link va JS qidiruvi...")
        gs_out = agent._run_cli(f"gospider -s {safe_url} -d 2 -c 10 -t 5 --js -q", log_fn, timeout=22, project_id=project_id)
        for gs_line in gs_out.splitlines()[:120]:
            for m_u in re.findall(r"https?://[^\s\"'<>]+", gs_line):
                u = agent._record_discovered_url(project_id, m_u, url, scope, "gospider")
                if u and u.endswith(".js") and len(js_list) < 40 and u not in js_list:
                    js_list.append(u)

    if "waymore" in active_ids and agent._find_binary("waymore") and dom == primary_host:
        wm_out_file = f"/tmp/spectre_waymore_{project_id}.txt"
        agent._run_cli(f"waymore -i {safe_dom} -mode U -l 100 -oU {wm_out_file}", log_fn, timeout=22, project_id=project_id)
        if os.path.exists(wm_out_file):
            try:
                for w_u in open(wm_out_file, "r", errors="ignore").read().splitlines()[:120]:
                    u = agent._record_discovered_url(project_id, w_u.strip(), url, scope, "waymore")
                    if u and u.endswith(".js") and len(js_list) < 40 and u not in js_list:
                        js_list.append(u)
            except Exception:
                pass

    # 6.2, 6.3 & 6.4 Dirsearch / Gobuster / Wfuzz Backup Directory Fuzzers
    if dom == primary_host and os.path.exists(seclists_common):
        if "gobuster" in active_ids and agent._find_binary("gobuster") and "ffuf" not in active_ids:
            gb_out = agent._run_cli(f"gobuster dir -u {safe_url} -w {seclists_common} -t 30 -q --no-error -k", log_fn, timeout=28, project_id=project_id)
            for g_line in gb_out.splitlines():
                m_gb = re.search(r"^(/[^\s]+)\s+\(Status:\s*(\d+)", g_line.strip())
                if m_gb:
                    agent._record_discovered_url(project_id, m_gb.group(1), url, scope, f"gobuster_{m_gb.group(2)}")
        elif "dirsearch" in active_ids and agent._find_binary("dirsearch") and "ffuf" not in active_ids:
            ds_out = agent._run_cli(f"dirsearch -u {safe_url} -t 25 -q --format=simple", log_fn, timeout=28, project_id=project_id)
            for d_line in ds_out.splitlines():
                if d_line.strip().startswith("http"):
                    agent._record_discovered_url(project_id, d_line.strip(), url, scope, "dirsearch")
        elif "wfuzz" in active_ids and agent._find_binary("wfuzz") and "ffuf" not in active_ids:
            agent._run_cli(f"wfuzz -c -z file,{seclists_common} --hc 404,403 {safe_url}/FUZZ", log_fn, timeout=25, project_id=project_id)

    # 5.8 Arjun Hidden HTTP Parameter Miner
    if "arjun" in active_ids and agent._find_binary("arjun") and dom == primary_host:
        arjun_json = f"/tmp/spectre_arjun_{project_id}.json"
        try:
            if os.path.exists(arjun_json):
                os.remove(arjun_json)
        except Exception:
            pass
        log_fn(f"[Tool 5.8 -> Arjun Parameter Miner] {url} da yashirin GET parametrlar qidirilmoqda...")
        agent._run_cli(f"arjun -u {safe_url} -oJ {arjun_json} -q -t 10", log_fn, timeout=30, project_id=project_id)
        if os.path.exists(arjun_json):
            try:
                a_data = json.load(open(arjun_json, "r", errors="ignore"))
                for ep_u, ep_info in a_data.items():
                    params_found = ep_info.get("params", []) if isinstance(ep_info, dict) else []
                    if params_found:
                        log_fn(f"  [🎯 Arjun Hidden Params] {ep_u} -> {params_found}")
                        agent._record_discovered_url(project_id, ep_u, url, scope, "arjun_miner", extra_params=params_found)
            except Exception:
                pass


def run_deep_cloud_osint_and_vuln_tools(agent, project_id: int, apex_domain: str, primary_host: str, active_ids: set, log_fn):
    import os
    import re
    import shlex

    bundle = agent.db.get_project_bundle(project_id)

    # 9.1 S3Scanner Cloud Bucket Auditor
    if "s3scanner" in active_ids and agent._find_binary("s3scanner"):
        base_w = apex_domain.split(".")[0]
        b_file = f"/tmp/spectre_buckets_{project_id}.txt"
        open(b_file, "w").write("\n".join([base_w, f"{base_w}-media", f"{base_w}-static", f"{base_w}-backup", f"{base_w}-dev"]) + "\n")
        s3_out = agent._run_cli(f"s3scanner -bucket-file {b_file}", log_fn, timeout=20, project_id=project_id)
        for line in s3_out.splitlines():
            if "exists" in line.lower() and "not_exist" not in line.lower():
                agent.db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (S3Scanner)", f"Public Cloud Bucket Identified ({line[:60]})",
                    "Cloud Storage Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", apex_domain, line[:200],
                    "S3Scanner orqali tashkilot nomiga mos ochiq bulutli bucket aniqlandi.",
                    "Bucket ACL ruxsatlarini yoping.",
                )

    # 10.1 & 10.2 TruffleHog & Gitleaks on Workspace / Source Code & Downloaded JS Cache
    proj = bundle.get("project", {}) or {}
    scan_dirs = []
    if proj.get("source_code_path", "").strip() and os.path.isdir(proj.get("source_code_path", "").strip()):
        scan_dirs.append(proj.get("source_code_path", "").strip())
    js_cache_d = f"/tmp/spectre_js_cache_{project_id}"
    if os.path.isdir(js_cache_d) and os.listdir(js_cache_d):
        scan_dirs.append(js_cache_d)

    for scan_dir in scan_dirs:
        safe_dir = shlex.quote(scan_dir)
        if "trufflehog" in active_ids and agent._find_binary("trufflehog"):
            th_out = agent._run_cli(f"trufflehog filesystem {safe_dir} --no-update --json", log_fn, timeout=25, project_id=project_id)
            for tl in th_out.splitlines()[:30]:
                if tl.strip().startswith("{"):
                    try:
                        tobj = json.loads(tl)
                        det = tobj.get("DetectorName", "")
                        raw_s = str(tobj.get("Raw", "")).strip()[:80]
                        if not det or not raw_s:
                            continue
                        agent.db.upsert_finding(
                            project_id, "SPECTRE-Agent1 (TruffleHog)", f"[CONFIRMED] TruffleHog Verified Secret: {det}",
                            "Cryptographic / Secret Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            "CWE-798", "A07:2021 - Identification and Authentication Failures", scan_dir,
                            f"Detector: {det} | Sample: {raw_s}", "TruffleHog tomonidan kodda maxfiy kalit aniqlandi.",
                            "Kalitni darhol revoke qiling va Secret Manager ga o'tkazing.", confidence="Confirmed-PoC"
                        )
                    except Exception:
                        pass
        if "gitleaks" in active_ids and agent._find_binary("gitleaks"):
            gl_json = f"/tmp/spectre_gitleaks_{project_id}.json"
            agent._run_cli(f"gitleaks detect --no-git -s {safe_dir} -r {gl_json}", log_fn, timeout=25, project_id=project_id)
            if os.path.exists(gl_json):
                try:
                    for gitem in (json.load(open(gl_json, "r", errors="ignore")) or [])[:15]:
                        rule_id = gitem.get("RuleID", "Hardcoded-Secret")
                        f_path = gitem.get("File", scan_dir)
                        agent.db.upsert_finding(
                            project_id, "SPECTRE-Agent1 (Gitleaks)", f"[CONFIRMED] Gitleaks Secret Leak ({rule_id})",
                            "Cryptographic / Secret Exposure", "High", 8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                            "CWE-798", "A07:2021 - Identification and Authentication Failures", f_path,
                            f"Rule: {rule_id} | Match: {str(gitem.get('Match', ''))[:90]}",
                            "Gitleaks tomonidan manba kodida hardcoded kalit aniqlandi.", "Kalitni koddan o'chiring va yangilang.", confidence="Confirmed-PoC"
                        )
                except Exception:
                    pass

    # 12.1 Holehe Corporate Email OSINT Account Checker
    if "holehe" in active_ids and agent._find_binary("holehe"):
        for f in bundle.get("findings", []):
            if "Email" in f.get("title", ""):
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@" + re.escape(apex_domain), f.get("evidence", ""))
                for em in emails[:2]:
                    hh_out = agent._run_cli(f"holehe {shlex.quote(em)} --only-used --no-color", log_fn, timeout=20, project_id=project_id)
                    used_svcs = [l.strip() for l in hh_out.splitlines() if "[+]" in l]
                    if used_svcs:
                        agent.db.log_task(project_id, "SPECTRE-Agent1", "holehe", "COMPLETED", f"holehe {em}", ", ".join(used_svcs[:10]))

    # 14.1 Nuclei Fast Exposure & Misconfiguration Scanner (Top 6 Live Web Services)
    if "nuclei" in active_ids and agent._find_binary("nuclei"):
        svcs = [s["url"] for s in bundle.get("http_services", []) if int(s.get("status_code") or 0) in (200, 401, 403)][:6]
        if not svcs:
            svcs = [f"https://{primary_host}"]
        nuc_list_file = f"/tmp/spectre_nuclei_targets_{project_id}.txt"
        open(nuc_list_file, "w").write("\n".join(svcs) + "\n")
        log_fn(f"[Tool 14.1 -> Nuclei Scanner] {len(svcs)} ta asosiy servisda miskonfiguratsiya, ochiq panel va CVE shablonlari tekshirilmoqda...")
        nuc_out = agent._run_cli(
            f"nuclei -l {nuc_list_file} -tags exposure,misconfig,panel,token -severity low,medium,high,critical -silent -jsonl -timeout 4 -c 25",
            log_fn,
            timeout=45,
            project_id=project_id,
        )
        for nl in nuc_out.splitlines():
            if nl.strip().startswith("{"):
                try:
                    nobj = json.loads(nl.strip())
                    t_id = nobj.get("template-id", "nuclei-hit")
                    info = nobj.get("info", {})
                    n_name = info.get("name", t_id)
                    n_sev = str(info.get("severity", "medium")).capitalize()
                    matched_at = nobj.get("matched-at", svcs[0])
                    cvss_map = {"Critical": 9.3, "High": 8.1, "Medium": 6.1, "Low": 3.7}
                    if n_sev in cvss_map:
                        agent.db.upsert_finding(
                            project_id, "SPECTRE-Agent1 (Nuclei)", f"[CONFIRMED] Nuclei: {n_name} ({t_id})",
                            "Nuclei Active Scan", n_sev, cvss_map[n_sev], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                            "CWE-200", "A05:2021 - Security Misconfiguration", matched_at,
                            f"Template: {t_id} | Matched: {matched_at}",
                            info.get("description") or f"Nuclei '{t_id}' shabloni bo'yicha zaiflik tasdiqlandi.",
                            info.get("remediation") or "Nuclei tavsiyasiga asosan miskonfiguratsiyani yoping.",
                            confidence="Confirmed-PoC",
                        )
                        log_fn(f"  [🚨 NUCLEI HIT] [{n_sev}] {n_name} -> {matched_at}")
                except Exception:
                    pass

    # 14.2 Dalfox Parameter & DOM XSS Analyzer
    if "dalfox" in active_ids and agent._find_binary("dalfox"):
        param_eps = [e for e in bundle.get("endpoints", []) if json.loads(e.get("params_json") or "[]")][:3]
        for pep in param_eps:
            p_list = json.loads(pep.get("params_json") or "[]")
            q_str = "&".join(f"{k}=spectre" for k in p_list[:3])
            full_p_url = f"{pep['url']}?{q_str}"
            log_fn(f"[Tool 14.2 -> Dalfox XSS Scanner] {full_p_url} da XSS va DOM sinklar tekshirilmoqda...")
            df_out = agent._run_cli(f"dalfox url {shlex.quote(full_p_url)} --silence --no-color --skip-bav", log_fn, timeout=22, project_id=project_id)
            for dl in df_out.splitlines():
                if "[V]" in dl or "[POC]" in dl:
                    agent.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (Dalfox XSS)", f"[CONFIRMED] Dalfox Verified XSS on {pep['url']}",
                        "Cross-Site Scripting (XSS)", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                        "CWE-79", "A03:2021 - Injection", pep["url"], dl.strip()[:250],
                        "Dalfox skaneri tomonidan XSS payload bajarilishi tasdiqlandi.",
                        "Kontekstli HTML encoding va qat'iy CSP qo'llang.", confidence="Confirmed-PoC"
                    )
                    log_fn(f"  [🚨 DALFOX XSS CONFIRMED] {dl.strip()[:140]}")









