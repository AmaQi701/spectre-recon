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


# ================= #8 DEEP MULTI-TOOL EXECUTION & STRUCTURED PARSERS (v7.0) =================
def run_deep_subdomain_tools(agent, project_id: int, apex_domain: str, scope, active_ids: set, log_fn):
    import os
    import re
    import shlex

    safe_apex = shlex.quote(apex_domain)

    # 1.2 Subfinder (-all -recursive)
    if "subfinder" in active_ids and agent._find_binary("subfinder"):
        log_fn(f"[Tool 1.2 -> Subfinder Deep] Barcha passiv manbalardan (-all) subdomenlar yig'ilmoqda: {apex_domain}...")
        out = agent._run_cli(f"subfinder -d {safe_apex} -all -silent", log_fn, timeout=50, project_id=project_id)
        cnt = 0
        for line in out.splitlines():
            h = line.strip().lower().rstrip(".")
            if h and scope.is_in_scope(h)[0]:
                agent.db.upsert_domain(project_id, h, source="subfinder_deep")
                cnt += 1
        log_fn(f"  [+] Subfinder Deep yakunlandi: {cnt} ta subdomen bazaga qo'shildi.")

    # 1.3 Sublist3r
    if "sublist3r" in active_ids and agent._find_binary("sublist3r"):
        out_file = f"/tmp/spectre_sublist3r_{project_id}.txt"
        try:
            if os.path.exists(out_file):
                os.remove(out_file)
        except Exception:
            pass
        log_fn(f"[Tool 1.3 -> Sublist3r] Qidiruv tizimlari orqali subdomenlar qidirilmoqda: {apex_domain}...")
        agent._run_cli(f"sublist3r -d {safe_apex} -n -o {out_file}", log_fn, timeout=45, project_id=project_id)
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

    # 1.4 OWASP Amass (Passive Graph)
    if "amass" in active_ids and agent._find_binary("amass"):
        log_fn(f"[Tool 1.4 -> OWASP Amass] Passiv ASN va subdomen grafigi tuzilmoqda: {apex_domain}...")
        out = agent._run_cli(f"amass enum -passive -d {safe_apex} -timeout 1", log_fn, timeout=65, project_id=project_id)
        cnt = 0
        for m in re.findall(r"(?:[a-zA-Z0-9\-]+\.)+" + re.escape(apex_domain), out):
            h = m.lower().strip(".")
            if scope.is_in_scope(h)[0]:
                agent.db.upsert_domain(project_id, h, source="amass_passive")
                cnt += 1
        log_fn(f"  [+] OWASP Amass yakunlandi: {cnt} ta subdomen ajratib olindi.")

    # 1.5 Assetfinder
    if "assetfinder" in active_ids and agent._find_binary("assetfinder"):
        log_fn(f"[Tool 1.5 -> Assetfinder] Qo'shimcha passiv manbalar tekshirilmoqda: {apex_domain}...")
        out = agent._run_cli(f"assetfinder --subs-only {safe_apex}", log_fn, timeout=30, project_id=project_id)
        cnt = 0
        for line in out.splitlines():
            h = line.strip().lower().rstrip(".")
            if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                agent.db.upsert_domain(project_id, h, source="assetfinder")
                cnt += 1
        log_fn(f"  [+] Assetfinder yakunlandi: {cnt} ta subdomen topildi.")

    # 1.6 Cero (SSL/TLS SAN Certificate Domain Hunter)
    if "cero" in active_ids and agent._find_binary("cero"):
        log_fn(f"[Tool 1.6 -> Cero TLS SAN Hunter] Sertifikat X.509 SAN yozuvlaridan domenlar qidirilmoqda: {apex_domain}...")
        out = agent._run_cli(f"cero {safe_apex}", log_fn, timeout=20, project_id=project_id)
        cnt = 0
        for line in out.splitlines():
            h = line.strip().lower().lstrip("*.").rstrip(".")
            if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                agent.db.upsert_domain(project_id, h, source="cero_tls")
                cnt += 1
        log_fn(f"  [+] Cero yakunlandi: {cnt} ta SAN subdomen topildi.")

    # 1.8 Findomain (Rust Subdomain Scanner)
    if "findomain" in active_ids and agent._find_binary("findomain"):
        log_fn(f"[Tool 1.8 -> Findomain Rust Scanner] Yuqori tezlikda subdomenlar yig'ilmoqda: {apex_domain}...")
        out = agent._run_cli(f"findomain -t {safe_apex} -q", log_fn, timeout=25, project_id=project_id)
        cnt = 0
        for line in out.splitlines():
            h = line.strip().lower().rstrip(".")
            if h and h.endswith(apex_domain) and scope.is_in_scope(h)[0]:
                agent.db.upsert_domain(project_id, h, source="findomain")
                cnt += 1
        log_fn(f"  [+] Findomain yakunlandi: {cnt} ta subdomen topildi.")

    # 2.2 ProjectDiscovery DNSX Multi-Record Verification
    if "dnsx" in active_ids and agent._find_binary("dnsx"):
        doms_now = [d["domain"] for d in agent.db.get_project_bundle(project_id).get("domains", [])]
        if doms_now:
            dom_file = f"/tmp/spectre_dnsx_in_{project_id}.txt"
            open(dom_file, "w").write("\n".join(doms_now[:150]) + "\n")
            log_fn(f"[Tool 2.2 -> ProjectDiscovery DNSX] {len(doms_now[:150])} ta subdomen A/CNAME yozuvlari tezkor tekshirilmoqda...")
            dx_out = agent._run_cli(f"dnsx -l {dom_file} -a -cname -resp -silent", log_fn, timeout=25, project_id=project_id)
            for line in dx_out.splitlines():
                clean_l = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                parts = clean_l.split()
                if len(parts) >= 3 and "[A]" in clean_l:
                    h = parts[0].strip().lower()
                    ip_val = parts[-1].strip("[]")
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_val) and scope.is_in_scope(h)[0]:
                        agent.db.upsert_domain(project_id, h, ip=ip_val, source="dnsx_verified")

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


def run_deep_network_and_ad_tools(agent, project_id: int, primary_host: str, active_ids: set, log_fn):
    import shlex
    import xml.etree.ElementTree as ET

    bundle = agent.db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])

    # 3.1 Nmap Deep NSE Recon Scanner (Primary Host + Top Origin IPs)
    if "nmap" in active_ids and agent._find_binary("nmap"):
        nmap_targets = [primary_host]
        for d in domains:
            ip = d.get("ip", "")
            cdn = str(d.get("cdn_waf", "")).lower()
            if ip and "cloudflare" not in cdn and ip not in nmap_targets and len(nmap_targets) < 3:
                nmap_targets.append(ip)

        for n_target in nmap_targets:
            if project_id in agent.abort_flags:
                break
            safe_t = shlex.quote(n_target)
            log_fn(f"[Tool 3.1 -> Nmap Deep NSE] {n_target} da servis versiyalari va NSE razvedka skriptlari (-sV --script=banner,http-title,ssl-cert,ftp-anon,smb-os-discovery) ishga tushirilmoqda...")
            xml_out = agent._run_cli(
                f"nmap -Pn -sV -T4 --top-ports 100 --script=banner,http-title,http-headers,http-methods,ssl-cert,ftp-anon,smb-os-discovery,smb-protocols -oX - {safe_t}",
                log_fn,
                timeout=85,
                project_id=project_id,
            )
            if "<nmaprun" in xml_out:
                try:
                    s = xml_out.find("<nmaprun")
                    e = xml_out.rfind("</nmaprun>")
                    root = ET.fromstring(xml_out[s : e + 10])
                    for h in root.findall("host"):
                        addr_el = h.find("address")
                        ip_addr = addr_el.get("addr", "") if addr_el is not None else n_target
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
                                            project_id, "SPECTRE-Agent1 (Nmap NSE)", f"Anonymous FTP Login Enabled on {n_target}:{port_id}",
                                            "Authentication Bypass", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                            "CWE-287", "A07:2021 - Identification and Authentication Failures", f"{n_target}:{port_id}",
                                            sout[:500], "FTP serverda anonim (parolsiz) kirish ruxsat etilgan.", "FTP konfiguratsiyasida anonymous_enable=NO qiling.",
                                        )
                                full_ver = f"{product} {ver} {extra} {' '.join(nse_notes[:2])}".strip()
                                agent.db.upsert_port(project_id, n_target, port_id, proto, ip=ip_addr, service=svc_name, version=full_ver[:220], source="nmap_deep_nse")
                                log_fn(f"  [🔬 Nmap Deep] {n_target}:{port_id}/{proto} -> {svc_name} | {full_ver[:120]}")
                except Exception as ex:
                    log_fn(f"  [!] Nmap Deep XML parse ogohlantirish: {ex}")

    # 3.2 Naabu Fast Top-1000 Port Scanner
    if "naabu" in active_ids and agent._find_binary("naabu"):
        log_fn(f"[Tool 3.2 -> Naabu] {primary_host} da Top-1000 portlar tezkor tekshirilmoqda...")
        nb_out = agent._run_cli(f"naabu -host {shlex.quote(primary_host)} -top-ports 1000 -silent", log_fn, timeout=45, project_id=project_id)
        for line in nb_out.splitlines():
            if ":" in line:
                h_part, p_part = line.strip().rsplit(":", 1)
                if p_part.isdigit():
                    agent.db.upsert_port(project_id, h_part, int(p_part), "tcp", service="tcp-open", source="naabu")

    # 13.1 NetExec (nxc) SMB & SSH Deep Service / AD Domain Inspector
    nxc_bin = agent._find_binary("nxc") or agent._find_binary("netexec")
    if "netexec" in active_ids and nxc_bin:
        ports_now = agent.db.get_project_bundle(project_id).get("ports", [])
        smb_ips = sorted({p.get("ip") or p.get("host") for p in ports_now if int(p.get("port", 0)) == 445 and (p.get("ip") or p.get("host"))})
        for sip in smb_ips[:3]:
            log_fn(f"[Tool 13.1 -> NetExec (nxc) SMB] {sip}:445 da OS versiyasi, Domain nomi va SMB Signing tekshirilmoqda...")
            nxc_out = agent._run_cli(f"{nxc_bin} smb {shlex.quote(sip)}", log_fn, timeout=20, project_id=project_id)
            if nxc_out.strip():
                clean_line = nxc_out.strip().splitlines()[-1]
                log_fn(f"  [🛡️ NetExec SMB] {clean_line}")
                agent.db.upsert_port(project_id, sip, 445, "tcp", ip=sip, service="microsoft-ds", version=clean_line[:200], source="netexec_smb")
                if "signing:false" in clean_line.lower():
                    agent.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (NetExec SMB)", f"SMB Signing Not Required on {sip}:445 (NTLM Relay Vector)",
                        "Network Protocol Misconfiguration", "Medium", 6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "CWE-300", "A05:2021 - Security Misconfiguration", f"{sip}:445",
                        clean_line, "SMB serverda raqamli imzo (SMB Signing) majburiy emas — bu NTLM Relay hujumlariga yo'l ochadi.",
                        "GPO yoki smb.conf orqali SMB Signing'ni majburiy (server signing = mandatory) qiling.",
                    )


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
            with agent.db._lock:
                row = agent.db._conn.execute("SELECT tech_stack_json FROM http_services WHERE project_id=? AND url=?", (project_id, url)).fetchone()
                if row:
                    cur_t = json.loads(row["tech_stack_json"] or "[]")
                    merged = list(dict.fromkeys(cur_t + ww_techs))
                    agent.db._conn.execute("UPDATE http_services SET tech_stack_json=? WHERE project_id=? AND url=?", (json.dumps(merged), project_id, url))
                    agent.db._conn.commit()
        agent.db.log_task(project_id, "SPECTRE-Agent1", "whatweb", "COMPLETED", f"whatweb -a 3 {url}", (", ".join(ww_techs) or ww_out)[:300])

    # 4.3 Wafw00f All-WAF Detector (-a)
    if "wafw00f" in active_ids and agent._find_binary("wafw00f") and dom == primary_host:
        log_fn(f"[Tool 4.3 -> Wafw00f Deep -a] {url} da barcha WAF qatlamlari tekshirilmoqda...")
        wf_out = agent._run_cli(f"wafw00f -a {safe_url}", log_fn, timeout=25, project_id=project_id)
        m_waf = re.search(r"is behind\s+([^\r\n(]+)", wf_out)
        if m_waf:
            waf_name = re.sub(r"\x1b\[[0-9;]*m", "", m_waf.group(1)).strip()
            log_fn(f"  [🛡️ Wafw00f] Aniqlangan WAF: {waf_name}")
            with agent.db._lock:
                agent.db._conn.execute("UPDATE http_services SET waf=? WHERE project_id=? AND url=?", (waf_name[:80], project_id, url))
                agent.db._conn.commit()
        agent.db.log_task(project_id, "SPECTRE-Agent1", "wafw00f", "COMPLETED", f"wafw00f -a {url}", wf_out[:250])

    # 5.1 Katana Deep JS & Form Crawler (-d 3 -jc -kf all -fx)
    if "katana" in active_ids and agent._find_binary("katana") and is_high_val:
        log_fn(f"[Tool 5.1 -> Katana Deep -d 3 -jc -kf all -fx] {url} chuqur crawl qilinmoqda...")
        kt_out = agent._run_cli(
            f"katana -u {safe_url} -d 3 -jc -kf all -fx -silent -ef woff,woff2,ttf,css,png,jpg,jpeg,gif,svg,ico -c 15",
            log_fn,
            timeout=42,
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
                cmd = f"waybackurls {safe_dom}" if hist_bin == "waybackurls" else f"gau {safe_dom} --subs"
                log_fn(f"[Tool 5 -> {hist_bin.upper()}] {dom} tarixiy arxiv URL'lari yig'ilmoqda...")
                h_out = agent._run_cli(cmd, log_fn, timeout=30, project_id=project_id)
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
    if "ffuf" in active_ids and agent._find_binary("ffuf") and os.path.exists(seclists_common) and dom == primary_host:
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

    # 4.4 ProjectDiscovery HTTPX JSON Tech & Header Enricher
    if "httpx" in active_ids and agent._find_binary("httpx") and is_high_val:
        hx_bin = agent._find_binary("httpx")
        hx_out = agent._run_cli(f"{hx_bin} -u {safe_url} -silent -title -tech-detect -status-code -server -json", log_fn, timeout=20, project_id=project_id)
        for line in hx_out.splitlines():
            if line.strip().startswith("{"):
                try:
                    hx_obj = json.loads(line.strip())
                    hx_techs = hx_obj.get("tech", [])
                    if hx_techs:
                        log_fn(f"  [⚡ HTTPX Tech] {url} -> {', '.join(hx_techs[:8])}")
                        with agent.db._lock:
                            row = agent.db._conn.execute("SELECT tech_stack_json FROM http_services WHERE project_id=? AND url=?", (project_id, url)).fetchone()
                            if row:
                                cur_t = json.loads(row["tech_stack_json"] or "[]")
                                merged = list(dict.fromkeys(cur_t + hx_techs))
                                agent.db._conn.execute("UPDATE http_services SET tech_stack_json=? WHERE project_id=? AND url=?", (json.dumps(merged), project_id, url))
                                agent.db._conn.commit()
                except Exception:
                    pass

    # 5.5 & 5.6 GoSpider & Hakrawler Redundant Crawler Layers
    if "hakrawler" in active_ids and agent._find_binary("hakrawler") and dom == primary_host:
        log_fn(f"[Tool 5.6 -> Hakrawler] {url} qo'shimcha endpoint va JS linklari yig'ilmoqda...")
        hk_out = agent._run_cli(f"echo {safe_url} | hakrawler -d 2 -subs -u", log_fn, timeout=25, project_id=project_id)
        for hk_url in hk_out.splitlines()[:120]:
            u = agent._record_discovered_url(project_id, hk_url, url, scope, "hakrawler")
            if u and u.endswith(".js") and u not in js_list:
                js_list.append(u)

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









