import concurrent.futures
import json
import os
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

import dns.resolver
import requests
import yaml
from bs4 import BeautifulSoup, Comment

from core.database import DatabaseManager
from core.scope_guard import ScopeGuard
from agents import spectre_deep_modules, spectre_v5_modules, spectre_ultra_modules

urllib3_disable = getattr(requests.packages, "urllib3", None)
if urllib3_disable:
    urllib3_disable.disable_warnings()


class ReconSuperAgent:
    """
    1-SuperAgent: Autonomous Recon & Attack Surface Mapper.
    YAML Registry dagi barcha CLI vositalarni va ichki (built-in) razvedka
    modullarini 6 bosqichda boshqaradi va natijalarni SQLite Asset Graph ga yozadi.
    """

    EXTRA_PATHS = [
        "/home/amaqi/go/bin",
        "/home/amaqi/.local/bin",
        "/snap/bin",
        "/usr/local/bin",
        "/usr/bin",
    ]

    COMMON_SUBDOMAINS = [
        "www", "api", "dev", "staging", "stage", "test", "admin", "portal",
        "mail", "webmail", "smtp", "pop", "imap", "vpn", "auth", "sso", "id",
        "beta", "cdn", "static", "media", "files", "storage", "s3", "minio",
        "docs", "app", "my", "cabinet", "client", "dashboard", "cp", "panel",
        "internal", "intranet", "git", "gitlab", "jenkins", "ci", "grafana",
        "kibana", "prometheus", "status", "monitor", "m", "mobile", "old",
        "new", "v1", "v2", "back", "backend", "cms", "crm", "erp", "pay",
        "billing", "live", "stream", "tv", "radio", "news", "press", "db"
    ]

    API_DOC_PATHS = [
        "/robots.txt", "/sitemap.xml", "/swagger.json", "/openapi.json",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
        "/api-docs", "/swagger-ui.html", "/graphql", "/api/graphql",
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/.env", "/.git/HEAD", "/.git/config", "/config.json", "/config.js",
        "/env.js", "/settings.json", "/phpinfo.php", "/server-status",
        "/nginx_status", "/actuator", "/actuator/health", "/actuator/env",
        "/wp-json/wp/v2/users", "/wp-login.php", "/_debugbar", "/telescope",
        "/crossdomain.xml", "/admin", "/api", "/api/v1", "/backup.zip"
    ]

    def __init__(self, db: DatabaseManager, registry_path: str = "/home/amaqi/projects/apex-pentest-gui/config/tools_registry.yaml"):
        self.db = db
        self.registry_path = Path(registry_path)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "APEX-ASM-Security-Audit/2.0"})
        self.active_procs: dict[int, list[subprocess.Popen]] = {}
        self.abort_flags: set[int] = set()

    def abort_project(self, project_id: int, log_fn=None):
        self.abort_flags.add(project_id)
        procs = self.active_procs.get(project_id, [])
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self.active_procs[project_id] = []
        if log_fn:
            log_fn("[ABORT] 🛑 Barcha faol razvedka jarayonlari foydalanuvchi tomonidan to'xtatildi.")


    def _find_binary(self, binary_name: str) -> str | None:
        if binary_name == "builtin":
            return "builtin"
        found = shutil.which(binary_name)
        if found:
            return found
        for p in self.EXTRA_PATHS:
            candidate = Path(p) / binary_name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def get_tools_status(self) -> list[dict]:
        if not self.registry_path.exists():
            return []
        data = yaml.safe_load(self.registry_path.read_text(encoding="utf-8")) or {}
        tools = data.get("tools", [])
        result = []
        for t in tools:
            bin_path = self._find_binary(t.get("binary", ""))
            t_copy = dict(t)
            t_copy["installed"] = bin_path is not None
            t_copy["resolved_path"] = bin_path or "Not Installed"
            result.append(t_copy)
        return result

    def save_custom_tool(self, tool_data: dict):
        data = yaml.safe_load(self.registry_path.read_text(encoding="utf-8")) or {"version": "2.0", "tools": []}
        tools = [t for t in data.get("tools", []) if t.get("id") != tool_data.get("id")]
        tools.append(tool_data)
        data["tools"] = tools
        self.registry_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")

    def toggle_tool(self, tool_id: str, enabled: bool):
        data = yaml.safe_load(self.registry_path.read_text(encoding="utf-8")) or {}
        for t in data.get("tools", []):
            if t.get("id") == tool_id:
                t["enabled"] = bool(enabled)
        self.registry_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")

    def _run_cli(self, cmd: str, log_fn, timeout: int = 45, project_id: int = 0) -> str:
        if project_id in self.abort_flags:
            return ""
        env = os.environ.copy()
        env["PATH"] = ":".join(self.EXTRA_PATHS) + ":" + env.get("PATH", "")
        log_fn(f"[CMD] $ {cmd}")
        proc = None
        timed_out = False

        def _watchdog_kill():
            nonlocal timed_out
            timed_out = True
            if proc and proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        timer = threading.Timer(timeout, _watchdog_kill)
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                preexec_fn=os.setsid,
            )
            timer.start()
            if project_id:
                self.active_procs.setdefault(project_id, []).append(proc)
            output_lines = []
            if proc.stdout:
                for line in proc.stdout:
                    if project_id in self.abort_flags or timed_out:
                        break
                    clean_line = line.rstrip()
                    if clean_line:
                        output_lines.append(clean_line)
                        if len(output_lines) <= 45:
                            log_fn(f"  │ {clean_line[:160]}")
            proc.wait(timeout=3)
            if timed_out:
                log_fn(f"[WARN] Command timeout ({timeout}s), davom etilmoqda: {cmd}")
            return "\n".join(output_lines)
        except Exception as e:
            if not timed_out:
                log_fn(f"[WARN] CLI yakunlandi: {e}")
            return ""
        finally:
            timer.cancel()



    # ================= STAGE 1: MULTI-SOURCE PASSIVE OSINT & DNS =================
    def _stage1_crtsh(self, project_id: int, domain: str, scope: ScopeGuard, log_fn):
        log_fn(f"[SPECTRE Stage 1] 5 ta Global OSINT Baza (CRT.sh, AlienVault OTX, HackerTarget, URLScan, Anubis) parallel qidiruvi: {domain}")
        discovered = set()

        def fetch_crtsh():
            try:
                r = self.session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=12)
                if r.status_code == 200:
                    for item in r.json():
                        for sub in str(item.get("name_value", "")).splitlines():
                            discovered.add((sub.strip().lower().lstrip("*."), "crt.sh"))
            except Exception:
                pass

        def fetch_otx():
            try:
                r = self.session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=12)
                if r.status_code == 200:
                    for row in r.json().get("passive_dns", []):
                        h = str(row.get("hostname", "")).strip().lower()
                        if h:
                            discovered.add((h, "alienvault_otx"))
            except Exception:
                pass

        def fetch_hackertarget():
            try:
                r = self.session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
                if r.status_code == 200 and "error" not in r.text.lower():
                    for line in r.text.splitlines():
                        parts = line.split(",")
                        if parts and "." in parts[0]:
                            discovered.add((parts[0].strip().lower(), "hackertarget"))
            except Exception:
                pass

        def fetch_urlscan():
            try:
                r = self.session.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=10)
                if r.status_code == 200:
                    for res in r.json().get("results", []):
                        d_val = str(res.get("page", {}).get("domain", "")).strip().lower()
                        if d_val:
                            discovered.add((d_val, "urlscan.io"))
            except Exception:
                pass

        def fetch_anubis():
            try:
                r = self.session.get(f"https://jonlu.ca/anubis/subdomains/{domain}", timeout=10)
                if r.status_code == 200 and isinstance(r.json(), list):
                    for sub in r.json():
                        discovered.add((str(sub).strip().lower(), "anubis_db"))
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(fn) for fn in (fetch_crtsh, fetch_otx, fetch_hackertarget, fetch_urlscan, fetch_anubis)]
            concurrent.futures.wait(futures, timeout=16)

        added = 0
        for sub, src in sorted(discovered):
            if "." in sub and scope.is_in_scope(sub)[0]:
                self.db.upsert_domain(project_id, sub, source=src)
                added += 1
        log_fn(f"  [+] Passive OSINT Mesh yakunlandi: {added} ta in-scope subdomen bazaga qo'shildi.")


    def _stage1_dns_enum(self, project_id: int, base_domain: str, scope: ScopeGuard, log_fn):
        apex_domain = ScopeGuard.extract_apex_domain(base_domain)
        candidates = {base_domain, apex_domain}
        for prefix in self.COMMON_SUBDOMAINS:
            candidates.add(f"{prefix}.{apex_domain}")

        # Load top 220 prefixes from SecLists if available on system
        seclist_dns = Path("/home/amaqi/SecLists/Discovery/DNS/subdomains-top1million-5000.txt")
        if seclist_dns.exists():
            try:
                for line in seclist_dns.read_text(encoding="utf-8", errors="ignore").splitlines()[:220]:
                    w = line.strip().lower()
                    if w and not w.startswith("#"):
                        candidates.add(f"{w}.{apex_domain}")
            except Exception:
                pass

        for reg_p in ("1c", "bitrix", "edo", "hr", "jira", "confluence", "payme", "click", "uzum", "accounts", "svc", "vod", "upload", "open", "reja", "zakovat", "fikr"):
            candidates.add(f"{reg_p}.{apex_domain}")

        existing = self.db.get_project_bundle(project_id).get("domains", [])
        for d in existing:
            candidates.add(d["domain"])
        log_fn(f"[Stage 1] Chuqur DNS yozuvlari va {len(candidates)} ta subdomen (SecLists + Regional) parallel tekshiruvi: {apex_domain}")


        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0

        wildcard_ips = set()
        try:
            w_ans = resolver.resolve(f"apex-wildcard-probe-918273.{apex_domain}", "A")
            wildcard_ips = {str(r).rstrip(".") for r in w_ans}
            if wildcard_ips:
                log_fn(f"  [!] Wildcard DNS aniqlandi (*.{apex_domain} -> {', '.join(wildcard_ips)}). Yolg'on subdomenlar filtrlanadi.")
        except Exception:
            pass

        def check_candidate(cand: str):
            ok, _ = scope.is_in_scope(cand)
            if not ok:
                return
            records = {}
            ip_val = ""
            cname_val = ""
            rtypes = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA") if cand in (base_domain, apex_domain) else ("A", "CNAME")
            for rtype in rtypes:
                try:
                    ans = resolver.resolve(cand, rtype)
                    vals = [str(r).rstrip(".") for r in ans]
                    records[rtype] = vals
                    if rtype == "A" and vals:
                        ip_val = vals[0]
                    elif rtype == "CNAME" and vals:
                        cname_val = vals[0]
                    elif rtype == "MX":
                        for mx_v in vals:
                            mx_host = mx_v.split()[-1].rstrip(".").lower()
                            if scope.is_in_scope(mx_host)[0]:
                                self.db.upsert_domain(project_id, mx_host, source="dns_mx")
                    elif rtype == "TXT":
                        for txt_v in vals:
                            if "v=spf1" in txt_v.lower():
                                spf_ips = re.findall(r"ip4:([0-9./]+)", txt_v)
                                spf_inc = re.findall(r"include:([a-zA-Z0-9.\-_]+)", txt_v)
                                if spf_ips or spf_inc:
                                    self.db.upsert_finding(
                                        project_id, "SPECTRE-Agent1 (SPF-Intel)", f"SPF Network & Mail Infrastructure Intelligence ({cand})",
                                        "Infrastructure Intelligence", "Low", 2.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                        "CWE-200", "A05:2021 - Security Misconfiguration", cand,
                                        f"SPF IPs/Subnets: {', '.join(spf_ips) or 'None'} | Includes: {', '.join(spf_inc) or 'None'} | Raw: {txt_v[:140]}",
                                        "DNS TXT (SPF) yozuvi orqali tashkilotning rasmiy pochta va server tarmoqlari aniqlandi.",
                                        "SPF yozuvida eskirgan yoki ichki test IP diapazonlari qolib ketmaganini tekshiring.",
                                    )
                                for inc_h in spf_inc:
                                    if scope.is_in_scope(inc_h)[0]:
                                        self.db.upsert_domain(project_id, inc_h, source="dns_spf")
                except Exception:
                    pass

            if cand not in (base_domain, apex_domain) and ip_val and ip_val in wildcard_ips:
                return
            if cname_val and not ip_val:
                takeover_sigs = ("github.io", "herokuapp.com", "s3.amazonaws.com", "azurewebsites.net", "vercel.app", "netlify.app", "digitaloceanspaces.com", "trafficmanager.net")
                if any(sig in cname_val.lower() for sig in takeover_sigs):
                    self.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (Takeover)", f"Potential Subdomain Takeover (Dangling CNAME: {cand})",
                        "Subdomain Takeover", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
                        "CWE-350", "A05:2021 - Security Misconfiguration", cand,
                        f"Subdomain: {cand} -> CNAME: {cname_val} (No A Record / NXDOMAIN)",
                        "Subdomen CNAME yozuvi tashqi bulutli servisga yo'naltirilgan, ammo u yerda resurs o'chirilgan.",
                        "DNS zonasidan eskirgan CNAME yozuvini o'chiring yoki tashqi servisda nomni band qiling.",
                    )
                    log_fn(f"  [🚨 TAKEOVER] Dangling CNAME aniqlandi: {cand} -> {cname_val}")
            if records:
                cdn = "Cloudflare" if any("cloudflare" in str(v).lower() for v in records.values()) else ""
                self.db.upsert_domain(project_id, cand, ip=ip_val, cname=cname_val, records=records, cdn_waf=cdn, source="dns_enum")
                if ip_val or cname_val:
                    log_fn(f"  [+] DNS Active: {cand} -> {ip_val or cname_val} {f'(Records: {list(records.keys())})' if len(records)>1 else ''}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            list(ex.map(check_candidate, sorted(candidates)))

        # Smart Subdomain Permutation Pass (like alterx / dnsgen)
        active_subs = [d["domain"] for d in self.db.get_project_bundle(project_id).get("domains", []) if d.get("ip") and d["domain"] != apex_domain]
        perm_candidates = set()
        for sub in active_subs[:10]:
            prefix = sub.replace("." + apex_domain, "").split(".")[0]
            if prefix and prefix not in ("www", "mail"):
                for mut in (f"{prefix}-dev", f"{prefix}-stage", f"{prefix}-test", f"{prefix}-v2", f"dev-{prefix}", f"old-{prefix}", f"admin-{prefix}"):
                    perm_candidates.add(f"{mut}.{apex_domain}")
        if perm_candidates:
            log_fn(f"[SPECTRE Smart Mutator] Topilgan faol subdomenlar asosida {len(perm_candidates)} ta mutatsiya (dev/stage/v2/old) tekshirilmoqda...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
                list(ex.map(check_candidate, sorted(perm_candidates)))


    def _stage2_shodan_internetdb(self, project_id: int, scope: ScopeGuard, log_fn):
        domains = self.db.get_project_bundle(project_id).get("domains", [])
        ip_to_hosts: dict[str, list[str]] = {}
        for d in domains:
            ip = d.get("ip", "").strip()
            if ip:
                ip_to_hosts.setdefault(ip, []).append(d["domain"])

        if not ip_to_hosts:
            return
        log_fn(f"[SPECTRE Stage 2] Shodan InternetDB orqali {len(ip_to_hosts)} ta noyob IP (portlar, CPE va CVE) tekshirilmoqda...")
        for ip, hosts in ip_to_hosts.items():
            try:
                r = self.session.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
                if r.status_code != 200:
                    continue
                data = r.json()
                ports = data.get("ports", [])
                cpes = data.get("cpes", [])
                vulns = data.get("vulns", [])
                hostnames = data.get("hostnames", [])
                primary_h = hosts[0]
                for p in ports:
                    self.db.upsert_port(project_id, primary_h, int(p), "tcp", ip=ip, service="shodan-port", version=", ".join(cpes[:2]), source="shodan_internetdb")
                for hn in hostnames:
                    if scope.is_in_scope(hn)[0]:
                        self.db.upsert_domain(project_id, hn, ip=ip, source="shodan_rdns")
                if vulns:
                    self.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (ShodanCVE)", f"Known CVEs on Host IP {ip} ({len(vulns)} CVEs)",
                        "Vulnerable Components (CVE)", "High", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                        "CWE-1104", "A06:2021 - Vulnerable and Outdated Components", f"{primary_h} ({ip})",
                        f"CVEs: {', '.join(vulns[:10])} | CPEs: {', '.join(cpes[:4])}",
                        "Shodan InternetDB ma'lumotlariga ko'ra ushbu IP dagi servis versiyalarida ma'lum CVE zaifliklar mavjud.",
                        "Servis versiyalarini yangilang va tashqi portlarni Firewall orqali cheklang.",
                    )
                log_fn(f"  [+] Shodan InternetDB ({ip}): Ports={ports} | CPEs={len(cpes)} | CVEs={len(vulns)}")
            except Exception:
                pass




    # ================= STAGE 2: NETWORK, PORT & TLS =================
    def _stage2_tls_inspect(self, project_id: int, host: str, scope: ScopeGuard, log_fn) -> dict:
        tls_info = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_info["version"] = ssock.version()
                    tls_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                    tls_info["notAfter"] = cert.get("notAfter", "")
                    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                    tls_info["san_count"] = len(sans)
                    for san in sans:
                        clean_san = san.lower().lstrip("*.")
                        ok, _ = scope.is_in_scope(clean_san)
                        if ok:
                            self.db.upsert_domain(project_id, clean_san, source="tls_san")
                    self.db.upsert_port(project_id, host, 443, "tcp", service="https", version=tls_info.get("version", ""), source="tls_inspector")
                    log_fn(f"  [+] TLS {host}: {tls_info.get('version')} | Cipher: {tls_info.get('cipher')} | SANs: {len(sans)}")
        except Exception:
            pass
        return tls_info

    def _parse_nmap_xml(self, project_id: int, host: str, xml_text: str, log_fn):
        if "<nmaprun" not in xml_text:
            return
        try:
            xml_start = xml_text.index("<nmaprun")
            root = ET.fromstring(xml_text[xml_start:])
            for h in root.findall("host"):
                addr_el = h.find("address")
                ip_addr = addr_el.get("addr", "") if addr_el is not None else ""
                for p in h.findall(".//port"):
                    state_el = p.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        port_id = int(p.get("portid", 0))
                        proto = p.get("protocol", "tcp")
                        svc_el = p.find("service")
                        svc_name = svc_el.get("name", "") if svc_el is not None else ""
                        product = svc_el.get("product", "") if svc_el is not None else ""
                        ver = svc_el.get("version", "") if svc_el is not None else ""
                        full_ver = f"{product} {ver}".strip()
                        self.db.upsert_port(project_id, host, port_id, proto, ip=ip_addr, service=svc_name, version=full_ver, source="nmap")
                        log_fn(f"  [+] Nmap Open Port: {host}:{port_id}/{proto} ({svc_name} {full_ver})")
        except Exception as e:
            log_fn(f"  [!] Nmap XML parse ogohlantirish: {e}")

    # ================= STAGE 3: WEB PROBING & TECH STACK =================
    def _stage3_http_probe(self, project_id: int, url: str, tls_info: dict, scope: ScopeGuard, log_fn) -> str:
        ok, reason = scope.is_in_scope(url)
        if not ok:
            return ""
        try:
            resp = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = {k: v for k, v in resp.headers.items()}
            headers_l = {k.lower(): v for k, v in headers.items()}

            soup = BeautifulSoup(resp.text[:50000], "html.parser")
            title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
            server = headers_l.get("server", "")
            powered = headers_l.get("x-powered-by", "")

            tech = []
            if server:
                tech.append(server)
            if powered:
                tech.append(powered)
            body_l = resp.text[:40000].lower()
            for sig, label in [
                ("wp-content", "WordPress"), ("laravel", "Laravel"), ("django", "Django"),
                ("react", "React"), ("vue", "Vue.js"), ("angular", "Angular"),
                ("next/static", "Next.js"), ("nuxt", "Nuxt.js"), ("graphql", "GraphQL"),
                ("swagger", "Swagger UI"), ("jquery", "jQuery"), ("bootstrap", "Bootstrap"),
            ]:
                if sig in body_l and label not in tech:
                    tech.append(label)

            sec_headers = {
                "Strict-Transport-Security": headers_l.get("strict-transport-security", ""),
                "Content-Security-Policy": headers_l.get("content-security-policy", ""),
                "X-Frame-Options": headers_l.get("x-frame-options", ""),
                "X-Content-Type-Options": headers_l.get("x-content-type-options", ""),
                "Access-Control-Allow-Origin": headers_l.get("access-control-allow-origin", ""),
                "Access-Control-Allow-Credentials": headers_l.get("access-control-allow-credentials", ""),
            }

            # SPECTRE CSP & Header Infrastructure Miner
            header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
            for cand_host in re.findall(r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,10}", header_blob):
                ch_low = cand_host.lower().strip(".")
                if scope.is_in_scope(ch_low)[0]:
                    self.db.upsert_domain(project_id, ch_low, source="http_header_csp")
            for priv_ip in re.findall(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b", header_blob):
                self.db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (HeaderMiner)", f"Internal Private IP Leaked in HTTP Headers ({priv_ip})",
                    "Information Disclosure", "Low", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", url,
                    f"Leaked RFC1918 Private IP in Response Header: {priv_ip}",
                    "HTTP javob headerlarida ichki tarmoq IP manzili oshkor qilingan.",
                    "Reverse-proxy (Nginx/HAProxy) da X-Upstream, Via va X-Backend-Server headerlarini tozalang.",
                )


            cookies_list = []
            raw_set_cookie = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist") else []
            if not raw_set_cookie and "set-cookie" in headers_l:
                raw_set_cookie = [headers_l["set-cookie"]]
            for sc in raw_set_cookie:
                sc_l = sc.lower()
                c_name = sc.split("=", 1)[0].strip()
                cookies_list.append({
                    "name": c_name,
                    "httponly": "httponly" in sc_l,
                    "secure": "secure" in sc_l,
                    "samesite": "samesite" in sc_l,
                    "raw": sc[:200],
                })

            waf = ""
            if "cf-ray" in headers_l or "cloudflare" in server.lower():
                waf = "Cloudflare"
            elif "x-sucuri-id" in headers_l:
                waf = "Sucuri"
            elif "x-iinfo" in headers_l:
                waf = "Imperva Incapsula"
            elif "akamai" in server.lower():
                waf = "Akamai"

            # High-Value Target priority score
            prio = 50
            if any(k in url.lower() for k in ("admin", "dev", "stage", "test", "api", "internal", "portal", "auth")):
                prio += 30
            if resp.status_code in (200, 401, 403):
                prio += 15

            self.db.upsert_http_service(
                project_id=project_id,
                url=url,
                status_code=resp.status_code,
                title=title[:150],
                server=server,
                tech_stack=tech,
                content_length=len(resp.content),
                headers=headers,
                security_headers=sec_headers,
                cookies=cookies_list,
                tls_info=tls_info,
                waf=waf,
                priority_score=min(prio, 100),
                source="http_prober",
            )
            log_fn(f"  [+] HTTP {resp.status_code} | {url} | Title: '{title[:45]}' | Tech: {', '.join(tech) or 'N/A'}")
            return resp.text
        except Exception as e:
            log_fn(f"  [-] HTTP probe javob bermadi ({url}): {e}")
            return ""

    @staticmethod
    def _classify_endpoint_risk(url: str, params: list[str]) -> tuple[str, list[str]]:
        u_l = url.lower()
        if any(u_l.endswith(ext) for ext in (".webp", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".mp4")):
            return "static_asset", []
        p_l = [p.lower() for p in params]
        risks = []
        cat = "web_page"
        if "/api/" in u_l or "/v1/" in u_l or "/v2/" in u_l or "graphql" in u_l or "api." in u_l:
            cat = "api_endpoint"
        elif u_l.endswith(".js"):
            cat = "javascript"
        elif any(x in u_l for x in ("admin", "dashboard", "internal", "config", "actuator", "swagger", "api-docs")):
            cat = "high_value_endpoint"
            risks.append("Sensitive/Admin Route")

        for p in p_l:
            if any(k in p for k in ("id", "uid", "user", "account", "order", "doc", "invoice", "profile", "slug")):
                if "IDOR_Candidate" not in risks:
                    risks.append("IDOR_Candidate")
            if any(k in p for k in ("url", "uri", "redirect", "next", "return", "callback", "webhook", "dest", "host")):
                if "SSRF_or_Redirect_Candidate" not in risks:
                    risks.append("SSRF_or_Redirect_Candidate")
            if any(k in p for k in ("file", "path", "template", "include", "page", "doc", "folder")):
                if "LFI_PathTraversal_Candidate" not in risks:
                    risks.append("LFI_PathTraversal_Candidate")
            if any(k in p for k in ("q", "search", "query", "filter", "sort", "order", "cmd", "exec")):
                if "Injection_Candidate" not in risks:
                    risks.append("Injection_Candidate")
            if any(k in p for k in ("price", "amount", "qty", "discount", "coupon", "role", "admin", "balance")):
                if "Business_Logic_Candidate" not in risks:
                    risks.append("Business_Logic_Candidate")
        return cat, risks


    def _record_discovered_url(self, project_id: int, raw_url: str, base_url: str, scope: ScopeGuard, source: str, method: str = "GET", extra_params: list | None = None) -> str | None:
        full_url = urllib.parse.urljoin(base_url, raw_url.strip())
        full_url = full_url.replace("/assets/assets/", "/assets/").replace("/static/static/", "/static/")
        ok, _ = scope.is_in_scope(full_url)
        if not ok:
            return None
        u_low = full_url.lower()
        if any(bad in u_low for bad in ("/logout", "/signout", "/sign-out", "/log-out", "action=logout", "/account/delete", "/user/delete")):
            return None
        parsed = urllib.parse.urlparse(full_url)
        qs_params = list(urllib.parse.parse_qs(parsed.query).keys())
        all_params = sorted(set(qs_params + (extra_params or [])))
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        cat, risks = self._classify_endpoint_risk(clean_url, all_params)
        self.db.upsert_endpoint(project_id, clean_url, method=method, params=all_params, category=cat, risk_tags=risks, source=source)
        return clean_url



    def _stage4_html_and_wayback(self, project_id: int, base_url: str, html_body: str, domain: str, scope: ScopeGuard, log_fn) -> list[str]:
        js_urls = set()
        if html_body:
            soup = BeautifulSoup(html_body[:80000], "html.parser")
            for a in soup.find_all(["a", "link"], href=True):
                self._record_discovered_url(project_id, a["href"], base_url, scope, "html_crawler")
            for form in soup.find_all("form"):
                action = form.get("action") or base_url
                method = (form.get("method") or "GET").upper()
                inputs = [inp.get("name") for inp in form.find_all(["input", "select", "textarea"]) if inp.get("name")]
                self._record_discovered_url(project_id, action, base_url, scope, "html_form", method=method, extra_params=inputs)

            # Hidden Input Miner
            hidden_inputs = [inp.get("name") for inp in soup.find_all("input", {"type": "hidden"}) if inp.get("name")]
            if hidden_inputs:
                self._record_discovered_url(project_id, base_url, base_url, scope, "hidden_inputs", method="POST", extra_params=hidden_inputs)

            # HTML Comment Intelligence Miner
            comments = [str(c).strip() for c in soup.find_all(string=lambda text: isinstance(text, Comment))]
            interesting_comments = [c[:140] for c in comments if any(k in c.lower() for k in ("todo", "fixme", "api", "admin", "debug", "token", "key", "http", "dev", "password")) and len(c.strip()) > 6]
            if interesting_comments:
                self.db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (HTML-Miner)", f"Developer Comments / Hints in HTML Source ({domain})",
                    "Information Disclosure", "Low", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-615", "A05:2021 - Security Misconfiguration", base_url,
                    f"Comments: {' | '.join(interesting_comments[:4])}",
                    "HTML sahifa kodida dasturchi izohlari yoki yashirin texnik ma'lumotlar qoldirilgan.",
                    "Production sahifalardan barcha HTML izohlarni (<!-- ... -->) olib tashlang.",
                )

            for sc in soup.find_all("script", src=True):
                u = self._record_discovered_url(project_id, sc["src"], base_url, scope, "script_tag")
                if u and u.endswith(".js"):
                    js_urls.add(u)


        wb_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=80"
        try:
            r = self.session.get(wb_url, timeout=10)
            if r.status_code == 200:
                rows = r.json()
                for row in rows[1:]:
                    if row:
                        u = self._record_discovered_url(project_id, row[0], base_url, scope, "wayback")
                        if u and u.endswith(".js"):
                            js_urls.add(u)
                log_fn(f"  [+] Wayback Archive: {max(0, len(rows)-1)} ta tarixiy URL olindi.")
        except Exception:
            pass
        return sorted(js_urls)

    def _stage5_openapi_discovery(self, project_id: int, base_url: str, scope: ScopeGuard, log_fn):
        baseline_len = -1
        try:
            b_resp = self.session.get(urllib.parse.urljoin(base_url, "/apex-nonexistent-404-check-99182"), timeout=5, verify=False, allow_redirects=False)
            if b_resp.status_code == 200:
                baseline_len = len(b_resp.text)
        except Exception:
            pass

        def probe_path(path: str):
            target = urllib.parse.urljoin(base_url, path)
            try:
                r = self.session.get(target, timeout=6, verify=False, allow_redirects=False)
                if r.status_code != 200 or len(r.text) < 10:
                    return
                ctype = r.headers.get("Content-Type", "").lower()
                body = r.text
                if baseline_len > 0 and abs(len(body) - baseline_len) < 60:
                    return
                if path not in ("/swagger-ui.html", "/admin", "/wp-login.php", "/_debugbar", "/telescope") and "text/html" in ctype and "<html" in body[:300].lower():
                    return

                self._record_discovered_url(project_id, target, base_url, scope, "api_discovery")
                log_fn(f"  [+] Stage 5 Active Path ({r.status_code}): {target} [{ctype.split(';')[0]}]")

                if path == "/robots.txt" and ("disallow:" in body.lower() or "allow:" in body.lower() or "sitemap:" in body.lower()):
                    for line in body.splitlines():
                        parts = line.split(":", 1)
                        if len(parts) == 2 and parts[0].strip().lower() in ("disallow", "allow", "sitemap"):
                            val = parts[1].strip()
                            if val and val != "/":
                                self._record_discovered_url(project_id, val, base_url, scope, "robots_txt")
                elif path == "/sitemap.xml" and "<loc>" in body:
                    for loc in re.findall(r"<loc>(.*?)</loc>", body)[:80]:
                        self._record_discovered_url(project_id, loc.strip(), base_url, scope, "sitemap_xml")
                elif path == "/.git/HEAD" and "ref:" in body:
                    self.db.upsert_finding(project_id, "Agent-1 (Stage5)", "Exposed Git Repository (/.git/HEAD)", "Information Disclosure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-538", "A05:2021 - Security Misconfiguration", target, body[:120].strip(), "/.git katalogi veb-server orqali ochiq qoldirilgan.", "Nginx/Apache da /.git yo'liga kirishni taqiqlang (deny all).")
                elif path == "/.env" and "=" in body and not body.lstrip().startswith("<"):
                    self.db.upsert_finding(project_id, "Agent-1 (Stage5)", "Exposed Environment File (/.env)", "Critical Secret Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration", target, body[:120].strip(), ".env konfiguratsiya fayli ochiq qolgan.", ".env faylini public_html tashqarisiga chiqaring.")
                elif "paths" in body and ("swagger" in body or "openapi" in body):
                    spec = r.json()
                    for api_path, methods in spec.get("paths", {}).items():
                        if isinstance(methods, dict):
                            for m, details in methods.items():
                                if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                    p_names = [p.get("name", "") for p in (details.get("parameters") or []) if isinstance(p, dict) and p.get("name")]
                                    self._record_discovered_url(project_id, api_path, base_url, scope, "openapi_spec", method=m.upper(), extra_params=p_names)
            except Exception:
                pass

        ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        futs = [ex.submit(probe_path, p) for p in self.API_DOC_PATHS]
        concurrent.futures.wait(futs, timeout=14.0)
        ex.shutdown(wait=False, cancel_futures=True)

        # Safe GraphQL Introspection Check
        for gql_path in ("/graphql", "/api/graphql"):
            gql_url = urllib.parse.urljoin(base_url, gql_path)
            try:
                rg = self.session.post(gql_url, json={"query": "{__schema{types{name}}}"}, timeout=5, verify=False)
                if rg.status_code == 200 and '"__schema"' in rg.text:
                    types_list = [t.get("name", "") for t in rg.json().get("data", {}).get("__schema", {}).get("types", []) if not str(t.get("name", "")).startswith("__")]
                    self.db.upsert_finding(
                        project_id, "SPECTRE-Agent1 (GraphQL)", f"GraphQL Introspection Enabled ({gql_url})",
                        "API Schema Exposure", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "CWE-200", "A05:2021 - Security Misconfiguration", gql_url,
                        f"Discovered {len(types_list)} GraphQL types: {', '.join(types_list[:10])}",
                        "GraphQL endpointda Introspection ochiq qoldirilgan — barcha sxema va mutatsiyalarni o'qish mumkin.",
                        "Production muhitida GraphQL Introspection so'rovlarini o'chirib qo'ying.",
                    )
                    log_fn(f"  [🚨 GRAPHQL] Introspection ochiq: {gql_url} ({len(types_list)} types)")
            except Exception:
                pass




    def _stage6_js_analyzer(self, project_id: int, js_urls: list[str], base_url: str, scope: ScopeGuard, log_fn):
        # Faqat satr boshidan (' " ` yoki ${...}) boshlangan haqiqiy route'larni tutish (tashqi YouTube/Vimeo URL o'rtasini kesib olmaslik uchun!)
        ep_regex = re.compile(r"""(?:['"`]|\$\{[^}]{1,35}\})((?:/api/v\d+/|/api/|/v1/|/v2/|/v3/|/graphql|/auth/|/admin/|/internal/|/live/|/stream/|/news/|/tv/|/radio/|/channels/)[a-zA-Z0-9_\-/\.?=&${}:]+)""")
        full_url_regex = re.compile(r"""['"`]((?:https?|wss?)://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[a-zA-Z0-9_\-/\.?=&%${}]*)?)['"`]""")
        param_regex = re.compile(r"""(?:params|body|query|data)\s*[:=]\s*\{([^}]{1,250})\}|[?&]([a-zA-Z_][a-zA-Z0-9_]{1,25})=""")
        sink_regex = re.compile(r"""(innerHTML|outerHTML|document\.write|eval\s*\(|setTimeout\s*\(\s*['"]|postMessage\s*\(|dangerouslySetInnerHTML)""")
        secret_regex = re.compile(r"""(?i)((?:api[_-]?key|access[_-]?token|secret[_-]?key|base_?url|vite_[a-z0-9_]+|authorization)\s*[:=]\s*['"][^'"]{4,100}['"]|bearer\s+[a-zA-Z0-9_\-\.]{12,})""")


        clean_js_urls = []
        for u in js_urls:
            cu = u.replace("/assets/assets/", "/assets/").replace("/static/static/", "/static/")
            if cu not in clean_js_urls:
                clean_js_urls.append(cu)

        log_fn(f"[Stage 6] {len(clean_js_urls[:40])} ta JavaScript bundle fayllarini chuqur dekonstruksiya qilish boshlandi...")

        # Unlinked Webpack/Vite Lazy-Chunk Hunter + HTTP Method Pairing
        chunk_regex = re.compile(r"""['"`]((?:assets/|/assets/|static/js/)[a-zA-Z0-9_\-\.]+\.js)['"`]""")
        method_ep_regex = re.compile(r"""(?i)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]{3,120})['"`]""")
        discovered_chunks = set()

        def analyze_one_js(js_url: str):
            try:
                r = self.session.get(js_url, timeout=10, verify=False)
                if r.status_code != 200 or "html" in r.headers.get("Content-Type", "").lower():
                    return
                content = r.text[:500000]
                for ch in chunk_regex.findall(content):
                    ch_full = urllib.parse.urljoin(base_url, "/" + ch.lstrip("/")).replace("/assets/assets/", "/assets/")
                    if ch_full not in clean_js_urls:
                        discovered_chunks.add(ch_full)

                method_map: dict[str, str] = {}
                for m_verb, m_path in method_ep_regex.findall(content):
                    clean_mp = re.sub(r"\$\{[^}]+\}", "{param}", m_path).rstrip(".,;)'\"`")
                    if clean_mp.startswith("/") or clean_mp.startswith("http"):
                        method_map[clean_mp] = m_verb.upper()


                raw_eps = ep_regex.findall(content)
                eps = set()
                for ep in raw_eps:
                    cleaned_ep = re.sub(r"\$\{[^}]*\}?", "{param}", ep).rstrip(".,;)'\"`${")
                    if len(cleaned_ep) > 4 and not any(cleaned_ep.endswith(ext) for ext in (".webp", ".png", ".jpg", ".svg", ".css", "/api/player.js")):
                        eps.add(cleaned_ep)

                full_urls = set(full_url_regex.findall(content))
                for fu in full_urls:
                    fu_clean = re.sub(r"\$\{[^}]*\}?", "{param}", fu).rstrip(".,;)'\"`${")
                    if any(fu_clean.lower().endswith(ext) for ext in (".webp", ".png", ".jpg", ".svg", ".css", ".ico")):
                        continue
                    ok, _ = scope.is_in_scope(fu_clean)
                    if ok:
                        host = ScopeGuard.extract_host(fu_clean)
                        self.db.upsert_domain(project_id, host, source="js_bundle")
                        eps.add(fu_clean)


                extracted_params = set()
                for m in param_regex.finditer(content):
                    blk, qkey = m.group(1), m.group(2)
                    if qkey:
                        extracted_params.add(qkey)
                    elif blk:
                        for key in re.findall(r"([a-zA-Z_][a-zA-Z0-9_]{1,28})\s*:", blk):
                            if key not in ("http", "https", "true", "false", "null", "undefined"):
                                extracted_params.add(key)

                sinks = sorted(set(sink_regex.findall(content)))
                secrets = sorted({s[:120] for s in secret_regex.findall(content)})
                eps.update(method_map.keys())
                sorted_eps = sorted(eps)

                self.db.upsert_js_asset(project_id, js_url, endpoints=sorted_eps, params=sorted(extracted_params), sinks=sinks, secrets_hints=secrets)
                for ep in sorted_eps:
                    ep_params = sorted(extracted_params)[:12] if ("/api" in ep or "{param}" in ep or "?" in ep) else []
                    if "{param}" in ep and "id" not in ep_params:
                        ep_params.append("id")
                    http_m = method_map.get(ep, "GET")
                    self._record_discovered_url(project_id, ep, base_url, scope, "js_intelligence", method=http_m, extra_params=ep_params)

                # SourceMap (.js.map) Hunter
                map_url = js_url + ".map"
                try:
                    rm = self.session.get(map_url, timeout=5, verify=False)
                    if rm.status_code == 200 and '"sources"' in rm.text[:600] and '"mappings"' in rm.text[:2000]:
                        self.db.upsert_finding(
                            project_id, "SPECTRE-Agent1 (SourceMap)", f"Exposed JavaScript SourceMap ({map_url.split('/')[-1]})",
                            "Source Code Disclosure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "CWE-540", "A05:2021 - Security Misconfiguration", map_url,
                            f"SourceMap file accessible ({len(rm.content)} bytes) containing original unminified source tree.",
                            "Production serverda .js.map (SourceMap) fayli ochiq qoldirilgan — bu orqali asl frontend kodni to'liq tiklash mumkin.",
                            "Production build jarayonida generateSourceMap ni o'chiring yoki Nginx da *.map fayllarga kirishni bloklang.",
                        )
                        log_fn(f"  [🚨 SOURCEMAP] Ochiq .js.map topildi: {map_url}")
                except Exception:
                    pass

                if sorted_eps or sinks or secrets:
                    log_fn(f"  [+] JS Bundle ({js_url.split('/')[-1]}): {len(sorted_eps)} API route, {len(extracted_params)} param, {len(sinks)} sink, {len(secrets)} config.")
            except Exception:
                pass

        ex = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        futs = [ex.submit(analyze_one_js, u) for u in clean_js_urls[:40]]
        concurrent.futures.wait(futs, timeout=18.0)
        ex.shutdown(wait=False, cancel_futures=True)

        if discovered_chunks:
            new_chunks = sorted(discovered_chunks - set(clean_js_urls))[:20]
            if new_chunks:
                log_fn(f"[SPECTRE Chunk Hunter] JS ichidan {len(new_chunks)} ta yashirin (unlinked) JS chunk topildi, tahlil qilinmoqda...")
                ex2 = concurrent.futures.ThreadPoolExecutor(max_workers=8)
                futs2 = [ex2.submit(analyze_one_js, u) for u in new_chunks]
                concurrent.futures.wait(futs2, timeout=12.0)
                ex2.shutdown(wait=False, cancel_futures=True)




    def run_full_recon(self, project_id: int, selected_tools: list[str] | None, log_fn, recon_mode: str = "full", progress_fn=None):
        def _prog(frac: float, text: str):
            if progress_fn:
                try:
                    progress_fn(frac, text)
                except Exception:
                    pass

        proj = self.db.get_project(project_id)
        if not proj:
            log_fn("[ERR] Loyiha topilmadi.")
            return

        self.db.update_project_status(project_id, "RUNNING_RECON")
        _prog(0.05, "Scope va nishon tekshirilmoqda...")
        scope = ScopeGuard(proj["in_scope"], proj["out_of_scope"])
        primary_host = ScopeGuard.extract_host(proj["primary_target"])
        ok, reason = scope.is_in_scope(primary_host)
        if not ok:
            log_fn(f"[SCOPE BLOCK] Asosiy nishon '{primary_host}' ruxsat berilgan scope ichida emas: {reason}")
            self.db.update_project_status(project_id, "SCOPE_BLOCKED")
            _prog(0.0, "Scope Blocked")
            return

        tools = self.get_tools_status()
        active_ids = set(selected_tools) if selected_tools else {t["id"] for t in tools if t.get("enabled") and t.get("installed")}

        self.abort_flags.discard(project_id)
        before_snap = spectre_deep_modules.take_recon_snapshot(self.db, project_id)
        collected_html: list[str] = []
        apex_domain = ScopeGuard.extract_apex_domain(primary_host)
        safe_host = shlex.quote(primary_host)
        safe_apex = shlex.quote(apex_domain)
        log_fn(f"═══ 🛰️ 1-SUPERAGENT: DEEP AUTONOMOUS RECON [{recon_mode.upper()}] (Target: {primary_host} | Apex: {apex_domain}) ═══")
        self.db.upsert_domain(project_id, primary_host, source="primary_target")
        if apex_domain != primary_host:
            self.db.upsert_domain(project_id, apex_domain, source="apex_domain")

        # Stage 1: Subdomains & OSINT
        if recon_mode in ("full", "subdomains"):
            _prog(0.15, "Stage 1/6: 5-OSINT Mesh, Subfinder, Sublist3r, Amass, Dig AXFR...")
            if "crtsh_builtin" in active_ids:
                self._stage1_crtsh(project_id, apex_domain, scope, log_fn)
            spectre_v5_modules.run_deep_subdomain_tools(self, project_id, apex_domain, scope, active_ids, log_fn)
            _prog(0.30, "Stage 1/6: SecLists DNS Enum & Smart Permutations...")
            self._stage1_dns_enum(project_id, primary_host, scope, log_fn)

        # Stage 2: Ports, Shodan, Nmap Deep NSE & NetExec
        tls_info = {}
        if recon_mode in ("full", "ports"):
            _prog(0.45, "Stage 2/6: TLS SAN, Shodan InternetDB & ASN/ISP...")
            tls_info = self._stage2_tls_inspect(project_id, primary_host, scope, log_fn)
            self._stage2_shodan_internetdb(project_id, scope, log_fn)
            spectre_v5_modules.enrich_asn_and_isp_intel(self.db, project_id, log_fn)
            _prog(0.55, f"Stage 2/6: Nmap Deep NSE, Naabu & NetExec ({primary_host})...")
            spectre_v5_modules.run_deep_network_and_ad_tools(self, project_id, primary_host, active_ids, log_fn)
            spectre_ultra_modules.sweep_subnet_neighbors_and_ptr(self.db, project_id, apex_domain, scope, log_fn)
            spectre_ultra_modules.unmask_cloudflare_origin_ips(self.db, self.session, project_id, apex_domain, primary_host, log_fn)
            spectre_deep_modules.probe_nonstandard_web_ports(self.db, self.session, project_id, log_fn)
            spectre_deep_modules.hunt_virtual_hosts(self.db, self.session, project_id, apex_domain, log_fn)



        # Stage 3, 4, 5, 6: Web, API & JS Bundles (across all High-Value Subdomains!)
        if recon_mode in ("full", "web_js"):
            _prog(0.70, "Stage 3-6: Web Probing, Katana SPA Crawl & JS Deconstruction...")
            high_value_prefixes = ("id.", "api.", "backend.", "accounts.", "my.", "admin.", "portal.", "dev.", "svc.", "auth.", "sso.")
            probed_domains = set()
            for pass_num in (1, 2):
                if pass_num == 2 and recon_mode == "full":
                    self._stage1_dns_enum(project_id, primary_host, scope, log_fn)
                    self._stage2_shodan_internetdb(project_id, scope, log_fn)
                    spectre_v5_modules.enrich_asn_and_isp_intel(self.db, project_id, log_fn)
                domains = [d["domain"] for d in self.db.get_project_bundle(project_id).get("domains", []) if d.get("ip") or d.get("cname") or d["domain"] == primary_host]
                if primary_host not in domains:
                    domains.insert(0, primary_host)
                new_batch = [d for d in domains if d not in probed_domains][:14]
                if not new_batch:
                    break
                if pass_num == 2 and recon_mode == "full":
                    log_fn(f"[SPECTRE Recursive Loop] 2-to'lqinda DNS tasdiqlangan {len(new_batch)} ta tirik subdomen tekshirilmoqda: {', '.join(new_batch)}")

                for dom in new_batch:
                    probed_domains.add(dom)
                    if project_id in self.abort_flags:
                        break
                    is_high_val = (dom == primary_host) or any(dom.startswith(hp) for hp in high_value_prefixes)
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{dom}"
                        safe_url = shlex.quote(url)
                        html = self._stage3_http_probe(project_id, url, tls_info if dom == primary_host else {}, scope, log_fn)
                        if html:
                            collected_html.append(html[:50000])
                            if dom == primary_host:
                                spectre_deep_modules.fingerprint_favicon(self.session, url, self.db, project_id, log_fn)
                            js_list = self._stage4_html_and_wayback(project_id, url, html, dom, scope, log_fn)
                            spectre_v5_modules.run_deep_web_and_fuzz_tools(
                                self, project_id, url, dom, primary_host, is_high_val, scope, active_ids, js_list, log_fn
                            )
                            if is_high_val:
                                self._stage5_openapi_discovery(project_id, url, scope, log_fn)
                            self._stage6_js_analyzer(project_id, js_list, url, scope, log_fn)
                            break

            _prog(0.90, "Stage 6/6: Adaptive Brain, Auto-Validator, SPA Manifests, Secrets v2 & Mobile/OIDC...")
            spectre_ultra_modules.run_adaptive_brain_strategy(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
            spectre_ultra_modules.deconstruct_spa_manifests_and_ssr_state(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
            spectre_ultra_modules.hunt_deep_secrets_and_uz_ecosystem(self.db, self.session, project_id, log_fn)
            spectre_ultra_modules.mine_well_known_and_mobile_links(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
            spectre_ultra_modules.trace_redirect_chains_and_oauth_flows(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
            spectre_ultra_modules.run_safe_auto_validator(self.db, self.session, project_id, log_fn)
            spectre_ultra_modules.extract_document_metadata_osint(self.db, self.session, project_id, apex_domain, log_fn)
            spectre_deep_modules.hunt_cloud_and_storage_buckets(self.db, self.session, project_id, apex_domain, log_fn)
            spectre_deep_modules.probe_api_versions_and_ghost_endpoints(self.db, project_id, log_fn)
            spectre_deep_modules.classify_auth_portals_and_schema(self.db, project_id, log_fn)
            spectre_deep_modules.analyze_badsecrets_and_cookies(self.db, project_id, apex_domain, log_fn)
            spectre_v5_modules.audit_ssl_certificates_deep(self.db, project_id, log_fn)
            spectre_v5_modules.audit_domain_backup_exposure(self.db, project_id, apex_domain, log_fn)
            spectre_deep_modules.harvest_emails_and_osint(self.db, project_id, apex_domain, collected_html, log_fn)
            spectre_deep_modules.build_custom_wordlist_and_params(self.db, project_id, apex_domain, log_fn)
            spectre_v5_modules.run_deep_cloud_osint_and_vuln_tools(self, project_id, apex_domain, primary_host, active_ids, log_fn)

        spectre_deep_modules.log_incremental_diff(before_snap, self.db, project_id, log_fn)
        _prog(1.0, "✅ Recon Completed!")

        b_final = self.db.get_project_bundle(project_id)
        unique_ips = sorted({d["ip"] for d in b_final["domains"] if d.get("ip")})
        api_eps = [e["url"] for e in b_final["endpoints"] if e.get("category") in ("api_endpoint", "high_value_endpoint")]
        log_fn("╔══════════════════════════════════════════════════════════════════════════╗")
        log_fn(f"║ 🧠 SPECTRE TACTICAL BRIEFING ({apex_domain})                             ")
        log_fn(f"║ • Subdomenlar: {len(b_final['domains'])} ta | Noyob IP/Serverlar: {len(unique_ips)} ta ({', '.join(unique_ips[:4])})")
        log_fn(f"║ • Ochiq Portlar: {len(b_final['ports'])} ta | Faol Web Servislar: {len(b_final['http_services'])} ta")
        log_fn(f"║ • Jami Endpointlar: {len(b_final['endpoints'])} ta | Yuqori qiymatli API'lar: {len(api_eps)} ta | JS Fayllar: {len(b_final['js_assets'])} ta")
        if api_eps:
            log_fn(f"║ • Birinchi navbatda tekshiriladigan API'lar: {', '.join(api_eps[:3])}")
        log_fn("╚══════════════════════════════════════════════════════════════════════════╝")

        self.db.update_project_status(project_id, "RECON_COMPLETED")
        log_fn("═══ ✅ SPECTRE 1-SUPERAGENT: DEEP RECON YAKUNLANDI ═══")

    def run_single_subdomain_deep_recon(self, project_id: int, target_host: str, log_fn, progress_fn=None):
        def _prog(frac: float, text: str):
            if progress_fn:
                try:
                    progress_fn(frac, text)
                except Exception:
                    pass

        proj = self.db.get_project(project_id)
        if not proj:
            return
        scope = ScopeGuard(proj["in_scope"], proj["out_of_scope"])
        target_host = ScopeGuard.extract_host(target_host)
        ok, reason = scope.is_in_scope(target_host)
        if not ok:
            log_fn(f"[SCOPE BLOCK] '{target_host}' ruxsat etilgan scope ichida emas: {reason}")
            return

        self.abort_flags.discard(project_id)
        active_ids = {t["id"] for t in self.get_tools_status() if t.get("enabled") and t.get("installed")}
        apex_domain = ScopeGuard.extract_apex_domain(target_host)
        log_fn(f"═══ 🎯 SINGLE-HOST DEEP SURGICAL RECON: {target_host} ═══")

        _prog(0.20, f"Single-Host DNS, TLS & Nmap Deep NSE: {target_host}...")
        tls_info = self._stage2_tls_inspect(project_id, target_host, scope, log_fn)
        spectre_v5_modules.run_deep_network_and_ad_tools(self, project_id, target_host, active_ids, log_fn)

        _prog(0.55, f"Single-Host Deep Web, FFUF, Katana, Arjun & JS: {target_host}...")
        for scheme in ("https", "http"):
            url = f"{scheme}://{target_host}"
            html = self._stage3_http_probe(project_id, url, tls_info, scope, log_fn)
            if html:
                spectre_deep_modules.fingerprint_favicon(self.session, url, self.db, project_id, log_fn)
                js_list = self._stage4_html_and_wayback(project_id, url, html, target_host, scope, log_fn)
                spectre_v5_modules.run_deep_web_and_fuzz_tools(
                    self, project_id, url, target_host, target_host, True, scope, active_ids, js_list, log_fn
                )
                self._stage5_openapi_discovery(project_id, url, scope, log_fn)
                self._stage6_js_analyzer(project_id, js_list, url, scope, log_fn)
                break

        _prog(0.85, f"Single-Host Adaptive Brain, Auto-Validator, SPA Manifest & SecretHunter v2: {target_host}...")
        spectre_ultra_modules.run_adaptive_brain_strategy(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
        spectre_ultra_modules.deconstruct_spa_manifests_and_ssr_state(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
        spectre_ultra_modules.hunt_deep_secrets_and_uz_ecosystem(self.db, self.session, project_id, log_fn)
        spectre_ultra_modules.mine_well_known_and_mobile_links(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
        spectre_ultra_modules.trace_redirect_chains_and_oauth_flows(self.db, self.session, project_id, scope, log_fn, self._record_discovered_url)
        spectre_ultra_modules.run_safe_auto_validator(self.db, self.session, project_id, log_fn)
        spectre_v5_modules.run_deep_cloud_osint_and_vuln_tools(self, project_id, apex_domain, target_host, active_ids, log_fn)
        _prog(1.0, f"✅ Deep Scan Completed: {target_host}")
        log_fn(f"═══ ✅ SINGLE-HOST DEEP RECON YAKUNLANDI: {target_host} ═══")







