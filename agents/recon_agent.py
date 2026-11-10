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
from agents import spectre_deep_modules, spectre_v5_modules, spectre_ultra_modules, spectre_predator_modules, spectre_v10_modules, spectre_v11_modules, spectre_v12_modules

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
        "www", "api", "dev", "staging", "stage", "test", "admin", "adm", "portal",
        "mail", "webmail", "smtp", "pop", "imap", "vpn", "auth", "sso", "id",
        "beta", "cdn", "static", "media", "files", "storage", "s3", "minio",
        "docs", "doc", "app", "my", "cabinet", "client", "dashboard", "cp", "panel",
        "internal", "intranet", "git", "gitlab", "jenkins", "ci", "grafana",
        "kibana", "prometheus", "zabbix", "status", "monitor", "m", "mobile", "old",
        "new", "v1", "v2", "back", "backend", "cms", "crm", "erp", "pay",
        "billing", "live", "stream", "tv", "radio", "news", "press", "db",
        "lms", "cctv", "reg", "student", "jurnal", "kpi", "syllabus", "hemis",
        "library", "exam", "qabul", "edu", "conference", "verify", "check", "chat",
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
        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({"User-Agent": "SPECTRE-ASM-Security-Audit/12.2"})
        self._http_get_cache: dict[tuple[str, bool], Any] = {}
        self._cache_lock = threading.Lock()
        self._probe_tls = threading.local()
        _orig_get = self.session.get

        def _cached_session_get(url, **kwargs):
            if not kwargs.get("headers") and not kwargs.get("stream") and not kwargs.get("params"):
                ckey = (str(url), bool(kwargs.get("allow_redirects", True)))
                with self._cache_lock:
                    if ckey in self._http_get_cache:
                        return self._http_get_cache[ckey]
                resp = _orig_get(url, **kwargs)
                if not resp.encoding or resp.encoding.lower() == "iso-8859-1":
                    resp.encoding = "utf-8"
                if resp.status_code == 200 and len(resp.content) < 600000:
                    with self._cache_lock:
                        if len(self._http_get_cache) > 160:
                            self._http_get_cache.clear()
                        self._http_get_cache[ckey] = resp
                return resp
            resp = _orig_get(url, **kwargs)
            if not kwargs.get("stream") and (not resp.encoding or resp.encoding.lower() == "iso-8859-1"):
                resp.encoding = "utf-8"
            return resp

        self.session.get = _cached_session_get
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
                stdin=subprocess.DEVNULL,
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
        log_fn(f"[SPECTRE Stage 1] 8 ta Global OSINT Baza (CRT.sh, SubdomainCenter, RapidDNS, CertSpotter, HackerTarget, URLScan, Wayback, OTX) parallel qidiruvi: {domain}")
        discovered: set[tuple[str, str, str]] = set()

        def fetch_crtsh():
            try:
                r = self.session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=12)
                if r.status_code == 200:
                    for item in r.json():
                        for sub in str(item.get("name_value", "")).splitlines():
                            discovered.add((sub.strip().lower().lstrip("*."), "", "crt.sh"))
            except Exception:
                pass

        def fetch_otx():
            try:
                r = self.session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=10)
                if r.status_code == 200:
                    for row in r.json().get("passive_dns", []):
                        h = str(row.get("hostname", "")).strip().lower()
                        addr = str(row.get("address", "")).strip()
                        ip_h = addr if re.match(r"^\d+\.\d+\.\d+\.\d+$", addr) else ""
                        if h:
                            discovered.add((h, ip_h, "alienvault_otx"))
            except Exception:
                pass

        def fetch_hackertarget():
            try:
                r = self.session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
                if r.status_code == 200 and "error" not in r.text.lower():
                    for line in r.text.splitlines():
                        parts = line.split(",")
                        if parts and "." in parts[0]:
                            ip_h = parts[1].strip() if len(parts) > 1 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1].strip()) else ""
                            discovered.add((parts[0].strip().lower(), ip_h, "hackertarget"))
            except Exception:
                pass

        def fetch_urlscan():
            try:
                r = self.session.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=10)
                if r.status_code == 200:
                    for res in r.json().get("results", []):
                        for sec in ("page", "task"):
                            d_val = str(res.get(sec, {}).get("domain", "")).strip().lower()
                            ip_v = str(res.get("page", {}).get("ip", "")).strip() if sec == "page" else ""
                            ip_h = ip_v if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_v) else ""
                            if d_val and d_val.endswith(domain):
                                discovered.add((d_val, ip_h, "urlscan.io"))
            except Exception:
                pass

        def fetch_subdomain_center():
            try:
                r = self.session.get(f"https://api.subdomain.center/?domain={domain}", timeout=10)
                if r.status_code == 200 and isinstance(r.json(), list):
                    for sub in r.json():
                        discovered.add((str(sub).strip().lower().lstrip("*."), "", "subdomain_center"))
            except Exception:
                pass

        def fetch_certspotter():
            try:
                r = self.session.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=10)
                if r.status_code == 200 and isinstance(r.json(), list):
                    for item in r.json():
                        for d_name in item.get("dns_names", []):
                            discovered.add((str(d_name).strip().lower().lstrip("*."), "", "certspotter"))
            except Exception:
                pass

        def fetch_rapiddns():
            try:
                r = self.session.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=12)
                if r.status_code == 200:
                    for m in re.findall(r"([a-zA-Z0-9_\-\.]+\." + re.escape(domain) + r")", r.text):
                        discovered.add((m.strip().lower().lstrip("*."), "", "rapiddns"))
            except Exception:
                pass

        def fetch_wayback_hosts():
            try:
                r = self.session.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=250", timeout=12)
                if r.status_code == 200:
                    for row in r.json()[1:]:
                        if row:
                            h = ScopeGuard.extract_host(row[0])
                            if h and h.endswith(domain):
                                discovered.add((h, "", "wayback_osint"))
            except Exception:
                pass

        ex = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        futures = [ex.submit(fn) for fn in (fetch_crtsh, fetch_otx, fetch_hackertarget, fetch_urlscan, fetch_subdomain_center, fetch_certspotter, fetch_rapiddns, fetch_wayback_hosts)]
        concurrent.futures.wait(futures, timeout=16)
        ex.shutdown(wait=False, cancel_futures=True)

        added = 0
        for sub, ip_hint, src in sorted(discovered):
            if "." in sub and scope.is_in_scope(sub)[0]:
                self.db.upsert_domain(project_id, sub, ip=ip_hint, source=src)
                added += 1
        log_fn(f"  [+] Passive OSINT Mesh yakunlandi: {added} ta in-scope subdomen bazaga qo'shildi.")


    def _stage1_dns_enum(self, project_id: int, base_domain: str, scope: ScopeGuard, log_fn, only_unresolved: bool = False):
        apex_domain = ScopeGuard.extract_apex_domain(base_domain)
        existing = self.db.get_project_bundle(project_id).get("domains", [])
        already_resolved = {d["domain"] for d in existing if d.get("ip") and d["domain"] not in (base_domain, apex_domain)}

        if only_unresolved:
            candidates = {d["domain"] for d in existing if not d.get("ip") and not d.get("cname")}
            if not candidates:
                return
        else:
            candidates = {base_domain, apex_domain}
            for prefix in self.COMMON_SUBDOMAINS:
                candidates.add(f"{prefix}.{apex_domain}")

            # Load top 1,200 prefixes from SecLists if available on system
            seclist_dns = Path("/home/amaqi/SecLists/Discovery/DNS/subdomains-top1million-5000.txt")
            if seclist_dns.exists():
                try:
                    for line in seclist_dns.read_text(encoding="utf-8", errors="ignore").splitlines()[:1200]:
                        w = line.strip().lower()
                        if w and not w.startswith("#"):
                            candidates.add(f"{w}.{apex_domain}")
                except Exception:
                    pass

            for reg_p in (
                "1c", "bitrix", "edo", "hr", "jira", "confluence", "payme", "click", "uzum",
                "accounts", "svc", "vod", "upload", "open", "reja", "zakovat", "fikr",
                "cabinet", "lex", "norma", "ijro", "edo-db", "minio", "keycloak", "sso", "id",
            ):
                candidates.add(f"{reg_p}.{apex_domain}")

            for d in existing:
                if d["domain"] not in already_resolved:
                    candidates.add(d["domain"])
        log_fn(f"[Stage 1] Chuqur DNS yozuvlari va {len(candidates)} ta subdomen (SecLists + Regional) parallel tekshiruvi: {apex_domain}")

        try:
            sys_ns = [ns for ns in dns.resolver.Resolver().nameservers if ns not in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1")]
        except Exception:
            sys_ns = []
        ns_list = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"] + sys_ns
        tls_local = threading.local()

        def _get_resolver() -> dns.resolver.Resolver:
            r_inst = getattr(tls_local, "resolver", None)
            if r_inst is None:
                r_inst = dns.resolver.Resolver(configure=False)
                r_inst.nameservers = ns_list
                r_inst.timeout = 1.8
                r_inst.lifetime = 2.5
                tls_local.resolver = r_inst
            return r_inst

        wildcard_ips = set()
        try:
            w_ans = _get_resolver().resolve(f"apex-wildcard-probe-918273.{apex_domain}", "A")
            wildcard_ips = {str(r).rstrip(".") for r in w_ans}
            if wildcard_ips:
                log_fn(f"  [!] Wildcard DNS aniqlandi (*.{apex_domain} -> {', '.join(wildcard_ips)}). Yolg'on subdomenlar filtrlanadi.")
                with self.db._lock, self.db._get_conn() as conn:
                    for wip in wildcard_ips:
                        conn.execute(
                            "UPDATE domains SET ip = '' WHERE project_id = ? AND ip = ? AND domain NOT IN (?, ?)",
                            (project_id, wip, base_domain, apex_domain),
                        )
        except Exception:
            pass

        def check_candidate(cand: str):
            ok, _ = scope.is_in_scope(cand)
            if not ok:
                return
            resolver = _get_resolver()
            records = {}
            ip_val = ""
            cname_val = ""
            is_root = cand in (base_domain, apex_domain)
            rtypes = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA") if is_root else ("A",)
            for rtype in rtypes:
                try:
                    ans = resolver.resolve(cand, rtype)
                    vals = [str(r).rstrip(".") for r in ans]
                    records[rtype] = vals
                    if rtype == "A" and vals:
                        ip_val = vals[0]
                        if hasattr(ans, "canonical_name") and ans.canonical_name:
                            cn = str(ans.canonical_name).rstrip(".").lower()
                            if cn and cn != cand:
                                cname_val = cn
                                records["CNAME"] = [cn]
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

            # Only query CNAME separately for non-root hosts if A record resolution returned no IP (to catch Dangling CNAMEs)
            if not is_root and not ip_val:
                try:
                    ans_c = resolver.resolve(cand, "CNAME")
                    c_vals = [str(r).rstrip(".") for r in ans_c]
                    if c_vals:
                        cname_val = c_vals[0]
                        records["CNAME"] = c_vals
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

        # Hybrid Fast-Path: Pre-filter large candidate sets with Go dnsx before deep dnspython inspection
        dnsx_bin = self._find_binary("dnsx")
        res_file = "/tmp/spectre_resolvers.txt"
        if not Path(res_file).exists():
            Path(res_file).write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.4.4\n1.0.0.1\n", encoding="utf-8")

        def _prefilter_with_dnsx(cand_set: set[str]) -> list[str]:
            if not dnsx_bin or len(cand_set) < 40:
                return sorted(cand_set)
            c_file = f"/tmp/spectre_s1_cands_{project_id}.txt"
            Path(c_file).write_text("\n".join(sorted(cand_set)) + "\n", encoding="utf-8")
            # Include -rcode noerror,nxdomain so Dangling CNAMEs (whose target is NXDOMAIN) are preserved for Takeover detection!
            dx_out = self._run_cli(f"{dnsx_bin} -l {c_file} -r {res_file} -a -cname -rcode noerror,nxdomain -resp -silent", log_fn, timeout=22, project_id=project_id)
            alive = {base_domain, apex_domain} & cand_set
            for ln in dx_out.splitlines():
                clean_ln = re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
                if "[A]" in clean_ln or "[CNAME]" in clean_ln:
                    h_clean = clean_ln.split()[0].lower().rstrip(".") if clean_ln else ""
                    if h_clean and h_clean in cand_set:
                        alive.add(h_clean)
            return sorted(alive)

        filtered_cands = _prefilter_with_dnsx(candidates)
        ex_c1 = concurrent.futures.ThreadPoolExecutor(max_workers=35)
        futs_c1 = [ex_c1.submit(check_candidate, c) for c in filtered_cands]
        concurrent.futures.wait(futs_c1, timeout=28)
        ex_c1.shutdown(wait=False, cancel_futures=True)

        # Prune 100% dead NXDOMAIN passive OSINT noise (no IP, no CNAME, no DNS records)
        with self.db._lock, self.db._get_conn() as conn:
            conn.execute(
                "DELETE FROM domains WHERE project_id = ? AND ip = '' AND cname = '' AND (records_json = '{}' OR records_json = '') AND domain NOT IN (?, ?)",
                (project_id, base_domain, apex_domain),
            )

        if only_unresolved:
            return

        # Smart Subdomain Permutation Pass + Recursive 3rd-Level Sub-Zone Discovery
        all_dom_rows = self.db.get_project_bundle(project_id).get("domains", [])
        active_subs = [d["domain"] for d in all_dom_rows if d.get("ip") and d["domain"] != apex_domain]
        perm_candidates = set()
        subzones = set()

        for d in all_dom_rows:
            dn = d["domain"]
            if dn.endswith("." + apex_domain):
                rel = dn[: -(len(apex_domain) + 1)]
                parts = rel.split(".")
                if len(parts) >= 2 and parts[-1] not in ("www", "mail", "ns", "ns1", "ns2"):
                    subzones.add(f"{parts[-1]}.{apex_domain}")

        for sz in sorted(subzones)[:15]:
            perm_candidates.add(sz)
            for sz_pref in ("www", "api", "admin", "my", "portal", "mail", "dev", "auth"):
                perm_candidates.add(f"{sz_pref}.{sz}")

        for sub in active_subs[:25]:
            prefix = sub.replace("." + apex_domain, "").split(".")[0]
            if prefix and prefix not in ("www", "mail", "ns1", "ns2"):
                for mut in (
                    f"{prefix}-dev", f"{prefix}-stage", f"{prefix}-test", f"{prefix}-prod",
                    f"{prefix}-api", f"{prefix}-ip", f"{prefix}-admin", f"{prefix}-v2",
                    f"dev-{prefix}", f"api-{prefix}", f"admin-{prefix}", f"old-{prefix}",
                ):
                    perm_candidates.add(f"{mut}.{apex_domain}")

        existing_set = {d["domain"] for d in all_dom_rows}
        perm_candidates -= existing_set
        if perm_candidates:
            log_fn(f"[SPECTRE Smart Mutator & Sub-Zone Engine] {len(perm_candidates)} ta mutatsiya va 3-darajali sub-zonalar ({len(subzones)} sub-zones) tekshirilmoqda...")
            filtered_perms = _prefilter_with_dnsx(perm_candidates)
            ex_c2 = concurrent.futures.ThreadPoolExecutor(max_workers=35)
            futs_c2 = [ex_c2.submit(check_candidate, c) for c in filtered_perms]
            concurrent.futures.wait(futs_c2, timeout=24)
            ex_c2.shutdown(wait=False, cancel_futures=True)
        self.db.log_task(project_id, "SPECTRE-Agent1", "dns_enum_builtin", "COMPLETED", f"deep_dns {apex_domain}", f"Checked {len(candidates)} candidates & {len(perm_candidates)} permutations")


    def _stage2_shodan_internetdb(self, project_id: int, scope: ScopeGuard, log_fn):
        domains = self.db.get_project_bundle(project_id).get("domains", [])
        ip_to_hosts: dict[str, list[str]] = {}
        cf_prefixes = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.67.", "188.114.")
        cdn_names = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva")
        for d in domains:
            ip = d.get("ip", "").strip()
            cdn_val = str(d.get("cdn_waf", "")).lower()
            if ip and not ip.startswith(cf_prefixes) and not any(c in cdn_val for c in cdn_names):
                ip_to_hosts.setdefault(ip, []).append(d["domain"])

        if not ip_to_hosts:
            return
        log_fn(f"[SPECTRE Stage 2] Shodan InternetDB orqali {len(ip_to_hosts)} ta noyob IP (portlar, CPE va CVE) parallel tekshirilmoqda...")

        def _host_rank(h_name: str) -> int:
            if h_name.startswith(("ns1.", "ns2.", "ns.", "www.ns")):
                return 0
            if any(k in h_name.split(".")[0] for k in ("api", "admin", "my", "id", "auth", "sso", "portal")):
                return 2
            return 1

        def _query_one_ip(item: tuple[str, list[str]]):
            ip, hosts = item
            try:
                r = self.session.get(f"https://internetdb.shodan.io/{ip}", timeout=7)
                if r.status_code != 200:
                    return
                data = r.json()
                ports = data.get("ports", [])
                cpes = data.get("cpes", [])
                vulns = data.get("vulns", [])
                hostnames = data.get("hostnames", [])
                sorted_h = sorted(hosts, key=lambda x: (-_host_rank(x), len(x)))
                primary_h = sorted_h[0]
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
                log_fn(f"  [+] Shodan InternetDB ({ip} -> {primary_h}): Ports={ports} | CPEs={len(cpes)} | CVEs={len(vulns)}")
            except Exception:
                pass

        ex_sh = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        futs_sh = [ex_sh.submit(_query_one_ip, item) for item in list(ip_to_hosts.items())[:40]]
        concurrent.futures.wait(futs_sh, timeout=18)
        ex_sh.shutdown(wait=False, cancel_futures=True)

    # ================= STAGE 2: NETWORK, PORT & TLS =================
    def _stage2_tls_inspect(self, project_id: int, host: str, scope: ScopeGuard, log_fn) -> dict:
        tls_info = {}
        sans = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_info["version"] = ssock.version()
                    tls_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                    tls_info["notAfter"] = cert.get("notAfter", "")
                    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        except ssl.SSLCertVerificationError:
            # Self-signed or expired certificate fallback: extract SANs via unverified DER cert
            try:
                ctx_u = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_u.check_hostname = False
                ctx_u.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with ctx_u.wrap_socket(sock, server_hostname=host) as ssock:
                        tls_info["version"] = ssock.version()
                        tls_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                        der_bytes = ssock.getpeercert(binary_form=True)
                        if der_bytes:
                            pem_str = ssl.DER_cert_to_PEM_cert(der_bytes)
                            p_ossl = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem_str, text=True, capture_output=True, timeout=3)
                            sans = re.findall(r"DNS:([a-zA-Z0-9.*\-_]+)", p_ossl.stdout)
            except Exception:
                pass
        except Exception:
            return tls_info

        if tls_info.get("version"):
            tls_info["san_count"] = len(sans)
            for san in sans:
                clean_san = san.lower().lstrip("*.")
                if scope.is_in_scope(clean_san)[0]:
                    self.db.upsert_domain(project_id, clean_san, source="tls_san")
            self.db.upsert_port(project_id, host, 443, "tcp", service="https", version=tls_info.get("version", ""), source="tls_inspector")
            log_fn(f"  [+] TLS {host}: {tls_info.get('version')} | Cipher: {tls_info.get('cipher')} | SANs: {len(sans)}")

        # Multi-Host Parallel TLS X.509 SAN Sweep across top discovered subdomains
        dom_rows = self.db.get_project_bundle(project_id).get("domains", [])
        known_dom_set = {d["domain"] for d in dom_rows}
        extra_tls_hosts = [
            d["domain"] for d in dom_rows
            if d.get("ip") and d["domain"] != host and not d["domain"].startswith(("ns1.", "ns2.", "mail."))
        ][:8]
        new_san_found = False
        for san in sans:
            if san.lower().lstrip("*.") not in known_dom_set:
                new_san_found = True

        def _inspect_sub_tls(sub_h: str):
            nonlocal new_san_found
            sub_sans = []
            try:
                ctx_s = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_s.check_hostname = False
                ctx_s.verify_mode = ssl.CERT_NONE
                with socket.create_connection((sub_h, 443), timeout=3.5) as s_sock:
                    with ctx_s.wrap_socket(s_sock, server_hostname=sub_h) as s_ssock:
                        der_b = s_ssock.getpeercert(binary_form=True)
                        if der_b:
                            pem_s = ssl.DER_cert_to_PEM_cert(der_b)
                            p_o = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem_s, text=True, capture_output=True, timeout=3)
                            sub_sans = re.findall(r"DNS:([a-zA-Z0-9.*\-_]+)", p_o.stdout)
            except Exception:
                pass
            for s_san in sub_sans:
                c_san = s_san.lower().lstrip("*.")
                if c_san and scope.is_in_scope(c_san)[0]:
                    if c_san not in known_dom_set:
                        new_san_found = True
                    self.db.upsert_domain(project_id, c_san, source="tls_san")

        if extra_tls_hosts:
            ex_tls = concurrent.futures.ThreadPoolExecutor(max_workers=6)
            futs_tls = [ex_tls.submit(_inspect_sub_tls, sh) for sh in extra_tls_hosts]
            concurrent.futures.wait(futs_tls, timeout=9)
            ex_tls.shutdown(wait=False, cancel_futures=True)

        if new_san_found:
            self._stage1_dns_enum(project_id, host, scope, log_fn, only_unresolved=True)

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
        self._probe_tls.last_status = 0
        ok, reason = scope.is_in_scope(url)
        if not ok:
            return ""
        try:
            resp = self.session.get(url, timeout=(3.5, 6.5), verify=False, allow_redirects=True)
            self._probe_tls.last_status = resp.status_code
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
            if resp.status_code in (500, 502, 503, 504):
                return ""
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

            # Vite / Vue 3 / Modern Bundler <link rel="modulepreload" href="...js"> extractor
            for lnk in soup.find_all("link", href=True):
                rel_s = " ".join(lnk.get("rel") or []).lower()
                href_v = lnk["href"].strip()
                if ("modulepreload" in rel_s or "preload" in rel_s or href_v.endswith(".js")) and ".js" in href_v:
                    u = self._record_discovered_url(project_id, href_v, base_url, scope, "modulepreload_js")
                    if u and u.endswith(".js"):
                        js_urls.add(u)

            # Inline <script> route & subdomain extractor
            inline_ep_re = re.compile(r"""['"`]((?:/api/v\d+/|/api/|/v1/|/v2/|/v3/|/graphql|/auth/|/admin/|/internal/)[a-zA-Z0-9_\-/\.?=&{}]+)['"`]""")
            for isc in soup.find_all("script", src=False):
                stxt = isc.string or isc.get_text() or ""
                if len(stxt) > 15:
                    for iep in inline_ep_re.findall(stxt[:60000]):
                        self._record_discovered_url(project_id, iep, base_url, scope, "inline_script")


        wb_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=60"
        try:
            r = self.session.get(wb_url, timeout=6)
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

        js_cache_dir = Path(f"/tmp/spectre_js_cache_{project_id}")
        js_cache_dir.mkdir(parents=True, exist_ok=True)

        def analyze_one_js(js_url: str):
            try:
                r = self.session.get(js_url, timeout=10, verify=False)
                if r.status_code != 200 or "html" in r.headers.get("Content-Type", "").lower():
                    return
                content = r.text[:500000]
                try:
                    safe_jname = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", js_url.split("/")[-1].split("?")[0])[-60:] or "bundle.js"
                    (js_cache_dir / safe_jname).write_text(content, encoding="utf-8", errors="ignore")
                except Exception:
                    pass
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
                    ep_params = []
                    if "{param}" in ep:
                        ep_params.append("id")
                    if "?" in ep:
                        ep_qs = urllib.parse.parse_qs(urllib.parse.urlparse(ep).query)
                        for qk in ep_qs.keys():
                            if qk not in ep_params:
                                ep_params.append(qk)
                    http_m = method_map.get(ep, "GET")
                    self._record_discovered_url(project_id, ep, base_url, scope, "js_intelligence", method=http_m, extra_params=ep_params)

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
        with self._cache_lock:
            self._http_get_cache.clear()
        shutil.rmtree(f"/tmp/spectre_js_cache_{project_id}", ignore_errors=True)
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
            _prog(0.15, "Stage 1/6: 8-OSINT Mesh, Subfinder, Sublist3r, Amass, Dig AXFR...")
            if "crtsh_builtin" in active_ids:
                self._stage1_crtsh(project_id, apex_domain, scope, log_fn)
            spectre_v5_modules.run_deep_subdomain_tools(self, project_id, apex_domain, scope, active_ids, log_fn)
            _prog(0.30, "Stage 1/6: SecLists DNS Enum & Smart Permutations...")
            if "dns_enum_builtin" in active_ids:
                self._stage1_dns_enum(project_id, primary_host, scope, log_fn)

        # Stage 2: Ports, Shodan, Nmap Deep NSE & NetExec
        tls_info = {}
        if recon_mode in ("full", "ports"):
            _prog(0.45, "Stage 2/6: TLS SAN, Shodan InternetDB & ASN/ISP...")
            if "tls_inspector_builtin" in active_ids:
                tls_info = self._stage2_tls_inspect(project_id, primary_host, scope, log_fn)
                self._stage2_shodan_internetdb(project_id, scope, log_fn)
                spectre_v5_modules.enrich_asn_and_isp_intel(self.db, project_id, log_fn)
                self.db.log_task(project_id, "SPECTRE-Agent1", "tls_inspector_builtin", "COMPLETED", f"tls_shodan_asn {primary_host}", f"TLS SAN + Shodan InternetDB + ASN/ISP completed")
            _prog(0.55, f"Stage 2/6: Nmap Deep NSE, Naabu & NetExec ({primary_host})...")
            spectre_v5_modules.run_deep_network_and_ad_tools(self, project_id, primary_host, active_ids, log_fn)
            spectre_ultra_modules.sweep_subnet_neighbors_and_ptr(self.db, project_id, apex_domain, scope, log_fn)
            spectre_ultra_modules.unmask_cloudflare_origin_ips(self.db, self.session, project_id, apex_domain, primary_host, log_fn)
            spectre_deep_modules.probe_nonstandard_web_ports(self.db, self.session, project_id, log_fn)
            spectre_deep_modules.hunt_virtual_hosts(self.db, self.session, project_id, apex_domain, log_fn)
            spectre_v12_modules.resolve_and_probe_ipv6_dual_stack(self.db, self.session, project_id, apex_domain, primary_host, log_fn)
            spectre_v12_modules.probe_udp_services_safe(self.db, project_id, log_fn)



        # Stage 3, 4, 5, 6: Web, API & JS Bundles (Smart Priority Sorting + Parallel HTTP Sweep)
        if recon_mode in ("full", "web_js"):
            _prog(0.70, "Stage 3-6: Parallel Web Probing, Katana SPA Crawl & JS Deconstruction...")
            hv_tokens = ("id", "api", "backend", "accounts", "my", "admin", "portal", "dev", "svc", "auth", "sso", "erp", "crm", "lms", "chat", "zabbix", "git", "doc", "document", "smart", "check", "cabinet", "pay", "huquq")
            low_prefixes = ("ns1.", "ns2.", "ns3.", "ns.", "www.ns", "www.mail.")

            def _dom_priority(d_name: str) -> int:
                if d_name == primary_host:
                    return 100
                if any(d_name.startswith(lp) for lp in low_prefixes):
                    return 10
                first_lbl = d_name.split(".")[0].lower()
                if any(tok in first_lbl for tok in hv_tokens):
                    return 90
                return 60

            probed_domains = set()
            for pass_num in (1, 2):
                if pass_num == 2 and recon_mode == "full":
                    self._stage1_dns_enum(project_id, primary_host, scope, log_fn, only_unresolved=True)
                    self._stage2_shodan_internetdb(project_id, scope, log_fn)
                    spectre_v5_modules.enrich_asn_and_isp_intel(self.db, project_id, log_fn)
                raw_domains = [d["domain"] for d in self.db.get_project_bundle(project_id).get("domains", []) if d.get("ip") or d.get("cname") or d["domain"] == primary_host]
                if primary_host not in raw_domains:
                    raw_domains.insert(0, primary_host)
                domains = sorted(set(raw_domains), key=lambda x: (-_dom_priority(x), x))
                unprobed = [d for d in domains if d not in probed_domains]
                if not unprobed:
                    break

                # Phase A: Fast parallel HTTP/HTTPS probe across up to 60 unprobed live subdomains
                probe_results: dict[str, tuple[str, str]] = {}
                b_cur = self.db.get_project_bundle(project_id)
                dom_ip_map = {d["domain"]: d.get("ip", "") for d in b_cur.get("domains", [])}
                open_ports_by_ip: dict[str, set[int]] = {}
                for pt in b_cur.get("ports", []):
                    pip = pt.get("ip") or pt.get("host") or ""
                    if pip:
                        open_ports_by_ip.setdefault(pip, set()).add(int(pt.get("port", 0)))

                def _fast_probe_host(dom_item: str):
                    if project_id in self.abort_flags:
                        return
                    dip = dom_ip_map.get(dom_item, "")
                    known_pts = open_ports_by_ip.get(dip, set()) | open_ports_by_ip.get(dom_item, set())
                    schemes = ("http", "https") if (80 in known_pts and 443 not in known_pts) else ("https", "http")
                    for sch in schemes:
                        u_cand = f"{sch}://{dom_item}"
                        h_body = self._stage3_http_probe(project_id, u_cand, tls_info if dom_item == primary_host else {}, scope, log_fn)
                        if h_body:
                            probe_results[dom_item] = (u_cand, h_body)
                            break
                        if sch == "https" and getattr(self._probe_tls, "last_status", 0) > 0:
                            break

                batch_to_probe = unprobed[:60]
                for d_p in batch_to_probe:
                    probed_domains.add(d_p)
                ex_p = concurrent.futures.ThreadPoolExecutor(max_workers=12)
                futs_p = [ex_p.submit(_fast_probe_host, d_i) for d_i in batch_to_probe]
                concurrent.futures.wait(futs_p, timeout=35)
                ex_p.shutdown(wait=False, cancel_futures=True)

                # Phase B: Deep Inspection on top-priority live web services
                live_sorted = sorted(probe_results.keys(), key=lambda x: (-_dom_priority(x), x))
                for dom in live_sorted[:18]:
                    if project_id in self.abort_flags:
                        break
                    url, html = probe_results[dom]
                    is_high_val = _dom_priority(dom) >= 60
                    collected_html.append(html[:50000])
                    js_list = self._stage4_html_and_wayback(project_id, url, html, dom, scope, log_fn)
                    spectre_v5_modules.run_deep_web_and_fuzz_tools(
                        self, project_id, url, dom, primary_host, is_high_val, scope, active_ids, js_list, log_fn
                    )
                    if is_high_val:
                        self._stage5_openapi_discovery(project_id, url, scope, log_fn)
                    self._stage6_js_analyzer(project_id, js_list, url, scope, log_fn)
                    if is_high_val:
                        spectre_predator_modules.run_predator_recon_suite(self, project_id, apex_domain, url, js_list, log_fn)
                        spectre_v10_modules.run_v10_enterprise_suite(self, project_id, apex_domain, url, js_list, log_fn)
                        spectre_v11_modules.run_v11_apex_suite(self, project_id, apex_domain, url, js_list, log_fn)
                        spectre_v12_modules.run_v12_titan_suite(self, project_id, apex_domain, primary_host, url, js_list, log_fn)

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
            spectre_deep_modules.harvest_emails_and_osint(self.db, project_id, apex_domain, collected_html, log_fn)
            spectre_deep_modules.build_custom_wordlist_and_params(self.db, project_id, apex_domain, log_fn)
            spectre_v5_modules.run_deep_cloud_osint_and_vuln_tools(self, project_id, apex_domain, primary_host, active_ids, log_fn)
            spectre_v11_modules.cluster_subdomains_by_dom_structure(self.db, self.session, project_id, log_fn)

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
        spectre_deep_modules.probe_nonstandard_web_ports(self.db, self.session, project_id, log_fn)

        _prog(0.55, f"Single-Host Deep Web, FFUF, Katana, Arjun & JS: {target_host}...")
        for scheme in ("https", "http"):
            url = f"{scheme}://{target_host}"
            html = self._stage3_http_probe(project_id, url, tls_info, scope, log_fn)
            if html:
                js_list = self._stage4_html_and_wayback(project_id, url, html, target_host, scope, log_fn)
                spectre_v5_modules.run_deep_web_and_fuzz_tools(
                    self, project_id, url, target_host, target_host, True, scope, active_ids, js_list, log_fn
                )
                self._stage5_openapi_discovery(project_id, url, scope, log_fn)
                self._stage6_js_analyzer(project_id, js_list, url, scope, log_fn)
                spectre_predator_modules.run_predator_recon_suite(self, project_id, apex_domain, url, js_list, log_fn)
                spectre_v10_modules.run_v10_enterprise_suite(self, project_id, apex_domain, url, js_list, log_fn)
                spectre_v11_modules.run_v11_apex_suite(self, project_id, apex_domain, url, js_list, log_fn)
                spectre_v12_modules.run_v12_titan_suite(self, project_id, apex_domain, target_host, url, js_list, log_fn)
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







