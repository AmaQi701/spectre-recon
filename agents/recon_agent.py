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
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

import dns.resolver
import requests
import yaml
from bs4 import BeautifulSoup

from core.database import DatabaseManager
from core.scope_guard import ScopeGuard

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

    def _run_cli(self, cmd: str, log_fn, timeout: int = 90, project_id: int = 0) -> str:
        if project_id in self.abort_flags:
            return ""
        env = os.environ.copy()
        env["PATH"] = ":".join(self.EXTRA_PATHS) + ":" + env.get("PATH", "")
        log_fn(f"[CMD] $ {cmd}")
        proc = None
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
            if project_id:
                self.active_procs.setdefault(project_id, []).append(proc)
            output_lines = []
            if proc.stdout:
                for line in proc.stdout:
                    if project_id in self.abort_flags:
                        break
                    clean_line = line.rstrip()
                    if clean_line:
                        output_lines.append(clean_line)
                        if len(output_lines) <= 45:
                            log_fn(f"  │ {clean_line[:160]}")
            proc.wait(timeout=timeout)
            return "\n".join(output_lines)
        except subprocess.TimeoutExpired:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    proc.kill()
            log_fn(f"[WARN] Command timeout ({timeout}s): {cmd}")
            return ""
        except Exception as e:
            log_fn(f"[ERR] CLI xatolik: {e}")
            return ""


    # ================= STAGE 1: PASSIVE & DNS RECON =================
    def _stage1_crtsh(self, project_id: int, domain: str, scope: ScopeGuard, log_fn):
        log_fn(f"[Stage 1] CRT.sh Certificate Transparency qidiruvi: {domain}")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                entries = resp.json()
                count = 0
                for item in entries:
                    for sub in str(item.get("name_value", "")).splitlines():
                        sub = sub.strip().lower().lstrip("*.")
                        ok, _ = scope.is_in_scope(sub)
                        if ok and "." in sub:
                            self.db.upsert_domain(project_id, sub, source="crt.sh")
                            count += 1
                log_fn(f"[Stage 1] CRT.sh orqali {count} ta yozuv tekshirildi.")
        except Exception as e:
            log_fn(f"[Stage 1] CRT.sh ogohlantirish: {e}")

    def _stage1_dns_enum(self, project_id: int, base_domain: str, scope: ScopeGuard, log_fn):
        apex_domain = ScopeGuard.extract_apex_domain(base_domain)
        log_fn(f"[Stage 1] Chuqur DNS yozuvlari va 60+ subdomen parallel tekshiruvi: {apex_domain}")
        candidates = {base_domain, apex_domain}
        for prefix in self.COMMON_SUBDOMAINS:
            candidates.add(f"{prefix}.{apex_domain}")

        existing = self.db.get_project_bundle(project_id).get("domains", [])
        for d in existing:
            candidates.add(d["domain"])

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
                except Exception:
                    pass
            if cand not in (base_domain, apex_domain) and ip_val and ip_val in wildcard_ips:
                return
            if records:
                cdn = "Cloudflare" if any("cloudflare" in str(v).lower() for v in records.values()) else ""
                self.db.upsert_domain(project_id, cand, ip=ip_val, cname=cname_val, records=records, cdn_waf=cdn, source="dns_enum")
                if ip_val or cname_val:
                    log_fn(f"  [+] DNS Active: {cand} -> {ip_val or cname_val} {f'(Records: {list(records.keys())})' if len(records)>1 else ''}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            list(ex.map(check_candidate, sorted(candidates)))



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

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(probe_path, self.API_DOC_PATHS))



    def _stage6_js_analyzer(self, project_id: int, js_urls: list[str], base_url: str, scope: ScopeGuard, log_fn):
        # Template literal (${...}) va oddiy satrlardagi API yo'llarini tutuvchi chuqur regex
        ep_regex = re.compile(r"""(?:/api/v\d+/|/api/|/v1/|/v2/|/v3/|/graphql|/auth/|/admin/|/internal/|/live/|/stream/|/news/|/channels/)[a-zA-Z0-9_\-/\.?=&${}:]*""")
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

        def analyze_one_js(js_url: str):
            try:
                r = self.session.get(js_url, timeout=10, verify=False)
                if r.status_code != 200 or "html" in r.headers.get("Content-Type", "").lower():
                    return
                content = r.text[:500000]
                raw_eps = ep_regex.findall(content)
                eps = set()
                for ep in raw_eps:
                    cleaned_ep = re.sub(r"\$\{[^}]+\}", "{param}", ep).rstrip(".,;)'\"`")
                    if len(cleaned_ep) > 4:
                        eps.add(cleaned_ep)

                full_urls = set(full_url_regex.findall(content))
                for fu in full_urls:
                    fu_clean = re.sub(r"\$\{[^}]+\}", "{param}", fu)
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
                sorted_eps = sorted(eps)

                self.db.upsert_js_asset(project_id, js_url, endpoints=sorted_eps, params=sorted(extracted_params), sinks=sinks, secrets_hints=secrets)
                for ep in sorted_eps:
                    ep_params = sorted(extracted_params)[:12] if ("/api" in ep or "{param}" in ep or "?" in ep) else []
                    if "{param}" in ep and "id" not in ep_params:
                        ep_params.append("id")
                    self._record_discovered_url(project_id, ep, base_url, scope, "js_intelligence", extra_params=ep_params)
                if sorted_eps or sinks or secrets:
                    log_fn(f"  [+] JS Bundle ({js_url.split('/')[-1]}): {len(sorted_eps)} API route, {len(extracted_params)} param, {len(sinks)} sink, {len(secrets)} config.")
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(analyze_one_js, clean_js_urls[:40]))



    def run_full_recon(self, project_id: int, selected_tools: list[str] | None, log_fn):
        proj = self.db.get_project(project_id)
        if not proj:
            log_fn("[ERR] Loyiha topilmadi.")
            return

        self.db.update_project_status(project_id, "RUNNING_RECON")
        scope = ScopeGuard(proj["in_scope"], proj["out_of_scope"])
        primary_host = ScopeGuard.extract_host(proj["primary_target"])
        ok, reason = scope.is_in_scope(primary_host)
        if not ok:
            log_fn(f"[SCOPE BLOCK] Asosiy nishon '{primary_host}' ruxsat berilgan scope ichida emas: {reason}")
            self.db.update_project_status(project_id, "SCOPE_BLOCKED")
            return

        tools = self.get_tools_status()
        active_ids = set(selected_tools) if selected_tools else {t["id"] for t in tools if t.get("enabled") and t.get("installed")}

        self.abort_flags.discard(project_id)
        apex_domain = ScopeGuard.extract_apex_domain(primary_host)
        safe_host = shlex.quote(primary_host)
        safe_apex = shlex.quote(apex_domain)
        log_fn(f"═══ 🛰️ 1-SUPERAGENT: DEEP AUTONOMOUS RECON BOSHLANDI (Target: {primary_host} | Apex: {apex_domain}) ═══")
        self.db.upsert_domain(project_id, primary_host, source="primary_target")
        if apex_domain != primary_host:
            self.db.upsert_domain(project_id, apex_domain, source="apex_domain")

        # Stage 1
        if "crtsh_builtin" in active_ids:
            self._stage1_crtsh(project_id, apex_domain, scope, log_fn)
        if "subfinder" in active_ids and self._find_binary("subfinder"):
            out = self._run_cli(f"subfinder -d {safe_apex} -silent", log_fn, timeout=45, project_id=project_id)
            for line in out.splitlines():
                if scope.is_in_scope(line.strip())[0]:
                    self.db.upsert_domain(project_id, line.strip(), source="subfinder")
        if "whois" in active_ids and self._find_binary("whois"):
            w_out = self._run_cli(f"whois {safe_apex}", log_fn, timeout=20, project_id=project_id)
            self.db.log_task(project_id, "Agent-1 (Recon)", "whois", "COMPLETED", f"whois {apex_domain}", w_out[:250])
        self._stage1_dns_enum(project_id, primary_host, scope, log_fn)

        # Stage 2
        tls_info = self._stage2_tls_inspect(project_id, primary_host, scope, log_fn)
        if "nmap" in active_ids and self._find_binary("nmap") and project_id not in self.abort_flags:
            log_fn(f"[Stage 2] Nmap Service & Port Scan (Top 100 ports): {primary_host}")
            xml_out = self._run_cli(f"nmap -Pn -sV -T4 --top-ports 100 -oX - {safe_host}", log_fn, timeout=90, project_id=project_id)
            self._parse_nmap_xml(project_id, primary_host, xml_out, log_fn)
            self.db.log_task(project_id, "Agent-1 (Recon)", "nmap", "COMPLETED", f"nmap -Pn -sV --top-ports 100 {primary_host}", "XML Parsed")

        # Stage 3, 4, 5, 6
        domains = [d["domain"] for d in self.db.get_project_bundle(project_id).get("domains", []) if d.get("ip") or d.get("cname") or d["domain"] == primary_host]
        if primary_host not in domains:
            domains.insert(0, primary_host)

        for dom in domains[:8]:
            if project_id in self.abort_flags:
                break
            for scheme in ("https", "http"):
                url = f"{scheme}://{dom}"
                safe_url = shlex.quote(url)
                html = self._stage3_http_probe(project_id, url, tls_info if dom == primary_host else {}, scope, log_fn)
                if html:
                    if "whatweb" in active_ids and self._find_binary("whatweb") and dom == primary_host:
                        ww = self._run_cli(f"whatweb --color=never -a 1 {safe_url}", log_fn, timeout=25, project_id=project_id)
                        self.db.log_task(project_id, "Agent-1 (Recon)", "whatweb", "COMPLETED", f"whatweb {url}", ww[:200])
                    if "wafw00f" in active_ids and self._find_binary("wafw00f") and dom == primary_host:
                        wf = self._run_cli(f"wafw00f {safe_url}", log_fn, timeout=25, project_id=project_id)
                        self.db.log_task(project_id, "Agent-1 (Recon)", "wafw00f", "COMPLETED", f"wafw00f {url}", wf[:200])
                    js_list = self._stage4_html_and_wayback(project_id, url, html, dom, scope, log_fn)
                    if "katana" in active_ids and self._find_binary("katana") and dom == primary_host:
                        kt_out = self._run_cli(f"katana -u {safe_url} -d 2 -jc -silent", log_fn, timeout=40, project_id=project_id)
                        for k_url in kt_out.splitlines():
                            u = self._record_discovered_url(project_id, k_url, url, scope, "katana")
                            if u and u.endswith(".js"):
                                js_list.append(u)
                    self._stage5_openapi_discovery(project_id, url, scope, log_fn)
                    self._stage6_js_analyzer(project_id, js_list, url, scope, log_fn)
                    break



        self.db.update_project_status(project_id, "RECON_COMPLETED")
        log_fn("═══ ✅ 1-SUPERAGENT: RECON VA ATTACK SURFACE XARITASI YAKUNLANDI ═══")





