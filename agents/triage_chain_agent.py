import json
import re
import urllib.parse
from pathlib import Path

from core.database import DatabaseManager


class TriageAndChainSuperAgent:
    """
    Phase 3 Engine: Asset-Bound Attack Graph Correlation, Triage & Report Studio.
    Correlates findings, cookies, ports, JS sinks, and API routes per exact host/origin.
    """

    def __init__(self, db: DatabaseManager, reports_dir: str | Path | None = None):
        self.db = db
        default_rep = Path(__file__).resolve().parent.parent / "reports"
        self.reports_dir = Path(reports_dir) if reports_dir else default_rep
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _extract_asset_host(asset_str: str, known_hosts: set[str], ip_to_host: dict[str, str]) -> str:
        s = (asset_str or "").strip()
        if not s:
            return ""
        if s.startswith(("http://", "https://")):
            h = (urllib.parse.urlparse(s).hostname or "").lower()
            return ip_to_host.get(h, h)
        first = s.split()[0].split(":")[0].strip("()").lower()
        if first in ip_to_host:
            return ip_to_host[first]
        if first in known_hosts:
            return first
        for kh in known_hosts:
            if kh in s.lower():
                return kh
        return ""

    def run_triage_and_chaining(self, project_id: int, log_fn):
        bundle = self.db.get_project_bundle(project_id)
        proj = bundle.get("project", {})
        if not proj:
            log_fn("[ERR] Loyiha topilmadi.")
            return
        domains = bundle.get("domains", [])
        ports = bundle.get("ports", [])
        http_svcs = bundle.get("http_services", [])
        endpoints = bundle.get("endpoints", [])
        js_assets = bundle.get("js_assets", [])
        findings = [f for f in bundle.get("findings", []) if f.get("triage_status") != "False-Positive"]

        log_fn(f"--- [PHASE 3] ASSET-BOUND GRAPH CORRELATION & CHAINING ({proj.get('name', '')}) ---")

        verified_count = 0
        manual_count = 0
        for f in findings:
            conf_val = str(f.get("confidence", ""))
            if "[CONFIRMED]" in str(f.get("title", "")) or "Confirmed-PoC" in conf_val:
                if f.get("triage_status") != "Verified":
                    self.db.update_finding_triage(int(f["id"]), "Verified")
                verified_count += 1
            elif "Manual-Review" in conf_val:
                manual_count += 1
            else:
                verified_count += 1
        log_fn(f"  [+] Triage: {verified_count} ta Verified, {manual_count} ta Manual-Review topilma saralandi.")

        pt_host = str(proj.get("primary_target") or "").strip().lower()
        known_hosts = {d["domain"].lower() for d in domains if d.get("domain")}
        ip_to_host: dict[str, str] = {}
        for d in sorted(domains, key=lambda x: (0 if str(x.get("domain", "")).lower() == pt_host else 1, len(str(x.get("domain", ""))))):
            if d.get("ip") and d.get("domain") and not d.get("cdn_waf"):
                ip_to_host.setdefault(str(d["ip"]).strip(), str(d["domain"]).strip().lower())

        def _node() -> dict:
            return {
                "cors": [], "weak_cookies": [], "xss_sinks": [], "bola_authz": [],
                "redirects": [], "cves": [], "open_ports": [], "api_routes": [],
                "state_routes": [], "data_stores": [], "xfh_poison": [], "proto_debug": [],
                "has_web": False,
            }

        graph: dict[str, dict] = {}
        sast_sinks: list[dict] = []

        csrf_cookie_tokens = ("xsrf-token", "csrftoken", "_csrf", "csrf_token", "csrf-token", "antiforgery")
        analytics_ck_prefixes = (
            "_ym_", "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl_", "__utm", "_pk_",
            "mp_", "amplitude_", "cf_clearance", "__cf_bm", "intercom-", "_hj", "_clck", "_clsk",
        )
        for svc in http_svcs:
            h = self._extract_asset_host(svc.get("url", ""), known_hosts, ip_to_host)
            if not h:
                continue
            g = graph.setdefault(h, _node())
            g["has_web"] = True
            for ck in json.loads(svc.get("cookies_json") or "[]"):
                ck_n = str(ck.get("name") or "session")
                ck_l = ck_n.lower()
                if ck_l.startswith(analytics_ck_prefixes):
                    continue
                if not ck.get("httponly") and not any(ct in ck_l for ct in csrf_cookie_tokens):
                    g["weak_cookies"].append(ck_n)

        for pt in ports:
            raw_pt_h = (pt.get("host") or pt.get("ip") or "").strip().lower()
            pt_ip = str(pt.get("ip") or "").strip()
            h = ip_to_host.get(raw_pt_h) or ip_to_host.get(pt_ip) or raw_pt_h
            if h:
                graph.setdefault(h, _node())["open_ports"].append(f"{pt['port']}/{pt['protocol']} ({pt.get('service', '')})")

        for ep in endpoints:
            h = self._extract_asset_host(ep.get("url", ""), known_hosts, ip_to_host)
            if not h:
                continue
            g = graph.setdefault(h, _node())
            tags = json.loads(ep.get("risk_tags_json") or "[]")
            if ep.get("category") in ("api_endpoint", "high_value_endpoint") or "IDOR_Candidate" in tags:
                g["api_routes"].append(f"{ep.get('method', 'GET')} {ep['url']}")
            if ep.get("method") in ("POST", "PUT", "DELETE", "PATCH"):
                g["state_routes"].append(f"{ep['method']} {ep['url']}")

        for js in js_assets:
            h = self._extract_asset_host(js.get("js_url", ""), known_hosts, ip_to_host)
            sinks = json.loads(js.get("sinks_json") or "[]")
            if h and sinks:
                graph.setdefault(h, _node())["xss_sinks"].append(f"{js['js_url'].split('/')[-1]} ({', '.join(sinks[:3])})")

        for f in findings:
            tl = f.get("title", "").lower()
            cat_l = f.get("category", "").lower()
            if "sast" in cat_l or (":" in str(f.get("asset", "")) and "/" in str(f.get("asset", "")) and not str(f.get("asset", "")).startswith("http")):
                if any(k in tl for k in ("sql injection", "command injection", "deserialization", "ssti", "ssrf", "traversal")):
                    sast_sinks.append(f)
            h = self._extract_asset_host(f.get("asset", ""), known_hosts, ip_to_host)
            if not h:
                continue
            g = graph.setdefault(h, _node())
            if "cors" in tl:
                g["cors"].append(f)
            if "cookie" in tl and not g["weak_cookies"] and not any(ct in tl for ct in csrf_cookie_tokens + analytics_ck_prefixes):
                g["weak_cookies"].append(f["title"])
            if ("dom xss" in tl or "reflection" in tl or "xss" in tl) and "x-forwarded-host" not in tl:
                g["xss_sinks"].append(f["title"])
            if "x-forwarded-host" in tl:
                g["xfh_poison"].append(f)
            if "anonymous ftp" in tl or "smb signing" in tl or "verbose " in tl:
                g["proto_debug"].append(f)
            if (
                cat_l != "hidden attack surface"
                and "manualtestguide" not in str(f.get("agent") or "").lower()
                and (re.search(r"\b(?:bola|idor)\b", tl) or "unauthenticated access" in tl or "access control" in cat_l)
            ):
                g["bola_authz"].append(f)
            if ("redirect" in tl or "oauth" in tl or "ssrf" in tl) and "manualtestguide" not in str(f.get("agent") or "").lower():
                g["redirects"].append(f)
            if "cve" in tl or "nuclei:" in tl or "advisory" in tl or "end-of-life" in tl:
                conf_s = str(f.get("confidence") or "")
                if "Passive Shodan Cache" not in conf_s:
                    g["cves"].append(f)
            if "data store" in tl or any(k in cat_l for k in ("database / cache", "message broker", "streaming / queue", "cluster coordination")):
                g["data_stores"].append(f)

        # Per-Host Asset-Bound Graph Correlation Rules
        seen_cve_chain_sigs: set[str] = set()
        for host, g in graph.items():
            if g["xss_sinks"] and g["weak_cookies"]:
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] Client-Side Execution + Non-HttpOnly Cookie -> Session Hijacking",
                    "High", 8.4,
                    [f"Host: {host}", f"Sink/Reflection: {g['xss_sinks'][0]}", f"Exposed Cookie: {g['weak_cookies'][0]}"],
                    f"'{host}' xostida aniqlangan XSS/DOM sink va HttpOnly bayrog'isiz '{g['weak_cookies'][0]}' cookie birgalikda sessiyani egallash zanjirini hosil qiladi.",
                    "Account Takeover (ATO) — foydalanuvchi sessiyasining o'g'irlanishi.",
                    "Cookie'ga HttpOnly; Secure o'rnating va barcha chiqish nuqtalarini kontekstli kodlang.",
                )
                log_fn(f"  [CHAIN] {host}: XSS/DOM Sink + Cookie '{g['weak_cookies'][0]}' -> ATO zanjiri tuzildi!")

            if g["cors"] and (g["api_routes"] or g["bola_authz"]):
                sample_rt = (g["api_routes"] or [g["bola_authz"][0]["asset"]])[0]
                max_c = max([float(x.get("cvss_score") or 5.3) for x in g["cors"]] + [8.5])
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] CORS Trust Misconfiguration + API Route -> Cross-Origin Data Exfiltration",
                    "Critical" if max_c >= 9.0 else "High", round(min(9.4, max_c), 1),
                    [f"Host: {host}", g["cors"][0]["title"], f"API Target: {sample_rt}"],
                    f"'{host}' xostidagi noto'g'ri CORS siyosati va '{sample_rt}' API endpointi tashqi domendan shaxsiy JSON ma'lumotlarni o'qish imkonini beradi.",
                    "Avtorizatsiyalangan foydalanuvchi ma'lumotlarining uchinchi tomon saytidan o'qilishi.",
                    "Access-Control-Allow-Origin qiymatini qat'iy oq ro'yxat bilan cheklang.",
                )
                log_fn(f"  [CHAIN] {host}: CORS + API ({sample_rt}) zanjiri tuzildi!")

            if g["bola_authz"] and (g["state_routes"] or len(g["api_routes"]) >= 1):
                bf = g["bola_authz"][0]
                is_conf = "[CONFIRMED]" in bf.get("title", "")
                rt_lbl = (g["state_routes"] or g["api_routes"])[0]
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] {'Verified ' if is_conf else ''}Access Control / BOLA Weakness + API Surface -> Account Data Compromise",
                    "Critical" if is_conf else "High", 9.1 if is_conf else 8.3,
                    [f"Host: {host}", bf["title"], f"Route: {rt_lbl}"],
                    f"'{host}' xostida obyekt darajasidagi avtorizatsiya (BOLA/RBAC) zaifligi va '{rt_lbl}' yo'li orqali begona yozuvlarni o'qish yoki o'zgartirish xavfi mavjud.",
                    "Gorizontal yoki vertikal imtiyozlarni oshirish va ma'lumotlar sizib chiqishi.",
                    "Har bir obyekt so'rovida joriy foydalanuvchi egaligini (ownership check) tekshiring.",
                )
                log_fn(f"  [CHAIN] {host}: BOLA/Authz + API ({rt_lbl}) zanjiri tuzildi!")

            if g["redirects"] and g["api_routes"]:
                rf = g["redirects"][0]
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] Redirect / OAuth Flow Weakness + Active API -> Token Leakage Path",
                    "High", 7.9,
                    [f"Host: {host}", rf["title"], f"API Context: {g['api_routes'][0]}"],
                    f"'{host}' dagi tekshirilmagan yo'naltirish / OAuth parametri aktiv API sessiya kontekstida token o'g'irlanishiga olib kelishi mumkin.",
                    "OAuth code/token sizib chiqishi yoki fishing zanjiri.",
                    "Redirect URI parametrlarini aniq domen va yo'l bo'yicha tasdiqlang.",
                )

            if g["cves"] and (g["open_ports"] or g["has_web"]):
                cf = g["cves"][0]
                cve_sig = re.sub(r"\s*\(\d+\s+Hosts\)", "", cf["title"])
                if cve_sig not in seen_cve_chain_sigs:
                    seen_cve_chain_sigs.add(cve_sig)
                    surf_lbl = f"Open Ports: {', '.join(g['open_ports'][:4])}" if g["open_ports"] else "Public HTTP/HTTPS Surface"
                    self.db.upsert_bug_chain(
                        project_id,
                        f"[{host}] Exposed Service Surface + Outdated Component Advisory -> Infrastructure Risk",
                        "High", 8.9,
                        [f"Host: {host}", surf_lbl, cf["title"]],
                        f"'{host}' xostida ochiq tarmoq/veb xizmati va eskirgan komponent versiyasi ({cf['title']}) aniqlandi.",
                        "Tashqi tarmoqdan xizmat barqarorligi va xavfsizligiga ta'sir.",
                        "Ma'muriy portlarni Firewall orqali yoping va xizmat paketlarini yangilang.",
                    )
                    log_fn(f"  [CHAIN] {host}: Exposed Surface + CVE Advisory ({cf['title'][:45]}) zanjiri tuzildi!")

            if g["data_stores"] and g["has_web"]:
                df = g["data_stores"][0]
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] Public Web Application + Exposed Backend Data Store -> Backend Risk Chain",
                    "Critical", 9.2,
                    [f"Host: {host}", "Public Web Service", df["title"]],
                    f"'{host}' xostida ommaviy veb-ilova bilan bir qatorda ma'lumotlar ombori porti ({df['title']}) tashqi interfeysda ochiq qoldirilgan.",
                    "Ma'lumotlar bazasi va ilova sessiyalarining bevosita xavf ostida qolishi.",
                    "Ma'lumotlar ombori portlarini faqat lokal/VPC tarmoqqa bog'lang va tashqi kirishni yoping.",
                )
                log_fn(f"  [CHAIN] {host}: Web Surface + Exposed Data Store zanjiri tuzildi!")

            if g["xfh_poison"] and (g["has_web"] or g["api_routes"]):
                xf = g["xfh_poison"][0]
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] Unvalidated X-Forwarded-Host + Active Web Surface -> Cache / Reset Link Poisoning",
                    "High", 8.1,
                    [f"Host: {host}", xf["title"], "Link / Redirect Generation"],
                    f"'{host}' xostida X-Forwarded-Host tekshirilmasdan havola yasalishi parolni tiklash linklari yoki veb-keshni zaharlash zanjirini hosil qiladi.",
                    "Foydalanuvchi parolini tiklash tokenining uchinchi tomon xostiga yuborilishi yoki kesh ifloslanishi.",
                    "Reverse-proxy da X-Forwarded-Host sarlavhasini tozalang va ALLOWED_HOSTS oq ro'yxatini yoqing.",
                )
                log_fn(f"  [CHAIN] {host}: X-Forwarded-Host + Web Surface zanjiri tuzildi!")

            if g["proto_debug"] and g["has_web"]:
                pf = g["proto_debug"][0]
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] Exposed Legacy Protocol / Debug Trace + Web Surface -> Infrastructure Exposure Chain",
                    "High", 8.2,
                    [f"Host: {host}", "Public Web Service", pf["title"]],
                    f"'{host}' xostida ommaviy veb-xizmat bilan birga ochiq tarmoq protokoli yoki batafsil debug ma'lumoti ({pf['title']}) aniqlandi.",
                    "Tizim ichki yo'llari va tarmoq xizmatlari orqali yonlama harakatlanish xavfi.",
                    "Production serverda DEBUG rejimini o'chiring va FTP/SMB portlarini tashqi interfeysdan yoping.",
                )
                log_fn(f"  [CHAIN] {host}: Protocol/Debug + Web Surface zanjiri tuzildi!")

        pt_host = proj.get("primary_target", "").lower()
        cdn_tokens = ("cloudflare", "cloudfront", "akamai", "fastly", "imperva", "incapsula", "sucuri", "ddos-guard", "qrator")
        cf_hosts = sorted(
            [d["domain"] for d in domains if "cloudflare" in str(d.get("cdn_waf", "")).lower()],
            key=lambda x: (0 if x.lower() == pt_host else 1, len(x), x),
        )
        direct_hosts = []
        seen_orig_ips: set[str] = set()
        for d in domains:
            d_ip = str(d.get("ip") or "").strip()
            d_cdn = str(d.get("cdn_waf") or "").lower()
            d_rec = str(d.get("records_json") or "").lower()
            if not d_ip or d_ip in seen_orig_ips:
                continue
            if any(ct in d_cdn or ct in d_rec for ct in cdn_tokens) or "amazon.com" in d_rec and "cloudfront" in str(d.get("cname") or "").lower():
                continue
            seen_orig_ips.add(d_ip)
            direct_hosts.append(f"{d['domain']} ({d_ip})")
        if cf_hosts and direct_hosts and any(pt_host in ch or ch in pt_host for ch in cf_hosts):
            self.db.upsert_bug_chain(
                project_id,
                f"[{cf_hosts[0]}] Cloudflare WAF Frontend + Exposed Direct Origin IP -> WAF Bypass",
                "High", 8.8,
                [f"WAF Host: {cf_hosts[0]}", f"Direct Origin: {', '.join(direct_hosts[:3])}", "Origin Direct HTTP Access"],
                "Asosiy domen Cloudflare ortida bo'lsa-da, yordamchi subdomenlar orqali to'g'ridan-to'g'ri Origin IP manzil ochiq qolgan.",
                "WAF qoidalarini Host sarlavhasi orqali to'g'ridan-to'g'ri Origin IP ga so'rov yuborib aylanib o'tish.",
                "Origin serverda faqat Cloudflare IP diapazonlaridan keluvchi 80/443 ulanishlarga ruxsat bering.",
            )

        cname_finds = [f for f in findings if "dangling dns cname" in str(f.get("title", "")).lower() or "unclaimed cloud cname" in str(f.get("title", "")).lower()]
        if cname_finds and http_svcs:
            cf0 = cname_finds[0]
            c_host = self._extract_asset_host(cf0.get("asset", ""), known_hosts, ip_to_host) or cf0.get("asset", "")
            self.db.upsert_bug_chain(
                project_id,
                f"[{c_host}] Dangling Cloud CNAME + Parent Domain Origin Trust -> Subdomain Trust Risk",
                "High", 8.6,
                [f"Subdomain: {c_host}", cf0["title"], f"Parent Web Surface ({len(http_svcs)} active services)"],
                f"'{c_host}' subdomenidagi uzilgan CNAME yozuvi asosiy domen cookie va CORS ishonch doirasiga ta'sir ko'rsatishi mumkin.",
                "Subdomen ishonch chegarasining buzilishi va sessiya xavfsizligiga ta'sir.",
                "DNS zonasidan barcha foydalanilmayotgan CNAME yozuvlarini olib tashlang va `__Host-` cookie prefiksidan foydalaning.",
            )

        all_api_eps = [e["url"] for e in endpoints if e.get("category") in ("api_endpoint", "high_value_endpoint")]
        smap_finds = [f for f in findings if "exposed javascript sourcemap" in str(f.get("title", "")).lower()]
        if smap_finds and all_api_eps:
            sf0 = smap_finds[0]
            self.db.upsert_bug_chain(
                project_id,
                f"[SourceMap->API] {sf0['title']} + Reconstructed API Surface -> White-Box Assisted Exposure",
                "High", 8.5,
                [f"SourceMap: {sf0['asset']}", "Reconstructed TypeScript/JSX Source", f"API Target: {all_api_eps[0]}"],
                "Production serverda ochiq qolgan SourceMap (.js.map) orqali tiklangan asl manba kodi ichki API marshrutlari va parametrlarini to'liq ochib bermoqda.",
                "Yashirin biznes-mantiq va API endpointlarning tahlil qilinishi.",
                "Build jarayonida `productionSourceMap: false` o'rnating va `*.map` fayllariga tashqi kirishni yoping.",
            )

        infra_crit = [
            f for f in findings
            if any(k in str(f.get("title", "")).lower() for k in (
                "docker daemon", "docker registry v2", "kubelet", "actuator environment",
                "ignition debug", "prometheus node exporter", "jdwp", "fastcgi", "java rmi",
            ))
        ]
        if infra_crit:
            ic0 = infra_crit[0]
            ic_h = self._extract_asset_host(ic0.get("asset", ""), known_hosts, ip_to_host) or pt_host
            self.db.upsert_bug_chain(
                project_id,
                f"[{ic_h}] Unauthenticated Control/Telemetry Interface + Public Surface -> Infrastructure Exposure",
                "Critical" if ic0.get("severity") == "Critical" else "High",
                9.5 if ic0.get("severity") == "Critical" else 8.4,
                [f"Host: {ic_h}", ic0["title"], f"Endpoint: {ic0['asset']}"],
                "Tashqi tarmoqqa ochiq qoldirilgan konteyner, orkestrator, RPC/debagger yoki diagnostika interfeysi tizim konfiguratsiyasini oshkor qilmoqda.",
                "Muhit o'zgaruvchilari, tokenlar yoki konteyner boshqaruvi ustidan ruxsatsiz amallar xavfi.",
                ic0.get("remediation", "Boshqaruv va diagnostika portlarini tashqi tarmoqdan Firewall orqali yoping."),
            )

        cicd_finds = [f for f in findings if str(f.get("agent", "")) == "Agent-2 (CICD-Auditor)"]
        iac_sca_finds = [f for f in findings if str(f.get("agent", "")) in ("Agent-2 (IaC-Auditor)", "Agent-2 (SCA-Engine)")]
        if cicd_finds and iac_sca_finds:
            cf0, isf0 = cicd_finds[0], iac_sca_finds[0]
            self.db.upsert_bug_chain(
                project_id,
                f"[CI/CD->Infra] {cf0['title']} + {isf0['title']} -> Supply-Chain & Deployment Risk",
                "Critical" if "Critical" in (cf0.get("severity"), isf0.get("severity")) else "High",
                9.2,
                [f"Pipeline: {cf0['asset']}", cf0["title"], isf0["title"]],
                "CI/CD quvuridagi zaiflik hamda konteyner/paket infratuzilmasidagi xatolik birgalikda dasturiy ta'minot zanjiri (Supply-Chain) xavfini yuzaga keltiradi.",
                "Build muhiti va deploy qilinadigan konteyner obrazlarining yaxlitligi buzilishi.",
                f"{cf0.get('remediation', '')} {isf0.get('remediation', '')}".strip(),
            )

        ai_finds = [f for f in findings if str(f.get("agent", "")) == "Agent-2 (AI-Posture)"]
        if ai_finds and (all_api_eps or iac_sca_finds):
            af0 = ai_finds[0]
            rhs_lbl = iac_sca_finds[0]["title"] if iac_sca_finds else f"API Surface ({all_api_eps[0]})"
            self.db.upsert_bug_chain(
                project_id,
                f"[AI/MCP->Data] {af0['title']} + {rhs_lbl} -> Agentic RAG & Model Exposure Chain",
                "Critical", 9.6,
                [f"AI Surface: {af0['asset']}", af0["title"], rhs_lbl],
                "Autentifikatsiyasiz AI/LLM, RAG vektor ombori yoki MCP vositalar serveri ichki API va korporativ ma'lumotlarga vositachi bo'lib xizmat qilmoqda.",
                "Korporativ RAG hujjatlarining sizib chiqishi yoki AI agent vositalari (`tools/list`) orqali ichki resurslarga murojaat.",
                af0.get("remediation", "AI/MCP endpointlarida OAuth 2.1 / mTLS autentifikatsiyasini majburiy qiling."),
            )

        if sast_sinks and all_api_eps:
            sf = sast_sinks[0]
            self.db.upsert_bug_chain(
                project_id,
                f"[SAST->DAST] {sf['title']} + Reachable API Surface -> High-Impact Code Path",
                "Critical" if sf.get("severity") == "Critical" else "High", 9.0,
                [f"Code Sink: {sf['asset']}", sf["title"], f"Reachable Route: {all_api_eps[0]}"],
                "Manba kodida (yoki tiklangan SourceMap ichida) topilgan xavfli funksiya hamda ochiq API endpoint birgalikda real ekspluatatsiya yo'lini ko'rsatmoqda.",
                "Backend server yoki ma'lumotlar bazasi ustidan ruxsatsiz amallar bajarilishi.",
                sf.get("remediation", "Parametrlangan so'rovlar va xavfsiz API chaqiruvlaridan foydalaning."),
            )

        self.db.update_project_status(project_id, "AUDIT_READY_FOR_REPORT")
        log_fn("--- [PHASE 3] ASSET-BOUND GRAPH CHAINING YAKUNLANDI ---")

    def generate_reports(self, project_id: int) -> dict:
        bundle = self.db.get_project_bundle(project_id)
        proj = bundle.get("project", {})
        domains = bundle.get("domains", [])
        ports = bundle.get("ports", [])
        http_svcs = bundle.get("http_services", [])
        endpoints = bundle.get("endpoints", [])
        findings = [f for f in bundle.get("findings", []) if f.get("triage_status") != "False-Positive" and f.get("severity") != "Info"]
        intel_entries = []
        seen_intel: set[str] = set()
        for lg in bundle.get("task_logs", []):
            if lg.get("agent") == "SPECTRE-Intel":
                s_key = f"{lg.get('tool')}:{lg.get('summary')}"
                if s_key not in seen_intel:
                    seen_intel.add(s_key)
                    intel_entries.append(lg)
        chains = bundle.get("bug_chains", [])

        safe_name = f"project_{project_id}_audit_report"
        md_path = self.reports_dir / f"{safe_name}.md"
        html_path = self.reports_dir / f"{safe_name}.html"

        # Markdown Report
        md_lines = [
            f"# SPECTRE v8.0.0 Security & Attack Surface Audit Report: {proj.get('name', '')}",
            f"- **Asosiy Nishon (Primary Target):** `{proj.get('primary_target', '')}`",
            f"- **In-Scope:** `{proj.get('in_scope', '')}`",
            f"- **Sana:** `{proj.get('created_at', '')}`",
            "",
            "---",
            "## 1. Executive Summary (Umumiy Xulosa)",
            f"- **Aniqlangan Subdomenlar:** {len(domains)} ta",
            f"- **Ochiq Portlar va Servislar:** {len(ports)} ta",
            f"- **Faol HTTP/HTTPS Servislar va Panellar:** {len(http_svcs)} ta",
            f"- **Topilgan API va Web Endpointlar:** {len(endpoints)} ta",
            f"- **Aniqlangan Zaifliklar va Tekshiruv Nuqtalari:** {len(findings)} ta",
            f"- **Zaifliklar Zanjiri (Bug Chains):** {len(chains)} ta",
            "",
            "### Topilgan Asosiy Subdomenlar va IP Serverlar",
        ]
        for d in domains[:35]:
            md_lines.append(f"- `{d['domain']}` -> IP: `{d.get('ip') or 'N/A'}` (Manba: `{d.get('source')}`)")
        md_lines.extend([
            "",
            "---",
            "## 2. Bug Chaining Scenarios (Zaifliklar Zanjiri)",
        ])
        if not chains:
            md_lines.append("_Zanjirlangan ssenariylar aniqlanmadi._")
        for ch in chains:
            nodes = json.loads(ch.get("nodes_json") or "[]")
            md_lines.extend([
                f"### {ch['chain_title']} [{ch['severity']} | CVSS: {ch['cvss_score']}]",
                f"- **Zanjir Bosqichlari:** `{' -> '.join(nodes)}`",
                f"- **Ssenariy:** {ch['attack_scenario']}",
                f"- **Ta'siri (Impact):** {ch['impact']}",
                f"- **Remediation (Yechim):** {ch['remediation']}",
                "",
            ])

        md_lines.extend(["---", "## 3. Batafsil Zaifliklar va Audit Topilmalari (Findings)"])
        for idx, f in enumerate(findings, start=1):
            md_lines.extend([
                f"### 3.{idx}. [{f['severity']}] {f['title']} (CVSS {f['cvss_score']})",
                f"- **Kategoriya:** {f['category']} | **CWE:** `{f['cwe']}` | **OWASP:** `{f['owasp']}`",
                f"- **Nishon (Asset):** `{f['asset']}`",
                f"- **Holati:** `{f['confidence']}` ({f['agent']})",
                f"- **Texnik Dalil (Evidence):** `{f['evidence']}`",
                f"- **Root Cause:** {f['root_cause']}",
                f"- **Remediation (Yopish yo'li):** {f['remediation']}",
                "",
            ])

        if intel_entries:
            md_lines.extend(["---", "## 4. Arxitektura va OSINT Razvedka Xulosasi (Consolidated Recon Intel)"])
            for ilg in intel_entries[:25]:
                md_lines.append(f"- **`[{ilg.get('tool')}]`** (`{ilg.get('command')}`): {ilg.get('summary')}")
            md_lines.append("")

        from core.compliance_exporter import build_compliance_matrix
        comp_mat = build_compliance_matrix(bundle)
        posture_score = comp_mat.get("posture_score", 100)
        fw_map = comp_mat.get("frameworks", {})
        md_lines.extend([
            "---",
            f"## 5. Xalqaro Standartlar Muvofiqlik Matritsasi (Security Posture Score: {posture_score}/100)",
        ])
        for fw_label, fw_key in (
            ("OWASP Top 10:2021", "owasp_2021"),
            ("OWASP API Security Top 10:2023", "owasp_api_2023"),
            ("PCI-DSS v4.0", "pci_dss_v4"),
            ("ISO/IEC 27001:2022", "iso_27001_2022"),
            ("NIST CSF 2.0", "nist_csf_2"),
            ("AICPA SOC 2 TSC", "soc2_tsc"),
            ("MITRE ATT&CK Enterprise v15", "mitre_attack_v15"),
        ):
            ctrls = fw_map.get(fw_key) or {}
            if ctrls:
                md_lines.append(f"### {fw_label}")
                for c_name, c_cnt in ctrls.items():
                    md_lines.append(f"- `{c_name}`: **{c_cnt}** ta topilma")
                md_lines.append("")

        md_content = "\n".join(md_lines)
        md_path.write_text(md_content, encoding="utf-8")

        # HTML Printable & Interactive CISO Report Portal v8.0 (100% offline, CSP-clean, escaped)
        import html as _html
        from core.remediation_cookbook import build_fix_patch_snippet, build_safe_reproducer

        svg_items = []
        for idx_c, ch in enumerate(chains[:6]):
            nodes_l = (json.loads(ch.get("nodes_json") or "[]") + ["Target Impact"])[:3]
            while len(nodes_l) < 3:
                nodes_l.append("Impact")
            y0 = 22 + idx_c * 52
            stroke_c = "#ef4444" if ch.get("severity") == "Critical" else "#f97316"
            for col_i, nd_txt in enumerate(nodes_l):
                x0 = 18 + col_i * 310
                lbl = _html.escape(str(nd_txt)[:34])
                svg_items.append(
                    f"<rect x='{x0}' y='{y0}' width='265' height='36' rx='6' fill='#111c16' stroke='{stroke_c}' stroke-width='1.4'/>"
                    f"<text x='{x0 + 12}' y='{y0 + 22}' fill='#e2e8f0' font-size='11.5' font-family='monospace'>{lbl}</text>"
                )
                if col_i < 2:
                    svg_items.append(
                        f"<line x1='{x0 + 265}' y1='{y0 + 18}' x2='{x0 + 308}' y2='{y0 + 18}' stroke='#4ade80' stroke-width='1.6'/>"
                        f"<polygon points='{x0 + 308},{y0 + 18} {x0 + 300},{y0 + 14} {x0 + 300},{y0 + 22}' fill='#4ade80'/>"
                    )
        svg_h = max(76, len(chains[:6]) * 52 + 28)
        attack_svg_html = (
            f"<svg viewBox='0 0 930 {svg_h}' style='width:100%;max-width:980px;background:#0b110e;border:1px solid #1b2a21;border-radius:8px;margin:10px 0;'>"
            + "".join(svg_items)
            + "</svg>"
        ) if svg_items else ""

        rows_html = "".join(
            f"<tr class='f-row' data-sev='{_html.escape(str(f['severity']), quote=True)}' data-kev='{'1' if '[CISA-KEV' in str(f.get('evidence', '')) else '0'}'>"
            f"<td><b>{_html.escape(str(f['severity']))}</b> ({_html.escape(str(f['cvss_score']))})"
            + ("<br><span style='background:#7f1d1d;color:#fecaca;padding:1px 5px;border-radius:3px;font-size:11px;font-weight:700;'>CISA KEV</span>" if "[CISA-KEV" in str(f.get("evidence", "")) else "")
            + f"<br><small>{_html.escape(str(f.get('confidence', '')))}</small></td>"
            f"<td>{_html.escape(str(f['title']))}<br><small>{_html.escape(str(f['cwe']))} | {_html.escape(str(f['owasp']))}</small></td>"
            f"<td><code>{_html.escape(str(f['asset']))}</code></td>"
            f"<td><code>{_html.escape(str(f['evidence']))}</code>"
            f"<div style='margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;'>"
            f"<button class='flt-btn' style='padding:3px 8px;font-size:11px;' data-cmd='{_html.escape(build_safe_reproducer(f), quote=True)}' onclick='spCopyAttr(this,\"data-cmd\")'>Copy Reproducer</button>"
            f"<button class='flt-btn' style='padding:3px 8px;font-size:11px;' data-fix='{_html.escape(build_fix_patch_snippet(f), quote=True)}' onclick='spCopyAttr(this,\"data-fix\")'>Copy Fix Patch</button>"
            f"</div></td>"
            f"<td>{_html.escape(str(f['remediation']))}</td></tr>"
            for f in findings
        )
        chains_html = "".join(
            f"<tr><td><b>{_html.escape(str(ch['severity']))}</b> ({_html.escape(str(ch['cvss_score']))})</td>"
            f"<td><b>{_html.escape(str(ch['chain_title']))}</b><br><small><code>{_html.escape(' -> '.join(json.loads(ch.get('nodes_json') or '[]')))}</code></small></td>"
            f"<td>{_html.escape(str(ch['attack_scenario']))}</td>"
            f"<td>{_html.escape(str(ch['remediation']))}</td></tr>"
            for ch in chains
        )
        crit_c = sum(1 for f in findings if f.get("severity") == "Critical")
        high_c = sum(1 for f in findings if f.get("severity") == "High")
        med_c = sum(1 for f in findings if f.get("severity") == "Medium")
        low_c = sum(1 for f in findings if f.get("severity") == "Low")
        kev_c = sum(1 for f in findings if "[CISA-KEV" in str(f.get("evidence", "")))
        comp_rows_html = ""
        for fw_lbl, fw_k in (
            ("OWASP Top 10:2021", "owasp_2021"),
            ("OWASP API:2023", "owasp_api_2023"),
            ("PCI-DSS v4.0", "pci_dss_v4"),
            ("ISO/IEC 27001:2022", "iso_27001_2022"),
            ("NIST CSF 2.0", "nist_csf_2"),
            ("AICPA SOC 2 TSC", "soc2_tsc"),
            ("MITRE ATT&CK v15", "mitre_attack_v15"),
        ):
            for ctrl_n, cnt_n in (fw_map.get(fw_k) or {}).items():
                comp_rows_html += (
                    f"<tr><td><b>{_html.escape(fw_lbl)}</b></td>"
                    f"<td><code>{_html.escape(ctrl_n)}</code></td>"
                    f"<td><b>{cnt_n}</b></td></tr>"
                )
        kpi_bar = (
            f"<div style='display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;'>"
            f"<div style='background:#0d2116;border:1px solid #22c55e;padding:10px 16px;border-radius:8px;'><b>Posture Score:</b> {posture_score}/100</div>"
            f"<div style='background:#1a1114;border:1px solid #7f1d1d;padding:10px 16px;border-radius:8px;'><b>Critical:</b> {crit_c}</div>"
            f"<div style='background:#1c1410;border:1px solid #9a3412;padding:10px 16px;border-radius:8px;'><b>High:</b> {high_c}</div>"
            f"<div style='background:#1a180f;border:1px solid #854d0e;padding:10px 16px;border-radius:8px;'><b>Medium:</b> {med_c}</div>"
            f"<div style='background:#0f1914;border:1px solid #166534;padding:10px 16px;border-radius:8px;'><b>Low:</b> {low_c}</div>"
            f"<div style='background:#17121e;border:1px solid #581c87;padding:10px 16px;border-radius:8px;'><b>CISA KEV:</b> {kev_c}</div>"
            f"<div style='background:#0f172a;border:1px solid #1e3a8a;padding:10px 16px;border-radius:8px;'><b>Attack Chains:</b> {len(chains)}</div>"
            f"</div>"
        )
        html_content = f"""<!DOCTYPE html>
<html lang="uz"><head><meta charset="utf-8"><title>SPECTRE v8.0.0 Audit Report - {_html.escape(str(proj.get('name', '')))}</title>
<style>
body {{ font-family: "Inter", system-ui, sans-serif; background: #090c0a; color: #e2e8f0; padding: 32px; }}
h1, h2 {{ color: #4ade80; border-bottom: 1px solid #1b2a21; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #0f1512; border-radius: 8px; overflow: hidden; }}
th, td {{ border: 1px solid #1b2a21; padding: 10px 12px; text-align: left; font-size: 13px; vertical-align: top; }}
th {{ background: #13281c; color: #4ade80; font-weight: 700; }}
code {{ color: #86efac; background: #080b09; padding: 2px 6px; border-radius: 4px; word-break: break-all; }}
.flt-bar {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 12px 0; }}
.flt-btn {{ background: #121b16; color: #e2e8f0; border: 1px solid #24362b; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-weight: 600; font-size: 12px; }}
.flt-btn.active, .flt-btn:hover {{ background: #143321; color: #4ade80; border-color: #22c55e; }}
.flt-inp {{ background: #090c0a; color: #f1f5f9; border: 1px solid #24362b; border-radius: 6px; padding: 6px 12px; min-width: 280px; font-size: 12.5px; }}
@media print {{ body {{ background: #ffffff; color: #111827; padding: 12px; }} table, th, td {{ border-color: #d1d5db; background: #ffffff; color: #111827; }} code {{ background: #f3f4f6; color: #065f46; }} .flt-bar {{ display: none; }} }}
</style></head><body>
<h1>SPECTRE v8.0.0 — Enterprise Security &amp; Attack Surface Report: {_html.escape(str(proj.get('name', '')))}</h1>
<p><b>Primary Target:</b> <code>{_html.escape(str(proj.get('primary_target', '')))}</code> | <b>In-Scope:</b> <code>{_html.escape(str(proj.get('in_scope', '')))}</code></p>
{kpi_bar}
<h2>Zaifliklar Zanjiri va Kill-Chain Grafikasi (Bug Chaining Scenarios — {len(chains)})</h2>
{attack_svg_html}
<table><thead><tr><th>Severity / CVSS</th><th>Zanjir Nomi va Bosqichlari</th><th>Hujum Ssenariysi</th><th>Remediation</th></tr></thead>
<tbody>{chains_html or '<tr><td colspan="4">Zanjirlangan ssenariylar aniqlanmadi.</td></tr>'}</tbody></table>
<h2>Aniqlangan Zaifliklar va Tekshiruv Nuqtalari ({len(findings)})</h2>
<div class="flt-bar">
  <button class="flt-btn active" onclick="spSetSev('ALL', this)">All ({len(findings)})</button>
  <button class="flt-btn" onclick="spSetSev('Critical', this)">Critical ({crit_c})</button>
  <button class="flt-btn" onclick="spSetSev('High', this)">High ({high_c})</button>
  <button class="flt-btn" onclick="spSetSev('Medium', this)">Medium ({med_c})</button>
  <button class="flt-btn" onclick="spSetSev('Low', this)">Low ({low_c})</button>
  <button class="flt-btn" onclick="spSetSev('KEV', this)">CISA KEV ({kev_c})</button>
  <input id="sp-q" class="flt-inp" type="search" placeholder="Filter by host, CVE, CWE, title..." oninput="spFilter()"/>
</div>
<table id="sp-ftbl"><thead><tr><th>Severity / CVSS</th><th>Zaiflik Nomi</th><th>Asset</th><th>Dalil (Evidence)</th><th>Remediation</th></tr></thead>
<tbody>{rows_html}</tbody></table>
<h2>Xalqaro Standartlar Muvofiqlik Matritsasi (OWASP / API:2023 / PCI-DSS v4.0 / ISO 27001 / NIST CSF 2.0 / SOC 2 / MITRE ATT&amp;CK v15)</h2>
<table><thead><tr><th>Standart (Framework)</th><th>Nazorat Bandi (Control)</th><th>Ta'sirlangan Topilmalar</th></tr></thead>
<tbody>{comp_rows_html or '<tr><td colspan="3">Nazorat buzilishlari aniqlanmadi (100% Muvofiq).</td></tr>'}</tbody></table>
<script>
var _spSev = 'ALL';
function spSetSev(s, btn) {{
  _spSev = s;
  document.querySelectorAll('.flt-btn').forEach(function(b){{ b.classList.remove('active'); }});
  if (btn) btn.classList.add('active');
  spFilter();
}}
function spFilter() {{
  var q = (document.getElementById('sp-q').value || '').toLowerCase();
  document.querySelectorAll('#sp-ftbl tr.f-row').forEach(function(tr) {{
    var sv = tr.getAttribute('data-sev') || '';
    var kv = tr.getAttribute('data-kev') || '0';
    var okSev = (_spSev === 'ALL') || (_spSev === 'KEV' ? kv === '1' : sv === _spSev);
    var okQ = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
    tr.style.display = (okSev && okQ) ? '' : 'none';
  }});
}}
function spCopyAttr(btn, attrName) {{
  var v = btn.getAttribute(attrName) || '';
  if (navigator.clipboard && v) {{
    navigator.clipboard.writeText(v);
    var old = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function(){{ btn.textContent = old; }}, 1200);
  }}
}}
</script>
</body></html>"""
        html_path.write_text(html_content, encoding="utf-8")

        return {
            "markdown_path": str(md_path),
            "html_path": str(html_path),
            "markdown_preview": md_content,
        }

