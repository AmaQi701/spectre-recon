import json
import re
import urllib.parse
from pathlib import Path

from core.database import DatabaseManager


class TriageAndChainSuperAgent:
    """
    3-SuperAgent (v13.0): Asset-Bound Attack Graph Correlation, Triage & Report Studio.
    Correlates findings, cookies, ports, JS sinks, and API routes per exact host/origin.
    """

    def __init__(self, db: DatabaseManager, reports_dir: str = "/home/amaqi/projects/apex-pentest-gui/reports"):
        self.db = db
        self.reports_dir = Path(reports_dir)
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

        log_fn(f"═══ 3-SUPERAGENT: ASSET-BOUND GRAPH CORRELATION & CHAINING ({proj.get('name', '')}) ═══")

        verified_count = 0
        manual_count = 0
        for f in findings:
            if "[CONFIRMED]" in str(f.get("title", "")) or f.get("confidence") == "Confirmed-PoC":
                if f.get("triage_status") != "Verified":
                    self.db.update_finding_triage(int(f["id"]), "Verified")
                verified_count += 1
            elif f.get("confidence") == "Manual-Review":
                manual_count += 1
            else:
                verified_count += 1
        log_fn(f"  [+] Triage: {verified_count} ta Verified, {manual_count} ta Manual-Review topilma saralandi.")

        known_hosts = {d["domain"].lower() for d in domains if d.get("domain")}
        ip_to_host = {d["ip"]: d["domain"].lower() for d in domains if d.get("ip") and d.get("domain")}

        def _node() -> dict:
            return {
                "cors": [], "weak_cookies": [], "xss_sinks": [], "bola_authz": [],
                "redirects": [], "cves": [], "open_ports": [], "api_routes": [],
                "state_routes": [],
            }

        graph: dict[str, dict] = {}
        sast_sinks: list[dict] = []

        for svc in http_svcs:
            h = self._extract_asset_host(svc.get("url", ""), known_hosts, ip_to_host)
            if not h:
                continue
            g = graph.setdefault(h, _node())
            for ck in json.loads(svc.get("cookies_json") or "[]"):
                if not ck.get("httponly"):
                    g["weak_cookies"].append(ck.get("name", "session"))

        for pt in ports:
            h = (pt.get("host") or ip_to_host.get(pt.get("ip", ""), "")).lower()
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
            if "cookie" in tl and not g["weak_cookies"]:
                g["weak_cookies"].append(f["title"])
            if "dom xss" in tl or "reflection" in tl or "xss" in tl:
                g["xss_sinks"].append(f["title"])
            if "bola" in tl or "idor" in tl or "unauthenticated access" in tl:
                g["bola_authz"].append(f)
            if "redirect" in tl or "oauth" in tl or "ssrf" in tl:
                g["redirects"].append(f)
            if "cve" in tl or "nuclei:" in tl:
                g["cves"].append(f)

        # Per-Host Asset-Bound Graph Correlation Rules
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

            if g["cves"] and g["open_ports"]:
                cf = g["cves"][0]
                self.db.upsert_bug_chain(
                    project_id,
                    f"[{host}] Exposed Network Ports + Known Service CVEs -> Initial Access Vector",
                    "High", 8.9,
                    [f"Host: {host}", f"Open Ports: {', '.join(g['open_ports'][:4])}", cf["title"]],
                    f"'{host}' xostida ochiq qoldirilgan tarmoq portlari va eskirgan servis CVE zaifliklari to'g'ridan-to'g'ri dastlabki kirish xavfini tug'diradi.",
                    "Tashqi tarmoqdan serverga ruxsatsiz kirish.",
                    "Ma'muriy portlarni Firewall orqali yoping va servis versiyalarini yangilang.",
                )

        pt_host = proj.get("primary_target", "").lower()
        cf_hosts = [d["domain"] for d in domains if "cloudflare" in str(d.get("cdn_waf", "")).lower()]
        direct_hosts = [f"{d['domain']} ({d['ip']})" for d in domains if d.get("ip") and "cloudflare" not in str(d.get("cdn_waf", "")).lower()]
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

        all_api_eps = [e["url"] for e in endpoints if e.get("category") in ("api_endpoint", "high_value_endpoint")]
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
        log_fn("═══ 3-SUPERAGENT: ASSET-BOUND GRAPH CHAINING YAKUNLANDI ═══")

    def generate_reports(self, project_id: int) -> dict:
        bundle = self.db.get_project_bundle(project_id)
        proj = bundle.get("project", {})
        domains = bundle.get("domains", [])
        ports = bundle.get("ports", [])
        http_svcs = bundle.get("http_services", [])
        endpoints = bundle.get("endpoints", [])
        findings = [f for f in bundle.get("findings", []) if f.get("triage_status") != "False-Positive"]
        chains = bundle.get("bug_chains", [])

        safe_name = f"project_{project_id}_audit_report"
        md_path = self.reports_dir / f"{safe_name}.md"
        html_path = self.reports_dir / f"{safe_name}.html"

        # Markdown Report
        md_lines = [
            f"# 👻 SPECTRE Cyber-Recon & Security Audit Report: {proj.get('name', '')}",
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
            "### 🌐 Topilgan Asosiy Subdomenlar va IP Serverlar",
        ]
        for d in domains[:35]:
            md_lines.append(f"- `{d['domain']}` ➔ IP: `{d.get('ip') or 'N/A'}` (Manba: `{d.get('source')}`)")
        md_lines.extend([
            "",
            "---",
            "## 2. 🔗 Bug Chaining Scenarios (Zaifliklar Zanjiri)",
        ])
        if not chains:
            md_lines.append("_Zanjirlangan ssenariylar aniqlanmadi._")
        for ch in chains:
            nodes = json.loads(ch.get("nodes_json") or "[]")
            md_lines.extend([
                f"### ⚡ {ch['chain_title']} [{ch['severity']} | CVSS: {ch['cvss_score']}]",
                f"- **Zanjir Bosqichlari:** `{' ➔ '.join(nodes)}`",
                f"- **Ssenariy:** {ch['attack_scenario']}",
                f"- **Ta'siri (Impact):** {ch['impact']}",
                f"- **Remediation (Yechim):** {ch['remediation']}",
                "",
            ])

        md_lines.extend(["---", "## 3. 🔍 Batafsil Zaifliklar va Audit Topilmalari (Findings)"])
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

        md_content = "\n".join(md_lines)
        md_path.write_text(md_content, encoding="utf-8")

        # HTML Printable Report (with proper HTML escaping for safe rendering)
        import html as _html
        rows_html = "".join(
            f"<tr><td><b>{_html.escape(str(f['severity']))}</b> ({_html.escape(str(f['cvss_score']))})</td>"
            f"<td>{_html.escape(str(f['title']))}<br><small>{_html.escape(str(f['cwe']))} | {_html.escape(str(f['owasp']))}</small></td>"
            f"<td><code>{_html.escape(str(f['asset']))}</code></td>"
            f"<td><code>{_html.escape(str(f['evidence']))}</code></td>"
            f"<td>{_html.escape(str(f['remediation']))}</td></tr>"
            for f in findings
        )
        chains_html = "".join(
            f"<tr><td><b>{_html.escape(str(ch['severity']))}</b> ({_html.escape(str(ch['cvss_score']))})</td>"
            f"<td><b>{_html.escape(str(ch['chain_title']))}</b><br><small><code>{_html.escape(' ➔ '.join(json.loads(ch.get('nodes_json') or '[]')))}</code></small></td>"
            f"<td>{_html.escape(str(ch['attack_scenario']))}</td>"
            f"<td>{_html.escape(str(ch['remediation']))}</td></tr>"
            for ch in chains
        )
        html_content = f"""<!DOCTYPE html>
<html lang="uz"><head><meta charset="utf-8"><title>SPECTRE v13.0 Obsidian Emerald Audit Report - {_html.escape(str(proj.get('name', '')))}</title>
<style>
body {{ font-family: "Inter", system-ui, sans-serif; background: #090c0a; color: #e2e8f0; padding: 32px; }}
h1, h2 {{ color: #4ade80; border-bottom: 1px solid #1b2a21; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #0f1512; border-radius: 8px; overflow: hidden; }}
th, td {{ border: 1px solid #1b2a21; padding: 10px 12px; text-align: left; font-size: 13px; }}
th {{ background: #13281c; color: #4ade80; font-weight: 700; }}
code {{ color: #86efac; background: #080b09; padding: 2px 6px; border-radius: 4px; }}
</style></head><body>
<h1>SPECTRE v13.0 Obsidian Emerald — Security &amp; Attack Surface Audit Report: {_html.escape(str(proj.get('name', '')))}</h1>
<p><b>Primary Target:</b> <code>{_html.escape(str(proj.get('primary_target', '')))}</code> | <b>In-Scope:</b> <code>{_html.escape(str(proj.get('in_scope', '')))}</code></p>
<h2>🔗 Zaifliklar Zanjiri (Bug Chaining Scenarios — {len(chains)})</h2>
<table><thead><tr><th>Severity / CVSS</th><th>Zanjir Nomi va Bosqichlari</th><th>Hujum Ssenariysi</th><th>Remediation</th></tr></thead>
<tbody>{chains_html or '<tr><td colspan="4">Zanjirlangan ssenariylar aniqlanmadi.</td></tr>'}</tbody></table>
<h2>🔍 Aniqlangan Zaifliklar va Tekshiruv Nuqtalari ({len(findings)})</h2>
<table><thead><tr><th>Severity / CVSS</th><th>Zaiflik Nomi</th><th>Asset</th><th>Dalil (Evidence)</th><th>Remediation</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</body></html>"""
        html_path.write_text(html_content, encoding="utf-8")

        return {
            "markdown_path": str(md_path),
            "html_path": str(html_path),
            "markdown_preview": md_content,
        }

