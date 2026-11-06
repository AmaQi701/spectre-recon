import json
from pathlib import Path

from core.database import DatabaseManager


class TriageAndChainSuperAgent:
    """
    3-SuperAgent: Triage, False-Positive Filtering, Bug Chaining & Report Generator.
    Topilgan zaifliklarni saralaydi, zanjirlaydi (Bug Chaining) va professional
    Markdown / HTML hisobot tayyorlaydi.
    """

    def __init__(self, db: DatabaseManager, reports_dir: str = "/home/amaqi/projects/apex-pentest-gui/reports"):
        self.db = db
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def run_triage_and_chaining(self, project_id: int, log_fn):
        bundle = self.db.get_project_bundle(project_id)
        proj = bundle.get("project", {})
        findings = bundle.get("findings", [])
        endpoints = bundle.get("endpoints", [])
        http_svcs = bundle.get("http_services", [])

        log_fn(f"═══ 🔗 3-SUPERAGENT: TRIAGE & BUG CHAINING TAHLILI BOSHLANDI ({proj.get('name', '')}) ═══")

        # 1. False-Positive Triage
        verified_count = 0
        manual_count = 0
        for f in findings:
            if f.get("confidence") == "Manual-Review":
                manual_count += 1
            else:
                verified_count += 1
        log_fn(f"  [+] Triage: {verified_count} ta avtomatik tasdiqlangan, {manual_count} ta Manual-Review nuqtasi saralandi.")

        # 2. Bug Chaining Correlation Engine
        titles = [f["title"].lower() for f in findings]
        categories = [f["category"].lower() for f in findings]

        has_cors = any("cors" in t for t in titles)
        has_cookie_weak = any("cookie" in t for t in titles)
        has_dom_sink = any("dom xss" in t for t in titles)
        has_idor = any("idor" in t for t in titles)
        has_ssrf_redir = any("ssrf" in t or "redirect" in t for t in titles)
        has_sast_inj = any("sql injection" in t or "command injection" in t for t in titles)
        has_api_eps = any(ep.get("category") in ("api_endpoint", "high_value_endpoint") for ep in endpoints)

        if has_dom_sink and has_cookie_weak:
            self.db.upsert_bug_chain(
                project_id,
                "Chain #1: DOM XSS Sink + Missing HttpOnly Cookie -> Session Hijacking Risk",
                "High",
                8.2,
                ["JavaScript DOM XSS Sink (innerHTML/eval)", "Session Cookie without HttpOnly Flag", "Authenticated User Session"],
                "JS fayldagi tozalanmagan DOM sink orqali XSS yuzaga kelsa, HttpOnly bayrog'i yo'qligi sababli document.cookie o'qilishi va sessiya egallanishi mumkin.",
                "Account Takeover (ATO) va foydalanuvchi sessiyasining to'liq o'g'irlanishi.",
                "1) Barcha session cookie'larga HttpOnly va Secure qo'shing. 2) DOM sinklarni DOMPurify bilan himoyalang va qat'iy CSP o'rnating.",
            )
            log_fn("  [⚡ CHAIN] DOM XSS Sink + Insecure Cookie -> Session Hijacking zanjiri tuzildi!")

        if has_cors and (has_api_eps or has_idor):
            self.db.upsert_bug_chain(
                project_id,
                "Chain #2: Permissive CORS + API/IDOR Endpoint -> Cross-Origin Sensitive Data Exposure",
                "High",
                8.5,
                ["Permissive CORS Policy", "API Endpoint with Object ID Parameter", "Cross-Origin Read Access"],
                "Keng ruxsat berilgan CORS siyosati va obyektni ID orqali qaytaruvchi API endpoint birgalikda tashqi domendan foydalanuvchi ma'lumotlarini o'qish xavfini yaratadi.",
                "Maxfiy API javoblarining ruxsatsiz uchinchi tomon originlari tomonidan o'qilishi.",
                "CORS Allow-Origin ro'yxatini cheklang va API endpointlarda obyekt darajasidagi avtorizatsiyani (BOLA) tekshiring.",
            )
            log_fn("  [⚡ CHAIN] Permissive CORS + API/IDOR -> Cross-Origin Data Exposure zanjiri tuzildi!")

        if has_ssrf_redir and has_api_eps:
            self.db.upsert_bug_chain(
                project_id,
                "Chain #3: Open Redirect / SSRF Parameter + API/Auth Flow -> Token Leak or Internal Probe",
                "High",
                7.8,
                ["URL/Redirect Parameter in Endpoint", "API / Auth Callback Route", "Internal Network / OAuth Token Context"],
                "Yo'naltirish (redirect/url) parametri OAuth/Auth oqimida token sizib chiqishiga yoki server tomonidan ichki servislarga so'rov yuborilishiga (SSRF) sabab bo'lishi mumkin.",
                "OAuth token o'g'irlanishi yoki ichki infratuzilma port/servislarining oshkor bo'lishi.",
                "Redirect va callback parametrlarini faqat ruxsat berilgan domen/yo'llar oq ro'yxati bilan tekshiring.",
            )
            log_fn("  [⚡ CHAIN] Redirect/SSRF Parameter + API Flow zanjiri tuzildi!")

        if has_sast_inj or (not has_dom_sink and not has_cors and findings):
            self.db.upsert_bug_chain(
                project_id,
                "Chain #4: Missing Defense-in-Depth Headers + Application Layer Findings",
                "Medium",
                6.8,
                ["Missing CSP / Hardening Headers", "Discovered Application Endpoints / Sinks", "Reduced Browser-Side Mitigation"],
                "Himoya headerlarining (CSP, HSTS, X-Frame-Options) yo'qligi ilova darajasidagi kamchiliklarning (Clickjacking, XSS, MITM) ta'sir darajasini oshiradi.",
                "Mijoz tomonidagi xavfsizlik cheklovlarining aylanib o'tilishi.",
                "Barcha javoblarda qat'iy CSP, HSTS va X-Frame-Options: DENY siyosatini joriy qiling.",
            )

        self.db.update_project_status(project_id, "AUDIT_READY_FOR_REPORT")
        log_fn("═══ ✅ 3-SUPERAGENT: TRIAGE VA BUG CHAINING YAKUNLANDI ═══")

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
            f"# 🛡️ Xavfsizlik Auditi va Pentest Hisoboti: {proj.get('name', '')}",
            f"- **Asosiy Nishon (Primary Target):** `{proj.get('primary_target', '')}`",
            f"- **In-Scope:** `{proj.get('in_scope', '')}`",
            f"- **Sana:** `{proj.get('created_at', '')}`",
            "",
            "---",
            "## 1. Executive Summary (Umumiy Xulosa)",
            f"- **Aniqlangan Subdomenlar:** {len(domains)} ta",
            f"- **Ochiq Portlar va Servislar:** {len(ports)} ta",
            f"- **Faol HTTP/HTTPS Servislar:** {len(http_svcs)} ta",
            f"- **Topilgan API va Web Endpointlar:** {len(endpoints)} ta",
            f"- **Aniqlangan Zaifliklar va Tekshiruv Nuqtalari:** {len(findings)} ta",
            f"- **Zaifliklar Zanjiri (Bug Chains):** {len(chains)} ta",
            "",
            "---",
            "## 2. 🔗 Bug Chaining Scenarios (Zaifliklar Zanjiri)",
        ]
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

        # HTML Printable Report
        rows_html = "".join(
            f"<tr><td><b>{f['severity']}</b> ({f['cvss_score']})</td><td>{f['title']}<br><small>{f['cwe']} | {f['owasp']}</small></td>"
            f"<td><code>{f['asset']}</code></td><td><code>{f['evidence']}</code></td><td>{f['remediation']}</td></tr>"
            for f in findings
        )
        html_content = f"""<!DOCTYPE html>
<html lang="uz"><head><meta charset="utf-8"><title>Audit Report - {proj.get('name')}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 32px; }}
h1, h2 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #1e293b; }}
th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; font-size: 13px; }}
th {{ background: #0284c7; color: #fff; }}
code {{ color: #f472b6; background: #0f172a; padding: 2px 5px; border-radius: 4px; }}
</style></head><body>
<h1>🛡️ APEX-ASM Security Audit Report: {proj.get('name')}</h1>
<p><b>Primary Target:</b> <code>{proj.get('primary_target')}</code> | <b>In-Scope:</b> <code>{proj.get('in_scope')}</code></p>
<h2>Aniqlangan Zaifliklar va Tekshiruv Nuqtalari ({len(findings)})</h2>
<table><thead><tr><th>Severity / CVSS</th><th>Zaiflik Nomi</th><th>Asset</th><th>Dalil (Evidence)</th><th>Remediation</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</body></html>"""
        html_path.write_text(html_content, encoding="utf-8")

        return {
            "markdown_path": str(md_path),
            "html_path": str(html_path),
            "markdown_preview": md_content,
        }

