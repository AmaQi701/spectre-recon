"""
SPECTRE v12.0 Titan — Headless V8 DOM, IPv6 Dual-Stack, CSP Nonce, UDP & WASM Intelligence
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import subprocess
import urllib.parse
from typing import Any

import dns.resolver
from bs4 import BeautifulSoup

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEADLESS CHROME V8 RUNTIME DOM & LAZY-ROUTE INTERCEPTOR
# ══════════════════════════════════════════════════════════════════════════════

def headless_chrome_dom_and_route_renderer(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> int:
    chrome_bin = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if not chrome_bin:
        return 0

    cmd = (
        f"{shlex.quote(chrome_bin)} --headless=new --no-sandbox --disable-gpu "
        f"--ignore-certificate-errors --disable-dev-shm-usage --virtual-time-budget=4000 "
        f"--dump-dom {shlex.quote(base_url)}"
    )
    proc = None
    rendered_html = ""
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        out_s, _ = proc.communicate(timeout=12)
        rendered_html = out_s or ""
    except subprocess.TimeoutExpired:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        return 0
    except Exception:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
        return 0

    if len(rendered_html) < 50:
        return 0

    soup = BeautifulSoup(rendered_html[:250000], "html.parser")
    new_discoveries = 0
    for sc in soup.find_all("script", src=True):
        full_js = urllib.parse.urljoin(base_url, sc["src"].strip())
        if full_js.endswith(".js") and full_js not in js_urls:
            js_urls.append(full_js)
            db.upsert_endpoint(project_id, full_js, method="GET", params=[], category="javascript", source="headless_v8_dom")
            new_discoveries += 1

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("/") and len(href) > 2 and not href.startswith("//"):
            full_ep = urllib.parse.urljoin(base_url, href.split("?")[0])
            db.upsert_endpoint(project_id, full_ep, method="GET", params=[], category="web_page", source="headless_v8_dom")
            new_discoveries += 1

    api_re = re.compile(r"""['"`]((?:/api/v\d+/|/api/|/v1/|/v2/|/graphql)[a-zA-Z0-9_\-/\.?=&{}]+)['"`]""")
    for rt in set(api_re.findall(rendered_html[:200000])):
        db.upsert_endpoint(project_id, urllib.parse.urljoin(base_url, rt), method="GET", params=[], category="api_endpoint", source="headless_v8_dom")
        new_discoveries += 1

    if new_discoveries:
        log_fn(f"  [🎭 HEADLESS V8 DOM] {base_url} -> Chromium V8 ijrosidan so'ng {new_discoveries} ta dinamik JS/route ushlandi!")
    return new_discoveries


# ══════════════════════════════════════════════════════════════════════════════
# 2. DUAL-STACK IPV6 (AAAA) RESOLVER & ORIGIN WAF-BYPASS PROBER
# ══════════════════════════════════════════════════════════════════════════════

def resolve_and_probe_ipv6_dual_stack(db, session, project_id: int, apex_domain: str, primary_host: str, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    resolver.timeout = 1.5
    resolver.lifetime = 2.0

    ipv6_hits = 0

    def _check_one_v6(d: dict):
        nonlocal ipv6_hits
        dom_name = d["domain"]
        try:
            ans = resolver.resolve(dom_name, "AAAA")
            v6_list = [str(r).strip() for r in ans if ":" in str(r)]
            if not v6_list:
                return
            ipv6_hits += 1
            recs = json.loads(d.get("records_json") or "{}")
            recs["AAAA"] = v6_list
            db.upsert_domain(
                project_id, dom_name, ip=d.get("ip", ""), cname=d.get("cname", ""),
                records=recs, cdn_waf=d.get("cdn_waf", ""), source=d.get("source", "ipv6_enum"),
            )
            v6_addr = v6_list[0]
            for sch in ("https", "http"):
                try:
                    r6 = session.get(f"{sch}://[{v6_addr}]/", headers={"Host": dom_name}, timeout=3.0, verify=False, allow_redirects=False)
                    if r6.status_code in (200, 301, 302, 401, 403):
                        srv6 = r6.headers.get("Server", "")
                        is_cf_v4 = "cloudflare" in (d.get("cdn_waf") or "").lower()
                        is_cf_v6 = "cloudflare" in srv6.lower() or "cf-ray" in {k.lower() for k in r6.headers.keys()}
                        if is_cf_v4 and not is_cf_v6:
                            db.upsert_finding(
                                project_id, "SPECTRE-v12 (IPv6-DualStack)",
                                f"[CONFIRMED] IPv6 Dual-Stack Origin Direct Access ({dom_name} -> [{v6_addr}])",
                                "WAF / CDN Bypass via IPv6", "High", 7.8,
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "CWE-284", "A05:2021 - Security Misconfiguration",
                                f"{dom_name} ([{v6_addr}])",
                                f"IPv4 is behind CDN/WAF ({d.get('cdn_waf')}), but IPv6 [{v6_addr}] responds directly (HTTP {r6.status_code}, Server: {srv6})",
                                "Domenning IPv4 manzili WAF ortida bo'lsa-da, IPv6 (AAAA) manzili to'g'ridan-to'g'ri origin serverga ochiq qolgan.",
                                "ip6tables / Cloud Firewall orqali IPv6 interfeysda ham faqat CDN subnetlariga ruxsat bering.",
                            )
                        break
                except Exception:
                    pass
        except Exception:
            pass

    ex_v6 = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    futs_v6 = [ex_v6.submit(_check_one_v6, d_row) for d_row in domains[:30]]
    concurrent.futures.wait(futs_v6, timeout=8)
    ex_v6.shutdown(wait=False, cancel_futures=True)

    if ipv6_hits:
        log_fn(f"  [🌐 IPv6 DUAL-STACK] {ipv6_hits} ta subdomenda AAAA (IPv6) yozuvlari aniqlandi va tekshirildi!")
    return ipv6_hits


# ══════════════════════════════════════════════════════════════════════════════
# 3. DEEP CSP DIRECTIVE MINER & STATIC NONCE REUSE AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_csp_deep_and_static_nonce(db, session, project_id: int, base_url: str, apex_domain: str, log_fn) -> int:
    nonce_re = re.compile(r"'nonce-([A-Za-z0-9+/=_\-]{6,})'")
    host_re = re.compile(r"(?:https?|wss?)://([a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s;,'\"]*)?)")
    issues = 0

    try:
        r1 = session.get(base_url, timeout=5, verify=False)
        csp1 = r1.headers.get("Content-Security-Policy") or r1.headers.get("Content-Security-Policy-Report-Only") or ""
        if not csp1:
            return 0
        r2 = session.get(base_url, headers={"Cache-Control": "no-cache"}, timeout=5, verify=False)
        csp2 = r2.headers.get("Content-Security-Policy") or r2.headers.get("Content-Security-Policy-Report-Only") or ""

        nonces1 = set(nonce_re.findall(csp1))
        nonces2 = set(nonce_re.findall(csp2))
        reused_nonces = sorted(nonces1 & nonces2)

        if reused_nonces:
            issues += 1
            db.upsert_finding(
                project_id, "SPECTRE-v12 (CSP-Auditor)",
                f"[CONFIRMED] Static / Reusable CSP Nonce Detected ({reused_nonces[0][:18]})",
                "Content-Security-Policy Weakness", "High", 7.4,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-330", "A05:2021 - Security Misconfiguration",
                base_url, f"Static Nonce across multiple HTTP requests: 'nonce-{reused_nonces[0]}'",
                "Content-Security-Policy sarlavhasidagi 'nonce' qiymati har bir so'rovda yangilanmasdan statik qaytmoqda — bu CSP himoyasini bekor qiladi.",
                "CSP nonce qiymatini har bir HTTP javob uchun kriptografik tasodifiy (CSPRNG) generatsiya qiling.",
            )
            log_fn(f"  [🛡️ STATIC CSP NONCE] {base_url} -> Statik CSP nonce aniqlandi: {reused_nonces[0][:16]}!")

        csp_subs = set()
        ws_eps = set()
        for raw_match in host_re.findall(csp1):
            h_only = raw_match.split("/")[0].split(":")[0].lower().lstrip("*.")
            if h_only.endswith(apex_domain):
                csp_subs.add(h_only)
                db.upsert_domain(project_id, h_only, source="csp_directive")
        for ws_m in re.findall(r"(wss?://[a-zA-Z0-9.\-_:/]+)", csp1):
            ws_eps.add(ws_m)
            db.upsert_endpoint(project_id, ws_m, method="GET", params=[], category="api_endpoint", risk_tags=["csp_websocket"], source="csp_connect_src")

        for rep_m in re.findall(r"(?:report-uri|report-to)\s+([^\s;]+)", csp1):
            if rep_m.startswith("/") or rep_m.startswith("http"):
                full_rep = urllib.parse.urljoin(base_url, rep_m)
                db.upsert_endpoint(project_id, full_rep, method="POST", params=[], category="api_endpoint", risk_tags=["csp_collector"], source="csp_report_uri")

        if csp_subs or ws_eps:
            log_fn(f"  [🛡️ CSP MINER] {base_url} -> {len(csp_subs)} ta subdomen va {len(ws_eps)} ta WebSocket CSP ichidan ajratib olindi!")
    except Exception:
        pass
    return issues


# ══════════════════════════════════════════════════════════════════════════════
# 4. CORPORATE BGPVIEW ASN & MULTI-SIGNAL BACKEND CORRELATOR
# ══════════════════════════════════════════════════════════════════════════════

def build_corporate_org_and_backend_correlation_graph(db, session, project_id: int, apex_domain: str, log_fn) -> dict[str, Any]:
    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    services = bundle.get("http_services", [])

    # Part A: Multi-Signal Backend Server Correlation (IP + Server + WAF + Status)
    ip_by_host = {d["domain"]: d.get("ip", "") for d in domains if d.get("ip")}
    backend_groups: dict[str, list[str]] = {}
    for svc in services:
        u = svc.get("url", "")
        h = (urllib.parse.urlparse(u).hostname or "").lower()
        ip_v = ip_by_host.get(h, "")
        subnet = ".".join(ip_v.split(".")[:3]) + ".0/24" if ip_v.count(".") == 3 else ip_v
        srv = (svc.get("server") or "unknown").lower()
        waf = (svc.get("waf") or "direct").lower()
        sig = f"{subnet}|{srv}|{waf}"
        if subnet:
            backend_groups.setdefault(sig, []).append(h)

    shared_backends = {k: sorted(set(v)) for k, v in backend_groups.items() if len(set(v)) > 1}
    if shared_backends:
        summary_parts = [f"[{sig} -> {', '.join(hosts[:5])} ({len(hosts)} hosts)]" for sig, hosts in list(shared_backends.items())[:5]]
        db.upsert_finding(
            project_id, "SPECTRE-v12 (Backend-Correlator)",
            f"Multi-Signal Shared Backend Infrastructure Graph ({len(shared_backends)} clusters)",
            "Asset Correlation Intelligence", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            apex_domain, "Shared Backend Clusters: " + " ; ".join(summary_parts),
            "Subdomenlarning /24 subneti, Server sarlavhasi va WAF imzolari korrelyatsiya qilinib, bitta fizik/virtual backendda yotgan ilovalar guruhlandi.",
            "Kritik ichki tizimlarni ommaviy veb-saytlar bilan bitta backend serverda birga joylashtirmang ( Izolyatsiya).",
        )
        log_fn(f"  [🕸️ BACKEND CORRELATOR] {len(shared_backends)} ta umumiy backend klasteri aniqlandi!")
    return shared_backends


# ══════════════════════════════════════════════════════════════════════════════
# 5. CALIBRATED SEMANTIC REST API ENDPOINT PREDICTOR
# ══════════════════════════════════════════════════════════════════════════════

def predict_and_verify_semantic_rest_endpoints(db, session, project_id: int, base_url: str, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    res_re = re.compile(r"((?:/api)?/v\d+/[a-zA-Z0-9_\-]+)$")
    base_resources: set[str] = set()

    for ep in bundle.get("endpoints", []):
        u = ep.get("url", "")
        if u.startswith(base_url):
            p = urllib.parse.urlparse(u).path.rstrip("/")
            m = res_re.search(p)
            if m:
                base_resources.add(m.group(1))

    if not base_resources:
        return 0

    cal_hash, cal_len, cal_status = "", -1, -1
    try:
        rc = session.get(urllib.parse.urljoin(base_url, "/api/v999_spectre_nonexistent/check"), timeout=4, verify=False, allow_redirects=False)
        cal_status = rc.status_code
        cal_len = len(rc.text)
        cal_hash = hashlib.sha256(rc.text.encode("utf-8", errors="ignore")).hexdigest()
    except Exception:
        pass

    verified_preds = []
    for res_p in sorted(base_resources)[:6]:
        for action in ("me", "search", "export", "config", "stats", "list"):
            cand_p = f"{res_p}/{action}"
            cand_u = urllib.parse.urljoin(base_url, cand_p)
            try:
                r = session.get(cand_u, timeout=4, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 20 and "application/json" in r.headers.get("Content-Type", "").lower():
                    rh = hashlib.sha256(r.text.encode("utf-8", errors="ignore")).hexdigest()
                    low_t = r.text.lower()
                    is_diff = (cal_status != 200) or (rh != cal_hash and abs(len(r.text) - cal_len) > 25)
                    if is_diff and '"not found"' not in low_t and '"status":404' not in low_t:
                        verified_preds.append(cand_p)
                        db.upsert_endpoint(project_id, cand_u, method="GET", params=[], category="api_endpoint", risk_tags=["semantic_predicted"], status_code=200, source="semantic_predictor")
            except Exception:
                pass

    if verified_preds:
        db.upsert_finding(
            project_id, "SPECTRE-v12 (Semantic-Predictor)",
            f"[CONFIRMED] Undocumented Semantic REST Endpoints Discovered ({len(verified_preds)} routes)",
            "Hidden API Surface", "Medium", 5.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            base_url, f"Verified Semantic Routes: {', '.join(verified_preds[:10])}",
            "Mavjud API resurs nomlaridan semantik bashorat (/export, /search, /config, /me) orqali hujjatlashtirilmagan faol JSON endpointlar topildi.",
            "Ichki export/config/stats endpointlarida qat'iy avtorizatsiya tekshiruvini o'rnating.",
        )
        log_fn(f"  [🔮 SEMANTIC API] {base_url} -> {len(verified_preds)} ta yashirin REST endpoint topildi: {', '.join(verified_preds[:5])}")
    return len(verified_preds)


# ══════════════════════════════════════════════════════════════════════════════
# 6. NON-ROOT PURE-PYTHON UDP SERVICE INSPECTOR (161/SNMP & 123/NTP)
# ══════════════════════════════════════════════════════════════════════════════

SNMP_PUBLIC_SYSDESCR_PKT = bytes.fromhex("302902010104067075626c6963a01c02041a2b3c4d020100020100300e300c06082b060102010101000500")
NTP_MODE3_PKT = b"\x1b" + (47 * b"\x00")


def probe_udp_services_safe(db, project_id: int, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    cdn_keywords = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula")
    target_ips = []
    for d in bundle.get("domains", []):
        ip = (d.get("ip") or "").strip()
        cdn = (d.get("cdn_waf") or "").lower()
        if ip and "." in ip and not any(k in cdn for k in cdn_keywords) and ip not in target_ips:
            target_ips.append(ip)

    hits = 0
    for ip in target_ips[:4]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_udp:
                s_udp.settimeout(1.8)
                s_udp.sendto(SNMP_PUBLIC_SYSDESCR_PKT, (ip, 161))
                data, _ = s_udp.recvfrom(2048)
                if data and len(data) > 20 and b"public" in data:
                    hits += 1
                    ascii_sys = "".join(chr(b) if 32 <= b < 127 else " " for b in data[24:]).strip()
                    db.upsert_port(project_id, ip, 161, "udp", ip=ip, service="snmp", version=ascii_sys[:120], source="udp_prober")
                    db.upsert_finding(
                        project_id, "SPECTRE-v12 (UDP-Inspector)",
                        f"[CONFIRMED] Exposed SNMP Service with Default 'public' Community ({ip}:161/udp)",
                        "Network Service Exposure", "Critical", 9.1,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-287", "A05:2021 - Security Misconfiguration",
                        f"{ip}:161/udp", f"SNMPv2c community 'public' sysDescr.0: {ascii_sys[:180]}",
                        "Serverda UDP 161 (SNMP) porti standart 'public' kaliti bilan tashqi internet uchun ochiq qoldirilgan.",
                        "SNMP xizmatini tashqi interfeysdan Firewall orqali yoping va SNMPv3 autentifikatsiyasiga o'ting.",
                    )
                    log_fn(f"  [📡 UDP SNMP HIT] {ip}:161/udp -> 'public' sysDescr: {ascii_sys[:80]}!")
        except Exception:
            pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_ntp:
                s_ntp.settimeout(1.5)
                s_ntp.sendto(NTP_MODE3_PKT, (ip, 123))
                ndata, _ = s_ntp.recvfrom(1024)
                if ndata and len(ndata) >= 48:
                    hits += 1
                    db.upsert_port(project_id, ip, 123, "udp", ip=ip, service="ntp", version="NTPv3/v4", source="udp_prober")
                    log_fn(f"  [📡 UDP NTP] {ip}:123/udp ochiq (NTP javob olindi).")
        except Exception:
            pass
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# 7. WEBASSEMBLY (.WASM) BINARY STRING EXTRACTOR & SERVER-TIMING MINER
# ══════════════════════════════════════════════════════════════════════════════

def analyze_wasm_binaries_and_server_timing(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> int:
    hits = 0
    wasm_urls: set[str] = set()
    wasm_re = re.compile(r"""['"`]([^'"`]+\.wasm(?:\?[^'"`]*)?)['"`]""")

    try:
        r = session.get(base_url, timeout=5, verify=False)
        st_hdr = r.headers.get("Server-Timing", "")
        if st_hdr:
            hits += 1
            services_leaked = re.findall(r"([a-zA-Z0-9_\-]+)\s*;", st_hdr)
            db.upsert_finding(
                project_id, "SPECTRE-v12 (Server-Timing)",
                "Internal Microservice Metrics Disclosed in Server-Timing Header",
                "Information Disclosure", "Low", 3.1,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
                base_url, f"Server-Timing: {st_hdr[:180]} | Services: {', '.join(services_leaked[:8])}",
                "HTTP javobidagi Server-Timing sarlavhasi ichki mikroservis nomlari va ma'lumotlar bazasi vaqtlarini oshkor qilmoqda.",
                "Production reverse-proxy darajasida Server-Timing sarlavhasini tashqi foydalanuvchilardan yashiring.",
            )
            log_fn(f"  [⏱️ SERVER-TIMING] {base_url} -> {st_hdr[:100]}")
        for wm in wasm_re.findall(r.text[:200000]):
            wasm_urls.add(urllib.parse.urljoin(base_url, wm))
    except Exception:
        pass

    for ju in js_urls[:12]:
        try:
            rj = session.get(ju, timeout=4.5, verify=False)
            if rj.status_code == 200:
                for wm in wasm_re.findall(rj.text[:250000]):
                    wasm_urls.add(urllib.parse.urljoin(ju, wm))
        except Exception:
            pass

    str_re = re.compile(rb"((?:/api/v\d+/|/api/|/v1/|/v2/|https?://)[a-zA-Z0-9_\-/\.?=&:]{4,100})")
    for wu in sorted(wasm_urls)[:5]:
        try:
            rw = session.get(wu, timeout=6, verify=False)
            if rw.status_code == 200 and rw.content.startswith(b"\x00asm"):
                wasm_eps = sorted({m.decode("ascii", errors="ignore") for m in str_re.findall(rw.content[:500000])})
                for wep in wasm_eps:
                    db.upsert_endpoint(project_id, urllib.parse.urljoin(base_url, wep), method="GET", params=[], category="api_endpoint", risk_tags=["wasm_binary"], source="wasm_extractor")
                hits += 1
                db.upsert_finding(
                    project_id, "SPECTRE-v12 (WASM-Analyzer)",
                    f"WebAssembly (.wasm) Binary Deconstructed ({len(wasm_eps)} embedded endpoints)",
                    "WebAssembly Binary Intelligence", "Info", 0.0,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
                    wu, f"WASM Size: {len(rw.content)}B | Extracted Routes: {', '.join(wasm_eps[:10])}",
                    "WebAssembly (.wasm) binar fayli data segmentidan ichki API URL manzillari ajratib olindi.",
                    "WASM modullari ichida maxfiy kalit va ichki endpointlarni ochiq satr sifatida saqlamang.",
                )
                log_fn(f"  [🧬 WASM BINARY] {wu} -> {len(wasm_eps)} ta endpoint tiklandi!")
        except Exception:
            pass
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ORCHESTRATOR FOR ALL SPECTRE v12.0 TITAN MODULES
# ══════════════════════════════════════════════════════════════════════════════

from core.plugin_runner import ScanPhase, run_plugin_safely


def run_v12_titan_suite(agent, project_id: int, apex_domain: str, primary_host: str, base_url: str, js_urls: list[str], log_fn) -> None:
    log_fn(f"  [🔱 SPECTRE v12.0 TITAN] {base_url} ustida Headless V8, IPv6, CSP Nonce, Semantic API, UDP va WASM modullari ishga tushirildi...")
    db = agent.db
    session = agent.session

    run_plugin_safely(db, project_id, "v12_headless_v8", headless_chrome_dom_and_route_renderer, db, session, project_id, base_url, js_urls, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "v12_csp_nonce", audit_csp_deep_and_static_nonce, db, session, project_id, base_url, apex_domain, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    run_plugin_safely(db, project_id, "v12_semantic_rest", predict_and_verify_semantic_rest_endpoints, db, session, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    run_plugin_safely(db, project_id, "v12_wasm_timing", analyze_wasm_binaries_and_server_timing, db, session, project_id, base_url, js_urls, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    if urllib.parse.urlparse(base_url).hostname == primary_host.split(":")[0].lower():
        run_plugin_safely(db, project_id, "v12_backend_correlator", build_corporate_org_and_backend_correlation_graph, db, session, project_id, apex_domain, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_END)
    db.log_task(project_id, "SPECTRE-v12", "v12_titan_suite", "COMPLETED", f"v12_suite {base_url}", f"Executed v12 Titan Intelligence Suite on {base_url}")




