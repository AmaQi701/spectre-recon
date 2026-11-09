"""
SPECTRE v10.0 — Deep Architecture, Protocol & Structural Intelligence Modules
"""

from __future__ import annotations

import json
import pathlib
import re
import urllib.parse
from typing import Any

import dns.resolver

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════════
# 1. VCS (.git/config & .git/logs/HEAD) METADATA & COMMIT HISTORY PARSER
# ══════════════════════════════════════════════════════════════════════════════

def audit_vcs_metadata_exposure(db, session, project_id: int, base_url: str, log_fn) -> int:
    hits = 0
    cfg_url = urllib.parse.urljoin(base_url, "/.git/config")
    logs_url = urllib.parse.urljoin(base_url, "/.git/logs/HEAD")

    try:
        rc = session.get(cfg_url, timeout=5, verify=False, allow_redirects=False)
        if rc.status_code == 200 and "[core]" in rc.text and "repositoryformatversion" in rc.text:
            hits += 1
            remotes = re.findall(r"url\s*=\s*([^\r\n]+)", rc.text)
            branches = re.findall(r'\[branch\s+"([^"]+)"\]', rc.text)
            db.upsert_finding(
                project_id, "SPECTRE-v10 (VCS-Auditor)",
                "[CONFIRMED] Exposed Git Configuration File (/.git/config)",
                "Source Control Metadata Exposure", "Critical", 9.1,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-538", "A05:2021 - Security Misconfiguration",
                cfg_url,
                f"Remotes: {', '.join(remotes[:4]) or 'local'} | Branches: {', '.join(branches[:5])}",
                "Veb-serverda /.git/config fayli ochiq qoldirilgan — ichki Git repozitoriy manzillari va tarmoq strukturasi ko'rinmoqda.",
                "Veb-server konfiguratsiyasida /.git katalogiga kirishni to'liq taqiqlang.",
            )
            log_fn(f"  [🧱 VCS CONFIG] {cfg_url} ochiq! Remotes: {', '.join(remotes[:3])}")
    except Exception:
        pass

    try:
        rl = session.get(logs_url, timeout=5, verify=False, allow_redirects=False)
        if rl.status_code == 200 and re.search(r"[0-9a-f]{40}\s+[0-9a-f]{40}", rl.text):
            hits += 1
            commits = re.findall(r"\s([0-9a-f]{40})\s+([^\r\n<]+<[^>]+>)", rl.text)
            sample = ", ".join([f"{c[0][:8]} ({c[1].strip()})" for c in commits[:4]])
            db.upsert_finding(
                project_id, "SPECTRE-v10 (VCS-Auditor)",
                "[CONFIRMED] Exposed Git Commit Reflog (/.git/logs/HEAD)",
                "Source Control History Exposure", "High", 7.5,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-538", "A05:2021 - Security Misconfiguration",
                logs_url,
                f"Commits ({len(commits)}): {sample}",
                "/.git/logs/HEAD ochiq qolgan — dasturchilarning elektron pochtalari va commit SHA-1 xeshlari o'qilmoqda.",
                "Production muhitidan .git katalogini olib tashlang.",
            )
            log_fn(f"  [🧱 VCS REFLOG] {logs_url} -> {len(commits)} ta commit va dasturchi ma'lumotlari tiklandi!")
    except Exception:
        pass
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# 2. STATIC DIRECTORY INDEXING & SERVER HEADER CONFIGURATION AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_static_routing_headers(db, session, project_id: int, base_url: str, log_fn) -> int:
    prefixes = ("/static/", "/assets/", "/media/", "/uploads/", "/public/", "/files/")
    issues = 0
    for pfx in prefixes:
        u = urllib.parse.urljoin(base_url, pfx)
        try:
            r = session.get(u, timeout=4.5, verify=False, allow_redirects=False)
            if r.status_code == 200 and ("Index of /" in r.text or "<title>Directory listing" in r.text):
                issues += 1
                files_listed = re.findall(r'href="([^"?/][^"]*)"', r.text)[:8]
                db.upsert_finding(
                    project_id, "SPECTRE-v10 (Static-Auditor)",
                    f"[CONFIRMED] Open Directory Listing Enabled ({pfx})",
                    "Directory Listing Exposure", "Medium", 5.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-548", "A05:2021 - Security Misconfiguration",
                    u, f"Listed entries: {', '.join(files_listed)}",
                    "Statik katalogda 'autoindex on' qoldirilgan — barcha ichki fayllar ro'yxatini ko'rish mumkin.",
                    "Nginx/Apache konfiguratsiyasida 'autoindex off;' yoki 'Options -Indexes' o'rnating.",
                )
                log_fn(f"  [🔀 DIR LISTING] {u} katalogida fayllar ro'yxati ochiq ({len(files_listed)} ta fayl)!")
        except Exception:
            pass
    return issues


# ══════════════════════════════════════════════════════════════════════════════
# 3. GRPC-WEB & PROTOBUF SERVICE/METHOD DESCRIPTOR EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

def extract_grpc_and_protobuf_schemas(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> list[str]:
    grpc_methods: set[str] = set()
    proto_types: set[str] = set()
    method_re = re.compile(r'["\'](/([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)/([A-Z][a-zA-Z0-9_]+))["\']')
    proto_re = re.compile(r"proto\.([a-zA-Z0-9_]+\.[A-Za-z0-9_.]+)")

    for ju in js_urls[:20]:
        try:
            rj = session.get(ju, timeout=5, verify=False)
            if rj.status_code != 200:
                continue
            txt = rj.text[:350000]
            if any(k in txt.lower() for k in ("grpc", "protobuf", "jspb", "proto.")):
                for full_m, pkg_svc, _ in method_re.findall(txt):
                    if "." in pkg_svc and not pkg_svc.endswith((".js", ".css", ".png", ".svg")):
                        grpc_methods.add(full_m)
                        db.upsert_endpoint(project_id, urllib.parse.urljoin(base_url, full_m), method="POST", params=[], category="api_endpoint", risk_tags=["grpc_web"], source="grpc_extractor")
                for pt in proto_re.findall(txt):
                    proto_types.add(pt)
        except Exception:
            pass

    if grpc_methods or proto_types:
        m_list, p_list = sorted(grpc_methods), sorted(proto_types)
        db.upsert_finding(
            project_id, "SPECTRE-v10 (gRPC-Mapper)",
            f"Discovered gRPC-Web / Protobuf RPC Schema ({len(m_list)} methods, {len(p_list)} types)",
            "API Architecture Discovery", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            base_url, f"gRPC Methods: {', '.join(m_list[:10])} | Protobuf Types: {', '.join(p_list[:10])}",
            "JavaScript bundle ichidan gRPC-Web servis metodlari va Protobuf xabar strukturalari tiklandi.",
            "gRPC-Web endpointlarda avtorizatsiya va xabar o'lchami cheklovlarini server tomonida tekshiring.",
        )
        log_fn(f"  [📡 gRPC MAPPER] {len(m_list)} ta gRPC metod va {len(p_list)} ta Protobuf tip tiklandi!")
    return sorted(grpc_methods)


# ══════════════════════════════════════════════════════════════════════════════
# 4. CLIENT-SIDE POSTMESSAGE BRACE-BALANCED AST HANDLER ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

def _extract_brace_block(text: str, start_idx: int, max_len: int = 1800) -> str:
    brace_pos = text.find("{", start_idx)
    if brace_pos == -1 or brace_pos - start_idx > 200:
        return text[start_idx : start_idx + 400]
    depth = 0
    end_limit = min(len(text), brace_pos + max_len)
    for i in range(brace_pos, end_limit):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_pos : i + 1]
    return text[brace_pos:end_limit]


def analyze_postmessage_handlers(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> int:
    listener_re = re.compile(r'addEventListener\s*\(\s*["\']message["\']\s*,')
    sink_re = re.compile(r"(innerHTML|outerHTML|document\.write|eval\s*\(|location\.href|location\.assign|location\.replace|setAttribute\s*\(\s*['\"]src)")
    issues = 0

    targets = [base_url] + list(js_urls[:20])
    for tu in targets:
        try:
            r = session.get(tu, timeout=5, verify=False)
            if r.status_code != 200:
                continue
            txt = r.text[:400000]
            for m in listener_re.finditer(txt):
                block = _extract_brace_block(txt, m.end())
                has_origin_check = (".origin" in block) or ("origin" in block and "===" in block)
                sink_match = sink_re.search(block)
                if not has_origin_check and sink_match:
                    issues += 1
                    sink_name = sink_match.group(1)
                    db.upsert_finding(
                        project_id, "SPECTRE-v10 (postMessage-AST)",
                        f"[CONFIRMED] Unvalidated DOM postMessage Handler Flowing to '{sink_name}'",
                        "DOM-Based Cross-Site Scripting (CWE-345)", "High", 7.8,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N", "CWE-345", "A03:2021 - Injection",
                        tu, f"Handler Body (Zero .origin check, Sink={sink_name}): {block[:180].strip()}",
                        "addEventListener('message') funksiyasi ichida event.origin tekshirilmagan va kelgan ma'lumot xavfli DOM sinkka uzatilgan.",
                        "Xabarni qayta ishlashdan oldin 'if (event.origin !== \"https://trusted.domain\") return;' tekshiruvini qo'shing.",
                    )
                    log_fn(f"  [🪟 POSTMESSAGE AST] {tu} -> '.origin' tekshiruvisiz '{sink_name}' sink topildi!")
                    break
        except Exception:
            pass
    return issues


# ══════════════════════════════════════════════════════════════════════════════
# 5. WEB CACHE POLICY, VARY HEADER & STATIC-EXTENSION CACHE AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_cache_policy_and_headers(db, session, project_id: int, base_url: str, log_fn) -> int:
    issues = 0
    try:
        r = session.get(base_url, timeout=5, verify=False)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        cache_status = hdrs.get("cf-cache-status") or hdrs.get("x-cache") or hdrs.get("x-drupal-cache") or hdrs.get("x-varnish") or ""
        vary = hdrs.get("vary", "")
        cache_ctrl = hdrs.get("cache-control", "")

        for api_p in ("/api/me", "/api/user", "/api/profile", "/account"):
            u_api = urllib.parse.urljoin(base_url, api_p)
            r_api = session.get(u_api, timeout=4, verify=False, allow_redirects=False)
            if r_api.status_code == 200 and len(r_api.text) > 60 and "application/json" in r_api.headers.get("Content-Type", "").lower():
                low_body = r_api.text.lower()
                if any(err_k in low_body for err_k in ('"unauthorized"', '"unauthenticated"', '"not found"', '"status":401', '"status":403', '"status":404')):
                    continue
                u_ext = urllib.parse.urljoin(base_url, f"{api_p}/spectre_check.css")
                r_ext = session.get(u_ext, timeout=4, verify=False, allow_redirects=False)
                ext_cache = (r_ext.headers.get("CF-Cache-Status") or r_ext.headers.get("X-Cache") or "").upper()
                # Faqat haqiqiy keshlangan (HIT / MISS / EXPIRED) holatni olish (DYNAMIC = keshlanmagan!)
                if r_ext.status_code == 200 and r_ext.text == r_api.text and any(k in ext_cache for k in ("HIT", "MISS", "EXPIRED")):
                    issues += 1
                    db.upsert_finding(
                        project_id, "SPECTRE-v10 (Cache-Auditor)",
                        f"[CONFIRMED] Dynamic API Path Ignores Static Suffix ({api_p}/spectre_check.css)",
                        "Web Cache Configuration Weakness", "High", 7.5,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "CWE-525", "A05:2021 - Security Misconfiguration",
                        u_ext, f"Endpoint returned identical JSON ({len(r_ext.text)}B) on .css suffix | Cache-Header: {ext_cache}",
                        "Dinamik API yo'li oxiriga .css qo'shilganda ham backend bir xil shaxsiy JSON ma'lumot qaytarmoqda (keshda saqlanib qolish xavfi).",
                        "Dinamik API endpointlarda 'Cache-Control: no-store, private' sarlavhasini majburiy o'rnating va qat'iy URL routing ishlating.",
                    )
                    log_fn(f"  [🧊 CACHE AUDIT] {u_ext} statik kengaytma bilan ham JSON qaytardi ({ext_cache})!")
                    break

        if cache_status and "origin" not in vary.lower() and hdrs.get("access-control-allow-origin"):
            issues += 1
            db.upsert_finding(
                project_id, "SPECTRE-v10 (Cache-Auditor)",
                "Cached CORS Response Missing 'Vary: Origin' Header",
                "Cache Key Configuration", "Low", 3.7,
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-525", "A05:2021 - Security Misconfiguration",
                base_url, f"Cache Status: {cache_status} | Vary: '{vary}' | Cache-Control: '{cache_ctrl}'",
                "Keshlanadigan sahifada Access-Control-Allow-Origin mavjud, ammo 'Vary: Origin' ko'rsatilmagan.",
                "CORS ishlatiladigan keshlanuvchi javoblarga 'Vary: Origin' sarlavhasini qo'shing.",
            )
    except Exception:
        pass
    return issues


# ══════════════════════════════════════════════════════════════════════════════
# 6. RECURSIVE DNS SPF LOOKUP-TREE & DMARC POLICY VALIDATOR (RFC-7208)
# ══════════════════════════════════════════════════════════════════════════════

def validate_spf_dmarc_recursive(db, project_id: int, apex_domain: str, log_fn) -> dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    visited: set[str] = set()
    dangling_includes: list[str] = []

    def _count_spf_lookups(dom: str, depth: int = 0) -> tuple[int, str]:
        if depth > 5 or dom in visited:
            return 0, ""
        visited.add(dom)
        txt_spf = ""
        try:
            ans = resolver.resolve(dom, "TXT")
            for rdata in ans:
                s = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if s.lower().startswith("v=spf1"):
                    txt_spf = s
                    break
        except dns.resolver.NXDOMAIN:
            if depth > 0:
                dangling_includes.append(dom)
            return 0, ""
        except Exception:
            return 0, ""

        if not txt_spf:
            return 0, ""
        lookups = 0
        for tok in txt_spf.split():
            tl = tok.lower().lstrip("+-~?")
            if tl in ("a", "mx", "ptr") or tl.startswith(("a:", "mx:", "exists:", "ptr:")):
                lookups += 1
            elif tl.startswith("include:"):
                lookups += 1
                inc_dom = tl.split(":", 1)[1].strip()
                sub_cnt, _ = _count_spf_lookups(inc_dom, depth + 1)
                lookups += sub_cnt
            elif tl.startswith("redirect="):
                lookups += 1
                red_dom = tl.split("=", 1)[1].strip()
                sub_cnt, _ = _count_spf_lookups(red_dom, depth + 1)
                lookups += sub_cnt
        return lookups, txt_spf

    total_lookups, root_spf = _count_spf_lookups(apex_domain)
    dmarc_txt = ""
    try:
        ans_d = resolver.resolve(f"_dmarc.{apex_domain}", "TXT")
        for rdata in ans_d:
            s = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if "v=dmarc1" in s.lower():
                dmarc_txt = s
                break
    except Exception:
        pass

    issues = []
    if not root_spf:
        issues.append("Missing SPF Record")
    else:
        if "+all" in root_spf.lower():
            issues.append("CRITICAL: SPF allows '+all'")
        elif "~all" in root_spf.lower() or "?all" in root_spf.lower():
            issues.append("SPF SoftFail/Neutral ('~all' / '?all')")
        if total_lookups > 10:
            issues.append(f"SPF Exceeds RFC-7208 10-Lookup Limit ({total_lookups} lookups -> PermError)")
        if dangling_includes:
            issues.append(f"Unregistered SPF Include Domain (NXDOMAIN): {', '.join(dangling_includes)}")

    if not dmarc_txt:
        issues.append("Missing DMARC Record (_dmarc)")
    elif "p=none" in dmarc_txt.lower():
        issues.append("DMARC Policy set to 'p=none' (Monitoring only)")

    if issues:
        sev = "High" if (dangling_includes or "+all" in root_spf.lower()) else "Medium" if (not dmarc_txt or "p=none" in dmarc_txt.lower() or total_lookups > 10) else "Low"
        cvss = 7.5 if sev == "High" else 5.3 if sev == "Medium" else 3.7
        db.upsert_finding(
            project_id, "SPECTRE-v10 (Mail-DNS-Auditor)",
            f"Mail Authentication & SPF/DMARC Policy Weaknesses ({apex_domain})",
            "Email Infrastructure Security (RFC-7208)", sev, cvss,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "CWE-290", "A05:2021 - Security Misconfiguration",
            apex_domain,
            f"Issues: {' | '.join(issues)} || SPF ({total_lookups} lookups): {root_spf or 'NONE'} || DMARC: {dmarc_txt or 'NONE'}",
            "Domenning pochta autentifikatsiya yozuvlarida (SPF/DMARC) RFC-7208 lookup cheklovi, p=none yoki NXDOMAIN xatoliklari aniqlandi.",
            "DMARC siyosatini 'p=quarantine' yoki 'p=reject' ga o'tkazing, SPF include sonini <=10 tagacha qisqartiring va '-all' ishlating.",
        )
        log_fn(f"  [📬 SPF/DMARC AUDIT] {apex_domain} -> {len(issues)} ta pochta siyosati kamchiligi ({total_lookups} DNS lookups)!")
    return {"spf_lookups": total_lookups, "issues": issues}


# ══════════════════════════════════════════════════════════════════════════════
# 7. SERVICE WORKER (sw.js / Workbox / Angular ngsw.json) ROUTE HARVESTER
# ══════════════════════════════════════════════════════════════════════════════

def parse_service_worker_manifests(db, session, project_id: int, base_url: str, log_fn) -> list[str]:
    sw_paths = ("/sw.js", "/service-worker.js", "/ngsw.json", "/manifest.json", "/manifest.webmanifest", "/asset-manifest.json")
    wb_re = re.compile(r'["\']url["\']\s*:\s*["\']([^"\']+)["\']')
    discovered_routes: set[str] = set()

    for sp in sw_paths:
        u = urllib.parse.urljoin(base_url, sp)
        try:
            r = session.get(u, timeout=4.5, verify=False, allow_redirects=False)
            if r.status_code != 200 or len(r.text) < 20:
                continue
            body = r.text[:300000]
            if sp.endswith(".json") and body.lstrip().startswith("{"):
                data = r.json()
                for ag in data.get("assetGroups", []):
                    for u_item in ag.get("urls", []):
                        discovered_routes.add(str(u_item))
                for _, v_url in (data.get("files") or {}).items():
                    if isinstance(v_url, str):
                        discovered_routes.add(v_url)
                if data.get("start_url"):
                    discovered_routes.add(str(data["start_url"]))
            elif "__WB_MANIFEST" in body or "precacheAndRoute" in body or "cache.addAll" in body:
                for m_url in wb_re.findall(body):
                    discovered_routes.add(m_url)
        except Exception:
            pass

    for rt in sorted(discovered_routes)[:60]:
        full_rt = urllib.parse.urljoin(base_url, rt)
        db.upsert_endpoint(project_id, full_rt, method="GET", params=[], category="pwa_manifest_route", source="service_worker")

    if discovered_routes:
        r_list = sorted(discovered_routes)
        db.upsert_finding(
            project_id, "SPECTRE-v10 (ServiceWorker-Harvester)",
            f"Service Worker & PWA Precache Route Table Discovered ({len(r_list)} assets)",
            "Attack Surface Discovery", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            base_url, f"Precached Routes ({len(r_list)}): {', '.join(r_list[:12])}",
            "Service Worker (sw.js / ngsw.json) manifest faylidan ilovaning oflayn keshlanadigan marshrutlari va modullari ajratib olindi.",
            "Maxfiy admin modullari va ichki marshrutlarni ommaviy Service Worker precache ro'yxatiga qo'shmang.",
        )
        log_fn(f"  [⚙️ SERVICE WORKER] {len(r_list)} ta yashirin PWA/Workbox marshruti tiklandi!")
    return sorted(discovered_routes)


# ══════════════════════════════════════════════════════════════════════════════
# 8. HTTP/3 (ALT-SVC) & REVERSE-PROXY TOPOLOGY MAPPER
# ══════════════════════════════════════════════════════════════════════════════

def inspect_http_protocol_and_proxy_topology(db, session, project_id: int, base_url: str, log_fn) -> dict[str, Any]:
    topo: dict[str, str] = {}
    try:
        r = session.get(base_url, timeout=5, verify=False)
        interesting = ("alt-svc", "via", "x-served-by", "x-backend-server", "x-upstream", "x-envoy-upstream-service-time", "x-amz-cf-pop", "cf-ray", "server-timing")
        for k, v in r.headers.items():
            if k.lower() in interesting:
                topo[k] = v
        if topo:
            summary = " | ".join([f"{k}: {v}" for k, v in topo.items()])
            db.merge_http_tech_stack(project_id, base_url, [f"Topology:{k}" for k in topo.keys()])
            db.upsert_finding(
                project_id, "SPECTRE-v10 (Topology-Mapper)",
                f"Reverse-Proxy & Protocol Topology Headers ({len(topo)} hops/hints)",
                "Infrastructure Topology Intelligence", "Info", 0.0,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
                base_url, summary,
                "HTTP javob sarlavhalari orqali upstream proksi zanjiri, Envoy/Varnish/CDN tugunlari va HTTP/3 (QUIC) portlari aniqlandi.",
                "Ichki upstream server nomlarini fosh qiluvchi X-Backend-Server va X-Upstream sarlavhalarini tozalang.",
            )
            log_fn(f"  [🧬 TOPOLOGY MAP] {base_url} -> {summary[:100]}")
    except Exception:
        pass
    return topo


# ══════════════════════════════════════════════════════════════════════════════
# 9. OAUTH 2.0 / OIDC STATE, PKCE & IMPLICIT FLOW AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_oauth_oidc_parameters(db, project_id: int, base_url: str, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    issues = 0
    for ep in bundle.get("endpoints", []):
        u = ep.get("url", "")
        if not any(k in u.lower() for k in ("/oauth", "/authorize", "/connect/authorize", "client_id=", "redirect_uri=")):
            continue
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs.get("client_id") and not qs.get("redirect_uri"):
            continue
        flaws = []
        if "state" not in qs:
            flaws.append("Missing 'state' parameter (OAuth CSRF risk)")
        if "code_challenge" not in qs:
            flaws.append("Missing PKCE 'code_challenge' parameter")
        rtype = " ".join(qs.get("response_type", [])).lower()
        if "token" in rtype:
            flaws.append("Deprecated Implicit Flow ('response_type=token')")
        redir = " ".join(qs.get("redirect_uri", []))
        if redir.startswith("http://") and not redir.startswith(("http://localhost", "http://127.0.0.1")):
            flaws.append(f"Cleartext HTTP redirect_uri ({redir})")

        if flaws:
            issues += 1
            sev = "High" if ("state" not in qs or "token" in rtype) else "Medium"
            cvss = 7.4 if sev == "High" else 5.3
            db.upsert_finding(
                project_id, "SPECTRE-v10 (OAuth-Auditor)",
                f"[CONFIRMED] OAuth 2.0 / OIDC Parameter Security Weakness ({parsed.path or '/'})",
                "Authentication & OAuth Security", sev, cvss,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "CWE-352", "A07:2021 - Identification and Authentication Failures",
                u, f"Flaws: {' | '.join(flaws)}",
                "OAuth 2.0 avtorizatsiya so'rovida CSRF himoyasi (state) yoki PKCE (code_challenge) ko'rsatilmagan.",
                "Barcha OAuth 2.0 oqimlarida kriptografik tasodifiy 'state' va 'PKCE (S256)' parametrlarini majburiy qiling.",
            )
            log_fn(f"  [🔑 OAUTH AUDIT] {u[:80]} -> {' | '.join(flaws)}")
    return issues


# ══════════════════════════════════════════════════════════════════════════════
# 10. CROSS-DOMAIN ANALYTICS & TAG ID (GTM / GA / METRIKA) CORRELATOR
# ══════════════════════════════════════════════════════════════════════════════

def correlate_analytics_and_tag_ids(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> dict[str, list[str]]:
    patterns = {
        "Google_Tag_Manager": re.compile(r"\b(GTM-[A-Z0-9]{5,10})\b"),
        "Google_Analytics_4": re.compile(r"\b(G-[A-Z0-9]{8,12})\b"),
        "Universal_Analytics": re.compile(r"\b(UA-\d{5,12}-\d{1,3})\b"),
        "Yandex_Metrika": re.compile(r"ym\s*\(\s*(\d{7,10})\s*,"),
        "Facebook_Pixel": re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{12,18})['\"]"),
    }
    found_ids: dict[str, set[str]] = {k: set() for k in patterns}
    for tu in [base_url] + list(js_urls[:10]):
        try:
            r = session.get(tu, timeout=5, verify=False)
            if r.status_code == 200:
                txt = r.text[:250000]
                for label, rx in patterns.items():
                    for m in rx.findall(txt):
                        found_ids[label].add(m)
        except Exception:
            pass

    clean_map = {k: sorted(v) for k, v in found_ids.items() if v}
    if clean_map:
        flat_str = " | ".join([f"{k}: {', '.join(vals)}" for k, vals in clean_map.items()])
        db.upsert_finding(
            project_id, "SPECTRE-v10 (Analytics-Pivot)",
            f"Organization Analytics & Tracking Correlation IDs ({sum(len(v) for v in clean_map.values())} IDs)",
            "Horizontal Domain Correlation OSINT", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            base_url, f"Extracted Identifiers: {flat_str}",
            "Ushbu GTM/GA/Metrika identifikatorlari orqali kompaniyaga tegishli bo'lgan boshqa (gorizontal) domenlar va loyihalarni aniqlash mumkin.",
            "Ichki test va ma'muriy tizimlarda ommaviy marketing/analitika teglarini ishlatmang.",
        )
        log_fn(f"  [🕸️ ANALYTICS PIVOT] {flat_str}")
    return clean_map


# ══════════════════════════════════════════════════════════════════════════════
# 11. HTTP RANGE (BYTES=0-63) ARCHIVE MAGIC-BYTE SIGNATURE VERIFIER
# ══════════════════════════════════════════════════════════════════════════════

ARCHIVE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP Archive"),
    (b"\x1f\x8b\x08", "GZIP Compressed Archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"Rar!\x1a\x07", "RAR Archive"),
    (b"SQLite format 3", "SQLite3 Database File"),
    (b"-- MySQL dump", "MySQL Database Dump"),
    (b"-- PostgreSQL database dump", "PostgreSQL Database Dump"),
]


def verify_archive_magic_bytes_range(db, session, project_id: int, apex_domain: str, base_url: str, log_fn) -> int:
    brand = apex_domain.split(".")[0].lower()
    candidates = [
        ("/backup.zip", b"PK\x03\x04", "ZIP Archive"),
        ("/backup.tar.gz", b"\x1f\x8b\x08", "GZIP Archive"),
        ("/db.sql", b"-- MySQL dump", "MySQL Database Dump"),
        ("/db.sql.gz", b"\x1f\x8b\x08", "GZIP SQL Archive"),
        ("/database.sqlite", b"SQLite format 3", "SQLite3 Database File"),
        (f"/{brand}.zip", b"PK\x03\x04", "ZIP Archive"),
        (f"/{brand}.sql.gz", b"\x1f\x8b\x08", "GZIP SQL Archive"),
        ("/www.zip", b"PK\x03\x04", "ZIP Archive"),
        ("/site.zip", b"PK\x03\x04", "ZIP Archive"),
        ("/dump.sql", b"-- PostgreSQL database dump", "PostgreSQL Database Dump"),
    ]
    verified = 0
    for path, exp_sig, fmt_name in candidates:
        u = urllib.parse.urljoin(base_url, path)
        try:
            # Accept-Encoding: identity majburiy — aks holda Nginx oddiy HTML sahifani gzip (\x1f\x8b\x08) qilib yuboradi!
            r = session.get(u, headers={"Range": "bytes=0-63", "Accept-Encoding": "identity"}, timeout=4, verify=False, allow_redirects=False)
            if r.status_code not in (200, 206) or len(r.content) < 8:
                continue
            ctype = r.headers.get("Content-Type", "").lower()
            cenc = r.headers.get("Content-Encoding", "").lower()
            if "text/html" in ctype or "application/json" in ctype or cenc == "gzip":
                continue
            head_bytes = r.content[:64]
            if head_bytes.lstrip()[:15].lower().startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<script", b"{")):
                continue
            if head_bytes.startswith(exp_sig) or (exp_sig.startswith(b"--") and exp_sig in head_bytes[:48]):
                verified += 1
                db.upsert_finding(
                    project_id, "SPECTRE-v10 (MagicByte-Verifier)",
                    f"[CONFIRMED] Binary-Verified Exposed Archive / DB ({path} — {fmt_name})",
                    "Sensitive Backup Exposure", "Critical", 9.1,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-530", "A05:2021 - Security Misconfiguration",
                    u, f"HTTP {r.status_code} | Content-Type: {ctype} | Verified Magic Bytes: {head_bytes[:16]!r} ({fmt_name})",
                    "HTTP Range (0-63 bayt, identity encoding) tekshiruvi orqali veb-serverda haqiqiy arxiv yoki ma'lumotlar bazasi fayli ochiq qolgani matematik tasdiqlandi.",
                    "Zaxira nusxalarini (.zip, .sql, .gz, .sqlite) veb-serverning ommaviy katalogidan darhol o'chiring.",
                )
                log_fn(f"  [🗃️ MAGIC-BYTE VERIFIED] {u} -> Haqiqiy {fmt_name} fayli tasdiqlandi!")
        except Exception:
            pass
    return verified


# ══════════════════════════════════════════════════════════════════════════════
# 12. CLIENT-SIDE WEB STORAGE (LOCALSTORAGE / SESSIONSTORAGE / INDEXEDDB) MAPPER
# ══════════════════════════════════════════════════════════════════════════════

def extract_client_storage_keys_and_checks(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> list[str]:
    storage_re = re.compile(r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\(\s*['"]([a-zA-Z0-9_\-\.]{2,45})['"]\s*[,)]""")
    idb_re = re.compile(r"""indexedDB\.open\s*\(\s*['"]([a-zA-Z0-9_\-\.]{2,45})['"]""")
    role_cmp_re = re.compile(r"""(?:localStorage|sessionStorage)\.getItem\s*\(\s*['"]([a-zA-Z0-9_\-\.]{2,35})['"]\s*\)\s*[!=]==?\s*['"]([a-zA-Z0-9_\-\.]{2,35})['"]""")

    keys: set[str] = set()
    role_checks: list[str] = []

    for tu in [base_url] + list(js_urls[:18]):
        try:
            r = session.get(tu, timeout=5, verify=False)
            if r.status_code != 200:
                continue
            txt = r.text[:350000]
            for k in storage_re.findall(txt):
                keys.add(k)
            for db_name in idb_re.findall(txt):
                keys.add(f"IndexedDB:{db_name}")
            for k_name, val_cmp in role_cmp_re.findall(txt):
                role_checks.append(f"{k_name} == '{val_cmp}'")
        except Exception:
            pass

    if keys or role_checks:
        k_list = sorted(keys)
        sev = "Medium" if role_checks else "Info"
        cvss = 5.3 if role_checks else 0.0
        db.upsert_finding(
            project_id, "SPECTRE-v10 (WebStorage-Mapper)",
            f"Client-Side Storage Keys & State Conditions ({len(k_list)} keys)" + (" [Client Role Check!]" if role_checks else ""),
            "Client-Side State & Storage Security", sev, cvss,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "CWE-922", "A04:2021 - Insecure Design",
            base_url,
            f"Storage Keys: {', '.join(k_list[:15])}" + (f" | Client Conditions: {', '.join(role_checks[:5])}" if role_checks else ""),
            "JavaScript kodida localStorage/sessionStorage/IndexedDB kalitlari va mijoz tomonida rol tekshiruvlari aniqlandi.",
            "Maxfiy tokenlarni HttpOnly cookie'da saqlang va foydalanuvchi huquqlarini faqat backendda tekshiring.",
        )
        log_fn(f"  [🧠 WEB STORAGE] {len(k_list)} ta kalit topildi" + (f" | Shartlar: {', '.join(role_checks[:3])}" if role_checks else ""))
    return sorted(keys)


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ORCHESTRATOR FOR ALL 12 SPECTRE v10.0 MODULES
# ══════════════════════════════════════════════════════════════════════════════

def run_v10_enterprise_suite(agent, project_id: int, apex_domain: str, base_url: str, js_urls: list[str], log_fn) -> None:
    log_fn(f"  [⚡ SPECTRE v10.0] {base_url} ustida 12 ta chuqur arxitektura va protokol moduli ishga tushirildi...")
    db = agent.db
    session = agent.session

    audit_vcs_metadata_exposure(db, session, project_id, base_url, log_fn)
    audit_static_routing_headers(db, session, project_id, base_url, log_fn)
    extract_grpc_and_protobuf_schemas(db, session, project_id, base_url, js_urls, log_fn)
    analyze_postmessage_handlers(db, session, project_id, base_url, js_urls, log_fn)
    audit_cache_policy_and_headers(db, session, project_id, base_url, log_fn)
    validate_spf_dmarc_recursive(db, project_id, apex_domain, log_fn)
    parse_service_worker_manifests(db, session, project_id, base_url, log_fn)
    inspect_http_protocol_and_proxy_topology(db, session, project_id, base_url, log_fn)
    audit_oauth_oidc_parameters(db, project_id, base_url, log_fn)
    correlate_analytics_and_tag_ids(db, session, project_id, base_url, js_urls, log_fn)
    verify_archive_magic_bytes_range(db, session, project_id, apex_domain, base_url, log_fn)
    extract_client_storage_keys_and_checks(db, session, project_id, base_url, js_urls, log_fn)
    db.log_task(project_id, "SPECTRE-v10", "v10_enterprise_suite", "COMPLETED", f"v10_suite {base_url}", f"Executed 12 v10 Deep Architecture modules on {base_url}")





