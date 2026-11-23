"""
SPECTRE v3.0 — Protocol, Cache, VCS & Client-State Analysis Modules
"""

from __future__ import annotations

import json
import pathlib
import re
import urllib.parse
from typing import Any

import dns.resolver
from core.http_engine import fetch_cached_text

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent


# 1. VCS (.git/config & .git/logs/HEAD) METADATA & COMMIT HISTORY PARSER

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


# 2. STATIC DIRECTORY INDEXING & SERVER HEADER CONFIGURATION AUDITOR

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


# 3. GRPC-WEB & PROTOBUF SERVICE/METHOD DESCRIPTOR EXTRACTOR

def extract_grpc_and_protobuf_schemas(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> list[str]:
    grpc_methods: set[str] = set()
    proto_types: set[str] = set()
    method_re = re.compile(r'["\'](/([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)/([A-Z][a-zA-Z0-9_]+))["\']')
    proto_re = re.compile(r"proto\.([a-zA-Z0-9_]+\.[A-Za-z0-9_.]+)")

    for ju in js_urls[:20]:
        try:
            txt = fetch_cached_text(session, project_id, ju, timeout=5.0, max_chars=350000)
            if not txt:
                continue
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
        db.log_task(
            project_id,
            "SPECTRE-Intel",
            "grpc_schema",
            "COMPLETED",
            base_url,
            f"gRPC ({len(m_list)} methods, {len(p_list)} types): {', '.join(m_list[:8])}",
        )
        log_fn(f"  [📡 gRPC MAPPER] {len(m_list)} ta gRPC metod va {len(p_list)} ta Protobuf tip tiklandi!")
    return sorted(grpc_methods)


# 4. CLIENT-SIDE POSTMESSAGE BRACE-BALANCED AST HANDLER ANALYZER

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
    dyn_sink_re = re.compile(
        r"""(\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!['"`][^'"`$+{]*['"`]\s*[;,\n}])|document\.write\s*\(|eval\s*\(|location\.(?:href|assign|replace)|setAttribute\s*\(\s*['"]src)"""
    )
    issues = 0

    targets = [base_url] + list(js_urls[:20])
    for tu in targets:
        try:
            txt = fetch_cached_text(session, project_id, tu, timeout=5.0, max_chars=400000)
            if not txt:
                continue
            for m in listener_re.finditer(txt):
                block = _extract_brace_block(txt, m.end())
                has_origin_check = (".origin" in block) or ("origin" in block and "===" in block)
                sink_match = dyn_sink_re.search(block)
                if not has_origin_check and sink_match and (".data" in block or "data" in block):
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


# 5. WEB CACHE POLICY, VARY HEADER & STATIC-EXTENSION CACHE AUDITOR

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


# 6. RECURSIVE DNS SPF LOOKUP-TREE & DMARC POLICY VALIDATOR (RFC-7208)

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

    mta_sts_txt = ""
    try:
        ans_m = resolver.resolve(f"_mta-sts.{apex_domain}", "TXT")
        for rdata in ans_m:
            s = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if "v=sts" in s.lower():
                mta_sts_txt = s
                break
    except Exception:
        pass
    if mta_sts_txt:
        db.log_task(project_id, "SPECTRE-Intel", "mta_sts", "COMPLETED", apex_domain, f"MTA-STS Enabled: {mta_sts_txt[:100]}")

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


# 7. SERVICE WORKER (sw.js / Workbox / Angular ngsw.json) ROUTE HARVESTER

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
        db.log_task(
            project_id,
            "SPECTRE-Intel",
            "service_worker_routes",
            "COMPLETED",
            base_url,
            f"PWA Precache Routes ({len(r_list)}): {', '.join(r_list[:10])}",
        )
        log_fn(f"  [⚙️ SERVICE WORKER] {len(r_list)} ta yashirin PWA/Workbox marshruti tiklandi!")
    return sorted(discovered_routes)


# 8. HTTP/3 (ALT-SVC) & REVERSE-PROXY TOPOLOGY MAPPER

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
            db.log_task(project_id, "SPECTRE-Intel", "topology_headers", "COMPLETED", base_url, f"Topology Headers: {summary[:220]}")
            log_fn(f"  [🧬 TOPOLOGY MAP] {base_url} -> {summary[:100]}")
    except Exception:
        pass
    return topo


# 9. OAUTH 2.0 / OIDC STATE, PKCE & IMPLICIT FLOW AUDITOR

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


# 10. CROSS-DOMAIN ANALYTICS & TAG ID (GTM / GA / METRIKA) CORRELATOR

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
        db.log_task(
            project_id,
            "SPECTRE-Intel",
            "analytics_correlation",
            "COMPLETED",
            base_url,
            f"Analytics IDs: {flat_str[:220]}",
        )
        log_fn(f"  [🕸️ ANALYTICS PIVOT] {flat_str}")
    return clean_map


# 11. HTTP RANGE (BYTES=0-63) ARCHIVE MAGIC-BYTE SIGNATURE VERIFIER

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


# 12. CLIENT-SIDE WEB STORAGE (LOCALSTORAGE / SESSIONSTORAGE / INDEXEDDB) MAPPER

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
        if role_checks:
            db.upsert_finding(
                project_id, "SPECTRE-v10 (WebStorage-Mapper)",
                f"Client-Side Storage Keys & State Conditions ({len(k_list)} keys) [Client Role Check!]",
                "Client-Side State & Storage Security", "Medium", 5.3,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "CWE-922", "A04:2021 - Insecure Design",
                base_url,
                f"Storage Keys: {', '.join(k_list[:15])} | Client Conditions: {', '.join(role_checks[:5])}",
                "JavaScript kodida localStorage/sessionStorage/IndexedDB orqali mijoz tomonida rol tekshiruvlari aniqlandi.",
                "Maxfiy tokenlarni HttpOnly cookie'da saqlang va foydalanuvchi huquqlarini faqat backendda tekshiring.",
            )
        else:
            db.log_task(
                project_id,
                "SPECTRE-Intel",
                "web_storage_keys",
                "COMPLETED",
                base_url,
                f"Client Storage Keys ({len(k_list)}): {', '.join(k_list[:12])}",
            )
        log_fn(f"  [🧠 WEB STORAGE] {len(k_list)} ta kalit topildi" + (f" | Shartlar: {', '.join(role_checks[:3])}" if role_checks else ""))
    return sorted(keys)


CLOUD_CNAME_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("github.io", "There isn't a GitHub Pages site here."),
    ("herokuapp.com", "No such app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("pantheonsite.io", "404 error unknown site"),
    ("fastly.net", "Fastly error: unknown domain:"),
    ("myshopify.com", "Sorry, this shop is currently unavailable."),
    ("surge.sh", "project not found"),
    ("ghost.io", "The thing you were looking for is no longer here"),
    ("zendesk.com", "Help Center Closed"),
)


def audit_dangling_cname_and_dns_caa(db, session, project_id: int, apex_domain: str, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.5
    hits = 0

    for d in bundle.get("domains", [])[:80]:
        dom = str(d.get("domain") or "").strip().lower()
        cn = str(d.get("cname") or "").strip().lower().rstrip(".")
        if not dom or not cn or cn == dom or cn.startswith("loopback:"):
            continue
        try:
            resolver.resolve(cn, "A")
        except dns.resolver.NXDOMAIN:
            hits += 1
            db.upsert_finding(
                project_id, "SPECTRE-Protocol (DNS-CNAME)",
                f"[CONFIRMED] Dangling DNS CNAME Pointing to NXDOMAIN ({dom})",
                "Subdomain CNAME Misconfiguration", "High", 8.1,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", "CWE-350", "A05:2021 - Security Misconfiguration",
                dom, f"CNAME: {dom} -> {cn} (DNS NXDOMAIN)",
                "Subdomen CNAME yozuvi ro'yxatdan o'chgan (NXDOMAIN) tashqi domenga yo'naltirilgan.",
                f"DNS zonasidan eskirgan `{dom}` CNAME yozuvini darhol olib tashlang.",
                confidence="Confirmed-PoC (QoD: 99%)",
            )
            continue
        except Exception:
            pass

        for prov_sfx, body_sig in CLOUD_CNAME_SIGNATURES:
            if cn.endswith(prov_sfx):
                for sch in ("http", "https"):
                    try:
                        rp = session.get(f"{sch}://{dom}", timeout=4.0, verify=False, allow_redirects=False)
                        if body_sig.lower() in (rp.text or "")[:16384].lower():
                            hits += 1
                            db.upsert_finding(
                                project_id, "SPECTRE-Protocol (DNS-CNAME)",
                                f"[CONFIRMED] Unclaimed Cloud CNAME Resource ({dom})",
                                "Subdomain CNAME Misconfiguration", "High", 8.6,
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", "CWE-350", "A05:2021 - Security Misconfiguration",
                                f"{sch}://{dom}", f"CNAME: {dom} -> {cn} | Matched Provider Signature: '{body_sig}'",
                                "Subdomen CNAME yozuvi bulutli provayderdagi band qilinmagan resursga ulangan.",
                                f"DNS zonasidan `{dom}` CNAME yozuvini o'chiring yoki provayder panelida resursni qayta biriktiring.",
                                confidence="Confirmed-PoC (QoD: 99%)",
                            )
                            break
                    except Exception:
                        pass

    caa_vals: list[str] = []
    has_dnssec = False
    try:
        for rdata in resolver.resolve(apex_domain, "CAA"):
            caa_vals.append(rdata.to_text())
    except Exception:
        pass
    try:
        if resolver.resolve(apex_domain, "DNSKEY"):
            has_dnssec = True
    except Exception:
        pass
    db.log_task(
        project_id, "SPECTRE-Intel", "dns_caa_dnssec", "COMPLETED", apex_domain,
        f"CAA: {', '.join(caa_vals[:4]) or 'Not Configured'} | DNSSEC: {'Enabled' if has_dnssec else 'Unsigned'}",
    )
    return hits


def run_protocol_client_suite(agent, project_id: int, apex_domain: str, base_url: str, js_urls: list[str], log_fn) -> None:
    from core.plugin_runner import ScanPhase, run_plugin_safely

    log_fn(f"  [Protocol-Client-Suite] {base_url} ustida 12 ta arxitektura va protokol moduli ishga tushirildi...")
    db = agent.db
    session = agent.session

    ran_apex = getattr(agent, "_ran_apex_suites", None)
    if ran_apex is None:
        agent._ran_apex_suites = {}
        ran_apex = agent._ran_apex_suites
    proj_done = ran_apex.setdefault(project_id, set())

    run_plugin_safely(db, project_id, "pc_vcs_metadata", audit_vcs_metadata_exposure, db, session, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    run_plugin_safely(db, project_id, "pc_routing_headers", audit_static_routing_headers, db, session, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    run_plugin_safely(db, project_id, "pc_grpc_schema", extract_grpc_and_protobuf_schemas, db, session, project_id, base_url, js_urls, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "pc_postmessage_ast", analyze_postmessage_handlers, db, session, project_id, base_url, js_urls, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "pc_cache_policy", audit_cache_policy_and_headers, db, session, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    if "spf_dmarc_audit" not in proj_done:
        proj_done.add("spf_dmarc_audit")
        run_plugin_safely(db, project_id, "pc_spf_dmarc", validate_spf_dmarc_recursive, db, project_id, apex_domain, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
        run_plugin_safely(db, project_id, "pc_cname_caa", audit_dangling_cname_and_dns_caa, db, session, project_id, apex_domain, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    run_plugin_safely(db, project_id, "pc_service_worker", parse_service_worker_manifests, db, session, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "pc_proxy_topology", inspect_http_protocol_and_proxy_topology, db, session, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "pc_oauth_oidc", audit_oauth_oidc_parameters, db, project_id, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "pc_analytics_corr", correlate_analytics_and_tag_ids, db, session, project_id, base_url, js_urls, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    run_plugin_safely(db, project_id, "pc_archive_magic", verify_archive_magic_bytes_range, db, session, project_id, apex_domain, base_url, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_VERIFY)
    run_plugin_safely(db, project_id, "pc_web_storage", extract_client_storage_keys_and_checks, db, session, project_id, base_url, js_urls, log_fn, log_fn=log_fn, phase=ScanPhase.ACT_GATHER_INFO)
    db.log_task(project_id, "SPECTRE-Protocol", "protocol_client_suite", "COMPLETED", f"protocol_suite {base_url}", f"Executed 12 protocol/client modules on {base_url}")





