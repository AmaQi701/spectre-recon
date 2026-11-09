"""
SPECTRE v9.0 — Predator Recon & Dark Attack Surface Intelligence Modules
"""

from __future__ import annotations

import base64
import codecs
import concurrent.futures
import hashlib
import hmac
import json
import pathlib
import re
import urllib.parse
from typing import Any

import dns.resolver
from bs4 import BeautifulSoup

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

KNOWN_FAVICON_HASHES: dict[int, str] = {
    116323821: "Spring Boot (Default Favicon)",
    81586312: "Jenkins CI/CD Server",
    981867722: "Atlassian Jira",
    -305179312: "Atlassian Confluence",
    1278323681: "GitLab Enterprise / CE",
    -1498185948: "Grafana Dashboard",
    -267431135: "Kibana Analytics",
    1768726119: "Microsoft Outlook Web App (OWA)",
    -1293291047: "Zimbra Collaboration Suite",
    -991427585: "Roundcube Webmail",
    -1333994158: "Plesk Control Panel",
    1993518473: "cPanel / WHM",
    -335242539: "F5 BIG-IP TMUI",
    945408572: "FortiGate SSL VPN",
    -1950415971: "Pulse Secure VPN",
    -1666561833: "Keycloak IAM / SSO",
    1485257654: "Metabase BI",
    -656811182: "1C-Bitrix CMS",
    -119764410: "WordPress Core",
    -297069493: "SonarQube Code Quality",
    -1205024243: "Harbor Container Registry",
    -1581907337: "MinIO Object Storage",
    516963061: "phpMyAdmin",
    -1695259674: "Hikvision IP Camera / NVR",
    -1742087623: "MikroTik RouterOS WebFig",
    -1409986931: "Proxmox Virtual Environment (PVE)",
    -1424036600: "Portainer Container Management",
    892542951: "Zabbix Monitoring",
    1065745209: "RabbitMQ Management Console",
    -1255326364: "VMware ESXi / vSphere",
    -631511155: "Palo Alto GlobalProtect Portal",
    1279085681: "ArgoCD Kubernetes GitOps",
    -1048569984: "HashiCorp Vault UI",
    -1566156368: "Sonatype Nexus Repository",
    -1997542297: "JFrog Artifactory",
    -1179873469: "Odoo ERP",
    1363895724: "FastAPI / Swagger UI",
}


def murmurhash3_32_signed(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x3
    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8) | ((data[i + 2] & 0xFF) << 16) | ((data[i + 3] & 0xFF) << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 0x3
    if tail == 3:
        k1 ^= (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 ^= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 ^= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


def compute_shodan_favicon_hash(raw_bytes: bytes) -> int:
    return murmurhash3_32_signed(codecs.encode(raw_bytes, "base64"))


def fingerprint_favicon_hash_and_tech(db, session, project_id: int, base_url: str, log_fn) -> dict[str, Any]:
    fav_urls = [urllib.parse.urljoin(base_url, "/favicon.ico")]
    try:
        r_home = session.get(base_url, timeout=6, verify=False)
        if r_home.status_code == 200 and "<link" in r_home.text.lower():
            soup = BeautifulSoup(r_home.text, "html.parser")
            for link in soup.find_all("link", href=True):
                if "icon" in " ".join(link.get("rel") or []).lower():
                    full_ico = urllib.parse.urljoin(base_url, link["href"])
                    if full_ico not in fav_urls:
                        fav_urls.insert(0, full_ico)
    except Exception:
        pass

    fav_hash, used_fav_url = None, ""
    for fu in fav_urls[:3]:
        try:
            rf = session.get(fu, timeout=6, verify=False)
            ctype = rf.headers.get("Content-Type", "").lower()
            if rf.status_code == 200 and len(rf.content) > 32 and "text/html" not in ctype:
                fav_hash = compute_shodan_favicon_hash(rf.content)
                used_fav_url = fu
                break
        except Exception:
            pass

    if fav_hash is None:
        return {}

    matched_tech = KNOWN_FAVICON_HASHES.get(fav_hash, "")
    shodan_dork = f"http.favicon.hash:{fav_hash}"
    log_fn(f"  [🕵️ FAVICON MMH3] {used_fav_url} -> Hash: {fav_hash} ({shodan_dork})" + (f" [{matched_tech}]" if matched_tech else ""))
    if matched_tech:
        db.merge_http_tech_stack(project_id, base_url, [f"Favicon:{matched_tech}"])

    bundle = db.get_project_bundle(project_id)
    cdn_keywords = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "ddos-guard")
    candidate_ips = {
        (d.get("ip") or "").strip()
        for d in bundle.get("domains", [])
        if (d.get("ip") or "").strip() and "." in (d.get("ip") or "") and not any(k in (d.get("cdn_provider") or "").lower() for k in cdn_keywords)
    }

    matched_origins = []
    fav_path = urllib.parse.urlparse(used_fav_url).path or "/favicon.ico"
    for ip in list(candidate_ips)[:8]:
        for scheme in ("https", "http"):
            try:
                rip = session.get(f"{scheme}://{ip}{fav_path}", timeout=3.5, verify=False)
                if rip.status_code == 200 and len(rip.content) > 32 and compute_shodan_favicon_hash(rip.content) == fav_hash:
                    matched_origins.append(ip)
                    break
            except Exception:
                pass

    desc_extra = f" | Origin IP Match: {', '.join(matched_origins)}" if matched_origins else ""
    db.upsert_finding(
        project_id, "SPECTRE-Predator (Favicon-MMH3)",
        f"Favicon MurmurHash3 Fingerprint ({fav_hash})" + (f" — {matched_tech}" if matched_tech else ""),
        "Reconnaissance & Shadow Asset Intelligence",
        "Medium" if matched_origins else "Info", 5.3 if matched_origins else 0.0,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
        used_fav_url, f"Shodan: {shodan_dork} | Censys: services.http.response.favicons.shodan_hash:{fav_hash}{desc_extra}",
        "Favicon MurmurHash3 xeshi orqali internet bo'ylab barcha klon/staging serverlar va CDN ortidagi IP manzillarni qidirish mumkin.",
        "Origin serverlarda asosiy domen favicon faylini ochiq qoldirmang va IP kirishni faqat CDN subnetlariga cheklang.",
    )
    return {"hash": fav_hash, "tech": matched_tech, "matched_origins": matched_origins}


# ══════════════════════════════════════════════════════════════════════════════
# 2. JAVASCRIPT SOURCEMAP (*.js.map) UNPACKER & SOURCE CODE RECONSTRUCTOR
# ══════════════════════════════════════════════════════════════════════════════

def unpack_js_sourcemaps(db, session, project_id: int, js_urls: list[str], base_url: str, log_fn) -> int:
    if not js_urls:
        return 0
    unpacked_count = 0
    route_re = re.compile(r"""['"`]((?:/api/v\d+/|/api/|/v1/|/v2/|/internal/|/admin/|/graphql|/auth/)[a-zA-Z0-9_\-/\.?=&{}]+)['"`]""")
    out_dir = BASE_DIR / "workspaces" / "sourcemaps" / f"project_{project_id}"

    for js_u in js_urls[:25]:
        map_candidates = [js_u + ".map"]
        try:
            rj = session.get(js_u, timeout=6, verify=False)
            if rj.status_code == 200:
                m_dir = re.search(r"//#\s*sourceMappingURL=([^\s'\"`]+)", rj.text[-2000:])
                if m_dir:
                    ref_map = m_dir.group(1).strip()
                    if not ref_map.startswith("data:"):
                        map_candidates.insert(0, urllib.parse.urljoin(js_u, ref_map))
        except Exception:
            pass

        for map_u in map_candidates[:2]:
            try:
                rm = session.get(map_u, timeout=8, verify=False)
                if rm.status_code == 200 and '"version"' in rm.text[:300] and '"sources"' in rm.text[:2000]:
                    data = rm.json()
                    sources = [str(s) for s in (data.get("sources") or []) if s]
                    contents = [str(c) for c in (data.get("sourcesContent") or []) if c]
                    extracted_routes = set()
                    saved_files = 0
                    out_dir.mkdir(parents=True, exist_ok=True)

                    for idx_s, src_code in enumerate(contents[:60]):
                        if not src_code or not isinstance(src_code, str):
                            continue
                        raw_name = sources[idx_s] if idx_s < len(sources) else f"module_{idx_s}.ts"
                        safe_rel = re.sub(r"[^a-zA-Z0-9_\-\./]", "_", raw_name.replace("webpack://", "").replace("../", "")).lstrip("/.")
                        if not safe_rel or safe_rel.endswith("/"):
                            safe_rel = f"unpacked_{idx_s}.ts"
                        dest_f = out_dir / safe_rel
                        try:
                            dest_f.parent.mkdir(parents=True, exist_ok=True)
                            dest_f.write_text(src_code[:400000], encoding="utf-8", errors="ignore")
                            saved_files += 1
                        except Exception:
                            pass
                        for rt in route_re.findall(src_code):
                            extracted_routes.add(rt)
                            db.upsert_endpoint(project_id, urllib.parse.urljoin(base_url, rt), method="GET", params=[], category="api_endpoint", source="sourcemap_unpacked")

                    unpacked_count += 1
                    sample_files = ", ".join(sources[:8])
                    db.upsert_finding(
                        project_id, "SPECTRE-Predator (SourceMap-Unpacker)",
                        f"[CONFIRMED] Exposed JavaScript SourceMap ({urllib.parse.urlparse(map_u).path.split('/')[-1]})",
                        "Source Code Exposure", "High", 7.5,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-540", "A05:2021 - Security Misconfiguration",
                        map_u,
                        f"Original Source Files ({len(sources)}): {sample_files} | Disk Reconstructed: {saved_files} files in {out_dir} | Hidden Routes: {len(extracted_routes)}",
                        "Production serverda .js.map (SourceMap) fayli ochiq qolgan — dasturning asl TypeScript/JSX manba kodini 100% tiklash va SAST orqali tahlil qilish mumkin.",
                        "Build jarayonida 'productionSourceMap: false' o'rnating yoki Nginx'da *.map fayllariga kirishni bloklang.",
                    )
                    log_fn(f"  [🧬 SOURCEMAP UNPACKED] {map_u} -> {saved_files} ta asl fayl '{out_dir.name}' ga tiklandi ({len(extracted_routes)} ta ichki route)!")
                    break
            except Exception:
                pass
    return unpacked_count


# ══════════════════════════════════════════════════════════════════════════════
# 3. 401/403 REVERSE-PROXY & PATH NORMALIZATION ACL AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_reverse_proxy_acl_misconfigs(db, session, project_id: int, base_url: str, log_fn) -> int:
    candidate_paths = ["/admin", "/api/admin", "/actuator", "/metrics", "/swagger-ui.html", "/internal", "/console", "/debug"]
    bundle = db.get_project_bundle(project_id)
    for u in bundle.get("endpoints", []):
        p = urllib.parse.urlparse(u.get("url", "")).path
        if p and any(k in p.lower() for k in ("admin", "internal", "manage", "config", "debug", "actuator", "private")) and p not in candidate_paths:
            candidate_paths.append(p)

    home_len, notfound_len = -1, -1
    home_hash, notfound_hash = "", ""
    supports_x_orig = False
    try:
        rh = session.get(base_url, timeout=5, verify=False, allow_redirects=False)
        home_len = len(rh.text)
        home_hash = hashlib.sha256(rh.text.encode("utf-8", errors="ignore")).hexdigest()
        rn = session.get(urllib.parse.urljoin(base_url, "/spectre-acl-nonexistent-91827"), timeout=5, verify=False, allow_redirects=False)
        notfound_len = len(rn.text)
        notfound_hash = hashlib.sha256(rn.text.encode("utf-8", errors="ignore")).hexdigest()
        # Calibration: agar X-Original-URL: /nonexistent yuborilganda ham 200 OK (homepage) qaytsa, server X-Original-URL ni umuman ishlatmaydi!
        rx_cal = session.get(base_url, headers={"X-Original-URL": "/spectre-acl-nonexistent-91827"}, timeout=5, verify=False, allow_redirects=False)
        if rx_cal.status_code in (400, 403, 404):
            supports_x_orig = True
    except Exception:
        pass

    confirmed = 0
    for path in candidate_paths[:10]:
        full_u = urllib.parse.urljoin(base_url, path)
        try:
            r_base = session.get(full_u, timeout=5, verify=False, allow_redirects=False)
            if r_base.status_code not in (401, 403):
                continue
            base_block_len = len(r_base.text)
            base_block_hash = hashlib.sha256(r_base.text.encode("utf-8", errors="ignore")).hexdigest()
            clean_p = path.lstrip("/")
            probes = [
                ("Header: X-Forwarded-For: 127.0.0.1", full_u, {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}),
                ("Path: /%2e/" + clean_p, urllib.parse.urljoin(base_url, f"/%2e/{clean_p}"), {}),
                ("Path: /" + clean_p + "/..;/", urllib.parse.urljoin(base_url, f"/{clean_p}/..;/"), {}),
                ("Path: /" + clean_p + ".json", urllib.parse.urljoin(base_url, f"/{clean_p}.json"), {}),
            ]
            if supports_x_orig:
                probes.insert(0, ("Header: X-Original-URL", base_url, {"X-Original-URL": path}))
                probes.insert(1, ("Header: X-Rewrite-URL", base_url, {"X-Rewrite-URL": path}))
            for label, p_url, hdrs in probes:
                rp = session.get(p_url, headers=hdrs, timeout=5, verify=False, allow_redirects=False)
                if rp.status_code == 200 and len(rp.text) > 40:
                    rp_hash = hashlib.sha256(rp.text.encode("utf-8", errors="ignore")).hexdigest()
                    if rp_hash not in (home_hash, notfound_hash, base_block_hash) and abs(len(rp.text) - base_block_len) > 25 and abs(len(rp.text) - home_len) > max(40, int(home_len * 0.05)):
                        confirmed += 1
                        db.upsert_finding(
                            project_id, "SPECTRE-Predator (ACL-Auditor)",
                            f"[CONFIRMED] Reverse-Proxy ACL Normalization Discrepancy ({path})",
                            "Broken Access Control", "High", 8.2,
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "CWE-436", "A01:2021 - Broken Access Control",
                            full_u,
                            f"Baseline: HTTP {r_base.status_code} ({base_block_len}B) -> Probe [{label}] returned HTTP 200 ({len(rp.text)}B)",
                            "Reverse-proxy va backend server o'rtasida URL normalizatsiyasi yoki X-Original-URL/X-Forwarded-For sarlavhalarini qayta ishlashda nomuvofiqlik aniqlandi.",
                            "ACL tekshiruvini faqat reverse-proxy darajasida emas, backend router darajasida ham majburiy bajaring va X-Original-URL sarlavhalarini bloklang.",
                        )
                        log_fn(f"  [🔓 ACL BYPASS CONFIRMED] {full_u} ({r_base.status_code}) -> HTTP 200 via {label}!")
                        break
        except Exception:
            pass
    return confirmed


# ══════════════════════════════════════════════════════════════════════════════
# 4. ARJUN-STYLE CHUNKED + BINARY-SEARCH HIDDEN QUERY PARAMETER MINER
# ══════════════════════════════════════════════════════════════════════════════

COMMON_HIDDEN_PARAMS = [
    "id", "user_id", "account_id", "page", "q", "search", "query", "keyword",
    "redirect", "redirect_uri", "return_to", "next", "url", "callback", "jsonp",
    "debug", "test", "admin", "role", "format", "type", "view", "template",
    "file", "path", "doc", "lang", "locale", "version", "v", "limit", "offset",
    "sort", "order", "filter", "category", "status", "token", "key", "api_key",
]


def mine_hidden_query_parameters(db, session, project_id: int, base_url: str, log_fn) -> int:
    """
    Discovers unlinked GET parameters using chunked canary requests and binary-search isolation
    (measuring dynamic baseline variance to avoid false positives).
    """
    bundle = db.get_project_bundle(project_id)
    candidates = [base_url]
    for u in bundle.get("endpoints", []):
        raw_u = u.get("url", "")
        if raw_u.startswith(base_url) and "?" not in raw_u and not any(raw_u.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff2")):
            if raw_u not in candidates:
                candidates.append(raw_u)

    discovered_total = 0

    def _response_differs(r_test, base_status: int, base_len: int, max_jitter: int, canaries: dict[str, str], reflects_query_url: bool) -> bool:
        if r_test.status_code != base_status:
            return True
        if not reflects_query_url and any(cv in r_test.text for cv in canaries.values()):
            return True
        if abs(len(r_test.text) - base_len) > max(180, max_jitter * 4):
            return True
        return False

    for target_u in candidates[:5]:
        try:
            r1 = session.get(target_u, timeout=5, verify=False, allow_redirects=False)
            if r1.status_code != 200:
                continue
            r2 = session.get(target_u, timeout=5, verify=False, allow_redirects=False)
            r_cal = session.get(f"{target_u}?spectre_cal_991=spcal991v", timeout=5, verify=False, allow_redirects=False)
            base_status = r1.status_code
            base_len = len(r1.text)
            reflects_query_url = "spcal991v" in r_cal.text
            jitter = max(abs(len(r1.text) - len(r2.text)), abs(len(r1.text) - len(r_cal.text)))

            found_for_url = []
            for idx in range(0, len(COMMON_HIDDEN_PARAMS), 20):
                chunk = COMMON_HIDDEN_PARAMS[idx : idx + 20]
                canaries = {p: f"sp7{i}x" for i, p in enumerate(chunk)}
                q_str = urllib.parse.urlencode(canaries)
                r_chunk = session.get(f"{target_u}?{q_str}", timeout=5, verify=False, allow_redirects=False)
                if not _response_differs(r_chunk, base_status, base_len, jitter, canaries, reflects_query_url):
                    continue

                # Binary search to isolate the exact reactive parameter(s)
                queue = [chunk]
                while queue:
                    sub = queue.pop(0)
                    if not sub or len(found_for_url) > 5:
                        continue
                    if len(sub) == 1:
                        p_one = sub[0]
                        c_one = {p_one: "sp99z"}
                        r_one = session.get(f"{target_u}?{urllib.parse.urlencode(c_one)}", timeout=5, verify=False, allow_redirects=False)
                        if _response_differs(r_one, base_status, base_len, jitter, c_one, reflects_query_url):
                            found_for_url.append(p_one)
                        continue
                    mid = len(sub) // 2
                    for half in (sub[:mid], sub[mid:]):
                        c_half = {p: f"sp8{i}y" for i, p in enumerate(half)}
                        r_half = session.get(f"{target_u}?{urllib.parse.urlencode(c_half)}", timeout=5, verify=False, allow_redirects=False)
                        if _response_differs(r_half, base_status, base_len, jitter, c_half, reflects_query_url):
                            queue.append(half)

            if 0 < len(found_for_url) <= 5:
                discovered_total += len(found_for_url)
                db.upsert_endpoint(project_id, target_u, method="GET", params=found_for_url, category="high_value_endpoint", risk_tags=["hidden_params"], source="arjun_param_miner")
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (Param-Miner)",
                    f"Hidden Query Parameters Discovered ({urllib.parse.urlparse(target_u).path or '/'})",
                    "Hidden Attack Surface", "Low", 3.7,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A04:2021 - Insecure Design",
                    target_u,
                    f"Reactive Hidden Parameters: {', '.join(found_for_url)}",
                    "Arjun-uslubidagi differensial va kanareyka tahlili orqali sahifada ko'rinmaydigan, ammo backend qabul qiladigan GET parametrlar aniqlandi.",
                    "Ishlatilmaydigan debug/redirect/query parametrlarini o'chiring va barcha kiruvchi parametrlarni qat'iy validatsiya qiling.",
                )
                log_fn(f"  [🧩 PARAM MINER] {target_u} -> Yashirin parametrlar topildi: {', '.join(found_for_url)}")
        except Exception:
            pass
    return discovered_total


# ══════════════════════════════════════════════════════════════════════════════
# 5. WEBSOCKET (WS/WSS & SOCKET.IO) HANDSHAKE & CSWSH AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_websocket_endpoints_and_cswsh(db, session, project_id: int, base_url: str, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    ws_targets = [
        urllib.parse.urljoin(base_url, "/socket.io/?EIO=4&transport=polling"),
        urllib.parse.urljoin(base_url, "/ws"),
        urllib.parse.urljoin(base_url, "/cable"),
    ]
    for u in bundle.get("endpoints", []):
        raw_u = u.get("url", "")
        if raw_u.startswith(("ws://", "wss://")):
            http_equiv = "https://" + raw_u[6:] if raw_u.startswith("wss://") else "http://" + raw_u[5:]
            if http_equiv not in ws_targets:
                ws_targets.insert(0, http_equiv)

    found = 0
    ws_headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": base64.b64encode(b"spectre-ws-key16").decode(),
        "Origin": "https://evil.spectre-audit.org",
    }
    for wt in ws_targets[:8]:
        try:
            r = session.get(wt, headers=ws_headers, timeout=5, verify=False, allow_redirects=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            is_sio = r.status_code == 200 and ('"sid"' in r.text[:200] or "0{" in r.text[:50])
            is_ws101 = r.status_code == 101
            if is_ws101 or (is_sio and acao in ("*", "https://evil.spectre-audit.org")):
                found += 1
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (WebSocket-CSWSH)",
                    f"[CONFIRMED] Cross-Origin WebSocket / Socket.IO Handshake Allowed ({urllib.parse.urlparse(wt).path})",
                    "Cross-Site WebSocket Hijacking (CSWSH)", "High", 7.4,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "CWE-1385", "A01:2021 - Broken Access Control",
                    wt, f"Status: HTTP {r.status_code} | Origin: https://evil.spectre-audit.org | ACAO: {acao or 'Accepted'}",
                    "WebSocket yoki Socket.IO endpointi tashqi Origin sarlavhasini tekshirmasdan ulanishga ruxsat bermoqda (CSWSH xavfi).",
                    "WebSocket handshake vaqtida Origin sarlavhasini oq ro'yxat (allowlist) asosida tekshiring va CSRF/JWT token talab qiling.",
                )
                log_fn(f"  [📡 WEBSOCKET CSWSH] {wt} -> Cross-Origin handshake ruxsat etilgan (HTTP {r.status_code})!")
        except Exception:
            pass
    return found



# ══════════════════════════════════════════════════════════════════════════════
# 6. MULTI-CLOUD (FIREBASE, MINIO, S3) & CONTAINER REGISTRY ENUMERATOR
# ══════════════════════════════════════════════════════════════════════════════

def enumerate_multicloud_and_containers(db, session, project_id: int, apex_domain: str, base_url: str, log_fn) -> int:
    brand = apex_domain.split(".")[0].lower()
    hits = 0

    for fb_name in (brand, f"{brand}-prod", f"{brand}-app"):
        fb_url = f"https://{fb_name}.firebaseio.com/.json"
        try:
            rf = session.get(fb_url, timeout=4.5, verify=False)
            if rf.status_code == 200 and rf.text.strip() not in ("null", "") and "Permission denied" not in rf.text:
                hits += 1
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (Cloud-Enum)",
                    f"[CONFIRMED] Publicly Readable Firebase Database ({fb_name}.firebaseio.com)",
                    "Cloud Storage Misconfiguration", "Critical", 9.1,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-284", "A05:2021 - Security Misconfiguration",
                    fb_url, f"Response Sample: {rf.text[:160]}",
                    "Firebase Realtime Database (/.json) autentifikatsiyasiz ochiq qoldirilgan.",
                    "Firebase Security Rules ichida '.read': 'auth != null' qoidasini o'rnating.",
                )
                log_fn(f"  [☁️ FIREBASE OPEN] {fb_url} ochiq ekanligi aniqlandi!")
        except Exception:
            pass

    infra_probes = [
        ("/v2/_catalog", '"repositories"', "Exposed Docker Registry API (/v2/_catalog)", "Critical", 9.1),
        ("/actuator/env", '"propertySources"', "Exposed Spring Boot Actuator Env (/actuator/env)", "Critical", 9.1),
        ("/actuator/heapdump", "", "Exposed Spring Boot Heapdump (/actuator/heapdump)", "Critical", 9.8),
        ("/metrics", "process_cpu_seconds_total", "Exposed Prometheus Metrics (/metrics)", "Medium", 5.3),
        ("/minio/login", "MinIO", "Exposed MinIO Object Storage Console (/minio/login)", "Low", 3.7),
    ]
    for path, marker, title, sev, cvss in infra_probes:
        u = urllib.parse.urljoin(base_url, path)
        try:
            if path == "/actuator/heapdump":
                rh = session.head(u, timeout=4, verify=False, allow_redirects=False)
                if rh.status_code == 200 and "octet-stream" in rh.headers.get("Content-Type", "").lower() and int(rh.headers.get("Content-Length", "0") or 0) > 100000:
                    hits += 1
                    db.upsert_finding(
                        project_id, "SPECTRE-Predator (Infra-Auditor)", f"[CONFIRMED] {title}",
                        "Infrastructure Exposure", sev, cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "CWE-200", "A05:2021 - Security Misconfiguration", u,
                        f"Content-Type: {rh.headers.get('Content-Type')} | Size: {rh.headers.get('Content-Length')} bytes",
                        "Spring Boot JVM xotira dampi (heapdump) ochiq qolgan.", "Actuator endpointlarini ichki tarmoqqa cheklang.",
                    )
                continue
            r = session.get(u, timeout=4.5, verify=False, allow_redirects=False)
            if r.status_code == 200 and marker and marker in r.text:
                hits += 1
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (Infra-Auditor)", f"[CONFIRMED] {title}",
                    "Infrastructure Exposure", sev, cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", u,
                    f"Matched signature '{marker}' in {u} ({len(r.text)}B)",
                    "Bulutli konteyner yoki monitoring interfeysi tashqi internet uchun ochiq qoldirilgan.",
                    "Ushbu endpointni reverse-proxy orqali bloklang yoki mTLS/Basic-Auth bilan himoyalang.",
                )
                log_fn(f"  [☁️ INFRA EXPOSED] {title}: {u}")
        except Exception:
            pass
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# 7. GRAPHQL FIELD-SUGGESTION ("DID YOU MEAN...") SCHEMA RECONSTRUCTOR
# ══════════════════════════════════════════════════════════════════════════════

def introspect_graphql_field_suggestions(db, session, project_id: int, base_url: str, log_fn) -> list[str]:
    """
    When GraphQL Introspection is disabled, probes short field prefixes ({usr}, {adm}, {cfg}, {pay}, {tok})
    to extract hidden schema field names from Apollo/GraphQL-js "Did you mean ...?" error messages.
    """
    gql_paths = ("/graphql", "/api/graphql", "/v1/graphql", "/query")
    suggestion_re = re.compile(r'Did you mean\s+([^?]+)\?', re.IGNORECASE)
    quoted_re = re.compile(r'\\?"([a-zA-Z0-9_]+)\\?"')
    discovered_fields: set[str] = set()

    for gp in gql_paths:
        gurl = urllib.parse.urljoin(base_url, gp)
        try:
            r_chk = session.post(gurl, json={"query": "{__typename}"}, timeout=4.5, verify=False)
            if r_chk.status_code not in (200, 400) or ("data" not in r_chk.text and "errors" not in r_chk.text):
                continue

            for probe_query in ("{ usr adm cfg tok pay ord acc prof sec int }", "mutation { log reg upd del pay rst tok adm }"):
                r_sug = session.post(gurl, json={"query": probe_query}, timeout=5, verify=False)
                if "Did you mean" in r_sug.text:
                    for m in suggestion_re.findall(r_sug.text):
                        for fld in quoted_re.findall(m):
                            discovered_fields.add(fld)

            # Check GraphQL Array Batching vulnerability ([{query}, {query}])
            r_batch = session.post(gurl, json=[{"query": "{__typename}"}, {"query": "{__typename}"}], timeout=4.5, verify=False)
            if r_batch.status_code == 200 and r_batch.text.lstrip().startswith("[") and r_batch.text.count("__typename") >= 2:
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (GraphQL-Batching)",
                    f"[CONFIRMED] GraphQL Query Array Batching Enabled ({gp})",
                    "API Rate-Limit Bypass / DoS", "Medium", 5.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", "CWE-770", "A04:2021 - Insecure Design",
                    gurl, "Sent JSON array of 2 queries -> Server executed both in a single HTTP request.",
                    "GraphQL serveri bitta HTTP so'rov ichida massiv ko'rinishidagi ko'plab so'rovlarni (Batching) cheklovsiz bajarmoqda (2FA/OTP brute-force xavfi).",
                    "GraphQL serverda query batching limitini o'rnating yoki array batching'ni o'chiring.",
                )
                log_fn(f"  [🧠 GRAPHQL BATCHING] {gurl} -> Array Batching yoqilgan!")

            if discovered_fields:
                fld_list = sorted(discovered_fields)
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (GraphQL-Suggest)",
                    f"[CONFIRMED] GraphQL Schema Leaked via Field Suggestions ({gp})",
                    "API Schema Disclosure", "Medium", 5.3,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-209", "A05:2021 - Security Misconfiguration",
                    gurl, f"Reconstructed GraphQL Fields ({len(fld_list)}): {', '.join(fld_list[:18])}",
                    "GraphQL serverida Introspection o'chirilgan bo'lsa ham, 'Did you mean...?' xatolik xabarlari orqali yashirin sxema maydonlari fosh bo'lmoqda.",
                    "Apollo/GraphQL serverda field suggestion xususiyatini production muhitida o'chirib qo'ying.",
                )
                log_fn(f"  [🧠 GRAPHQL SUGGEST] {gurl} -> {len(fld_list)} ta yashirin GraphQL field tiklandi: {', '.join(fld_list[:8])}")
                break
        except Exception:
            pass
    return sorted(discovered_fields)


# ══════════════════════════════════════════════════════════════════════════════
# 8. DEPENDENCY CONFUSION & UNCLAIMED SCOPED NPM PACKAGE HUNTER
# ══════════════════════════════════════════════════════════════════════════════

def hunt_dependency_confusion_risks(db, session, project_id: int, js_urls: list[str], base_url: str, log_fn) -> int:
    """
    Extracts scoped (@org/pkg) NPM package names from package.json and JS bundles/sourcemaps,
    and checks registry.npmjs.org for unclaimed (HTTP 404) organization scopes/packages.
    """
    scoped_pkgs: set[str] = set()
    pkg_re = re.compile(r"node_modules/(@[a-z0-9\-_]+/[a-z0-9\-_\.]+)")
    PUBLIC_SAFE_SCOPES = {
        "@babel", "@vue", "@angular", "@react", "@emotion", "@mui", "@fortawesome",
        "@sentry", "@stripe", "@floating-ui", "@popperjs", "@radix-ui", "@tanstack",
        "@reduxjs", "@apollo", "@graphql", "@testing-library", "@types", "@vercel",
        "@next", "@nuxt", "@vite", "@rollup", "@ tailwind", "@headlessui", "@heroicons",
    }

    for manifest_p in ("/package.json", "/static/package.json", "/assets/package.json"):
        try:
            rm = session.get(urllib.parse.urljoin(base_url, manifest_p), timeout=4.5, verify=False)
            if rm.status_code == 200 and '"dependencies"' in rm.text:
                data = rm.json()
                for sec in ("dependencies", "devDependencies"):
                    for k in (data.get(sec) or {}).keys():
                        if k.startswith("@"):
                            scoped_pkgs.add(k)
        except Exception:
            pass

    for ju in js_urls[:15]:
        try:
            rj = session.get(ju, timeout=5, verify=False)
            if rj.status_code == 200:
                for p in pkg_re.findall(rj.text[:300000]):
                    scope_prefix = p.split("/")[0]
                    if scope_prefix not in PUBLIC_SAFE_SCOPES:
                        scoped_pkgs.add(p)
        except Exception:
            pass

    unclaimed = 0
    for pkg in sorted(scoped_pkgs)[:12]:
        scope_prefix = pkg.split("/")[0]
        if scope_prefix in PUBLIC_SAFE_SCOPES:
            continue
        try:
            r_npm = session.get(f"https://registry.npmjs.org/{pkg}", timeout=5)
            if r_npm.status_code == 404:
                unclaimed += 1
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (Dep-Confusion)",
                    f"[CONFIRMED] Unclaimed Private NPM Package ({pkg}) — Dependency Confusion",
                    "Supply-Chain / Dependency Confusion", "Critical", 9.8,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-427", "A08:2021 - Software and Data Integrity Failures",
                    base_url, f"Package '{pkg}' referenced in client bundle returned HTTP 404 on https://registry.npmjs.org/{pkg}",
                    "Loyiha ichida ishlatilgan xususiy (private) NPM paketi ommaviy NPM reestrida band qilinmagan (Dependency Confusion xavfi).",
                    "Ichki paket scope nomini (@org) npmjs.com da rasman band qiling va .npmrc faylida scoped registryni qat'iy belgilang.",
                )
                log_fn(f"  [📦 DEPENDENCY CONFUSION] Ommaviy reestrda bo'sh qolgan paket topildi: {pkg}!")
        except Exception:
            pass
    return unclaimed


# ══════════════════════════════════════════════════════════════════════════════
# 9. JWT (eyJ...) PASSIVE HARVESTER, CLAIMS DECODER & WEAK-HMAC AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_JWT_SECRETS = (
    "secret", "123456", "password", "jwt_secret", "changeme", "admin", "default",
    "supersecret", "mysecret", "key", "private", "dev", "development", "production",
    "laravel", "django-insecure", "uzbekistan", "tashkent", "12345678", "qwerty",
)


def _b64url_decode(segment: str) -> bytes:
    rem = len(segment) % 4
    if rem:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def harvest_and_audit_jwt_tokens(db, session, project_id: int, apex_domain: str, base_url: str, js_urls: list[str], log_fn) -> int:
    """
    Passively harvests JWT tokens from Set-Cookie headers, HTML, and JS bundles;
    decodes header/payload claims and audits for alg:none, missing exp, or default HMAC secrets.
    """
    jwt_re = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)\b")
    found_tokens: set[str] = set()

    try:
        r = session.get(base_url, timeout=6, verify=False)
        for hdr_v in r.headers.values():
            for m in jwt_re.findall(hdr_v):
                found_tokens.add(m)
        for m in jwt_re.findall(r.text[:250000]):
            found_tokens.add(m)
    except Exception:
        pass

    for ju in js_urls[:10]:
        try:
            rj = session.get(ju, timeout=5, verify=False)
            if rj.status_code == 200:
                for m in jwt_re.findall(rj.text[:250000]):
                    found_tokens.add(m)
        except Exception:
            pass

    brand = apex_domain.split(".")[0].lower()
    candidate_secrets = list(DEFAULT_JWT_SECRETS) + [
        apex_domain, brand, f"{brand}123", f"{brand}_secret", f"{brand}_jwt",
        f"{brand}2024", f"{brand}2025", f"{brand}2026", "jwt", "token", "auth",
        "access_token", "refresh_token", "spring", "nodejs", "express", "fastapi",
    ]

    audited = 0
    for tok in list(found_tokens)[:8]:
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        try:
            hdr = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="ignore"))
            payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="ignore"))
            if not isinstance(hdr, dict) or not isinstance(payload, dict):
                continue
            alg = str(hdr.get("alg", "none"))
            sig_bytes = _b64url_decode(parts[2]) if parts[2] else b""
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

            matched_secret = ""
            if alg.upper() in ("HS256", "HS384", "HS512") and sig_bytes:
                hash_mod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg.upper()]
                for cand in candidate_secrets:
                    if hmac.compare_digest(hmac.new(cand.encode(), signing_input, hash_mod).digest(), sig_bytes):
                        matched_secret = cand
                        break

            audited += 1
            claims_keys = ", ".join(list(payload.keys())[:10])
            has_exp = "exp" in payload
            risky_hdrs = [h for h in ("jku", "x5u", "jwk", "kid") if h in hdr]

            if matched_secret or alg.lower() == "none":
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (JWT-Auditor)",
                    f"[CONFIRMED] Critical JWT Cryptographic Weakness (alg={alg}" + (f", key='{matched_secret}')" if matched_secret else ")"),
                    "Cryptographic Failures", "Critical", 9.8,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-347", "A02:2021 - Cryptographic Failures",
                    base_url, f"Header: {json.dumps(hdr)} | Claims: [{claims_keys}] | Verified Secret: {matched_secret or 'alg:none'}",
                    "Topilgan JWT token kuchsiz standart kalit (default HMAC secret) yoki 'alg:none' bilan imzolangan — har qanday foydalanuvchi nomidan token yasash (Account Takeover) mumkin.",
                    "JWT imzolash uchun kamida 256-bitli kriptografik tasodifiy kalit yoki RS256/EdDSA asimmetrik kalitlardan foydalaning.",
                )
                log_fn(f"  [🔐 JWT CRACKED] {base_url} -> JWT kaliti aniqlandi: '{matched_secret or 'alg:none'}'!")
            else:
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (JWT-Auditor)",
                    f"Discovered JWT Token Structure (alg={alg}, exp={'Yes' if has_exp else 'MISSING'})" + (f" [Headers: {','.join(risky_hdrs)}]" if risky_hdrs else ""),
                    "Authentication Intelligence", "Medium" if (not has_exp or risky_hdrs) else "Info", 5.3 if (not has_exp or risky_hdrs) else 0.0,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-613", "A07:2021 - Identification and Authentication Failures",
                    base_url, f"Header: {json.dumps(hdr)} | Payload Keys: [{claims_keys}]",
                    "Sayt/JS ichida JWT token topildi va dekod qilindi." + (" Tokenda 'exp' (muddati tugash) maydoni yo'q!" if not has_exp else "") + (f" Динамик kalit sarlavhalari mavjud: {risky_hdrs}" if risky_hdrs else ""),
                    "JWT tokenlarda qisqa yashash muddati ('exp') belgilang va jku/x5u/kid sarlavhalarini qat'iy oq ro'yxatdan o'tkazing.",
                )
        except Exception:
            pass
    return audited


# ══════════════════════════════════════════════════════════════════════════════
# 10. SECOND-ORDER <SCRIPT SRC> NXDOMAIN TAKEOVER & BROKEN LINK HIJACKING
# ══════════════════════════════════════════════════════════════════════════════

def hunt_broken_external_links_and_script_hijack(db, session, project_id: int, base_url: str, log_fn) -> int:
    """
    Audits external <script src="https://..."> domains for NXDOMAIN (Second-Order Script Takeover)
    and external GitHub / Telegram links for unclaimed handles (Broken Link Hijacking).
    """
    ext_script_hosts: dict[str, str] = {}
    gh_links: set[str] = set()
    tg_handles: set[str] = set()

    try:
        r = session.get(base_url, timeout=6, verify=False)
        if r.status_code != 200:
            return 0
        soup = BeautifulSoup(r.text, "html.parser")
        base_host = (urllib.parse.urlparse(base_url).hostname or "").lower()

        for sc in soup.find_all("script", src=True):
            full_s = urllib.parse.urljoin(base_url, sc["src"])
            shost = (urllib.parse.urlparse(full_s).hostname or "").lower()
            if shost and shost != base_host and "." in shost:
                ext_script_hosts[shost] = full_s

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            m_gh = re.match(r"https?://(?:www\.)?github\.com/([a-zA-Z0-9\-_]+)(?:/([a-zA-Z0-9\-_\.]+))?", href)
            if m_gh and m_gh.group(1).lower() not in ("features", "pricing", "login", "join", "about", "security", "orgs"):
                gh_links.add(f"https://github.com/{m_gh.group(1)}")
            m_tg = re.match(r"https?://(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})", href)
            if m_tg and m_tg.group(1).lower() not in ("share", "joinchat", "addstickers", "iv", "proxy"):
                tg_handles.add(m_tg.group(1))
    except Exception:
        return 0

    issues = 0
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    # 1. Check external <script src> domains for NXDOMAIN
    for shost, s_url in list(ext_script_hosts.items())[:15]:
        try:
            resolver.resolve(shost, "A")
        except dns.resolver.NXDOMAIN:
            issues += 1
            db.upsert_finding(
                project_id, "SPECTRE-Predator (Script-Hijack)",
                f"[CONFIRMED] Second-Order Script Domain Takeover — NXDOMAIN ({shost})",
                "Second-Order Domain Takeover / Stored XSS", "Critical", 9.6,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", "CWE-829",
                "A08:2021 - Software and Data Integrity Failures",
                base_url, f"External script <script src='{s_url}'> points to unregistered/expired domain '{shost}' (DNS NXDOMAIN)",
                "Sahifaga ulangan tashqi JavaScript faylining domeni muddati tugagan (NXDOMAIN) — ushbu domenni sotib olib, butun saytda Stored XSS bajarish mumkin.",
                "Eskirgan tashqi <script> teglarini darhol olib tashlang va Subresource Integrity (SRI) xeshlaridan foydalaning.",
            )
            log_fn(f"  [🚨 SECOND-ORDER TAKEOVER] <script src='{s_url}'> domeni NXDOMAIN qaytaruvda ({shost})!")
        except Exception:
            pass

    # 2. Check GitHub org/user links for 404
    for gh_u in list(gh_links)[:6]:
        try:
            rg = session.get(gh_u, timeout=4.5)
            if rg.status_code == 404:
                issues += 1
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (Broken-Link)",
                    f"[CONFIRMED] Unclaimed GitHub Organization/Account Link ({gh_u})",
                    "Broken Link Hijacking", "High", 7.1,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", "CWE-350", "A05:2021 - Security Misconfiguration",
                    base_url, f"Link on page points to HTTP 404 GitHub profile: {gh_u}",
                    "Rasmiy saytda ko'rsatilgan GitHub havolasi bo'sh (404) — uni begona shaxs ro'yxatdan o'tkazib, kompaniya nomidan zararli kod tarqatishi mumkin.",
                    "Saytdagi eskirgan GitHub havolasini yangilang yoki tegishli username'ni band qiling.",
                )
                log_fn(f"  [🕸️ BROKEN GITHUB LINK] {gh_u} bo'sh (HTTP 404)!")
        except Exception:
            pass

    # 3. Check Telegram t.me/<handle> links for unclaimed usernames
    for tg_h in list(tg_handles)[:6]:
        try:
            rt = session.get(f"https://t.me/{tg_h}", timeout=4.5)
            if rt.status_code == 200 and "tgme_page_extra" not in rt.text and "tgme_page_title" not in rt.text:
                issues += 1
                db.upsert_finding(
                    project_id, "SPECTRE-Predator (Broken-Link)",
                    f"[CONFIRMED] Unclaimed Telegram Handle Linked on Site (@{tg_h})",
                    "Broken Link / Social Hijacking", "Medium", 6.5,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", "CWE-350", "A05:2021 - Security Misconfiguration",
                    base_url, f"Telegram link https://t.me/{tg_h} has no active profile/channel (unclaimed username)",
                    "Saytda ko'rsatilgan rasmiy Telegram havolasi (@username) bo'sh qolgan — uni begona shaxs band qilib fishing uchun ishlatishi mumkin.",
                    "Saytdagi Telegram havolasini yangilang yoki @username ni darhol band qiling.",
                )
                log_fn(f"  [🕸️ UNCLAIMED TELEGRAM] https://t.me/{tg_h} bo'sh qolgan!")
        except Exception:
            pass

    return issues


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ORCHESTRATOR FOR ALL 10 PREDATOR MODULES
# ══════════════════════════════════════════════════════════════════════════════

def run_predator_recon_suite(agent, project_id: int, apex_domain: str, base_url: str, js_urls: list[str], log_fn) -> None:
    """
    Executes all 10 Predator v9.0 Recon & Dark Attack Surface Intelligence modules on a live target.
    """
    log_fn(f"  [🦁 PREDATOR v9.0] {base_url} ustida 10 ta chuqur Dark-Attack-Surface moduli ishga tushirildi...")
    db = agent.db
    session = agent.session

    fingerprint_favicon_hash_and_tech(db, session, project_id, base_url, log_fn)
    unpack_js_sourcemaps(db, session, project_id, js_urls, base_url, log_fn)
    audit_reverse_proxy_acl_misconfigs(db, session, project_id, base_url, log_fn)
    mine_hidden_query_parameters(db, session, project_id, base_url, log_fn)
    audit_websocket_endpoints_and_cswsh(db, session, project_id, base_url, log_fn)
    enumerate_multicloud_and_containers(db, session, project_id, apex_domain, base_url, log_fn)
    introspect_graphql_field_suggestions(db, session, project_id, base_url, log_fn)
    hunt_dependency_confusion_risks(db, session, project_id, js_urls, base_url, log_fn)
    harvest_and_audit_jwt_tokens(db, session, project_id, apex_domain, base_url, js_urls, log_fn)
    hunt_broken_external_links_and_script_hijack(db, session, project_id, base_url, log_fn)
    db.log_task(project_id, "SPECTRE-Predator", "predator_v9_suite", "COMPLETED", f"predator_suite {base_url}", f"Executed 10 Predator modules on {base_url} ({len(js_urls)} JS bundles)")




