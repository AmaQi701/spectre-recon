import concurrent.futures
import difflib
import io
import json
import re
import socket
import ssl
import urllib.parse
import zipfile
import zlib
import dns.resolver
import dns.reversename
import requests


# ================= #1 CLOUDFLARE / WAF ORIGIN IP UNMASKER (TRUE TLS SNI + HOST INJECTION) =================
def _raw_sni_https_get(ip_addr: str, host_name: str, path: str = "/", timeout: float = 4.0) -> tuple[int, bytes, list[str]]:
    sans = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip_addr, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host_name) as ssock:
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host_name}\r\n"
                    f"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64)\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8")
                ssock.sendall(req)
                chunks = []
                total = 0
                while total < 65536:
                    data = ssock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                raw_resp = b"".join(chunks)
                if b"\r\n\r\n" in raw_resp:
                    hdr_b, body_b = raw_resp.split(b"\r\n\r\n", 1)
                    first_line = hdr_b.splitlines()[0].decode("latin-1", errors="ignore")
                    parts = first_line.split()
                    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    return code, body_b, sans
    except Exception:
        pass
    return 0, b"", sans


def unmask_cloudflare_origin_ips(db, session: requests.Session, project_id: int, apex_domain: str, primary_host: str, log_fn):
    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    if not domains:
        return

    log_fn(f"[SPECTRE Ultra #1 -> Origin IP Unmasker] {primary_host} uchun True TLS SNI + Host Injection orqali Origin IP tekshirilmoqda...")

    base_title = ""
    base_body = ""
    base_len = 0
    for scheme in ("https", "http"):
        try:
            r = session.get(f"{scheme}://{primary_host}", timeout=6, verify=False)
            if r.status_code < 500 and len(r.content) > 100:
                base_len = len(r.content)
                txt_dec = r.content.decode("utf-8", errors="ignore")
                m_t = re.search(r"<title[^>]*>(.*?)</title>", txt_dec, re.I | re.S)
                base_title = m_t.group(1).strip() if m_t else ""
                base_body = re.sub(r"\s+", " ", txt_dec[:25000])
                break
        except Exception:
            pass

    candidate_ips = set()
    cdn_keywords = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "ddos-guard", "sucuri")
    for d in domains:
        ip = d.get("ip", "")
        cdn = str(d.get("cdn_waf", "")).lower()
        if ip and not any(k in cdn for k in cdn_keywords):
            candidate_ips.add(ip)
        recs = json.loads(d.get("records_json") or "{}")
        for txt_val in recs.get("TXT", []):
            for m_ip in re.findall(r"ip4:(\d+\.\d+\.\d+\.\d+)", str(txt_val)):
                candidate_ips.add(m_ip)

    if not candidate_ips:
        return

    def check_candidate_ip(ip_addr: str):
        code, body_b, _ = _raw_sni_https_get(ip_addr, primary_host, "/")
        scheme_used = "https"
        if code not in (200, 301, 302) or len(body_b) < 200:
            try:
                r = session.get(
                    f"http://{ip_addr}/",
                    headers={"Host": primary_host, "User-Agent": "Mozilla/5.0"},
                    timeout=4.0,
                    allow_redirects=False,
                )
                code = r.status_code
                body_b = r.content
                scheme_used = "http"
            except Exception:
                return

        txt_dec = body_b.decode("utf-8", errors="ignore")
        body_clean = re.sub(r"\s+", " ", txt_dec[:25000])
        m_t = re.search(r"<title[^>]*>(.*?)</title>", txt_dec, re.I | re.S)
        cand_title = m_t.group(1).strip() if m_t else ""
        sim_ratio = difflib.SequenceMatcher(None, base_body[:8000], body_clean[:8000]).ratio() if base_body else 0.0
        title_match = bool(base_title and len(base_title) >= 4 and cand_title == base_title)
        len_match = bool(base_len > 500 and code == 200 and abs(len(body_b) - base_len) / float(base_len) < 0.20)

        if title_match or sim_ratio >= 0.65 or len_match:
            reasons = []
            if title_match:
                reasons.append(f"Exact Title Match ('{cand_title[:40]}')")
            if sim_ratio >= 0.65:
                reasons.append(f"HTML Similarity {int(sim_ratio * 100)}%")
            if len_match:
                reasons.append(f"Content-Length Match ({len(body_b)}B)")
            log_fn(f"  [🎯 ORIGIN IP UNMASKED] {ip_addr} -> {primary_host} ({', '.join(reasons)})")
            db.upsert_finding(
                project_id, "SPECTRE-Agent1 (Origin Unmasker)", f"Direct Origin Server IP Confirmed: {ip_addr} ({primary_host})",
                "Origin IP Exposure / WAF Bypass Vector", "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-200", "A05:2021 - Security Misconfiguration", f"{scheme_used}://{ip_addr} (Host: {primary_host})",
                f"Origin Proof: {', '.join(reasons)} | HTTP {code} ({len(body_b)}B)\nPoC: curl -k -i --resolve {primary_host}:443:{ip_addr} https://{primary_host}/",
                f"Asosiy domen ({primary_host}) ga xizmat ko'rsatuvchi to'g'ridan-to'g'ri Origin server IP manzili ({ip_addr}) tasdiqlandi.",
                "Serverda faqat ruxsat etilgan WAF/Proxy IP manzillaridan keluvchi trafikni qabul qilishni sozlang.",
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(check_candidate_ip, sorted(candidate_ips)[:25]))


# ================= #2 FULL /24 SUBNET NEIGHBOR PTR & INFRASTRUCTURE SWEEPER =================
def sweep_subnet_neighbors_and_ptr(db, project_id: int, apex_domain: str, scope, log_fn):
    bundle = db.get_project_bundle(project_id)
    domains = bundle.get("domains", [])
    non_cdn_ips = [
        d.get("ip")
        for d in domains
        if d.get("ip") and "cloudflare" not in str(d.get("cdn_waf", "")).lower()
    ]
    if not non_cdn_ips:
        return

    neighbor_set = set()
    for ip in sorted(set(non_cdn_ips))[:5]:
        parts = ip.split(".")
        if len(parts) == 4 and parts[3].isdigit():
            pref = ".".join(parts[:3])
            oct_val = int(parts[3])
            for d_oct in list(range(max(1, oct_val - 20), min(255, oct_val + 21))) + [1, 2, 5, 10, 50, 100, 150, 156, 200, 250, 253, 254]:
                neighbor_set.add(f"{pref}.{d_oct}")
    neighbor_candidates = sorted(neighbor_set)
    if not neighbor_candidates:
        return

    log_fn(f"[SPECTRE Ultra #2 -> /24 Subnet PTR Sweeper] {len(neighbor_candidates)} ta qo'shni IP manzilda Reverse-DNS (PTR) tekshirilmoqda...")
    ptr_map = {}

    def check_neighbor(n_ip: str):
        try:
            rev_name = dns.reversename.from_address(n_ip)
            ans = dns.resolver.resolve(rev_name, "PTR", lifetime=1.0)
            for rdata in ans:
                ptr_host = rdata.to_text().rstrip(".").lower()
                if ptr_host:
                    ptr_map[n_ip] = ptr_host
                    if ptr_host.endswith(apex_domain) or scope.is_in_scope(ptr_host)[0]:
                        db.upsert_domain(project_id, ptr_host, ip=n_ip, source="subnet_ptr_sweep")
                        log_fn(f"  [🌐 /24 In-Scope PTR Hit] {n_ip} -> {ptr_host}")
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        list(ex.map(check_neighbor, neighbor_candidates))

    if ptr_map:
        sample_ptrs = [f"{k} -> {v}" for k, v in sorted(ptr_map.items())[:12]]
        log_fn(f"  [🗺️ /24 Neighborhood Map] Jami {len(ptr_map)} ta qo'shni server PTR yozuvi aniqlandi: {', '.join(sample_ptrs[:6])}")
        db.upsert_finding(
            project_id, "SPECTRE-Agent1 (/24 Subnet PTR Mapper)", f"Datacenter /24 Subnet Neighborhood Map ({len(ptr_map)} Active PTR Hosts)",
            "Network Infrastructure Intelligence", "Info", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "CWE-200", "A05:2021 - Security Misconfiguration", ", ".join(sorted({".".join(i.split(".")[:3]) + ".0/24" for i in non_cdn_ips[:3]})),
            "Discovered /24 PTR Neighbors:\n" + "\n".join(sample_ptrs),
            "Nishon server joylashgan /24 subnetdagi qo'shni serverlar va PTR yozuvlari xaritasi tuzildi.",
            "Maxfiy ichki subdomen nomlarini oshkor qilmaslik uchun PTR (Reverse-DNS) yozuvlarini neytral nomda saqlang.",
        )


# ================= #3 NEXT.JS / NUXT / VITE / WEBPACK MANIFEST & SSR DECONSTRUCTOR =================
def deconstruct_spa_manifests_and_ssr_state(db, session: requests.Session, project_id: int, scope, log_fn, record_url_fn=None):
    bundle = db.get_project_bundle(project_id)
    services = bundle.get("http_services", [])
    if not services:
        return

    log_fn(f"[SPECTRE Ultra #3 -> SPA Manifest & SSR State Deconstructor] Next.js/Nuxt/Vite manifestlari va SSR JSON obyektlari tekshirilmoqda...")

    manifest_paths = [
        "/asset-manifest.json",
        "/manifest.json",
        "/build-manifest.json",
        "/.vite/manifest.json",
        "/mix-manifest.json",
    ]

    for svc in services[:8]:
        base_url = svc["url"]
        try:
            r = session.get(base_url, timeout=6, verify=False)
            html = r.text[:120000]

            # 1. Next.js __NEXT_DATA__ SSR extraction
            m_next = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html, re.I | re.S)
            if m_next:
                try:
                    nd = json.loads(m_next.group(1).strip())
                    build_id = nd.get("buildId", "")
                    runtime_cfg = nd.get("runtimeConfig") or nd.get("publicRuntimeConfig") or {}
                    log_fn(f"  [⚡ Next.js SSR] {base_url} -> buildId={build_id} | runtimeConfig keys={list(runtime_cfg.keys())}")
                    if build_id:
                        bm_url = urllib.parse.urljoin(base_url, f"/_next/static/{build_id}/_buildManifest.js")
                        rbm = session.get(bm_url, timeout=5, verify=False)
                        if rbm.status_code == 200:
                            routes = re.findall(r'["\'](/[a-zA-Z0-9_\-\[\]/\.]+)["\']', rbm.text)
                            for rt in set(routes):
                                if not rt.endswith(".js") and not rt.endswith(".css") and record_url_fn:
                                    record_url_fn(project_id, rt, base_url, scope, "nextjs_build_manifest")
                            log_fn(f"  [🗺️ Next.js _buildManifest] {len(set(routes))} ta yashirin frontend route ajratib olindi!")
                except Exception:
                    pass

            # 2. CMS & SPA Global State Variables (DLE, WordPress, Laravel, Nuxt, Custom Config)
            cms_vars = []
            for var_rgx, v_label in [
                (r"var\s+dle_(?:root|admin|login_hash|group|skin)\s*=\s*['\"]([^'\"]*)['\"]", "DLE State"),
                (r"window\.__NUXT__\s*=\s*(\{[^\n;]{5,180})", "Nuxt SSR State"),
                (r"wpApiSettings\s*=\s*(\{[^\n;]{5,180})", "WordPress REST API Config"),
                (r"window\.(?:__INITIAL_STATE__|__APP_CONFIG__|ENV)\s*=\s*(\{[^\n;]{5,180})", "SPA Global Config"),
            ]:
                for m_v in re.finditer(var_rgx, html):
                    cms_vars.append(f"{v_label}: {m_v.group(0)[:90]}")
            if cms_vars:
                log_fn(f"  [🧩 Frontend/CMS State] {base_url} -> {' | '.join(cms_vars[:4])}")
                if any("dle_" in x for x in cms_vars) and record_url_fn:
                    for dle_ep in ("/engine/ajax/controller.php", "/engine/ajax/search.php", "/index.php?do=register", "/index.php?do=lostpassword", "/admin.php"):
                        record_url_fn(project_id, dle_ep, base_url, scope, "dle_cms_deconstructor")

            # 3. Manifest JSON files
            for mp in manifest_paths:
                m_url = urllib.parse.urljoin(base_url, mp)
                try:
                    rm = session.get(m_url, timeout=4, verify=False)
                    if rm.status_code == 200 and rm.text.strip().startswith("{"):
                        for path_hit in re.findall(r'["\']((?:/|static/|assets/)[a-zA-Z0-9_\-\./]+\.js)["\']', rm.text)[:30]:
                            if record_url_fn:
                                record_url_fn(project_id, "/" + path_hit.lstrip("/"), base_url, scope, "spa_manifest_json")
                except Exception:
                    pass
        except Exception:
            pass


# ================= #4 SECRETHUNTER V2 (TELEGRAM BOT, PAYME/CLICK/UZUM, FIREBASE, AWS, WSS) =================
def hunt_deep_secrets_and_uz_ecosystem(db, session: requests.Session, project_id: int, log_fn):
    bundle = db.get_project_bundle(project_id)
    js_assets = bundle.get("js_assets", [])
    services = bundle.get("http_services", [])
    if not js_assets and not services:
        return

    log_fn("[SPECTRE Ultra #4 -> SecretHunter v2] Telegram Bot, Payme/Click/Uzum, AWS, Firebase va WSS sirlari tekshirilmoqda...")

    patterns = [
        ("Telegram Bot Token", "Critical", 9.1, r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b"),
        ("AWS Access Key ID", "High", 8.2, r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        ("Google Cloud / Firebase API Key", "Medium", 6.5, r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        ("Stripe Live Secret/Publishable Key", "High", 7.5, r"\b((?:sk|pk|rk)_live_[0-9a-zA-Z]{24,99})\b"),
        ("GitHub Personal Access Token", "Critical", 9.0, r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        ("Slack Webhook / Bot Token", "High", 7.5, r"\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b"),
        ("Sentry DSN Endpoint", "Low", 3.7, r"(https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+)"),
        ("Uzbekistan Fintech / Payment Merchant Key (Payme/Click/Uzum)", "Medium", 5.8, r"(?i)((?:payme|paycom|click_?merchant|click_?service_?id|uzum_?merchant)[a-z0-9_]*\s*[:=]\s*['\"][a-zA-Z0-9_\-]{6,64}['\"])"),
    ]

    targets_to_scan = [j["js_url"] for j in js_assets[:25]] + [s["url"] for s in services[:8]]
    seen_hits = set()

    for t_url in targets_to_scan:
        try:
            r = session.get(t_url, timeout=6, verify=False)
            if r.status_code != 200:
                continue
            body = r.text[:350000]
            for label, sev, cvss, rgx in patterns:
                for m in re.findall(rgx, body)[:4]:
                    val = m if isinstance(m, str) else m[0]
                    hit_key = f"{label}:{val}"
                    if hit_key in seen_hits:
                        continue
                    seen_hits.add(hit_key)

                    extra_note = ""
                    if label == "Telegram Bot Token":
                        try:
                            rtg = session.get(f"https://api.telegram.org/bot{val}/getMe", timeout=4)
                            if rtg.status_code == 200 and rtg.json().get("ok"):
                                bot_u = rtg.json().get("result", {}).get("username", "")
                                extra_note = f" [ACTIVE TELEGRAM BOT CONFIRMED: @{bot_u}]"
                        except Exception:
                            pass

                    log_fn(f"  [🚨 SECRET V2] {label}: {val[:45]}... ({t_url}){extra_note}")
                    db.upsert_finding(
                        project_id,
                        "SPECTRE-Agent1 (SecretHunter v2)",
                        f"Exposed {label} in {t_url.split('/')[-1] or t_url}{extra_note}",
                        "Hardcoded Secret / Credential Exposure",
                        sev,
                        cvss,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        "CWE-798",
                        "A07:2021 - Identification and Authentication Failures",
                        t_url,
                        f"Matched {label}: {val}{extra_note}",
                        f"Ochiq JS/HTML ichida {label} topildi.",
                        "Maxfiy kalit va tokenlarni darhol revoke qiling hamda backend .env orqali ishlating.",
                    )
        except Exception:
            pass


# ================= #5 MOBILE APP & .WELL-KNOWN DEEP-LINK MINER =================
def mine_well_known_and_mobile_links(db, session: requests.Session, project_id: int, scope, log_fn, record_url_fn=None):
    bundle = db.get_project_bundle(project_id)
    services = bundle.get("http_services", [])
    if not services:
        return

    log_fn("[SPECTRE Ultra #5 -> Mobile App & .well-known Miner] Android/iOS Deep-Link va OAuth2 OpenID konfiguratsiyalari tekshirilmoqda...")

    wk_paths = [
        ("/.well-known/assetlinks.json", "Android Digital Asset Links"),
        ("/.well-known/apple-app-site-association", "iOS Universal App Links"),
        ("/apple-app-site-association", "iOS Universal App Links (Root)"),
        ("/.well-known/openid-configuration", "OAuth2 / OIDC Discovery Configuration"),
        ("/.well-known/oauth-authorization-server", "OAuth2 Authorization Server Metadata"),
    ]

    for svc in services[:8]:
        base_url = svc["url"]
        for path, label in wk_paths:
            full_u = urllib.parse.urljoin(base_url, path)
            try:
                r = session.get(full_u, timeout=4.5, verify=False)
                if r.status_code == 200 and r.text.strip().startswith(("{", "[")):
                    data = r.json()
                    summary = ""
                    if "assetlinks" in path and isinstance(data, list):
                        pkgs = [item.get("target", {}).get("package_name", "") for item in data if isinstance(item, dict)]
                        pkgs = [p for p in pkgs if p]
                        if pkgs:
                            summary = f"Android APK Package(s): {', '.join(pkgs)}"
                    elif "apple-app-site" in path and isinstance(data, dict):
                        applinks = data.get("applinks", {}).get("details", [])
                        if isinstance(applinks, list) and applinks:
                            summary = f"iOS App Details: {json.dumps(applinks)[:220]}"
                    elif "openid" in path or "oauth" in path:
                        eps = [data.get(k, "") for k in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri") if data.get(k)]
                        for ep in eps:
                            if record_url_fn:
                                record_url_fn(project_id, ep, base_url, scope, "oidc_discovery")
                        summary = f"OIDC Endpoints: {', '.join(eps[:4])}"

                    if summary:
                        log_fn(f"  [📱 {label}] {full_u} -> {summary[:140]}")
                        db.upsert_finding(
                            project_id, "SPECTRE-Agent1 (Mobile/OIDC Miner)", f"{label} Discovered ({full_u})",
                            "Mobile & SSO Architecture Intelligence", "Info", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "CWE-200", "A05:2021 - Security Misconfiguration", full_u,
                            summary, f"{label} orqali nishonning mobil ilova paketlari yoki SSO endpointlari aniqlandi.",
                            "Mobil deep-link va OIDC endpointlarida redirect_uri validatsiyasini tekshiring.",
                        )
            except Exception:
                pass


# ================= #6 HTTP REDIRECT-CHAIN & SSO/OAUTH PARAMETER TRACKER =================
def trace_redirect_chains_and_oauth_flows(db, session: requests.Session, project_id: int, scope, log_fn, record_url_fn=None):
    bundle = db.get_project_bundle(project_id)
    services = bundle.get("http_services", [])
    if not services:
        return

    log_fn("[SPECTRE Ultra #6 -> Redirect-Chain & SSO Tracker] 301/302 redirect zanjirlari va SSO/OAuth redirect_uri parametrlari kuzatilmoqda...")
    probe_routes = ["/", "/admin", "/login", "/dashboard", "/cabinet", "/auth", "/sso", "/profile"]

    for svc in services[:6]:
        base_url = svc["url"]
        for rt in probe_routes:
            cur_url = urllib.parse.urljoin(base_url, rt)
            hops = []
            try:
                for _ in range(4):
                    r = session.get(cur_url, timeout=4.0, verify=False, allow_redirects=False)
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                        nxt = urllib.parse.urljoin(cur_url, r.headers["Location"])
                        hops.append(f"{r.status_code}:{nxt}")
                        if any(p in nxt.lower() for p in ("redirect_uri=", "returnurl=", "return_to=", "next=", "client_id=", "continue=")):
                            log_fn(f"  [🔄 OAuth/Redirect Flow] {' -> '.join(hops)}")
                            if record_url_fn:
                                record_url_fn(project_id, nxt, base_url, scope, "redirect_chain_tracker")
                        cur_url = nxt
                    else:
                        break
            except Exception:
                pass


# ================= #7 DOCUMENT METADATA (PDF / DOCX / XLSX) OSINT EXTRACTOR =================
def extract_document_metadata_osint(db, session: requests.Session, project_id: int, apex_domain: str, log_fn):
    bundle = db.get_project_bundle(project_id)
    doc_urls = [
        e["url"]
        for e in bundle.get("endpoints", [])
        if any(e["url"].lower().split("?")[0].endswith(ext) for ext in (".pdf", ".docx", ".xlsx", ".pptx"))
    ]
    if not doc_urls:
        return

    log_fn(f"[SPECTRE Ultra #7 -> Document Metadata OSINT] {len(doc_urls[:8])} ta PDF/DOCX/XLSX hujjat ichidan muallif va dastur metadatasi o'qilmoqda...")
    for d_url in doc_urls[:8]:
        try:
            r = session.get(d_url, timeout=6, verify=False, stream=True)
            raw = r.raw.read(262144, decode_content=True)
            r.close()
            meta_hits = []
            if raw.startswith(b"%PDF"):
                for k in ("Author", "Creator", "Producer", "Title"):
                    m = re.search(rb"/" + k.encode() + rb"\s*\(([^)]{2,80})\)", raw)
                    if m:
                        val = m.group(1).decode("utf-8", errors="ignore").strip()
                        if val:
                            meta_hits.append(f"{k}: {val}")
            elif raw.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    if "docProps/core.xml" in zf.namelist():
                        xml_txt = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                        for tag in ("dc:creator", "cp:lastModifiedBy"):
                            m = re.search(f"<{tag}>([^<]+)</{tag}>", xml_txt)
                            if m:
                                meta_hits.append(f"{tag}: {m.group(1)}")
            if meta_hits:
                log_fn(f"  [📄 Document Metadata] {d_url} -> {' | '.join(meta_hits)}")
                db.upsert_finding(
                    project_id, "SPECTRE-Agent1 (Doc Metadata OSINT)", f"Document Metadata & Author Leak ({d_url.split('/')[-1]})",
                    "OSINT & Metadata Exposure", "Info", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", d_url,
                    " | ".join(meta_hits), "Ochiq hujjat metadatasi orqali ichki foydalanuvchi nomi va dastur versiyasi aniqlandi.",
                    "Hujjatlarni ommaga e'lon qilishdan oldin Exif/Metadata ma'lumotlarini tozalang.",
                )
        except Exception:
            pass




