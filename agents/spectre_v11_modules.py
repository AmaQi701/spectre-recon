"""
SPECTRE v11.0 — Apex Enterprise Intelligence & Schema Synthesis Modules
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.parse
from typing import Any

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════════
# 1. KEYCLOAK / OIDC IAM REALM & DISCOVERY MAPPER
# ══════════════════════════════════════════════════════════════════════════════

def map_iam_and_keycloak_realms(db, session, project_id: int, base_url: str, log_fn) -> int:
    bundle = db.get_project_bundle(project_id)
    realm_candidates: set[tuple[str, str]] = set()
    realm_re = re.compile(r"(https?://[^/]+(?:/auth)?/realms/([a-zA-Z0-9_\-]+))")

    for ep in bundle.get("endpoints", []):
        m = realm_re.search(ep.get("url", ""))
        if m:
            realm_candidates.add((m.group(1), m.group(2)))
    for f in bundle.get("findings", []):
        for txt in (f.get("asset", ""), f.get("evidence", "")):
            m = realm_re.search(str(txt))
            if m:
                realm_candidates.add((m.group(1), m.group(2)))

    for r_name in ("master", "smart-realm", "main", "public"):
        if any(k in base_url for k in ("id.", "sso.", "auth.", "keycloak.")):
            realm_candidates.add((urllib.parse.urljoin(base_url, f"/realms/{r_name}"), r_name))

    mapped = 0
    for realm_url, realm_name in sorted(realm_candidates)[:6]:
        oidc_url = f"{realm_url.rstrip('/')}/.well-known/openid-configuration"
        try:
            r = session.get(oidc_url, timeout=5, verify=False)
            if r.status_code == 200 and '"issuer"' in r.text:
                data = r.json()
                grants = data.get("grant_types_supported", [])
                for k in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "end_session_endpoint", "jwks_uri", "registration_endpoint"):
                    if data.get(k):
                        db.upsert_endpoint(project_id, str(data[k]), method="POST" if "token" in k else "GET", params=[], category="api_endpoint", risk_tags=["oidc_iam"], source="keycloak_mapper")
                mapped += 1
                has_reg = "registration_endpoint" in data
                has_direct_grant = "password" in grants
                db.upsert_finding(
                    project_id, "SPECTRE-v11 (IAM-Mapper)",
                    f"Keycloak / OIDC Realm Intelligence Mapped ({realm_name})",
                    "IAM & SSO Architecture", "Medium" if (has_reg or has_direct_grant) else "Info",
                    5.3 if (has_reg or has_direct_grant) else 0.0,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A07:2021 - Identification and Authentication Failures",
                    oidc_url,
                    f"Realm: {realm_name} | Grants: {', '.join(grants[:6])} | Registration Endpoint: {'Yes' if has_reg else 'No'}",
                    "Keycloak/OIDC realm konfiguratsiyasi, token endpointlari va ruxsat etilgan grant turlari xaritasi tuzildi.",
                    "Production realm'larda 'Direct Access Grants (password)' va ochiq ro'yxatdan o'tishni faqat zarur bo'lgandagina yoqing.",
                )
                log_fn(f"  [🔐 IAM MAPPER] Realm '{realm_name}' ({oidc_url}) -> Grants: {', '.join(grants[:5])}")
        except Exception:
            pass
    return mapped


# ══════════════════════════════════════════════════════════════════════════════
# 2. OPENAPI / SWAGGER $REF SCHEMA PARAMETER & BODY SYNTHESIZER
# ══════════════════════════════════════════════════════════════════════════════

def resolve_openapi_schema_refs(db, session, project_id: int, base_url: str, log_fn) -> int:
    doc_paths = ("/v3/api-docs", "/v2/api-docs", "/openapi.json", "/swagger.json", "/api/openapi.json")
    synthesized = 0

    def _extract_schema_props(spec: dict, schema_obj: dict, depth: int = 0) -> list[str]:
        if depth > 4 or not isinstance(schema_obj, dict):
            return []
        ref = schema_obj.get("$ref", "")
        if ref.startswith("#/"):
            parts = ref.lstrip("#/").split("/")
            cur: Any = spec
            for p in parts:
                cur = cur.get(p, {}) if isinstance(cur, dict) else {}
            return _extract_schema_props(spec, cur, depth + 1)
        props = list((schema_obj.get("properties") or {}).keys())
        for sub_k in ("allOf", "oneOf", "anyOf"):
            for item in schema_obj.get(sub_k, []):
                props.extend(_extract_schema_props(spec, item, depth + 1))
        if schema_obj.get("items"):
            props.extend(_extract_schema_props(spec, schema_obj["items"], depth + 1))
        return sorted(set(props))

    for dp in doc_paths:
        u = urllib.parse.urljoin(base_url, dp)
        try:
            r = session.get(u, timeout=6, verify=False)
            if r.status_code != 200 or not r.text.lstrip().startswith("{"):
                continue
            spec = r.json()
            paths = spec.get("paths") or {}
            if not isinstance(paths, dict) or not paths:
                continue
            all_dto_fields: set[str] = set()
            for p_str, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for verb, op in methods.items():
                    if verb.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH") or not isinstance(op, dict):
                        continue
                    p_names = []
                    for param in op.get("parameters") or []:
                        if isinstance(param, dict):
                            if param.get("name"):
                                p_names.append(str(param["name"]))
                            if param.get("schema"):
                                p_names.extend(_extract_schema_props(spec, param["schema"]))
                    req_body = (op.get("requestBody") or {}).get("content") or {}
                    for ctype_obj in req_body.values():
                        if isinstance(ctype_obj, dict) and ctype_obj.get("schema"):
                            body_props = _extract_schema_props(spec, ctype_obj["schema"])
                            p_names.extend(body_props)
                            all_dto_fields.update(body_props)
                    clean_params = sorted(set(p_names))[:20]
                    full_ep = urllib.parse.urljoin(base_url, p_str)
                    db.upsert_endpoint(project_id, full_ep, method=verb.upper(), params=clean_params, category="api_endpoint", risk_tags=["openapi_ref_resolved"], source="openapi_v11")
                    synthesized += 1
            if synthesized:
                db.upsert_finding(
                    project_id, "SPECTRE-v11 (OpenAPI-Synthesizer)",
                    f"OpenAPI Schema & DTO Body Properties Synthesized ({synthesized} operations)",
                    "API Schema Intelligence", "Info", 0.0,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
                    u, f"Synthesized Operations: {synthesized} | DTO Properties ({len(all_dto_fields)}): {', '.join(sorted(all_dto_fields)[:18])}",
                    "OpenAPI/Swagger sxemasidagi barcha $ref model bog'lamalari yechilib, POST/PUT JSON maydonlari tiklandi.",
                    "Production muhitida Swagger/OpenAPI hujjatlariga kirishni ichki tarmoq bilan cheklang.",
                )
                log_fn(f"  [🧬 OPENAPI SYNTH] {u} -> {synthesized} ta operatsiya va {len(all_dto_fields)} ta DTO maydoni tiklandi!")
                break
        except Exception:
            pass
    return synthesized


# ══════════════════════════════════════════════════════════════════════════════
# 3. STRUCTURAL DOM FINGERPRINTING & SUBDOMAIN CLUSTERING
# ══════════════════════════════════════════════════════════════════════════════

def cluster_subdomains_by_dom_structure(db, session, project_id: int, log_fn) -> dict[str, list[str]]:
    bundle = db.get_project_bundle(project_id)
    services = bundle.get("http_services", [])
    if len(services) < 2:
        return {}

    tag_re = re.compile(r"<([a-zA-Z0-9]+)")
    clusters: dict[str, list[str]] = {}
    for svc in services[:25]:
        u = svc.get("url", "")
        if not u:
            continue
        try:
            r = session.get(u, timeout=4.5, verify=False)
            tags = tag_re.findall(r.text[:60000].lower())[:120]
            sig_str = f"{r.status_code}:{svc.get('server', '')}:{'-'.join(tags)}"
            fp = hashlib.sha256(sig_str.encode("utf-8", errors="ignore")).hexdigest()[:12]
            clusters.setdefault(fp, []).append(u)
        except Exception:
            pass

    if clusters:
        unique_apps = [urls[0] for urls in clusters.values() if len(urls) == 1]
        cloned_groups = [f"[{fp}: {len(urls)} hosts ({', '.join(urls[:3])})]" for fp, urls in clusters.items() if len(urls) > 1]
        summary = f"Total Clusters: {len(clusters)} | Unique Apps ({len(unique_apps)}): {', '.join(unique_apps[:6])}"
        if cloned_groups:
            summary += f" | Shared Templates: {' ; '.join(cloned_groups[:4])}"
        db.upsert_finding(
            project_id, "SPECTRE-v11 (DOM-Clusterer)",
            f"Subdomain Structural DOM Clustering ({len(clusters)} distinct application templates)",
            "Attack Surface Prioritization", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            f"Project #{project_id}", summary,
            "HTML DOM teglar zanjiri (Structural SimHash) asosida klon subdomenlar guruhlandi va noyob veb-ilovalar ajratildi.",
            "Birinchi navbatda noyob (One-of-a-Kind) arxitekturaga ega subdomenlarni chuqur auditdan o'tkazing.",
        )
        log_fn(f"  [🛰️ DOM CLUSTER] {len(services[:25])} ta servis {len(clusters)} ta noyob klasterga ajratildi!")
    return clusters


# ══════════════════════════════════════════════════════════════════════════════
# 4. WEBPACK / VITE LAZY-LOADED CHUNK HASH PREDICTOR
# ══════════════════════════════════════════════════════════════════════════════

def predict_and_fetch_webpack_chunks(db, session, project_id: int, base_url: str, js_urls: list[str], log_fn) -> list[str]:
    map_re = re.compile(r"\{((?:\s*['\"]?[a-zA-Z0-9_\-]+['\"]?\s*:\s*['\"][a-f0-9]{6,20}['\"]\s*,?){2,40})\}")
    kv_re = re.compile(r"['\"]?([a-zA-Z0-9_\-]+)['\"]?\s*:\s*['\"]([a-f0-9]{6,20})['\"]")
    route_re = re.compile(r"""['"`]((?:/api/v\d+/|/api/|/v1/|/v2/|/internal/|/admin/)[a-zA-Z0-9_\-/\.?=&{}]+)['"`]""")
    found_chunks: list[str] = []

    for ju in js_urls[:15]:
        try:
            rj = session.get(ju, timeout=5, verify=False)
            if rj.status_code != 200:
                continue
            base_js_dir = ju.rsplit("/", 1)[0] + "/"
            for m_map in map_re.findall(rj.text[:250000]):
                pairs = kv_re.findall(m_map)
                for chunk_id, chunk_hash in pairs[:12]:
                    for pattern in (f"{chunk_id}.{chunk_hash}.js", f"{chunk_id}.{chunk_hash}.chunk.js", f"chunk-{chunk_id}.{chunk_hash}.js"):
                        cand_u = urllib.parse.urljoin(base_js_dir, pattern)
                        if cand_u in js_urls or cand_u in found_chunks:
                            continue
                        rc = session.get(cand_u, timeout=3.5, verify=False)
                        if rc.status_code == 200 and "javascript" in rc.headers.get("Content-Type", "").lower():
                            found_chunks.append(cand_u)
                            js_urls.append(cand_u)
                            for rt in route_re.findall(rc.text[:200000]):
                                db.upsert_endpoint(project_id, urllib.parse.urljoin(base_url, rt), method="GET", params=[], category="api_endpoint", source="webpack_lazy_chunk")
                            break
        except Exception:
            pass

    if found_chunks:
        db.upsert_finding(
            project_id, "SPECTRE-v11 (Webpack-Predictor)",
            f"Unlinked Lazy-Loaded Webpack Chunks Reconstructed ({len(found_chunks)} chunks)",
            "Hidden Frontend Attack Surface", "Low", 3.7,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            base_url, f"Discovered Chunks: {', '.join(found_chunks[:8])}",
            "Webpack runtime xesh jadvalidan foydalanib, oddiy foydalanuvchiga yuklanmaydigan yashirin JS chunk fayllari topildi.",
            "Admin va ichki modullarni ommaviy chunk xesh jadvalida ochiq qoldirmang.",
        )
        log_fn(f"  [📦 WEBPACK PREDICTOR] {len(found_chunks)} ta yashirin lazy-chunk topildi!")
    return found_chunks


# ══════════════════════════════════════════════════════════════════════════════
# 5. INTERNATIONALIZATION (i18n / LOCALES JSON) FEATURE & ADMIN MINER
# ══════════════════════════════════════════════════════════════════════════════

def mine_i18n_translation_dictionaries(db, session, project_id: int, base_url: str, log_fn) -> list[str]:
    i18n_paths = [
        "/assets/i18n/uz.json", "/assets/i18n/ru.json", "/assets/i18n/en.json",
        "/locales/en.json", "/locales/ru.json", "/locales/uz.json",
        "/i18n/en.json", "/static/locales/en/translation.json",
    ]
    priv_keywords = ("admin", "moderator", "super", "role", "permission", "delete", "approve", "reject", "export", "internal", "secret", "audit", "config")
    discovered_keys: set[str] = set()

    def _walk_keys(obj: Any, prefix: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_k = f"{prefix}.{k}" if prefix else str(k)
                if any(pk in full_k.lower() for pk in priv_keywords):
                    discovered_keys.add(full_k)
                _walk_keys(v, full_k)

    for ipath in i18n_paths:
        u = urllib.parse.urljoin(base_url, ipath)
        try:
            r = session.get(u, timeout=4.5, verify=False, allow_redirects=False)
            if r.status_code == 200 and r.text.lstrip().startswith("{"):
                data = r.json()
                _walk_keys(data)
                if discovered_keys:
                    k_list = sorted(discovered_keys)
                    db.upsert_finding(
                        project_id, "SPECTRE-v11 (i18n-Miner)",
                        f"Privileged Application Capabilities in i18n Dictionary ({len(k_list)} keys)",
                        "Application Feature Intelligence", "Info", 0.0,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
                        u, f"Privileged i18n Keys ({len(k_list)}): {', '.join(k_list[:15])}",
                        "Ochiq i18n tarjima faylidan tizimning yashirin ma'muriy funksiyalari va rollari ro'yxati aniqlandi.",
                        "Maxfiy admin paneli tarjima lug'atlarini ommaviy frontend bundle'dan ajrating.",
                    )
                    log_fn(f"  [🌍 i18n MINER] {u} -> {len(k_list)} ta ichki funksiya/rol kaliti topildi!")
                    break
        except Exception:
            pass
    return sorted(discovered_keys)


# ══════════════════════════════════════════════════════════════════════════════
# 6. LOAD-BALANCER NODE, CLOCK SKEW & ETAG INODE FINGERPRINTER
# ══════════════════════════════════════════════════════════════════════════════

def fingerprint_load_balancer_and_etag(db, session, project_id: int, base_url: str, log_fn) -> dict[str, Any]:
    etags: list[str] = []
    upstreams: set[str] = set()
    try:
        for _ in range(2):
            r = session.get(base_url, timeout=4.5, verify=False)
            et = r.headers.get("ETag", "").strip()
            if et:
                etags.append(et)
            for hk in ("X-Upstream", "X-Backend-Server", "X-Served-By", "X-Server-Name"):
                if r.headers.get(hk):
                    upstreams.add(r.headers[hk])

        if etags:
            clean_et = etags[0].lstrip("W/").strip('"')
            parts = clean_et.split("-")
            if len(parts) == 3 and all(re.fullmatch(r"[0-9a-fA-F]{2,16}", p) for p in parts):
                inode_val = int(parts[0], 16)
                size_val = int(parts[1], 16)
                db.upsert_finding(
                    project_id, "SPECTRE-v11 (ETag-Auditor)",
                    f"Filesystem Inode Disclosed in HTTP ETag Header (Inode: {inode_val})",
                    "Information Disclosure", "Low", 3.1,
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
                    base_url, f"ETag: {etags[0]} -> Decoded Inode={inode_val}, Size={size_val} bytes",
                    "Veb-server ETag sarlavhasida fayl tizimi Inode raqamini oshkor qilmoqda (CVE-2003-1418).",
                    "Apache 'FileETag MTime Size' direktivasini o'rnating (Inode'ni olib tashlang).",
                )
                log_fn(f"  [🕒 ETAG INODE] {base_url} -> ETag ichidan Inode={inode_val} aniqlandi!")
    except Exception:
        pass
    return {"etags": etags, "upstreams": sorted(upstreams)}


# ══════════════════════════════════════════════════════════════════════════════
# 7. CORS PREFLIGHT (OPTIONS) ALLOWED-METHODS & CUSTOM-HEADERS HARVESTER
# ══════════════════════════════════════════════════════════════════════════════

def harvest_cors_preflight_capabilities(db, session, project_id: int, base_url: str, log_fn) -> dict[str, list[str]]:
    custom_headers: set[str] = set()
    allowed_methods: set[str] = set()
    standard_hdrs = {
        "accept", "accept-language", "content-language", "content-type", "origin",
        "authorization", "cache-control", "pragma", "expires", "x-requested-with",
        "x-custom-check",
    }

    for p in ("/", "/api", "/api/v1", "/v1"):
        u = urllib.parse.urljoin(base_url, p)
        try:
            r = session.options(
                u,
                headers={"Origin": base_url, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "X-Custom-Check"},
                timeout=4,
                verify=False,
            )
            acah = r.headers.get("Access-Control-Allow-Headers", "")
            acam = r.headers.get("Access-Control-Allow-Methods", "") or r.headers.get("Allow", "")
            for h in acah.split(","):
                hc = h.strip()
                if hc and hc.lower() not in standard_hdrs and hc != "*":
                    custom_headers.add(hc)
            for m in acam.split(","):
                mc = m.strip().upper()
                if mc:
                    allowed_methods.add(mc)
        except Exception:
            pass

    if custom_headers:
        from core.scope_guard import ScopeGuard
        apex_asset = ScopeGuard.extract_apex_domain(urllib.parse.urlparse(base_url).hostname or base_url)
        ch_list = sorted(custom_headers)
        m_list = sorted(allowed_methods)
        db.upsert_finding(
            project_id, "SPECTRE-v11 (Preflight-Harvester)",
            f"Custom Backend Headers Discovered via OPTIONS Preflight ({len(ch_list)} headers)",
            "API Header Intelligence", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            apex_asset, f"Sample Host: {base_url} | Custom Allowed Headers: {', '.join(ch_list[:15])} | Allowed Methods: {', '.join(m_list)}",
            "CORS OPTIONS preflight javobidan backend qabul qiladigan maxsus HTTP sarlavhalar (custom headers) ro'yxati olindi.",
            "Access-Control-Allow-Headers ro'yxatida faqat tashqi mijozlar uchun zarur sarlavhalarni qoldiring.",
        )
        log_fn(f"  [🔗 PREFLIGHT HEADERS] {base_url} -> Custom Headers: {', '.join(ch_list[:8])}")
    return {"custom_headers": sorted(custom_headers), "methods": sorted(allowed_methods)}


# ══════════════════════════════════════════════════════════════════════════════
# 8. SMART SCOPE EXPANSION RECOMMENDER (RELATED APEX / SISTER DOMAINS)
# ══════════════════════════════════════════════════════════════════════════════

def discover_related_sister_domains(db, project_id: int, apex_domain: str, log_fn) -> list[str]:
    from core.scope_guard import ScopeGuard

    bundle = db.get_project_bundle(project_id)
    ignore_apex = {
        apex_domain.lower(), "cloudflare.com", "google.com", "googleapis.com", "gstatic.com",
        "googletagmanager.com", "yandex.ru", "facebook.com", "w3.org", "jsdelivr.net", "cdnjs.cloudflare.com",
        "amazonaws.com", "googleusercontent.com", "cloudfront.net", "azure.com", "digitalocean.com",
        "hetzner.com", "linode.com", "ovh.net", "akamaitechnologies.com", "fastly.net", "contabo.net",
    }
    sister_apexes: set[str] = set()
    dom_re = re.compile(r"\b([a-z0-9\-]+\.(?:uz|com|net|org|io|gov\.uz|com\.uz))\b", re.IGNORECASE)

    for f in bundle.get("findings", []):
        if "TLS" in f.get("title", "") or "Certificate" in f.get("title", "") or "CSP" in f.get("title", ""):
            for m in dom_re.findall(f.get("evidence", "")):
                ap = ScopeGuard.extract_apex_domain(m.lower())
                if ap and ap not in ignore_apex and "." in ap:
                    sister_apexes.add(ap)

    if sister_apexes:
        s_list = sorted(sister_apexes)
        db.upsert_finding(
            project_id, "SPECTRE-v11 (Scope-Recommender)",
            f"Discovered Related Organization / Sister Domains ({len(s_list)} domains)",
            "Attack Surface Scope Expansion", "Info", 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", "A05:2021 - Security Misconfiguration",
            apex_domain, f"Related Apex Domains on Shared Subnet/TLS: {', '.join(s_list[:12])}",
            "PTR yozuvlari va TLS sertifikatlaridan shu infratuzilmada joylashgan ikkinchi darajali asosiy domenlar (Sister Domains) aniqlandi.",
            "Agar ushbu domenlar ham tashkilotga tegishli bo'lsa, ularni In-Scope ro'yxatiga qo'shib alohida tekshiring.",
        )
        log_fn(f"  [🧭 SISTER DOMAINS] Bog'liq tashkilot domenlari: {', '.join(s_list[:8])}")
    return sorted(sister_apexes)


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ORCHESTRATOR FOR ALL 8 SPECTRE v11.0 APEX MODULES
# ══════════════════════════════════════════════════════════════════════════════

def run_v11_apex_suite(agent, project_id: int, apex_domain: str, base_url: str, js_urls: list[str], log_fn) -> None:
    log_fn(f"  [👑 SPECTRE v11.0 APEX] {base_url} ustida 8 ta intellektual sxema va klaster moduli ishga tushirildi...")
    db = agent.db
    session = agent.session

    ran_apex = getattr(agent, "_ran_apex_suites", None)
    if ran_apex is None:
        agent._ran_apex_suites = {}
        ran_apex = agent._ran_apex_suites
    proj_done = ran_apex.setdefault(project_id, set())

    map_iam_and_keycloak_realms(db, session, project_id, base_url, log_fn)
    resolve_openapi_schema_refs(db, session, project_id, base_url, log_fn)
    predict_and_fetch_webpack_chunks(db, session, project_id, base_url, js_urls, log_fn)
    mine_i18n_translation_dictionaries(db, session, project_id, base_url, log_fn)
    fingerprint_load_balancer_and_etag(db, session, project_id, base_url, log_fn)
    harvest_cors_preflight_capabilities(db, session, project_id, base_url, log_fn)
    if "v11_sister_domains" not in proj_done:
        proj_done.add("v11_sister_domains")
        discover_related_sister_domains(db, project_id, apex_domain, log_fn)
    db.log_task(project_id, "SPECTRE-v11", "v11_apex_suite", "COMPLETED", f"v11_suite {base_url}", f"Executed 8 v11 Apex Intelligence modules on {base_url}")





