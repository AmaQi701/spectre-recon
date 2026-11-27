"""
SPECTRE CMS, Framework & Enterprise Application NVT Verifiers
=============================================================
Baseline-calibrated, non-destructive verification for Moodle, WordPress,
1C-Bitrix, DataLife Engine, Spring Boot Actuator, Laravel Ignition/Telescope,
Grafana, Zabbix, MinIO, and Jenkins.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import urllib.parse
from typing import Any

from core.native_bridge import fast_structural_hash
from core.plugin_runner import QoD


def _body_sig(text: str) -> str:
    return hashlib.sha256((text or "")[:4096].encode("utf-8", errors="ignore")).hexdigest()[:16]


def _is_soft_200(resp: Any, cal_status: int, cal_len: int, cal_sig: str, cal_skel: int = 0) -> bool:
    if resp.status_code != 200:
        return True
    txt = resp.text or ""
    if cal_status == 200:
        if _body_sig(txt) == cal_sig:
            return True
        if cal_skel and fast_structural_hash(txt[:16384]) == cal_skel and abs(len(txt) - cal_len) < max(512, int(cal_len * 0.35)):
            return True
    return False


def _audit_cms_paths(db: Any, http_engine: Any, project_id: int, base_url: str, tech_blob: str, cal: tuple[int, int, str, int]) -> int:
    hits = 0
    cal_st, cal_ln, cal_sg, cal_sk = cal
    host_lbl = urllib.parse.urlparse(base_url).hostname or base_url

    if "wordpress" in tech_blob or "wp-" in tech_blob:
        try:
            r_wp = http_engine.request("GET", f"{base_url}/wp-json/wp/v2/users?per_page=5", timeout=(2.5, 3.5), allow_redirects=False, max_bytes=32768)
            if not _is_soft_200(r_wp, cal_st, cal_ln, cal_sg, cal_sk) and r_wp.text.lstrip().startswith("[") and '"slug"' in r_wp.text:
                arr = json.loads(r_wp.text)
                slugs = [str(u.get("slug") or "") for u in arr if isinstance(u, dict) and u.get("slug")]
                if slugs:
                    db.upsert_finding(
                        project_id, "Agent-2 (CMS-NVT)", f"[CONFIRMED] WordPress REST API User Enumeration ({host_lbl})",
                        "Information Disclosure", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "CWE-200", "A01:2021 - Broken Access Control", f"{base_url}/wp-json/wp/v2/users",
                        f"Exposed User Slugs ({len(slugs)}): {', '.join(slugs[:6])}",
                        "WordPress REST API foydalanuvchi loginlarini autentifikatsiyasiz oshkor qilmoqda.",
                        "`rest_endpoints` filtrida `/wp/v2/users` yo'lini anonim foydalanuvchilar uchun yoping.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
        except Exception:
            pass
        try:
            xml_pl = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
            r_xr = http_engine.request("POST", f"{base_url}/xmlrpc.php", data=xml_pl, headers={"Content-Type": "text/xml"}, timeout=(2.5, 3.5), allow_redirects=False, max_bytes=32768)
            if r_xr.status_code == 200 and "wp.getUsersBlogs" in r_xr.text and "system.multicall" in r_xr.text:
                db.upsert_finding(
                    project_id, "Agent-2 (CMS-NVT)", f"[CONFIRMED] WordPress XML-RPC Multicall Surface Enabled ({host_lbl})",
                    "Brute-Force Amplification / Attack Surface", "Low", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    "CWE-307", "A07:2021 - Identification and Authentication Failures", f"{base_url}/xmlrpc.php",
                    "XML-RPC methods active: system.multicall, wp.getUsersBlogs",
                    "WordPress xmlrpc.php multicall parol terish va pingback SSRF xavfini oshiradi.",
                    "Veb-server darajasida `/xmlrpc.php` ga kirishni cheklang.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
                hits += 1
        except Exception:
            pass

    if "moodle" in tech_blob or "moodle" in base_url.lower():
        try:
            r_md = http_engine.request("GET", f"{base_url}/lib/upgrade.txt", timeout=(2.2, 3.2), allow_redirects=False, max_bytes=24576)
            if not _is_soft_200(r_md, cal_st, cal_ln, cal_sg, cal_sk) and "moodle" in r_md.text[:800].lower() and "===" in r_md.text[:600]:
                m_mv = re.search(r"===\s*([345]\.\d+(?:\.\d+)?)\s*===", r_md.text[:1500])
                ver_m = m_mv.group(1) if m_mv else ""
                if ver_m:
                    db.merge_http_tech_stack(project_id, base_url, [f"Moodle {ver_m}"])
                db.upsert_finding(
                    project_id, "Agent-2 (CMS-NVT)", f"Exposed Moodle Upgrade Changelog ({host_lbl})",
                    "Information Disclosure", "Low", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", f"{base_url}/lib/upgrade.txt",
                    f"Detected Moodle branch: {ver_m or 'confirmed'} via /lib/upgrade.txt",
                    "Moodle relizlar tarixi fayli tashqi foydalanuvchilar uchun ochiq qoldirilgan.",
                    "`/lib/upgrade.txt` va `/composer.json` fayllariga tashqi kirishni yoping.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
                hits += 1
        except Exception:
            pass

    if "bitrix" in tech_blob:
        try:
            r_bx = http_engine.request("GET", f"{base_url}/bitrix/tools/composite_data.php", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=16384)
            if not _is_soft_200(r_bx, cal_st, cal_ln, cal_sg, cal_sk) and "server_tz_offset" in r_bx.text.lower():
                db.upsert_finding(
                    project_id, "Agent-2 (CMS-NVT)", f"1C-Bitrix Composite Diagnostic Endpoint Exposed ({host_lbl})",
                    "Information Disclosure", "Low", 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", f"{base_url}/bitrix/tools/composite_data.php",
                    f"HTTP 200 JSON: {r_bx.text[:100]}",
                    "1C-Bitrix yordamchi diagnostika skripti tashqi so'rovlar uchun ochiq qoldirilgan.",
                    "`/bitrix/tools/` va `/bitrix/backup/` yo'llariga kirishni WAF/Nginx orqali cheklang.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
                hits += 1
        except Exception:
            pass

    if "datalife" in tech_blob or re.search(r"\bdle\b", tech_blob):
        try:
            r_dle = http_engine.request("GET", f"{base_url}/upgrade/index.php", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=16384)
            if not _is_soft_200(r_dle, cal_st, cal_ln, cal_sg, cal_sk) and "datalife engine" in r_dle.text.lower():
                db.upsert_finding(
                    project_id, "Agent-2 (CMS-NVT)", f"[CONFIRMED] Exposed DataLife Engine Upgrade Script ({host_lbl})",
                    "Security Misconfiguration", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{base_url}/upgrade/index.php",
                    "HTTP 200 DataLife Engine /upgrade/index.php accessible",
                    "CMS yangilash skripti production serverdan o'chirilmagan.",
                    "`/upgrade/` katalogini production serverdan o'chiring.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass
        try:
            r_adm = http_engine.request("GET", f"{base_url}/admin.php", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=24576)
            adm_low = r_adm.text.lower()
            if not _is_soft_200(r_adm, cal_st, cal_ln, cal_sg, cal_sk) and "<form" in adm_low and ("password" in adm_low or "datalife" in adm_low or "username" in adm_low):
                has_rl = any(k.lower() in ("x-ratelimit-limit", "ratelimit-limit", "retry-after") for k in r_adm.headers.keys())
                rl_note = "Rate-Limit Headers: Present" if has_rl else "Rate-Limit Headers: Absent"
                db.upsert_finding(
                    project_id, "Agent-2 (CMS-NVT)", f"Exposed DataLife Engine Administrative Interface ({host_lbl}/admin.php)",
                    "Administrative Interface Exposure", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{base_url}/admin.php",
                    f"HTTP 200 Login Interface ({len(r_adm.text)}B) | {rl_note}",
                    "CMS ma'muriy boshqaruv kirish sahifasi (`/admin.php`) standart nom bilan tashqi tarmoq uchun ochiq qoldirilgan.",
                    "CMS sozlamalarida `admin.php` fayl nomini o'zgartiring va Nginx/Apache orqali faqat ishonchli IP manzillarga ruxsat bering.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
                hits += 1
        except Exception:
            pass
    return hits


def _audit_enterprise_panels(db: Any, http_engine: Any, project_id: int, base_url: str, tech_blob: str, cal: tuple[int, int, str, int]) -> int:
    hits = 0
    cal_st, cal_ln, cal_sg, cal_sk = cal
    host_lbl = urllib.parse.urlparse(base_url).netloc or base_url

    if any(k in tech_blob for k in ("spring", "java", "tomcat", "jetty")) or any(p in base_url for p in (":808", ":809", ":8443", ":900")):
        for act_p in ("/actuator/env", "/env"):
            try:
                r_ac = http_engine.request("GET", f"{base_url}{act_p}", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=32768)
                if not _is_soft_200(r_ac, cal_st, cal_ln, cal_sg, cal_sk) and ("propertySources" in r_ac.text or "activeProfiles" in r_ac.text):
                    db.upsert_finding(
                        project_id, "Agent-2 (Enterprise-NVT)", f"[CONFIRMED] Unauthenticated Spring Boot Actuator Environment ({host_lbl})",
                        "Sensitive Data Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "CWE-200", "A05:2021 - Security Misconfiguration", f"{base_url}{act_p}",
                        f"Actuator JSON keys confirmed ({len(r_ac.text)}B)",
                        "Spring Boot Actuator `/actuator/env` tizim o'zgaruvchilari va konfiguratsiyani parolsiz qaytarmoqda.",
                        "`management.endpoints.web.exposure.include=health` bilan cheklang va Actuator portini tashqi tarmoqdan yoping.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
                    break
            except Exception:
                pass

    if "laravel" in tech_blob or "php" in tech_blob:
        try:
            r_ig = http_engine.request("GET", f"{base_url}/_ignition/health-check", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=8192)
            if not _is_soft_200(r_ig, cal_st, cal_ln, cal_sg, cal_sk) and '"can_execute_commands"' in r_ig.text:
                db.upsert_finding(
                    project_id, "Agent-2 (Enterprise-NVT)", f"[CONFIRMED] Exposed Laravel Ignition Debug Endpoint ({host_lbl})",
                    "Debug Mode Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "CWE-489", "A05:2021 - Security Misconfiguration", f"{base_url}/_ignition/health-check",
                    f"Ignition JSON: {r_ig.text[:120]}",
                    "Production serverda Laravel Ignition debug endpointi yoqib qoldirilgan.",
                    "`.env` faylida `APP_DEBUG=false` o'rnating va Ignition paketini productiondan chiqaring.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass

    # Grafana /api/health (version feed) & /api/datasources
    try:
        r_gf = http_engine.request("GET", f"{base_url}/api/health", timeout=(2.0, 2.8), allow_redirects=False, max_bytes=8192)
        if not _is_soft_200(r_gf, cal_st, cal_ln, cal_sg, cal_sk) and '"database"' in r_gf.text and '"version"' in r_gf.text:
            gf_obj = json.loads(r_gf.text)
            gf_ver = str(gf_obj.get("version") or "")
            if re.match(r"^\d+\.\d+", gf_ver):
                db.merge_http_tech_stack(project_id, base_url, [f"Grafana {gf_ver}"])
            r_ds = http_engine.request("GET", f"{base_url}/api/datasources", timeout=(2.0, 2.8), allow_redirects=False, max_bytes=16384)
            if r_ds.status_code == 200 and r_ds.text.lstrip().startswith("[") and '"type"' in r_ds.text:
                db.upsert_finding(
                    project_id, "Agent-2 (Enterprise-NVT)", f"[CONFIRMED] Anonymous Grafana Datasource API Access ({host_lbl})",
                    "Broken Access Control", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-306", "A01:2021 - Broken Access Control", f"{base_url}/api/datasources",
                    f"Grafana {gf_ver} anonymous /api/datasources exposed",
                    "Grafana instansiyasida anonim kirish (`auth.anonymous.enabled`) yoqib qo'yilgan.",
                    "`grafana.ini` ichida `[auth.anonymous] enabled = false` o'rnating.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
    except Exception:
        pass

    # MinIO Cluster Metrics, Jenkins Unauthenticated API, Zabbix Guest Mode, ASP.NET ELMAH/Trace & Debug Logs
    for ep_u, sig_s, f_title, sev_s, cvss_f, rem_s in (
        ("/minio/v2/metrics/cluster", "minio_cluster_", "Exposed MinIO Cluster Prometheus Metrics", "Medium", 5.8, "MinIO metrikalarini `MINIO_PROMETHEUS_AUTH_TYPE=jwt` rejimiga o'tkazing."),
        ("/api/json", '"jobs":[', "Unauthenticated Jenkins Dashboard API", "High", 8.2, "Jenkins Global Security bo'limida anonim o'qish huquqini o'chiring."),
        ("/zabbix.php?action=dashboard.view", "zabbix", "Zabbix Guest Dashboard Access Enabled", "High", 7.8, "Zabbix Users -> Guest guruhini o'chiring."),
        ("/elmah.axd", "errorlogfor", "Exposed ASP.NET ELMAH Error Log Interface", "High", 7.5, "`web.config` ichida `elmah.axd` ga masofaviy kirishni (`allowRemoteAccess=false`) o'chiring."),
        ("/trace.axd", "applicationtrace", "Exposed ASP.NET Application Trace (`trace.axd`)", "High", 7.5, "`web.config` ichida `<trace enabled=\"false\" />` o'rnating."),
        ("/wp-content/debug.log", "php", "Exposed WordPress PHP Debug Log (`debug.log`)", "High", 7.5, "`wp-config.php` da `WP_DEBUG_LOG` ni o'chiring va `debug.log` faylini o'chiring."),
        ("/storage/logs/laravel.log", ".error:", "Exposed Laravel Application Log (`laravel.log`)", "High", 8.1, "Veb-server ildizini faqat `/public` katalogiga yo'naltiring va `/storage` kirishini bloklang."),
        ("/telescope/requests", "telescope", "Exposed Laravel Telescope Debug Dashboard", "High", 8.2, "`TelescopeServiceProvider::gate()` orqali production kirishni cheklang."),
    ):
        try:
            r_ep = http_engine.request("GET", f"{base_url}{ep_u}", timeout=(2.0, 2.8), allow_redirects=False, max_bytes=24576)
            norm_b = r_ep.text.lower().replace(" ", "")
            if not _is_soft_200(r_ep, cal_st, cal_ln, cal_sg, cal_sk) and sig_s in norm_b:
                if ep_u.startswith("/zabbix") and ("sign-in" in norm_b or "name=\"password\"" in norm_b):
                    continue
                if ep_u.endswith("debug.log") and not any(k in r_ep.text for k in ("PHP Notice", "PHP Warning", "PHP Fatal", "Stack trace:")):
                    continue
                db.upsert_finding(
                    project_id, "Agent-2 (Enterprise-NVT)", f"[CONFIRMED] {f_title} ({host_lbl})",
                    "Broken Access Control / Information Disclosure", sev_s, cvss_f, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-200", "A05:2021 - Security Misconfiguration", f"{base_url}{ep_u}",
                    f"Signature `{sig_s}` confirmed on {ep_u} ({len(r_ep.text)}B)",
                    f"`{ep_u}` diagnostika yoki log manzili autentifikatsiyasiz ochiq qoldirilgan.",
                    rem_s,
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        except Exception:
            pass
    return hits


def run_cms_and_enterprise_nvts(
    db: Any,
    http_engine: Any,
    project_id: int,
    http_services: list[dict[str, Any]],
    log_fn: Any,
) -> int:
    candidates: list[tuple[str, str]] = []
    seen_tpl: set[tuple[str, str, int]] = set()
    for svc in (http_services or []):
        sc = int(svc.get("status_code") or 0)
        if sc not in (200, 401, 403):
            continue
        title_s = str(svc.get("title") or "").strip()
        clen = int(svc.get("content_length") or 0)
        if title_s.startswith(("Redirect (", "External Redirect", "Meta-Refresh ->")):
            continue
        if sc == 200 and clen < 200 and ("nginx" in title_s.lower() or not title_s):
            continue
        url = str(svc.get("url") or "").rstrip("/")
        if not url or http_engine.is_host_dead(url):
            continue
        tpl = (str(svc.get("server") or ""), title_s[:50], clen // 2048)
        if tpl in seen_tpl and len(candidates) >= 1:
            continue
        seen_tpl.add(tpl)
        t_blob = f"{title_s} {svc.get('server', '')} {svc.get('tech_stack', '')}".lower()
        candidates.append((url, t_blob))

    if not candidates:
        return 0

    def _run_one(item: tuple[str, str]) -> int:
        b_url, tb = item
        cal = (-1, -1, "", 0)
        try:
            rc = http_engine.request("GET", f"{b_url}/spectre-cal-nvt-8821", timeout=(2.0, 2.8), allow_redirects=False, max_bytes=16384)
            rc_t = rc.text or ""
            cal = (rc.status_code, len(rc_t), _body_sig(rc_t), fast_structural_hash(rc_t[:16384]))
        except Exception:
            return 0
        return _audit_cms_paths(db, http_engine, project_id, b_url, tb, cal) + _audit_enterprise_panels(db, http_engine, project_id, b_url, tb, cal)

    total_hits = 0
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(candidates)))
    futs = [ex.submit(_run_one, c) for c in candidates[:10]]
    done, _ = concurrent.futures.wait(futs, timeout=15.0)
    ex.shutdown(wait=False, cancel_futures=True)
    for fut in done:
        try:
            total_hits += int(fut.result() or 0)
        except Exception:
            pass
    if total_hits:
        log_fn(f"  [CMS/ENTERPRISE-NVT] Kalibratsiyalangan dasturiy tekshiruv: {total_hits} ta tasdiqlangan holat topildi.")
    return total_hits


