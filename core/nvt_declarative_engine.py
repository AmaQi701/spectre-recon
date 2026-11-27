"""
SPECTRE Declarative NVT Signature Engine
========================================
Executes baseline-calibrated, non-destructive HTTP posture checks defined in
`config/nvt_catalog.json` with KB technology gating and anti-cardinality grouping.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from core.native_bridge import (
    fast_cpp_lookup_nvt,
    fast_go_run_yaml_plugins,
    fast_nvt_body_sig_mask,
    fast_structural_hash,
)
from core.plugin_runner import QoD

ROOT_DIR = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT_DIR / "config" / "nvt_catalog.json"
PLUGINS_DIR = ROOT_DIR / "plugins"
CUSTOM_NVTS_DIR = ROOT_DIR / "config" / "custom_nvts"
_CACHED_RULES: list[dict[str, Any]] | None = None


def _has_valid_nvt_fields(r: Any) -> bool:
    if not isinstance(r, dict) or not r.get("id") or not r.get("path"):
        return False
    p = str(r.get("path") or "")
    if not p.startswith("/") or p.startswith("//"):
        return False
    return bool(r.get("match_all") or r.get("match_any"))


def parse_custom_yaml_nvt(raw_yaml: str) -> list[dict[str, Any]]:
    """Parses native SPECTRE YAML rules or simplified Nuclei-compatible HTTP YAML templates."""
    import yaml
    if not raw_yaml or len(raw_yaml) > 524288 or raw_yaml.count("*") > 64:
        return []
    try:
        doc = yaml.safe_load(raw_yaml)
    except Exception:
        return []
    if isinstance(doc, list):
        return [r for r in doc if _has_valid_nvt_fields(r)]
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get("rules"), list):
        return [r for r in doc["rules"] if _has_valid_nvt_fields(r)]
    if _has_valid_nvt_fields(doc):
        return [doc]
    # Simplified Nuclei HTTP template compatibility
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    reqs = doc.get("http") or doc.get("requests") or []
    if doc.get("id") and info.get("name") and isinstance(reqs, list) and reqs:
        r0 = reqs[0] if isinstance(reqs[0], dict) else {}
        paths = r0.get("path") or []
        raw_p = str(paths[0]) if isinstance(paths, list) and paths else ""
        clean_p = "/" + raw_p.split("}}/", 1)[-1].lstrip("/") if raw_p else ""
        words: list[str] = []
        status_code = 200
        for mt in (r0.get("matchers") or []):
            if isinstance(mt, dict) and mt.get("type") == "word":
                words.extend(str(w) for w in (mt.get("words") or []) if w)
            elif isinstance(mt, dict) and mt.get("type") == "status" and mt.get("status"):
                status_code = int(mt["status"][0])
        sev_map = {"critical": ("Critical", 9.1), "high": ("High", 7.8), "medium": ("Medium", 5.8), "low": ("Low", 3.7)}
        sev_lbl, cvss_v = sev_map.get(str(info.get("severity") or "medium").lower(), ("Medium", 5.8))
        if clean_p.startswith("/") and words:
            return [{
                "id": f"CUSTOM-{doc['id']}",
                "title": str(info["name"]),
                "category": "Custom YAML NVT",
                "severity": sev_lbl,
                "cvss": cvss_v,
                "cwe": str((info.get("classification") or {}).get("cwe-id", ["CWE-200"])[0] if isinstance((info.get("classification") or {}).get("cwe-id"), list) else "CWE-200"),
                "path": clean_p,
                "status": status_code,
                "match_all": words,
                "exclude_any": [],
                "remediation": str(info.get("remediation") or "Custom YAML NVT qoidasi asosida ushbu endpoint ruxsatini cheklang."),
            }]
    return []


def load_nvt_catalog(extra_dir: Path | None = None) -> list[dict[str, Any]]:
    global _CACHED_RULES
    if _CACHED_RULES is not None and extra_dir is None:
        return _CACHED_RULES
    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    if CATALOG_PATH.is_file():
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        for r in (list(data.get("rules", [])) if isinstance(data, dict) else []):
            rid = str(r.get("id") or "")
            if rid and rid not in seen_ids:
                seen_ids.add(rid)
                rules.append(r)
    if extra_dir is None:
        from core.threat_intel_pack import INTEL_NVT_PACK_PATH, ensure_offline_intel_pack
        ensure_offline_intel_pack()
        if INTEL_NVT_PACK_PATH.is_file():
            try:
                kdata = json.loads(INTEL_NVT_PACK_PATH.read_text(encoding="utf-8"))
                for kr in (kdata.get("rules") or []):
                    krid = str(kr.get("id") or "")
                    if krid and krid not in seen_ids:
                        seen_ids.add(krid)
                        rules.append(kr)
            except Exception:
                pass
    scan_dirs = [extra_dir] if extra_dir is not None else [PLUGINS_DIR, CUSTOM_NVTS_DIR]
    for scan_dir in scan_dirs:
        if not scan_dir.is_dir():
            continue
        for pf in sorted(scan_dir.glob("*")):
            if pf.is_symlink() or not pf.is_file():
                continue
            try:
                if pf.stat().st_size > 524288:
                    continue
            except OSError:
                continue
            if pf.suffix.lower() in (".yaml", ".yml"):
                for yr in parse_custom_yaml_nvt(pf.read_text(encoding="utf-8", errors="ignore")):
                    yrid = str(yr.get("id") or "")
                    if yrid and yrid not in seen_ids:
                        seen_ids.add(yrid)
                        rules.append(yr)
            elif pf.suffix.lower() == ".json":
                try:
                    jd = json.loads(pf.read_text(encoding="utf-8", errors="ignore"))
                    if isinstance(jd, dict) and isinstance(jd.get("rules"), list):
                        for jr in jd["rules"]:
                            jrid = str(jr.get("id") or "")
                            if jrid and jrid not in seen_ids:
                                seen_ids.add(jrid)
                                rules.append(jr)
                except Exception:
                    pass
    if extra_dir is None:
        _CACHED_RULES = rules
    return rules


def _sig16(text: str) -> str:
    return hashlib.sha256((text or "")[:4096].encode("utf-8", errors="ignore")).hexdigest()[:16]


def _is_calibrated_hit(resp: Any, rule: dict[str, Any], cal: tuple[int, int, str, int, str]) -> bool:
    exp_st = int(rule.get("status", 200))
    if resp.status_code != exp_st:
        return False
    body = resp.text or ""
    if len(body) < int(rule.get("min_bytes", 16)):
        return False
    ct_any = [str(x).lower() for x in (rule.get("content_type_any") or [])]
    if ct_any:
        ct_hdr = str(resp.headers.get("Content-Type") or "").lower()
        if not any(c in ct_hdr for c in ct_any):
            return False
    low_b = body.lower()
    if any(str(ex).lower() in low_b for ex in (rule.get("exclude_any") or [])):
        return False
    req_all = [str(m).lower() for m in (rule.get("match_all") or []) if str(m)]
    req_any = [str(m).lower() for m in (rule.get("match_any") or []) if str(m)]
    if not req_all and not req_any:
        return False
    if req_all and not all(m in low_b for m in req_all):
        return False
    if req_any and not any(m in low_b for m in req_any):
        return False
    cal_st, cal_ln, cal_sg, cal_skel, cal_low = cal
    if cal_st == exp_st:
        if _sig16(body) == cal_sg:
            return False
        if req_all and all(m in cal_low for m in req_all):
            return False
        if req_any and not req_all and any(m in cal_low for m in req_any):
            return False
        body_skel = fast_structural_hash(body[:16384])
        if cal_skel and body_skel == cal_skel and abs(len(body) - cal_ln) < max(512, int(cal_ln * 0.35)):
            return False
    return True


def build_host_kb_facts(
    svc: dict[str, Any],
    open_ports: set[int] | None = None,
    domain_waf: str = "",
) -> dict[str, Any]:
    """Builds a per-origin Host Posture Knowledge Base (KB) dictionary for NVT pre-flight gating."""
    raw_url = str(svc.get("url") or "").rstrip("/")
    parsed = urllib.parse.urlparse(raw_url)
    scheme = (parsed.scheme or "http").lower()
    inferred_port = parsed.port or (443 if scheme == "https" else 80)
    ports_set: set[int] = {int(inferred_port)}
    if open_ports:
        ports_set.update(int(p) for p in open_ports if int(p) > 0)

    raw_tech = svc.get("tech_stack") or ""
    tech_str = raw_tech
    if isinstance(raw_tech, str) and raw_tech.strip().startswith("["):
        try:
            tech_str = " ".join(str(x) for x in json.loads(raw_tech) if x)
        except Exception:
            tech_str = raw_tech
    elif isinstance(raw_tech, (list, tuple, set)):
        tech_str = " ".join(str(x) for x in raw_tech if x)

    srv = str(svc.get("server") or "").strip()
    title = str(svc.get("title") or "").strip()
    waf = str(svc.get("waf") or svc.get("cdn_waf") or domain_waf or "").strip()
    hdr_blob = str(svc.get("headers_json") or "")[:2048]
    nvt_sig = fast_nvt_body_sig_mask(f"{title}\n{srv}\n{hdr_blob}")
    return {
        "url": raw_url,
        "http/status": str(svc.get("status_code") or ""),
        "http/server": srv,
        "http/title": title,
        "http/nvt_sig_mask": str(nvt_sig),
        "tech/stack": f"{srv} {tech_str}".strip(),
        "cdn/waf": waf,
        "tls/enabled": "true" if scheme == "https" else "false",
        "ports/tcp": ports_set,
    }


def _kb_expr_matches(host_kb: dict[str, Any], expr: str) -> bool:
    raw = str(expr or "").strip()
    if not raw:
        return False
    if "=" not in raw:
        val = host_kb.get(raw)
        if isinstance(val, (set, list, tuple)):
            return len(val) > 0
        return bool(str(val or "").strip())
    k_part, pat_part = raw.split("=", 1)
    k_part = k_part.strip()
    pat_part = pat_part.strip()
    raw_val = host_kb.get(k_part)
    if raw_val is None:
        return False
    val_str = " ".join(str(x) for x in raw_val) if isinstance(raw_val, (set, list, tuple)) else str(raw_val)
    if not val_str.strip():
        return False
    try:
        return bool(re.search(pat_part, val_str, re.IGNORECASE))
    except re.error:
        return pat_part.lower() in val_str.lower()


def evaluate_nvt_kb_gate(host_kb: dict[str, Any], rule: dict[str, Any]) -> tuple[bool, str]:
    """
    Evaluates declarative NVT pre-flight gates (`required_ports`, `excluded_keys`,
    `mandatory_keys`, and `tech_any`) against `host_kb` prior to issuing HTTP probes.
    """
    req_ports = [int(p) for p in (rule.get("required_ports") or []) if int(p) > 0]
    if req_ports:
        open_tcp = host_kb.get("ports/tcp") or set()
        if not any(p in open_tcp for p in req_ports):
            return False, f"missing_required_port:{req_ports}"

    for ex_expr in (rule.get("excluded_keys") or []):
        if _kb_expr_matches(host_kb, str(ex_expr)):
            return False, f"excluded_key:{ex_expr}"

    for req_expr in (rule.get("mandatory_keys") or []):
        if not _kb_expr_matches(host_kb, str(req_expr)):
            return False, f"missing_mandatory_key:{req_expr}"

    req_tech = [str(t).lower() for t in (rule.get("tech_any") or []) if str(t)]
    if req_tech:
        t_blob = (
            f"{host_kb.get('http/title', '')} {host_kb.get('http/server', '')} "
            f"{host_kb.get('tech/stack', '')} {host_kb.get('url', '')}"
        ).lower()
        if not any(t in t_blob for t in req_tech):
            return False, "missing_tech_any"

    return True, "OK"


def run_declarative_nvt_catalog(
    db: Any,
    http_engine: Any,
    project_id: int,
    http_services: list[dict[str, Any]],
    log_fn: Any,
) -> int:
    rules = load_nvt_catalog()
    if not rules or not http_services:
        return 0

    host_ports_map: dict[str, set[int]] = {}
    dom_waf_map: dict[str, str] = {}
    dom_ip_map: dict[str, str] = {}
    if hasattr(db, "get_project_bundle"):
        try:
            bnd = db.get_project_bundle(project_id)
            for d_row in bnd.get("domains", []):
                dn = str(d_row.get("domain") or "").strip().lower()
                dip = str(d_row.get("ip") or "").strip()
                dw = str(d_row.get("cdn_waf") or "").strip()
                if dn:
                    if dw:
                        dom_waf_map[dn] = dw
                    if dip:
                        dom_ip_map[dn] = dip
            for p_row in bnd.get("ports", []):
                if str(p_row.get("protocol") or "tcp").lower() != "tcp":
                    continue
                pnum = int(p_row.get("port") or 0)
                if pnum <= 0:
                    continue
                for hk in (str(p_row.get("host") or "").lower(), str(p_row.get("ip") or "").lower()):
                    if hk:
                        host_ports_map.setdefault(hk, set()).add(pnum)
        except Exception:
            pass

    targets: list[tuple[str, dict[str, Any]]] = []
    seen_origins: set[str] = set()
    ordered = sorted(
        http_services,
        key=lambda s: (
            0 if int(s.get("status_code") or 0) == 200 else 1,
            1 if (urllib.parse.urlparse(str(s.get("url") or "")).hostname or "").lower().startswith("www.") else 0,
        ),
    )
    for svc in ordered:
        if int(svc.get("status_code") or 0) not in (200, 401, 403):
            continue
        u = str(svc.get("url") or "").rstrip("/")
        if not u or http_engine.is_host_dead(u):
            continue
        pu = urllib.parse.urlparse(u)
        hn = (pu.hostname or "").lower()
        orig_k = f"{(pu.scheme or 'http').lower()}://{pu.netloc.lower()}"
        if orig_k in seen_origins:
            continue
        seen_origins.add(orig_k)
        h_ports = set(host_ports_map.get(hn, set()))
        if hn in dom_ip_map:
            h_ports.update(host_ports_map.get(dom_ip_map[hn], set()))
        targets.append((u, build_host_kb_facts(svc, open_ports=h_ports, domain_waf=dom_waf_map.get(hn, ""))))
        if len(targets) >= 16:
            break

    if not targets:
        return 0

    active_rules = [rl for rl in rules if not rl.get("passive_only")]
    rule_by_id = {str(rl.get("id") or ""): rl for rl in active_rules}
    has_proxy = bool(getattr(getattr(http_engine, "session", None), "proxies", None))
    hits_by_rule: dict[str, list[tuple[dict[str, Any], str, int]]] = {}

    def _eval_host(item: tuple[str, dict[str, Any]]) -> list[tuple[dict[str, Any], str, int]]:
        base_u, host_kb = item
        local_hits: list[tuple[dict[str, Any], str, int]] = []
        go_handled_ids: set[str] = set()
        if not has_proxy and PLUGINS_DIR.is_dir():
            kb_s = ";".join(f"{k}={v}" for k, v in host_kb.items() if isinstance(v, str) and v and ";" not in v)
            go_rep = fast_go_run_yaml_plugins(base_u, str(PLUGINS_DIR), kb_hints=kb_s, timeout_ms=2600)
            if isinstance(go_rep, dict):
                go_handled_ids = {str(r.get("id") or "") for r in active_rules if str(r.get("id") or "").startswith("YAML-NVT-")}
                for gf in (go_rep.get("findings") or []):
                    pid = str(gf.get("plugin_id") or "")
                    rl_g = rule_by_id.get(pid) or gf
                    local_hits.append((rl_g, str(gf.get("asset") or base_u), 64))
        try:
            rc = http_engine.request("GET", f"{base_u}/spectre-decl-cal-7741", timeout=(2.0, 2.8), allow_redirects=False, max_bytes=16384)
            rc_txt = rc.text or ""
            cal = (rc.status_code, len(rc_txt), _sig16(rc_txt), fast_structural_hash(rc_txt[:16384]), rc_txt[:2048].lower())
        except Exception:
            return local_hits
        for rl in active_rules:
            if str(rl.get("id") or "") in go_handled_ids:
                continue
            ok_gate, _ = evaluate_nvt_kb_gate(host_kb, rl)
            if not ok_gate:
                continue
            probe_u = f"{base_u}{rl['path']}"
            try:
                rp = http_engine.request("GET", probe_u, timeout=(2.0, 2.8), allow_redirects=False, max_bytes=24576)
                if _is_calibrated_hit(rp, rl, cal):
                    local_hits.append((rl, probe_u, len(rp.text or "")))
            except Exception:
                pass
        return local_hits

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(targets)))
    futs = [ex.submit(_eval_host, t) for t in targets[:16]]
    done, _ = concurrent.futures.wait(futs, timeout=22.0)
    ex.shutdown(wait=False, cancel_futures=True)

    for fut in done:
        try:
            for rl, p_u, b_len in fut.result() or []:
                hits_by_rule.setdefault(str(rl["id"]), []).append((rl, p_u, b_len))
        except Exception:
            pass

    total_written = 0
    for rid, items in hits_by_rule.items():
        rl, first_u, first_len = items[0]
        cpp_meta = fast_cpp_lookup_nvt(rid)
        cwe_val = str(rl.get("cwe") or (cpp_meta or {}).get("cwe") or "CWE-200")
        host0 = urllib.parse.urlparse(first_u).netloc or first_u
        suffix = f"({len(items)} Hosts)" if len(items) > 1 else f"({host0})"
        ev_urls = ", ".join(u_i for _, u_i, _ in items[:5])
        db.upsert_finding(
            project_id,
            "Agent-2 (Declarative-NVT)",
            f"[CONFIRMED] {rl['title']} {suffix}",
            str(rl.get("category") or "Security Misconfiguration"),
            str(rl.get("severity") or "Medium"),
            float(rl.get("cvss") or 5.3),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe_val,
            str(rl.get("owasp") or "A05:2021 - Security Misconfiguration"),
            first_u,
            f"NVT {rid} | Verified ({first_len}B): {ev_urls}",
            f"Kalibratsiyalangan deklarativ NVT ({rid}) tekshiruvi orqali ochiq ma'muriy yoki diagnostik resurs tasdiqlandi.",
            str(rl.get("remediation") or "Ushbu diagnostik resursga tashqi tarmoqdan kirishni cheklang."),
            confidence=str(rl.get("qod") or QoD.ACTIVE_VERIFIED),
        )
        total_written += 1

    if total_written and log_fn:
        log_fn(f"  [DECLARATIVE-NVT] {len(rules)} ta NVT qoidasidan {total_written} ta tasdiqlangan holat aniqlandi.")
    return total_written

