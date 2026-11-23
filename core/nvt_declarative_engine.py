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
import urllib.parse
from pathlib import Path
from typing import Any

from core.native_bridge import fast_structural_hash
from core.plugin_runner import QoD

CATALOG_PATH = Path(__file__).resolve().parent.parent / "config" / "nvt_catalog.json"
_CACHED_RULES: list[dict[str, Any]] | None = None


def load_nvt_catalog() -> list[dict[str, Any]]:
    global _CACHED_RULES
    if _CACHED_RULES is not None:
        return _CACHED_RULES
    if not CATALOG_PATH.is_file():
        _CACHED_RULES = []
        return _CACHED_RULES
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    _CACHED_RULES = list(data.get("rules", [])) if isinstance(data, dict) else []
    return _CACHED_RULES


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
    req_all = [str(m).lower() for m in (rule.get("match_all") or [])]
    if not req_all or not all(m in low_b for m in req_all):
        return False
    cal_st, cal_ln, cal_sg, cal_skel, cal_low = cal
    if cal_st == exp_st:
        if _sig16(body) == cal_sg:
            return False
        if all(m in cal_low for m in req_all):
            return False
        body_skel = fast_structural_hash(body[:16384])
        if cal_skel and body_skel == cal_skel and abs(len(body) - cal_ln) < max(512, int(cal_ln * 0.35)):
            return False
    return True


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

    targets: list[tuple[str, str]] = []
    seen_tpl: set[tuple[str, str, int]] = set()
    ordered = sorted(
        http_services,
        key=lambda s: (1 if (urllib.parse.urlparse(str(s.get("url") or "")).hostname or "").lower().startswith("www.") else 0),
    )
    for svc in ordered:
        if int(svc.get("status_code") or 0) not in (200, 401, 403):
            continue
        u = str(svc.get("url") or "").rstrip("/")
        if not u or http_engine.is_host_dead(u):
            continue
        tpl = (str(svc.get("server") or ""), str(svc.get("title") or "")[:50], int(svc.get("content_length") or 0) // 2048)
        if tpl in seen_tpl and targets:
            continue
        seen_tpl.add(tpl)
        t_blob = f"{svc.get('title', '')} {svc.get('server', '')} {svc.get('tech_stack', '')} {u}".lower()
        targets.append((u, t_blob))

    if not targets:
        return 0

    hits_by_rule: dict[str, list[tuple[dict[str, Any], str, int]]] = {}

    def _eval_host(item: tuple[str, str]) -> list[tuple[dict[str, Any], str, int]]:
        base_u, t_blob = item
        local_hits: list[tuple[dict[str, Any], str, int]] = []
        try:
            rc = http_engine.request("GET", f"{base_u}/spectre-decl-cal-7741", timeout=(2.0, 2.8), allow_redirects=False, max_bytes=16384)
            rc_txt = rc.text or ""
            cal = (rc.status_code, len(rc_txt), _sig16(rc_txt), fast_structural_hash(rc_txt[:16384]), rc_txt[:2048].lower())
        except Exception:
            return local_hits
        for rl in rules:
            req_tech = [str(t).lower() for t in (rl.get("tech_any") or [])]
            if req_tech and not any(t in t_blob for t in req_tech):
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
    futs = [ex.submit(_eval_host, t) for t in targets[:8]]
    done, _ = concurrent.futures.wait(futs, timeout=14.0)
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
            str(rl.get("cwe") or "CWE-200"),
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

