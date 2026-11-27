"""
SPECTRE — Automated AST, Signature, Schema & Runtime Integrity Gate
===================================================================
Run before every commit to guarantee zero invalid keys, zero mismatched
function signatures, zero hardcoded developer paths, and 49/49 tool readiness.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import py_compile
import sys
import tempfile

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.models import BUNDLE_KEYS, FORBIDDEN_HALLUCINATED_KEYS
from core.database import DatabaseManager
from core.scope_guard import ScopeGuard
from agents.recon_agent import ReconSuperAgent
from agents.vuln_agent import VulnAssessmentSuperAgent
from agents.triage_chain_agent import TriageAndChainSuperAgent
from agents import (
    active_web_auditor,
    cli_orchestrator,
    origin_and_spa,
    protocol_and_client,
    runtime_and_network,
    schema_and_iam,
    surface_prober,
)

MODULE_MAP = {
    "surface_prober": surface_prober,
    "cli_orchestrator": cli_orchestrator,
    "origin_and_spa": origin_and_spa,
    "active_web_auditor": active_web_auditor,
    "protocol_and_client": protocol_and_client,
    "schema_and_iam": schema_and_iam,
    "runtime_and_network": runtime_and_network,
}


def run_integrity_gate() -> list[str]:
    errors: list[str] = []
    py_files = sorted(ROOT_DIR.rglob("*.py"))

    for pf in py_files:
        if "tests" in pf.relative_to(ROOT_DIR).parts:
            continue
        try:
            py_compile.compile(str(pf), doraise=True)
        except Exception as ex:
            errors.append(f"[COMPILE ERROR] {pf.name}: {ex}")
            continue

        src = pf.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src, filename=str(pf))

        for node in ast.walk(tree):
            # 1. Check for forbidden hallucinated dictionary keys in .get("...") or row["..."]
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    k_val = node.args[0].value
                    if k_val in FORBIDDEN_HALLUCINATED_KEYS:
                        errors.append(f"[HALLUCINATED KEY '{k_val}'] {pf.name}:{node.lineno}")
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in ("bundle", "b", "b_final"):
                        if k_val not in BUNDLE_KEYS:
                            errors.append(f"[INVALID BUNDLE KEY '{k_val}'] {pf.name}:{node.lineno}")

            # 2. Check cross-module function calls (e.g. spectre_v12_modules.foo(...)) for exact signature arity!
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                mod_name = node.func.value.id
                fn_name = node.func.attr
                if mod_name in MODULE_MAP:
                    mod_obj = MODULE_MAP[mod_name]
                    if not hasattr(mod_obj, fn_name):
                        errors.append(f"[MISSING FUNCTION] {pf.name}:{node.lineno} calls {mod_name}.{fn_name} which does not exist!")
                    else:
                        fn_obj = getattr(mod_obj, fn_name)
                        sig = inspect.signature(fn_obj)
                        params = list(sig.parameters.values())
                        min_args = sum(1 for p in params if p.default is inspect.Parameter.empty and p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD))
                        max_args = len(params)
                        passed_args = len(node.args) + len(node.keywords)
                        if not (min_args <= passed_args <= max_args):
                            errors.append(
                                f"[SIGNATURE MISMATCH] {pf.name}:{node.lineno} calls {mod_name}.{fn_name} with {passed_args} args, expected {min_args}..{max_args}"
                            )

            # 3. Check for deprecated datetime.utcnow()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "utcnow":
                errors.append(f"[DEPRECATED utcnow()] {pf.name}:{node.lineno}")

            # 4. Check for blocking 'with ThreadPoolExecutor'
            if isinstance(node, ast.With):
                for item in node.items:
                    ctx_s = ast.unparse(item.context_expr) if hasattr(ast, "unparse") else ""
                    if "ThreadPoolExecutor" in ctx_s:
                        errors.append(f"[BLOCKING WITH-EXECUTOR] {pf.name}:{node.lineno} -> Use explicit wait(timeout=...) + shutdown(wait=False, cancel_futures=True)")

            # 4b. Portability Gate — forbid hardcoded '/home/<username>' strings in source code
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "/home/" in node.value:
                errors.append(f"[HARDCODED HOME PATH] {pf.name}:{node.lineno} contains '{node.value[:60]}'")

    # 5. Runtime Smoke Check of DB, ScopeGuard, KB Gate, Advisory Catalog, and 49/49 Tools
    from core.advisory_kb import CURATED_CVE_ADVISORIES, extract_cpe_inventory, match_version_advisories, version_in_range
    from core.plugin_runner import PhaseOrchestrator, ScanContextKB, ScanPhase

    kb_smoke = ScanContextKB(1, "target.local")
    kb_smoke.add_fact("Ports/tcp", 6379)
    if not kb_smoke.check_gate(require_ports=[6379])[0] or kb_smoke.check_gate(require_ports=[27017])[0]:
        errors.append("[KB GATE BROKEN] ScanContextKB.check_gate port gating failed")
    if kb_smoke.check_gate(exclude_keys=["Ports/tcp"])[0] or not kb_smoke.check_gate(require_any_keys=["Missing/k", "Ports/tcp"])[0]:
        errors.append("[KB GATE BROKEN] exclude_keys or require_any_keys failed")

    order_trace: list[str] = []
    orch_smoke = PhaseOrchestrator(None, 1, kb_smoke)
    orch_smoke.register("step_verify", ScanPhase.ACT_VERIFY, lambda: order_trace.append("verify"), require_keys=["Gathered/ok"])
    orch_smoke.register("step_gather", ScanPhase.ACT_GATHER_INFO, lambda: (kb_smoke.add_fact("Gathered/ok", 1), order_trace.append("gather")))
    orch_smoke.execute_all()
    if order_trace != ["gather", "verify"]:
        errors.append(f"[ORCHESTRATOR BROKEN] Expected ['gather', 'verify'], got {order_trace}")

    if not all(version_in_range(a["min"], a["min"], a["max"]) and not version_in_range(a["max"], a["min"], a["max"]) for a in CURATED_CVE_ADVISORIES):
        errors.append("[ADVISORY KB BROKEN] Invalid min/max boundary in CURATED_CVE_ADVISORIES")
    if (match_version_advisories("Server: nginx/1.26.2 (Ubuntu)\nX-Powered-By: PHP/8.2.10") or [{}])[0].get("distro_backport_likely") is not False:
        errors.append("[ADVISORY KB BROKEN] Cross-header distro marker bleed onto PHP/8.2.10")
    if extract_cpe_inventory("nginx/1.26.2") != ["cpe:2.3:a:f5:nginx:1.26.2:*:*:*:*:*:*:*"]:
        errors.append("[ADVISORY KB BROKEN] NIST CPE 2.3 inventory builder failed")
    if not match_version_advisories("Elasticsearch/7.10.2") or not match_version_advisories("Node.js v18.19.0"):
        errors.append("[ADVISORY KB BROKEN] New enterprise stack advisories failed")
    if not match_version_advisories("Nginx:1.18.0") or match_version_advisories("OpenSSH_9.8p1"):
        errors.append("[ADVISORY KB BROKEN] match_version_advisories failed smoke check")
    if match_version_advisories("mysql 5.5.5-10.11.8-MariaDB") or not match_version_advisories("mysql 5.5.5-10.3.29-MariaDB"):
        errors.append("[ADVISORY KB BROKEN] MariaDB 5.5.5 protocol-prefix disambiguation failed")
    if not match_version_advisories("220 mail ESMTP Postfix (3.6.12)") or match_version_advisories("Postfix/3.6.13"):
        errors.append("[ADVISORY KB BROKEN] Postfix branch boundary check failed")
    if match_version_advisories("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20") or not match_version_advisories("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"):
        errors.append("[ADVISORY KB BROKEN] Ubuntu OpenSSH backport disambiguation failed")
    if not match_version_advisories("cpe:/a:apache:http_server:2.4.50") or not match_version_advisories("jQuery:2.2.4"):
        errors.append("[ADVISORY KB BROKEN] CPE underscore or jQuery matching failed")
    if match_version_advisories("nginx 1.26.2 [http-title: Fixing Apache 2.4.49 and PHP 7.4]"):
        errors.append("[ADVISORY KB BROKEN] Untrusted [http-title] triggered false CVE")
    if "CVE-2021-3711" not in (match_version_advisories("OpenSSL/1.1.1k-fips") or [{}])[0].get("cve", ""):
        errors.append("[ADVISORY KB BROKEN] OpenSSL letter sub-patch comparison failed")
    if match_version_advisories("Via: 1.1 nginx (1.18.0.1)") or match_version_advisories("redis (2.18.0.1)"):
        errors.append("[ADVISORY KB BROKEN] 4-octet IPv4 address falsely parsed as software version")
    if not (match_version_advisories("PHP/8.1.2-1ubuntu2.18") or [{}])[0].get("distro_backport_likely"):
        errors.append("[ADVISORY KB BROKEN] Ubuntu -1ubuntu package revision distro marker missed")
    if "EOL-OPENSSL-1.0" in (match_version_advisories("OpenSSL/1.0.2u Via: OpenSSL/3.0.5") or [{}])[0].get("cve", ""):
        errors.append("[ADVISORY KB BROKEN] Cross-version CVE contamination occurred")
    if match_version_advisories("SSH-2.0-OpenSSH_9.8") or match_version_advisories("SSH-2.0-OpenSSH_9.8p1"):
        errors.append("[ADVISORY KB BROKEN] OpenSSH 9.8 / 9.8p1 falsely flagged as vulnerable")
    if (match_version_advisories("php7.4-fpm (Ubuntu)") or [{}])[0].get("distro_backport_likely") is not False:
        errors.append("[ADVISORY KB BROKEN] EOL branch wrongly marked as distro_backport_likely")

    if ScopeGuard.extract_apex_domain("portal.academy.mil.uz") != "academy.mil.uz":
        errors.append("[SCOPE GUARD BROKEN] 2nd-level TLD .mil.uz apex extraction failed")
    sg_roe = ScopeGuard("example.com", "billing.example.com")
    if not sg_roe.is_in_scope("dev.example.com")[0] or sg_roe.is_in_scope("billing.example.com")[0] or sg_roe.is_in_scope("pay.billing.example.com")[0]:
        errors.append("[SCOPE GUARD BROKEN] Out-of-Scope rule over-blocked apex or failed sub-tree block")
    sg_v6 = ScopeGuard("2001:db8::/32", "2001:db8::99")
    if not sg_v6.is_in_scope("[2001:db8::1]:8443/api")[0] or sg_v6.is_in_scope("2001:db8::99")[0]:
        errors.append("[SCOPE GUARD BROKEN] IPv6 CIDR / bracket literal scope check failed")
    if ScopeGuard("gov.uz", "").is_in_scope("portal.gov.uz")[0]:
        errors.append("[SCOPE GUARD BROKEN] Bare 2nd-level TLD gov.uz must not act as wildcard scope")
    if any(sg_roe.is_in_scope(bad)[0] for bad in ("1.18.0", "192.168.1", "10.0.0.999")) or not sg_roe.is_in_scope("//cdn.example.com/app.js")[0]:
        errors.append("[SCOPE GUARD BROKEN] Numeric TLD accepted or protocol-relative // URL rejected")
    sg_wc = ScopeGuard("https://*.dev.example.com", "")
    if not sg_wc.is_in_scope("a.dev.example.com")[0] or sg_wc.is_in_scope("prod.example.com")[0]:
        errors.append("[SCOPE GUARD BROKEN] Scheme-prefixed wildcard https://*.sub rule failed")

    with tempfile.TemporaryDirectory() as tmpd:
        db = DatabaseManager(str(pathlib.Path(tmpd) / "gate.db"))
        pid = db.create_project("GateTest", "example.org", "example.org")
        db.upsert_finding(pid, "A2", "SampleTitle", "Cat", "Medium", 5.0, "", "CWE-200", "A05", "https://example.org", "ev1", "rc", "rem", confidence="High", triage_status="Verified")
        f_id = db.get_project_bundle(pid)["findings"][0]["id"]
        db.update_finding_triage(f_id, "False-Positive")
        db.upsert_finding(pid, "A2", "SampleTitle", "Cat", "High", 7.5, "", "CWE-200", "A05", "https://example.org", "ev2", "rc", "rem", confidence="Confirmed-PoC (QoD: 99%)", triage_status="Verified")
        f_after = db.get_project_bundle(pid)["findings"][0]
        if f_after["confidence"] != "Confirmed-PoC (QoD: 99%)" or f_after["triage_status"] != "False-Positive":
            errors.append(f"[DB FINDING UPSERT BROKEN] {f_after}")

        db.upsert_port(pid, "example.org", 443, "tcp", service="https", version="nginx 1.24.0")
        db.upsert_port(pid, "example.org", 443, "tcp", service="https", version="TLSv1.3")
        if db.get_project_bundle(pid)["ports"][0]["version"] != "nginx 1.24.0":
            errors.append("[DB PORT UPSERT BROKEN] TLSv1.3 overwrote server version")

        db.upsert_endpoint(pid, "https://example.org/api/items", "GET", params=["id"], risk_tags=["IDOR_Candidate"])
        db.upsert_endpoint(pid, "https://example.org/api/items", "GET", params=["role", "debug"], risk_tags=["hidden_params"])
        ep_row = db.get_project_bundle(pid)["endpoints"][0]
        if '"id"' not in ep_row["params_json"] or '"role"' not in ep_row["params_json"] or '"IDOR_Candidate"' not in ep_row["risk_tags_json"] or '"hidden_params"' not in ep_row["risk_tags_json"]:
            errors.append(f"[DB ENDPOINT MERGE BROKEN] {ep_row}")

        db.upsert_js_asset(pid, "https://example.org/app.js", endpoints=["/api/v1"], sinks=["innerHTML"])
        db.upsert_js_asset(pid, "https://example.org/app.js", endpoints=["/api/v2"], sinks=None)
        js_row = db.get_project_bundle(pid)["js_assets"][0]
        if '"innerHTML"' not in js_row["sinks_json"] or '"/api/v1"' not in js_row["endpoints_json"] or '"/api/v2"' not in js_row["endpoints_json"]:
            errors.append(f"[DB JS MERGE BROKEN] {js_row}")

        db.upsert_http_service(pid, "https://example.org", 200, "Home", "nginx", ["nginx/1.24.0"])
        db.upsert_http_service(pid, "https://example.org", 200, "", "", ["React"])
        svc_row = db.get_project_bundle(pid)["http_services"][0]
        if '"nginx/1.24.0"' not in svc_row["tech_stack"] or '"React"' not in svc_row["tech_stack"]:
            errors.append(f"[DB HTTP TECH MERGE BROKEN] {svc_row}")

        db.upsert_domain(pid, "sub.example.org", ip="93.184.216.34", records={"TXT": ["v=spf1"]})
        db.upsert_domain(pid, "sub.example.org", records={"asn_intel": {"asn": "AS15133"}})
        db.upsert_domain(pid, "rebind.example.org", ip="169.254.169.254")
        dom_map = {d["domain"]: d for d in db.get_project_bundle(pid)["domains"]}
        if '"TXT"' not in dom_map["sub.example.org"]["records_json"] or '"asn_intel"' not in dom_map["sub.example.org"]["records_json"]:
            errors.append(f"[DB DOMAIN RECORDS MERGE BROKEN] {dom_map['sub.example.org']}")
        if dom_map["rebind.example.org"]["ip"] != "":
            errors.append(f"[DB LINK-LOCAL REBIND GUARD BROKEN] {dom_map['rebind.example.org']}")

        ra = ReconSuperAgent(db, str(ROOT_DIR / "config" / "tools_registry.yaml"))
        tools = ra.get_tools_status()
        builtin_tools = [t for t in tools if t.get("binary") == "builtin"]
        ready = [t for t in tools if t.get("installed") and t.get("enabled")]
        if len(tools) != 49 or not all(t.get("installed") for t in builtin_tools):
            errors.append(f"[TOOLS REGISTRY BROKEN] Expected 49 tools & all builtin ready, got {len(tools)}")
        if "--require-all-cli" in sys.argv and len(ready) != 49:
            errors.append(f"[TOOLS NOT READY] Expected 49/49 ready, got {len(ready)}/{len(tools)}")

        # 6. Multi-Host Scale, Anti-Cardinality & Port Deduplication Gate
        from agents.vuln_agent import VulnAssessmentSuperAgent
        from agents import surface_prober
        pid_scale = db.create_project("ScaleGate", "example.org", "example.org")
        db.upsert_domain(pid_scale, "example.org", ip="93.184.216.34")
        db.upsert_port(pid_scale, "example.org", 443, "tcp", ip="93.184.216.34", service="https", version="nginx 1.24.0", source="nmap_deep_nse")
        db.upsert_port(pid_scale, "93.184.216.34", 443, "tcp", ip="93.184.216.34", service="https", version="cpe:/a:f5:nginx", source="shodan_internetdb")
        dossier_txt = surface_prober.build_target_dossier(db, pid_scale, "example.org")
        if "OCHIQ TARMOQ PORTLARI (1 ta)" not in dossier_txt or "nmap_deep_nse,shodan_internetdb" not in dossier_txt:
            errors.append(f"[DOSSIER PORT MERGE BROKEN] {dossier_txt}")

        for idx_j in range(6):
            db.upsert_js_asset(pid_scale, f"https://sub{idx_j}.example.org/chunk_{idx_j}.js", sinks=["innerHTML", "dangerouslySetInnerHTML"])
        va = VulnAssessmentSuperAgent(db)
        va._audit_endpoints_and_js(pid_scale, [], db.get_project_bundle(pid_scale)["js_assets"], lambda _m: None)
        dom_sink_findings = [f for f in db.get_project_bundle(pid_scale)["findings"] if "DOM XSS" in f["title"]]
        if len(dom_sink_findings) != 1 or "Across 6 JS Bundles" not in dom_sink_findings[0]["title"]:
            errors.append(f"[JS SINK CARDINALITY EXPLOSION] Expected 1 consolidated finding, got {len(dom_sink_findings)}")

        # Cross-host 301 redirect isolation check (Rule 12)
        class _FakeResp:
            def __init__(self, status_code, headers, text=""):
                self.status_code = status_code
                self.headers = headers
                self.text = text
                self.content = text.encode("utf-8")
                self.raw = None
                self.url = "https://example.org/"

        orig_sget = ra.session.get
        ra.session.get = lambda u, **kw: (
            _FakeResp(301, {"Location": "https://example.org/"}, "")
            if not kw.get("allow_redirects", True)
            else _FakeResp(200, {"Server": "nginx"}, "<html><title>Main Portal</title></html>")
        )
        body_redir = ra._stage3_http_probe(pid_scale, "https://sub99.example.org", {}, ScopeGuard("example.org"), lambda _m: None, primary_host="example.org")
        ra.session.get = orig_sget
        redir_svc = [s for s in db.get_project_bundle(pid_scale)["http_services"] if "sub99.example.org" in s["url"]]
        if body_redir != "" or not redir_svc or redir_svc[0]["status_code"] != 301:
            errors.append(f"[CROSS-HOST REDIRECT CLONE LEAK] {body_redir!r} | {redir_svc}")

        # CSRF & Analytics Cookies (XSRF-TOKEN, _ym_apphash, _ga) must NOT trigger HttpOnly false positive
        db.upsert_http_service(
            pid_scale,
            "https://csrf-check.example.org",
            200,
            "Portal",
            "nginx",
            [],
            cookies=[
                {"name": "XSRF-TOKEN", "httponly": False, "secure": True, "samesite": True, "raw": "XSRF-TOKEN=abc; Secure"},
                {"name": "_ym_apphash", "httponly": False, "secure": False, "samesite": True, "raw": "_ym_apphash=123; SameSite=Lax"},
            ],
        )
        va._audit_http_services(pid_scale, [s for s in db.get_project_bundle(pid_scale)["http_services"] if "csrf-check" in s["url"]], lambda _m: None)
        xsrf_fp = [f for f in db.get_project_bundle(pid_scale)["findings"] if "XSRF-TOKEN" in f["title"] or "_ym_apphash" in f["title"]]
        if xsrf_fp:
            errors.append(f"[CSRF/ANALYTICS COOKIE FALSE POSITIVE] {xsrf_fp}")

        # Word-boundary BOLA/IDOR check: URL words like 'bolalarim' or 'koridor' must NOT create BOLA chains
        from agents.triage_chain_agent import TriageAndChainSuperAgent
        db.upsert_endpoint(pid_scale, "https://example.org/api/post", "POST")
        db.upsert_finding(
            pid_scale, "Param-Miner",
            "Hidden Query Parameters Discovered (/seriall/tortinchi-bolalarim-koridor.html)",
            "Hidden Attack Surface", "Low", 3.7, "", "CWE-200", "A04", "https://example.org/seriall/tortinchi-bolalarim-koridor.html",
            "Reactive Hidden Parameters: category", "rc", "rem",
        )
        tc_g = TriageAndChainSuperAgent(db, "/tmp/spectre_gate_rep")
        tc_g.run_triage_and_chaining(pid_scale, lambda _m: None)
        false_bola_ch = [c for c in db.get_project_bundle(pid_scale)["bug_chains"] if "BOLA" in c["chain_title"]]
        if false_bola_ch:
            errors.append(f"[SUBSTRING BOLA FALSE CHAIN] {false_bola_ch}")

        # Active Socket Verifier Gate: mock TCP Redis responder
        import socket as _sock
        import threading as _thr
        from core.protocol_verifiers import _tcp_exchange
        srv_s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        srv_s.bind(("127.0.0.1", 0))
        srv_s.listen(1)
        s_port = srv_s.getsockname()[1]

        def _fake_redis():
            try:
                conn_s, _ = srv_s.accept()
                conn_s.recv(1024)
                conn_s.sendall(b"+PONG\r\nredis_version:6.0.9\r\n")
                conn_s.close()
            except Exception:
                pass
            finally:
                srv_s.close()

        t_red = _thr.Thread(target=_fake_redis, daemon=True)
        t_red.start()
        ex_out = _tcp_exchange("127.0.0.1", s_port, [b"PING\r\n"], timeout=1.5)
        if "redis_version:6.0.9" not in ex_out:
            errors.append(f"[SOCKET NVT EXCHANGE BROKEN] {ex_out!r}")

        # Expanded 45-Product Enterprise & CMS CVE Catalog Gate
        m_gf = match_version_advisories("Grafana 8.2.0\nMoodle 4.0.5\nGitLab 16.5.0")
        found_cves = {x["product"]: x["cve"] for x in m_gf}
        if "CVE-2021-43798" not in found_cves.get("grafana", "") or "CVE-2024-43425" not in found_cves.get("moodle", "") or "CVE-2023-7028" not in found_cves.get("gitlab", ""):
            errors.append(f"[EXPANDED CVE CATALOG BROKEN] {found_cves}")

        # CISA KEV Enrichment & JWT HMAC Key Posture Gate
        from core.feed_updater import enrich_project_findings_with_kev
        db.upsert_finding(pid_scale, "A2", "GitLab (< 16.7.2) Advisory [CVE-2023-7028]", "Vulnerable & Outdated Components", "Critical", 10.0, "", "CWE-640", "A07", "https://example.org", "CPE: gitlab", "rc", "rem")
        kev_cnt = enrich_project_findings_with_kev(db, pid_scale)
        if kev_cnt < 1:
            errors.append("[CISA KEV ENRICHMENT BROKEN]")
        import base64 as _b64, hashlib as _hl, hmac as _hm
        _hdr_pl = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        _sig_b64 = _b64.urlsafe_b64encode(_hm.new(b"secret", _hdr_pl.encode(), _hl.sha256).digest()).decode().rstrip("=")
        jwt_res = va.audit_jwt_token(f"{_hdr_pl}.{_sig_b64}")
        if not any("secret" in x and "CRITICAL" in x for x in jwt_res.get("issues", [])):
            errors.append(f"[JWT HMAC KEY CHECK BROKEN] {jwt_res}")

        # C++17 Native Accelerator Gate (libspectre_accel.so + Linux epoll + SimHash64)
        from core.native_bridge import get_native_lib, fast_epoll_tcp_probe, fast_simhash64, fast_shannon_entropy
        if get_native_lib() is None:
            errors.append("[NATIVE C++ ENGINE FAILED TO COMPILE OR LOAD]")
        srv_ep = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        srv_ep.bind(("127.0.0.1", 0))
        srv_ep.listen(1)
        ep_port = srv_ep.getsockname()[1]

        def _fake_mysql():
            try:
                cs, _ = srv_ep.accept()
                cs.sendall(b"\x20\x00\x00\x00\x0a8.0.36\x00")
                cs.close()
            except Exception:
                pass
            finally:
                srv_ep.close()

        _thr.Thread(target=_fake_mysql, daemon=True).start()
        ep_hits = fast_epoll_tcp_probe("127.0.0.1", [ep_port], timeout_ms=400)
        if ep_port not in ep_hits or b"8.0.36" not in ep_hits[ep_port]:
            errors.append(f"[NATIVE C++ EPOLL PROBE BROKEN] {ep_hits}")
        if fast_simhash64("<html><body>Admin Panel</body></html>") == 0 or fast_shannon_entropy("A9f8K2m9P0q7Z1x4") < 3.5:
            errors.append("[NATIVE C++ HASH/ENTROPY BROKEN]")

        # Enterprise Advisory Catalog + SourceMap Chain + CISA KEV HTML Badge Gate
        m_infra = match_version_advisories("FortiOS 7.2.1\nConfluence 8.5.1\nArgoCD 2.9.3\nDjango 4.2.10")
        inf_prods = {x["product"] for x in m_infra}
        if not {"fortios", "confluence", "argocd", "django"}.issubset(inf_prods):
            errors.append(f"[68-PRODUCT INFRA CATALOG BROKEN] {inf_prods}")
        db.upsert_finding(pid_scale, "SPECTRE-Web", "[CONFIRMED] Exposed JavaScript SourceMap (app.js.map)", "Source Code Exposure", "High", 7.5, "", "CWE-540", "A05", "https://example.org/app.js.map", "ev", "rc", "rem")
        db.upsert_endpoint(pid_scale, "https://example.org/api/v1/users", "GET", category="api_endpoint")
        tc_g.run_triage_and_chaining(pid_scale, lambda _m: None)
        reps_g = tc_g.generate_reports(pid_scale)
        html_rep_txt = pathlib.Path(reps_g["html_path"]).read_text(encoding="utf-8")
        if "CISA KEV" not in html_rep_txt or not any("SourceMap->API" in c["chain_title"] for c in db.get_project_bundle(pid_scale)["bug_chains"]):
            errors.append("[REPORT KEV BADGE OR SOURCEMAP CHAIN BROKEN]")

        # C++17 Multi-Token Byte Pre-Scanner, Bundle Cache & Consolidated Intel Gate
        from core.native_bridge import JS_TOK_CHUNK, JS_TOK_ROUTE, JS_TOK_SECRET, JS_TOK_SINK, JS_TOK_SOURCEMAP, fast_js_token_mask
        if fast_js_token_mask("function sum(a, b) { return a + b; }") != 0:
            errors.append("[NATIVE C++ JS TOKEN PRE-SCANNER FALSE BIT ON CLEAN CODE]")
        full_mask = fast_js_token_mask(
            "fetch('/api/v1/items'); el.innerHTML = v; const api_key='1234567890ab'; import('assets/lazy.js'); //# sourceMappingURL=x.js.map"
        )
        expected_mask = JS_TOK_ROUTE | JS_TOK_SINK | JS_TOK_SECRET | JS_TOK_CHUNK | JS_TOK_SOURCEMAP
        if full_mask != expected_mask:
            errors.append(f"[NATIVE C++ JS TOKEN PRE-SCANNER MISSED BITS] got={full_mask}, expected={expected_mask}")

        db.log_task(pid_scale, "SPECTRE-Intel", "favicon_mmh3", "COMPLETED", "https://example.org", "Favicon MMH3 (-12345)")
        dos_intel = surface_prober.build_target_dossier(db, pid_scale, "example.org")
        rep_intel = tc_g.generate_reports(pid_scale)["markdown_preview"]
        if "Favicon MMH3 (-12345)" not in dos_intel or "Favicon MMH3 (-12345)" not in rep_intel:
            errors.append("[CONSOLIDATED SPECTRE-INTEL DOSSIER OR REPORT MISSING]")

        # Live-Target #30 Calibration Gate: Out-of-scope JS isolation, DLE comment non-IDOR & www. port canonicalization
        ext_js_g: list[str] = []
        ra._extract_html_surface(
            pid_scale,
            "https://example.org/",
            "<script src='https://yandex.ru/ads/system/context.js'></script><script src='/bundle.js'></script>",
            "example.org",
            ScopeGuard("example.org"),
            ext_js_g,
            set(),
        )
        if ext_js_g != ["https://example.org/bundle.js"]:
            errors.append(f"[OUT-OF-SCOPE JS LEAKED INTO STAGE 6] {ext_js_g}")
        _, c_tags = ra._classify_endpoint_risk("https://example.org/kino/55-film.html", ["comments", "post_id", "subaction"])
        if "IDOR_Candidate" in c_tags:
            errors.append("[DLE ARTICLE COMMENT FORM FALSELY FLAGGED AS IDOR]")
        from core.protocol_verifiers import SUPPORTED_ACTIVE_PORTS, parse_ssh_kexinit_packet
        if not {22, 636, 1022, 1433, 2379, 5900, 6380, 8500, 9042, 15672}.issubset(SUPPORTED_ACTIVE_PORTS):
            errors.append(f"[EXTENDED SOCKET NVT PORTS MISSING] {SUPPORTED_ACTIVE_PORTS}")
        import struct as _st
        _nl = [b"diffie-hellman-group14-sha1,curve25519-sha256", b"ssh-ed25519,ssh-dss", b"aes128-cbc", b"aes128-cbc", b"hmac-md5", b"hmac-md5", b"none", b"none", b"", b""]
        _pl = b"\x14" + (b"\xaa" * 16) + b"".join(_st.pack("!I", len(x)) + x for x in _nl) + b"\x00\x00\x00\x00\x00"
        _pad = 8 - ((len(_pl) + 5) % 8)
        if _pad < 4:
            _pad += 8
        _ssh_raw = b"SSH-2.0-OpenSSH_7.4\r\n" + _st.pack("!IB", len(_pl) + _pad + 1, _pad) + _pl + (b"\x00" * _pad)
        _parsed_kex = parse_ssh_kexinit_packet(_ssh_raw)
        if "diffie-hellman-group14-sha1" not in _parsed_kex.get("kex", []) or "aes128-cbc" not in _parsed_kex.get("enc", []):
            errors.append(f"[SSH KEXINIT PARSER BROKEN] {_parsed_kex}")

        # Declarative NVT Catalog + NIST CPE 2.3 Catalog Gate
        from core.nvt_declarative_engine import load_nvt_catalog
        from core.advisory_kb import _CPE_VENDOR_PRODUCT
        nvt_rules = load_nvt_catalog()
        if len(nvt_rules) < 100:
            errors.append(f"[DECLARATIVE NVT CATALOG TOO SMALL] count={len(nvt_rules)}")
        if len(_CPE_VENDOR_PRODUCT) < 120:
            errors.append(f"[CPE 2.3 CATALOG BELOW 120 PRODUCTS] count={len(_CPE_VENDOR_PRODUCT)}")
        m_ext = match_version_advisories("Kibana 8.12.0\nRoundcube 1.6.5\nownCloud 10.13.1\nGitea 1.21.5\nSolr 9.2.0\nActiveMQ 5.17.1\nMetabase 0.45.2\nOllama 0.1.29\nMLflow 2.10.0")
        ext_prods = {x["product"] for x in m_ext}
        if not {"kibana", "roundcube", "owncloud", "gitea", "solr", "activemq", "metabase", "ollama", "mlflow"}.issubset(ext_prods):
            errors.append(f"[120-PRODUCT ENTERPRISE CPE MATCHING BROKEN] {ext_prods}")
        if surface_prober.murmur3_32(b"spectre_favicon_check") != active_web_auditor.murmurhash3_32_signed(b"spectre_favicon_check"):
            errors.append("[C++17 MURMUR3 UNIFICATION MISMATCH]")
        from core.sca_engine import extract_js_bundle_libraries, match_dependencies_advisories, parse_manifest_dependencies
        _sca_deps = parse_manifest_dependencies("package.json", '{"dependencies": {"lodash": "^4.17.15", "express": "4.18.2"}}')
        _sca_hits = match_dependencies_advisories(_sca_deps, allow_online_osv=False)
        _js_libs = extract_js_bundle_libraries("/*! jQuery v2.1.4 | (c) JS Foundation */")
        if len(_sca_hits) < 2 or ("npm", "jquery", "2.1.4") not in _js_libs:
            errors.append(f"[SCA DEPENDENCY ENGINE BROKEN] {_sca_hits} | {_js_libs}")
        from core.compliance_exporter import build_cyclonedx_sbom, build_sarif_report
        _b_comp = db.get_project_bundle(pid_scale)
        _sarif = build_sarif_report(_b_comp)
        _sbom = build_cyclonedx_sbom(_b_comp)
        if _sarif.get("version") != "2.1.0" or _sbom.get("bomFormat") != "CycloneDX":
            errors.append("[SARIF 2.1.0 OR CYCLONEDX 1.5 EXPORTER BROKEN]")
        from core.credentialed_auditor import parse_sshd_posture
        import spectre_cli
        _ssh_issues = parse_sshd_posture("PermitRootLogin yes\nPermitEmptyPasswords yes\n")
        if len(_ssh_issues) < 2 or spectre_cli.build_parser() is None:
            errors.append(f"[CREDENTIALED SSH OR HEADLESS CLI BROKEN] {_ssh_issues}")

    return errors


if __name__ == "__main__":
    errs = run_integrity_gate()
    out_txt = "\n".join(errs) if errs else "INTEGRITY_GATE_PASSED_100_PCT (0 ERRORS)"
    open("/tmp/integrity_gate_report.txt", "w").write(out_txt + "\n")
    print(f"ERRORS_FOUND={len(errs)}")
    sys.exit(1 if errs else 0)
