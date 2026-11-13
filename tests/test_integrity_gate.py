"""
SPECTRE v12.3 — Automated AST, Signature, Schema & Runtime Integrity Gate
=========================================================================
Run before every commit to guarantee zero hallucinated keys, zero mismatched
function signatures, zero deprecated calls, and 49/49 tool readiness.
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
    spectre_deep_modules,
    spectre_v5_modules,
    spectre_ultra_modules,
    spectre_predator_modules,
    spectre_v10_modules,
    spectre_v11_modules,
    spectre_v12_modules,
)

MODULE_MAP = {
    "spectre_deep_modules": spectre_deep_modules,
    "spectre_v5_modules": spectre_v5_modules,
    "spectre_ultra_modules": spectre_ultra_modules,
    "spectre_predator_modules": spectre_predator_modules,
    "spectre_v10_modules": spectre_v10_modules,
    "spectre_v11_modules": spectre_v11_modules,
    "spectre_v12_modules": spectre_v12_modules,
}


def run_integrity_gate() -> list[str]:
    errors: list[str] = []
    py_files = sorted(ROOT_DIR.rglob("*.py"))

    for pf in py_files:
        if "tests/" in str(pf):
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

        ra = ReconSuperAgent(db, str(ROOT_DIR / "config" / "tools_registry.yaml"))
        tools = ra.get_tools_status()
        ready = [t for t in tools if t.get("installed") and t.get("enabled")]
        if len(ready) != 49:
            errors.append(f"[TOOLS NOT READY] Expected 49/49 ready, got {len(ready)}/{len(tools)}")

    return errors


if __name__ == "__main__":
    errs = run_integrity_gate()
    out_txt = "\n".join(errs) if errs else "INTEGRITY_GATE_PASSED_100_PCT (0 ERRORS)"
    open("/tmp/integrity_gate_report.txt", "w").write(out_txt + "\n")
    print(f"ERRORS_FOUND={len(errs)}")
    sys.exit(1 if errs else 0)
