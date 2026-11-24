#!/usr/bin/env python3
"""
SPECTRE Autonomous Headless CLI & CI/CD Security Runner (`spectre_cli.py`)
==========================================================================
Executes the full 3-phase reconnaissance, NVT/AI/SCA/SAST verification,
attack-graph chaining, and SARIF 2.1.0 / CycloneDX 1.5 SBOM reporting pipeline
on headless Linux servers, SSH sessions, Docker containers, and CI/CD runners.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from agents import cli_orchestrator
from agents.recon_agent import ReconSuperAgent
from agents.triage_chain_agent import TriageAndChainSuperAgent
from agents.vuln_agent import VulnAssessmentSuperAgent
from core.credentialed_auditor import run_credentialed_ssh_audit
from core.database import DatabaseManager
from core.scope_guard import ScopeGuard

SEV_RANK = {"none": 99, "low": 1, "medium": 2, "high": 3, "critical": 4}
FIND_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SPECTRE Headless Enterprise Recon, NVT & SARIF/SBOM CLI v8.2.0")
    p.add_argument("-t", "--target", default="", help="Primary target domain, host, or URL (required unless --export-project/--benchmark/--doctor)")
    p.add_argument("--export-project", type=int, default=0, help="Re-generate HTML/SARIF/SBOM/JUnit/Compliance artifacts for an existing project ID without re-scanning")
    p.add_argument("--benchmark", action="store_true", help="Run live 1 MB C++17 libspectre_accel.so throughput benchmark and exit")
    p.add_argument("--doctor", action="store_true", help="Verify C++17 kernel, SQLite WAL DB, 250-NVT/CPE catalogs, 50-port verifiers, and CLI tools")
    p.add_argument("-n", "--name", default="", help="Project name (defaults to target host)")
    p.add_argument("--in-scope", default="", help="Comma/newline-separated in-scope rules")
    p.add_argument("--out-of-scope", default="", help="Comma/newline-separated out-of-scope rules")
    p.add_argument("--source-path", default="", help="Optional local source directory for White-Box SAST & SCA")
    p.add_argument("--auth-a", default="", help="Primary Role-A header or Cookie")
    p.add_argument("--auth-b", default="", help="Secondary Role-B header for Multi-Role BOLA matrix")
    p.add_argument("--proxy", default="", help="Outbound HTTP/SOCKS proxy URL")
    p.add_argument("--ssh-audit", default="", help="Optional user@host[:port] for read-only SSH CIS/package audit")
    p.add_argument("--ssh-key", default="", help="Optional SSH private key path for --ssh-audit")
    p.add_argument("--mode", choices=("full", "subdomains", "ports", "web_js"), default="full")
    p.add_argument("--no-cli", action="store_true", help="Disable external CLI binaries (100%% built-in C++/Python mode)")
    p.add_argument("--db", default=str(BASE_DIR / "workspaces" / "apex_state.db"), help="SQLite state DB path")
    p.add_argument("--reports-dir", default=str(BASE_DIR / "reports"), help="Output directory for HTML/MD/SARIF/SBOM/JUnit")
    p.add_argument("--diff-project", type=int, default=0, help="Compare attack-surface & finding drift against baseline project ID")
    p.add_argument("--min-qod", type=int, default=0, help="Minimum QoD %% (e.g. 90) counted toward --fail-on CI exit gate")
    p.add_argument("--fail-on-drift", action="store_true", help="Return exit code 3 if new High/Critical drift is detected vs --diff-project")
    p.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="none", help="CI/CD exit code 2 gate")
    return p


def _extract_qod_pct(conf_str: str) -> int:
    m = re.search(r"QoD:\s*(\d+)%", str(conf_str or ""))
    return int(m.group(1)) if m else 80


def _run_live_cpp_benchmark() -> int:
    from core.native_bridge import (
        fast_js_token_mask,
        fast_mmh3_signed,
        fast_secret_prefilter_mask,
        fast_structural_hash,
        get_native_lib,
    )
    lib = get_native_lib()
    buf = (b"fetch('/api/v1/accounts'); el.innerHTML = x; AKIA1234567890ABCDEF sk-ant-api03-test0011223344556677889900\n") * 10000
    mb = len(buf) / (1024.0 * 1024.0)

    def _rate(fn, iters: int = 8) -> float:
        t0 = time.perf_counter()
        for _ in range(iters):
            fn(buf)
        return (mb * iters) / max(1e-6, time.perf_counter() - t0)

    r_mmh = _rate(fast_mmh3_signed)
    r_sec = _rate(fast_secret_prefilter_mask)
    r_tok = _rate(fast_js_token_mask)
    r_str = _rate(fast_structural_hash, iters=4)
    print(f"SPECTRE v8.2.0 Hybrid C++17 Kernel Benchmark (CppLoaded={lib is not None})")
    print("=" * 72)
    print(f"  1. C++17 MurmurHash3 (Favicon/Asset Fingerprint) : {r_mmh:8.1f} MB/s")
    print(f"  2. C++17 Secret & AI Key Pre-Filter Mask         : {r_sec:8.1f} MB/s")
    print(f"  3. C++17 JS Route/Sink/SourceMap Token Scanner   : {r_tok:8.1f} MB/s")
    print(f"  4. C++17 Structural DOM/JSON Soft-200 Skeleton   : {r_str:8.1f} MB/s")
    print("=" * 72)
    return 0 if lib is not None else 1


def _run_doctor_diagnostics(db_path: str) -> int:
    from core.advisory_kb import _CPE_VENDOR_PRODUCT
    from core.native_bridge import get_native_lib
    from core.nvt_declarative_engine import load_nvt_catalog
    from core.protocol_verifiers import SUPPORTED_ACTIVE_PORTS
    from core.sca_engine import OFFLINE_SCA_RULES, SUPPORTED_MANIFEST_NAMES

    cpp_ok = get_native_lib() is not None
    nvts = len(load_nvt_catalog())
    cpes = len(_CPE_VENDOR_PRODUCT)
    ports_n = len(SUPPORTED_ACTIVE_PORTS)
    sca_n = len(OFFLINE_SCA_RULES)
    man_n = len(SUPPORTED_MANIFEST_NAMES)
    db_chk = DatabaseManager(db_path)
    projs = len(db_chk.get_projects())
    print(
        f"SPECTRE_DOCTOR_OK | CppKernel={cpp_ok} | NVTs={nvts} | CPEs={cpes} "
        f"| ActivePorts={ports_n} | SCAFormats={man_n}+csproj | SCARules={sca_n} | DBProjects={projs}"
    )
    return 0 if (cpp_ok and nvts >= 250 and cpes >= 250 and ports_n >= 50) else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.benchmark:
        return _run_live_cpp_benchmark()
    if args.doctor:
        return _run_doctor_diagnostics(args.db)

    def _log(msg: str) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    db = DatabaseManager(args.db)
    triage = TriageAndChainSuperAgent(db, args.reports_dir)

    if args.export_project > 0:
        pid = int(args.export_project)
        b_ex = db.get_project_bundle(pid)
        if not b_ex.get("project"):
            print(f"[ERR] Project ID {pid} not found in DB.", file=sys.stderr)
            return 1
        triage.run_triage_and_chaining(pid, _log)
        rep = triage.generate_reports(pid)
        art = cli_orchestrator.export_project_artifacts(db, pid, reports_dir=args.reports_dir)
        _log(f"[EXPORT-ONLY COMPLETE] HTML: {rep['html_path']} | SARIF: {art['sarif_json']} | Compliance: {art['compliance_matrix_json']}")
        if args.diff_project > 0:
            from core.surface_diff_engine import compute_project_diff, format_diff_report_text
            diff_obj = compute_project_diff(db.get_project_bundle(args.diff_project), db.get_project_bundle(pid))
            _log("\n" + format_diff_report_text(diff_obj))
            if args.fail_on_drift and diff_obj["drift_level"] in ("CRITICAL_DRIFT", "HIGH_DRIFT"):
                return 3
        if args.fail_on != "none":
            thresh = SEV_RANK[args.fail_on]
            finds = db.get_project_bundle(pid).get("findings", [])
            if any(
                FIND_RANK.get(str(f.get("severity") or ""), 0) >= thresh
                and _extract_qod_pct(str(f.get("confidence") or "")) >= int(args.min_qod)
                for f in finds if f.get("triage_status") != "False-Positive"
            ):
                return 2
        return 0

    target = ScopeGuard.extract_host(args.target)
    if not target:
        print("[ERR] Invalid --target specified.", file=sys.stderr)
        return 1

    apex = ScopeGuard.extract_apex_domain(target)
    in_sc = args.in_scope.strip() or "\n".join(dict.fromkeys([target, apex, f"*.{apex}"]))
    pid = db.create_project(args.name or target, target, in_sc, args.out_of_scope, args.source_path)

    recon = ReconSuperAgent(db, str(BASE_DIR / "config" / "tools_registry.yaml"))
    if args.auth_a.strip():
        if ":" in args.auth_a:
            hk, hv = args.auth_a.split(":", 1)
            recon.session.headers[hk.strip()] = hv.strip()
        else:
            recon.session.headers["Cookie"] = args.auth_a.strip()
    if args.proxy.strip():
        recon.session.proxies.update({"http": args.proxy.strip(), "https": args.proxy.strip()})

    vuln = VulnAssessmentSuperAgent(db, shared_session=recon.session)
    vuln.configure_context(primary_auth=args.auth_a, secondary_auth=args.auth_b, proxy_url=args.proxy)

    try:
        active_override = [] if args.no_cli else None
        recon.run_full_recon(pid, active_override, _log, recon_mode=args.mode)
        if args.ssh_audit.strip():
            run_credentialed_ssh_audit(db, pid, args.ssh_audit.strip(), _log, ssh_key=args.ssh_key.strip())
        vuln.run_assessment(
            pid,
            _log,
            enable_cli=not args.no_cli,
            progress_fn=lambda f, m: _log(f"[PROGRESS {int(f * 100)}%] {m}"),
        )
        triage.run_triage_and_chaining(pid, _log)
        rep = triage.generate_reports(pid)
        art = cli_orchestrator.export_project_artifacts(db, pid, reports_dir=args.reports_dir)
        _log(
            f"[COMPLETE] HTML: {rep['html_path']} | SARIF: {art['sarif_json']} "
            f"| SBOM: {art['cyclonedx_sbom_json']} | JUnit: {art['junit_xml']} | Compliance: {art['compliance_matrix_json']}"
        )
        if args.diff_project > 0:
            from core.surface_diff_engine import compute_project_diff, format_diff_report_text
            base_b = db.get_project_bundle(args.diff_project)
            curr_b = db.get_project_bundle(pid)
            diff_obj = compute_project_diff(base_b, curr_b)
            diff_path = Path(args.reports_dir) / f"project_{pid}_vs_{args.diff_project}_drift.json"
            diff_path.write_text(json.dumps(diff_obj, indent=2, ensure_ascii=False), encoding="utf-8")
            _log("\n" + format_diff_report_text(diff_obj))
            if args.fail_on_drift and diff_obj["drift_level"] in ("CRITICAL_DRIFT", "HIGH_DRIFT"):
                return 3
    except KeyboardInterrupt:
        recon.abort_project(pid, _log)
        return 130

    if args.fail_on != "none":
        thresh = SEV_RANK[args.fail_on]
        finds = db.get_project_bundle(pid).get("findings", [])
        if any(
            FIND_RANK.get(str(f.get("severity") or ""), 0) >= thresh
            and _extract_qod_pct(str(f.get("confidence") or "")) >= int(args.min_qod)
            for f in finds if f.get("triage_status") != "False-Positive"
        ):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
