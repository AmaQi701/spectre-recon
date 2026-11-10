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

    # 5. Runtime Smoke Check of DB, ScopeGuard, and 49/49 Tools
    with tempfile.TemporaryDirectory() as tmpd:
        db = DatabaseManager(str(pathlib.Path(tmpd) / "gate.db"))
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
