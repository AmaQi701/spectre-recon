"""
SPECTRE — KB-Driven Phased Orchestrator, QoD Standard & Fault-Isolated Plugin Runner
====================================================================================
"""

from __future__ import annotations

import json
import re
import threading
import time
import traceback
from typing import Any, Callable, Iterable

from core.native_bridge import fast_topological_waves


class ScanPhase:
    """Ordered lifecycle phases for reconnaissance and security posture verification."""

    ACT_INIT = "ACT_INIT"
    ACT_SCANNER = "ACT_SCANNER"
    ACT_SETTINGS = "ACT_SETTINGS"
    ACT_GATHER_INFO = "ACT_GATHER_INFO"
    ACT_VERIFY = "ACT_VERIFY"
    ACT_END = "ACT_END"

    ORDER: dict[str, int] = {
        ACT_INIT: 10,
        ACT_SCANNER: 20,
        ACT_SETTINGS: 30,
        ACT_GATHER_INFO: 40,
        ACT_VERIFY: 50,
        ACT_END: 60,
    }


class QoD:
    """Quality of Detection (%) labels stored in `findings.confidence`."""

    ACTIVE_VERIFIED = "Confirmed-PoC (QoD: 99%)"
    PROTOCOL_VERIFIED = "Confirmed-PoC (QoD: 95%)"
    HEADER_CONFIG = "High (QoD: 90%)"
    BANNER_CVE = "Banner-CVE (QoD: 75%)"
    STATIC_SAST = "Static-SAST (QoD: 70%)"
    HEURISTIC = "Manual-Review (QoD: 60%)"


class ScanContextKB:
    """Central Knowledge Base (KB) supporting O(1) `require_keys` & `require_ports` gating."""

    def __init__(self, project_id: int, primary_host: str = "", apex_domain: str = ""):
        self.project_id = project_id
        self.primary_host = primary_host
        self.apex_domain = apex_domain
        self._lock = threading.RLock()
        self._facts: dict[str, set[Any]] = {}
        self._kv: dict[str, Any] = {}
        self.skipped_plugins: int = 0
        self.executed_plugins: int = 0

    def set_value(self, key: str, value: Any) -> None:
        with self._lock:
            self._kv[key] = value

    def get_value(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._kv.get(key, default)

    def add_fact(self, category: str, item: Any) -> None:
        with self._lock:
            self._facts.setdefault(category, set()).add(item)

    def get_facts(self, category: str) -> list[Any]:
        with self._lock:
            return sorted(self._facts.get(category, set()), key=str)

    def has_fact(self, category: str, item: Any = None) -> bool:
        with self._lock:
            if item is None:
                return bool(self._facts.get(category)) or bool(self._kv.get(category))
            return item in self._facts.get(category, set())

    def matches_key_expr(self, expr: str) -> bool:
        """Evaluates plain KB keys (`Services/www`) or regex predicates (`Tech/detected=nginx|apache`)."""
        raw = str(expr or "").strip()
        if not raw:
            return False
        with self._lock:
            if "=" not in raw:
                return self.has_fact(raw)
            key_part, pat_part = raw.split("=", 1)
            key_part = key_part.strip()
            pat_part = pat_part.strip()
            candidates: list[str] = [str(x) for x in self._facts.get(key_part, set()) if x is not None]
            if key_part in self._kv and self._kv[key_part] is not None:
                candidates.append(str(self._kv[key_part]))
            if not candidates:
                return False
            try:
                cre = re.compile(pat_part, re.IGNORECASE)
                return any(bool(cre.search(val)) for val in candidates)
            except re.error:
                low_p = pat_part.lower()
                return any(low_p in val.lower() for val in candidates)

    def hydrate_from_bundle(
        self, bundle: dict[str, Any], has_auth_a: bool = False, has_auth_b: bool = False
    ) -> None:
        proj = bundle.get("project") or {}
        if proj.get("primary_target") and not self.primary_host:
            self.primary_host = str(proj.get("primary_target", ""))
        if proj.get("source_code_path"):
            self.set_value("Source/local_path", str(proj["source_code_path"]))
        for d in bundle.get("domains", []):
            if d.get("domain"):
                self.add_fact("Host/domains", str(d["domain"]).strip())
            if d.get("cdn_waf"):
                self.add_fact("Host/waf", str(d["cdn_waf"]))
        for pt in bundle.get("ports", []):
            pnum = int(pt.get("port") or 0)
            proto = str(pt.get("protocol") or "tcp").lower()
            if pnum > 0:
                self.add_fact(f"Ports/{proto}", pnum)
                b_str = " ".join(
                    x for x in (str(pt.get("service") or ""), str(pt.get("version") or ""), str(pt.get("banner") or "")) if x
                ).strip()
                if b_str:
                    self.add_fact(f"Banner/{proto}/{pnum}", f"{pt.get('host', '')}:{pnum} | {b_str}")
        for svc in bundle.get("http_services", []):
            if svc.get("url"):
                self.add_fact("Services/www", str(svc["url"]).strip())
            if svc.get("server"):
                self.add_fact("Tech/detected", str(svc["server"]).strip())
            for t_item in json.loads(svc.get("tech_stack") or "[]"):
                if t_item:
                    self.add_fact("Tech/detected", str(t_item))
        for ep in bundle.get("endpoints", []):
            u = str(ep.get("url") or "").strip()
            if not u:
                continue
            self.add_fact("Endpoints/all", u)
            if json.loads(ep.get("params_json") or "[]"):
                self.add_fact("Endpoints/parameterized", u)
            if str(ep.get("category") or "") in ("api_endpoint", "high_value_endpoint") or "IDOR_Candidate" in str(ep.get("risk_tags_json") or ""):
                self.add_fact("Endpoints/api", u)
        for js in bundle.get("js_assets", []):
            if js.get("js_url"):
                self.add_fact("JS/assets", str(js["js_url"]).strip())
        if has_auth_a:
            self.set_value("Auth/role_a", True)
        if has_auth_b:
            self.set_value("Auth/role_b", True)

    def check_gate(
        self,
        require_keys: Iterable[str] | None = None,
        require_ports: Iterable[int] | None = None,
        require_any_keys: Iterable[str] | None = None,
        exclude_keys: Iterable[str] | None = None,
    ) -> tuple[bool, str]:
        with self._lock:
            if exclude_keys:
                for ek in exclude_keys:
                    if self.matches_key_expr(ek):
                        return False, f"excluded_kb_key:{ek}"
            if require_keys:
                for rk in require_keys:
                    if not self.matches_key_expr(rk):
                        return False, f"missing_kb_key:{rk}"
            if require_any_keys:
                any_list = list(require_any_keys)
                if any_list and not any(self.matches_key_expr(rk) for rk in any_list):
                    return False, f"missing_any_kb_key:{any_list}"
            if require_ports:
                open_all = self._facts.get("Ports/tcp", set()) | self._facts.get("Ports/udp", set())
                if not any(int(rp) in open_all for rp in require_ports):
                    return False, f"missing_port:{list(require_ports)}"
        return True, "OK"


def run_plugin_safely(
    db,
    project_id: int,
    plugin_name: str,
    fn: Callable[..., Any],
    *args: Any,
    log_fn: Callable[[str], None] | None = None,
    kb: ScanContextKB | None = None,
    require_keys: Iterable[str] | None = None,
    require_ports: Iterable[int] | None = None,
    require_any_keys: Iterable[str] | None = None,
    exclude_keys: Iterable[str] | None = None,
    phase: str = ScanPhase.ACT_GATHER_INFO,
    **kwargs: Any,
) -> Any:
    """
    Executes a reconnaissance or audit plugin inside an isolated fault boundary.
    Enforces optional KB gating (`require_keys`, `require_any_keys`, `exclude_keys`, `require_ports`).
    """
    if kb is not None and (require_keys or require_ports or require_any_keys or exclude_keys):
        ok, _ = kb.check_gate(
            require_keys=require_keys,
            require_ports=require_ports,
            require_any_keys=require_any_keys,
            exclude_keys=exclude_keys,
        )
        if not ok:
            with kb._lock:
                kb.skipped_plugins += 1
            return None

    t0 = time.monotonic()
    try:
        if kb is not None:
            with kb._lock:
                kb.executed_plugins += 1
        result = fn(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if elapsed_ms >= 500:
            db.log_task(
                project_id,
                f"SPECTRE-{phase}",
                plugin_name,
                "COMPLETED",
                fn.__name__,
                f"Completed in {elapsed_ms} ms | Result: {str(result)[:120]}",
            )
        return result
    except Exception as ex:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        tb_short = " | ".join(traceback.format_exc().splitlines()[-3:])
        err_summary = f"Exception after {elapsed_ms} ms: {ex} ({tb_short[:220]})"
        try:
            db.log_task(
                project_id,
                f"SPECTRE-{phase}",
                plugin_name,
                "PLUGIN_ERROR",
                fn.__name__,
                err_summary,
            )
        except Exception:
            pass
        if log_fn:
            log_fn(f"  [PLUGIN-ISOLATED-ERROR] {plugin_name}: {ex}")
        return None


def compute_topological_waves(
    task_specs: Iterable[tuple[str, Iterable[str] | None]],
) -> list[list[str]]:
    """
    Groups named tasks into deterministic topological execution waves (Kahn DAG algorithm).
    Raises `ValueError` if a cyclic dependency exists among registered task names.
    """
    ordered_names: list[str] = []
    raw_deps: dict[str, list[str]] = {}
    for name, deps in task_specs:
        t_name = str(name)
        if t_name not in raw_deps:
            ordered_names.append(t_name)
            raw_deps[t_name] = [str(d) for d in (deps or []) if str(d)]
        else:
            for d in (deps or []):
                if str(d) and str(d) not in raw_deps[t_name]:
                    raw_deps[t_name].append(str(d))

    rs_waves = fast_topological_waves([(n, raw_deps[n]) for n in ordered_names])
    if rs_waves is not None:
        return rs_waves

    known = set(ordered_names)
    in_deg: dict[str, int] = {}
    dependents: dict[str, list[str]] = {n: [] for n in ordered_names}
    for n in ordered_names:
        valid_deps = [d for d in raw_deps[n] if d in known]
        in_deg[n] = len(valid_deps)
        for d in valid_deps:
            dependents[d].append(n)

    rank = {n: idx for idx, n in enumerate(ordered_names)}
    ready = sorted([n for n in ordered_names if in_deg[n] == 0], key=lambda x: rank[x])
    waves: list[list[str]] = []
    visited = 0

    while ready:
        current_wave = list(ready)
        waves.append(current_wave)
        visited += len(current_wave)
        next_ready: list[str] = []
        for done_node in current_wave:
            for child in dependents[done_node]:
                in_deg[child] -= 1
                if in_deg[child] == 0:
                    next_ready.append(child)
        ready = sorted(next_ready, key=lambda x: rank[x])

    if visited != len(ordered_names):
        cyclic = [n for n in ordered_names if in_deg[n] > 0]
        raise ValueError(f"Cyclic plugin dependency detected: {', '.join(cyclic)}")
    return waves


class PhaseOrchestrator:
    """
    Deterministic phased + DAG wave scheduler.
    Executes registered plugins strictly in `ScanPhase.ORDER` and topological `depends_on` waves,
    evaluating `ScanContextKB` gates dynamically at execution time.
    """

    def __init__(
        self,
        db: Any,
        project_id: int,
        kb: ScanContextKB,
        log_fn: Callable[[str], None] | None = None,
    ) -> None:
        self.db = db
        self.project_id = project_id
        self.kb = kb
        self.log_fn = log_fn
        self._tasks: list[tuple[int, int, str, str, Callable[..., Any], tuple[Any, ...], dict[str, Any], dict[str, Any], list[str]]] = []
        self._seq = 0

    def register(
        self,
        plugin_name: str,
        phase: str,
        fn: Callable[..., Any],
        *args: Any,
        require_keys: Iterable[str] | None = None,
        require_any_keys: Iterable[str] | None = None,
        exclude_keys: Iterable[str] | None = None,
        require_ports: Iterable[int] | None = None,
        depends_on: Iterable[str] | None = None,
        **kwargs: Any,
    ) -> None:
        p_ord = ScanPhase.ORDER.get(phase, 40)
        gate_cfg = {
            "require_keys": require_keys,
            "require_any_keys": require_any_keys,
            "exclude_keys": exclude_keys,
            "require_ports": require_ports,
        }
        dep_list = [str(d) for d in (depends_on or []) if str(d)]
        self._tasks.append((p_ord, self._seq, plugin_name, phase, fn, args, kwargs, gate_cfg, dep_list))
        self._seq += 1

    def build_execution_waves(self) -> list[list[str]]:
        """Builds phase-respecting topological execution waves across all registered plugins."""
        ordered = sorted(self._tasks, key=lambda x: (x[0], x[1]))
        waves: list[list[str]] = []
        idx = 0
        while idx < len(ordered):
            p_ord = ordered[idx][0]
            group = []
            while idx < len(ordered) and ordered[idx][0] == p_ord:
                group.append(ordered[idx])
                idx += 1
            specs = [(item[2], item[8]) for item in group]
            waves.extend(compute_topological_waves(specs))
        return waves

    def execute_all(
        self,
        progress_fn: Callable[[float, str], None] | None = None,
        start_frac: float = 0.89,
        end_frac: float = 0.96,
    ) -> dict[str, Any]:
        results: dict[str, Any] = {}
        waves = self.build_execution_waves()
        by_name = {item[2]: item for item in self._tasks}
        flat_order = [name for wave in waves for name in wave if name in by_name]
        total = max(1, len(flat_order))
        for idx, p_name in enumerate(flat_order, start=1):
            _, _, _, phase, fn, args, kwargs, gate_cfg, _ = by_name[p_name]
            if progress_fn:
                frac = start_frac + (end_frac - start_frac) * ((idx - 1) / total)
                progress_fn(frac, f"Phase 2 ({idx}/{total}): {p_name}...")
            results[p_name] = run_plugin_safely(
                self.db,
                self.project_id,
                p_name,
                fn,
                *args,
                log_fn=self.log_fn,
                kb=self.kb,
                phase=phase,
                **gate_cfg,
                **kwargs,
            )
        return results
