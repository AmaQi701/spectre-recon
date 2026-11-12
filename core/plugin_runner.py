"""
SPECTRE v14.0 — KB-Driven Phased Orchestrator, QoD Standard & Fault-Isolated Plugin Runner
==========================================================================================
"""

from __future__ import annotations

import json
import threading
import time
import traceback
from typing import Any, Callable, Iterable


class ScanPhase:
    """Ordered lifecycle phases for reconnaissance and security posture verification."""

    ACT_INIT = "ACT_INIT"
    ACT_SCANNER = "ACT_SCANNER"
    ACT_SETTINGS = "ACT_SETTINGS"
    ACT_GATHER_INFO = "ACT_GATHER_INFO"
    ACT_VERIFY = "ACT_VERIFY"
    ACT_END = "ACT_END"


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
        self, require_keys: Iterable[str] | None = None, require_ports: Iterable[int] | None = None
    ) -> tuple[bool, str]:
        with self._lock:
            if require_keys:
                for rk in require_keys:
                    if not self.has_fact(rk):
                        return False, f"missing_kb_key:{rk}"
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
    phase: str = ScanPhase.ACT_GATHER_INFO,
    **kwargs: Any,
) -> Any:
    """
    Executes a reconnaissance or audit plugin inside an isolated fault boundary.
    Enforces optional KB gating (`require_keys` / `require_ports`) before invocation.
    """
    if kb is not None and (require_keys or require_ports):
        ok, _ = kb.check_gate(require_keys=require_keys, require_ports=require_ports)
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
            log_fn(f"  [⚠️ PLUGIN ISOLATED ERROR] {plugin_name}: {ex}")
        return None
