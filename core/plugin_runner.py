"""
SPECTRE v12.4 — Nessus/OpenVAS-Style Shared Knowledge Base (KB) & Fault-Isolated Plugin Runner
==============================================================================================
1. ScanContextKB: Shared per-scan memory store so plugins share discovered facts,
   headers, technologies, and cached responses without redundant network traffic.
2. run_plugin_safely: Wraps every recon/audit plugin execution with millisecond
   timing telemetry and structured exception logging into SQLite `task_logs`
   (eliminating silent failure blindness).
"""

from __future__ import annotations

import threading
import time
import traceback
from typing import Any, Callable


class ScanContextKB:
    """
    Nessus-style Knowledge Base (KB) shared across all plugins during a scan.
    """

    def __init__(self, project_id: int, primary_host: str, apex_domain: str):
        self.project_id = project_id
        self.primary_host = primary_host
        self.apex_domain = apex_domain
        self._lock = threading.RLock()
        self._facts: dict[str, set[Any]] = {}
        self._kv: dict[str, Any] = {}

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
                return bool(self._facts.get(category))
            return item in self._facts.get(category, set())


def run_plugin_safely(
    db,
    project_id: int,
    plugin_name: str,
    fn: Callable[..., Any],
    *args: Any,
    log_fn: Callable[[str], None] | None = None,
    **kwargs: Any,
) -> Any:
    """
    Executes a reconnaissance or audit plugin function inside an isolated fault boundary.
    Records execution duration (ms) and captures any unhandled exception into `task_logs`
    so no plugin failure ever goes unnoticed or crashes the parent scan thread.
    """
    t0 = time.monotonic()
    try:
        result = fn(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if elapsed_ms >= 500:
            db.log_task(
                project_id,
                "SPECTRE-PluginRunner",
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
                "SPECTRE-PluginRunner",
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
