"""
SPECTRE — Strict Database Schema Contracts & Typed Models
=========================================================
Single source of truth for all SQLite table column names and bundle keys.
Prevents invalid dictionary keys across reconnaissance and audit modules.
"""

from __future__ import annotations
from typing import TypedDict


class ProjectRow(TypedDict, total=False):
    id: int
    name: str
    primary_target: str
    in_scope: str
    out_of_scope: str
    source_code_path: str
    notes: str
    status: str
    created_at: str


class DomainRow(TypedDict, total=False):
    id: int
    project_id: int
    domain: str
    ip: str
    cname: str
    records_json: str
    cdn_waf: str
    source: str
    in_scope: int
    created_at: str


class PortRow(TypedDict, total=False):
    id: int
    project_id: int
    host: str
    ip: str
    port: int
    protocol: str
    service: str
    version: str
    banner: str
    source: str
    created_at: str


class HttpServiceRow(TypedDict, total=False):
    id: int
    project_id: int
    url: str
    status_code: int
    title: str
    server: str
    tech_stack: str
    content_length: int
    headers_json: str
    security_headers_json: str
    cookies_json: str
    tls_json: str
    waf: str
    priority_score: int
    source: str
    created_at: str


class EndpointRow(TypedDict, total=False):
    id: int
    project_id: int
    url: str
    method: str
    params_json: str
    category: str
    risk_tags_json: str
    status_code: int
    source: str
    created_at: str


class JsAssetRow(TypedDict, total=False):
    id: int
    project_id: int
    js_url: str
    endpoints_json: str
    params_json: str
    sinks_json: str
    secrets_hints_json: str
    created_at: str


class FindingRow(TypedDict, total=False):
    id: int
    project_id: int
    agent: str
    title: str
    category: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe: str
    owasp: str
    asset: str
    evidence: str
    root_cause: str
    remediation: str
    confidence: str
    triage_status: str
    created_at: str


BUNDLE_KEYS = frozenset({
    "project", "domains", "ports", "http_services",
    "endpoints", "js_assets", "findings", "bug_chains", "task_logs",
})

FORBIDDEN_HALLUCINATED_KEYS = frozenset({
    "cdn_provider", "ip_address", "tech_stack_json", "params_list",
    "headers_dict", "cookies_list", "sinks_list", "risk_tags_list",
})


def resolve_writable_runtime_dir(base_dir: "os.PathLike[str] | str") -> "Path":
    import os
    from pathlib import Path
    import shutil

    root = Path(base_dir).resolve()
    ws_dir = root / "workspaces"
    if os.access(root, os.W_OK) and (not ws_dir.exists() or os.access(ws_dir, os.W_OK)):
        return root

    xdg_base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    runtime_root = xdg_base / "spectre-recon"
    for sub in ("workspaces", "reports", "config"):
        sub_pf = runtime_root / sub
        sub_pf.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(sub_pf, 0o700)
        except OSError:
            pass
    src_reg = root / "config" / "tools_registry.yaml"
    dst_reg = runtime_root / "config" / "tools_registry.yaml"
    if src_reg.is_file() and not dst_reg.exists():
        try:
            shutil.copy2(src_reg, dst_reg)
        except OSError:
            pass
    return runtime_root


def walk_safe_repo_files(
    root_dir: "os.PathLike[str] | str",
    max_files: int = 240,
    max_bytes: int = 524288,
    skip_dirs: tuple[str, ...] = (
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        ".terraform", "tests", "test", "__tests__", "mocks",
    ),
) -> list["Path"]:
    """Walks `root_dir` with `followlinks=False`, pruning `.git`/vendor dirs first and rejecting symlinks (`HIGH-11`)."""
    import os
    from pathlib import Path

    root = Path(root_dir)
    if not root.exists() or root.is_symlink():
        return []
    root_res = root.resolve()
    if root.is_file():
        try:
            return [root] if root.stat().st_size <= max_bytes else []
        except OSError:
            return []
    skip_low = {d.lower() for d in skip_dirs}
    out: list[Path] = []
    for cur_dir, dirs, fnames in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in skip_low and not (Path(cur_dir) / d).is_symlink()
        )
        for fn in sorted(fnames):
            fp = Path(cur_dir) / fn
            if fp.is_symlink():
                continue
            try:
                resolved = fp.resolve()
                if not resolved.is_relative_to(root_res):
                    continue
                if resolved.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            out.append(fp)
            if len(out) >= max_files:
                return out
    return out

