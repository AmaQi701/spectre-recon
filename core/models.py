"""
SPECTRE v12.3 — Strict Database Schema Contracts & Typed Models
===============================================================
Single source of truth for all SQLite table column names and bundle keys.
Prevents hallucinated dictionary keys (e.g. 'cdn_provider', 'ip_address', 'urls').
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
