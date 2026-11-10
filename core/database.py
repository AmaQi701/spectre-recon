import contextlib
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    primary_target TEXT NOT NULL,
    in_scope TEXT NOT NULL,
    out_of_scope TEXT DEFAULT '',
    source_code_path TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'READY',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    ip TEXT DEFAULT '',
    cname TEXT DEFAULT '',
    records_json TEXT DEFAULT '{}',
    cdn_waf TEXT DEFAULT '',
    source TEXT DEFAULT '',
    in_scope INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, domain)
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    ip TEXT DEFAULT '',
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    source TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, host, port, protocol)
);
CREATE TABLE IF NOT EXISTS http_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER DEFAULT 0,
    title TEXT DEFAULT '',
    server TEXT DEFAULT '',
    tech_stack TEXT DEFAULT '[]',
    content_length INTEGER DEFAULT 0,
    headers_json TEXT DEFAULT '{}',
    security_headers_json TEXT DEFAULT '{}',
    cookies_json TEXT DEFAULT '[]',
    tls_json TEXT DEFAULT '{}',
    waf TEXT DEFAULT '',
    priority_score INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, url)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    params_json TEXT DEFAULT '[]',
    category TEXT DEFAULT 'general',
    risk_tags_json TEXT DEFAULT '[]',
    status_code INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, url, method)
);
CREATE TABLE IF NOT EXISTS js_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    js_url TEXT NOT NULL,
    endpoints_json TEXT DEFAULT '[]',
    params_json TEXT DEFAULT '[]',
    sinks_json TEXT DEFAULT '[]',
    secrets_hints_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, js_url)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    agent TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL DEFAULT 0.0,
    cvss_vector TEXT DEFAULT '',
    cwe TEXT DEFAULT '',
    owasp TEXT DEFAULT '',
    asset TEXT NOT NULL,
    evidence TEXT DEFAULT '',
    root_cause TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    confidence TEXT DEFAULT 'High',
    triage_status TEXT DEFAULT 'Verified',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, title, asset)
);
CREATE TABLE IF NOT EXISTS bug_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    chain_title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL DEFAULT 0.0,
    nodes_json TEXT DEFAULT '[]',
    attack_scenario TEXT DEFAULT '',
    impact TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, chain_title)
);
CREATE TABLE IF NOT EXISTS task_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL,
    command TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    domains_json TEXT DEFAULT '[]',
    ports_json TEXT DEFAULT '[]',
    endpoints_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_proj ON domains(project_id);
CREATE INDEX IF NOT EXISTS idx_ports_proj ON ports(project_id);
CREATE INDEX IF NOT EXISTS idx_http_proj ON http_services(project_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_proj ON endpoints(project_id);
CREATE INDEX IF NOT EXISTS idx_js_proj ON js_assets(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_proj ON findings(project_id, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_chains_proj ON bug_chains(project_id);
CREATE INDEX IF NOT EXISTS idx_logs_proj ON task_logs(project_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_snaps_proj ON scan_snapshots(project_id, id DESC);
"""



class DatabaseManager:
    def __init__(self, db_path: str = "/home/amaqi/projects/apex-pentest-gui/workspaces/apex_state.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), timeout=60, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()

    @contextlib.contextmanager
    def _get_conn(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise


    @staticmethod
    def now() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def create_project(self, name: str, primary_target: str, in_scope: str, out_of_scope: str = "", source_code_path: str = "", notes: str = "") -> int:
        with self._lock, self._get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO projects (name, primary_target, in_scope, out_of_scope, source_code_path, notes, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'READY', ?)",
                (name, primary_target, in_scope, out_of_scope, source_code_path, notes, self.now()),
            )
            return int(cur.lastrowid)

    def get_projects(self) -> list[dict]:
        with self._get_conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()]

    def get_project(self, project_id: int) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            return dict(row) if row else None

    def update_project_status(self, project_id: int, status: str):
        with self._lock, self._get_conn() as conn:
            conn.execute("UPDATE projects SET status = ? WHERE id = ?", (status, project_id))

    def reset_stale_running_projects(self):
        with self._lock, self._get_conn() as conn:
            conn.execute("UPDATE projects SET status = 'READY' WHERE status LIKE 'RUNNING%'")

    def delete_project(self, project_id: int):
        with self._lock, self._get_conn() as conn:
            for tbl in ("domains", "ports", "http_services", "endpoints", "js_assets", "findings", "bug_chains", "task_logs", "scan_snapshots"):
                conn.execute(f"DELETE FROM {tbl} WHERE project_id = ?", (project_id,))
            conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    def save_scan_snapshot(self, project_id: int, domains: list[str], ports: list[str], endpoints: list[str]):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "INSERT INTO scan_snapshots (project_id, domains_json, ports_json, endpoints_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, json.dumps(domains), json.dumps(ports), json.dumps(endpoints), self.now()),
            )

    def get_latest_snapshot(self, project_id: int) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM scan_snapshots WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)).fetchone()
            return dict(row) if row else None



    def upsert_domain(self, project_id: int, domain: str, ip: str = "", cname: str = "", records: dict | None = None, cdn_waf: str = "", source: str = "recon"):
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            return
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO domains (project_id, domain, ip, cname, records_json, cdn_waf, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, domain) DO UPDATE SET
                ip = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE domains.ip END,
                cname = CASE WHEN excluded.cname != '' THEN excluded.cname ELSE domains.cname END,
                records_json = CASE WHEN excluded.records_json != '{}' THEN excluded.records_json ELSE domains.records_json END,
                cdn_waf = CASE WHEN excluded.cdn_waf != '' THEN excluded.cdn_waf ELSE domains.cdn_waf END""",
                (project_id, domain, ip, cname, json.dumps(records or {}), cdn_waf, source, self.now()),
            )

    def upsert_port(self, project_id: int, host: str, port: int, protocol: str = "tcp", ip: str = "", service: str = "", version: str = "", banner: str = "", source: str = "nmap"):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO ports (project_id, host, ip, port, protocol, service, version, banner, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, host, port, protocol) DO UPDATE SET
                service = CASE WHEN excluded.service != '' THEN excluded.service ELSE ports.service END,
                version = CASE WHEN excluded.version != '' THEN excluded.version ELSE ports.version END,
                banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE ports.banner END""",
                (project_id, host, ip, int(port), protocol, service, version, banner, source, self.now()),
            )

    def upsert_http_service(self, project_id: int, url: str, status_code: int, title: str = "", server: str = "", tech_stack: list | None = None, content_length: int = 0, headers: dict | None = None, security_headers: dict | None = None, cookies: list | None = None, tls_info: dict | None = None, waf: str = "", priority_score: int = 0, source: str = "http_probe"):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO http_services (project_id, url, status_code, title, server, tech_stack, content_length, headers_json, security_headers_json, cookies_json, tls_json, waf, priority_score, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, url) DO UPDATE SET
                status_code = CASE WHEN excluded.status_code > 0 THEN excluded.status_code ELSE http_services.status_code END,
                title = CASE WHEN excluded.title != '' THEN excluded.title ELSE http_services.title END,
                server = CASE WHEN excluded.server != '' THEN excluded.server ELSE http_services.server END,
                tech_stack = CASE WHEN excluded.tech_stack != '[]' THEN excluded.tech_stack ELSE http_services.tech_stack END,
                headers_json = CASE WHEN excluded.headers_json != '{}' THEN excluded.headers_json ELSE http_services.headers_json END,
                security_headers_json = CASE WHEN excluded.security_headers_json != '{}' THEN excluded.security_headers_json ELSE http_services.security_headers_json END,
                cookies_json = CASE WHEN excluded.cookies_json != '[]' THEN excluded.cookies_json ELSE http_services.cookies_json END,
                tls_json = CASE WHEN excluded.tls_json != '{}' THEN excluded.tls_json ELSE http_services.tls_json END,
                waf = CASE WHEN excluded.waf != '' THEN excluded.waf ELSE http_services.waf END,
                priority_score = MAX(http_services.priority_score, excluded.priority_score)""",
                (project_id, url, int(status_code), title, server, json.dumps(tech_stack or []), int(content_length), json.dumps(headers or {}), json.dumps(security_headers or {}), json.dumps(cookies or []), json.dumps(tls_info or {}), waf, int(priority_score), source, self.now()),
            )

    def merge_http_tech_stack(self, project_id: int, url: str, new_techs: list[str]):
        if not new_techs:
            return
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT tech_stack FROM http_services WHERE project_id = ? AND url = ?", (project_id, url)).fetchone()
            if row:
                try:
                    cur_t = json.loads(row["tech_stack"] or "[]")
                except Exception:
                    cur_t = []
                merged = list(dict.fromkeys([str(x) for x in (cur_t + list(new_techs)) if x]))
                conn.execute("UPDATE http_services SET tech_stack = ? WHERE project_id = ? AND url = ?", (json.dumps(merged), project_id, url))

    def upsert_endpoint(self, project_id: int, url: str, method: str = "GET", params: list | None = None, category: str = "general", risk_tags: list | None = None, status_code: int = 0, source: str = "crawler"):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO endpoints (project_id, url, method, params_json, category, risk_tags_json, status_code, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, url, method) DO UPDATE SET
                params_json = CASE WHEN excluded.params_json != '[]' THEN excluded.params_json ELSE endpoints.params_json END,
                category = CASE WHEN excluded.category NOT IN ('general', 'web_page') THEN excluded.category ELSE endpoints.category END,
                risk_tags_json = CASE WHEN excluded.risk_tags_json != '[]' THEN excluded.risk_tags_json ELSE endpoints.risk_tags_json END,
                status_code = CASE WHEN excluded.status_code > 0 THEN excluded.status_code ELSE endpoints.status_code END""",
                (project_id, url, method.upper(), json.dumps(params or []), category, json.dumps(risk_tags or []), int(status_code), source, self.now()),
            )

    def upsert_js_asset(self, project_id: int, js_url: str, endpoints: list | None = None, params: list | None = None, sinks: list | None = None, secrets_hints: list | None = None):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO js_assets (project_id, js_url, endpoints_json, params_json, sinks_json, secrets_hints_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, js_url) DO UPDATE SET
                endpoints_json = excluded.endpoints_json,
                params_json = excluded.params_json,
                sinks_json = excluded.sinks_json,
                secrets_hints_json = excluded.secrets_hints_json""",
                (project_id, js_url, json.dumps(endpoints or []), json.dumps(params or []), json.dumps(sinks or []), json.dumps(secrets_hints or []), self.now()),
            )

    def upsert_finding(self, project_id: int, agent: str, title: str, category: str, severity: str, cvss_score: float, cvss_vector: str, cwe: str, owasp: str, asset: str, evidence: str, root_cause: str, remediation: str, confidence: str = "High", triage_status: str = "Verified"):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO findings (project_id, agent, title, category, severity, cvss_score, cvss_vector, cwe, owasp, asset, evidence, root_cause, remediation, confidence, triage_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, title, asset) DO UPDATE SET
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                evidence = excluded.evidence,
                triage_status = excluded.triage_status""",
                (project_id, agent, title, category, severity, float(cvss_score), cvss_vector, cwe, owasp, asset, evidence, root_cause, remediation, confidence, triage_status, self.now()),
            )

    def upsert_bug_chain(self, project_id: int, chain_title: str, severity: str, cvss_score: float, nodes: list, attack_scenario: str, impact: str, remediation: str):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO bug_chains (project_id, chain_title, severity, cvss_score, nodes_json, attack_scenario, impact, remediation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, chain_title) DO UPDATE SET
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                nodes_json = excluded.nodes_json,
                attack_scenario = excluded.attack_scenario""",
                (project_id, chain_title, severity, float(cvss_score), json.dumps(nodes), attack_scenario, impact, remediation, self.now()),
            )

    def log_task(self, project_id: int, agent: str, tool: str, status: str, command: str = "", summary: str = ""):
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "INSERT INTO task_logs (project_id, agent, tool, status, command, summary, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (project_id, agent, tool, status, command, summary, self.now()),
            )

    def update_finding_triage(self, finding_id: int, triage_status: str):
        with self._lock, self._get_conn() as conn:
            conn.execute("UPDATE findings SET triage_status = ? WHERE id = ?", (triage_status, int(finding_id)))


    def get_project_bundle(self, project_id: int) -> dict:
        with self._get_conn() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            domains = [dict(r) for r in conn.execute("SELECT * FROM domains WHERE project_id = ? ORDER BY id DESC", (project_id,)).fetchall()]
            ports = [dict(r) for r in conn.execute("SELECT * FROM ports WHERE project_id = ? ORDER BY port ASC", (project_id,)).fetchall()]
            http_svcs = [dict(r) for r in conn.execute("SELECT * FROM http_services WHERE project_id = ? ORDER BY priority_score DESC, id DESC", (project_id,)).fetchall()]
            endpoints = [dict(r) for r in conn.execute("SELECT * FROM endpoints WHERE project_id = ? ORDER BY id DESC", (project_id,)).fetchall()]
            js_assets = [dict(r) for r in conn.execute("SELECT * FROM js_assets WHERE project_id = ? ORDER BY id DESC", (project_id,)).fetchall()]
            findings = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE project_id = ? ORDER BY cvss_score DESC, id DESC", (project_id,)).fetchall()]
            chains = [dict(r) for r in conn.execute("SELECT * FROM bug_chains WHERE project_id = ? ORDER BY cvss_score DESC", (project_id,)).fetchall()]
            logs = [dict(r) for r in conn.execute("SELECT * FROM task_logs WHERE project_id = ? ORDER BY id DESC LIMIT 100", (project_id,)).fetchall()]
            return {
                "project": dict(proj) if proj else {},
                "domains": domains,
                "ports": ports,
                "http_services": http_svcs,
                "endpoints": endpoints,
                "js_assets": js_assets,
                "findings": findings,
                "bug_chains": chains,
                "task_logs": logs,
            }

