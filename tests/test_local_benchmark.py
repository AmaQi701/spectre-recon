"""
SPECTRE v13.0 — Local 5-Second End-to-End Integration Benchmark
"""

from __future__ import annotations

import html as _html
import http.server
import json
import pathlib
import socketserver
import sys
import tempfile
import threading
import urllib.parse

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.database import DatabaseManager
from core.plugin_runner import ScanContextKB
from core.scope_guard import ScopeGuard
from agents import spectre_deep_modules
from agents.recon_agent import ReconSuperAgent
from agents.vuln_agent import VulnAssessmentSuperAgent
from agents.triage_chain_agent import TriageAndChainSuperAgent


class _BenchmarkHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        origin = self.headers.get("Origin", "")

        if parsed.path == "/":
            body = (
                "<html><head><title>Benchmark Portal</title></head>"
                "<body><a href='/go?next=/home'>Go</a>"
                "<a href='/search?q=item'>Search</a>"
                "<a href='/safe_search?safe_q=item'>SafeSearch</a>"
                "<script src='/static/app.js'></script></body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "nginx/1.18.0")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/static/app.js":
            js_code = (
                "const api = '/api/v1/orders/101';\n"
                "const adm = '/api/v1/admin/export';\n"
                "document.getElementById('x').innerHTML = location.hash;\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(js_code)
        elif parsed.path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "paths": {
                    "/api/v1/orders/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
                    "/api/v1/orders/101": {"put": {}},
                },
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(spec).encode())
        elif parsed.path.startswith("/api/v1/orders/"):
            if not self.headers.get("Authorization", ""):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
                return
            payload = {"order_id": 101, "owner": "alice", "total": 450.0, "address": "Tashkent"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
        elif parsed.path == "/api/v1/admin/export":
            payload = {"users_count": 42, "export_ready": True, "role_scope": "internal"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
        elif parsed.path == "/go":
            nxt = (qs.get("next") or ["/home"])[0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.end_headers()
        elif parsed.path == "/search":
            q_val = (qs.get("q") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Results for {q_val}</body></html>".encode())
        elif parsed.path == "/safe_search":
            sq_val = _html.escape((qs.get("safe_q") or [""])[0], quote=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Safe results for {sq_val}</body></html>".encode())
        else:
            self.send_response(404)
            self.end_headers()



class _ReusableTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_benchmark() -> None:
    srv = _ReusableTCPServer(("127.0.0.1", 0), _BenchmarkHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    try:
        with tempfile.TemporaryDirectory() as tmpd:
            tmp_path = pathlib.Path(tmpd)
            sast_dir = tmp_path / "src"
            sast_dir.mkdir()
            (sast_dir / "repo_sample.py").write_text(
                "def get_order(cursor, uid):\n"
                "    cursor.execute(f'SELECT * FROM orders WHERE id = {uid}')\n",
                encoding="utf-8",
            )

            db = DatabaseManager(str(tmp_path / "bench.db"))
            base_url = f"http://127.0.0.1:{port}"
            pid = db.create_project("Benchmark-v14", f"127.0.0.1:{port}", "127.0.0.1", "", str(sast_dir))
            db.upsert_domain(pid, "127.0.0.1", ip="127.0.0.1", source="primary_target")
            db.upsert_domain(pid, "vhost1.invalid", ip="198.51.100.10", source="subfinder")
            db.upsert_domain(pid, "vhost2.invalid", ip="198.51.100.10", source="subfinder")
            db.upsert_http_service(pid, "https://vhost1.invalid", 200, "App1", "Apache/2.4.50", ["Apache/2.4.50"], 120, {}, {}, [], {})
            db.upsert_http_service(pid, "https://vhost2.invalid", 200, "App2", "Apache/2.4.50", ["Apache/2.4.50"], 120, {}, {}, [], {})
            db.upsert_port(pid, "127.0.0.1", 22, "tcp", ip="127.0.0.1", service="ssh", version="OpenSSH 8.9p1", banner="SSH-2.0-OpenSSH_8.9p1 ssh-dss")
            db.upsert_port(pid, "127.0.0.1", 6379, "tcp", ip="127.0.0.1", service="redis", version="6.0.5", banner="Redis 6.0.5")
            db.upsert_port(pid, "vhost1.invalid", 21, "tcp", ip="198.51.100.10", service="ftp", version="vsftpd 3.0.3 [ftp-anon: Anonymous FTP login allowed]", banner="")
            db.upsert_port(pid, "vhost2.invalid", 21, "tcp", ip="198.51.100.10", service="ftp", version="vsftpd 3.0.3 [ftp-anon: Anonymous FTP login allowed]", banner="")
            db.upsert_port(pid, "vhost1.invalid", 445, "tcp", ip="198.51.100.10", service="microsoft-ds", version="Windows Server (signing:false)", banner="")
            db.upsert_port(pid, "vhost1.invalid", 9200, "tcp", ip="198.51.100.10", service="elasticsearch", version="8.12.2", banner='{"cluster_name":"prod-es"}')
            db.upsert_port(pid, "vhost1.invalid", 161, "udp", ip="198.51.100.10", service="snmp", version="Linux SNMPd", banner="")

            logs: list[str] = []
            scope = ScopeGuard("127.0.0.1", "")
            recon = ReconSuperAgent(db, str(ROOT_DIR / "config" / "tools_registry.yaml"))

            html = recon._stage3_http_probe(pid, base_url, {}, scope, logs.append)
            assert html, "Stage 3 failed to probe local benchmark server"
            js_urls = recon._stage4_html_and_wayback(pid, base_url, html, "127.0.0.1", scope, logs.append)
            recon._stage5_openapi_discovery(pid, base_url, scope, logs.append)
            recon._stage6_js_analyzer(pid, js_urls, base_url, scope, logs.append)
            spectre_deep_modules.probe_api_versions_and_ghost_endpoints(db, pid, logs.append, recon.session)
            r_404 = recon.session.get(f"{base_url}/nonexistent-404-cache-check")
            assert r_404.status_code == 404 and (f"{base_url}/nonexistent-404-cache-check", True) in recon._http_get_cache, "404 GET cache failed"

            kb_check = ScanContextKB(pid, "127.0.0.1")
            kb_check.hydrate_from_bundle(db.get_project_bundle(pid), has_auth_a=True)
            assert kb_check.check_gate(require_ports=[6379])[0] is True, "KB Gate failed to detect port 6379"
            assert kb_check.check_gate(require_ports=[27017])[0] is False, "KB Gate failed to block closed port 27017"

            vuln = VulnAssessmentSuperAgent(db)
            vuln.configure_context(
                primary_auth="Authorization: Bearer token_user_a",
                secondary_auth="Authorization: Bearer token_user_b",
            )
            vuln.run_assessment(pid, logs.append, enable_cli=False)

            triage = TriageAndChainSuperAgent(db, str(tmp_path / "reports"))
            triage.run_triage_and_chaining(pid, logs.append)
            rep_paths = triage.generate_reports(pid)

            bundle = db.get_project_bundle(pid)
            titles = [f["title"] for f in bundle["findings"]]
            confs = [f["confidence"] for f in bundle["findings"]]
            chains = [c["chain_title"] for c in bundle["bug_chains"]]

            assert len(bundle["js_assets"]) >= 1, "JS Analyzer failed to capture app.js"
            assert any("BOLA" in t for t in titles), f"Multi-Role BOLA Matrix missed flaw: {titles}"
            assert any("Unauthenticated Access" in t for t in titles), f"Authz Matrix missed flaw: {titles}"
            assert any("Arbitrary CORS Origin Reflection" in t for t in titles), f"CORS audit missed flaw: {titles}"
            assert any("Verified Open Redirect" in t for t in titles), f"Redirect verifier missed flaw: {titles}"
            assert any("Unencoded HTML Output Reflection via 'q'" in t for t in titles), f"Encoding verifier missed unencoded q: {titles}"
            assert not any("safe_q" in t for t in titles), f"False positive on properly HTML-escaped safe_q: {titles}"
            assert any("SQL Injection" in t for t in titles), f"SAST engine missed flaw: {titles}"
            assert any("CVE-2021-23017" in t for t in titles), f"Semantic CVE engine missed nginx 1.18.0: {titles}"
            apache_cves = [f for f in bundle["findings"] if "CVE-2021-41773" in f["title"]]
            assert len(apache_cves) == 1 and "Shared Origin VHosts (2)" in apache_cves[0]["evidence"] and "cpe:2.3:a:apache:http_server:2.4.50" in apache_cves[0]["evidence"], f"Shared VHost dedup or CPE 2.3 failed: {apache_cves}"
            assert any("CVE-2024-6387" in t for t in titles), f"Semantic CVE engine missed OpenSSH 8.9p1: {titles}"
            assert any("Exposed Backend Data Store Port" in t for t in titles), f"Port posture missed Redis: {titles}"
            assert any("Unauthenticated Backend Data Store Access" in t for t in titles), f"Port posture missed unauth Elastic: {titles}"
            ftp_anon_hits = [t for t in titles if "Anonymous FTP Access Enabled" in t]
            assert len(ftp_anon_hits) == 1, f"FTP Anon check or shared-IP dedup failed: {ftp_anon_hits}"
            assert any("SMB Signing Not Required" in t for t in titles), f"SMB signing check failed: {titles}"
            assert any("Exposed UDP SNMP" in t for t in titles), f"UDP SNMP check failed: {titles}"
            agent2_confs = [f["confidence"] for f in bundle["findings"] if str(f.get("agent", "")).startswith("Agent-2")]
            assert all("QoD:" in c for c in agent2_confs), f"Missing QoD label in Agent-2 findings: {agent2_confs}"
            assert any("QoD: 99%" in c for c in confs), f"QoD 99% tag missing: {confs}"
            assert any("QoD: 75%" in c for c in confs), f"QoD 75% Banner-CVE tag missing: {confs}"
            assert len(chains) >= 5, f"Asset-Bound Graph Chainer produced too few chains: {chains}"
            assert pathlib.Path(rep_paths["html_path"]).is_file(), "HTML report was not generated"

            print(
                f"BENCHMARK_OK | Endpoints={len(bundle['endpoints'])} | JS={len(bundle['js_assets'])} "
                f"| Findings={len(titles)} | Chains={len(chains)}"
            )
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    run_benchmark()
