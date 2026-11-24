"""
SPECTRE — Local End-to-End Integration Benchmark
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
from agents import surface_prober
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

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        clen = int(self.headers.get("Content-Length") or 0)
        raw_b = self.rfile.read(clen).decode("utf-8", errors="ignore") if clen > 0 else ""
        form_qs = urllib.parse.parse_qs(raw_b)
        if parsed.path == "/portal/update_role":
            r_val = (form_qs.get("role") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body>Updated role: {r_val}</body></html>".encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        origin = self.headers.get("Origin", "")

        if parsed.path == "/":
            xfh_h = self.headers.get("X-Forwarded-Host", "127.0.0.1")
            body = (
                "<html><head><title>Benchmark Portal</title></head>"
                f"<body><a href='https://{xfh_h}/reset'>Reset</a>"
                "<a href='/go?next=/home'>Go</a>"
                "<a href='/search?q=item'>Search</a>"
                "<a href='/safe_search?safe_q=item'>SafeSearch</a>"
                "<a href='/debug_err?id=1'>DebugErr</a>"
                "<a href='/portal'>Portal</a>"
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
        elif parsed.path == "/debug_err":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Traceback (most recent call last):\n  File 'app.py', line 12\nZeroDivisionError")
        elif parsed.path == "/portal":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Inner Portal</title></head><body>"
                b"<h1>Staff Portal</h1><a href='/portal/settings'>Settings</a></body></html>"
            )
        elif parsed.path == "/portal/settings":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Portal Settings</title></head><body>"
                b"<form action='/portal/update_role' method='POST'><input name='role'></form>"
                b"<script src='/static/portal.js'></script></body></html>"
            )
        elif parsed.path == "/static/portal.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"axios.post('/api/v2/internal/audit', {actor: 'admin'});\n")
        elif parsed.path == "/nginx_status":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Active connections: 4\nserver accepts handled requests\n 120 120 340\nReading: 0 Writing: 1 Waiting: 3\n")
        elif parsed.path == "/debug/pprof/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Types of profiles available:\n12 goroutine\n4 heap\n")
        elif parsed.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /internal-ops/metrics\n")
        elif parsed.path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Contact: mailto:sec@127.0.0.1\nExpires: 2030-01-01T00:00:00Z\n")
        elif parsed.path == "/api/tags":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"models":[{"name":"qwen2.5:14b","digest":"sha256:9911"}]}')
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
                "    cursor.execute('SELECT id FROM orders WHERE id = %s', (uid,))\n"
                "    raw_sql = f'SELECT * FROM orders WHERE owner = {uid}'\n"
                "    cursor.execute(raw_sql)\n",
                encoding="utf-8",
            )
            wf_dir = sast_dir / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text(
                "on: pull_request_target\njobs:\n  build:\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
                encoding="utf-8",
            )
            (sast_dir / ".npmrc").write_text("//registry.npmjs.org/:_authToken=npm_benchToken9876543210\n", encoding="utf-8")
            (sast_dir / "Jenkinsfile").write_text('pipeline { stages { stage("Deploy") { steps { sh "deploy.sh ${params.ENV_TAG}" } } } }\n', encoding="utf-8")
            (sast_dir / "node_route.js").write_text(
                "function loadAccount(pool, req) {\n"
                "  const q = 'SELECT * FROM billing WHERE tenant = ' + req.query.tenant;\n"
                "  pool.query(q);\n"
                "}\n",
                encoding="utf-8",
            )
            (sast_dir / "requirements.txt").write_text("pyyaml==5.3.1\nrequests==2.25.0\n", encoding="utf-8")
            (sast_dir / "pom.xml").write_text(
                "<project><dependencies><dependency>"
                "<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version>"
                "</dependency></dependencies></project>\n",
                encoding="utf-8",
            )
            (sast_dir / "package-lock.json").write_text(
                json.dumps({"lockfileVersion": 3, "packages": {"node_modules/minimist": {"version": "1.2.5"}}}),
                encoding="utf-8",
            )
            (sast_dir / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY . /app\nCMD [\"python\", \"/app/main.py\"]\n", encoding="utf-8")
            (sast_dir / "main.tf").write_text('resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n', encoding="utf-8")
            (sast_dir / "rbac.yaml").write_text(
                "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: admin-all\n"
                "rules:\n  - verbs: [\"*\"]\n    resources: [\"*\"]\n",
                encoding="utf-8",
            )
            (sast_dir / "Billing.csproj").write_text(
                '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>\n',
                encoding="utf-8",
            )
            (sast_dir / "handler.go").write_text(
                'package main\nfunc load(db DB, r Req) {\n  uid := r.URL.Query().Get("uid")\n  q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", uid)\n  db.Query(q)\n}\n',
                encoding="utf-8",
            )
            (sast_dir / "legacy.php").write_text(
                "<?php\n$acct = $_GET['acct'];\n$sql = \"SELECT * FROM ledger WHERE id = '\" . $acct . \"'\";\nmysqli_query($conn, $sql);\n",
                encoding="utf-8",
            )
            (sast_dir / "nginx.conf").write_text("server { location /assets { alias /var/www/assets/; } }\n", encoding="utf-8")
            (sast_dir / "pubspec.lock").write_text('packages:\n  dio:\n    dependency: "direct main"\n    version: "5.1.0"\n', encoding="utf-8")
            (sast_dir / "mcp.json").write_text('{"mcpServers":{"rag":{"command":"npx","args":["-y","unpinned-rag-mcp"]}}}', encoding="utf-8")

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
            db.upsert_port(pid, "198.51.100.10", 445, "tcp", ip="198.51.100.10", service="microsoft-ds", version="Windows Server (signing:false)", banner="")
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
            from agents import origin_and_spa
            origin_and_spa.mine_well_known_and_mobile_links(db, recon.session, pid, scope, logs.append, recon._record_discovered_url)
            surface_prober.probe_api_versions_and_ghost_endpoints(db, pid, logs.append, recon.session)
            r_404 = recon.session.get(f"{base_url}/nonexistent-404-cache-check")
            assert r_404.status_code == 404 and (f"{base_url}/nonexistent-404-cache-check", True) in recon._http_get_cache, "404 GET cache failed"

            kb_check = ScanContextKB(pid, "127.0.0.1")
            kb_check.hydrate_from_bundle(db.get_project_bundle(pid), has_auth_a=True)
            assert kb_check.check_gate(require_ports=[6379])[0] is True, "KB Gate failed to detect port 6379"
            assert kb_check.check_gate(require_ports=[27017])[0] is False, "KB Gate failed to block closed port 27017"

            recon.session.headers["Authorization"] = "Bearer token_user_a"
            vuln = VulnAssessmentSuperAgent(db, shared_session=recon.session)
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
            ep_urls = [e["url"] for e in bundle["endpoints"]]

            assert len(bundle["js_assets"]) >= 2, f"Depth-2 BFS or JS Analyzer missed portal.js: {bundle['js_assets']}"
            assert any("/portal/update_role" in u for u in ep_urls) and any("/api/v2/internal/audit" in u for u in ep_urls), f"Depth-2 BFS crawler missed inner form/JS routes: {ep_urls}"
            assert not any(f["severity"] == "Info" for f in bundle["findings"]), f"Info noise leaked into findings table: {bundle['findings']}"
            assert any("BOLA" in t for t in titles), f"Multi-Role BOLA Matrix missed flaw: {titles}"
            assert any("Unauthenticated Access" in t for t in titles), f"Authz Matrix missed flaw: {titles}"
            assert any("Arbitrary CORS Origin Reflection" in t for t in titles), f"CORS audit missed flaw: {titles}"
            assert any("Verified Open Redirect" in t for t in titles), f"Redirect verifier missed flaw: {titles}"
            assert any("Unencoded HTML Output Reflection via 'q'" in t for t in titles), f"Encoding verifier missed unencoded q: {titles}"
            assert any("Unencoded HTML Output Reflection via POST 'role'" in t for t in titles), f"POST form encoding verifier missed role: {titles}"
            assert any("Nginx Stub-Status" in t for t in titles), f"Declarative NVT engine missed /nginx_status: {titles}"
            assert any("Go pprof Runtime Profiling" in t for t in titles), f"Declarative NVT engine missed /debug/pprof/: {titles}"
            assert any("Vulnerable Open-Source Dependencies in requirements.txt" in t for t in titles), f"SCA engine missed requirements.txt: {titles}"
            assert any("Vulnerable Open-Source Dependencies in pom.xml" in t for t in titles), f"SCA engine missed pom.xml Log4Shell: {titles}"
            assert any("Vulnerable Open-Source Dependencies in package-lock.json" in t for t in titles), f"SCA engine missed package-lock.json: {titles}"
            assert any("Container Image Runs as Root User" in t for t in titles), f"IaC engine missed root Dockerfile: {titles}"
            assert any("Terraform Database Instance Configured as Publicly Accessible" in t for t in titles), f"IaC engine missed Terraform RDS: {titles}"
            assert any("AST Multi-Line Data-Flow" in t for t in titles), f"Multi-line AST SAST engine missed taint flow: {titles}"
            assert any("pull_request_target" in t for t in titles), f"CI/CD workflow auditor missed pwn-request: {titles}"
            assert any("Hardcoded Package Registry Auth Token in .npmrc" in t for t in titles), f"Registry config auditor missed .npmrc: {titles}"
            assert any("Jenkinsfile" in t for t in titles), f"CI/CD auditor missed Jenkinsfile groovy sh interpolation: {titles}"
            assert any("JS/Node Multi-Line Data-Flow" in t for t in titles), f"JS/Node multi-line taint engine missed SQLi: {titles}"
            assert any("Go Multi-Line Data-Flow" in t for t in titles), f"Go multi-line taint engine missed SQLi: {titles}"
            assert any("Wildcard / Cluster-Admin Privileges" in t for t in titles), f"K8s RBAC auditor missed wildcard ClusterRole: {titles}"
            assert any("Billing.csproj" in t for t in titles), f"NuGet .csproj SCA missed Newtonsoft.Json: {titles}"
            assert any("Supply-Chain & Deployment Risk" in c for c in chains), f"CI/CD->Infra supply-chain correlation missing: {chains}"
            assert any("Ollama LLM Model Registry" in t for t in titles), f"AI/LLM auditor missed /api/tags: {titles}"
            assert any("PHP Multi-Line Data-Flow" in t for t in titles), f"PHP taint engine missed legacy.php: {titles}"
            assert any("Off-By-Slash Alias" in t for t in titles), f"Nginx IaC auditor missed off-by-slash alias: {titles}"
            assert any("pubspec.lock" in t for t in titles), f"Dart pubspec.lock SCA missed dio: {titles}"
            assert any("Agentic RAG & Model Exposure Chain" in c for c in chains), f"AI/MCP->Data attack chain missing: {chains}"
            assert any("/internal-ops/metrics" in u for u in ep_urls), f"robots.txt Disallow harvester missed /internal-ops/metrics: {ep_urls}"
            html_out = pathlib.Path(rep_paths["html_path"]).read_text(encoding="utf-8")
            assert "spSetSev(" in html_out and "NIST CSF 2.0" in html_out and "AICPA SOC 2 TSC" in html_out, "HTML v6.0 filter or 6-framework table missing"
            assert any("[EPSS:" in str(f.get("evidence", "")) for f in bundle["findings"]), "EPSS enrichment tag missing from CVE findings"
            assert not any("safe_q" in t for t in titles), f"False positive on properly HTML-escaped safe_q: {titles}"
            assert any("Unvalidated X-Forwarded-Host" in t for t in titles), f"XFH verifier missed flaw: {titles}"
            assert any("Verbose Python Stack Trace Disclosed" in t for t in titles), f"Debug stack-trace detector missed 500 trace: {titles}"
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
            assert any("Cache / Reset Link Poisoning" in c for c in chains), f"XFH chain missing: {chains}"
            assert any("Infrastructure Exposure Chain" in c for c in chains), f"Protocol/Debug chain missing: {chains}"
            assert len(chains) >= 10, f"Asset-Bound Graph Chainer produced too few chains: {chains}"
            assert pathlib.Path(rep_paths["html_path"]).is_file(), "HTML report was not generated"
            from agents import cli_orchestrator
            exp_res = cli_orchestrator.export_project_artifacts(db, pid, str(tmp_path / "reports"))
            assert pathlib.Path(exp_res["sarif_json"]).is_file() and pathlib.Path(exp_res["cyclonedx_sbom_json"]).is_file(), "SARIF or SBOM export missing"
            assert pathlib.Path(exp_res["junit_xml"]).is_file() and pathlib.Path(exp_res["compliance_matrix_json"]).is_file(), "JUnit or Compliance Matrix export missing"
            sbom_obj = json.loads(pathlib.Path(exp_res["cyclonedx_sbom_json"]).read_text(encoding="utf-8"))
            assert any(c.get("purl", "").startswith("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") for c in sbom_obj.get("components", [])), f"SBOM missing Maven purl: {sbom_obj}"
            assert any(v.get("id") == "CVE-2021-44228" for v in sbom_obj.get("vulnerabilities", [])), "SBOM missing VEX CVE-2021-44228"

            print(
                f"BENCHMARK_OK | Endpoints={len(bundle['endpoints'])} | JS={len(bundle['js_assets'])} "
                f"| Findings={len(titles)} | Chains={len(chains)}"
            )
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    run_benchmark()
