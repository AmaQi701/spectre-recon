# 🏛️ SPECTRE Recon & Attack Surface Studio — Architecture Memory & Engineering Rules
**(Permanent Project Memory, Schema Bible & Engineering Standards — v12.4)**

> **CRITICAL RULE FOR AI / DEVELOPERS:**
> Before editing ANY file in this repository, read this document first. After completing any architectural change, update Section 4 (Changelog) and run `python3 tests/test_integrity_gate.py` (must return `ERRORS_FOUND=0`).

---

## 1. Ten Golden Engineering Rules (40-Year Systems Engineering Standard)
1. **Atomic Edits Only:** Never modify more than 1–2 logical components at a time without running `python3 tests/test_integrity_gate.py`.
2. **Strict Schema Compliance (`core/models.py`):** Never invent dictionary keys on database rows or bundles. Use only the canonical column names listed in Section 2 below.
3. **Zero Silent Failures:** High-level recon and audit plugins run inside `core.plugin_runner.run_plugin_safely()` so exceptions and execution durations (`elapsed_ms`) are recorded in `task_logs` instead of swallowed silently.
4. **Non-Blocking Concurrency:** Never use `with concurrent.futures.ThreadPoolExecutor(...) as ex:` (which blocks indefinitely on `__exit__`). Always use:
   ```python
   ex = concurrent.futures.ThreadPoolExecutor(max_workers=N)
   futs = [ex.submit(...)]
   concurrent.futures.wait(futs, timeout=T)
   ex.shutdown(wait=False, cancel_futures=True)
   ```
5. **Subprocess Safety (`_run_cli`):** All external CLI calls must pass `stdin=subprocess.DEVNULL`, `preexec_fn=os.setsid`, and a watchdog `threading.Timer`.
6. **Mandatory Calibration Before Reporting:** Any active HTTP discovery check (Reverse-Proxy ACL, Semantic REST, Shadow API, Archive Magic-Bytes, Hidden Params, Cache Deception) MUST calibrate against a deterministic nonexistent path (`/spectre-nonexistent-99182`) and compare status code, content-length, and SHA-256 hash to prevent soft-200 / SPA fallback false positives.
7. **Shared HTTP Session Cache:** Standard read-only `GET` requests on `ReconSuperAgent.session` are cached in `self._http_get_cache` per scan. Pass custom `headers={"Cache-Control": "no-cache"}` only when a fresh un-cached response is explicitly required (e.g., static CSP nonce comparison).
8. **CDN vs ISP Separation:** `domains.cdn_waf` must ONLY store actual CDN/WAF names (`Cloudflare`, `Akamai`, `Fastly`, `CloudFront`, `Imperva`, `DDoS-Guard`, `Qrator`), never regular ISP names (`Uzbektelecom`, etc.), which belong in `records_json["asn_intel"]`.
9. **GTK3 Thread Safety:** Never perform network I/O or heavy computation on the GTK main thread. Use daemon `threading.Thread` and update UI widgets exclusively via `GLib.idle_add`.
10. **Privacy & Scope Discipline:** Never hardcode or log sensitive third-party/government production data in code or tests; use `ScopeGuard` (`core/scope_guard.py`) on every discovered asset.

---

## 2. Canonical SQLite Database Schema (`core/database.py` & `core/models.py`)
Database file: `workspaces/apex_state.db` (`WAL` mode, thread-safe `RLock`).
Bundle keys returned by `db.get_project_bundle(project_id)`:
- `project`: `id, name, primary_target, in_scope, out_of_scope, source_code_path, notes, status, created_at`
- `domains`: `id, project_id, domain, ip, cname, records_json, cdn_waf, source, in_scope, created_at`
- `ports`: `id, project_id, host, ip, port, protocol, service, version, banner, source, created_at`
- `http_services`: `id, project_id, url, status_code, title, server, tech_stack, content_length, headers_json, security_headers_json, cookies_json, tls_json, waf, priority_score, source, created_at`
- `endpoints`: `id, project_id, url, method, params_json, category, risk_tags_json, status_code, source, created_at`
- `js_assets`: `id, project_id, js_url, endpoints_json, params_json, sinks_json, secrets_hints_json, created_at`
- `findings`: `id, project_id, agent, title, category, severity, cvss_score, cvss_vector, cwe, owasp, asset, evidence, root_cause, remediation, confidence, triage_status, created_at`
- `bug_chains`: `id, project_id, chain_title, severity, cvss_score, nodes_json, attack_scenario, impact, remediation, created_at`
- `task_logs`: `id, project_id, agent, tool, status, command, summary, created_at`

---

## 3. Complete Architecture & File Map
- `apex_gtk_app.py` — Native Ubuntu GTK3 Desktop UI (7 tabs, Cairo 2D Topology Graph, Interactive HTTP Repeater, Smart Noise Filter, Right-Click Context Menu).
- `core/database.py` — `DatabaseManager` (SQLite WAL CRUD, `merge_http_tech_stack`, `scan_snapshots`).
- `core/scope_guard.py` — `ScopeGuard` (RFC-1123 hostname validator, `.gov.uz`/`.com.uz` 2nd-level TLD apex extractor, RoE filter).
- `core/models.py` — `TypedDict` schema definitions & `FORBIDDEN_HALLUCINATED_KEYS`.
- `core/plugin_runner.py` — Nessus-style `ScanContextKB` (Shared Knowledge Base) & fault-isolated `run_plugin_safely()` telemetry wrapper.
- `agents/stages.py` — Stage 1–6 modular index of all 46 internal reconnaissance engines.
- `agents/recon_agent.py` — `ReconSuperAgent` (6-Stage Pipeline, 8-OSINT Mesh, Hybrid `dnsx`+`dnspython` Fast-Path, Smart Priority Web Prober, JS Deconstructor).
- `agents/spectre_v5_modules.py` — 49-Tool CLI execution wrappers, ASN/ISP Mapper, Deep SSL Auditor, Multi-Target Nuclei/FFUF/Katana/Naabu/Nmap runners, Artifact Exporter, HTTP Repeater, Ollama AI Tactical Analyst.
- `agents/spectre_deep_modules.py` — Non-Standard Web Port Prober, VHost Hunter, Cloud Storage Hunter, Cookie Scope Auditor, Custom Wordlist Miner, Persistent Snapshot Differ, PTT Target Dossier, Calibrated Shadow API Prober.
- `agents/spectre_ultra_modules.py` — TLS SNI Origin IP Unmasker, `/24` PTR Sweeper, SPA/Next/Nuxt Manifest Deconstructor, SecretHunter v2 (live Telegram Bot verification), Mobile/OIDC Miner, Redirect-Chain Tracker, Document Metadata OSINT, Adaptive Brain, Safe Auto-Validator (`"<>` HTML reflection PoC).
- `agents/spectre_predator_modules.py` (`v9.0`) — Favicon MMH3 Fingerprinter, SourceMap (`*.js.map`) Unpacker -> White-Box SAST Bridge, Calibrated Reverse-Proxy ACL Auditor, Calibrated Arjun Binary-Search Param Miner, WebSocket CSWSH Auditor, Multi-Cloud/Container Enumerator, GraphQL Field-Suggestion & Batching Auditor, Dependency Confusion Hunter, JWT Offline HMAC Cracker, Second-Order `<script src>` NXDOMAIN Takeover Hunter.
- `agents/spectre_v10_modules.py` (`v10.0`) — VCS (`.git/config` & `logs/HEAD`) Auditor, Static Autoindex Auditor, gRPC-Web/Protobuf Extractor, Brace-Balanced `postMessage` AST Analyzer, Cache Suffix Auditor, Recursive RFC-7208 SPF/DMARC Validator, Service Worker Route Harvester, HTTP/3 `Alt-Svc` Topology Mapper, OAuth PKCE/State Auditor, Analytics ID Pivot, `Range: bytes=0-63` (`identity`) Archive Magic-Byte Verifier, Client WebStorage Role Mapper.
- `agents/spectre_v11_modules.py` (`v11.0`) — Keycloak/OIDC Realm Mapper, OpenAPI `$ref` DTO Synthesizer, Structural DOM SimHash Clusterer, Webpack Lazy-Chunk Predictor, `i18n` Dictionary Miner, ETag Inode Auditor, CORS `OPTIONS` Custom-Header Harvester, Sister-Domain Scope Recommender.
- `agents/spectre_v12_modules.py` (`v12.0`) — Headless Chrome V8 DOM & Route Renderer, Dual-Stack IPv6 (`AAAA`) Origin Prober, Deep CSP Directive & Static-Nonce Auditor, Multi-Signal Backend Correlator, Semantic REST CRUD Predictor, Non-Root UDP (`161/SNMP` & `123/NTP`) Inspector, WebAssembly (`.wasm`) Binary Deconstructor & `Server-Timing` Microservice Miner.
- `agents/vuln_agent.py` — `VulnAssessmentSuperAgent` (2-SuperAgent: Security Headers, Active CORS Reflection, Host-Grouped IDOR/SSRF/Business-Logic Guides, 9-Rule White-Box SAST + Unpacked SourceMap SAST).
- `agents/triage_chain_agent.py` — `TriageAndChainSuperAgent` (3-SuperAgent: Triage, 8 Dynamic Bug Chains, Markdown & Escaped HTML Reports).
- `tests/test_integrity_gate.py` — Automated AST, Function Signature, Schema & 49-Tool Readiness Gate (wired to `.git/hooks/pre-commit`).

---

## 4. Cumulative Changelog (`v8.5 -> v12.4`)
- **v8.5:** Wired all 49/49 CLI tools, fixed `merge_http_tech_stack` SQL column bug, added SQLite indexes, fixed `ScopeGuard` CDN override & `.lstrip('www.')` bug, non-blocking Ollama AI thread.
- **v9.0 (Predator):** Added 10 Dark-Attack-Surface modules + SourceMap-to-SAST bridge.
- **v10.0–v10.2 (Phantom):** Added 12 Enterprise Protocol/AST modules, calibrated `MagicByte-Verifier` (`Accept-Encoding: identity`), calibrated `X-Original-URL` & `Param-Miner`, fixed JS parameter bleed, skipped `502/503/504` dead hosts, added `HTTPAdapter(50, 50)`.
- **v11.0–v11.8 (Apex):** Added 8 Schema/Cluster modules, compiled `massdns` for `puredns`/`shuffledns`, fixed Python 3.14 `sublist3r` `fork` multiprocessing crash, optimized `subfinder` (`-es commoncrawl` -> 3.0s), scoped `katana` (`-fs rdn -ct 15s`), cached JS bundles for `TruffleHog`/`Gitleaks`, fixed Stage-1 Wildcard IP pre-filtering & Dangling CNAME `-rcode noerror,nxdomain` preservation.
- **v12.0–v12.4 (Titan):** Added 7 Titan modules (Headless Chrome V8, IPv6 Dual-Stack, CSP Static Nonce, Backend Correlator, Semantic REST, UDP 161/123, WASM/Server-Timing), remediated all 28 full-audit items, added `core/models.py`, `core/plugin_runner.py`, `agents/stages.py`, and `tests/test_integrity_gate.py` with Git `pre-commit` hook.

