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

## 4. Cumulative Changelog (`v8.5 -> v13.1`)
- **v8.5:** Wired all 49/49 CLI tools, fixed `merge_http_tech_stack` SQL column bug, added SQLite indexes, fixed `ScopeGuard` CDN override & `.lstrip('www.')` bug, non-blocking Ollama AI thread.
- **v9.0 (Predator):** Added 10 Dark-Attack-Surface modules + SourceMap-to-SAST bridge.
- **v10.0–v10.2 (Phantom):** Added 12 Enterprise Protocol/AST modules, calibrated `MagicByte-Verifier` (`Accept-Encoding: identity`), calibrated `X-Original-URL` & `Param-Miner`, fixed JS parameter bleed, skipped `502/503/504` dead hosts, added `HTTPAdapter(50, 50)`.
- **v11.0–v11.8 (Apex):** Added 8 Schema/Cluster modules, compiled `massdns` for `puredns`/`shuffledns`, fixed Python 3.14 `sublist3r` `fork` multiprocessing crash, optimized `subfinder` (`-es commoncrawl` -> 3.0s), scoped `katana` (`-fs rdn -ct 15s`), cached JS bundles for `TruffleHog`/`Gitleaks`, fixed Stage-1 Wildcard IP pre-filtering & Dangling CNAME `-rcode noerror,nxdomain` preservation.
- **v12.0–v12.4 (Titan):** Added 7 Titan modules (Headless Chrome V8, IPv6 Dual-Stack, CSP Static Nonce, Backend Correlator, Semantic REST, UDP 161/123, WASM/Server-Timing), remediated all 28 full-audit items, added `core/models.py`, `core/plugin_runner.py`, `agents/stages.py`, and `tests/test_integrity_gate.py` with Git `pre-commit` hook.
- **v12.5 (Stage 1 & Stage 2 Deep Engineering Overhaul):**
  - **Stage 1:** Resolved bare sub-zones (`www.student.<apex>` -> `student.<apex>`), added 16 education/enterprise prefixes (`lms`, `cctv`, `reg`, `student`, `jurnal`, `kpi`, `syllabus`, `hemis`, etc.), filtered `dnsgen`/`gotator` outputs to `*.{apex_domain}`, and restricted `_cached_session_get` to cache only `HTTP 200` responses without custom headers.
  - **Stage 2:** Chained `Naabu (Top-1000)` BEFORE `Nmap Deep NSE (-sV)` so Nmap dynamically inspects all open ports discovered by `Shodan + Naabu + Core Ports`, added Multi-Host Parallel TLS X.509 SAN inspection across top 8 subdomains, fixed `hunt_virtual_hosts` skipping `[ISP]`-tagged IPs, and moved `IPv6 Dual-Stack` & `UDP Safe Prober (161/SNMP, 123/NTP)` into Stage 2.
- **v12.6–v12.7 (Live-Target Telemetry Audit & Stage 3–6 Parallel/Deduplication Overhaul):**
  - **Stage 1:** Automatically prunes 100% dead `NXDOMAIN` passive OSINT noise (`ip='' AND cname='' AND records_json='{}'`) after DNS verification; queries `MX/TXT/NS/SOA` only on `apex_domain` to eliminate duplicate `www.` SPF findings.
  - **Stage 2:** Deduplicates `primary_host` vs IP across `Naabu/Nmap/Shodan`, preserves specific service names in `db.upsert_port`, filters router SIP/SCCP ALG fake ports (`2000, 5060`), and uses `--version-light --max-retries 1 --host-timeout 30s --script-timeout 8s` in Nmap.
  - **Stage 3–6:** Fixed multi-thread `self._last_probe_status` race condition via `threading.local()` + port-80 scheme priority; added Phase-B `404/Error` gate and `Smart Clone Application Deduplicator` (`(ip, title, script_sig)`); parallelized `whatweb`, `katana`, `httpx`, `hakrawler`, `subjs` (`ThreadPoolExecutor(max_workers=5)`); deduplicated JS bundle downloads across subdomains (`_seen_js_by_proj`); filtered 3rd-party vendor `.js.map` files (`bootstrap`, `jquery`, etc.); and fixed `TruffleHog` info-log false positive & `Sister Domains` cloud/PTR noise.
- **v12.8–v12.13 (Multi-Target Live Telemetry Hardening & Obsidian Emerald UI):**
  - **Pre-Flight & Loopback Safety:** Added 1.5s NXDOMAIN typo guard on `apex_domain` and `127.0.0.1` loopback DNS rebinding detector/self-scan blocker.
  - **Cloudflare NS vs Proxy & Hosting Ports:** Fixed false `cdn_waf="Cloudflare"` tag on origin IPs using Cloudflare NS only; added `1500/ISPmanager`, `2082–2096/cPanel-WHM`, `8006/Proxmox` to `STANDARD_PORT_SERVICES` and `WEB_CANDIDATE_PORTS`; mapped CPEs strictly by port protocol.
  - **Firewall Tarpit Protection & Crawl-Before-Fuzz Order:** Added Global Session Circuit-Breaker (`_guard_call`), uncached Phase-B liveness probe (`_raw_session_get`), safe out-of-scope `301/302` redirect capture, `Hakrawler` whitespace sanitizer, `wafw00f --no-colors` clean summary, `stream=True` context-manager socket closure, single-run `_ran_apex_suites` deduplication, and reordered Phase B (`Crawl -> JS Analyzer -> v9–v12 -> FFUF/Arjun`) so all JS bundles are cached before active brute-forcing.
  - **Obsidian & Cyber-Emerald UI:** Redesigned GTK3 workstation with Obsidian/Emerald palette (`#090c0a` + `#22c55e`), native `-symbolic` vector icons, borderless tables, interactive **Finding Inspector**, and syntax-colored **Target Dossier**.
- **v13.0–v13.1 (Enterprise Multi-Role BOLA Matrix, Asset-Bound Graph Chainer & Live-Audit Polish):**
  - **Enterprise v13.0 Modules:** Added `core/http_engine.py` (`RateLimitedHttpEngine` with per-host token-bucket RPS pacing & circuit-breaker), `agents/domain_facade.py`, **Multi-Role BOLA / Authz Matrix (`Guest vs Role-A vs Role-B`)** in `agents/vuln_agent.py` + `Role-B Auth` UI input, **Host-Indexed Asset-Bound Attack Graph Chainer** in `agents/triage_chain_agent.py`, and 2-second local E2E benchmark `tests/test_local_benchmark.py`.
  - **Live-Audit v13.1 Fixes (8 Root-Cause Remediations):**
    1. *ISP/FortiGuard Block-Page Filter & Cross-IP Clone Dedup:* Detected `Fortinet Secure DNS` / `FortiGuard` / `Cisco Umbrella` block portals in `_stage3_http_probe` (skipping Phase B fuzzing) and removed IP from `app_sig` (`(t_sig, sc_names, body_sig)`) so multi-subnet clones are deduplicated globally.
    2. *SecretHunter v2 Fintech Regex Fix:* Tightened `payme/click/uzum` regex to require explicit credential suffixes (`payme_(id|key|merchant|secret)`), eliminating false positives on generic English `PaymentMethod*` identifiers.
    3. *External Static-CDN `<script src>` Capture:* Prioritized live first-party `<script src>` / `modulepreload` JS bundles hosted on static CDNs ahead of archival Wayback URLs in `_stage4_html_and_wayback` while excluding analytics scripts.
    4. *Strict OIDC JSON Schema Check:* Required valid `"issuer"` + endpoint URLs in `mine_well_known_and_mobile_links` to prevent empty OIDC findings on generic JSON responses.
    5. *Preflight Echo Filter:* Excluded self-sent `X-Custom-Check` probe header in `harvest_cors_preflight_capabilities`.
    6. *S3Scanner & NetExec Output Parsers:* Parsed structured bucket/region/ACL fields from `s3scanner` logs and stripped IP/column padding from `netexec` SSH banners.
    7. *Browser-Grade User-Agent:* Replaced legacy scanner `User-Agent` in `ReconSuperAgent` and `apex_gtk_app.py` with standard Chrome Linux UA to reduce WAF `403` blocks.
    8. *Full-Pipeline Launch Button on Tab 0:* Added `Yaratish va To'liq Skaner (1 -> 2 -> 3)` (`auto_mode="all"`) on the New Target screen so all 3 SuperAgents run end-to-end automatically.
- **v14.0 (NASL-Titan KB-Driven Phased Orchestrator, Semantic CVE Catalog & QoD Standard):**
  - **KB-Driven Phased Gatekeeper (`core/plugin_runner.py`):** Added `ScanPhase` (`ACT_INIT` .. `ACT_END`), `QoD` (`Quality of Detection %` taxonomy: `99%`, `95%`, `90%`, `75%`, `70%`, `60%`), `ScanContextKB.hydrate_from_bundle()`, and O(1) `check_gate(require_keys, require_ports)` in `run_plugin_safely()` so plugins skip in 0 ms when required KB keys or ports are absent.
  - **Semantic Version & Vendor CVE Catalog (`core/advisory_kb.py`):** Added `parse_semver()`, `version_in_range()`, and `CURATED_CVE_ADVISORIES` matching `Apache`, `nginx`, `OpenSSH`, `PHP`, `OpenSSL`, `Redis`, `Exim`, and `IIS` versions from HTTP headers and port banners (`QoD: 75%`).
  - **Protocol, TLS & Cache Posture Auditors (`agents/vuln_agent.py`):** Added KB-gated `run_assessment` pipeline, `_audit_version_cve_advisories()`, `_audit_tls_and_cache_posture()` (deprecated TLS protocols & missing `Vary: Origin` on dynamic CORS), weak SSH KEX/cipher banner detection, and exposed backend data store / cleartext protocol classification.
  - **Graph Chainer & UI QoD Integration (`agents/triage_chain_agent.py`, `apex_gtk_app.py`):** Added `Public Web Application + Exposed Backend Data Store -> Backend Risk Chain` and `Exposed Service Surface + Outdated Component Advisory` correlation rules, HTML report `QoD` badges, and `Confidence / QoD` metadata in GTK3 Finding Inspector.




