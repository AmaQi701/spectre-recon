<div align="center">

<img src="ui/apex-icon.svg" width="105" alt="SPECTRE Logo" />

# SPECTRE (`spectre-recon`) v5.2.0

**Hybrid C++17 v2 / Python Attack Surface Management (ASM), 150-Rule Declarative NVT, 34-Port Socket NVT, 150-Product CPE 2.3, Cloud IaC Auditor, 14-Lockfile SCA, KEV+EPSS & Compliance/Drift Platform (GTK3 Desktop + Headless CLI)**

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Kali%20%7C%20Debian-0ea5e9?style=for-the-badge&logo=linux)](https://github.com/AmaQi701/spectre-recon)
[![Engine](https://img.shields.io/badge/Core-C%2B%2B17%20epoll%20%2B%20OpenSSL-ef4444?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-10b981?style=for-the-badge&logo=python)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/Desktop%20GUI-Native%20GTK3%20%2B%20Cairo-6366f1?style=for-the-badge&logo=gnome)](https://gtk.org/)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)

</div>

---

## Overview

**SPECTRE (`spectre-recon`)** is a native Linux **GTK3 Desktop Reconnaissance & Application Security Audit Platform** built for penetration testers, AppSec engineers, and red-team operators.

Instead of chaining fragile shell scripts or running heavy browser-bound wrappers, **SPECTRE** combines a thread-safe **SQLite WAL Asset Graph**, a deterministic **NASL-style Knowledge-Base (`ScanContextKB`) Orchestrator**, calibrated **Soft-404 / Catch-All VHost isolation**, **NIST CPE 2.3 semantic version advisory matching**, and an interactive **Cairo 2D Topology & HTTP Repeater Studio**.

---

## Core Architecture

### 1. Strict Scope & RoE Enforcement (`core/scope_guard.py`)
- RFC-1123 hostname validation, multi-level ccTLD apex resolution, CIDR/IPv4/IPv6 matching, explicit Out-of-Scope blocking, and automatic third-party CDN/Analytics exclusion.

### 2. Agent 1 — Multi-Stage Autonomous Recon (`agents/recon_agent.py`)
- **DNS & Passive OSINT (`cli_orchestrator.py`, `protocol_and_client.py`):** Certificate Transparency (`crt.sh`), wildcard DNS pre-filtering, recursive SPF/DMARC evaluation, and parallel CLI orchestration (`subfinder`, `amass`, `puredns`, `dnsx`, etc.).
- **Network, TLS & Dual-Stack Surface (`surface_prober.py`, `runtime_and_network.py`):** TLS SAN extraction, Nmap XML service/NSE parsing, Shodan InternetDB enrichment, ASN/subnet mapping, IPv6 dual-stack probing, non-standard web port discovery, and safe UDP service checks (`161/SNMP`, `123/NTP`).
- **Calibrated Web & API Discovery (`active_web_auditor.py`, `schema_and_iam.py`):** Soft-404 SHA-256 baseline calibration, reverse-proxy ACL bypass checks, OpenAPI `$ref` DTO synthesis, GraphQL field-suggestion introspection, Keycloak/OIDC realm mapping, and hidden parameter discovery.
- **SPA, SourceMap & Runtime Analysis (`origin_and_spa.py`, `runtime_and_network.py`):** Deep JS bundle & Webpack lazy-chunk extraction, `.js.map` SourceMap reconstruction, Headless Chromium V8 DOM route interception, `postMessage` receiver analysis, and WebAssembly (`.wasm`) endpoint extraction.

### 3. Agent 2 — Hybrid C++17 & KB-Gated Vulnerability Assessment (`agents/vuln_agent.py`)
- **Native C++17 Accelerator v2 (`core/native/spectre_accel.cpp`, `core/native_bridge.py`):** Dual-stack IPv4/IPv6 Linux `epoll` multi-port TCP/banner sweep, single-pass `spectre_structural_hash` HTML/JSON skeleton engine, `spectre_js_token_mask` byte pre-scanner, OpenSSL `HMAC` JWT key validation, hardware `popcount` `SimHash64` Hamming distance, `MurmurHash3`, and Shannon entropy scanning.
- **Active Socket Protocol NVTs (`core/protocol_verifiers.py`):** Direct read-only TCP & TLS protocol handshakes across 34 services (`RFC 4253 SSH_MSG_KEXINIT`, `MySQL/MariaDB`, `PostgreSQL`, `MongoDB`, `LDAP/LDAPS`, `Redis/Redis-TLS`, `Memcached`, `Elasticsearch`, `etcd`, `Consul`, `RabbitMQ`, `5672/AMQP`, `1883/8883/MQTT`, `2181/ZooKeeper`, `4222/NATS`, `9092/Kafka`, `8086/InfluxDB`, `8123/ClickHouse`, `Prometheus`, `Docker API`, `Kubernetes Kubelet`, `5900/VNC`, `1433/MSSQL`, `9042/Cassandra`, `Rsync`, `FTP`, and `SMTP`).
- **150-Rule Declarative & CMS NVT Engine (`core/nvt_declarative_engine.py`, `config/nvt_catalog.json`, `core/cms_enterprise_nvts.py`):** C++17 structural-hash calibrated checks across 150 enterprise gateways, AI/ML & Vector DB servers (`Ollama`, `vLLM`, `MLflow`, `Ray`, `Triton`, `Gradio`, `Langflow`, `Flowise`, `Qdrant`, `ChromaDB`, `Milvus`, `Weaviate`), DevOps control planes, databases, and CMS platforms.
- **150-Product CPE 2.3, Cloud-Native IaC, CISA KEV + FIRST.org EPSS & 14-Lockfile SCA Engine (`core/advisory_kb.py`, `core/iac_auditor.py`, `core/sca_engine.py`, `core/feed_updater.py`):** Deterministic SemVer advisory matching across 150 enterprise products, multi-stage `Dockerfile` / `docker-compose` / Kubernetes / Terraform IaC security checks, transitive lockfile auditing (`purl` + VEX), and CISA `KEV` + `EPSS` exploit probability correlation.
- **Differential Access Control (Multi-Role & Autonomous Guest BOLA Matrix):** Compares `Guest`, `Role A`, and `Role B` responses across API routes to confirm Broken Object Level Authorization (`CWE-639`) and unauthenticated API exposure (`CWE-306`), alongside calibrated GET/POST output encoding, `X-Forwarded-Host`, Open Redirect, OAuth2, JWT/JWS key-injection, GraphQL introspection, and Python AST / SourceMap SAST checks.

### 4. Agent 3 — Asset-Bound Attack Graph, Surface Drift & Compliance Studio (`agents/triage_chain_agent.py`, `core/compliance_exporter.py`, `core/surface_diff_engine.py`)
- Host-exact correlation of findings, session flags, dangling CNAMEs, exposed data stores/brokers, and API routes into multi-step **Attack Chains**, continuous **EASM Attack-Surface Drift** comparison across projects, and automated **OASIS SARIF 2.1.0, CycloneDX 1.5 VEX SBOM, JUnit XML, OWASP Top 10:2021 / OWASP API:2023 / PCI-DSS v4.0 / ISO 27001 Compliance Matrix, Markdown, HTML, CSV, JSON, and Burp Suite Scope** exports.

---

## Project Structure

```text
spectre-recon/
├── apex_gtk_app.py               # Native Linux GTK3 + Cairo 2D Topology Desktop GUI
├── launch_apex.sh                # Portable desktop launcher (Snap-safe GTK environment)
├── build_deb.sh                  # Debian (.deb) package builder
├── config/
│   ├── nvt_catalog.json          # 60 declarative enterprise/DevOps/DB/CMS NVT rules
│   └── tools_registry.yaml       # Configurable external CLI & built-in tool registry
├── core/
│   ├── native/
│   │   └── spectre_accel.cpp     # C++17 Linux epoll, JS token mask, OpenSSL HMAC & SimHash64
│   ├── native_bridge.py          # Auto-compiling ctypes bridge with Python fallbacks
│   ├── nvt_declarative_engine.py # Dual-baseline JSON declarative NVT runner
│   ├── protocol_verifiers.py     # 23-port active TCP/TLS/binary & SSH KEXINIT verifiers
│   ├── cms_enterprise_nvts.py    # Tech-gated CMS, framework & DevOps panel verifiers
│   ├── sca_engine.py             # Manifest SCA parser & cached OSV.dev batch query engine
│   ├── feed_updater.py           # Offline CISA KEV catalog synchronizer & enricher
│   ├── advisory_kb.py            # 106-product NIST CPE 2.3 & SemVer advisory catalog
│   ├── database.py               # Thread-safe SQLite WAL Asset Graph manager
│   ├── http_engine.py            # Streaming-capped, adaptive-backoff HTTP pool
│   ├── models.py                 # Strict TypedDict schema contracts
│   ├── plugin_runner.py          # ScanContextKB & PhaseOrchestrator engine
│   └── scope_guard.py            # Rules of Engagement (RoE) scope enforcer
├── agents/
│   ├── recon_agent.py            # Agent 1: 6-stage reconnaissance orchestrator
│   ├── vuln_agent.py             # Agent 2: KB-gated posture, CVE, SAST & BOLA auditor
│   ├── triage_chain_agent.py     # Agent 3: Asset-bound attack graph & report builder
│   ├── stages.py                 # Stage-to-capability index
│   ├── domain_facade.py          # Domain-driven capability namespaces
│   ├── cli_orchestrator.py       # External CLI runners, Repeater & artifact exporters
│   ├── surface_prober.py         # VHost, custom ports, shadow API & target dossier
│   ├── origin_and_spa.py         # Origin unmasking, PTR sweep & SPA manifest parsers
│   ├── active_web_auditor.py     # Proxy ACL, GraphQL, SourceMap, JWT & WebSocket checks
│   ├── protocol_and_client.py    # VCS, gRPC, cache policy, SPF/DMARC & WebStorage checks
│   ├── schema_and_iam.py         # OIDC/Keycloak, OpenAPI DTO & DOM SimHash clustering
│   └── runtime_and_network.py    # Headless V8, IPv6, CSP nonce, UDP & WASM analyzers
└── tests/
    ├── test_integrity_gate.py    # AST, signature, portability & schema integrity gate
    └── test_local_benchmark.py   # Self-contained local E2E verification benchmark
```

---

## Installation (Ubuntu / Kali / Debian)

### Option 1: Run Directly from Source

```bash
sudo apt update
sudo apt install -y python3 python3-gi gir1.2-gtk-3.0 python3-requests python3-yaml python3-dnspython python3-bs4 g++ libssl-dev nmap whois dnsutils

git clone https://github.com/AmaQi701/spectre-recon.git
cd spectre-recon
./launch_apex.sh
```

### Option 2: Headless Server & CI/CD CLI Mode (`spectre_cli.py`)

```bash
python3 spectre_cli.py --target example.org --mode full --fail-on high --min-qod 90
# Compare Attack-Surface & Vulnerability Drift vs Baseline Project #1:
python3 spectre_cli.py --target example.org --diff-project 1 --fail-on-drift
# Optional Read-Only Credentialed SSH CIS & Package Audit:
python3 spectre_cli.py --target example.org --ssh-audit auditor@example.org --ssh-key ~/.ssh/id_ed25519
```

### Option 3: Build & Install `.deb` Package

```bash
chmod +x build_deb.sh
./build_deb.sh
sudo dpkg -i dist/spectre-recon_5.0.0_amd64.deb
spectre-recon
```

### Verification Suite

```bash
python3 tests/test_integrity_gate.py
python3 tests/test_local_benchmark.py
```

---

## Legal Disclaimer

This software is intended strictly for **authorized security assessments, penetration testing, and defensive attack-surface auditing**. Always obtain explicit written authorization (Rules of Engagement) before testing any target.

---

## Author

**AmaQi701** — Security Auditor & Penetration Tester


