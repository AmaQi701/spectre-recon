<div align="center">

<img src="ui/apex-icon.svg" width="105" alt="SPECTRE Logo" />

# SPECTRE (`spectre-recon`) v8.0.0

**Hybrid C++17 v3 / Python Enterprise ASM, AI/LLM/RAG & MCP Security Auditor, 250-Rule Declarative + Custom YAML NVT, 50-Port Active Socket NVT, 250-Product NIST CPE 2.3, 6-Language Polyglot Taint SAST, Cloud/IaC v3, 18-Format 90-CVE SCA, 1-Click Reproducer/Patch Cookbook & 7-Framework (+MITRE ATT&CK v15) Platform**

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Kali%20%7C%20Debian-0ea5e9?style=for-the-badge&logo=linux)](https://github.com/AmaQi701/spectre-recon)
[![Engine](https://img.shields.io/badge/Core-C%2B%2B17%20epoll%20%2B%20OpenSSL-ef4444?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)
[![AI_Security](https://img.shields.io/badge/AI%20%26%20MCP%20Audit-Ollama%20%7C%20vLLM%20%7C%20Qdrant%20%7C%20MCP-8b5cf6?style=for-the-badge)](https://github.com/AmaQi701/spectre-recon)
[![GUI](https://img.shields.io/badge/Desktop%20GUI-Native%20GTK3%20%2B%20Cairo-6366f1?style=for-the-badge&logo=gnome)](https://gtk.org/)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)

</div>

---

## Why SPECTRE v8.0 Over Legacy Scanners?

| Capability | **SPECTRE v8.0 (OSS)** | Nessus Pro | OpenVAS / Greenbone | Nuclei | Trivy |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **100% Free & Open-Source** | **Yes (MIT)** | Paid Commercial | Yes | Yes | Yes |
| **Hybrid C++17 `epoll` + OpenSSL Kernel** | **Yes (`>350 MB/s`)** | Proprietary C/NASL | C / NASL | Go | Go |
| **AI/LLM, RAG Vector DB & MCP `tools/list` Audit** | **Built-in (`Ollama/vLLM/Qdrant/Chroma/Ray/MCP`)** | Partial | No | Community YAML | No |
| **Active Read-Only Binary/Text Socket NVTs** | **50 Protocols** | Yes | Yes | Limited TCP | No |
| **Declarative NVTs + Custom YAML / Nuclei SDK** | **250 Built-in + Custom YAML** | NASL Only | NASL Only | YAML | No |
| **6-Language Multi-Line Taint-Flow SAST** | **Py / JS / TS / Go / Java / PHP / C#** | No | No | No | No |
| **SourceMap (`.js.map`) Unpack -> White-Box SAST** | **Automatic** | No | No | No | No |
| **Polyglot Lockfile SCA + CycloneDX 1.5 VEX SBOM** | **18 Formats (`90` Offline + OSV.dev)** | Basic | No | No | Yes |
| **Cloud/IaC (`Dockerfile`, K8s RBAC/Ingress, Helm, TF, Nginx, Ansible)** | **Built-in** | Compliance Only | No | Partial | Yes |
| **Multi-Role BOLA / Authz Differential Matrix** | **Guest vs Role-A vs Role-B** | No | No | Manual | No |
| **1-Click Safe `curl` Reproducer + Ready Fix Patch** | **Every Finding** | No | No | curl Only | No |
| **Interactive SVG Kill-Chain + 7 Compliance Frameworks** | **OWASP / API / PCI v4 / ISO / NIST CSF 2 / SOC 2 / MITRE v15** | Paid Add-on | Basic | Paid Cloud | Partial |
| **Native Linux GTK3 + Cairo 2D Topology Studio + CLI** | **Both Included** | Web UI | Web UI | CLI Only | CLI Only |

---

## Overview

**SPECTRE (`spectre-recon`)** is a native Linux **GTK3 Desktop Reconnaissance & Application Security Audit Platform** built for penetration testers, AppSec engineers, and red-team operators.

Instead of chaining fragile shell scripts or running heavy browser-bound wrappers, **SPECTRE** combines a thread-safe **SQLite WAL Asset Graph**, a deterministic **NASL-style Knowledge-Base (`ScanContextKB`) Orchestrator**, calibrated **Soft-404 / Catch-All VHost isolation**, **NIST CPE 2.3 semantic version advisory matching**, and an interactive **Cairo 2D Topology & HTTP Repeater Studio**.

---

## Core Architecture

### 1. Strict Scope & RoE Enforcement (`core/scope_guard.py`)
- RFC-1123 hostname validation, multi-level ccTLD apex resolution, CIDR/IPv4/IPv6 matching, explicit Out-of-Scope blocking, and automatic third-party CDN/Analytics exclusion.

### 2. Phase 1 — Multi-Stage Autonomous Recon (`agents/recon_agent.py`)
- **DNS & Passive OSINT (`cli_orchestrator.py`, `protocol_and_client.py`):** Certificate Transparency (`crt.sh`), wildcard DNS pre-filtering, recursive SPF/DMARC evaluation, and parallel CLI orchestration (`subfinder`, `amass`, `puredns`, `dnsx`, etc.).
- **Network, TLS & Dual-Stack Surface (`surface_prober.py`, `runtime_and_network.py`):** TLS SAN extraction, Nmap XML service/NSE parsing, Shodan InternetDB enrichment, ASN/subnet mapping, IPv6 dual-stack probing, non-standard web port discovery, and safe UDP service checks (`161/SNMP`, `123/NTP`).
- **Calibrated Web & API Discovery (`active_web_auditor.py`, `schema_and_iam.py`):** Soft-404 SHA-256 baseline calibration, reverse-proxy ACL bypass checks, OpenAPI `$ref` DTO synthesis, GraphQL field-suggestion introspection, Keycloak/OIDC realm mapping, and hidden parameter discovery.
- **SPA, SourceMap & Runtime Analysis (`origin_and_spa.py`, `runtime_and_network.py`):** Deep JS bundle & Webpack lazy-chunk extraction, `.js.map` SourceMap reconstruction, Headless Chromium V8 DOM route interception, `postMessage` receiver analysis, and WebAssembly (`.wasm`) endpoint extraction.

### 3. Phase 2 — Hybrid C++17 v3 & KB-Gated Vulnerability Assessment (`agents/vuln_agent.py`)
- **Native C++17 Accelerator v3 (`core/native/spectre_accel.cpp`, `core/native_bridge.py`):** Dual-stack IPv4/IPv6 Linux `epoll` multi-port TCP/banner sweep, single-pass `spectre_secret_prefilter_mask` (`>350 MB/s`), `spectre_structural_hash` HTML/JSON skeleton engine, `spectre_js_token_mask` byte pre-scanner, OpenSSL `HMAC` JWT key validation, hardware `popcount` `SimHash64`, `MurmurHash3`, and Shannon entropy scanning.
- **50-Port Active Socket Protocol NVTs (`core/protocol_verifiers.py`):** Direct read-only TCP & TLS protocol handshakes across 50 services (`RFC 4253 SSH_MSG_KEXINIT`, `MySQL/MariaDB`, `PostgreSQL`, `MongoDB`, `LDAP/LDAPS`, `Redis/Redis-TLS`, `Memcached`, `Elasticsearch`, `etcd`, `Consul`, `RabbitMQ`, `AMQP`, `MQTT/MQTTS`, `ZooKeeper`, `NATS`, `Kafka`, `InfluxDB`, `ClickHouse`, `Prometheus`, `Docker API`, `Docker Registry v2`, `Kubernetes Kubelet`, `VNC`, `RDP X.224 NLA`, `WinRM`, `Java RMI`, `JDWP`, `FastCGI`, `MSSQL`, `Cassandra`, `WebLogic T3`, `ActiveMQ OpenWire`, `SOCKS5`, `Hadoop HDFS`, `Oracle TNS`, `NFSv4 RPC`, `SIP`, `Zabbix`, `Rsync`, `FTP`, `POP3`, `IMAP`, and `SMTP`).
- **AI/LLM, RAG Vector DB & MCP Security Auditor (`core/ai_llm_auditor.py`):** Read-only exposure verification across `Ollama` (`/api/tags`), `vLLM` / `LiteLLM` (`/v1/models`), `Qdrant` (`/collections`), `ChromaDB`, `Ray Dashboard`, and `Model Context Protocol (MCP)` JSON-RPC `tools/list` endpoints.
- **250-Rule Declarative, Custom YAML & CMS NVT Engine (`core/nvt_declarative_engine.py`, `config/nvt_catalog.json`, `core/cms_enterprise_nvts.py`):** C++17 structural-hash calibrated checks across 250 enterprise gateways, AI/ML & Vector DB servers, Zero-Trust/VPN appliances, IAM providers, observability control planes, databases, and CMS platforms, plus user-extensible YAML / Nuclei-compatible rules (`config/custom_nvts/`).
- **250-Product CPE 2.3, Cloud/IaC v3, CI/CD Auditor, CISA KEV + EPSS & 18-Format SCA Engine (`core/advisory_kb.py`, `core/iac_auditor.py`, `core/cicd_workflow_auditor.py`, `core/sca_engine.py`, `core/feed_updater.py`):** Deterministic SemVer advisory matching across 250 products, `Dockerfile` / `docker-compose` / Kubernetes Pod, RBAC & Ingress / Helm `values.yaml` / Ansible / `nginx.conf` / Terraform IaC checks, GitHub Actions / GitLab CI / Jenkinsfile / `.npmrc` / Spring config hygiene, 18-format lockfile/manifest SCA (`90` offline CVEs + OSV.dev + `purl` + VEX across npm, PyPI, Packagist, Go, Maven, Gradle, NuGet, RubyGems, Cargo, Dart/Flutter, Elixir), and CISA `KEV` + `EPSS` correlation.
- **Differential Access Control & 6-Language Multi-Line Taint-Flow SAST (`agents/vuln_agent.py`, `core/sast_ast_engine.py`):** Compares `Guest`, `Role A`, and `Role B` responses across API routes to confirm Broken Object Level Authorization (`CWE-639`) and unauthenticated API exposure (`CWE-306`), alongside OAuth2 PKCE, JWT header (`jku`/`x5u`/`kid`) & key-confusion checks, GraphQL batching/field-suggestion checks, and 6-language multi-line taint-flow SAST (`Python`, `JS/TS`, `Go`, `Java`, `PHP`, `C#`).

### 4. Phase 3 — Attack-Graph Correlation, Reproducer Cookbook & 7-Framework Compliance (`agents/triage_chain_agent.py`, `core/remediation_cookbook.py`, `core/compliance_exporter.py`, `core/surface_diff_engine.py`)
- Host-exact correlation of findings, session flags, AI/MCP & Cloud Ingress exposures, dangling CNAMEs, data stores, and API routes into interactive **SVG Kill-Chain Graphs**, 1-click safe `curl`/`openssl` verification reproducers and ready-to-apply fix patches, continuous **EASM Attack-Surface Drift**, and automated **OASIS SARIF 2.1.0, CycloneDX 1.5 VEX SBOM, JUnit XML, and 7-Framework Compliance (`OWASP Top 10:2021`, `OWASP API:2023`, `PCI-DSS v4.0`, `ISO/IEC 27001:2022`, `NIST CSF 2.0`, `AICPA SOC 2 TSC`, `MITRE ATT&CK Enterprise v15`)** exports.

---

## Project Structure

```text
spectre-recon/
├── apex_gtk_app.py               # Native Linux GTK3 + Cairo 2D Topology & Posture Studio
├── spectre_cli.py                # Headless CI/CD CLI (--benchmark, --doctor, --export-project, --diff-project)
├── launch_apex.sh                # Portable desktop launcher (Snap-safe GTK environment)
├── build_deb.sh                  # Debian (.deb) package builder
├── config/
│   ├── nvt_catalog.json          # 250 declarative enterprise, AI/LLM, Zero-Trust & DB NVT rules
│   ├── custom_nvts/              # Optional user YAML / Nuclei-compatible custom NVT directory
│   └── tools_registry.yaml       # Configurable external CLI & built-in tool registry
├── core/
│   ├── native/
│   │   └── spectre_accel.cpp     # C++17 v3 epoll, secret prefilter, structural hash, OpenSSL HMAC & SimHash64
│   ├── native_bridge.py          # Auto-compiling ctypes bridge with deterministic Python fallbacks
│   ├── ai_llm_auditor.py         # Ollama, vLLM/LiteLLM, Qdrant, ChromaDB, Ray & MCP JSON-RPC auditor
│   ├── remediation_cookbook.py   # 1-Click safe curl/openssl reproducers & ready-to-apply fix patches
│   ├── nvt_declarative_engine.py # Dual-baseline JSON + Custom YAML NVT runner
│   ├── protocol_verifiers.py     # 50-port read-only TCP/TLS/binary & SSH KEXINIT verifiers
│   ├── sast_ast_engine.py        # 6-language multi-line taint-flow SAST (Py, JS/TS, Go, Java, PHP, C#)
│   ├── iac_auditor.py            # Dockerfile, Compose, K8s Pod/RBAC/Ingress, Helm, Ansible, Nginx & Terraform
│   ├── cicd_workflow_auditor.py  # GitHub Actions, GitLab CI, Jenkinsfile, .npmrc & Spring config auditor
│   ├── sca_engine.py             # 18-format lockfile/manifest SCA (90 offline CVEs + OSV.dev + purl)
│   ├── compliance_exporter.py    # SARIF 2.1.0, CycloneDX 1.5 VEX, JUnit & 7-Framework (+MITRE v15) exporter
│   ├── surface_diff_engine.py    # Continuous EASM attack-surface & posture drift comparator
│   ├── credentialed_auditor.py   # Agentless read-only SSH CIS & distro package security auditor
│   ├── cms_enterprise_nvts.py    # Tech-gated CMS, framework & DevOps panel verifiers
│   ├── feed_updater.py           # CISA KEV + FIRST.org EPSS exploit probability enricher
│   ├── advisory_kb.py            # 250-product NIST CPE 2.3 & SemVer advisory catalog
│   ├── database.py               # Thread-safe SQLite WAL Asset Graph manager
│   ├── http_engine.py            # Zero-refetch cached, adaptive-backoff HTTP pool
│   ├── models.py                 # Strict TypedDict schema contracts
│   ├── plugin_runner.py          # ScanContextKB & PhaseOrchestrator engine
│   └── scope_guard.py            # Rules of Engagement (RoE) scope enforcer
├── agents/
│   ├── recon_agent.py            # Phase 1: 6-stage autonomous OSINT, DNS, TLS & web surface mapper
│   ├── stages.py                 # Modular stage registry & execution pipeline
│   ├── active_web_auditor.py     # Soft-404 calibrated ACL, SourceMap, GraphQL, JWT & parameter auditor
│   ├── origin_and_spa.py         # Origin IP unmasking, SPA manifest & JS bundle route/secret extractor
│   ├── protocol_and_client.py    # SPF/DMARC, Web Cache Deception, VCS & CORS verification
│   ├── runtime_and_network.py    # Chromium V8 DOM, IPv6 dual-stack, CSP nonce, UDP & WASM analyzer
│   ├── schema_and_iam.py         # OpenAPI DTO synthesis, OAuth2 PKCE, JWT header & OIDC realm auditor
│   ├── surface_prober.py         # Non-standard web ports, VHost hunter & target dossier builder
│   ├── cli_orchestrator.py       # External CLI wrappers, HTTP repeater & multi-format exporter
│   ├── vuln_agent.py             # Phase 2: KB-gated NVT, 50-port socket, AI/MCP, SAST, IaC, SCA & BOLA
│   └── triage_chain_agent.py     # Phase 3: SVG Kill-Chain correlation & 7-framework report studio
└── tests/
    ├── test_integrity_gate.py    # AST, schema, signature & deterministic runtime gate
    └── test_local_benchmark.py   # Full loopback E2E multi-protocol & multi-language benchmark
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
# Verify C++17 kernel, 250-NVT / 250-CPE catalogs, 50-port verifiers & DB health:
python3 spectre_cli.py --doctor
# Run live 1 MB C++17 throughput micro-benchmark:
python3 spectre_cli.py --benchmark
# Full headless enterprise scan + CI/CD QoD gate:
python3 spectre_cli.py --target example.org --mode full --fail-on high --min-qod 90
# Compare Attack-Surface & Vulnerability Drift vs Baseline Project #1:
python3 spectre_cli.py --target example.org --diff-project 1 --fail-on-drift
# Fast offline artifact re-export (HTML v8.0 SVG, SARIF 2.1.0, CycloneDX 1.5 VEX, 7-Framework Matrix):
python3 spectre_cli.py --export-project 1
```

### Option 3: Build & Install `.deb` Package

```bash
chmod +x build_deb.sh
./build_deb.sh
sudo dpkg -i dist/spectre-recon_8.0.0_amd64.deb
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


