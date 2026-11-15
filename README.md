<div align="center">

<img src="ui/apex-icon.svg" width="105" alt="SPECTRE Logo" />

# SPECTRE (`spectre-recon`) v3.0.0

**Autonomous Attack Surface Management (ASM), Multi-Stage Reconnaissance, Differential Access-Control Auditing & Attack-Graph Correlation Studio for Linux (Native GTK3)**

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Kali%20%7C%20Debian-0ea5e9?style=for-the-badge&logo=linux)](https://github.com/AmaQi701/spectre-recon)
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

### 3. Agent 2 — KB-Gated Vulnerability & BOLA Assessment (`agents/vuln_agent.py`)
- **Phased Execution (`core/plugin_runner.py`):** O(1) `ScanContextKB` gating (`ACT_GATHER_INFO` -> `ACT_VERIFY`) with explicit **Quality of Detection (`QoD`)** confidence scoring.
- **Semantic CVE & CPE 2.3 Engine (`core/advisory_kb.py`):** Deterministic SemVer advisory matching across 27+ server/runtime stacks with Debian/Ubuntu/RHEL backport awareness.
- **Differential Access Control (Multi-Role BOLA Matrix):** Compares `Guest`, `Role A`, and `Role B` responses across discovered API routes to confirm Broken Object Level Authorization (`CWE-639`) and unauthenticated exposures.
- **Safe Active Verifiers:** Non-destructive checks for CORS origin reflection, unencoded HTML reflection, `X-Forwarded-Host` link poisoning, open redirects, and reconstructed SourceMap SAST scanning.

### 4. Agent 3 — Asset-Bound Attack Graph & Reporting (`agents/triage_chain_agent.py`)
- Host-exact correlation of findings, session flags, exposed data stores, and API routes into multi-step **Attack Chains** with automated **Markdown, HTML, CSV, JSON, and Burp Suite Scope** exports.

---

## Project Structure

```text
spectre-recon/
├── apex_gtk_app.py               # Native Linux GTK3 + Cairo 2D Topology Desktop GUI
├── launch_apex.sh                # Portable desktop launcher (Snap-safe GTK environment)
├── build_deb.sh                  # Debian (.deb) package builder
├── config/
│   └── tools_registry.yaml       # Configurable external CLI & built-in tool registry
├── core/
│   ├── advisory_kb.py            # NIST CPE 2.3 & SemVer vendor advisory catalog
│   ├── database.py               # Thread-safe SQLite WAL Asset Graph manager
│   ├── http_engine.py            # Per-host token-bucket & circuit-breaker HTTP pool
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
sudo apt install -y python3 python3-gi gir1.2-gtk-3.0 python3-requests python3-yaml python3-dnspython python3-bs4 nmap whois dnsutils

git clone https://github.com/AmaQi701/spectre-recon.git
cd spectre-recon
./launch_apex.sh
```

### Option 2: Build & Install `.deb` Package

```bash
chmod +x build_deb.sh
./build_deb.sh
sudo dpkg -i dist/spectre-recon_3.0.0_all.deb
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


