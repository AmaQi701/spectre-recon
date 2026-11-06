<div align="center">

<img src="ui/apex-icon.svg" width="110" alt="APEX-ASM Logo" />

# 🛡️ APEX-ASM & Audit Studio v2.0

**Autonomous Attack Surface Management, Deep JS/API Intelligence, Vulnerability Assessment, Bug Chaining & Pentest Reporting Studio for Linux (Native GTK3 + Web UI)**

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Kali%20%7C%20Debian-0ea5e9?style=for-the-badge&logo=linux)](https://github.com/AmaQi701/apex-asm-studio)
[![Python](https://img.shields.io/badge/Python-3.10%2B-10b981?style=for-the-badge&logo=python)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/Desktop%20GUI-Native%20GTK3%20%2B%20Dark%20Mode-6366f1?style=for-the-badge&logo=gnome)](https://gtk.org/)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)

</div>

---

## ⚡ Overview

**APEX-ASM & Audit Studio** is an open-source, modular **Multi-Agent Security Assessment & Attack Surface Management (ASM)** desktop platform engineered for professional penetration testers, AppSec engineers, and red-team auditors.

Unlike brittle bash wrappers or browser-bound dashboards, **APEX-ASM Studio** provides a **100% Native Ubuntu/Linux GTK3 Dark-Mode Desktop GUI** backed by a persistent **SQLite WAL Asset Graph** and a **Dynamic YAML Tool Registry**.

---

## 🏗️ Multi-Agent Architecture

- **🛡️ Module 0 — Strict Scope & RoE Enforcer (`core/scope_guard.py`):**
  - Automatic Apex Domain normalization (`www.target.com` -> `target.com` + `*.target.com`), CIDR/IP matching, out-of-scope blocking, and third-party CDN/Analytics exclusion.
- **🛰️ SuperAgent 1 — Autonomous Recon & ASM Engine (`agents/recon_agent.py`):**
  - **Stage 1 (Passive & DNS):** Certificate Transparency (`crt.sh`), 60+ concurrent subdomain resolver (`dnspython`), and automatic MX/TXT(SPF)/CNAME/NS extraction with **Wildcard DNS filtering**.
  - **Stage 2 (Network, Port & TLS):** SSL/TLS SAN extractor & Nmap (`-Pn -sV --top-ports 100 -oX -`) XML service parser.
  - **Stage 3 (Web Probing & Fingerprinting):** HTTP/HTTPS status, titles, server banners, tech-stack detection, WAF identification (`whatweb`, `wafw00f`), and cookie/security header inspection.
  - **Stage 4 (Crawling & Archives):** `katana` JS-aware crawler, HTML form/input parser, and Wayback Machine CDX collector with **Logout/Destructive URL Guard**.
  - **Stage 5 (API & Sensitive Path Discovery):** Concurrent probing of 35+ sensitive paths (`swagger.json`, `openapi.json`, `graphql`, `robots.txt`, `sitemap.xml`, `/.env`, `/.git/HEAD`, `/actuator`) with **Soft-404 baseline filtering**.
  - **Stage 6 (Deep SPA JS Bundle Deconstructor):** Concurrent extraction of template-literal API routes (`` `${baseUrl}/api/v1/orders/${id}` ``), backend URLs, parameter keys, DOM XSS sinks, and config secrets across 40+ JS chunks.
- **🔍 SuperAgent 2 — Vulnerability Assessment & SAST (`agents/vuln_agent.py`):**
  - Active Safe CORS Origin Reflection testing, Security Header & Cookie auditing, Network port exposure checks, Manual Testing Prioritizer (`IDOR/BOLA`, `SSRF`, `LFI`, `Business Logic` candidates), White-box SAST scanner, and JWT Token Decoder.
- **🔗 SuperAgent 3 & 5 — Triage, Bug Chaining & Report Studio (`agents/triage_chain_agent.py`):**
  - Interactive Triage (`Verified` / `Manual-Review` / `False-Positive`), automated Bug Chaining correlation, One-Click `Copy as cURL` with Grey-box Auth headers, and instant **Markdown & HTML Report** generation.

---

## 🚀 Installation (Ubuntu / Kali / Debian)

### Option 1: Build & Install Official `.deb` Package (Recommended)

```bash
git clone https://github.com/AmaQi701/apex-asm-studio.git
cd apex-asm-studio
chmod +x build_deb.sh
./build_deb.sh
sudo dpkg -i dist/apex-asm-studio_2.0_all.deb
```

Launch **APEX-ASM Pentest Studio** from your Ubuntu Applications Menu or terminal:
```bash
apex-asm-studio
```

### Option 2: Run Directly from Source

```bash
sudo apt update
sudo apt install -y python3 python3-gi gir1.2-gtk-3.0 python3-requests python3-yaml python3-dnspython python3-bs4 python3-flask nmap whois dnsutils

git clone https://github.com/AmaQi701/apex-asm-studio.git
cd apex-asm-studio
./launch_apex.sh
```

---

## 📂 Project Structure

```text
apex-asm-studio/
├── apex_gtk_app.py           # Native Ubuntu GTK3 Desktop GUI Application
├── app.py                    # Optional Flask REST & Web Dashboard Server
├── launch_apex.sh            # Native Desktop Launcher (with Snap env sanitizer)
├── build_deb.sh              # Debian (.deb) Package Builder Script
├── config/
│   └── tools_registry.yaml   # Dynamic CLI & Built-in Recon Tool Registry
├── core/
│   ├── database.py           # Thread-safe SQLite WAL Asset Graph Engine
│   └── scope_guard.py        # Strict RoE & Apex Domain Scope Enforcer
├── agents/
│   ├── recon_agent.py        # SuperAgent 1: 6-Stage Autonomous Recon & JS Parser
│   ├── vuln_agent.py         # SuperAgent 2: Vuln Assessment, Active CORS & SAST
│   └── triage_chain_agent.py # SuperAgent 3: Triage, Bug Chaining & Report Builder
└── ui/
    ├── apex-icon.svg         # Vector Application Icon
    ├── index.html            # Web Dashboard Interface
    └── app.js                # Web Dashboard Frontend Controller
```

---

## ⚖️ Legal Disclaimer

This software is designed strictly for **authorized security assessments, penetration testing, and educational purposes**. Always obtain explicit written permission (Rules of Engagement) from the asset owner before scanning or auditing any target. The author assumes no liability for misuse or unauthorized damage.

---

## 👤 Author

**AmaQi701** — Security Auditor & Penetration Tester

