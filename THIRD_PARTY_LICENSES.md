# THIRD-PARTY OPEN DATA & SOFTWARE LICENSES (`SPECTRE v8.5.0+`)

SPECTRE (`spectre-recon`) strictly enforces clean-room engineering and open-data copyright compliance. Every offline threat-intelligence table, wordlist, domain suffix registry, hardware vendor prefix table, and declarative NVT template distributed with or compiled by SPECTRE originates exclusively from **U.S. Government Public Domain (`17 U.S.C. § 105`)**, **MIT**, **Apache-2.0**, **CC-BY-4.0**, **MPL-2.0**, **Public Standards Registries**, or **100% SPECTRE Clean-Room Original IP**.

Zero (`0`) files or code fragments from GPLv2/GPLv3 `.nasl` feeds, proprietary commercial vulnerability feeds, Nmap Public Source License (`NPSL`) data files (`nmap-service-probes`, `nmap-os-db`), or restricted commercial GeoIP databases are included.

---

## 1. CISA Known Exploited Vulnerabilities (KEV) & NIST NVD / CPE 2.3 Dictionary
- **Source:** Cybersecurity and Infrastructure Security Agency (`cisa.gov`) & National Institute of Standards and Technology (`nvd.nist.gov`)
- **SPDX Identifier:** `CC0-1.0` / `US-Gov-Public-Domain`
- **Legal Basis:** Pursuant to **17 U.S.C. § 105**, works produced by officers or employees of the United States Government as part of their official duties are in the worldwide public domain and free of copyright restrictions.

---

## 2. OSV.dev Open Source Advisories & FIRST.org EPSS Metadata
- **Source:** Google Open Source Insights (`osv.dev`) & Forum of Incident Response and Security Teams (`first.org/epss`)
- **SPDX Identifier:** `CC-BY-4.0` / `Apache-2.0`
- **Attribution:** Vulnerability advisory mappings incorporate open-source ecosystem data made available by OSV.dev contributors under Creative Commons Attribution 4.0 International (`https://creativecommons.org/licenses/by/4.0/`).

---

## 3. SecLists Discovery Wordlists (DNS Subdomains, Web Content & API Parameters)
- **Source:** `https://github.com/danielmiessler/SecLists` (`/usr/share/seclists/Discovery/`)
- **SPDX Identifier:** `MIT`
- **License Text:**

```text
MIT License

Copyright (c) 2018 Daniel Miessler, Jason Haddix, Ignacio Portal, g0tmi1k, and SecLists Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 4. Mozilla Public Suffix List (`public_suffix_list.dat`)
- **Source:** Mozilla Foundation (`https://publicsuffix.org/list/public_suffix_list.dat`, `/usr/share/publicsuffix/public_suffix_list.dat`)
- **SPDX Identifier:** `MPL-2.0`
- **Notice:** This data form is subject to the terms of the Mozilla Public License, v. 2.0. A copy of the MPL v2.0 is available at `https://mozilla.org/MPL/2.0/`. SPECTRE compiles unmodified suffix tokens into `intel/spectre_intel.db` without altering MPL-covered source files.

---

## 5. IEEE Registration Authority OUI Registry & IANA Service Port Registry
- **Source:** IEEE Registration Authority MA-L/OUI CSV (`/usr/share/ieee-data/oui.csv`) and IANA Service Names and Transport Protocol Port Numbers (`/etc/services`)
- **SPDX Identifier:** `Public-Registry-Data`
- **Notice:** Factual protocol port assignments and 24-bit IEEE Organizationally Unique Identifier (OUI) hardware manufacturer assignments are compiled from standard Debian/Ubuntu system packages (`ieee-data`, `netbase`) for offline asset classification.

---

## 6. SPECTRE Clean-Room Declarative NVT Pack & Technology Fingerprint Catalog
- **Source:** Authored in clean-room declarative JSON/Python format by SPECTRE R&D (`core/threat_intel_pack.py`, `config/nvt_catalog.json`)
- **SPDX Identifier:** `SPECTRE-Clean-Room` (`MIT`)
- **Notice:** Synthesized strictly from public CVE identifiers, vendor product names, and HTTP RFC specifications with `key=regex` Host Posture KB pre-flight gating and dual-baseline jitter calibration.
