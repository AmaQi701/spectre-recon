# SPECTRE v13.0 — Enterprise Architecture & AppSec Audit Roadmap

Ushbu hujjat `v12.13` jonli sinovlaridan keyingi xolis arxitektura tahlili asosida tuzilgan keyingi avlod (`v13.0`) modernizatsiya rejasidir.

---

## 1. `2-SuperAgent` (`vuln_agent.py`) — Haqiqiy AppSec & Access Control Auditor darajasiga olib chiqish
- **CLI Audit Orkestratsiyasi:** `1-Agent` oxirida turgan zaiflik tekshiruvchilarini (`Nuclei` konfiguratsiya/CVE shablonlari va xavfsiz kanareyka tekshiruvlarini) mantiqan `2-Agent` ga o‘tkazish va `1-Agent` ni sof razvedka (Recon) tezligida saqlash.
- **Multi-Role Authorization Matrix (Guest vs User A vs User B):** UI va `VulnAssessmentSuperAgent` ga ikkinchi avtorizatsiya sessiyasi (`Secondary Role Auth Header`) kiritish imkoniyatini qo‘shish — topilgan API endpointlarni `Guest`, `User A` va `User B` kontekstida strukturaviy solishtirish (Differential Access Control / BOLA Audit).
- **Xavfsiz Differential Verifikatorlar:** Harmless kanareyka (`spectre_audit_check`) va javob metrikalari (status, JSON kalitlari, Content-Type, kesh sarlavhalari) asosida yolg‘on pozitivsiz konfiguratsiya va avtorizatsiya zaifliklarini tasdiqlash.

## 2. `3-SuperAgent` (`triage_chain_agent.py`) — Haqiqiy Asset-Bound Graph Correlation
- Qotirilgan global `if "cors" in titles` shartlari o‘rniga **Aniq Xost va Endpoint Grafiga (`Exact Host + Port + Endpoint + Cookie/Header Context`)** bog‘langan zanjir dvigatelini qurish.
- Bir xil xostdagi real kombinatsiyalarni (masalan, aynan bitta subdomendagi `CORS Reflection` + `Cookie SameSite/HttpOnly` + `Authenticated API Route` yoki `Exposed SourceMap` + `SAST Sink`) matematik ravishda bog‘lash va CVSS zanjir bahosini hisoblash.

## 3. Asinxron HTTP Dvigateli (`AsyncIO / HTTPX Pool` + Global Rate-Limiter)
- Katta korporativ nishonlarda (`200+` subdomen) sinxron `requests` kutishlarini bartaraf etish uchun bosqichma-bosqich yagona ulanish puli, xost bo‘yicha adaptiv tezlik cheklovchisi (`Per-Host Token Bucket`) va `Circuit-Breaker` bilan himoyalangan asinxron so‘rov qatlamiga o‘tish.

## 4. "Version Soup" dan Toza Domen Modullariga O‘tish (Clean Domain-Driven Structure)
- `spectre_v5`, `ultra`, `predator`, `v10`, `v11`, `v12` fayllaridagi takroriy funksiyalarni (masalan, 3 joydagi Cloud Bucket tekshiruvi yoki 2 joydagi OAuth tahlili) bosqichma-bosqich vazifasiga ko‘ra yagona toza modullarga (`dns_intel`, `web_surface`, `js_deconstructor`, `api_schema`, `cloud_osint`) birlashtirish (`test_integrity_gate.py` ni buzmasdan!).

## 5. Lokal E2E Benchmark Server (`tests/test_local_benchmark.py`)
- Tashqi internet saytlarini 30 daqiqa kutmasdan har bir razvedka va audit modulining aniqligini **5 soniya ichida** tekshiradigan lokal (`127.0.0.1` vaqtinchalik Python `http.server` stendi) avtomatlashtirilgan integratsion test yaratish.
