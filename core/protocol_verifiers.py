"""
SPECTRE Active Non-Destructive Socket & Protocol NVT Verifiers
==============================================================
Performs safe, read-only protocol handshakes against open TCP ports (Redis,
Memcached, Elasticsearch, Prometheus, Docker API, Kubernetes Kubelet, Rsync,
FTP anonymous check, and SMTP EHLO/STARTTLS posture) with 95-99% QoD.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import socket
from typing import Any

from core.plugin_runner import QoD

SUPPORTED_ACTIVE_PORTS = {21, 25, 587, 873, 2375, 2376, 6379, 6443, 9100, 9200, 10250, 11211}


def _tcp_exchange(host: str, port: int, payloads: list[bytes], timeout: float = 2.6, read_initial: bool = False) -> str:
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if read_initial:
            try:
                chunks.append(sock.recv(2048))
            except Exception:
                pass
        for pl in payloads:
            sock.sendall(pl)
            try:
                data = sock.recv(4096)
                if data:
                    chunks.append(data)
            except Exception:
                break
    return b"\n".join(chunks).decode("utf-8", errors="ignore")


def _probe_data_and_metrics(db: Any, http_engine: Any, project_id: int, connect_target: str, target_ip: str, disp_host: str, port: int, log_fn: Any) -> int:
    hits = 0
    if port == 6379:
        out = _tcp_exchange(connect_target, 6379, [b"PING\r\n", b"INFO server\r\n"], timeout=2.5)
        if "+PONG" in out or "redis_version:" in out:
            m_ver = re.search(r"redis_version:([0-9]+\.[0-9]+\.[0-9]+)", out)
            ver_s = f"Redis {m_ver.group(1)}" if m_ver else "Redis"
            db.upsert_port(project_id, disp_host, 6379, "tcp", ip=target_ip, service="redis", version=ver_s, banner=out[:240], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Backend Data Store Access (Redis on {disp_host}:6379)",
                "Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:6379",
                f"Direct TCP PING/INFO succeeded ({ver_s})",
                "Redis xizmati parolsiz tashqi tarmoqdan buyruqlarni qabul qilmoqda.",
                "redis.conf ichida `bind 127.0.0.1` va kuchli `requirepass` / ACL o'rnating.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            log_fn(f"  [SOCKET-NVT] {disp_host}:6379 -> Unauthenticated {ver_s} tasdiqlandi!")
            hits += 1
    elif port == 11211:
        out = _tcp_exchange(connect_target, 11211, [b"stats\r\n", b"quit\r\n"], timeout=2.5)
        if "STAT pid" in out or "STAT version" in out:
            m_ver = re.search(r"STAT version\s+([0-9]+\.[0-9]+\.[0-9]+)", out)
            ver_s = f"Memcached {m_ver.group(1)}" if m_ver else "Memcached"
            db.upsert_port(project_id, disp_host, 11211, "tcp", ip=target_ip, service="memcached", version=ver_s, banner=out[:240], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Backend Data Store Access (Memcached on {disp_host}:11211)",
                "Database / Cache Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:11211",
                f"Direct TCP stats succeeded ({ver_s})",
                "Memcached kesh serveri autentifikatsiyasiz tashqi tarmoqqa ochiq qoldirilgan.",
                "Memcached xizmatini `-l 127.0.0.1` ga bog'lang va SASL autentifikatsiyasini yoqing.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 9200:
        for sch in ("http", "https"):
            try:
                r = http_engine.request("GET", f"{sch}://{connect_target}:9200/", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=32768)
                if r.status_code == 200 and '"cluster_name"' in r.text and '"version"' in r.text:
                    j = json.loads(r.text)
                    es_ver = str((j.get("version") or {}).get("number") or "")
                    ver_s = f"Elasticsearch {es_ver}".strip()
                    db.upsert_port(project_id, disp_host, 9200, "tcp", ip=target_ip, service="elasticsearch", version=ver_s, banner=r.text[:220], source="socket_nvt")
                    db.upsert_finding(
                        project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Backend Data Store Access (Elasticsearch on {disp_host}:9200)",
                        "Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "CWE-306", "A05:2021 - Security Misconfiguration", f"{sch}://{disp_host}:9200/",
                        f"Cluster: {j.get('cluster_name')} | Version: {es_ver}",
                        "Elasticsearch REST API autentifikatsiyasiz tashqi tarmoq uchun ochiq qoldirilgan.",
                        "`xpack.security.enabled: true` va `network.host: 127.0.0.1` sozlamalarini yoqing.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
                    break
            except Exception:
                continue
    elif port == 9100:
        r = http_engine.request("GET", f"http://{connect_target}:9100/metrics", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=49152)
        if r.status_code == 200 and ("node_uname_info" in r.text or "process_cpu_seconds_total" in r.text or "go_goroutines" in r.text):
            m_u = re.search(r"node_uname_info\{([^}]+)\}", r.text)
            uname_s = m_u.group(1)[:120] if m_u else "Prometheus /metrics active"
            db.upsert_port(project_id, disp_host, 9100, "tcp", ip=target_ip, service="prometheus-node-exporter", version="Node Exporter", banner=uname_s, source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Prometheus Node Exporter Metrics ({disp_host}:9100)",
                "Information Disclosure / Monitoring Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-200", "A05:2021 - Security Misconfiguration", f"http://{disp_host}:9100/metrics",
                f"HTTP 200 /metrics | {uname_s}",
                "Prometheus Node Exporter serverning ichki yadro, tarmoq va jarayon metrikalarini parolsiz oshkor qilmoqda.",
                "9100-portni tashqi interfeysdan Firewall orqali yoping va faqat monitoring serveriga ruxsat bering.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port in (2375, 2376):
        sch = "https" if port == 2376 else "http"
        r = http_engine.request("GET", f"{sch}://{connect_target}:{port}/version", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=16384)
        if r.status_code == 200 and '"ApiVersion"' in r.text and '"Version"' in r.text:
            j = json.loads(r.text)
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Docker Daemon API Exposure ({disp_host}:{port})",
                "Container / Infrastructure Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{sch}://{disp_host}:{port}/version",
                f"Docker Version: {j.get('Version')} | ApiVersion: {j.get('ApiVersion')} | OS: {j.get('Os')}",
                "Docker Engine API TLS mijoz sertifikatisiz tashqi tarmoqqa ochiq qoldirilgan.",
                "Docker TCP soketini o'chiring (`unix:///var/run/docker.sock`) yoki o'zaro mTLS (`--tlsverify`) yoqing.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port in (6443, 10250):
        ep_path = "/pods" if port == 10250 else "/version"
        r = http_engine.request("GET", f"https://{connect_target}:{port}{ep_path}", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=32768)
        if port == 10250 and r.status_code == 200 and '"items"' in r.text and '"metadata"' in r.text:
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Kubernetes Kubelet API ({disp_host}:10250)",
                "Container / Cluster Exposure", "Critical", 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"https://{disp_host}:10250/pods",
                f"HTTP 200 on Kubelet /pods ({len(r.text)}B)",
                "Kubernetes Kubelet API anonim so'rovlarga (`--anonymous-auth=true`) ruxsat bermoqda.",
                "Kubelet konfiguratsiyasida `--anonymous-auth=false` va `--authorization-mode=Webhook` yoqing.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    return hits


def _probe_single_port(
    db: Any,
    http_engine: Any,
    project_id: int,
    target_ip: str,
    disp_host: str,
    port: int,
    existing_ver: str,
    log_fn: Any,
) -> int:
    hits = 0
    connect_target = target_ip or disp_host
    try:
        if port in (6379, 11211, 9200, 9100, 2375, 2376, 6443, 10250):
            return _probe_data_and_metrics(db, http_engine, project_id, connect_target, target_ip, disp_host, port, log_fn)
        if port == 873:
            out = _tcp_exchange(connect_target, 873, [b"\n"], timeout=2.5, read_initial=True)
            if "@RSYNCD:" in out:
                mods = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("@RSYNCD")]
                if mods:
                    db.upsert_finding(
                        project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Rsync Daemon Modules ({disp_host}:873)",
                        "Unauthenticated File Share Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        "CWE-284", "A05:2021 - Security Misconfiguration", f"{disp_host}:873",
                        f"Rsync Modules: {', '.join(mods[:6])[:150]}",
                        "Rsync xizmati tashqi tarmoqqa ochiq modullar ro'yxatini qaytarmoqda.",
                        "rsyncd.conf ichida `hosts allow` va `auth users` o'rnating.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
        elif port == 21:
            out = _tcp_exchange(connect_target, 21, [b"USER anonymous\r\n", b"PASS anonymous@example.org\r\n", b"QUIT\r\n"], timeout=2.8, read_initial=True)
            first_ln = (out.splitlines()[0] if out else "").strip()
            if first_ln.startswith("220") and not existing_ver:
                db.upsert_port(project_id, disp_host, 21, "tcp", ip=target_ip, service="ftp", version=first_ln[4:90].strip(), banner=first_ln[:160], source="socket_nvt")
            if re.search(r"^230[\s\-]", out, re.M):
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Anonymous FTP Access Enabled ({disp_host}:21)",
                    "Authentication Bypass", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "CWE-287", "A07:2021 - Identification and Authentication Failures", f"{disp_host}:21",
                    f"Live FTP Socket: {first_ln[:80]} -> 230 Anonymous Login Succeeded",
                    "FTP serverda parolsiz anonim kirish amalda tasdiqlandi.",
                    "FTP konfiguratsiyasida `anonymous_enable=NO` o'rnating va SFTP ga o'ting.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
        elif port in (25, 587):
            out = _tcp_exchange(connect_target, port, [b"EHLO spectre.local\r\n", b"QUIT\r\n"], timeout=2.8, read_initial=True)
            first_ln = (out.splitlines()[0] if out else "").strip()
            if first_ln.startswith("220") and not existing_ver:
                db.upsert_port(project_id, disp_host, port, "tcp", ip=target_ip, service="smtp", version=first_ln[4:90].strip(), banner=out[:220], source="socket_nvt")
            out_up = out.upper()
            if ("AUTH PLAIN" in out_up or "AUTH LOGIN" in out_up) and "STARTTLS" not in out_up:
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] SMTP Cleartext Auth Advertised Without STARTTLS ({disp_host}:{port})",
                    "Cleartext Transmission", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-319", "A02:2021 - Cryptographic Failures", f"{disp_host}:{port}",
                    f"Live EHLO Capabilities: {out.replace(chr(13), '').replace(chr(10), ' | ')[:160]}",
                    "SMTP serveri STARTTLS shifrlashsiz ochiq matnda AUTH PLAIN/LOGIN e'lon qilmoqda.",
                    "`smtpd_tls_auth_only = yes` sozlamasini yoqing.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
                hits += 1
    except Exception:
        pass
    return hits


def run_active_protocol_verifiers(
    db: Any,
    http_engine: Any,
    project_id: int,
    ports: list[dict[str, Any]],
    domains: list[dict[str, Any]],
    log_fn: Any,
) -> int:
    non_cdn_dom_ip: dict[str, str] = {}
    ip_to_primary_dom: dict[str, str] = {}
    cdn_ips: set[str] = set()
    for d in (domains or []):
        dom = str(d.get("domain") or "").strip().lower()
        dip = str(d.get("ip") or "").strip()
        if dom and dip:
            if d.get("cdn_waf"):
                cdn_ips.add(dip)
            else:
                ip_to_primary_dom.setdefault(dip, dom)
                non_cdn_dom_ip[dom] = dip

    tasks: list[tuple[str, str, int, str]] = []
    seen_targets: set[tuple[str, int]] = set()
    for pt in (ports or []):
        if str(pt.get("protocol") or "tcp").lower() != "tcp":
            continue
        pnum = int(pt.get("port") or 0)
        if pnum not in SUPPORTED_ACTIVE_PORTS:
            continue
        raw_h = str(pt.get("host") or pt.get("ip") or "").strip().lower()
        pt_ip = str(pt.get("ip") or "").strip() or non_cdn_dom_ip.get(raw_h, "")
        if pt_ip and pt_ip in cdn_ips and pt_ip not in ip_to_primary_dom:
            continue
        dedup_k = pt_ip or raw_h
        if not dedup_k or (dedup_k, pnum) in seen_targets:
            continue
        seen_targets.add((dedup_k, pnum))
        disp_h = ip_to_primary_dom.get(dedup_k, raw_h or dedup_k)
        tasks.append((pt_ip, disp_h, pnum, str(pt.get("version") or "").strip()))

    if not tasks:
        return 0

    total_hits = 0
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(tasks)))
    futs = [
        ex.submit(_probe_single_port, db, http_engine, project_id, tip, dh, pn, ev, log_fn)
        for tip, dh, pn, ev in tasks[:24]
    ]
    done, _ = concurrent.futures.wait(futs, timeout=12.0)
    ex.shutdown(wait=False, cancel_futures=True)
    for fut in done:
        try:
            total_hits += int(fut.result() or 0)
        except Exception:
            pass
    if total_hits:
        log_fn(f"  [SOCKET-NVT] Jonli protokol tekshiruvi: {total_hits} ta tasdiqlangan xizmat zaifligi/metrikasi aniqlandi.")
    return total_hits


