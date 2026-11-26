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
import ssl
import struct
from typing import Any

from core.plugin_runner import QoD

SUPPORTED_ACTIVE_PORTS = {
    21, 22, 25, 110, 143, 389, 587, 636, 873, 1022, 1080, 1099, 1433, 1521, 1883,
    2049, 2181, 2375, 2376, 2379, 3306, 3389, 4222, 5000, 5005, 5060, 5432, 5672,
    5900, 5985, 6379, 6380, 6443, 7001, 8086, 8123, 8500, 8883, 9000, 9042, 9092,
    9100, 9200, 10050, 10250, 11211, 15672, 27017, 50070, 61616,
}


def parse_ssh_kexinit_packet(raw_stream: bytes) -> dict[str, list[str]]:
    """Parses an RFC 4253 Section 7.1 binary SSH_MSG_KEXINIT (type 20) packet into algorithm lists."""
    if not raw_stream or len(raw_stream) < 28:
        return {}
    idx = 0
    if raw_stream.startswith(b"SSH-"):
        nl_pos = raw_stream.find(b"\n")
        if nl_pos == -1:
            return {}
        idx = nl_pos + 1
    while idx + 22 <= len(raw_stream):
        pkt_len = struct.unpack("!I", raw_stream[idx : idx + 4])[0]
        pad_len = raw_stream[idx + 4]
        if 16 <= pkt_len <= 32768 and idx + 4 + pkt_len <= len(raw_stream):
            payload = raw_stream[idx + 5 : idx + 4 + pkt_len - pad_len]
            if len(payload) > 17 and payload[0] == 20:
                pos = 17  # 1-byte msg_type (20) + 16-byte random cookie
                lists: list[list[str]] = []
                for _ in range(8):
                    if pos + 4 > len(payload):
                        break
                    slen = struct.unpack("!I", payload[pos : pos + 4])[0]
                    pos += 4
                    if pos + slen > len(payload):
                        break
                    s_val = payload[pos : pos + slen].decode("ascii", errors="ignore")
                    lists.append([x.strip() for x in s_val.split(",") if x.strip()])
                    pos += slen
                if len(lists) >= 6:
                    return {
                        "kex": lists[0],
                        "host_key": lists[1],
                        "enc": sorted(set(lists[2] + lists[3])),
                        "mac": sorted(set(lists[4] + lists[5])),
                    }
        idx += 1
    return {}


def _tcp_exchange(host: str, port: int, payloads: list[bytes], timeout: float = 2.6, read_initial: bool = False, use_tls: bool = False) -> str:
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
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
    if port in (6379, 6380):
        out = _tcp_exchange(connect_target, port, [b"PING\r\n", b"INFO server\r\n"], timeout=2.5, use_tls=(port == 6380))
        if "+PONG" in out or "redis_version:" in out:
            m_ver = re.search(r"redis_version:([0-9]+\.[0-9]+\.[0-9]+)", out)
            ver_s = f"Redis {m_ver.group(1)}" if m_ver else "Redis"
            db.upsert_port(project_id, disp_host, port, "tcp", ip=target_ip, service="redis", version=ver_s, banner=out[:240], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Backend Data Store Access (Redis on {disp_host}:{port})",
                "Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:{port}",
                f"Direct {'TLS' if port == 6380 else 'TCP'} PING/INFO succeeded ({ver_s})",
                "Redis xizmati parolsiz tashqi tarmoqdan buyruqlarni qabul qilmoqda.",
                "redis.conf ichida `bind 127.0.0.1` va kuchli `requirepass` / ACL o'rnating.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            log_fn(f"  [SOCKET-NVT] {disp_host}:{port} -> Unauthenticated {ver_s} tasdiqlandi!")
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
    elif port == 2379:
        r = http_engine.request("GET", f"http://{connect_target}:2379/version", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=16384)
        if r.status_code == 200 and '"etcdserver"' in r.text:
            j = json.loads(r.text)
            et_v = str(j.get("etcdserver") or "")
            db.upsert_port(project_id, disp_host, 2379, "tcp", ip=target_ip, service="etcd", version=f"etcd {et_v}".strip(), banner=r.text[:160], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated etcd Cluster Endpoint ({disp_host}:2379)",
                "Container / Cluster Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"http://{disp_host}:2379/version",
                f"etcdserver: {et_v} | etcdcluster: {j.get('etcdcluster', '')}",
                "etcd kalit-qiymat klasteri mijoz TLS sertifikatisiz tashqi tarmoqqa ochiq qoldirilgan.",
                "`--client-cert-auth=true` yoqing va 2379-portni faqat klaster control-plane tugunlariga cheklang.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 8500:
        r = http_engine.request("GET", f"http://{connect_target}:8500/v1/agent/self", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=32768)
        if r.status_code == 200 and '"Config"' in r.text and '"Datacenter"' in r.text:
            db.upsert_port(project_id, disp_host, 8500, "tcp", ip=target_ip, service="consul", version="HashiCorp Consul", banner=r.text[:160], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated HashiCorp Consul Agent API ({disp_host}:8500)",
                "Infrastructure / Service Mesh Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"http://{disp_host}:8500/v1/agent/self",
                f"HTTP 200 Consul /v1/agent/self ({len(r.text)}B)",
                "HashiCorp Consul API ACL tokensiz tashqi so'rovlarga klaster ma'lumotlarini qaytarmoqda.",
                "Consul konfiguratsiyasida `acl.enabled = true` va `default_policy = \"deny\"` o'rnating.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 15672:
        r = http_engine.request("GET", f"http://{connect_target}:15672/api/overview", timeout=(2.2, 3.0), allow_redirects=False, max_bytes=24576)
        if r.status_code == 200 and '"rabbitmq_version"' in r.text:
            j = json.loads(r.text)
            rmq_v = str(j.get("rabbitmq_version") or "")
            db.upsert_port(project_id, disp_host, 15672, "tcp", ip=target_ip, service="rabbitmq-mgmt", version=f"RabbitMQ {rmq_v}".strip(), banner=r.text[:160], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated RabbitMQ Management API ({disp_host}:15672)",
                "Message Broker Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"http://{disp_host}:15672/api/overview",
                f"RabbitMQ Version: {rmq_v}",
                "RabbitMQ Management API autentifikatsiyasiz xabar brokeri ma'lumotlarini qaytarmoqda.",
                "15672-portni ichki tarmoqqa cheklang va standart hisob yozuvlarini o'chiring.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    return hits


def _probe_binary_db_and_ldap(db: Any, project_id: int, connect_target: str, target_ip: str, disp_host: str, port: int, log_fn: Any) -> int:
    hits = 0
    if port == 3306:
        with socket.create_connection((connect_target, 3306), timeout=2.5) as s:
            s.settimeout(2.5)
            pkt = s.recv(512)
        if len(pkt) >= 6:
            proto_b = pkt[4]
            if proto_b == 0x0A:
                end_v = pkt.find(b"\x00", 5)
                if end_v > 5:
                    ver_str = pkt[5:end_v].decode("utf-8", errors="ignore").strip()
                    plugin_m = re.search(rb"(mysql_native_password|caching_sha2_password|mariadb_gssapi_client)", pkt[end_v:])
                    plug_s = plugin_m.group(1).decode("ascii") if plugin_m else ""
                    lbl_v = f"MariaDB {ver_str}" if "mariadb" in ver_str.lower() else f"MySQL {ver_str}"
                    db.upsert_port(project_id, disp_host, 3306, "tcp", ip=target_ip, service="mysql", version=lbl_v, banner=f"{lbl_v} {plug_s}".strip(), source="socket_nvt")
            elif proto_b == 0xFF and len(pkt) > 7:
                err_txt = pkt[7:].decode("utf-8", errors="ignore").strip()
                db.upsert_port(project_id, disp_host, 3306, "tcp", ip=target_ip, service="mysql", banner=err_txt[:160], source="socket_nvt")

    elif port == 5432:
        body = b"user\x00postgres\x00database\x00postgres\x00\x00"
        startup = struct.pack("!II", len(body) + 8, 196608) + body
        with socket.create_connection((connect_target, 5432), timeout=2.5) as s:
            s.settimeout(2.5)
            s.sendall(startup)
            resp = s.recv(1024)
        if resp.startswith(b"R") and len(resp) >= 9:
            auth_code = struct.unpack("!I", resp[5:9])[0]
            db.upsert_port(project_id, disp_host, 5432, "tcp", ip=target_ip, service="postgresql", banner=f"PG AuthCode={auth_code}", source="socket_nvt")
            if auth_code == 0:
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Backend Data Store Access (PostgreSQL Trust on {disp_host}:5432)",
                    "Database / Cache Exposure", "Critical", 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:5432",
                    "PostgreSQL StartupMessage returned AuthenticationOk (code=0, pg_hba.conf trust)",
                    "PostgreSQL serveri tashqi ulanishlarga parolsiz (`trust` rejimida) kirishga ruxsat bermoqda.",
                    "`pg_hba.conf` faylida `trust` o'rniga `scram-sha-256` o'rnating va portni ichki tarmoqqa cheklang.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1

    elif port == 27017:
        bson_doc = b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
        op_query = struct.pack("<IIII", 0, 0, 0, 1) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + bson_doc
        wire_pkt = struct.pack("<IIII", len(op_query) + 16, 1, 0, 2004) + op_query
        with socket.create_connection((connect_target, 27017), timeout=2.5) as s:
            s.settimeout(2.5)
            s.sendall(wire_pkt)
            resp = s.recv(2048)
        if b"maxWireVersion" in resp or b"ismaster" in resp:
            db.upsert_port(project_id, disp_host, 27017, "tcp", ip=target_ip, service="mongodb", version="MongoDB", banner="MongoDB Wire Handshake OK", source="socket_nvt")

    elif port in (389, 636):
        # Standard ASN.1 BER LDAPv3 Anonymous Simple BindRequest (messageID=1, version=3, name="", simple="")
        ldap_bind = bytes.fromhex("300c020101600702010304008000")
        with socket.create_connection((connect_target, port), timeout=2.5) as raw_s:
            if port == 636:
                ctx_l = ssl.create_default_context()
                ctx_l.check_hostname = False
                ctx_l.verify_mode = ssl.CERT_NONE
                s: socket.socket = ctx_l.wrap_socket(raw_s, server_hostname=disp_host)
            else:
                s = raw_s
            s.settimeout(2.5)
            s.sendall(ldap_bind)
            resp = s.recv(512)
        if len(resp) >= 7 and b"\x61" in resp[:6] and b"\x0a\x01\x00" in resp[:14]:
            db.upsert_port(project_id, disp_host, port, "tcp", ip=target_ip, service="ldaps" if port == 636 else "ldap", version="LDAPv3", banner="Anonymous Bind Allowed", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] LDAP Anonymous Bind Permitted ({disp_host}:{port})",
                "Directory Service Misconfiguration", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-284", "A01:2021 - Broken Access Control", f"{disp_host}:{port}",
                "LDAPv3 Simple BindRequest (empty DN/password) returned resultCode=0 (success)",
                "LDAP serveri parolsiz (Anonymous Bind) ulanishga ruxsat bermoqda.",
                "OpenLDAP (`disallow bind_anon`) yoki Active Directory da anonim LDAP so'rovlarini o'chiring.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            log_fn(f"  [SOCKET-NVT] {disp_host}:{port} -> LDAP Anonymous Bind tasdiqlandi!")
            hits += 1

    elif port == 5900:
        with socket.create_connection((connect_target, 5900), timeout=2.5) as s_vnc:
            s_vnc.settimeout(2.2)
            rfb_ver = s_vnc.recv(16)
            if rfb_ver.startswith(b"RFB "):
                ver_txt = rfb_ver.decode("ascii", errors="ignore").strip()
                db.upsert_port(project_id, disp_host, 5900, "tcp", ip=target_ip, service="vnc", version=ver_txt, banner=ver_txt, source="socket_nvt")
                s_vnc.sendall(rfb_ver[:12])
                sec_b = s_vnc.recv(32)
                no_auth = False
                if b"003.003" in rfb_ver and len(sec_b) >= 4 and struct.unpack("!I", sec_b[:4])[0] == 1:
                    no_auth = True
                elif len(sec_b) >= 2 and sec_b[0] > 0 and 1 in sec_b[1 : 1 + sec_b[0]]:
                    no_auth = True
                if no_auth:
                    db.upsert_finding(
                        project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated VNC Remote Desktop Service ({disp_host}:5900)",
                        "Remote Desktop Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "CWE-306", "A07:2021 - Identification and Authentication Failures", f"{disp_host}:5900",
                        f"RFB Handshake ({ver_txt}) offered SecurityType=1 (None)",
                        "VNC serveri parolsiz masofaviy ekran ulanishiga (SecurityType=None) ruxsat bermoqda.",
                        "VNC serverda parol talabini yoqing va 5900-portni faqat SSH/VPN tunnel orqali oching.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1

    elif port == 1433:
        tds_prelogin = bytes.fromhex("1201001d00000100000015000601001b0001ff09000000000002")
        with socket.create_connection((connect_target, 1433), timeout=2.5) as s_ms:
            s_ms.settimeout(2.2)
            s_ms.sendall(tds_prelogin)
            resp = s_ms.recv(512)
        if len(resp) >= 28 and resp[0] == 0x04:
            pl = resp[8:]
            if len(pl) >= 18 and pl[0] == 0x00:
                v_off = struct.unpack("!H", pl[1:3])[0]
                if v_off + 4 <= len(pl):
                    maj, min_v, bld = pl[v_off], pl[v_off + 1], struct.unpack("!H", pl[v_off + 2 : v_off + 4])[0]
                    ms_ver = f"Microsoft SQL Server {maj}.{min_v}.{bld}"
                    db.upsert_port(project_id, disp_host, 1433, "tcp", ip=target_ip, service="ms-sql-s", version=ms_ver, banner=ms_ver, source="socket_nvt")

    elif port == 9042:
        cql_opts = b"\x04\x00\x00\x00\x05\x00\x00\x00\x00"
        with socket.create_connection((connect_target, 9042), timeout=2.5) as s_cas:
            s_cas.settimeout(2.2)
            s_cas.sendall(cql_opts)
            resp = s_cas.recv(512)
        if len(resp) >= 9 and (resp[4] == 0x06 or b"CQL_VERSION" in resp):
            db.upsert_port(project_id, disp_host, 9042, "tcp", ip=target_ip, service="cassandra", version="Apache Cassandra CQL", banner="CQL Binary Protocol SUPPORTED", source="socket_nvt")
    return hits


def _probe_messaging_and_tsdb(
    db: Any,
    http_engine: Any,
    project_id: int,
    connect_target: str,
    target_ip: str,
    disp_host: str,
    port: int,
    log_fn: Any,
) -> int:
    hits = 0
    if port in (1883, 8883):
        mqtt_conn = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x1e\x00\x04spct"
        with socket.create_connection((connect_target, port), timeout=2.5) as raw_m:
            if port == 8883:
                ctx_m = ssl.create_default_context()
                ctx_m.check_hostname = False
                ctx_m.verify_mode = ssl.CERT_NONE
                s_m: socket.socket = ctx_m.wrap_socket(raw_m, server_hostname=disp_host)
            else:
                s_m = raw_m
            s_m.settimeout(2.2)
            s_m.sendall(mqtt_conn)
            resp = s_m.recv(16)
            try:
                s_m.sendall(b"\xe0\x00")
            except Exception:
                pass
        if len(resp) >= 4 and resp[0] == 0x20 and resp[1] == 0x02:
            rc_code = resp[3]
            db.upsert_port(project_id, disp_host, port, "tcp", ip=target_ip, service="mqtts" if port == 8883 else "mqtt", version="MQTT v3.1.1", banner=f"CONNACK rc={rc_code}", source="socket_nvt")
            if rc_code == 0x00:
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated MQTT Message Broker Access ({disp_host}:{port})",
                    "Message Broker Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:{port}",
                    "MQTT v3.1.1 anonymous CONNECT returned CONNACK returnCode=0x00 (Connection Accepted)",
                    "MQTT broker parolsiz anonim obuna va xabar yuborishga ruxsat bermoqda.",
                    "Mosquitto/EMQX da `allow_anonymous false` o'rnating va TLS + ACL yoqing.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
    elif port == 2181:
        out = _tcp_exchange(connect_target, 2181, [b"envi"], timeout=2.5)
        if "Environment:" in out or "zookeeper.version=" in out:
            mv = re.search(r"zookeeper\.version=([0-9]+\.[0-9]+\.[0-9]+)", out)
            zk_v = f"Apache ZooKeeper {mv.group(1)}" if mv else "Apache ZooKeeper"
            db.upsert_port(project_id, disp_host, 2181, "tcp", ip=target_ip, service="zookeeper", version=zk_v, banner=out[:200], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated ZooKeeper Cluster Environment Exposure ({disp_host}:2181)",
                "Cluster Coordination Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:2181",
                f"ZooKeeper 'envi' command succeeded without ACL: {zk_v}",
                "ZooKeeper 4-harfli ma'muriy buyrug'i autentifikatsiyasiz tizim va klaster muhitini oshkor qilmoqda.",
                "`4lw.commands.whitelist` ni cheklang va SASL autentifikatsiya hamda tarmoq ACL o'rnating.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 4222:
        out = _tcp_exchange(connect_target, 4222, [], timeout=2.4, read_initial=True)
        if out.startswith("INFO {"):
            try:
                info_json = json.loads(out[5:].splitlines()[0])
                nv = str(info_json.get("version") or "")
                db.upsert_port(project_id, disp_host, 4222, "tcp", ip=target_ip, service="nats", version=f"nats-server {nv}".strip(), banner=out[:200], source="socket_nvt")
                if info_json.get("auth_required") is False:
                    db.upsert_finding(
                        project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated NATS Messaging Bus ({disp_host}:4222)",
                        "Message Broker Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:4222",
                        f"NATS INFO banner confirmed auth_required=false (version={nv})",
                        "NATS xabar almashish shinasida autentifikatsiya o'chirilgan (`auth_required: false`).",
                        "NATS konfiguratsiyasida NKey/JWT yoki token autentifikatsiyani majburiy yoqing.",
                        confidence=QoD.ACTIVE_VERIFIED,
                    )
                    hits += 1
            except Exception:
                pass
    return hits + _probe_kafka_amqp_tsdb(db, http_engine, project_id, connect_target, target_ip, disp_host, port)


def _probe_kafka_amqp_tsdb(
    db: Any,
    http_engine: Any,
    project_id: int,
    connect_target: str,
    target_ip: str,
    disp_host: str,
    port: int,
) -> int:
    hits = 0
    if port == 5672:
        with socket.create_connection((connect_target, 5672), timeout=2.5) as s_amq:
            s_amq.settimeout(2.2)
            s_amq.sendall(b"AMQP\x00\x00\x09\x01")
            resp = s_amq.recv(1024)
        if len(resp) > 12 and resp[0] == 0x01:
            txt_a = resp.decode("latin-1", errors="ignore")
            mr = re.search(r"RabbitMQ[^a-zA-Z0-9]{0,8}(\d+\.\d+\.\d+)", txt_a)
            av = f"RabbitMQ {mr.group(1)}" if mr else "AMQP 0-9-1 Broker"
            db.upsert_port(project_id, disp_host, 5672, "tcp", ip=target_ip, service="amqp", version=av, banner=av, source="socket_nvt")
    elif port == 9092:
        k_body = struct.pack("!hhih", 3, 0, 7742, 2) + b"sp" + struct.pack("!i", 0)
        k_pkt = struct.pack("!i", len(k_body)) + k_body
        with socket.create_connection((connect_target, 9092), timeout=2.5) as s_kf:
            s_kf.settimeout(2.2)
            s_kf.sendall(k_pkt)
            hdr = s_kf.recv(8)
            rest = s_kf.recv(2048) if len(hdr) == 8 else b""
        if len(hdr) == 8 and len(rest) >= 8:
            r_len, corr_id = struct.unpack("!ii", hdr)
            broker_cnt = struct.unpack("!i", rest[:4])[0]
            if corr_id == 7742 and 8 <= r_len <= 1048576 and 1 <= broker_cnt <= 256:
                db.upsert_port(project_id, disp_host, 9092, "tcp", ip=target_ip, service="kafka", version="Apache Kafka", banner=f"Plaintext Brokers={broker_cnt}", source="socket_nvt")
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Apache Kafka Broker Metadata Access ({disp_host}:9092)",
                    "Streaming / Queue Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:9092",
                    f"Kafka MetadataRequest v0 returned {broker_cnt} active cluster broker(s) over unauthenticated PLAINTEXT",
                    "Apache Kafka brokeri SASL autentifikatsiyasiz klaster va topic metama'lumotlarini ochiq qaytarmoqda.",
                    "`SASL_SSL` tinglovchisiga o'ting va Kafka `AclAuthorizer` ni yoqing.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
    elif port == 8086:
        rp = http_engine.request("GET", f"http://{connect_target}:8086/query?q=SHOW+DATABASES", timeout=(2.0, 2.8), allow_redirects=False)
        inf_v = rp.headers.get("X-Influxdb-Version", "")
        if inf_v:
            db.upsert_port(project_id, disp_host, 8086, "tcp", ip=target_ip, service="influxdb", version=f"InfluxDB {inf_v}", banner=f"InfluxDB {inf_v}", source="socket_nvt")
        if rp.status_code == 200 and '"results"' in rp.text and '"databases"' in rp.text:
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated InfluxDB Database Access ({disp_host}:8086)",
                "Database / Cache Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:8086",
                f"GET /query?q=SHOW+DATABASES returned HTTP 200 (Version: {inf_v or 'detected'})",
                "InfluxDB ma'lumotlar bazasida HTTP autentifikatsiya o'chirilgan (`auth-enabled = false`).",
                "`[http] auth-enabled = true` sozlamasini yoqing va tashqi kirishni yoping.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 8123:
        rc = http_engine.request("GET", f"http://{connect_target}:8123/?query=SELECT%20version()", timeout=(2.0, 2.8), allow_redirects=False)
        ch_ver = (rc.text or "").strip()
        if rc.status_code == 200 and "X-ClickHouse-Summary" in rc.headers and re.match(r"^\d+\.\d+\.\d+", ch_ver):
            db.upsert_port(project_id, disp_host, 8123, "tcp", ip=target_ip, service="clickhouse", version=f"ClickHouse {ch_ver[:24]}", banner=f"ClickHouse {ch_ver[:24]}", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated ClickHouse SQL Interface ({disp_host}:8123)",
                "Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:8123",
                f"Unauthenticated SQL SELECT version() returned ClickHouse {ch_ver[:24]}",
                "ClickHouse HTTP SQL interfeysi parolsiz (`default` foydalanuvchi) so'rovlarni bajarmoqda.",
                "`users.xml` da `default` foydalanuvchiga parol va IP cheklovi o'rnating.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    return hits


def _probe_enterprise_rpc_and_mgmt(
    db: Any, http_engine: Any, project_id: int, connect_target: str, target_ip: str, disp_host: str, port: int, connect_port: int | None = None
) -> int:
    hits = 0
    cp = connect_port or port
    if port == 110:
        out = _tcp_exchange(connect_target, cp, [b"CAPA\r\n", b"QUIT\r\n"], timeout=2.5, read_initial=True)
        up = out.upper()
        if "+OK" in up and "STLS" not in up and ("USER" in up or "PLAIN" in up):
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Cleartext POP3 Authentication Without STLS ({disp_host}:110)",
                "Cleartext Mail Protocol Exposure", "Medium", 5.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-319", "A02:2021 - Cryptographic Failures", f"{disp_host}:110",
                "POP3 CAPA advertised USER/PLAIN login without STLS transport upgrade",
                "POP3 xizmati parollarni shifrlanmagan TCP oqimida qabul qilmoqda (`STLS` mavjud emas).",
                "POP3S (`:995`) yoki majburiy `STLS` rejimini yoqing.",
                confidence=QoD.PROTOCOL_VERIFIED,
            )
            hits += 1
    elif port == 143:
        out = _tcp_exchange(connect_target, cp, [b"a01 CAPABILITY\r\n", b"a02 LOGOUT\r\n"], timeout=2.5, read_initial=True)
        up = out.upper()
        if "CAPABILITY" in up and "IMAP4" in up and "STARTTLS" not in up and "LOGINDISABLED" not in up:
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Cleartext IMAP Authentication Without STARTTLS ({disp_host}:143)",
                "Cleartext Mail Protocol Exposure", "Medium", 5.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-319", "A02:2021 - Cryptographic Failures", f"{disp_host}:143",
                "IMAP CAPABILITY permitted cleartext LOGIN without STARTTLS or LOGINDISABLED",
                "IMAP xizmati `STARTTLS` shifrlashisiz ochiq matnli login ruxsat etmoqda.",
                "IMAPS (`:993`) yoki majburiy `STARTTLS` + `LOGINDISABLED` sozlang.",
                confidence=QoD.PROTOCOL_VERIFIED,
            )
            hits += 1
    elif port == 1099:
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_rmi:
            s_rmi.settimeout(2.2)
            s_rmi.sendall(b"JRMI\x00\x02\x4b")
            resp = s_rmi.recv(64)
        if len(resp) >= 1 and resp[0] == 0x4E:
            db.upsert_port(project_id, disp_host, 1099, "tcp", ip=target_ip, service="java-rmi", version="Java JRMP Registry", banner="JRMI ProtocolAck 0x4E", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Java RMI Registry Service ({disp_host}:1099)",
                "RPC / Deserialization Surface", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                "CWE-502", "A08:2021 - Software and Data Integrity Failures", f"{disp_host}:1099",
                "JRMP handshake (JRMI v2 StreamProtocol) returned ProtocolAck (0x4E)",
                "Java RMI reestri tashqi tarmoqqa ochiq qoldirilgan (JEP 290 deserializatsiya xavfi).",
                "`:1099` portini xavfsizlik devorida yoping va JEP 290 serializatsiya filtrini yoqing.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 3389:
        rdp_req = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_rdp:
            s_rdp.settimeout(2.2)
            s_rdp.sendall(rdp_req)
            resp = s_rdp.recv(64)
        if len(resp) >= 11 and resp[0] == 0x03 and resp[5] == 0xD0:
            nla_off = len(resp) == 11 or (len(resp) >= 19 and resp[11] == 0x02 and struct.unpack("<I", resp[15:19])[0] == 0)
            db.upsert_port(project_id, disp_host, 3389, "tcp", ip=target_ip, service="ms-wbt-server", version="RDP (NLA Disabled)" if nla_off else "RDP (NLA/TLS)", banner="X.224 CC", source="socket_nvt")
            if nla_off:
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] RDP Exposed Without Network Level Authentication ({disp_host}:3389)",
                    "Remote Management Exposure", "High", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    "CWE-287", "A07:2021 - Identification and Authentication Failures", f"{disp_host}:3389",
                    "X.224 Connection Confirm selected PROTOCOL_RDP (0x00) instead of CredSSP/Hybrid NLA",
                    "RDP xizmati Network Level Authentication (CredSSP/NLA) talabisiz tashqi tarmoqqa ochiq.",
                    "CredSSP / NLA rejimini majburiy qiling va `:3389` ni VPN ortiga oling.",
                    confidence=QoD.PROTOCOL_VERIFIED,
                )
                hits += 1
    elif port == 5000:
        rr = http_engine.request("GET", f"http://{connect_target}:{cp}/v2/_catalog", timeout=(2.0, 2.8), allow_redirects=False)
        if rr.status_code == 200 and '"repositories"' in (rr.text or ""):
            db.upsert_port(project_id, disp_host, 5000, "tcp", ip=target_ip, service="docker-registry", version="Docker Distribution v2", banner="Registry /v2/_catalog 200", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Private Docker Registry v2 Catalog ({disp_host}:5000)",
                "Container Infrastructure Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:5000",
                f"GET /v2/_catalog returned HTTP 200: {(rr.text or '').strip()[:120]}",
                "Shaxsiy Docker obrazlar reestri autentifikatsiyasiz `/v2/_catalog` ro'yxatini ochiq bermoqda.",
                "Docker Registry uchun token/htpasswd autentifikatsiya va TLS yoqing.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 5005:
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_jd:
            s_jd.settimeout(2.2)
            s_jd.sendall(b"JDWP-Handshake")
            resp = s_jd.recv(32)
        if resp.startswith(b"JDWP-Handshake"):
            db.upsert_port(project_id, disp_host, 5005, "tcp", ip=target_ip, service="jdwp", version="Java Debug Wire Protocol", banner="JDWP-Handshake", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Java Debug Wire Protocol Debugger ({disp_host}:5005)",
                "Remote Code / Debug Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CWE-489", "A05:2021 - Security Misconfiguration", f"{disp_host}:5005",
                "TCP 5005 echoed 'JDWP-Handshake' without authentication",
                "JVM production jarayonida autentifikatsiyasiz masofaviy JDWP debagger porti yoqib qo'yilgan.",
                "`-agentlib:jdwp` bayrog'ini olib tashlang yoki faqat `127.0.0.1` ga bog'lang.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 5985:
        rw = http_engine.request("POST", f"http://{connect_target}:{cp}/wsman", timeout=(2.0, 2.8), allow_redirects=False)
        wa = rw.headers.get("WWW-Authenticate", "")
        if (rw.status_code == 401 and "basic" in wa.lower()) or (rw.status_code == 200 and "wsman" in (rw.text or "").lower()):
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Cleartext WinRM Management Service Exposure ({disp_host}:5985)",
                "Remote Management Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-319", "A02:2021 - Cryptographic Failures", f"{disp_host}:5985",
                f"HTTP {rw.status_code} on /wsman | WWW-Authenticate: {wa[:80]}",
                "Windows Remote Management (`:5985`) shifrlanmagan HTTP orqali Basic autentifikatsiya yoki ochiq kirishga ruxsat bermoqda.",
                "WinRM HTTPS (`:5986`) ga o'ting va `AllowUnencrypted=false`, `Basic=false` o'rnating.",
                confidence=QoD.PROTOCOL_VERIFIED,
            )
            hits += 1
    elif port == 9000:
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_fc:
            s_fc.settimeout(2.2)
            s_fc.sendall(b"\x01\x09\x00\x00\x00\x00\x00\x00")
            resp = s_fc.recv(64)
        if len(resp) >= 8 and resp[0] == 0x01 and resp[1] in (10, 11):
            db.upsert_port(project_id, disp_host, 9000, "tcp", ip=target_ip, service="fastcgi", version="FastCGI / PHP-FPM", banner=f"FCGI v1 type={resp[1]}", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed FastCGI / PHP-FPM Daemon Socket ({disp_host}:9000)",
                "Application Runtime Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CWE-284", "A05:2021 - Security Misconfiguration", f"{disp_host}:9000",
                f"FastCGI FCGI_GET_VALUES returned valid FCGI v1 record (type={resp[1]})",
                "PHP-FPM / FastCGI ishchi soketi autentifikatsiyasiz tashqi TCP tarmog'iga bog'langan.",
                "`listen = /run/php/php-fpm.sock` yoki `listen.allowed_clients = 127.0.0.1` o'rnating.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    return hits


def _probe_middleware_and_infra_v7(
    db: Any, http_engine: Any, project_id: int, connect_target: str, target_ip: str, disp_host: str, port: int, connect_port: int | None = None
) -> int:
    hits = 0
    cp = connect_port or port
    if port == 1080:
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_sk:
            s_sk.settimeout(2.2)
            s_sk.sendall(b"\x05\x01\x00")
            resp = s_sk.recv(16)
        if len(resp) >= 2 and resp[0] == 0x05 and resp[1] == 0x00:
            db.upsert_port(project_id, disp_host, 1080, "tcp", ip=target_ip, service="socks5", version="SOCKS5 (No-Auth)", banner="SOCKS5 0x05 0x00", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated SOCKS5 Open Proxy ({disp_host}:1080)",
                "Network Relay / Proxy Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                "CWE-287", "A05:2021 - Security Misconfiguration", f"{disp_host}:1080",
                "RFC 1928 greeting accepted Method 0x00 (NO AUTHENTICATION REQUIRED)",
                "SOCKS5 proksi xizmati autentifikatsiyasiz ochiq holatda ishlamoqda.",
                "`:1080` portini yoping va RFC 1929 autentifikatsiyasini majburiy qiling.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 1521:
        tns_cmd = b"(DESCRIPTION=(CONNECT_DATA=(COMMAND=ping)))"
        pkt_len = 58 + len(tns_cmd)
        tns_hdr = struct.pack(">HHBBH", pkt_len, 0, 1, 0, 0) + struct.pack(">HHHHHHHHII", 0x0139, 0x012C, 0, 2048, 32767, 0x4F98, 0, 1, len(tns_cmd), 58) + (b"\x00" * 24)
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_tns:
            s_tns.settimeout(2.2)
            s_tns.sendall(tns_hdr + tns_cmd)
            resp = s_tns.recv(256)
        if len(resp) >= 8 and resp[4] in (2, 4, 11) and (b"ERR=0" in resp or b"ALIAS=" in resp or b"VSNNUM=" in resp):
            db.upsert_port(project_id, disp_host, 1521, "tcp", ip=target_ip, service="oracle-tns", version="Oracle TNS Listener", banner=resp[8:96].decode("ascii", errors="ignore"), source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Oracle TNS Listener Diagnostics ({disp_host}:1521)",
                "Database Listener Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "CWE-284", "A05:2021 - Security Misconfiguration", f"{disp_host}:1521",
                f"TNS Connect ping returned type={resp[4]}",
                "Oracle TNS Listener Valid Node Checking cheklovisiz diagnostika so'rovlariga javob bermoqda.",
                "`sqlnet.ora` ichida `TCP.VALIDNODE_CHECKING = YES` yoqing.",
                confidence=QoD.PROTOCOL_VERIFIED,
            )
            hits += 1
    elif port == 2049:
        rpc_call = struct.pack(">IIIIIIIIII", 0x80000028, 0x53504354, 0, 2, 100003, 4, 0, 0, 0, 0) + struct.pack(">II", 0, 0)
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_nfs:
            s_nfs.settimeout(2.2)
            s_nfs.sendall(rpc_call)
            resp = s_nfs.recv(64)
        if len(resp) >= 28 and resp[4:8] == b"SPCT" and struct.unpack(">II", resp[8:16]) == (1, 0):
            db.upsert_port(project_id, disp_host, 2049, "tcp", ip=target_ip, service="nfs", version="NFSv4 ONC-RPC", banner="ONC-RPC NFSPROC4_NULL Accepted", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed NFSv4 ONC-RPC File Service ({disp_host}:2049)",
                "Network File Share Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "CWE-284", "A05:2021 - Security Misconfiguration", f"{disp_host}:2049",
                "RFC 5531 ONC-RPC prog=100003 (NFSv4) proc=0 returned MSG_ACCEPTED",
                "NFS tarmoq fayl tizimi tashqi tarmoqdan ochiq RPC chaqiruvlarini qabul qilmoqda.",
                "`:2049` portini firewall orqali yoping va `/etc/exports` da qat'iy subnet qo'llang.",
                confidence=QoD.PROTOCOL_VERIFIED,
            )
            hits += 1
    elif port == 5060:
        sip_opt = (
            b"OPTIONS sip:status@spectre.local SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK776\r\n"
            b"Max-Forwards: 0\r\nTo: <sip:status@spectre.local>\r\nFrom: <sip:audit@spectre.local>;tag=19283\r\n"
            b"Call-ID: sp7060check@spectre.local\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )
        out = _tcp_exchange(connect_target, cp, [sip_opt], timeout=2.5, read_initial=False)
        if out.startswith("SIP/2.0 200"):
            m_srv = re.search(r"(?im)^(?:Server|User-Agent):\s*(.+)$", out)
            sv = m_srv.group(1).strip()[:80] if m_srv else "SIP UAS"
            db.upsert_port(project_id, disp_host, 5060, "tcp", ip=target_ip, service="sip", version=sv, banner=out.splitlines()[0][:80], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated SIP Signaling OPTIONS Disclosure ({disp_host}:5060)",
                "VoIP / Signaling Exposure", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "CWE-200", "A05:2021 - Security Misconfiguration", f"{disp_host}:5060",
                f"SIP/2.0 200 OK | Agent: {sv}",
                "SIP xizmati autentifikatsiyasiz `OPTIONS` so'roviga dastur versiyasini ochiq qaytarmoqda.",
                "SIP trunk ACL o'rnating va SIPS TLS (`:5061`) ishlating.",
                confidence=QoD.PROTOCOL_VERIFIED,
            )
            hits += 1
    elif port == 7001:
        out = _tcp_exchange(connect_target, cp, [b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"], timeout=2.5, read_initial=False)
        if out.startswith("HELO:"):
            ver_s = out.splitlines()[0].split(":", 1)[1].strip()[:48]
            db.upsert_port(project_id, disp_host, 7001, "tcp", ip=target_ip, service="weblogic-t3", version=f"WebLogic {ver_s}", banner=out.splitlines()[0][:80], source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Oracle WebLogic T3 Protocol Endpoint ({disp_host}:7001)",
                "RPC / Deserialization Surface", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-502", "A08:2021 - Software and Data Integrity Failures", f"{disp_host}:7001",
                f"WebLogic T3 Handshake succeeded: {out.splitlines()[0][:80]}",
                "Oracle WebLogic T3 kanali ConnectionFilter himoyasisiz tashqi tarmoqqa ochiq qoldirilgan.",
                "`weblogic.security.net.ConnectionFilterImpl` orqali T3 protokolini ichki tarmoqqa cheklang.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 10050:
        zbx_req = b"ZBXD\x01" + struct.pack("<Q", 13) + b"agent.version"
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_zb:
            s_zb.settimeout(2.2)
            s_zb.sendall(zbx_req)
            resp = s_zb.recv(128)
        if len(resp) > 13 and resp.startswith(b"ZBXD\x01"):
            zv = resp[13:].decode("utf-8", errors="ignore").strip("\x00\r\n ")[:48]
            if zv and "ZBX_NOTSUPPORTED" not in zv:
                db.upsert_port(project_id, disp_host, 10050, "tcp", ip=target_ip, service="zabbix-agent", version=f"Zabbix Agent {zv}", banner=f"ZBXD {zv}", source="socket_nvt")
                db.upsert_finding(
                    project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Zabbix Agent Passive Telemetry ({disp_host}:10050)",
                    "Monitoring Agent Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "CWE-284", "A05:2021 - Security Misconfiguration", f"{disp_host}:10050",
                    f"ZBXD v1 passive query 'agent.version' returned '{zv}'",
                    "Zabbix monitoring agenti shifrlashsiz tashqi IP manzillardan so'rovlarni qabul qilmoqda.",
                    "`zabbix_agentd.conf` da `Server=` IP ro'yxatini cheklang va `TLSConnect=psk` yoqing.",
                    confidence=QoD.ACTIVE_VERIFIED,
                )
                hits += 1
    elif port == 50070:
        rh = http_engine.request("GET", f"http://{connect_target}:{cp}/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo", timeout=(2.0, 2.8), allow_redirects=False)
        if rh.status_code == 200 and ("NameNodeInfo" in (rh.text or "") or "ClusterId" in (rh.text or "")):
            db.upsert_port(project_id, disp_host, 50070, "tcp", ip=target_ip, service="hadoop-namenode", version="Apache Hadoop HDFS NameNode", banner="NameNode /jmx 200", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Unauthenticated Apache Hadoop NameNode JMX Console ({disp_host}:50070)",
                "Big Data Cluster Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:50070",
                "GET /jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo returned HTTP 200",
                "Hadoop HDFS NameNode JMX konsoli Kerberos autentifikatsiyasiz ochiq ishlamoqda.",
                "`hadoop.security.authentication=kerberos` sozlamasini yoqing.",
                confidence=QoD.ACTIVE_VERIFIED,
            )
            hits += 1
    elif port == 61616:
        with socket.create_connection((connect_target, cp), timeout=2.5) as s_mq:
            s_mq.settimeout(2.2)
            resp = s_mq.recv(256)
        if b"ActiveMQ" in resp:
            m_ver = re.search(rb"ProviderVersion[^\x20-\x7e]*([0-9]+\.[0-9]+\.[0-9]+)", resp)
            av = m_ver.group(1).decode("ascii") if m_ver else "OpenWire"
            db.upsert_port(project_id, disp_host, 61616, "tcp", ip=target_ip, service="activemq", version=f"Apache ActiveMQ {av}", banner=f"ActiveMQ {av}", source="socket_nvt")
            db.upsert_finding(
                project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Exposed Apache ActiveMQ OpenWire Broker ({disp_host}:61616)",
                "Message Broker Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "CWE-306", "A05:2021 - Security Misconfiguration", f"{disp_host}:61616",
                f"TCP 61616 advertised OpenWire WireFormatInfo magic (ActiveMQ {av})",
                "Apache ActiveMQ OpenWire transport porti tashqi tarmoqqa ochiq qoldirilgan.",
                "`activemq.xml` da JAAS autentifikatsiyasini yoqing va 5.18.3+ ga yangilang.",
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
        if port in (1080, 1521, 2049, 5060, 7001, 10050, 50070, 61616):
            return _probe_middleware_and_infra_v7(db, http_engine, project_id, connect_target, target_ip, disp_host, port)
        if port in (110, 143, 1099, 3389, 5000, 5005, 5985, 9000):
            return _probe_enterprise_rpc_and_mgmt(db, http_engine, project_id, connect_target, target_ip, disp_host, port)
        if port in (1883, 2181, 4222, 5672, 8086, 8123, 8883, 9092):
            return _probe_messaging_and_tsdb(db, http_engine, project_id, connect_target, target_ip, disp_host, port, log_fn)
        if port in (6379, 6380, 11211, 9200, 9100, 2375, 2376, 2379, 6443, 8500, 10250, 15672):
            return _probe_data_and_metrics(db, http_engine, project_id, connect_target, target_ip, disp_host, port, log_fn)
        if port in (1433, 3306, 5432, 5900, 9042, 27017, 389, 636):
            return _probe_binary_db_and_ldap(db, project_id, connect_target, target_ip, disp_host, port, log_fn)
        if port in (22, 1022):
            buf_ssh = bytearray()
            with socket.create_connection((connect_target, port), timeout=2.5) as s_ssh:
                s_ssh.settimeout(2.2)
                try:
                    buf_ssh.extend(s_ssh.recv(256))
                except Exception:
                    pass
                s_ssh.sendall(b"SSH-2.0-SPECTRE_Audit_3.4\r\n")
                for _ in range(3):
                    try:
                        chunk = s_ssh.recv(4096)
                        if not chunk:
                            break
                        buf_ssh.extend(chunk)
                        if len(buf_ssh) >= 512 and parse_ssh_kexinit_packet(bytes(buf_ssh)):
                            break
                    except Exception:
                        break
            raw_b = bytes(buf_ssh)
            banner_ln = raw_b.splitlines()[0].decode("utf-8", errors="ignore").strip() if raw_b else ""
            kex_info = parse_ssh_kexinit_packet(raw_b)
            if banner_ln.startswith("SSH-") and not existing_ver:
                db.upsert_port(project_id, disp_host, port, "tcp", ip=target_ip, service="ssh", version=banner_ln[:90], banner=banner_ln[:160], source="socket_nvt")
            if kex_info:
                weak_kex = [a for a in kex_info["kex"] if a in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")]
                weak_hk = [a for a in kex_info["host_key"] if a == "ssh-dss"]
                weak_enc = [a for a in kex_info["enc"] if a in ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc")]
                weak_mac = [a for a in kex_info["mac"] if a in ("hmac-md5", "hmac-md5-96", "hmac-sha1-96")]
                weak_all = weak_kex + weak_hk + weak_enc + weak_mac
                if weak_all:
                    db.upsert_finding(
                        project_id, "Agent-2 (Socket-NVT)", f"[CONFIRMED] Weak / Legacy SSH Protocol or Algorithm ({disp_host}:{port})",
                        "Cryptographic Failure", "Medium", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "CWE-327", "A02:2021 - Cryptographic Failures", f"{disp_host}:{port}",
                        f"Banner: {banner_ln[:60]} | Weak KEXINIT Algorithms ({len(weak_all)}): {', '.join(weak_all[:8])}",
                        "SSH serveri RFC 4253 KEXINIT almashinuvida eskirgan SHA-1 kalit almashish, DSA, CBC/RC4 shifr yoki MD5 MAC algoritmlarini taklif qilmoqda.",
                        "sshd_config ichida faqat zamonaviy Curve25519/ECDH KEX, Ed25519/RSA-SHA2 host-key va ChaCha20-Poly1305 / AES-GCM shifrlarini qoldiring.",
                        confidence=QoD.PROTOCOL_VERIFIED,
                    )
                    log_fn(f"  [SOCKET-NVT] {disp_host}:{port} -> SSH KEXINIT zaif algoritmlar tasdiqlandi: {', '.join(weak_all[:5])}")
                    hits += 1
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
    sorted_doms = sorted(
        domains or [],
        key=lambda x: (1 if str(x.get("domain") or "").lower().startswith("www.") else 0, len(str(x.get("domain") or "")), str(x.get("domain") or "")),
    )
    for d in sorted_doms:
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
        if raw_h and raw_h in non_cdn_dom_ip and not raw_h.startswith("www."):
            disp_h = raw_h
        else:
            disp_h = ip_to_primary_dom.get(dedup_k, raw_h or dedup_k)
        tasks.append((pt_ip, disp_h, pnum, str(pt.get("version") or "").strip()))

    if not tasks:
        return 0

    from core.native_bridge import fast_go_probe_sockets

    by_host: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for tip, dh, pn, ev in tasks[:32]:
        conn_h = tip or dh
        by_host.setdefault((conn_h, dh), []).append((pn, ev))

    total_hits = 0
    go_handled = True
    for (conn_h, dh), p_list in by_host.items():
        go_res = fast_go_probe_sockets(conn_h, dh, [(pn, pn) for pn, _ in p_list], timeout_ms=2500)
        if go_res is None:
            go_handled = False
            break
        ev_map = {pn: ev for pn, ev in p_list}
        tip_val = conn_h if conn_h != dh else ""
        for item in go_res:
            p_num = int(item.get("port") or 0)
            svc = str(item.get("service") or "")
            ver = str(item.get("version") or "")
            bnr = str(item.get("banner") or "")
            if svc and (ver or bnr) and not ev_map.get(p_num):
                db.upsert_port(project_id, dh, p_num, "tcp", ip=tip_val, service=svc, version=ver, banner=bnr, source="socket_nvt")
            if item.get("has_finding"):
                db.upsert_finding(
                    project_id,
                    "Agent-2 (Socket-NVT)",
                    str(item.get("title") or f"[CONFIRMED] Socket Service Exposure ({dh}:{p_num})"),
                    str(item.get("category") or "Protocol Exposure"),
                    str(item.get("severity") or "High"),
                    float(item.get("cvss") or 7.5),
                    str(item.get("vector") or ""),
                    str(item.get("cwe") or "CWE-306"),
                    str(item.get("owasp") or "A05:2021 - Security Misconfiguration"),
                    str(item.get("asset") or f"{dh}:{p_num}"),
                    str(item.get("evidence") or bnr),
                    str(item.get("description") or ""),
                    str(item.get("remediation") or ""),
                    confidence=(
                        QoD.ACTIVE_VERIFIED
                        if int(item.get("confidence") or 99) >= 99
                        else QoD.PROTOCOL_VERIFIED
                    ),
                )
                total_hits += 1

    if not go_handled:
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


