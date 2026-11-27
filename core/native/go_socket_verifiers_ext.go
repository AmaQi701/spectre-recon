// SPECTRE Native Go 50-Port Verifier (Part 2: Binary DBs, Mail, LDAP, VNC, RPC & Brokers)
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var (
	reZkVer  = regexp.MustCompile(`zookeeper\.version=([0-9]+\.[0-9]+\.[0-9]+)`)
	reAmqVer = regexp.MustCompile(`ProviderVersion[^\x20-\x7e]*([0-9]+\.[0-9]+\.[0-9]+)`)
	reSipSrv = regexp.MustCompile(`(?im)^(?:Server|User-Agent):\s*(.+)$`)
)

func probeMailLdapSqlGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 21:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("USER anonymous\r\n"), []byte("PASS anonymous@example.org\r\n"), []byte("QUIT\r\n")}, tms, true, false)
		if err != nil {
			return nil
		}
		out := string(raw)
		fl := truncStrGo(strings.Split(out, "\n")[0], 110)
		if reFtp230.MatchString(out) {
			return makeFindingGo(disp, 21, "ftp", strings.TrimSpace(strings.TrimPrefix(fl, "220")), fl,
				fmt.Sprintf("[CONFIRMED] Anonymous FTP Access Enabled (%s)", ap),
				"Authentication Bypass", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				"CWE-287", "A07:2021 - Identification and Authentication Failures", ap, "FTP 230 Anonymous Login Succeeded",
				"FTP serverda parolsiz anonim kirish amalda tasdiqlandi.",
				"FTP konfiguratsiyasida `anonymous_enable=NO` o'rnating va SFTP ga o'ting.", 99)
		}
		return &SocketProbeResult{Host: disp, Port: 21, Service: "ftp", Version: strings.TrimSpace(strings.TrimPrefix(fl, "220")), Banner: fl}
	case 25, 587:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("EHLO spectre.local\r\n"), []byte("QUIT\r\n")}, tms, true, false)
		if err != nil {
			return nil
		}
		out := string(raw)
		up := strings.ToUpper(out)
		fl := truncStrGo(strings.Split(out, "\n")[0], 110)
		if (strings.Contains(up, "AUTH PLAIN") || strings.Contains(up, "AUTH LOGIN")) && !strings.Contains(up, "STARTTLS") {
			return makeFindingGo(disp, port, "smtp", strings.TrimSpace(strings.TrimPrefix(fl, "220")), truncStrGo(out, 160),
				fmt.Sprintf("[CONFIRMED] SMTP Cleartext Auth Advertised Without STARTTLS (%s)", ap),
				"Cleartext Transmission", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				"CWE-319", "A02:2021 - Cryptographic Failures", ap, "EHLO AUTH PLAIN/LOGIN without STARTTLS",
				"SMTP serveri STARTTLS shifrlashsiz ochiq matnda AUTH PLAIN/LOGIN e'lon qilmoqda.",
				"`smtpd_tls_auth_only = yes` sozlamasini yoqing.", 95)
		}
		return &SocketProbeResult{Host: disp, Port: port, Service: "smtp", Version: strings.TrimSpace(strings.TrimPrefix(fl, "220")), Banner: fl}
	case 110:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("CAPA\r\n"), []byte("QUIT\r\n")}, tms, true, false)
		if err == nil {
			up := strings.ToUpper(string(raw))
			if strings.Contains(up, "+OK") && !strings.Contains(up, "STLS") && (strings.Contains(up, "USER") || strings.Contains(up, "PLAIN")) {
				return makeFindingGo(disp, 110, "pop3", "POP3", "POP3 Cleartext",
					fmt.Sprintf("[CONFIRMED] Cleartext POP3 Authentication Without STLS (%s)", ap),
					"Cleartext Mail Protocol Exposure", "Medium", 5.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
					"CWE-319", "A02:2021 - Cryptographic Failures", ap, "POP3 CAPA advertised USER/PLAIN without STLS",
					"POP3 xizmati parollarni shifrlanmagan TCP oqimida qabul qilmoqda.",
					"POP3S (`:995`) yoki majburiy `STLS` rejimini yoqing.", 95)
			}
		}
	case 143:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("a01 CAPABILITY\r\n"), []byte("a02 LOGOUT\r\n")}, tms, true, false)
		if err == nil {
			up := strings.ToUpper(string(raw))
			if strings.Contains(up, "CAPABILITY") && strings.Contains(up, "IMAP4") && !strings.Contains(up, "STARTTLS") && !strings.Contains(up, "LOGINDISABLED") {
				return makeFindingGo(disp, 143, "imap", "IMAP4", "IMAP Cleartext",
					fmt.Sprintf("[CONFIRMED] Cleartext IMAP Authentication Without STARTTLS (%s)", ap),
					"Cleartext Mail Protocol Exposure", "Medium", 5.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
					"CWE-319", "A02:2021 - Cryptographic Failures", ap, "IMAP CAPABILITY permitted cleartext LOGIN without STARTTLS",
					"IMAP xizmati STARTTLS shifrlashisiz ochiq matnli login ruxsat etmoqda.",
					"IMAPS (`:993`) yoki majburiy `STARTTLS` + `LOGINDISABLED` sozlang.", 95)
			}
		}
	case 873:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("\n")}, tms, true, false)
		if err == nil && bytes.Contains(raw, []byte("@RSYNCD:")) {
			var mods []string
			for _, ln := range strings.Split(string(raw), "\n") {
				t := strings.TrimSpace(ln)
				if t != "" && !strings.HasPrefix(t, "@RSYNCD") {
					mods = append(mods, t)
				}
			}
			if len(mods) > 0 {
				return makeFindingGo(disp, 873, "rsync", "Rsyncd", strings.Join(mods, ","),
					fmt.Sprintf("[CONFIRMED] Exposed Rsync Daemon Modules (%s)", ap),
					"Unauthenticated File Share Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
					"CWE-284", "A05:2021 - Security Misconfiguration", ap, "Rsync Modules: "+truncStrGo(strings.Join(mods, ", "), 140),
					"Rsync xizmati tashqi tarmoqqa ochiq modullar ro'yxatini qaytarmoqda.",
					"rsyncd.conf ichida `hosts allow` va `auth users` o'rnating.", 99)
			}
		}
	}
	return probeBinaryDbAndRpcGo(host, disp, port, cp, tms)
}


func minIntGo(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func probeBinaryDbAndRpcGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 3306:
		raw, err := tcpExchangeMultiGo(host, cp, nil, tms, true, false)
		if err == nil && len(raw) >= 6 && raw[4] == 0x0A {
			endV := bytes.IndexByte(raw[5:], 0)
			if endV > 0 {
				vs := strings.TrimSpace(string(raw[5 : 5+endV]))
				lbl := "MySQL " + vs
				if strings.Contains(strings.ToLower(vs), "mariadb") {
					lbl = "MariaDB " + vs
				}
				return &SocketProbeResult{Host: disp, Port: 3306, Service: "mysql", Version: lbl, Banner: lbl}
			}
		}
	case 5432:
		body := []byte("user\x00postgres\x00database\x00postgres\x00\x00")
		pkt := make([]byte, 8+len(body))
		binary.BigEndian.PutUint32(pkt[0:4], uint32(8+len(body)))
		binary.BigEndian.PutUint32(pkt[4:8], 196608)
		copy(pkt[8:], body)
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{pkt}, tms, false, false)
		if err == nil && len(raw) >= 9 && raw[0] == 'R' {
			ac := binary.BigEndian.Uint32(raw[5:9])
			if ac == 0 {
				return makeFindingGo(disp, 5432, "postgresql", "PostgreSQL", "PG AuthCode=0",
					fmt.Sprintf("[CONFIRMED] Unauthenticated Backend Data Store Access (PostgreSQL Trust on %s)", ap),
					"Database / Cache Exposure", "Critical", 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"CWE-306", "A05:2021 - Security Misconfiguration", ap, "PostgreSQL AuthenticationOk (code=0, trust)",
					"PostgreSQL serveri tashqi ulanishlarga parolsiz (`trust` rejimida) ruxsat bermoqda.",
					"`pg_hba.conf` faylida `scram-sha-256` o'rnating.", 99)
			}
			return &SocketProbeResult{Host: disp, Port: 5432, Service: "postgresql", Version: "PostgreSQL", Banner: fmt.Sprintf("PG AuthCode=%d", ac)}
		}
	case 27017:
		helloBson := []byte("\x1f\x00\x00\x00\x10hello\x00\x01\x00\x00\x00\x02$db\x00\x06\x00\x00\x00admin\x00\x00")
		binary.LittleEndian.PutUint32(helloBson[0:4], uint32(len(helloBson)))
		opMsg := make([]byte, 16+5+len(helloBson))
		binary.LittleEndian.PutUint32(opMsg[0:4], uint32(len(opMsg)))
		binary.LittleEndian.PutUint32(opMsg[4:8], 1)
		binary.LittleEndian.PutUint32(opMsg[12:16], 2013)
		copy(opMsg[21:], helloBson)
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{opMsg}, tms, false, false)
		if err != nil || (!bytes.Contains(raw, []byte("maxWireVersion")) && !bytes.Contains(raw, []byte("isWritablePrimary")) && !bytes.Contains(raw, []byte("ismaster"))) {
			legBson := []byte("\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00")
			wire := make([]byte, 16+4+11+8+len(legBson))
			binary.LittleEndian.PutUint32(wire[0:4], uint32(len(wire)))
			binary.LittleEndian.PutUint32(wire[4:8], 2)
			binary.LittleEndian.PutUint32(wire[12:16], 2004)
			copy(wire[20:31], []byte("admin.$cmd\x00"))
			binary.LittleEndian.PutUint32(wire[35:39], 1)
			copy(wire[39:], legBson)
			raw, err = tcpExchangeMultiGo(host, cp, [][]byte{wire}, tms, false, false)
		}
		if err == nil && (bytes.Contains(raw, []byte("maxWireVersion")) || bytes.Contains(raw, []byte("isWritablePrimary")) || bytes.Contains(raw, []byte("ismaster"))) {
			return &SocketProbeResult{Host: disp, Port: 27017, Service: "mongodb", Version: "MongoDB", Banner: "MongoDB OP_MSG Handshake OK"}
		}
	case 389, 636:
		lb, _ := hex.DecodeString("300c020101600702010304008000")
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{lb}, tms, false, port == 636)
		if err == nil && len(raw) >= 7 && bytes.IndexByte(raw[:6], 0x61) >= 0 && bytes.Contains(raw[:minIntGo(len(raw), 14)], []byte{0x0a, 0x01, 0x00}) {
			svc := "ldap"
			if port == 636 {
				svc = "ldaps"
			}
			return makeFindingGo(disp, port, svc, "LDAPv3", "Anonymous Bind Allowed",
				fmt.Sprintf("[CONFIRMED] LDAP Anonymous Bind Permitted (%s)", ap),
				"Directory Service Misconfiguration", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				"CWE-284", "A01:2021 - Broken Access Control", ap, "LDAPv3 Simple BindRequest returned resultCode=0",
				"LDAP serveri parolsiz (Anonymous Bind) ulanishga ruxsat bermoqda.",
				"OpenLDAP (`disallow bind_anon`) yoki AD da anonim LDAP so'rovlarini o'chiring.", 99)
		}
	case 5900:
		conn, err := dialSocketGo(host, cp, tms, false)
		if err == nil {
			defer conn.Close()
			rb := make([]byte, 16)
			n, _ := conn.Read(rb)
			if n >= 12 && bytes.HasPrefix(rb[:n], []byte("RFB ")) {
				vt := strings.TrimSpace(string(rb[:n]))
				_, _ = conn.Write(rb[:12])
				sb := make([]byte, 32)
				sn, _ := conn.Read(sb)
				noAuth := false
				if bytes.Contains(rb[:n], []byte("003.003")) && sn >= 4 && binary.BigEndian.Uint32(sb[:4]) == 1 {
					noAuth = true
				} else if sn >= 2 && sb[0] > 0 && int(1+sb[0]) <= sn && bytes.IndexByte(sb[1:1+sb[0]], 1) >= 0 {
					noAuth = true
				}
				if noAuth {
					return makeFindingGo(disp, 5900, "vnc", vt, vt,
						fmt.Sprintf("[CONFIRMED] Unauthenticated VNC Remote Desktop Service (%s)", ap),
						"Remote Desktop Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						"CWE-306", "A07:2021 - Identification and Authentication Failures", ap, "RFB offered SecurityType=1 (None)",
						"VNC serveri parolsiz masofaviy ulanishga ruxsat bermoqda.",
						"VNC parol talabini yoqing va 5900-portni VPN/SSH ortiga oling.", 99)
				}
				return &SocketProbeResult{Host: disp, Port: 5900, Service: "vnc", Version: vt, Banner: vt}
			}
		}
	case 1433:
		tds := []byte{
			0x12, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x0b, 0x00, 0x06, 0x01, 0x00, 0x11, 0x00, 0x01, 0xff,
			0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		}
		binary.BigEndian.PutUint16(tds[2:4], uint16(len(tds)))
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{tds}, tms, false, false)
		if err == nil && len(raw) >= 28 && raw[0] == 0x04 {
			pl := raw[8:]
			if len(pl) >= 18 && pl[0] == 0x00 {
				vo := int(binary.BigEndian.Uint16(pl[1:3]))
				if vo+4 <= len(pl) {
					mv := fmt.Sprintf("Microsoft SQL Server %d.%d.%d", pl[vo], pl[vo+1], binary.BigEndian.Uint16(pl[vo+2:vo+4]))
					return &SocketProbeResult{Host: disp, Port: 1433, Service: "ms-sql-s", Version: mv, Banner: mv}
				}
			}
		}
	case 9042:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("\x04\x00\x00\x00\x05\x00\x00\x00\x00")}, tms, false, false)
		if err == nil && len(raw) >= 9 && (raw[4] == 0x06 || bytes.Contains(raw, []byte("CQL_VERSION"))) {
			return &SocketProbeResult{Host: disp, Port: 9042, Service: "cassandra", Version: "Apache Cassandra CQL", Banner: "CQL Binary SUPPORTED"}
		}
	}
	return probeBrokersAndRpcGo(host, disp, port, cp, tms)
}
