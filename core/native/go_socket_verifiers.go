// SPECTRE Native Go 50-Port Concurrent Active Socket Protocol Verifier (Part 1: Core + DB/Mail/SSH/LDAP/VNC)
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SocketProbeSpec struct {
	LogicalPort int
	ConnectPort int
}

type SocketProbeResult struct {
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Service     string  `json:"service"`
	Version     string  `json:"version"`
	Banner      string  `json:"banner"`
	HasFinding  bool    `json:"has_finding"`
	Title       string  `json:"title,omitempty"`
	Category    string  `json:"category,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Vector      string  `json:"vector,omitempty"`
	CWE         string  `json:"cwe,omitempty"`
	OWASP       string  `json:"owasp,omitempty"`
	Asset       string  `json:"asset,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
	Description string  `json:"description,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Confidence  int     `json:"confidence,omitempty"`
}

var SupportedSocketPorts = []int{
	21, 22, 25, 110, 143, 389, 587, 636, 873, 1022, 1080, 1099, 1433, 1521, 1883,
	2049, 2181, 2375, 2376, 2379, 3306, 3389, 4222, 5000, 5005, 5060, 5432, 5672,
	5900, 5985, 6379, 6380, 6443, 7001, 8086, 8123, 8500, 8883, 9000, 9042, 9092,
	9100, 9200, 10050, 10250, 11211, 15672, 27017, 50070, 61616,
}

func dialSocketGo(host string, port int, timeoutMs int, useTLS bool) (net.Conn, error) {
	dur := time.Duration(timeoutMs) * time.Millisecond
	d := net.Dialer{Timeout: dur}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if useTLS {
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
		conn, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(dur))
		return conn, nil
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(dur))
	return conn, nil
}

func tcpExchangeMultiGo(host string, port int, payloads [][]byte, timeoutMs int, readInit bool, useTLS bool) ([]byte, error) {
	conn, err := dialSocketGo(host, port, timeoutMs, useTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var chunks [][]byte
	if readInit {
		ibuf := make([]byte, 2048)
		if n, _ := conn.Read(ibuf); n > 0 {
			chunks = append(chunks, append([]byte(nil), ibuf[:n]...))
		}
	}
	for _, pl := range payloads {
		if len(pl) > 0 {
			_, _ = conn.Write(pl)
		}
		rbuf := make([]byte, 4096)
		n, rerr := conn.Read(rbuf)
		if n > 0 {
			chunks = append(chunks, append([]byte(nil), rbuf[:n]...))
		}
		if rerr != nil {
			break
		}
	}
	if len(chunks) == 0 {
		return nil, io.EOF
	}
	return bytes.Join(chunks, []byte("\n")), nil
}

func httpSocketProbeGo(scheme string, host string, port int, method string, path string, timeoutMs int) (int, http.Header, string, error) {
	dur := time.Duration(timeoutMs) * time.Millisecond
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	cli := &http.Client{
		Transport: tr,
		Timeout:   dur,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	urlStr := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)), path)
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", "SPECTRE-Audit/9.5")
	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 49152))
	return resp.StatusCode, resp.Header, string(raw), nil
}

func parseSSHKexInitGo(raw []byte) []string {
	if len(raw) < 28 {
		return nil
	}
	idx := 0
	if bytes.HasPrefix(raw, []byte("SSH-")) {
		nl := bytes.IndexByte(raw, '\n')
		if nl < 0 {
			return nil
		}
		idx = nl + 1
	}
	weakSet := map[string]bool{
		"diffie-hellman-group1-sha1":          true,
		"diffie-hellman-group14-sha1":         true,
		"diffie-hellman-group-exchange-sha1":  true,
		"ssh-dss":                             true,
		"3des-cbc":                            true,
		"aes128-cbc":                          true,
		"aes192-cbc":                          true,
		"aes256-cbc":                          true,
		"arcfour":                             true,
		"arcfour128":                          true,
		"arcfour256":                          true,
		"blowfish-cbc":                        true,
		"hmac-md5":                            true,
		"hmac-md5-96":                         true,
		"hmac-sha1-96":                        true,
	}
	var found []string
	seen := map[string]bool{}
	for idx+22 <= len(raw) {
		pktLen := int(binary.BigEndian.Uint32(raw[idx : idx+4]))
		padLen := int(raw[idx+4])
		if pktLen >= 16 && pktLen <= 32768 && idx+4+pktLen <= len(raw) && 4+pktLen-padLen > 5 {
			payload := raw[idx+5 : idx+4+pktLen-padLen]
			if len(payload) > 17 && payload[0] == 20 {
				pos := 17
				for field := 0; field < 6 && pos+4 <= len(payload); field++ {
					slen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
					pos += 4
					if slen < 0 || pos+slen > len(payload) {
						break
					}
					for _, alg := range strings.Split(string(payload[pos:pos+slen]), ",") {
						a := strings.TrimSpace(alg)
						if weakSet[a] && !seen[a] {
							seen[a] = true
							found = append(found, a)
						}
					}
					pos += slen
				}
				return found
			}
		}
		idx++
	}
	return found
}



var (
	reRedisVer = regexp.MustCompile(`redis_version:([0-9]+\.[0-9]+\.[0-9]+)`)
	reMemcVer  = regexp.MustCompile(`STAT version\s+([0-9]+\.[0-9]+\.[0-9]+)`)
	reFtp230   = regexp.MustCompile(`(?m)^230[\s\-]`)
)

func truncStrGo(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func makeFindingGo(host string, port int, svc, ver, banner, title, cat, sev string, cvss float64, vec, cwe, owasp, asset, ev, desc, rem string, conf int) *SocketProbeResult {
	return &SocketProbeResult{
		Host: host, Port: port, Service: svc, Version: ver, Banner: banner,
		HasFinding: true, Title: title, Category: cat, Severity: sev, CVSS: cvss,
		Vector: vec, CWE: cwe, OWASP: owasp, Asset: asset, Evidence: ev,
		Description: desc, Remediation: rem, Confidence: conf,
	}
}

func probeDbMailSshLdapGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 6379, 6380:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("PING\r\n"), []byte("INFO server\r\n")}, tms, false, port == 6380)
		if err == nil && (bytes.Contains(raw, []byte("+PONG")) || bytes.Contains(raw, []byte("redis_version:"))) {
			ver := "Redis"
			if m := reRedisVer.FindStringSubmatch(string(raw)); len(m) > 1 {
				ver = "Redis " + m[1]
			}
			return makeFindingGo(disp, port, "redis", ver, truncStrGo(string(raw), 200),
				fmt.Sprintf("[CONFIRMED] Unauthenticated Backend Data Store Access (Redis on %s)", ap),
				"Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "Direct PING/INFO succeeded ("+ver+")",
				"Redis xizmati parolsiz tashqi tarmoqdan buyruqlarni qabul qilmoqda.",
				"redis.conf ichida `bind 127.0.0.1` va kuchli `requirepass` / ACL o'rnating.", 99)
		}
	case 11211:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("stats\r\n"), []byte("quit\r\n")}, tms, false, false)
		if err == nil && (bytes.Contains(raw, []byte("STAT pid")) || bytes.Contains(raw, []byte("STAT version"))) {
			ver := "Memcached"
			if m := reMemcVer.FindStringSubmatch(string(raw)); len(m) > 1 {
				ver = "Memcached " + m[1]
			}
			return makeFindingGo(disp, 11211, "memcached", ver, truncStrGo(string(raw), 200),
				fmt.Sprintf("[CONFIRMED] Unauthenticated Backend Data Store Access (Memcached on %s)", ap),
				"Database / Cache Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "Direct TCP stats succeeded ("+ver+")",
				"Memcached kesh serveri autentifikatsiyasiz tashqi tarmoqqa ochiq qoldirilgan.",
				"Memcached xizmatini `-l 127.0.0.1` ga bog'lang va SASL autentifikatsiyasini yoqing.", 99)
		}
	case 22, 1022:
		conn, err := dialSocketGo(host, cp, tms, false)
		if err != nil {
			return nil
		}
		var buf bytes.Buffer
		tmp := make([]byte, 4096)
		if n, _ := conn.Read(tmp); n > 0 {
			buf.Write(tmp[:n])
		}
		_, _ = conn.Write([]byte("SSH-2.0-SPECTRE_Audit_9.5\r\n"))
		for i := 0; i < 3; i++ {
			n, rerr := conn.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
				if buf.Len() >= 512 && len(parseSSHKexInitGo(buf.Bytes())) > 0 {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = conn.Close()
		if buf.Len() == 0 {
			return nil
		}
		bn := truncStrGo(strings.Split(buf.String(), "\n")[0], 90)
		if weak := parseSSHKexInitGo(buf.Bytes()); len(weak) > 0 {
			return makeFindingGo(disp, port, "ssh", bn, bn,
				fmt.Sprintf("[CONFIRMED] Weak / Legacy SSH Protocol or Algorithm (%s)", ap),
				"Cryptographic Failure", "Medium", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
				"CWE-327", "A02:2021 - Cryptographic Failures", ap, "Weak KEXINIT: "+strings.Join(weak, ", "),
				"SSH serveri RFC 4253 KEXINIT almashinuvida eskirgan SHA-1/CBC/RC4/MD5 algoritmlarini taklif qilmoqda.",
				"sshd_config ichida faqat Curve25519/ECDH KEX va ChaCha20-Poly1305 / AES-GCM shifrlarini qoldiring.", 95)
		}
		return &SocketProbeResult{Host: disp, Port: port, Service: "ssh", Version: bn, Banner: bn}
	}
	return probeMailLdapSqlGo(host, disp, port, cp, tms)
}
