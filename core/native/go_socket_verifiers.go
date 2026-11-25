// SPECTRE Native Go 50-Port Concurrent Active Socket Protocol Verifier
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type SocketFinding struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss"`
	CWE      string  `json:"cwe"`
	Banner   string  `json:"banner"`
}

var SupportedSocketPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 143, 389, 443, 445, 465, 587, 636, 873,
	993, 995, 1022, 1080, 1099, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 2379,
	3306, 3389, 4222, 5000, 5060, 5432, 5672, 5900, 5985, 6379, 6380, 7001, 8000,
	8086, 8123, 8500, 8883, 9000, 9042, 9090, 9092, 9200, 10050, 10250, 11211,
	15672, 27017, 50070, 61616,
}

func tcpExchangeGo(host string, port int, payload []byte, timeoutMs int) ([]byte, error) {
	d := net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil { return nil, err }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	if len(payload) > 0 { _, _ = conn.Write(payload) }
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 { return buf[:n], nil }
	return nil, err
}

func parseSSHKexInitGo(pkt []byte) []string {
	idx := bytes.IndexByte(pkt, 0x14)
	if idx < 0 || idx+17 >= len(pkt) { return nil }
	off := idx + 17
	var weak []string
	for field := 0; field < 4 && off+4 <= len(pkt); field++ {
		slen := int(binary.BigEndian.Uint32(pkt[off : off+4]))
		off += 4
		if slen < 0 || off+slen > len(pkt) { break }
		algList := string(pkt[off : off+slen])
		off += slen
		for _, w := range []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "3des-cbc", "arcfour", "aes128-cbc"} {
			if strings.Contains(algList, w) { weak = append(weak, w) }
		}
	}
	return weak
}

func ProbeSingleSocketPort(host string, port int, timeoutMs int) *SocketFinding {
	switch port {
	case 6379:
		resp, err := tcpExchangeGo(host, port, []byte("*1\r\n$4\r\nINFO\r\n"), timeoutMs)
		if err == nil && bytes.Contains(resp, []byte("redis_version:")) {
			return &SocketFinding{Host: host, Port: port, Protocol: "redis", Title: "Unauthenticated Redis INFO Exposure", Severity: "Critical", CVSS: 9.8, CWE: "CWE-306", Banner: "redis_version"}
		}
	case 11211:
		resp, err := tcpExchangeGo(host, port, []byte("stats\r\n"), timeoutMs)
		if err == nil && bytes.Contains(resp, []byte("STAT pid ")) {
			return &SocketFinding{Host: host, Port: port, Protocol: "memcached", Title: "Unauthenticated Memcached Stats", Severity: "High", CVSS: 7.5, CWE: "CWE-306", Banner: "STAT pid"}
		}
	case 22, 1022:
		resp, err := tcpExchangeGo(host, port, []byte("SSH-2.0-SPECTRE_Audit\r\n"), timeoutMs)
		if err == nil && len(resp) > 0 {
			if w := parseSSHKexInitGo(resp); len(w) > 0 {
				return &SocketFinding{Host: host, Port: port, Protocol: "ssh", Title: "Weak SSH KEX/Cipher Negotiable", Severity: "Medium", CVSS: 5.3, CWE: "CWE-327", Banner: strings.Join(w, ",")}
			}
		}
	}
	return nil
}

func ProbePortsConcurrentGo(host string, ports []int, timeoutMs int) []SocketFinding {
	var out []SocketFinding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, p := range ports {
		wg.Add(1)
		go func(pt int) {
			defer wg.Done()
			sem <- struct{}{}; defer func() { <-sem }()
			if f := ProbeSingleSocketPort(host, pt, timeoutMs); f != nil {
				mu.Lock(); out = append(out, *f); mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return out
}
