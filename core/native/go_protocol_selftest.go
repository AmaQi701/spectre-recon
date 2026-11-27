// SPECTRE Native Go Ephemeral Loopback Protocol & MCP JSON-RPC Self-Test Engine
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type GoProtocolSelfTestReport struct {
	ABI          int               `json:"abi"`
	AllPassed    bool              `json:"all_passed"`
	ChecksPassed int               `json:"checks_passed"`
	ChecksTotal  int               `json:"checks_total"`
	Details      map[string]string `json:"details"`
}

func generateEphemeralTlsCertGo() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(95001),
		Subject:      pkix.Name{CommonName: "spectre-selftest.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"cache.internal.example", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func runMssqlLoopbackCheckGo() (bool, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err.Error()
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var hdrMatch atomic.Bool
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 128)
		n, rerr := conn.Read(buf)
		if rerr != nil || n < 8 {
			return
		}
		if buf[0] == 0x12 && int(binary.BigEndian.Uint16(buf[2:4])) == n {
			hdrMatch.Store(true)
			resp := make([]byte, 32)
			resp[0], resp[1] = 0x04, 0x01
			binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)))
			pl := resp[8:]
			binary.BigEndian.PutUint16(pl[1:3], 18)
			binary.BigEndian.PutUint16(pl[3:5], 6)
			pl[5], pl[18], pl[19] = 0xff, 16, 0
			binary.BigEndian.PutUint16(pl[20:22], 4135)
			_, _ = conn.Write(resp)
		}
	}()
	res := ProbeSingleSocketPortEx("127.0.0.1", "sql.internal.example", 1433, port, 1200)
	if res != nil && hdrMatch.Load() && strings.Contains(res.Version, "16.0.4135") {
		return true, res.Version
	}
	return false, "mssql prelogin framing mismatch"
}

func runMongoOpMsgLoopbackCheckGo() (bool, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err.Error()
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var opMsgOk atomic.Bool
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, rerr := conn.Read(buf)
		if rerr != nil || n < 21 {
			return
		}
		msgLen := int(binary.LittleEndian.Uint32(buf[0:4]))
		opCode := binary.LittleEndian.Uint32(buf[12:16])
		if msgLen == n && opCode == 2013 && bytes.Contains(buf[:n], []byte("hello")) {
			opMsgOk.Store(true)
			replyDoc := []byte("\x1d\x00\x00\x00\x10maxWireVersion\x00\x15\x00\x00\x00\x08ok\x00\x01\x00")
			binary.LittleEndian.PutUint32(replyDoc[0:4], uint32(len(replyDoc)))
			reply := make([]byte, 21+len(replyDoc))
			binary.LittleEndian.PutUint32(reply[0:4], uint32(len(reply)))
			binary.LittleEndian.PutUint32(reply[12:16], 2013)
			copy(reply[21:], replyDoc)
			_, _ = conn.Write(reply)
		}
	}()
	res := ProbeSingleSocketPortEx("127.0.0.1", "mongo.internal.example", 27017, port, 1200)
	if res != nil && opMsgOk.Load() && res.Service == "mongodb" {
		return true, res.Banner
	}
	return false, "mongodb OP_MSG framing mismatch"
}

func runKafkaLoopbackCheckGo() (bool, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err.Error()
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var kafkaLenOk atomic.Bool
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 128)
		n, rerr := conn.Read(buf)
		if rerr != nil || n < 12 {
			return
		}
		frameLen := int(binary.BigEndian.Uint32(buf[0:4]))
		corrID := int(binary.BigEndian.Uint32(buf[8:12]))
		if frameLen == n-4 && corrID == 7742 {
			kafkaLenOk.Store(true)
			resp := make([]byte, 12)
			binary.BigEndian.PutUint32(resp[0:4], 8)
			binary.BigEndian.PutUint32(resp[4:8], 7742)
			binary.BigEndian.PutUint32(resp[8:12], 2)
			_, _ = conn.Write(resp)
		}
	}()
	res := ProbeSingleSocketPortEx("127.0.0.1", "kafka.internal.example", 9092, port, 1200)
	if res != nil && kafkaLenOk.Load() && res.HasFinding && strings.Contains(res.Banner, "Brokers=2") {
		return true, res.Banner
	}
	return false, "kafka metadata framing mismatch"
}

func runTlsSniLoopbackCheckGo() (bool, string) {
	cert, err := generateEphemeralTlsCertGo()
	if err != nil {
		return false, err.Error()
	}
	var seenSNI atomic.Value
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			seenSNI.Store(chi.ServerName)
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		return false, err.Error()
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		tmp := make([]byte, 64)
		_, _ = conn.Read(tmp)
		_, _ = conn.Write([]byte("+PONG\r\nredis_version:7.2.5\r\n"))
	}()
	res := ProbeSingleSocketPortEx("127.0.0.1", "cache.internal.example", 6380, port, 1500)
	sniStr, _ := seenSNI.Load().(string)
	if res != nil && sniStr == "cache.internal.example" && strings.Contains(res.Version, "7.2.5") {
		return true, "SNI=" + sniStr
	}
	return false, "tls SNI propagation mismatch: " + sniStr
}

func runMcpJsonRpcCheckGo() (bool, string) {
	origIn, origOut := os.Stdin, os.Stdout
	inR, inW, err := os.Pipe()
	if err != nil {
		return false, err.Error()
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return false, err.Error()
	}
	os.Stdin = inR
	os.Stdout = outW
	defer func() {
		os.Stdin = origIn
		os.Stdout = origOut
	}()
	payload := strings.Join([]string{
		"{not-valid-json",
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"spectre_engine_posture","arguments":{}}}`,
	}, "\n") + "\n"
	go func() {
		_, _ = io.WriteString(inW, payload)
		_ = inW.Close()
	}()
	_ = RunLocalMcpStdioServerGo("")
	_ = outW.Close()
	rawOut, _ := io.ReadAll(outR)
	_ = inR.Close()
	_ = outR.Close()
	lines := strings.Split(strings.TrimSpace(string(rawOut)), "\n")
	if len(lines) != 2 {
		return false, fmt.Sprintf("expected 2 responses, got %d", len(lines))
	}
	var r0 map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &r0)
	eMap, _ := r0["error"].(map[string]any)
	code0, _ := eMap["code"].(float64)
	if int(code0) == -32700 && (strings.Contains(lines[1], `"abi":1000`) || strings.Contains(lines[1], `\"abi\":1000`)) {
		return true, "JSON-RPC -32700 + notification skip + ABI=1000 OK"
	}
	return false, "mcp json-rpc response mismatch"
}

func runOsintPivotGraphCheckGo() (bool, string) {
	nodes := []OsintAssetNode{
		{
			Domain: "portal.example.org", IP: "104.21.10.5", CdnWaf: "Cloudflare",
			CertSerial: "0a1b2c3d4e5f6789", FaviconMMH3: 981867722,
		},
		{
			Domain: "origin-gw.example.org", IP: "198.51.100.44", CdnWaf: "",
			CertSerial: "0a1b2c3d4e5f6789", FaviconMMH3: 981867722,
		},
		{
			Domain: "cdn-only.example.org", IP: "172.67.12.9", CdnWaf: "Cloudflare",
			CertSerial: "0a1b2c3d4e5f6789", FaviconMMH3: 981867722,
		},
	}
	rep := BuildOsintPivotGraphGo(nodes)
	if len(rep.UnmaskCandidates) == 2 && rep.UnmaskCandidates[0].CandidateOriginIP == "198.51.100.44" {
		return true, "CDN isolated + Direct Origin 198.51.100.44 unmasked"
	}
	return false, "osint pivot graph correlation mismatch"
}

func runAccessMatrixCheckGo() (bool, string) {
	probes := []AccessMatrixProbe{
		{
			Endpoint: "/api/v1/orders/4091", Method: "GET",
			AnonStatus: 401, UserAStatus: 200, UserALen: 320, UserAHash: 0xabc123,
			UserBStatus: 200, UserBLen: 320, UserBHash: 0xabc123, BaseJitter: 20,
			BodySnippet: `{"order_id":4091,"owner":"alice","amount":199.95,"status":"paid","items":["pro"]}`,
			HasOwnerMatch: true,
		},
		{
			Endpoint: "/api/v1/admin/users", Method: "GET",
			AnonStatus: 200, AnonLen: 180, AnonHash: 0x99, AdminStatus: 200, AdminLen: 180, AdminHash: 0x99,
			BodySnippet: "<html><body>Welcome to nginx! default server stub page padding text here</body></html>",
		},
	}
	hits := EvaluateAccessMatrixGo(probes)
	if len(hits) == 1 && hits[0].CWE == "CWE-639" {
		return true, "BOLA confirmed + nginx decoy stub suppressed"
	}
	return false, "access matrix evaluation mismatch"
}

func runCloudPostureCheckGo() (bool, string) {
	items := []CloudPostureInput{
		{
			Asset: "iam/admin_policy.json", Kind: "iam_json",
			Content: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		},
		{
			Asset: "https://s3.example.org/private", Kind: "bucket_xml",
			Content: `<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>`,
		},
	}
	hits := AuditCloudPostureGo(items)
	if len(hits) == 1 && hits[0].CWE == "CWE-269" {
		return true, "IAM wildcard detected + S3 AccessDenied suppressed"
	}
	return false, "cloud posture evaluation mismatch"
}

func runHttpFramingCheckGo() (bool, string) {
	items := []HttpFramingInput{
		{
			Asset: "https://gw.example.org/api", StatusCode: 200,
			RawHeaders: map[string][]string{
				"Content-Length":    {"42"},
				"Transfer-Encoding": {"chunked"},
			},
		},
	}
	hits := AuditHttpRfc9112FramingGo(items)
	if len(hits) == 1 && hits[0].CWE == "CWE-444" {
		return true, "RFC 9112 CL+TE framing ambiguity detected"
	}
	return false, "http framing check mismatch"
}

func RunAllGoProtocolSelfTests() GoProtocolSelfTestReport {
	details := make(map[string]string)
	passed := 0
	checks := []struct {
		name string
		fn   func() (bool, string)
	}{
		{"mssql_tds_prelogin", runMssqlLoopbackCheckGo},
		{"mongodb_op_msg_2013", runMongoOpMsgLoopbackCheckGo},
		{"kafka_metadata_v0", runKafkaLoopbackCheckGo},
		{"tls_sni_propagation", runTlsSniLoopbackCheckGo},
		{"mcp_jsonrpc_2_0", runMcpJsonRpcCheckGo},
		{"osint_pivot_graph", runOsintPivotGraphCheckGo},
		{"cross_role_access_matrix", runAccessMatrixCheckGo},
		{"cloud_iam_posture", runCloudPostureCheckGo},
		{"rfc9112_http_framing", runHttpFramingCheckGo},
	}
	for _, c := range checks {
		ok, msg := c.fn()
		if ok {
			passed++
			details[c.name] = "PASS: " + msg
		} else {
			details[c.name] = "FAIL: " + msg
		}
	}
	return GoProtocolSelfTestReport{
		ABI:          1000,
		AllPassed:    passed == len(checks),
		ChecksPassed: passed,
		ChecksTotal:  len(checks),
		Details:      details,
	}
}

