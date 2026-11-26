// SPECTRE Native Go 50-Port Verifier (Part 4: Brokers, Middleware, RPC & Concurrent Dispatcher)
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

func probeBrokersAndRpcGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 1883, 8883:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("\x10\x10\x00\x04MQTT\x04\x02\x00\x1e\x00\x04spct")}, tms, false, port == 8883)
		if err == nil && len(raw) >= 4 && raw[0] == 0x20 && raw[1] == 0x02 {
			svc := "mqtt"
			if port == 8883 {
				svc = "mqtts"
			}
			if raw[3] == 0x00 {
				return makeFindingGo(disp, port, svc, "MQTT v3.1.1", "CONNACK rc=0",
					fmt.Sprintf("[CONFIRMED] Unauthenticated MQTT Message Broker Access (%s)", ap),
					"Message Broker Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
					"CWE-306", "A05:2021 - Security Misconfiguration", ap, "MQTT v3.1.1 CONNACK returnCode=0x00",
					"MQTT broker parolsiz anonim ulanishga ruxsat bermoqda.",
					"Mosquitto/EMQX da `allow_anonymous false` va TLS + ACL yoqing.", 99)
			}
			return &SocketProbeResult{Host: disp, Port: port, Service: svc, Version: "MQTT v3.1.1", Banner: fmt.Sprintf("CONNACK rc=%d", raw[3])}
		}
	case 2181:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("envi")}, tms, false, false)
		if err == nil && (bytes.Contains(raw, []byte("Environment:")) || bytes.Contains(raw, []byte("zookeeper.version="))) {
			zv := "Apache ZooKeeper"
			if m := reZkVer.FindStringSubmatch(string(raw)); len(m) > 1 {
				zv = "Apache ZooKeeper " + m[1]
			}
			return makeFindingGo(disp, 2181, "zookeeper", zv, truncStrGo(string(raw), 160),
				fmt.Sprintf("[CONFIRMED] Unauthenticated ZooKeeper Cluster Environment Exposure (%s)", ap),
				"Cluster Coordination Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "ZooKeeper 'envi' succeeded: "+zv,
				"ZooKeeper 4lw buyrug'i autentifikatsiyasiz muhit ma'lumotlarini oshkor qilmoqda.",
				"`4lw.commands.whitelist` ni cheklang va SASL ACL o'rnating.", 99)
		}
	case 4222:
		raw, err := tcpExchangeMultiGo(host, cp, nil, tms, true, false)
		if err == nil && bytes.HasPrefix(raw, []byte("INFO {")) {
			ln := strings.Split(string(raw)[5:], "\n")[0]
			var obj map[string]any
			if json.Unmarshal([]byte(ln), &obj) == nil {
				nv, _ := obj["version"].(string)
				if ar, ok := obj["auth_required"].(bool); ok && !ar {
					return makeFindingGo(disp, 4222, "nats", "nats-server "+nv, truncStrGo(string(raw), 140),
						fmt.Sprintf("[CONFIRMED] Unauthenticated NATS Messaging Bus (%s)", ap),
						"Message Broker Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
						"CWE-306", "A05:2021 - Security Misconfiguration", ap, "NATS INFO auth_required=false",
						"NATS xabar almashish shinasida autentifikatsiya o'chirilgan.",
						"NATS konfiguratsiyasida NKey/JWT yoki token autentifikatsiyani yoqing.", 99)
				}
				return &SocketProbeResult{Host: disp, Port: 4222, Service: "nats", Version: "nats-server " + nv, Banner: truncStrGo(string(raw), 140)}
			}
		}
	case 5672:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("AMQP\x00\x00\x09\x01")}, tms, false, false)
		if err == nil && len(raw) > 12 && raw[0] == 0x01 {
			return &SocketProbeResult{Host: disp, Port: 5672, Service: "amqp", Version: "AMQP 0-9-1 Broker", Banner: "AMQP Connection.Start"}
		}
	case 9092:
		kb := []byte{0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x3e, 0x00, 0x02, 's', 'p', 0x00, 0x00, 0x00, 0x00}
		conn, err := dialSocketGo(host, cp, tms, false)
		if err == nil {
			defer conn.Close()
			_, _ = conn.Write(kb)
			hdr := make([]byte, 12)
			n, _ := conn.Read(hdr)
			if n >= 12 {
				rLen := int32(binary.BigEndian.Uint32(hdr[0:4]))
				corr := int32(binary.BigEndian.Uint32(hdr[4:8]))
				bcnt := int32(binary.BigEndian.Uint32(hdr[8:12]))
				if corr == 7742 && rLen >= 8 && rLen <= 1048576 && bcnt >= 1 && bcnt <= 256 {
					return makeFindingGo(disp, 9092, "kafka", "Apache Kafka", fmt.Sprintf("Plaintext Brokers=%d", bcnt),
						fmt.Sprintf("[CONFIRMED] Unauthenticated Apache Kafka Broker Metadata Access (%s)", ap),
						"Streaming / Queue Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
						"CWE-306", "A05:2021 - Security Misconfiguration", ap, fmt.Sprintf("Kafka MetadataRequest returned %d broker(s)", bcnt),
						"Apache Kafka SASL autentifikatsiyasiz klaster metama'lumotlarini ochiq qaytarmoqda.",
						"`SASL_SSL` va `AclAuthorizer` ni yoqing.", 99)
				}
			}
		}
	}
	return probeEnterpriseRpcMiddlewareGo(host, disp, port, cp, tms)
}

func probeEnterpriseRpcMiddlewareGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 1099:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("JRMI\x00\x02\x4b")}, tms, false, false)
		if err == nil && len(raw) >= 1 && raw[0] == 0x4E {
			return makeFindingGo(disp, 1099, "java-rmi", "Java JRMP Registry", "JRMI ProtocolAck 0x4E",
				fmt.Sprintf("[CONFIRMED] Exposed Java RMI Registry Service (%s)", ap),
				"RPC / Deserialization Surface", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
				"CWE-502", "A08:2021 - Software and Data Integrity Failures", ap, "JRMP ProtocolAck (0x4E)",
				"Java RMI reestri tashqi tarmoqqa ochiq qoldirilgan.",
				"`:1099` portini firewallda yoping va JEP 290 filtrini yoqing.", 99)
		}
	case 3389:
		req := []byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{req}, tms, false, false)
		if err == nil && len(raw) >= 11 && raw[0] == 0x03 && raw[5] == 0xD0 {
			nlaOff := len(raw) == 11 || (len(raw) >= 19 && raw[11] == 0x02 && binary.LittleEndian.Uint32(raw[15:19]) == 0)
			if nlaOff {
				return makeFindingGo(disp, 3389, "ms-wbt-server", "RDP (NLA Disabled)", "X.224 CC NLA=0",
					fmt.Sprintf("[CONFIRMED] RDP Exposed Without Network Level Authentication (%s)", ap),
					"Remote Management Exposure", "High", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
					"CWE-287", "A07:2021 - Identification and Authentication Failures", ap, "X.224 Connection Confirm PROTOCOL_RDP (0x00)",
					"RDP xizmati Network Level Authentication (CredSSP/NLA) talabisiz ochiq.",
					"CredSSP / NLA rejimini majburiy qiling va `:3389` ni VPN ortiga oling.", 95)
			}
			return &SocketProbeResult{Host: disp, Port: 3389, Service: "ms-wbt-server", Version: "RDP (NLA/TLS)", Banner: "X.224 CC NLA"}
		}
	case 5005:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("JDWP-Handshake")}, tms, false, false)
		if err == nil && bytes.HasPrefix(raw, []byte("JDWP-Handshake")) {
			return makeFindingGo(disp, 5005, "jdwp", "Java Debug Wire Protocol", "JDWP-Handshake",
				fmt.Sprintf("[CONFIRMED] Exposed Java Debug Wire Protocol Debugger (%s)", ap),
				"Remote Code / Debug Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"CWE-489", "A05:2021 - Security Misconfiguration", ap, "TCP 5005 echoed JDWP-Handshake",
				"JVM jarayonida autentifikatsiyasiz masofaviy JDWP debagger porti ochiq qoldirilgan.",
				"`-agentlib:jdwp` bayrog'ini olib tashlang yoki `127.0.0.1` ga bog'lang.", 99)
		}
	case 9000:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("\x01\x09\x00\x00\x00\x00\x00\x00")}, tms, false, false)
		if err == nil && len(raw) >= 8 && raw[0] == 0x01 && (raw[1] == 10 || raw[1] == 11) {
			return makeFindingGo(disp, 9000, "fastcgi", "FastCGI / PHP-FPM", fmt.Sprintf("FCGI v1 type=%d", raw[1]),
				fmt.Sprintf("[CONFIRMED] Exposed FastCGI / PHP-FPM Daemon Socket (%s)", ap),
				"Application Runtime Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"CWE-284", "A05:2021 - Security Misconfiguration", ap, fmt.Sprintf("FCGI_GET_VALUES returned type=%d", raw[1]),
				"PHP-FPM / FastCGI ishchi soketi autentifikatsiyasiz tashqi TCP tarmog'iga bog'langan.",
				"`listen = /run/php/php-fpm.sock` yoki `listen.allowed_clients = 127.0.0.1` o'rnating.", 99)
		}
	case 1080:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("\x05\x01\x00")}, tms, false, false)
		if err == nil && len(raw) >= 2 && raw[0] == 0x05 && raw[1] == 0x00 {
			return makeFindingGo(disp, 1080, "socks5", "SOCKS5 (No-Auth)", "SOCKS5 0x05 0x00",
				fmt.Sprintf("[CONFIRMED] Unauthenticated SOCKS5 Open Proxy (%s)", ap),
				"Network Relay / Proxy Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
				"CWE-287", "A05:2021 - Security Misconfiguration", ap, "RFC 1928 Method 0x00 accepted",
				"SOCKS5 proksi xizmati autentifikatsiyasiz ochiq holatda ishlamoqda.",
				"`:1080` portini yoping va RFC 1929 autentifikatsiyasini majburiy qiling.", 99)
		}
	}
	return probeOracleNfsSipWeblogicGo(host, disp, port, cp, tms)
}

func probeOracleNfsSipWeblogicGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 1521:
		cmd := []byte("(DESCRIPTION=(CONNECT_DATA=(COMMAND=ping)))")
		pktLen := 58 + len(cmd)
		pkt := make([]byte, pktLen)
		binary.BigEndian.PutUint16(pkt[0:2], uint16(pktLen))
		pkt[4] = 1
		binary.BigEndian.PutUint16(pkt[8:10], 0x0139)
		binary.BigEndian.PutUint16(pkt[10:12], 0x012C)
		binary.BigEndian.PutUint16(pkt[14:16], 2048)
		binary.BigEndian.PutUint16(pkt[16:18], 32767)
		binary.BigEndian.PutUint16(pkt[18:20], 0x4F98)
		binary.BigEndian.PutUint16(pkt[22:24], 1)
		binary.BigEndian.PutUint16(pkt[24:26], uint16(len(cmd)))
		binary.BigEndian.PutUint16(pkt[26:28], 58)
		copy(pkt[58:], cmd)
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{pkt}, tms, false, false)
		if err == nil && len(raw) >= 8 && (raw[4] == 2 || raw[4] == 4 || raw[4] == 11) &&
			(bytes.Contains(raw, []byte("ERR=0")) || bytes.Contains(raw, []byte("ALIAS=")) || bytes.Contains(raw, []byte("VSNNUM="))) {
			return makeFindingGo(disp, 1521, "oracle-tns", "Oracle TNS Listener", truncStrGo(string(raw[8:]), 80),
				fmt.Sprintf("[CONFIRMED] Exposed Oracle TNS Listener Diagnostics (%s)", ap),
				"Database Listener Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
				"CWE-284", "A05:2021 - Security Misconfiguration", ap, fmt.Sprintf("TNS Connect ping returned type=%d", raw[4]),
				"Oracle TNS Listener Valid Node Checking cheklovisiz diagnostika so'rovlariga javob bermoqda.",
				"`sqlnet.ora` ichida `TCP.VALIDNODE_CHECKING = YES` yoqing.", 95)
		}
	case 2049:
		rpc := make([]byte, 44)
		binary.BigEndian.PutUint32(rpc[0:4], 0x80000028)
		binary.BigEndian.PutUint32(rpc[4:8], 0x53504354)
		binary.BigEndian.PutUint32(rpc[12:16], 2)
		binary.BigEndian.PutUint32(rpc[16:20], 100003)
		binary.BigEndian.PutUint32(rpc[20:24], 4)
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{rpc}, tms, false, false)
		if err == nil && len(raw) >= 28 && string(raw[4:8]) == "SPCT" &&
			binary.BigEndian.Uint32(raw[8:12]) == 1 && binary.BigEndian.Uint32(raw[12:16]) == 0 {
			return makeFindingGo(disp, 2049, "nfs", "NFSv4 ONC-RPC", "ONC-RPC NFSPROC4_NULL Accepted",
				fmt.Sprintf("[CONFIRMED] Exposed NFSv4 ONC-RPC File Service (%s)", ap),
				"Network File Share Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				"CWE-284", "A05:2021 - Security Misconfiguration", ap, "RFC 5531 ONC-RPC prog=100003 proc=0 MSG_ACCEPTED",
				"NFS tarmoq fayl tizimi tashqi tarmoqdan ochiq RPC chaqiruvlarini qabul qilmoqda.",
				"`:2049` portini firewall orqali yoping va `/etc/exports` da qat'iy subnet qo'llang.", 95)
		}
	case 5060:
		sip := []byte(
			"OPTIONS sip:status@spectre.local SIP/2.0\r\n" +
				"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK776\r\n" +
				"Max-Forwards: 0\r\n" +
				"To: <sip:status@spectre.local>\r\n" +
				"From: <sip:audit@spectre.local>;tag=19283\r\n" +
				"Call-ID: sp7060check@spectre.local\r\n" +
				"CSeq: 1 OPTIONS\r\n" +
				"Content-Length: 0\r\n\r\n",
		)
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{sip}, tms, false, false)
		if err == nil && bytes.HasPrefix(raw, []byte("SIP/2.0 200")) {
			sv := "SIP UAS"
			if m := reSipSrv.FindStringSubmatch(string(raw)); len(m) > 1 {
				sv = truncStrGo(m[1], 72)
			}
			return makeFindingGo(disp, 5060, "sip", sv, "SIP/2.0 200 OK",
				fmt.Sprintf("[CONFIRMED] Unauthenticated SIP Signaling OPTIONS Disclosure (%s)", ap),
				"VoIP / Signaling Exposure", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				"CWE-200", "A05:2021 - Security Misconfiguration", ap, "SIP/2.0 200 OK | Agent: "+sv,
				"SIP xizmati autentifikatsiyasiz OPTIONS so'roviga dastur versiyasini ochiq qaytarmoqda.",
				"SIP trunk ACL o'rnating va SIPS TLS (`:5061`) ishlating.", 95)
		}
	}
	return probeWeblogicZabbixActivemqGo(host, disp, port, cp, tms)
}

func probeWeblogicZabbixActivemqGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 7001:
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{[]byte("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")}, tms, false, false)
		if err == nil && bytes.HasPrefix(raw, []byte("HELO:")) {
			fl := truncStrGo(strings.Split(string(raw), "\n")[0], 80)
			vs := strings.TrimSpace(strings.TrimPrefix(fl, "HELO:"))
			return makeFindingGo(disp, 7001, "weblogic-t3", "WebLogic "+vs, fl,
				fmt.Sprintf("[CONFIRMED] Exposed Oracle WebLogic T3 Protocol Endpoint (%s)", ap),
				"RPC / Deserialization Surface", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				"CWE-502", "A08:2021 - Software and Data Integrity Failures", ap, "WebLogic T3 Handshake: "+fl,
				"Oracle WebLogic T3 kanali ConnectionFilter himoyasisiz tashqi tarmoqqa ochiq.",
				"`ConnectionFilterImpl` orqali T3 protokolini ichki tarmoqqa cheklang.", 99)
		}
	case 10050:
		zreq := make([]byte, 5+8+13)
		copy(zreq[0:5], []byte("ZBXD\x01"))
		binary.LittleEndian.PutUint64(zreq[5:13], 13)
		copy(zreq[13:], []byte("agent.version"))
		raw, err := tcpExchangeMultiGo(host, cp, [][]byte{zreq}, tms, false, false)
		if err == nil && len(raw) > 13 && bytes.HasPrefix(raw, []byte("ZBXD\x01")) {
			zv := truncStrGo(strings.Trim(string(raw[13:]), "\x00\r\n "), 48)
			if zv != "" && !strings.Contains(zv, "ZBX_NOTSUPPORTED") {
				return makeFindingGo(disp, 10050, "zabbix-agent", "Zabbix Agent "+zv, "ZBXD "+zv,
					fmt.Sprintf("[CONFIRMED] Unauthenticated Zabbix Agent Passive Telemetry (%s)", ap),
					"Monitoring Agent Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
					"CWE-284", "A05:2021 - Security Misconfiguration", ap, "ZBXD v1 agent.version="+zv,
					"Zabbix monitoring agenti shifrlashsiz tashqi IP manzillardan so'rovlarni qabul qilmoqda.",
					"`zabbix_agentd.conf` da `Server=` IP cheklovi va `TLSConnect=psk` yoqing.", 99)
			}
		}
	case 61616:
		raw, err := tcpExchangeMultiGo(host, cp, nil, tms, true, false)
		if err == nil && bytes.Contains(raw, []byte("ActiveMQ")) {
			av := "OpenWire"
			if m := reAmqVer.FindSubmatch(raw); len(m) > 1 {
				av = string(m[1])
			}
			return makeFindingGo(disp, 61616, "activemq", "Apache ActiveMQ "+av, "ActiveMQ "+av,
				fmt.Sprintf("[CONFIRMED] Exposed Apache ActiveMQ OpenWire Broker (%s)", ap),
				"Message Broker Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "TCP 61616 OpenWire ActiveMQ "+av,
				"Apache ActiveMQ OpenWire transport porti tashqi tarmoqqa ochiq qoldirilgan.",
				"`activemq.xml` da JAAS autentifikatsiyasini yoqing va 5.18.3+ ga yangilang.", 99)
		}
	}
	return probeHttpClusterEndpointsGo(host, disp, port, cp, tms)
}

func ProbeSingleSocketPortEx(host string, dispHost string, logicalPort int, connectPort int, timeoutMs int) *SocketProbeResult {
	if connectPort <= 0 {
		connectPort = logicalPort
	}
	if dispHost == "" {
		dispHost = host
	}
	if timeoutMs <= 0 {
		timeoutMs = 2400
	}
	return probeDbMailSshLdapGo(host, dispHost, logicalPort, connectPort, timeoutMs)
}

func ProbePortsConcurrentGo(host string, dispHost string, specs []SocketProbeSpec, timeoutMs int) []SocketProbeResult {
	var out []SocketProbeResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, sp := range specs {
		wg.Add(1)
		go func(s SocketProbeSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if r := ProbeSingleSocketPortEx(host, dispHost, s.LogicalPort, s.ConnectPort, timeoutMs); r != nil {
				mu.Lock()
				out = append(out, *r)
				mu.Unlock()
			}
		}(sp)
	}
	wg.Wait()
	return out
}
