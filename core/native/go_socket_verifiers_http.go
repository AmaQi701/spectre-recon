// SPECTRE Native Go 50-Port Verifier (Part 3: HTTP/HTTPS Cluster, DB & Registry Endpoints)
package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var reChVer = regexp.MustCompile(`^\d+\.\d+\.\d+`)

func probeHttpClusterEndpointsGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 9200:
		for _, sch := range []string{"http", "https"} {
			code, _, body, err := httpSocketProbeGo(sch, host, cp, "GET", "/", tms)
			if err == nil && code == 200 && strings.Contains(body, `"cluster_name"`) && strings.Contains(body, `"version"`) {
				var obj map[string]any
				_ = json.Unmarshal([]byte(body), &obj)
				ver := "Elasticsearch"
				if vm, ok := obj["version"].(map[string]any); ok {
					if num, ok2 := vm["number"].(string); ok2 && num != "" {
						ver = "Elasticsearch " + num
					}
				}
				return makeFindingGo(disp, 9200, "elasticsearch", ver, truncStrGo(body, 180),
					fmt.Sprintf("[CONFIRMED] Unauthenticated Backend Data Store Access (Elasticsearch on %s)", ap),
					"Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
					"CWE-306", "A05:2021 - Security Misconfiguration", fmt.Sprintf("%s://%s/", sch, ap),
					"Elasticsearch HTTP 200 ("+ver+")",
					"Elasticsearch REST API autentifikatsiyasiz tashqi tarmoq uchun ochiq qoldirilgan.",
					"`xpack.security.enabled: true` va `network.host: 127.0.0.1` sozlamalarini yoqing.", 99)
			}
		}
	case 9100:
		code, _, body, err := httpSocketProbeGo("http", host, cp, "GET", "/metrics", tms)
		if err == nil && code == 200 && (strings.Contains(body, "node_uname_info") || strings.Contains(body, "process_cpu_seconds_total") || strings.Contains(body, "go_goroutines")) {
			return makeFindingGo(disp, 9100, "prometheus-node-exporter", "Node Exporter", "Prometheus /metrics 200",
				fmt.Sprintf("[CONFIRMED] Exposed Prometheus Node Exporter Metrics (%s)", ap),
				"Information Disclosure / Monitoring Exposure", "Medium", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				"CWE-200", "A05:2021 - Security Misconfiguration", "http://"+ap+"/metrics", "HTTP 200 /metrics active",
				"Prometheus Node Exporter serverning ichki metrikalarini parolsiz oshkor qilmoqda.",
				"9100-portni tashqi interfeysdan Firewall orqali yoping.", 99)
		}
	case 2375, 2376:
		sch := "http"
		if port == 2376 {
			sch = "https"
		}
		code, _, body, err := httpSocketProbeGo(sch, host, cp, "GET", "/version", tms)
		if err == nil && code == 200 && strings.Contains(body, `"ApiVersion"`) && strings.Contains(body, `"Version"`) {
			return makeFindingGo(disp, port, "docker", "Docker Engine", truncStrGo(body, 160),
				fmt.Sprintf("[CONFIRMED] Unauthenticated Docker Daemon API Exposure (%s)", ap),
				"Container / Infrastructure Exposure", "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				"CWE-306", "A05:2021 - Security Misconfiguration", fmt.Sprintf("%s://%s/version", sch, ap),
				"HTTP 200 /version: "+truncStrGo(body, 120),
				"Docker Engine API TLS mijoz sertifikatisiz tashqi tarmoqqa ochiq qoldirilgan.",
				"Docker TCP soketini o'chiring yoki `--tlsverify` mTLS yoqing.", 99)
		}
	case 6443, 10250:
		ep := "/version"
		if port == 10250 {
			ep = "/pods"
		}
		code, _, body, err := httpSocketProbeGo("https", host, cp, "GET", ep, tms)
		if err == nil && port == 10250 && code == 200 && strings.Contains(body, `"items"`) && strings.Contains(body, `"metadata"`) {
			return makeFindingGo(disp, 10250, "kubelet", "Kubernetes Kubelet", "Kubelet /pods 200",
				fmt.Sprintf("[CONFIRMED] Unauthenticated Kubernetes Kubelet API (%s)", ap),
				"Container / Cluster Exposure", "Critical", 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", "https://"+ap+"/pods", "HTTP 200 on Kubelet /pods",
				"Kubernetes Kubelet API anonim so'rovlarga (`--anonymous-auth=true`) ruxsat bermoqda.",
				"`--anonymous-auth=false` va `--authorization-mode=Webhook` yoqing.", 99)
		}
		if err == nil && port == 6443 && code == 200 && strings.Contains(body, `"gitVersion"`) {
			return &SocketProbeResult{Host: disp, Port: 6443, Service: "kubernetes-api", Version: "Kubernetes API", Banner: truncStrGo(body, 140)}
		}
	case 2379:
		code, _, body, err := httpSocketProbeGo("http", host, cp, "GET", "/version", tms)
		if err == nil && code == 200 && strings.Contains(body, `"etcdserver"`) {
			return makeFindingGo(disp, 2379, "etcd", "etcd", truncStrGo(body, 140),
				fmt.Sprintf("[CONFIRMED] Unauthenticated etcd Cluster Endpoint (%s)", ap),
				"Container / Cluster Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", "http://"+ap+"/version", truncStrGo(body, 120),
				"etcd kalit-qiymat klasteri mijoz TLS sertifikatisiz tashqi tarmoqqa ochiq qoldirilgan.",
				"`--client-cert-auth=true` yoqing va 2379-portni control-plane tugunlariga cheklang.", 99)
		}
	case 8500:
		code, _, body, err := httpSocketProbeGo("http", host, cp, "GET", "/v1/agent/self", tms)
		if err == nil && code == 200 && strings.Contains(body, `"Config"`) && strings.Contains(body, `"Datacenter"`) {
			return makeFindingGo(disp, 8500, "consul", "HashiCorp Consul", "Consul /v1/agent/self 200",
				fmt.Sprintf("[CONFIRMED] Unauthenticated HashiCorp Consul Agent API (%s)", ap),
				"Infrastructure / Service Mesh Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", "http://"+ap+"/v1/agent/self", "HTTP 200 Consul /v1/agent/self",
				"HashiCorp Consul API ACL tokensiz klaster ma'lumotlarini qaytarmoqda.",
				"`acl.enabled = true` va `default_policy = \"deny\"` o'rnating.", 99)
		}
	}
	return probeHttpTsdbAndMgmtGo(host, disp, port, cp, tms)
}

func probeHttpTsdbAndMgmtGo(host string, disp string, port int, cp int, tms int) *SocketProbeResult {
	ap := fmt.Sprintf("%s:%d", disp, port)
	switch port {
	case 15672:
		code, _, body, err := httpSocketProbeGo("http", host, cp, "GET", "/api/overview", tms)
		if err == nil && code == 200 && strings.Contains(body, `"rabbitmq_version"`) {
			return makeFindingGo(disp, 15672, "rabbitmq-mgmt", "RabbitMQ", truncStrGo(body, 140),
				fmt.Sprintf("[CONFIRMED] Unauthenticated RabbitMQ Management API (%s)", ap),
				"Message Broker Exposure", "High", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", "http://"+ap+"/api/overview", truncStrGo(body, 120),
				"RabbitMQ Management API autentifikatsiyasiz xabar brokeri ma'lumotlarini qaytarmoqda.",
				"15672-portni ichki tarmoqqa cheklang va guest kirishini o'chiring.", 99)
		}
	case 8086:
		code, hdr, body, err := httpSocketProbeGo("http", host, cp, "GET", "/query?q=SHOW+DATABASES", tms)
		if err == nil {
			iv := hdr.Get("X-Influxdb-Version")
			if code == 200 && strings.Contains(body, `"results"`) && strings.Contains(body, `"databases"`) {
				return makeFindingGo(disp, 8086, "influxdb", "InfluxDB "+iv, "InfluxDB "+iv,
					fmt.Sprintf("[CONFIRMED] Unauthenticated InfluxDB Database Access (%s)", ap),
					"Database / Cache Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
					"CWE-306", "A05:2021 - Security Misconfiguration", ap, "GET /query?q=SHOW+DATABASES HTTP 200",
					"InfluxDB bazasida HTTP autentifikatsiya o'chirilgan (`auth-enabled = false`).",
					"`[http] auth-enabled = true` sozlamasini yoqing.", 99)
			}
			if iv != "" {
				return &SocketProbeResult{Host: disp, Port: 8086, Service: "influxdb", Version: "InfluxDB " + iv, Banner: "InfluxDB " + iv}
			}
		}
	case 8123:
		code, hdr, body, err := httpSocketProbeGo("http", host, cp, "GET", "/?query=SELECT%20version()", tms)
		if err == nil && code == 200 && hdr.Get("X-Clickhouse-Summary") != "" && reChVer.MatchString(strings.TrimSpace(body)) {
			cv := truncStrGo(body, 24)
			return makeFindingGo(disp, 8123, "clickhouse", "ClickHouse "+cv, "ClickHouse "+cv,
				fmt.Sprintf("[CONFIRMED] Unauthenticated ClickHouse SQL Interface (%s)", ap),
				"Database / Cache Exposure", "Critical", 9.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "SELECT version() -> ClickHouse "+cv,
				"ClickHouse HTTP SQL interfeysi parolsiz so'rovlarni bajarmoqda.",
				"`users.xml` da `default` foydalanuvchiga parol va IP cheklovi o'rnating.", 99)
		}
	case 5000:
		code, _, body, err := httpSocketProbeGo("http", host, cp, "GET", "/v2/_catalog", tms)
		if err == nil && code == 200 && strings.Contains(body, `"repositories"`) {
			return makeFindingGo(disp, 5000, "docker-registry", "Docker Distribution v2", "Registry /v2/_catalog 200",
				fmt.Sprintf("[CONFIRMED] Unauthenticated Private Docker Registry v2 Catalog (%s)", ap),
				"Container Infrastructure Exposure", "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "GET /v2/_catalog HTTP 200",
				"Shaxsiy Docker obrazlar reestri autentifikatsiyasiz `/v2/_catalog` ro'yxatini ochiq bermoqda.",
				"Docker Registry uchun token/htpasswd autentifikatsiya va TLS yoqing.", 99)
		}
	case 5985:
		code, hdr, body, err := httpSocketProbeGo("http", host, cp, "POST", "/wsman", tms)
		if err == nil {
			wa := hdr.Get("WWW-Authenticate")
			if (code == 401 && strings.Contains(strings.ToLower(wa), "basic")) || (code == 200 && strings.Contains(strings.ToLower(body), "wsman")) {
				return makeFindingGo(disp, 5985, "wsman", "WinRM HTTP", "WinRM /wsman",
					fmt.Sprintf("[CONFIRMED] Cleartext WinRM Management Service Exposure (%s)", ap),
					"Remote Management Exposure", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					"CWE-319", "A02:2021 - Cryptographic Failures", ap, fmt.Sprintf("HTTP %d /wsman | Auth: %s", code, truncStrGo(wa, 60)),
					"WinRM (`:5985`) shifrlanmagan HTTP orqali Basic autentifikatsiya yoki ochiq kirishga ruxsat bermoqda.",
					"WinRM HTTPS (`:5986`) ga o'ting va `AllowUnencrypted=false` o'rnating.", 95)
			}
		}
	case 50070:
		code, _, body, err := httpSocketProbeGo("http", host, cp, "GET", "/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo", tms)
		if err == nil && code == 200 && (strings.Contains(body, "NameNodeInfo") || strings.Contains(body, "ClusterId")) {
			return makeFindingGo(disp, 50070, "hadoop-namenode", "Apache Hadoop NameNode", "NameNode /jmx 200",
				fmt.Sprintf("[CONFIRMED] Unauthenticated Apache Hadoop NameNode JMX Console (%s)", ap),
				"Big Data Cluster Exposure", "High", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				"CWE-306", "A05:2021 - Security Misconfiguration", ap, "GET /jmx NameNodeInfo HTTP 200",
				"Hadoop HDFS NameNode JMX konsoli Kerberos autentifikatsiyasiz ochiq ishlamoqda.",
				"`hadoop.security.authentication=kerberos` sozlamasini yoqing.", 99)
		}
	}
	return nil
}
