// SPECTRE Go Clean-Room Enterprise Server & Ecosystem Advisory Pack (NIST NVD / OSV / Debian)
// 100% Copyright-Clean (US-Gov-Public-Domain & CC-BY-4.0) baseline CPE/SemVer advisories.
package main

type CleanroomAdvisoryRow struct {
	ID, Vendor, Product, CPE23, MinVer, MaxVer string
	CVSS                                       float64
	Severity, CWE                              string
	IsKEV                                      int
	Summary, Remediation, SPDX                 string
}

var CompiledCleanroomAdvisories = []CleanroomAdvisoryRow{
	{
		"CVE-2024-6387", "openbsd", "openssh", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
		"8.5p1", "9.8p1", 8.1, "High", "CWE-362", 1,
		"OpenSSH sshd signal handler timing issue",
		"Upgrade OpenSSH to >= 9.8p1 or set LoginGraceTime 0", "US-Gov-Public-Domain",
	},
	{
		"CVE-2023-38408", "openbsd", "openssh", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
		"5.5p1", "9.3p2", 9.8, "Critical", "CWE-427", 1,
		"OpenSSH ssh-agent PKCS#11 library loading issue",
		"Upgrade OpenSSH to >= 9.3p2 and restrict forwarding", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-4577", "php", "php", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
		"8.1.0", "8.1.29", 9.8, "Critical", "CWE-78", 1,
		"PHP CGI locale parameter handling issue (8.1 branch)",
		"Upgrade PHP 8.1 to >= 8.1.29", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-4577", "php", "php", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
		"8.2.0", "8.2.20", 9.8, "Critical", "CWE-78", 1,
		"PHP CGI locale parameter handling issue (8.2 branch)",
		"Upgrade PHP 8.2 to >= 8.2.20", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-4577", "php", "php", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
		"8.3.0", "8.3.8", 9.8, "Critical", "CWE-78", 1,
		"PHP CGI locale parameter handling issue (8.3 branch)",
		"Upgrade PHP 8.3 to >= 8.3.8", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-3094", "tukaani", "xz", "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*",
		"5.6.0", "5.6.2", 10.0, "Critical", "CWE-506", 1,
		"XZ Utils liblzma upstream release integrity issue",
		"Downgrade to xz 5.4.x or upgrade to >= 5.6.2", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-27198", "jetbrains", "teamcity", "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*",
		"2017.1", "2023.11.4", 9.8, "Critical", "CWE-287", 1,
		"JetBrains TeamCity web authentication validation issue",
		"Upgrade TeamCity to >= 2023.11.4", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-1709", "connectwise", "screenconnect",
		"cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
		"19.0", "23.9.8", 10.0, "Critical", "CWE-287", 1,
		"ConnectWise ScreenConnect setup path access control issue",
		"Upgrade ScreenConnect to >= 23.9.8", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-3400", "paloaltonetworks", "pan-os",
		"cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
		"10.2.0", "11.1.2", 10.0, "Critical", "CWE-78", 1,
		"PAN-OS GlobalProtect telemetry input validation issue",
		"Apply official Palo Alto Networks PAN-OS update", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-21762", "fortinet", "fortios", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
		"6.0.0", "7.0.14", 9.8, "Critical", "CWE-787", 1,
		"Fortinet FortiOS SSL-VPN boundary write issue (6.x/7.0 branch)",
		"Upgrade FortiOS to >= 7.0.14", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-21762", "fortinet", "fortios", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
		"7.2.0", "7.2.7", 9.8, "Critical", "CWE-787", 1,
		"Fortinet FortiOS SSL-VPN boundary write issue (7.2 branch)",
		"Upgrade FortiOS 7.2 to >= 7.2.7", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-21762", "fortinet", "fortios", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
		"7.4.0", "7.4.3", 9.8, "Critical", "CWE-787", 1,
		"Fortinet FortiOS SSL-VPN boundary write issue (7.4 branch)",
		"Upgrade FortiOS 7.4 to >= 7.4.3", "US-Gov-Public-Domain",
	},
	{
		"CVE-2023-4966", "citrix", "netscaler_adc",
		"cpe:2.3:a:citrix:netscaler_adc:*:*:*:*:*:*:*:*",
		"13.0.0", "14.1.8", 9.4, "Critical", "CWE-200", 1,
		"Citrix NetScaler ADC memory disclosure issue",
		"Upgrade NetScaler ADC and rotate active sessions", "US-Gov-Public-Domain",
	},
	{
		"CVE-2023-22527", "atlassian", "confluence",
		"cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*",
		"8.0.0", "8.5.5", 10.0, "Critical", "CWE-94", 1,
		"Atlassian Confluence template evaluation issue",
		"Upgrade Confluence Data Center/Server to >= 8.5.5", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-23897", "jenkins", "jenkins", "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
		"2.0", "2.442", 9.8, "Critical", "CWE-22", 1,
		"Jenkins CLI args4j file path parsing issue",
		"Upgrade Jenkins to >= 2.442 or LTS >= 2.426.3", "US-Gov-Public-Domain",
	},
	{
		"CVE-2023-46604", "apache", "activemq", "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
		"5.0.0", "5.18.3", 10.0, "Critical", "CWE-502", 1,
		"Apache ActiveMQ OpenWire class instantiation issue",
		"Upgrade Apache ActiveMQ to >= 5.18.3", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-38816", "vmware", "spring_framework",
		"cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
		"5.3.0", "6.1.13", 7.5, "High", "CWE-22", 1,
		"Spring Framework WebFlux static resource path traversal",
		"Upgrade Spring Framework to >= 6.1.13", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-50379", "apache", "tomcat", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
		"9.0.0", "9.0.98", 9.8, "Critical", "CWE-362", 0,
		"Apache Tomcat JSP compilation concurrency issue (9.0 branch)",
		"Upgrade Apache Tomcat 9.0 to >= 9.0.98", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-50379", "apache", "tomcat", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
		"10.1.0", "10.1.34", 9.8, "Critical", "CWE-362", 0,
		"Apache Tomcat JSP compilation concurrency issue (10.1 branch)",
		"Upgrade Apache Tomcat 10.1 to >= 10.1.34", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-7348", "postgresql", "postgresql",
		"cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		"12.0", "14.13", 8.8, "High", "CWE-362", 0,
		"PostgreSQL pg_dump relation concurrency issue (12-14 branch)",
		"Upgrade PostgreSQL 14 to >= 14.13", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-7348", "postgresql", "postgresql",
		"cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		"15.0", "15.8", 8.8, "High", "CWE-362", 0,
		"PostgreSQL pg_dump relation concurrency issue (15 branch)",
		"Upgrade PostgreSQL 15 to >= 15.8", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-7348", "postgresql", "postgresql",
		"cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		"16.0", "16.4", 8.8, "High", "CWE-362", 0,
		"PostgreSQL pg_dump relation concurrency issue (16 branch)",
		"Upgrade PostgreSQL 16 to >= 16.4", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-31449", "redis", "redis", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
		"6.0.0", "7.2.6", 7.0, "High", "CWE-122", 0,
		"Redis Lua bit library buffer bounds issue (6.x-7.2 branch)",
		"Upgrade Redis 7.2 to >= 7.2.6", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-31449", "redis", "redis", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
		"7.4.0", "7.4.1", 7.0, "High", "CWE-122", 0,
		"Redis Lua bit library buffer bounds issue (7.4 branch)",
		"Upgrade Redis 7.4 to >= 7.4.1", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-45337", "golang", "x_crypto_ssh", "cpe:2.3:a:golang:x_crypto:*:*:*:*:*:*:*:*",
		"0.1.0", "0.31.0", 9.1, "Critical", "CWE-287", 0,
		"Go golang.org/x/crypto/ssh callback verification issue",
		"Upgrade golang.org/x/crypto to >= v0.31.0", "CC-BY-4.0",
	},
	{
		"CVE-2025-29927", "vercel", "next.js", "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
		"11.1.4", "13.5.9", 9.1, "Critical", "CWE-285", 0,
		"Next.js subrequest header authorization validation issue (11-13 branch)",
		"Upgrade Next.js 13 to >= 13.5.9", "CC-BY-4.0",
	},
	{
		"CVE-2025-29927", "vercel", "next.js", "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
		"14.0.0", "14.2.25", 9.1, "Critical", "CWE-285", 0,
		"Next.js subrequest header authorization validation issue (14 branch)",
		"Upgrade Next.js 14 to >= 14.2.25", "CC-BY-4.0",
	},
	{
		"CVE-2025-29927", "vercel", "next.js", "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
		"15.0.0", "15.2.3", 9.1, "Critical", "CWE-285", 0,
		"Next.js subrequest header authorization validation issue (15 branch)",
		"Upgrade Next.js 15 to >= 15.2.3", "CC-BY-4.0",
	},
	{
		"CVE-2024-9264", "grafana", "grafana", "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
		"11.0.0", "11.2.2", 9.9, "Critical", "CWE-78", 0,
		"Grafana SQL expression query parameter issue",
		"Upgrade Grafana to >= 11.2.2+security-01", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-45409", "gitlab", "gitlab", "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
		"16.0.0", "17.2.7", 9.8, "Critical", "CWE-347", 1,
		"GitLab SAML response signature verification issue (16.x-17.2 branch)",
		"Upgrade GitLab 17.2 to >= 17.2.7", "US-Gov-Public-Domain",
	},
	{
		"CVE-2024-45409", "gitlab", "gitlab", "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
		"17.3.0", "17.3.3", 9.8, "Critical", "CWE-347", 1,
		"GitLab SAML response signature verification issue (17.3 branch)",
		"Upgrade GitLab 17.3 to >= 17.3.3", "US-Gov-Public-Domain",
	},
}
