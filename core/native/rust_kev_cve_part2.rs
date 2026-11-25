// SPECTRE Rust Static .rodata CVE & KEV Shard (KEV_CVE_PART2)

use crate::rust_kev_cve_part1::KevCveRecord;

pub static KEV_CVE_PART2: &[KevCveRecord] = &[
    KevCveRecord {
        cve_id: "CVE-2020-3992",
        vendor: "VMware",
        product: "ESXi",
        cpe23: "cpe:2.3:a:vmware:esxi:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware ESXi OpenSLP contains a use-after-free vulnerability that a",
            "llows an attacker residing in the management network with access t",
            "o port 427 to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-4006",
        vendor: "VMware",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:vmware:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware Workspace One Access, Access Connector, Identity Manager, a",
            "nd Identity Manager Connector contain a command injection vulnerab",
            "ility. An attacker with network access to the administrative confi",
            "gurator on port 8443 and a valid password for the configurator adm",
            "inistrator account can execute commands with unrestricte"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-4427",
        vendor: "IBM",
        product: "Data Risk Manager",
        cpe23: "cpe:2.3:a:ibm:data_risk_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "IBM Data Risk Manager contains a security bypass vulnerability tha",
            "t could allow a remote attacker to bypass security restrictions wh",
            "en configured with SAML authentication. By sending a specially cra",
            "fted HTTP request, an attacker could exploit this vulnerability to",
            " bypass the authentication process and gain full adminis"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-4428",
        vendor: "IBM",
        product: "Data Risk Manager",
        cpe23: "cpe:2.3:a:ibm:data_risk_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "IBM Data Risk Manager contains an unspecified vulnerability which ",
            "could allow a remote, authenticated attacker to execute commands o",
            "n the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-4430",
        vendor: "IBM",
        product: "Data Risk Manager",
        cpe23: "cpe:2.3:a:ibm:data_risk_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "IBM Data Risk Manager contains a directory traversal vulnerability",
            " that could allow a remote authenticated attacker to traverse dire",
            "ctories and send a specially crafted URL request to download arbit",
            "rary files from the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5135",
        vendor: "SonicWall",
        product: "SonicOS",
        cpe23: "cpe:2.3:a:sonicwall:sonicos:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A buffer overflow vulnerability in SonicOS allows a remote attacke",
            "r to cause Denial of Service (DoS) and potentially execute arbitra",
            "ry code by sending a malicious request to the firewall."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5410",
        vendor: "VMware Tanzu",
        product: "Spring Cloud Configuration (Config) Server",
        cpe23: concat!(
            "cpe:2.3:a:vmware_tanzu:spring_cloud_configuration_config_server:*:",
            "*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Spring, by VMware Tanzu, Cloud Config contains a path traversal vu",
            "lnerability that allows applications to serve arbitrary configurat",
            "ion files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5722",
        vendor: "Grandstream",
        product: "UCM6200",
        cpe23: "cpe:2.3:a:grandstream:ucm6200:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Grandstream UCM6200 series is vulnerable to an unauthenticated rem",
            "ote SQL injection via crafted HTTP request. Exploitation can allow",
            " for code execution as root."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5735",
        vendor: "Amcrest",
        product: "Cameras and Network Video Recorder (NVR)",
        cpe23: concat!(
            "cpe:2.3:a:amcrest:cameras_and_network_video_recorder_nvr:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Amcrest cameras and NVR contain a stack-based buffer overflow vuln",
            "erability through port 37777 that allows an unauthenticated, remot",
            "e attacker to crash the device and possibly execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5741",
        vendor: "Plex",
        product: "Media Server",
        cpe23: "cpe:2.3:a:plex:media_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Plex Media Server contains a remote code execution vulnerability t",
            "hat allows an attacker with access to the server administrator's P",
            "lex account to upload a malicious file via the Camera Upload featu",
            "re and have the media server execute it."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5847",
        vendor: "Unraid",
        product: "Unraid",
        cpe23: "cpe:2.3:a:unraid:unraid:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unraid contains a vulnerability due to the insecure use of the ext",
            "ract PHP function that can be abused to execute remote code as roo",
            "t. This CVE is chainable with CVE-2020-5849 for initial access."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5849",
        vendor: "Unraid",
        product: "Unraid",
        cpe23: "cpe:2.3:a:unraid:unraid:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unraid contains an authentication bypass vulnerability that allows",
            " attackers to gain access to the administrative interface. This CV",
            "E is chainable with CVE-2020-5847 for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-5902",
        vendor: "F5",
        product: "BIG-IP",
        cpe23: "cpe:2.3:a:f5:big-ip:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "F5 BIG-IP Traffic Management User Interface (TMUI) contains a remo",
            "te code execution vulnerability in undisclosed pages."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-6207",
        vendor: "SAP",
        product: "Solution Manager",
        cpe23: "cpe:2.3:a:sap:solution_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP Solution Manager User Experience Monitoring contains a missing",
            " authentication for critical function vulnerability which results ",
            "in complete compromise of all SMDAgents connected to the Solution ",
            "Manager."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-6287",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver Application Server Java Platforms contains a missing",
            " authentication for critical function vulnerability allowing unaut",
            "henticated access to execute configuration tasks and create admini",
            "strative users."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-6418",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "allows a remote attacker to potentially exploit heap corruption vi",
            "a a crafted HTML page. This vulnerability could affect multiple we",
            "b browsers that utilize Chromium, including, but not limited to, G",
            "oogle Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-6572",
        vendor: "Google",
        product: "Chrome Media",
        cpe23: "cpe:2.3:a:google:chrome_media:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chrome Media contains a use-after-free vulnerability that a",
            "llows a remote attacker to execute code via a crafted HTML page."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-6819",
        vendor: "Mozilla",
        product: "Firefox and Thunderbird",
        cpe23: "cpe:2.3:a:mozilla:firefox_and_thunderbird:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox and Thunderbird contain a race condition vulnerabi",
            "lity when running the nsDocShell destructor under certain conditio",
            "ns. The race condition creates a use-after-free vulnerability, cau",
            "sing unspecified impacts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-6820",
        vendor: "Mozilla",
        product: "Firefox and Thunderbird",
        cpe23: "cpe:2.3:a:mozilla:firefox_and_thunderbird:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox and Thunderbird contain a race condition vulnerabi",
            "lity when handling a ReadableStream under certain conditions. The ",
            "race condition creates a use-after-free vulnerability, causing uns",
            "pecified impacts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-7247",
        vendor: "OpenBSD",
        product: "OpenSMTPD",
        cpe23: "cpe:2.3:a:openbsd:opensmtpd:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "smtp_mailaddr in smtp_session.c in OpenSMTPD, as used in OpenBSD a",
            "nd other products, allows remote attackers to execute arbitrary co",
            "mmands as root via a crafted SMTP session."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-7660",
        vendor: "npm",
        product: "serialize-javascript",
        cpe23: "cpe:2.3:a:npm:serialize-javascript:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm serialize-javascript vulnerability advisory",
        remediation: "Upgrade serialize-javascript to >= 3.1.0",
    },
    KevCveRecord {
        cve_id: "CVE-2020-7796",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a server-side re",
            "quest forgery vulnerability if WebEx zimlet installed and zimlet J",
            "SP is enabled."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-7961",
        vendor: "Liferay",
        product: "Liferay Portal",
        cpe23: "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Liferay Portal contains a deserialization of untrusted data vulner",
            "ability that allows remote attackers to execute code via JSON web ",
            "services."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8193",
        vendor: "Citrix",
        product: concat!(
            "Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP A",
            "ppliance"
        ),
        cpe23: concat!(
            "cpe:2.3:a:citrix:application_delivery_controller_adc_gateway_and_s",
            "d-wan_wanop_appliance:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix ADC, Citrix Gateway, and multiple Citrix SD-WAN WANOP appli",
            "ance models contain an authorization bypass vulnerability that may",
            " allow unauthenticated access to certain URL endpoints. The attack",
            "er must have access to the NetScaler IP (NSIP) in order to perform",
            " exploitation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8195",
        vendor: "Citrix",
        product: concat!(
            "Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP A",
            "ppliance"
        ),
        cpe23: concat!(
            "cpe:2.3:a:citrix:application_delivery_controller_adc_gateway_and_s",
            "d-wan_wanop_appliance:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix ADC, Citrix Gateway, and multiple Citrix SD-WAN WANOP appli",
            "ance models contain an information disclosure vulnerability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8196",
        vendor: "Citrix",
        product: concat!(
            "Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP A",
            "ppliance"
        ),
        cpe23: concat!(
            "cpe:2.3:a:citrix:application_delivery_controller_adc_gateway_and_s",
            "d-wan_wanop_appliance:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix ADC, Citrix Gateway, and multiple Citrix SD-WAN WANOP appli",
            "ance models contain an information disclosure vulnerability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8218",
        vendor: "Pulse Secure",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:pulse_secure:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A code injection vulnerability exists in Pulse Connect Secure that",
            " allows an attacker to crafted a URI to perform an arbitrary code ",
            "execution via the admin web interface."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8243",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Pulse Connect Secure contains an unspecified vulnerability ",
            "in the admin web interface that could allow an authenticated attac",
            "ker to upload a custom template to perform code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8260",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Pulse Connect Secure contains an unspecified vulnerability that al",
            "lows an authenticated attacker to perform code execution using unc",
            "ontrolled gzip extraction."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8467",
        vendor: "Trend Micro",
        product: "Apex One and OfficeScan",
        cpe23: "cpe:2.3:a:trend_micro:apex_one_and_officescan:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One and OfficeScan contain an unspecified vulnera",
            "bility within a migration tool component that allows for remote co",
            "de execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8468",
        vendor: "Trend Micro",
        product: "Apex One, OfficeScan and Worry-Free Business Security Agents",
        cpe23: concat!(
            "cpe:2.3:a:trend_micro:apex_one_officescan_and_worry-free_business_",
            "security_agents:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One, OfficeScan, and Worry-Free Business Security",
            " agents contain a content validation escape vulnerability that cou",
            "ld allow an attacker to manipulate certain agent client components",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8515",
        vendor: "DrayTek",
        product: "Multiple Vigor Routers",
        cpe23: "cpe:2.3:a:draytek:multiple_vigor_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "DrayTek Vigor3900, Vigor2960, and Vigor300B routers contain an uns",
            "pecified vulnerability that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8599",
        vendor: "Trend Micro",
        product: "Apex One and OfficeScan",
        cpe23: "cpe:2.3:a:trend_micro:apex_one_and_officescan:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One and OfficeScan server contain a vulnerable EX",
            "E file that could allow a remote attacker to write data to a path ",
            "on affected installations and bypass root login."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8644",
        vendor: "PlaySMS",
        product: "PlaySMS",
        cpe23: "cpe:2.3:a:playsms:playsms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PlaySMS contains a server-side template injection vulnerability th",
            "at allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8655",
        vendor: "EyesOfNetwork",
        product: "EyesOfNetwork",
        cpe23: "cpe:2.3:a:eyesofnetwork:eyesofnetwork:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "EyesOfNetwork contains an improper privilege management vulnerabil",
            "ity that may allow a user to run commands as root via a crafted Nm",
            "ap Scripting Engine (NSE) script to nmap7."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8657",
        vendor: "EyesOfNetwork",
        product: "EyesOfNetwork",
        cpe23: "cpe:2.3:a:eyesofnetwork:eyesofnetwork:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "EyesOfNetwork contains a use of hard-coded credentials vulnerabili",
            "ty, as it uses the same API key by default. Exploitation allows an",
            " attacker to calculate or guess the admin access token."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-8816",
        vendor: "Pi-hole",
        product: "AdminLTE",
        cpe23: "cpe:2.3:a:pi-hole:adminlte:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Pi-hole Web v4.3.2 (aka AdminLTE) allows Remote Code Execution by ",
            "privileged dashboard users via a crafted DHCP static lease."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-9054",
        vendor: "Zyxel",
        product: "Multiple Network-Attached Storage (NAS) Devices",
        cpe23: concat!(
            "cpe:2.3:a:zyxel:multiple_network-attached_storage_nas_devices:*:*:",
            "*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Zyxel network-attached storage (NAS) devices contain a pr",
            "e-authentication command injection vulnerability, which may allow ",
            "a remote, unauthenticated attacker to execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-9377",
        vendor: "D-Link",
        product: "DIR-610 Devices",
        cpe23: "cpe:2.3:a:d-link:dir-610_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-610 devices allow remote code execution via the cmd par",
            "ameter to command.php."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-9715",
        vendor: "Adobe",
        product: "Acrobat",
        cpe23: "cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat contains a use-after-free vulnerability that allows ",
            "for code execution"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-9818",
        vendor: "Apple",
        product: "iOS, iPadOS, and watchOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_watchos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and watchOS Mail contains an out-of-bounds writ",
            "e vulnerability which may allow memory modification or application",
            " termination when processing a maliciously crafted mail message."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-9819",
        vendor: "Apple",
        product: "iOS, iPadOS, and watchOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_watchos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and watchOS Mail contains a memory corruption v",
            "ulnerability that may allow heap corruption when processing a mali",
            "ciously crafted mail message."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-9859",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, watchOS, and tvOS contain an unspecified",
            " vulnerability that may allow an application to execute code with ",
            "kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-9907",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and tvOS contain a memory corruption vulnerabil",
            "ity that could allow an application to execute code with kernel pr",
            "ivileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-9934",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS contain an unspecified vulnerability ",
            "involving input validation which can allow a local attacker to vie",
            "w sensitive user information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-0920",
        vendor: "Android",
        product: "Kernel",
        cpe23: "cpe:2.3:a:android:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android kernel contains a race condition, which allows for a use-a",
            "fter-free vulnerability. Exploitation can allow for privilege esca",
            "lation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1048",
        vendor: "Android",
        product: "Kernel",
        cpe23: "cpe:2.3:a:android:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android kernel contains a use-after-free vulnerability that allows",
            " for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1497",
        vendor: "Cisco",
        product: "HyperFlex HX",
        cpe23: "cpe:2.3:a:cisco:hyperflex_hx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco HyperFlex HX Installer Virtual Machine contains an insuffici",
            "ent input validation vulnerability which could allow an attacker t",
            "o execute commands on an affected device as the root user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1498",
        vendor: "Cisco",
        product: "HyperFlex HX",
        cpe23: "cpe:2.3:a:cisco:hyperflex_hx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco HyperFlex HX Installer Virtual Machine contains an insuffici",
            "ent input validation vulnerability which could allow an attacker t",
            "o execute commands on an affected device as the tomcat8 user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1647",
        vendor: "Microsoft",
        product: "Defender",
        cpe23: "cpe:2.3:a:microsoft:defender:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Defender contains an unspecified vulnerability that allo",
            "ws for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1675",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Print Spooler contains an unspecified vulnerabil",
            "ity that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1732",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability that allows",
            " for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1782",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOs, macOS, watchOS, and tvOS contain a race conditi",
            "on vulnerability that may allow a malicious application to elevate",
            " privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1789",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A type confusion issue affecting multiple Apple products allows pr",
            "ocessing of maliciously crafted web content, leading to arbitrary ",
            "code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1870",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS WebKit contain an unspecified logic v",
            "ulnerability that allows a remote attacker to execute code. This v",
            "ulnerability could impact HTML parsers that use WebKit, including ",
            "but not limited to Apple Safari and non-Apple products which rely ",
            "on WebKit for HTML processing."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1871",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS WebKit contain an unspecified logic v",
            "ulnerability that allows a remote attacker to execute code. This v",
            "ulnerability could impact HTML parsers that use WebKit, including ",
            "but not limited to Apple Safari and non-Apple products which rely ",
            "on WebKit for HTML processing."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1879",
        vendor: "Apple",
        product: "iOS, iPadOS, and watchOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_watchos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and watchOS WebKit contain an unspecified vulne",
            "rability that allows for universal cross-site scripting (XSS) when",
            " processing maliciously crafted web content. This vulnerability co",
            "uld impact HTML parsers that use WebKit, including but not limited",
            " to Apple Safari and non-Apple products which rely on We"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1905",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm Chipsets contain a use after free vulnerability ",
            "due to improper handling of memory mapping of multiple processes s",
            "imultaneously."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-1906",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a detection of error condition ",
            "without action vulnerability when improper handling of address der",
            "egistration on failure can lead to new GPU address allocation fail",
            "ure."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20016",
        vendor: "SonicWall",
        product: "SSLVPN SMA100",
        cpe23: "cpe:2.3:a:sonicwall:sslvpn_sma100:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SSLVPN SMA100 contains a SQL injection vulnerability tha",
            "t allows remote exploitation for credential access by an unauthent",
            "icated attacker."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20021",
        vendor: "SonicWall",
        product: "SonicWall Email Security",
        cpe23: "cpe:2.3:a:sonicwall:sonicwall_email_security:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall Email Security contains an improper privilege management",
            " vulnerability that allows an attacker to create an administrative",
            " account by sending a crafted HTTP request to the remote host. Thi",
            "s vulnerability has known usage in a SonicWall Email Security expl",
            "oit chain along with CVE-2021-20022 and CVE-2021-20023 t"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20022",
        vendor: "SonicWall",
        product: "SonicWall Email Security",
        cpe23: "cpe:2.3:a:sonicwall:sonicwall_email_security:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall Email Security contains an unrestricted upload of file w",
            "ith dangerous type vulnerability that allows a post-authenticated ",
            "attacker to upload a file to the remote host. This vulnerability h",
            "as known usage in a SonicWall Email Security exploit chain along w",
            "ith CVE-2021-20021 and CVE-2021-20023 to achieve privile"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20023",
        vendor: "SonicWall",
        product: "SonicWall Email Security",
        cpe23: "cpe:2.3:a:sonicwall:sonicwall_email_security:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall Email Security contains a path traversal vulnerability t",
            "hat allows a post-authenticated attacker to read files on the remo",
            "te host. This vulnerability has known usage in a SonicWall Email S",
            "ecurity exploit chain along with CVE-2021-20021 and CVE-2021-20022",
            " to achieve privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20028",
        vendor: "SonicWall",
        product: "Secure Remote Access (SRA)",
        cpe23: "cpe:2.3:a:sonicwall:secure_remote_access_sra:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall Secure Remote Access (SRA) products contain an improper ",
            "neutralization of a SQL Command leading to SQL injection."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-20035",
        vendor: "SonicWall",
        product: "SMA100 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma100_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SonicWall SMA100 appliances contain an OS command injection vulner",
            "ability in the management interface that allows a remote authentic",
            "ated attacker to inject arbitrary commands as a 'nobody' user, whi",
            "ch could potentially lead to code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-20038",
        vendor: "SonicWall",
        product: "SMA 100 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma_100_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SMA 100 devies are vulnerable to an unauthenticated stac",
            "k-based buffer overflow vulnerability where exploitation can resul",
            "t in code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20090",
        vendor: "Arcadyan",
        product: "Buffalo Firmware",
        cpe23: "cpe:2.3:a:arcadyan:buffalo_firmware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arcadyan Buffalo firmware contains a path traversal vulnerability ",
            "that could allow unauthenticated, remote attackers to bypass authe",
            "ntication and access sensitive information. This vulnerability aff",
            "ects multiple routers across several different vendors."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-20123",
        vendor: "DrayTek",
        product: "VigorConnect",
        cpe23: "cpe:2.3:a:draytek:vigorconnect:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Draytek VigorConnect contains a path traversal vulnerability in th",
            "e DownloadFileServlet endpoint. An unauthenticated attacker could ",
            "leverage this vulnerability to download arbitrary files from the u",
            "nderlying operating system with root privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-20124",
        vendor: "DrayTek",
        product: "VigorConnect",
        cpe23: "cpe:2.3:a:draytek:vigorconnect:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Draytek VigorConnect contains a path traversal vulnerability in th",
            "e file download functionality of the WebServlet endpoint. An unaut",
            "henticated attacker could leverage this vulnerability to download ",
            "arbitrary files from the underlying operating system with root pri",
            "vileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-21017",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Acrobat Acrobat and Reader contain a heap-based buffer overflow vu",
            "lnerability that could allow an unauthenticated attacker to achiev",
            "e code execution in the context of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21148",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a heap buffer overflow vulnerab",
            "ility that allows a remote attacker to potentially exploit heap co",
            "rruption via a crafted HTML page. This vulnerability could affect ",
            "multiple web browsers that utilize Chromium, including, but not li",
            "mited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21166",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium contains a race condition vulnerability that allow",
            "s a remote attacker to potentially exploit heap corruption via a c",
            "rafted HTML page. This vulnerability could affect multiple web bro",
            "wsers that utilize Chromium, including, but not limited to, Google",
            " Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21193",
        vendor: "Google",
        product: "Chromium Blink",
        cpe23: "cpe:2.3:a:google:chromium_blink:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Blink contains a use-after-free vulnerability that",
            " allows a remote attacker to potentially exploit heap corruption v",
            "ia a crafted HTML page. This vulnerability could affect multiple w",
            "eb browsers that utilize Chromium, including, but not limited to, ",
            "Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21206",
        vendor: "Google",
        product: "Chromium Blink",
        cpe23: "cpe:2.3:a:google:chromium_blink:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Blink contains a use-after-free vulnerability that",
            " allows a remote attacker to potentially exploit heap corruption v",
            "ia a crafted HTML page. This vulnerability could affect multiple w",
            "eb browsers that utilize Chromium, including, but not limited to, ",
            "Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21220",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an improper input validation vu",
            "lnerability that allows a remote attacker to potentially exploit h",
            "eap corruption via a crafted HTML page. This vulnerability could a",
            "ffect multiple web browsers that utilize Chromium, including, but ",
            "not limited to, Google Chrome, Microsoft Edge, and Opera"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21224",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to execute code inside a sandbox via",
            " a crafted HTML page. This vulnerability could affect multiple web",
            " browsers that utilize Chromium, including, but not limited to, Go",
            "ogle Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21311",
        vendor: "Adminer",
        product: "Adminer",
        cpe23: "cpe:2.3:a:adminer:adminer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adminer contains a server-side request forgery vulnerability that,",
            " when exploited, allows a remote attacker to obtain potentially se",
            "nsitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-21315",
        vendor: "Npm package",
        product: "System Information Library for Node.JS",
        cpe23: concat!(
            "cpe:2.3:a:npm_package:system_information_library_for_node.js:*:*:*",
            ":*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "In this vulnerability, an attacker can send a malicious payload th",
            "at will exploit the name parameter. After successful exploitation,",
            " attackers can execute remote."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21551",
        vendor: "Dell",
        product: "dbutil Driver",
        cpe23: "cpe:2.3:a:dell:dbutil_driver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dell dbutil driver contains an insufficient access control vulnera",
            "bility which may lead to escalation of privileges, denial-of-servi",
            "ce (DoS), or information disclosure."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21972",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware vCenter Server vSphere Client contains a remote code execut",
            "ion vulnerability in a vCenter Server plugin which allows an attac",
            "ker with network access to port 443 to execute commands with unres",
            "tricted privileges on the underlying operating system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21973",
        vendor: "VMware",
        product: "vCenter Server and Cloud Foundation",
        cpe23: concat!(
            "cpe:2.3:a:vmware:vcenter_server_and_cloud_foundation:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware vCenter Server and Cloud Foundation Server contain a SSRF v",
            "ulnerability due to improper validation of URLs in a vCenter Serve",
            "r plugin. This allows for information disclosure."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21975",
        vendor: "VMware",
        product: "vRealize Operations Manager API",
        cpe23: "cpe:2.3:a:vmware:vrealize_operations_manager_api:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Server Side Request Forgery (SSRF) in vRealize Operations Manager ",
            "API prior to 8.4 may allow a malicious actor with network access t",
            "o the vRealize Operations Manager API to perform a SSRF attack to ",
            "steal administrative credentials."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-21985",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware vSphere Client contains an improper input validation vulner",
            "ability in the Virtual SAN Health Check plug-in, which is enabled ",
            "by default in vCenter Server, which allows for remote code executi",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22005",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware vCenter Server contains a file upload vulnerability in the ",
            "Analytics service that allows a user with network access to port 4",
            "43 to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22017",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Rhttproxy as used in vCenter Server contains a vulnerability due t",
            "o improper implementation of URI normalization."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22054",
        vendor: "Omnissa",
        product: "Workspace One UEM",
        cpe23: "cpe:2.3:a:omnissa:workspace_one_uem:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Omnissa Workspace One UEM formerly known as VMware Workspace One U",
            "EM contains a server-side request forgery (SSRF) vulnerability tha",
            "t could allow a malicious actor with network access to UEM to send",
            " their requests without authentication and to gain access to sensi",
            "tive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-22175",
        vendor: "GitLab",
        product: "GitLab",
        cpe23: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GitLab contains a server-side request forgery (SSRF) vulnerability",
            " when requests to the internal network for webhooks are enabled."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-22204",
        vendor: "Perl",
        product: "Exiftool",
        cpe23: "cpe:2.3:a:perl:exiftool:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Improper neutralization of user data in the DjVu file format in Ex",
            "iftool versions 7.44 and up allows arbitrary code execution when p",
            "arsing the malicious image"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22205",
        vendor: "GitLab",
        product: "Community and Enterprise Editions",
        cpe23: "cpe:2.3:a:gitlab:community_and_enterprise_editions:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "GitHub Community and Enterprise Editions that utilize the ability ",
            "to upload images through GitLab Workhorse are vulnerable to remote",
            " code execution. Workhorse passes image file extensions through Ex",
            "ifTool, which improperly validates the image files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22502",
        vendor: "Micro Focus",
        product: "Operation Bridge Reporter (OBR)",
        cpe23: concat!(
            "cpe:2.3:a:micro_focus:operation_bridge_reporter_obr:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Micro Focus Operation Bridge Report (OBR) contains an unspecified ",
            "vulnerability that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22506",
        vendor: "Micro Focus",
        product: "Micro Focus Access Manager",
        cpe23: "cpe:2.3:a:micro_focus:micro_focus_access_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Micro Focus Access Manager contains an information leakage vulnera",
            "bility resulting from a SAML service provider redirection issue wh",
            "en the Assertion Consumer Service URL is used."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22555",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains a heap out-of-bounds write vulnerability tha",
            "t could allow an attacker to gain privileges or cause a DoS (via h",
            "eap memory corruption) through user name space."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-22600",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains a flaw in the packet socket (AF_PACKET) impl",
            "ementation which could lead to incorrectly freeing memory. A local",
            " user could exploit this for denial-of-service (DoS) or possibly f",
            "or privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22681",
        vendor: "Rockwell",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:rockwell:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Rockwell products contain an insufficient protected crede",
            "ntials vulnerability. Studio 5000 Logix Designer software may allo",
            "w a key to be discovered. This key is used to verify Logix control",
            "lers are communicating with Rockwell Automation design software. I",
            "f successfully exploited, this vulnerability could allow"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-22893",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Pulse Connect Secure contains a use-after-free vulnerabilit",
            "y that allow a remote, unauthenticated attacker to execute code vi",
            "a license services."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22894",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Pulse Connect Secure Collaboration Suite contains a buffer ",
            "overflow vulnerabilities that allows a remote authenticated users ",
            "to execute code as the root user via maliciously crafted meeting r",
            "oom."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22899",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Pulse Connect Secure contains a command injection vulnerabi",
            "lity that allows remote authenticated users to perform remote code",
            " execution via Windows File Resource Profiles."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22900",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Pulse Connect Secure contains an unrestricted file upload v",
            "ulnerability that allows an authenticated administrator to perform",
            " a file write via a maliciously crafted archive upload in the admi",
            "nistrator web interface."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22941",
        vendor: "Citrix",
        product: "ShareFile",
        cpe23: "cpe:2.3:a:citrix:sharefile:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Improper Access Control in Citrix ShareFile storage zones controll",
            "er may allow an unauthenticated attacker to remotely compromise th",
            "e storage zones controller."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22986",
        vendor: "F5",
        product: "BIG-IP and BIG-IQ Centralized Management",
        cpe23: concat!(
            "cpe:2.3:a:f5:big-ip_and_big-iq_centralized_management:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "F5 BIG-IP and BIG-IQ Centralized Management contain a remote code ",
            "execution vulnerability in the iControl REST interface that allows",
            " unauthenticated attackers with network access to execute system c",
            "ommands, create or delete files, and disable services."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-22991",
        vendor: "F5",
        product: "BIG-IP Traffic Management Microkernel",
        cpe23: "cpe:2.3:a:f5:big-ip_traffic_management_microkernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Traffic Management Microkernel of BIG-IP ASM Risk Engine has a",
            " buffer overflow vulnerability, leading to a bypassing of URL-base",
            "d access controls."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-23017",
        vendor: "f5",
        product: "nginx",
        cpe23: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        cvss_x10: 77, severity: "High", cwe: "CWE-193",
        is_kev: false, ransomware: "Unknown", epss_permille: 745,
        summary: "Outdated nginx (< 1.20.1) DNS Resolver Memory Advisory",
        remediation: "nginx serverini 1.24+ / 1.26+ barqaror versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-23337",
        vendor: "npm",
        product: "lodash",
        cpe23: "cpe:2.3:a:npm:lodash:*:*:*:*:*:*:*:*",
        cvss_x10: 72, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm lodash vulnerability advisory",
        remediation: "Upgrade lodash to >= 4.17.21",
    },
    KevCveRecord {
        cve_id: "CVE-2021-23358",
        vendor: "npm",
        product: "underscore",
        cpe23: "cpe:2.3:a:npm:underscore:*:*:*:*:*:*:*:*",
        cvss_x10: 72, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm underscore vulnerability advisory",
        remediation: "Upgrade underscore to >= 1.13.6",
    },
    KevCveRecord {
        cve_id: "CVE-2021-23369",
        vendor: "npm",
        product: "handlebars",
        cpe23: "cpe:2.3:a:npm:handlebars:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm handlebars vulnerability advisory",
        remediation: "Upgrade handlebars to >= 4.7.7",
    },
    KevCveRecord {
        cve_id: "CVE-2021-23758",
        vendor: "Ajax.NET Professional",
        product: "Ajax.NET Professional",
        cpe23: concat!(
            "cpe:2.3:a:ajax.net_professional:ajax.net_professional:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ajax.NET Professional (AjaxPro) contains a deserialization of untr",
            "usted data vulnerability that could allow for remote code executio",
            "n via arbitrary .NET classes. The impacted product(s) could be end",
            "-of-life (EoL) and/or end-of-service (EoS). Users are advised to d",
            "iscontinue use and/or transition to a supported version."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-23874",
        vendor: "McAfee",
        product: "McAfee Total Protection (MTP)",
        cpe23: "cpe:2.3:a:mcafee:mcafee_total_protection_mtp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "McAfee Total Protection (MTP) contains an improper privilege manag",
            "ement vulnerability that allows a local user to gain elevated priv",
            "ileges and execute code, bypassing MTP self-defense."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25296",
        vendor: "Nagios",
        product: "Nagios XI",
        cpe23: "cpe:2.3:a:nagios:nagios_xi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Nagios XI contains a vulnerability which can lead to OS command in",
            "jection on the Nagios XI server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25297",
        vendor: "Nagios",
        product: "Nagios XI",
        cpe23: "cpe:2.3:a:nagios:nagios_xi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Nagios XI contains a vulnerability which can lead to OS command in",
            "jection on the Nagios XI server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25298",
        vendor: "Nagios",
        product: "Nagios XI",
        cpe23: "cpe:2.3:a:nagios:nagios_xi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Nagios XI contains a vulnerability which can lead to OS command in",
            "jection on the Nagios XI server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25337",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an improper access control vulnerab",
            "ility in clipboard service which allows untrusted applications to ",
            "read or write arbitrary files. This vulnerability was chained with",
            " CVE-2021-25369 and CVE-2021-25370."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25369",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices using Mali GPU contains an improper access ",
            "control vulnerability in sec_log file. Exploitation of the vulnera",
            "bility exposes sensitive kernel information to the userspace. This",
            " vulnerability was chained with CVE-2021-25337 and CVE-2021-25370."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25370",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices using Mali GPU contain an incorrect impleme",
            "ntation handling file descriptor in dpu driver. This incorrect imp",
            "lementation results in memory corruption, leading to kernel panic.",
            " This vulnerability was chained with CVE-2021-25337 and CVE-2021-2",
            "5369."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-25371",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an unspecified vulnerability within",
            " DSP driver that allows attackers to load ELF libraries inside DSP",
            "."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-25372",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an improper boundary check vulnerab",
            "ility within DSP driver that allows for out-of-bounds memory acces",
            "s."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-25394",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain a race condition vulnerability with",
            "in the MFC charger driver that leads to a use-after-free allowing ",
            "for a write given a radio privilege is compromised."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-25395",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain a race condition vulnerability with",
            "in the MFC charger driver that leads to a use-after-free allowing ",
            "for a write given a radio privilege is compromised."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-25487",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an out-of-bounds read vulnerability",
            " within the modem interface driver due to a lack of boundary check",
            "ing of a buffer in set_skb_priv(), leading to remote code executio",
            "n by dereference of an invalid function pointer."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-25489",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an improper input validation vulner",
            "ability within the modem interface driver that results in a format",
            " string bug leading to kernel panic."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-26084",
        vendor: "Atlassian",
        product: "Confluence Server and Data Center",
        cpe23: concat!(
            "cpe:2.3:a:atlassian:confluence_server_and_data_center:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Atlassian Confluence Server and Data Server contain an Object-Grap",
            "h Navigation Language (OGNL) injection vulnerability that may allo",
            "w an unauthenticated attacker to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-26085",
        vendor: "Atlassian",
        product: "Confluence Server",
        cpe23: "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Affected versions of Atlassian Confluence Server allow remote atta",
            "ckers to view restricted resources via a pre-authorization arbitra",
            "ry file read vulnerability in the /s/ endpoint."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-26086",
        vendor: "Atlassian",
        product: "Jira Server and Data Center",
        cpe23: "cpe:2.3:a:atlassian:jira_server_and_data_center:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Atlassian Jira Server and Data Center contain a path traversal vul",
            "nerability that allows a remote attacker to read particular files ",
            "in the /WEB-INF/web.xml endpoint."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-26411",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Internet Explorer contains an unspecified vulnerability ",
            "that allows for memory corruption."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-26828",
        vendor: "OpenPLC",
        product: "ScadaBR",
        cpe23: "cpe:2.3:a:openplc:scadabr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OpenPLC ScadaBR contains an unrestricted upload of file with dange",
            "rous type vulnerability that allows remote authenticated users to ",
            "upload and execute arbitrary JSP files via view_edit.shtm."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-26829",
        vendor: "OpenPLC",
        product: "ScadaBR",
        cpe23: "cpe:2.3:a:openplc:scadabr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OpenPLC ScadaBR contains a cross-site scripting vulnerability via ",
            "system_settings.shtm."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-26855",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for remote code execution. This vulnerability is part of",
            " the ProxyLogon exploit chain."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-26857",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for remote code execution. This vulnerability is part of",
            " the ProxyLogon exploit chain."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-26858",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for remote code execution. This vulnerability is part of",
            " the ProxyLogon exploit chain."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27059",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains an unspecified vulnerability that allows",
            " for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27065",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for remote code execution. This vulnerability is part of",
            " the ProxyLogon exploit chain."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27085",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains an unspecified vulnerability ",
            "that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27101",
        vendor: "Accellion",
        product: "FTA",
        cpe23: "cpe:2.3:a:accellion:fta:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Accellion FTA contains a SQL injection vulnerability exploited via",
            " a crafted host header in a request to document_root.html."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27102",
        vendor: "Accellion",
        product: "FTA",
        cpe23: "cpe:2.3:a:accellion:fta:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Accellion FTA contains an OS command injection vulnerability explo",
            "ited via a local web service call."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27103",
        vendor: "Accellion",
        product: "FTA",
        cpe23: "cpe:2.3:a:accellion:fta:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Accellion FTA contains a server-side request forgery (SSRF) vulner",
            "ability exploited via a crafted POST request to wmProgressstat.htm",
            "l."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27104",
        vendor: "Accellion",
        product: "FTA",
        cpe23: "cpe:2.3:a:accellion:fta:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Accellion FTA contains an OS command injection vulnerability explo",
            "ited via a crafted POST request to various admin endpoints."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27137",
        vendor: "DD-WRT",
        product: "DD-WRT",
        cpe23: "cpe:2.3:a:dd-wrt:dd-wrt:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "DD-WRT contains a stack-based buffer overflow vulnerability that c",
            "ould allow an unauthenticated attacker to overflow an internal buf",
            "fer used by UPnP and trigger a code execution vulnerability."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-27561",
        vendor: "Yealink",
        product: "Device Management",
        cpe23: "cpe:2.3:a:yealink:device_management:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Yealink Device Management contains a server-side request forgery (",
            "SSRF) vulnerability that allows for unauthenticated remote code ex",
            "ecution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27562",
        vendor: "Arm",
        product: "Trusted Firmware",
        cpe23: "cpe:2.3:a:arm:trusted_firmware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Trusted Firmware contains an out-of-bounds write vulnerability",
            " allowing the non-secure (NS) world to trigger a system halt, over",
            "write secure data, or print out secure data when calling secure fu",
            "nctions under the non-secure processing environment (NSPE) handler",
            " mode. This vulnerability affects Yealink Device Managem"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27852",
        vendor: "Checkbox",
        product: "Checkbox Survey",
        cpe23: "cpe:2.3:a:checkbox:checkbox_survey:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Deserialization of Untrusted Data vulnerability in CheckboxWeb.dll",
            " of Checkbox Survey allows an unauthenticated remote attacker to e",
            "xecute arbitrary code."
        ),
        remediation: concat!(
            "Versions 6 and earlier for this product are end-of-life and must b",
            "e removed from agency networks. Versions 7 and later are not consi",
            "dered vulnerable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-27860",
        vendor: "FatPipe",
        product: "WARP, IPVPN, and MPVPN software",
        cpe23: "cpe:2.3:a:fatpipe:warp_ipvpn_and_mpvpn_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the web management interface of FatPipe WARP, I",
            "PVPN, and MPVPN software allows a remote, unauthenticated attacker",
            " to upload a file to any location on the filesystem."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27876",
        vendor: "Veritas",
        product: "Backup Exec Agent",
        cpe23: "cpe:2.3:a:veritas:backup_exec_agent:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Veritas Backup Exec (BE) Agent contains a file access vulnerabilit",
            "y that could allow an attacker to specially craft input parameters",
            " on a data management protocol command to access files on the BE A",
            "gent machine."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27877",
        vendor: "Veritas",
        product: "Backup Exec Agent",
        cpe23: "cpe:2.3:a:veritas:backup_exec_agent:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Veritas Backup Exec (BE) Agent contains an improper authentication",
            " vulnerability that could allow an attacker unauthorized access to",
            " the BE Agent via SHA authentication scheme."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-27878",
        vendor: "Veritas",
        product: "Backup Exec Agent",
        cpe23: "cpe:2.3:a:veritas:backup_exec_agent:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Veritas Backup Exec (BE) Agent contains a command execution vulner",
            "ability that could allow an attacker to use a data management prot",
            "ocol command to execute a command on the BE Agent machine."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-28310",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Win32k contains an unspecified vulnerability tha",
            "t allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-28550",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contains a use-after-free vulnerability t",
            "hat could allow an unauthenticated attacker to achieve code execut",
            "ion in the context of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-28663",
        vendor: "Arm",
        product: "Mali Graphics Processing Unit (GPU)",
        cpe23: "cpe:2.3:a:arm:mali_graphics_processing_unit_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali Graphics Processing Unit (GPU) kernel driver contains a u",
            "se-after-free vulnerability that may allow a non-privileged user t",
            "o make improper operations on GPU memory to gain root privilege, a",
            "nd/or disclose information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-28664",
        vendor: "Arm",
        product: "Mali Graphics Processing Unit (GPU)",
        cpe23: "cpe:2.3:a:arm:mali_graphics_processing_unit_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali Graphics Processing Unit (GPU) kernel driver contains an ",
            "unspecified vulnerability that may allow a non-privileged user to ",
            "gain write access to read-only memory, gain root privilege, corrup",
            "t memory, and modify the memory of other processes."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-28799",
        vendor: "QNAP",
        product: "Network Attached Storage (NAS)",
        cpe23: "cpe:2.3:a:qnap:network_attached_storage_nas:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "QNAP NAS running HBS 3 contains an improper authorization vulnerab",
            "ility which can allow remote attackers to log in to a device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-29256",
        vendor: "Arm",
        product: "Mali Graphics Processing Unit (GPU)",
        cpe23: "cpe:2.3:a:arm:mali_graphics_processing_unit_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali GPU Kernel Driver contains a use-after-free vulnerability",
            " that may allow a non-privileged user to gain root privilege and/o",
            "r disclose information."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-30116",
        vendor: "Kaseya",
        product: "Virtual System/Server Administrator (VSA)",
        cpe23: concat!(
            "cpe:2.3:a:kaseya:virtual_system_server_administrator_vsa:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Kaseya Virtual System/Server Administrator (VSA) contains an infor",
            "mation disclosure vulnerability allowing an attacker to obtain the",
            " sessionId that can be used to execute further attacks against the",
            " system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30533",
        vendor: "Google",
        product: "Chromium PopupBlocker",
        cpe23: "cpe:2.3:a:google:chromium_popupblocker:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium PopupBlocker contains an insufficient policy enfor",
            "cement vulnerability that allows a remote attacker to bypass navig",
            "ation restrictions via a crafted iframe. This vulnerability could ",
            "affect multiple web browsers that utilize Chromium, including, but",
            " not limited to, Google Chrome, Microsoft Edge, and Oper"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30551",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30554",
        vendor: "Google",
        product: "Chromium WebGL",
        cpe23: "cpe:2.3:a:google:chromium_webgl:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium WebGL contains a use-after-free vulnerability that",
            " allows a remote attacker to potentially exploit heap corruption v",
            "ia a crafted HTML page. This vulnerability could affect multiple w",
            "eb browsers that utilize Chromium, including, but not limited to, ",
            "Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30563",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30632",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an out-of-bounds write vulnerab",
            "ility that allows a remote attacker to potentially exploit heap co",
            "rruption via a crafted HTML page. This vulnerability could affect ",
            "multiple web browsers that utilize Chromium, including, but not li",
            "mited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30633",
        vendor: "Google",
        product: "Chromium Indexed DB API",
        cpe23: "cpe:2.3:a:google:chromium_indexed_db_api:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Indexed DB API contains a use-after-free vulnerabi",
            "lity that allows a remote attacker, who has compromised the render",
            "er process, to potentially perform a sandbox escape via a crafted ",
            "HTML page. This vulnerability could affect multiple web browsers t",
            "hat utilize Chromium, including, but not limited to, Goo"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30657",
        vendor: "Apple",
        product: "macOS",
        cpe23: "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple macOS contains an unspecified logic issue in System Preferen",
            "ces that may allow a malicious application to bypass Gatekeeper ch",
            "ecks."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30661",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit Storage",
            " contain a use-after-free vulnerability that leads to code executi",
            "on when processing maliciously crafted web content. This vulnerabi",
            "lity could impact HTML parsers that use WebKit, including but not ",
            "limited to Apple Safari and non-Apple products which rel"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30663",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and Safari WebKit contain an integ",
            "er overflow vulnerability that leads to code execution when proces",
            "sing maliciously crafted web content. This vulnerability could imp",
            "act HTML parsers that use WebKit, including but not limited to App",
            "le Safari and non-Apple products which rely on WebKit fo"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30665",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, watchOS, and tvOS WebKit contain a memor",
            "y corruption vulnerability that leads to code execution when proce",
            "ssing maliciously crafted web content. This vulnerability could im",
            "pact HTML parsers that use WebKit, including but not limited to Ap",
            "ple Safari and non-Apple products which rely on WebKit f"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30666",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS WebKit contains a buffer-overflow vulnerability that lea",
            "ds to code execution when processing maliciously crafted web conte",
            "nt. This vulnerability could impact HTML parsers that use WebKit, ",
            "including but not limited to Apple Safari and non-Apple products w",
            "hich rely on WebKit for HTML processing."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30713",
        vendor: "Apple",
        product: "macOS",
        cpe23: "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple macOS Transparency, Consent, and Control (TCC) contains an u",
            "nspecified permissions issue which may allow a malicious applicati",
            "on to bypass privacy preferences."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30761",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS WebKit contains a memory corruption vulnerability that l",
            "eads to code execution when processing maliciously crafted web con",
            "tent. This vulnerability could impact HTML parsers that use WebKit",
            ", including but not limited to Apple Safari and non-Apple products",
            " which rely on WebKit for HTML processing."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30762",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS WebKit contains a use-after-free vulnerability that lead",
            "s to code execution when processing maliciously crafted web conten",
            "t. This vulnerability could impact HTML parsers that use WebKit, i",
            "ncluding but not limited to Apple Safari and non-Apple products wh",
            "ich rely on WebKit for HTML processing."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30807",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS IOMobileFrameBuffer contain ",
            "a memory corruption vulnerability which may allow an application t",
            "o execute code with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30858",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS WebKit contain a use-after-free vulne",
            "rability that leads to code execution when processing maliciously ",
            "crafted web content. This vulnerability could impact HTML parsers ",
            "that use WebKit, including but not limited to Apple Safari and non",
            "-Apple products which rely on WebKit for HTML processing"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30860",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS CoreGraphics contain an inte",
            "ger overflow vulnerability which may allow code execution when pro",
            "cessing a maliciously crafted PDF. The vulnerability is also known",
            " under the moniker of FORCEDENTRY."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30869",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS contain a type confusion vulnerabilit",
            "y in the XNU which may allow a malicious application to execute co",
            "de with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30883",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, watchOS, and tvOS contain a memory corruption vu",
            "lnerability that could allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30900",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple GPU drivers, included in iOS, iPadOS, and macOS, contain an ",
            "out-of-bounds write vulnerability that may allow a malicious appli",
            "cation to execute code with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-30952",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple tvOS, macOS, Safari, iPadOS and watchOS contain an integer o",
            "verflow or wraparound vulnerability due to the processing of malic",
            "iously crafted web content that may lead to arbitrary code executi",
            "on."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-30983",
        vendor: "Apple",
        product: "iOS and iPadOS",
        cpe23: "cpe:2.3:a:apple:ios_and_ipados:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and iPadOS contain a buffer overflow vulnerability that ",
            "could allow an application to execute code with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31010",
        vendor: "Apple",
        product: "iOS, macOS, watchOS",
        cpe23: "cpe:2.3:a:apple:ios_macos_watchos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "In affected versions of Apple iOS, macOS, and watchOS, a sandboxed",
            " process may be able to circumvent sandbox restrictions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31166",
        vendor: "Microsoft",
        product: "HTTP Protocol Stack",
        cpe23: "cpe:2.3:a:microsoft:http_protocol_stack:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft HTTP Protocol Stack contains a vulnerability in http.sys",
            " that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31196",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Exchange Server contains an information disclosure vulne",
            "rability that allows for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-31199",
        vendor: "Microsoft",
        product: "Enhanced Cryptographic Provider",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:enhanced_cryptographic_provider:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Enhanced Cryptographic Provider contains an unspecified ",
            "vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31201",
        vendor: "Microsoft",
        product: "Enhanced Cryptographic Provider",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:enhanced_cryptographic_provider:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Enhanced Cryptographic Provider contains an unspecified ",
            "vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31207",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for security feature bypass."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3129",
        vendor: "Laravel",
        product: "Ignition",
        cpe23: "cpe:2.3:a:laravel:ignition:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Laravel Ignition contains a file upload vulnerability that allows ",
            "unauthenticated remote attackers to execute malicious code due to ",
            "insecure usage of file_get_contents() and file_put_contents()."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-31402",
        vendor: "pub",
        product: "dio",
        cpe23: "cpe:2.3:a:pub:dio:*:*:*:*:*:*:*:*",
        cvss_x10: 74, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Pub dio vulnerability advisory",
        remediation: "Upgrade dio to >= 5.3.2",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3156",
        vendor: "Sudo",
        product: "Sudo",
        cpe23: "cpe:2.3:a:sudo:sudo:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sudo contains an off-by-one error that can result in a heap-based ",
            "buffer overflow, which allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31755",
        vendor: "Tenda",
        product: "AC11 Router",
        cpe23: "cpe:2.3:a:tenda:ac11_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Tenda AC11 devices contain a stack buffer overflow vulnerability i",
            "n /goform/setmac which allows attackers to execute code via a craf",
            "ted post request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31955",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Kernel contains an unspecified vulnerability tha",
            "t allows for information disclosure. Successful exploitation allow",
            "s attackers to read the contents of kernel memory from a user-mode",
            " process."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31956",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows New Technology File System (NTFS) contains an un",
            "specified vulnerability that allows attackers to escalate privileg",
            "es via a specially crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-31979",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows kernel contains an unspecified vulnerability tha",
            "t allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3199",
        vendor: "ONLYOFFICE",
        product: "Docs",
        cpe23: "cpe:2.3:a:onlyoffice:docs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ONLYOFFICE Docs contains a path traversal vulnerability that can o",
            "ccur when JWT is used, via a /.. sequence in an image upload param",
            "eter and could allow for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-32030",
        vendor: "ASUS",
        product: "Routers",
        cpe23: "cpe:2.3:a:asus:routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ASUS Lyra Mini and ASUS GT-AC2900 devices contain an improper auth",
            "entication vulnerability that allows an attacker to gain unauthori",
            "zed access to the administrative interface. The impacted products ",
            "could be end-of-life (EoL) and/or end-of-service (EoS). Users shou",
            "ld discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-32648",
        vendor: "October CMS",
        product: "October CMS",
        cpe23: "cpe:2.3:a:october_cms:october_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "In affected versions of the october/system package an attacker can",
            " request an account password reset and then gain access to the acc",
            "ount using a specially crafted request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-33044",
        vendor: "Dahua",
        product: "IP Camera Firmware",
        cpe23: "cpe:2.3:a:dahua:ip_camera_firmware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dahua IP cameras and related products contain an authentication by",
            "pass vulnerability when the NetKeyboard type argument is specified",
            " by the client during authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-33045",
        vendor: "Dahua",
        product: "IP Camera Firmware",
        cpe23: "cpe:2.3:a:dahua:ip_camera_firmware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dahua IP cameras and related products contain an authentication by",
            "pass vulnerability when the loopback device is specified by the cl",
            "ient during authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-33739",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Desktop Window Manager (DWM) Core Library contains an un",
            "specified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-33742",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows MSHTML Platform contains an unspecified vulnerab",
            "ility that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-33766",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Exchange Server contains an information disclosure vulne",
            "rability which can allow an unauthenticated attacker to steal emai",
            "l traffic from target."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-33771",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows kernel contains an unspecified vulnerability tha",
            "t allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34432",
        vendor: "vernemq",
        product: "vernemq",
        cpe23: "cpe:2.3:a:vernemq:vernemq:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated VerneMQ (< 1.12.0) MQTT Broker ACL Advisory",
        remediation: "VerneMQ brokerini 1.13+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34448",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Scripting Engine contains an unspecified vulnera",
            "bility that allows for memory corruption."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34473",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34484",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows User Profile Service contains an unspecified vul",
            "nerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34486",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Event Tracing contains an unspecified vulnerabil",
            "ity which can allow for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34523",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-34527",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Print Spooler contains an unspecified vulnerabil",
            "ity due to the Windows Print Spooler service improperly performing",
            " privileged file operations. Successful exploitation allows an att",
            "acker to perform remote code execution with SYSTEM privileges. The",
            " vulnerability is also known under the moniker of PrintN"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3493",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The overlayfs stacking file system in Linux kernel does not proper",
            "ly validate the application of file capabilities against user name",
            "spaces, which could lead to privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-35211",
        vendor: "SolarWinds",
        product: "Serv-U",
        cpe23: "cpe:2.3:a:solarwinds:serv-u:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SolarWinds Serv-U contains an unspecified memory escape vulnerabil",
            "ity which can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-35247",
        vendor: "SolarWinds",
        product: "Serv-U",
        cpe23: "cpe:2.3:a:solarwinds:serv-u:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Serv-U versions 15.2.5 and earlier contain an improper ",
            "input validation vulnerability that allows attackers to build and ",
            "send queries without sanitization."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-35394",
        vendor: "Realtek",
        product: "Jungle Software Development Kit (SDK)",
        cpe23: concat!(
            "cpe:2.3:a:realtek:jungle_software_development_kit_sdk:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "RealTek Jungle SDK contains multiple memory corruption vulnerabili",
            "ties which can allow an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-35395",
        vendor: "Realtek",
        product: "AP-Router SDK",
        cpe23: "cpe:2.3:a:realtek:ap-router_sdk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Realtek AP-Router SDK HTTP web server boa contains a buffer overfl",
            "ow vulnerability due to unsafe copies of some overly long paramete",
            "rs submitted in the form that lead to denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-35464",
        vendor: "ForgeRock",
        product: "Access Management (AM)",
        cpe23: "cpe:2.3:a:forgerock:access_management_am:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "ForgeRock Access Management (AM) Core Server allows an attacker wh",
            "o sends a specially crafted HTTP request to one of three endpoints",
            " (/ccversion/Version, /ccversion/Masthead, or /ccversion/ButtonFra",
            "me) to execute code in the context of the current user (unless For",
            "geRock AM is running as root user, which the vendor does"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-35587",
        vendor: "Oracle",
        product: "Fusion Middleware",
        cpe23: "cpe:2.3:a:oracle:fusion_middleware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Fusion Middleware Access Manager allows an unauthenticated ",
            "attacker with network access via HTTP to takeover the Access Manag",
            "er product."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3560",
        vendor: "Red Hat",
        product: "Polkit",
        cpe23: "cpe:2.3:a:red_hat:polkit:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Red Hat Polkit contains an incorrect authorization vulnerability t",
            "hrough the bypassing of credential checks for D-Bus requests, allo",
            "wing for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3603",
        vendor: "packagist",
        product: "phpmailer/phpmailer",
        cpe23: "cpe:2.3:a:packagist:phpmailer_phpmailer:*:*:*:*:*:*:*:*",
        cvss_x10: 70, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Packagist phpmailer/phpmailer vulnerability advisory",
        remediation: "Upgrade phpmailer/phpmailer to >= 6.5.0",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3618",
        vendor: "vsftpd_project",
        product: "vsftpd",
        cpe23: "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
        cvss_x10: 53, severity: "Medium", cwe: "CWE-295",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated vsFTPd (< 3.0.4) ALPACA TLS Enforcement Advisory",
        remediation: concat!(
            "vsFTPd xizmatini 3.0.5+ versiyasiga yangilang yoki SFTP/SSH ga o't",
            "ing."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-36260",
        vendor: "Hikvision",
        product: "Security cameras web server",
        cpe23: "cpe:2.3:a:hikvision:security_cameras_web_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A command injection vulnerability in the web server of some Hikvis",
            "ion product. Due to the insufficient input validation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-36380",
        vendor: "Sunhillo",
        product: "SureLine",
        cpe23: "cpe:2.3:a:sunhillo:sureline:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sunhillo SureLine contains an OS command injection vulnerability t",
            "hat allows an attacker to cause a denial-of-service or utilize the",
            " device for persistence on the network via shell metacharacters in",
            " ipAddr or dnsAddr in /cgi/networkDiag.cgi."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-36741",
        vendor: "Trend Micro",
        product: "Apex One, Apex One as a Service, and Worry-Free Business Security",
        cpe23: concat!(
            "cpe:2.3:a:trend_micro:apex_one_apex_one_as_a_service_and_worry-fre",
            "e_business_security:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One, Apex One as a Service, and Worry-Free Busine",
            "ss Security contain an improper input validation vulnerability tha",
            "t allows a remote attacker to upload files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-36742",
        vendor: "Trend Micro",
        product: "Apex One, Apex One as a Service, and Worry-Free Business Security",
        cpe23: concat!(
            "cpe:2.3:a:trend_micro:apex_one_apex_one_as_a_service_and_worry-fre",
            "e_business_security:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One, Apex One as a Service, and Worry-Free Busine",
            "ss Security contain an improper input validation vulnerability tha",
            "t allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-36934",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "If a Volume Shadow Copy (VSS) shadow copy of the system drive is a",
            "vailable, users can read the SAM file which would allow any user t",
            "o escalate privileges to SYSTEM level."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-36942",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Local Security Authority (LSA) contains a spoofi",
            "ng vulnerability allowing an unauthenticated attacker to call a me",
            "thod on the LSARPC interface and coerce the domain controller to a",
            "uthenticate against another server using NTLM."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-36948",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Update Medic Service contains an unspecified vul",
            "nerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-36955",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) driver contains an",
            " unspecified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3711",
        vendor: "openssl",
        product: "openssl",
        cpe23: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-120",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "OpenSSL 1.1.1 (< 1.1.1l) SM2 Decryption Buffer Overflow Advisory",
        remediation: "OpenSSL 1.1.1 tarmog'ini OpenSSL 3.x LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-37415",
        vendor: "Zoho",
        product: "ManageEngine ServiceDesk Plus (SDP)",
        cpe23: "cpe:2.3:a:zoho:manageengine_servicedesk_plus_sdp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho ManageEngine ServiceDesk Plus before 11302 is vulnerable to a",
            "uthentication bypass that allows a few REST-API URLs without authe",
            "ntication"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-37973",
        vendor: "Google",
        product: "Chromium Portals",
        cpe23: "cpe:2.3:a:google:chromium_portals:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Portals contains a use-after-free vulnerability th",
            "at allows a remote attacker, who has compromised the renderer proc",
            "ess, to potentially perform a sandbox escape via a crafted HTML pa",
            "ge. This vulnerability affects web browsers that utilize Chromium,",
            " including Google Chrome and Microsoft Edge."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-37975",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a use-after-free vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-37976",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium contains an information disclosure vulnerability w",
            "ithin the core memory component that allows a remote attacker to o",
            "btain potentially sensitive information from process memory via a ",
            "crafted HTML page. This vulnerability could affect multiple web br",
            "owsers that utilize Chromium, including, but not limited"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38000",
        vendor: "Google",
        product: "Chromium Intents",
        cpe23: "cpe:2.3:a:google:chromium_intents:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Intents contains an improper input validation vuln",
            "erability that allows a remote attacker to arbitrarily browser to ",
            "a malicious URL via a crafted HTML page. This vulnerability could ",
            "affect multiple web browsers that utilize Chromium, including, but",
            " not limited to, Google Chrome, Microsoft Edge, and Oper"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38003",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine has a bug in JSON.stringify, where the i",
            "nternal TheHole value can leak to script code, causing memory corr",
            "uption. This vulnerability could affect multiple web browsers that",
            " utilize Chromium, including, but not limited to, Google Chrome, M",
            "icrosoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38163",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver contains a vulnerability that allows unrestricted fi",
            "le upload."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38406",
        vendor: "Delta Electronics",
        product: "DOPSoft 2",
        cpe23: "cpe:2.3:a:delta_electronics:dopsoft_2:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Delta Electronics DOPSoft 2 lacks proper validation of user-suppli",
            "ed data when parsing specific project files (improper input valida",
            "tion) resulting in an out-of-bounds write that allows for code exe",
            "cution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-38645",
        vendor: "Microsoft",
        product: "Open Management Infrastructure (OMI)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:open_management_infrastructure_omi:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Open Management Infrastructure (OMI) within Azure VM Man",
            "agement Extensions contains an unspecified vulnerability that allo",
            "ws for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38646",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Office Access Connectivity Engine contains an unspecifie",
            "d vulnerability which can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38647",
        vendor: "Microsoft",
        product: "Open Management Infrastructure (OMI)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:open_management_infrastructure_omi:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Open Management Infrastructure (OMI) within Azure VM Man",
            "agement Extensions contains an unspecified vulnerability allowing ",
            "remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38648",
        vendor: "Microsoft",
        product: "Open Management Infrastructure (OMI)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:open_management_infrastructure_omi:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Open Management Infrastructure (OMI) within Azure VM Man",
            "agement Extensions contains an unspecified vulnerability allowing ",
            "privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-38649",
        vendor: "Microsoft",
        product: "Open Management Infrastructure (OMI)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:open_management_infrastructure_omi:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Open Management Infrastructure (OMI) within Azure VM Man",
            "agement Extensions contains an unspecified vulnerability allowing ",
            "privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-3879",
        vendor: "corosync",
        product: "corosync",
        cpe23: "cpe:2.3:a:corosync:corosync:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-120",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Corosync (< 3.1.8) Packet Validation Advisory",
        remediation: "Corosync klaster paketini 3.1.8+ ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-39144",
        vendor: "XStream",
        product: "XStream",
        cpe23: "cpe:2.3:a:xstream:xstream:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "XStream contains a remote code execution vulnerability that allows",
            " an attacker to manipulate the processed input stream and replace ",
            "or inject objects that result in the execution of a local command ",
            "on the server. This vulnerability can affect multiple products, in",
            "cluding but not limited to VMware Cloud Foundation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-39226",
        vendor: "Grafana Labs",
        product: "Grafana",
        cpe23: "cpe:2.3:a:grafana_labs:grafana:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Grafana contains an authentication bypass vulnerability that allow",
            "s authenticated and unauthenticated users to view and delete all s",
            "napshot data, potentially resulting in complete snapshot data loss",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-39793",
        vendor: "Google",
        product: "Pixel",
        cpe23: "cpe:2.3:a:google:pixel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Pixel contains a possible out-of-bounds write due to a logi",
            "c error in the code that could lead to local escalation of privile",
            "ge."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-39935",
        vendor: "GitLab",
        product: "Community and Enterprise Editions",
        cpe23: "cpe:2.3:a:gitlab:community_and_enterprise_editions:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GitLab Community and Enterprise Editions contain a server-side req",
            "uest forgery vulnerability which could allow unauthorized external",
            " users to perform Server Side Requests via the CI Lint API."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-4034",
        vendor: "Red Hat",
        product: "Polkit",
        cpe23: "cpe:2.3:a:red_hat:polkit:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Red Hat polkit pkexec utility contains an out-of-bounds read a",
            "nd write vulnerability that allows for privilege escalation with a",
            "dministrative rights."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-40407",
        vendor: "Reolink",
        product: "RLC-410W IP Camera",
        cpe23: "cpe:2.3:a:reolink:rlc-410w_ip_camera:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Reolink RLC-410W IP cameras contain an authenticated OS command in",
            "jection vulnerability in the device network settings functionality",
            "."
        ),
        remediation: concat!(
            "The impacted product could be end-of-life (EoL) and/or end-of-serv",
            "ice (EoS). Users should discontinue product utilization if a curre",
            "nt mitigation is unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-40438",
        vendor: "Apache",
        product: "Apache",
        cpe23: "cpe:2.3:a:apache:apache:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A crafted request uri-path can cause mod_proxy to forward the requ",
            "est to an origin server choosen by the remote user. This issue aff",
            "ects Apache HTTP Server 2.4.48 and earlier."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-40444",
        vendor: "Microsoft",
        product: "MSHTML",
        cpe23: "cpe:2.3:a:microsoft:mshtml:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft MSHTML contains a unspecified vulnerability that allows ",
            "for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-40449",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unspecified vulnerability allows for an authenticated user to esca",
            "late privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-40450",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability that allows",
            " for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-40539",
        vendor: "Zoho",
        product: "ManageEngine",
        cpe23: "cpe:2.3:a:zoho:manageengine:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Zoho ManageEngine ADSelfService Plus contains an authentication by",
            "pass vulnerability affecting the REST API URLs which allow for rem",
            "ote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-40655",
        vendor: "D-Link",
        product: "DIR-605 Router",
        cpe23: "cpe:2.3:a:d-link:dir-605_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-605 routers contain an information disclosure vulnerabi",
            "lity that allows attackers to obtain a username and password by fo",
            "rging a post request to the /getcfg.php page."
        ),
        remediation: concat!(
            "This vulnerability affects legacy D-Link products. All associated ",
            "hardware revisions have reached their end-of-life (EOL) or end-of-",
            "service (EOS) life cycle and should be retired and replaced per ve",
            "ndor instructions."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-40870",
        vendor: "Aviatrix",
        product: "Aviatrix Controller",
        cpe23: "cpe:2.3:a:aviatrix:aviatrix_controller:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unrestricted upload of a file with a dangerous type is possible, w",
            "hich allows an unauthenticated user to execute arbitrary code via ",
            "directory traversal."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-4102",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a use-after-free vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-41277",
        vendor: "Metabase",
        product: "Metabase",
        cpe23: "cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Metabase contains a local file inclusion vulnerability in the cust",
            "om map support in the API to read GeoJSON formatted data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-41357",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability that allows",
            " for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-41379",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Installer contains an unspecified vulnerability ",
            "that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-41617",
        vendor: "openbsd",
        product: "openssh",
        cpe23: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        cvss_x10: 64, severity: "Medium", cwe: "CWE-203",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Legacy OpenSSH (< 8.5) Cryptographic & Privilege Escalation Adviso",
            "ry"
        ),
        remediation: "OpenSSH xizmatini zamonaviy LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-41773",
        vendor: "apache",
        product: "apache",
        cpe23: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 974,
        summary: "Apache HTTP Server 2.4.49–2.4.50 Path Normalization Advisory",
        remediation: concat!(
            "Apache HTTP Server paketini 2.4.62+ versiyasiga yangilang va katal",
            "og ruxsatlarini tekshiring."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-42013",
        vendor: "apache",
        product: "apache",
        cpe23: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 973,
        summary: "Apache HTTP Server 2.4.49–2.4.50 Path Normalization Advisory",
        remediation: concat!(
            "Apache HTTP Server paketini 2.4.62+ versiyasiga yangilang va katal",
            "og ruxsatlarini tekshiring."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-42237",
        vendor: "Sitecore",
        product: "XP",
        cpe23: "cpe:2.3:a:sitecore:xp:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Sitcore XP contains an insecure deserialization vulnerability whic",
            "h can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-42258",
        vendor: "BQE",
        product: "BillQuick Web Suite",
        cpe23: "cpe:2.3:a:bqe:billquick_web_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "BQE BillQuick Web Suite contains an SQL injection vulnerability wh",
            "en accessing the username parameter that may allow for unauthentic",
            "ated, remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-42278",
        vendor: "Microsoft",
        product: "Active Directory",
        cpe23: "cpe:2.3:a:microsoft:active_directory:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Active Directory Domain Services contains an unspecified",
            " vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-42287",
        vendor: "Microsoft",
        product: "Active Directory",
        cpe23: "cpe:2.3:a:microsoft:active_directory:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Active Directory Domain Services contains an unspecified",
            " vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-42292",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A security feature bypass vulnerability in Microsoft Excel would a",
            "llow a local user to perform arbitrary code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-42321",
        vendor: "Microsoft",
        product: "Exchange",
        cpe23: "cpe:2.3:a:microsoft:exchange:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An authenticated attacker could leverage improper validation in cm",
            "dlet arguments within Microsoft Exchange and perform remote code e",
            "xecution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-43226",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System Driver contains a privile",
            "ge escalation vulnerability that could allow a local, privileged a",
            "ttacker to bypass certain security mechanisms."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-43798",
        vendor: "grafana",
        product: "grafana",
        cpe23: "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Grafana (8.0.0–8.3.0) Plugin Asset Path Traversal Advisory",
        remediation: "Grafana xizmatini 10.4+ yoki 11.x LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-43890",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows AppX Installer contains a spoofing vulnerability",
            " which has a high impacts to confidentiality, integrity, and avail",
            "ability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-44026",
        vendor: "Roundcube",
        product: "Roundcube Webmail",
        cpe23: "cpe:2.3:a:roundcube:roundcube_webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail is vulnerable to SQL injection via search or sea",
            "rch_params."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-44077",
        vendor: "Zoho",
        product: "ManageEngine ServiceDesk Plus (SDP) / SupportCenter Plus",
        cpe23: concat!(
            "cpe:2.3:a:zoho:manageengine_servicedesk_plus_sdp_supportcenter_plu",
            "s:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus ",
            "MSP before 10530, and SupportCenter Plus before 11014 are vulnerab",
            "le to unauthenticated remote code execution"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-44168",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiOS \"execute restore src-vis\" downloads code withou",
            "t integrity checking, allowing an attacker to arbitrarily download",
            " files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-44207",
        vendor: "Acclaim Systems",
        product: "USAHERDS",
        cpe23: "cpe:2.3:a:acclaim_systems:usaherds:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Acclaim Systems USAHERDS contains a hard-coded credentials vulnera",
            "bility that could allow an attacker to achieve remote code executi",
            "on on the system that runs the application. The MachineKey must be",
            " obtained via a separate vulnerability or other channel."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable. Please contact the produ",
            "ct developer for support and vulnerability mitigation."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-44225",
        vendor: "keepalived",
        product: "keepalived",
        cpe23: "cpe:2.3:a:keepalived:keepalived:*:*:*:*:*:*:*:*",
        cvss_x10: 78, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Keepalived (< 2.2.8) D-Bus Access Control Advisory",
        remediation: "Keepalived ni 2.2.8+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-44228",
        vendor: "Apache",
        product: "Log4j2",
        cpe23: "cpe:2.3:a:apache:log4j2:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 975,
        summary: concat!(
            "Apache Log4j2 contains a vulnerability where JNDI features do not ",
            "protect against attacker-controlled JNDI-related endpoints, allowi",
            "ng for remote code execution."
        ),
        remediation: concat!(
            "For all affected software assets for which updates exist, the only",
            " acceptable remediation actions are: 1) Apply updates; OR 2) remov",
            "e affected assets from agency networks. Temporary mitigations usin",
            "g one of the measures provided at https://www.cisa.gov/uscert/"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-44515",
        vendor: "Zoho",
        product: "Desktop Central",
        cpe23: "cpe:2.3:a:zoho:desktop_central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho Desktop Central contains an authentication bypass vulnerabili",
            "ty that could allow an attacker to execute arbitrary code in the D",
            "esktop Central MSP server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-44529",
        vendor: "Ivanti",
        product: "Endpoint Manager Cloud Service Appliance (EPM CSA)",
        cpe23: concat!(
            "cpe:2.3:a:ivanti:endpoint_manager_cloud_service_appliance_epm_csa:",
            "*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Endpoint Manager Cloud Service Appliance (EPM CSA) contains",
            " a code injection vulnerability that allows an unauthenticated use",
            "r to execute malicious code with limited permissions (nobody)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-44906",
        vendor: "npm",
        product: "minimist",
        cpe23: "cpe:2.3:a:npm:minimist:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm minimist vulnerability advisory",
        remediation: "Upgrade minimist to >= 1.2.6",
    },
    KevCveRecord {
        cve_id: "CVE-2021-45046",
        vendor: "Apache",
        product: "Log4j2",
        cpe23: "cpe:2.3:a:apache:log4j2:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Apache Log4j2 contains a deserialization of untrusted data vulnera",
            "bility due to the incomplete fix of CVE-2021-44228, where the Thre",
            "ad Context Lookup Pattern is vulnerable to remote code execution i",
            "n certain non-default configurations."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2021-45382",
        vendor: "D-Link",
        product: "Multiple Routers",
        cpe23: "cpe:2.3:a:d-link:multiple_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in all series H/W rev",
            "isions routers via the DDNS function in ncc2 binary file."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2021-46743",
        vendor: "packagist",
        product: "firebase/php-jwt",
        cpe23: "cpe:2.3:a:packagist:firebase_php-jwt:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Packagist firebase/php-jwt vulnerability advisory",
        remediation: "Upgrade firebase/php-jwt to >= 6.0.0",
    },
    KevCveRecord {
        cve_id: "CVE-2022-0028",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A Palo Alto Networks PAN-OS URL filtering policy misconfiguration ",
            "could allow a network-based attacker to conduct reflected and ampl",
            "ified TCP denial-of-service (RDoS) attacks."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-0185",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel contains a heap-based buffer overflow vulnerability i",
            "n the legacy_parse_param function in the Filesystem Context functi",
            "onality. This allows an attacker to open a filesystem that does no",
            "t support the Filesystem Context API and ultimately escalate privi",
            "leges."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-0492",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an improper authentication vulnerability whi",
            "ch could allow for privilege escalation via the cgroups v1 release",
            "_agent feature."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-0543",
        vendor: "redis",
        product: "redis",
        cpe23: "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Outdated Redis Server (< 6.2.7) Security Advisory",
        remediation: concat!(
            "Redis serverini 7.2+ versiyasiga yangilang, ACL/parol yoqing va ta",
            "shqi tarmoqdan yoping."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-0609",
        vendor: "Google",
        product: "Chromium Animation",
        cpe23: "cpe:2.3:a:google:chromium_animation:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Animation contains a use-after-free vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-0847",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel contains an improper initialization vulnerability whe",
            "re an unprivileged local user could escalate their privileges on t",
            "he system. This vulnerability has the moniker of \"Dirty Pipe.\""
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-0995",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an out-of-bounds memory write vulnerability ",
            "which could allow a local user to gain privileged access or cause ",
            "a denial of service on the system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-1040",
        vendor: "Sophos",
        product: "Firewall",
        cpe23: "cpe:2.3:a:sophos:firewall:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An authentication bypass vulnerability in User Portal and Webadmin",
            " of Sophos Firewall allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-1096",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-1364",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-1388",
        vendor: "F5",
        product: "BIG-IP",
        cpe23: "cpe:2.3:a:f5:big-ip:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "F5 BIG-IP contains a missing authentication in critical function v",
            "ulnerability which can allow for remote code execution, creation o",
            "r deletion of files, or disabling services."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-1471",
        vendor: "maven",
        product: "org.yaml:snakeyaml",
        cpe23: "cpe:2.3:a:maven:org.yaml_snakeyaml:*:*:*:*:*:*:*:*",
        cvss_x10: 83, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Maven org.yaml:snakeyaml vulnerability advisory",
        remediation: "Upgrade org.yaml:snakeyaml to >= 2.0.0",
    },
    KevCveRecord {
        cve_id: "CVE-2022-20699",
        vendor: "Cisco",
        product: "Small Business RV160, RV260, RV340, and RV345 Series Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv160_rv260_rv340_and_rv345_series_",
            "routers:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in Cisco Small Business RV160, RV260, RV340, and R",
            "V345 Series Routers could allow an attacker to do any of the follo",
            "wing: Execute arbitrary code elevate privileges, execute arbitrary",
            " commands, bypass authentication and authorization protections, fe",
            "tch and run unsigned software, or cause a denial of serv"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-20700",
        vendor: "Cisco",
        product: "Small Business RV160, RV260, RV340, and RV345 Series Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv160_rv260_rv340_and_rv345_series_",
            "routers:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in Cisco Small Business RV160, RV260, RV340, and R",
            "V345 Series Routers could allow an attacker to do any of the follo",
            "wing: Execute arbitrary code elevate privileges, execute arbitrary",
            " commands, bypass authentication and authorization protections, fe",
            "tch and run unsigned software, or cause a denial of serv"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-20701",
        vendor: "Cisco",
        product: "Small Business RV160, RV260, RV340, and RV345 Series Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv160_rv260_rv340_and_rv345_series_",
            "routers:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in Cisco Small Business RV160, RV260, RV340, and R",
            "V345 Series Routers could allow an attacker to do any of the follo",
            "wing: Execute arbitrary code elevate privileges, execute arbitrary",
            " commands, bypass authentication and authorization protections, fe",
            "tch and run unsigned software, or cause a denial of serv"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-20703",
        vendor: "Cisco",
        product: "Small Business RV160, RV260, RV340, and RV345 Series Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv160_rv260_rv340_and_rv345_series_",
            "routers:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in Cisco Small Business RV160, RV260, RV340, and R",
            "V345 Series Routers could allow an attacker to do any of the follo",
            "wing: Execute arbitrary code elevate privileges, execute arbitrary",
            " commands, bypass authentication and authorization protections, fe",
            "tch and run unsigned software, or cause a denial of serv"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-20708",
        vendor: "Cisco",
        product: "Small Business RV160, RV260, RV340, and RV345 Series Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv160_rv260_rv340_and_rv345_series_",
            "routers:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in Cisco Small Business RV160, RV260, RV340, and R",
            "V345 Series Routers could allow an attacker to do any of the follo",
            "wing: Execute arbitrary code elevate privileges, execute arbitrary",
            " commands, bypass authentication and authorization protections, fe",
            "tch and run unsigned software, or cause a denial of serv"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-20775",
        vendor: "Cisco",
        product: "SD-WAN",
        cpe23: "cpe:2.3:a:cisco:sd-wan:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco SD-WAN CLI contains a path traversal vulnerability that coul",
            "d allow an authenticated local attacker to gain elevated privilege",
            "s via improper access controls on commands within the application ",
            "CLI. A successful exploit could allow the attacker to execute arbi",
            "trary commands as the root user."
        ),
        remediation: concat!(
            "Please adhere to CISA’s guidelines to assess exposure and mitigate",
            " risks associated with Cisco SD-WAN devices as outlines in CISA’s ",
            "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s “",
            "Hunt & Hardening Guidance for Cisco SD-WAN Devices (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-20821",
        vendor: "Cisco",
        product: "IOS XR",
        cpe23: "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XR software health check opens TCP port 6379 by default ",
            "on activation. An attacker can connect to the Redis instance on th",
            "e open port and allow access to the Redis instance that is running",
            " within the NOSi container."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-21445",
        vendor: "Oracle",
        product: "ADF Faces",
        cpe23: "cpe:2.3:a:oracle:adf_faces:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle ADF Faces library, included with Oracle JDeveloper Distribu",
            "tion, contains a deserialization of untrusted data vulnerability l",
            "eading to unauthenticated remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-21587",
        vendor: "Oracle",
        product: "E-Business Suite",
        cpe23: "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Oracle E-Business Suite contains an unspecified vulnerability that",
            " allows an unauthenticated attacker with network access via HTTP t",
            "o compromise Oracle Web Applications Desktop Integrator."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-21882",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability that allows",
            " for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-21919",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows User Profile Service contains an unspecified vul",
            "nerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-21971",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Runtime contains an unspecified vulnerability th",
            "at allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-21999",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Print Spooler contains an unspecified vulnerabil",
            "ity which can allow for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22047",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows CSRSS contains an unspecified vulnerability that",
            " allows for privilege escalation to SYSTEM privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22071",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a use-after-free vulnerability ",
            "when process shell memory is freed using IOCTL munmap call and pro",
            "cess initialization is in progress."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-22265",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung devices with selected Exynos chipsets contain a use-after-",
            "free vulnerability that allows malicious memory write and code exe",
            "cution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-22536",
        vendor: "SAP",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:sap:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver Application Server ABAP, SAP NetWeaver Application S",
            "erver Java, ABAP Platform, SAP Content Server and SAP Web Dispatch",
            "er allow HTTP request smuggling. An unauthenticated attacker can p",
            "repend a victim's request with arbitrary data, allowing for functi",
            "on execution impersonating the victim or poisoning inter"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22587",
        vendor: "Apple",
        product: "iOS and macOS",
        cpe23: "cpe:2.3:a:apple:ios_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple IOMobileFrameBuffer contains a memory corruption vulnerabili",
            "ty which can allow a malicious application to execute arbitrary co",
            "de with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22620",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS WebKit contain a use-after-free vulne",
            "rability that leads to code execution when processing maliciously ",
            "crafted web content. This vulnerability could impact HTML parsers ",
            "that use WebKit, including but not limited to Apple Safari and non",
            "-Apple products which rely on WebKit for HTML processing"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22674",
        vendor: "Apple",
        product: "macOS",
        cpe23: "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "macOS Monterey contains an out-of-bounds read vulnerability that c",
            "ould allow an application to read kernel memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22675",
        vendor: "Apple",
        product: "macOS",
        cpe23: "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "macOS Monterey contains an out-of-bounds write vulnerability that ",
            "could allow an application to execute arbitrary code with kernel p",
            "rivileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22706",
        vendor: "Arm",
        product: "Mali Graphics Processing Unit (GPU)",
        cpe23: "cpe:2.3:a:arm:mali_graphics_processing_unit_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali GPU Kernel Driver contains an unspecified vulnerability t",
            "hat allows a non-privileged user to achieve write access to read-o",
            "nly memory pages."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22718",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Print Spooler contains an unspecified vulnerabil",
            "ity which allow for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-2294",
        vendor: "WebRTC",
        product: "WebRTC",
        cpe23: "cpe:2.3:a:webrtc:webrtc:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "WebRTC, an open-source project providing web browsers with real-ti",
            "me communication, contains a heap buffer overflow vulnerability th",
            "at allows an attacker to perform shellcode execution. This vulnera",
            "bility impacts web browsers using WebRTC including but not limited",
            " to Google Chrome."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22947",
        vendor: "VMware",
        product: "Spring Cloud Gateway",
        cpe23: "cpe:2.3:a:vmware:spring_cloud_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Spring Cloud Gateway applications are vulnerable to a code injecti",
            "on attack when the Gateway Actuator endpoint is enabled, exposed a",
            "nd unsecured."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22948",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware vCenter Server contains an incorrect default file permissio",
            "ns vulnerability that allows a remote, privileged attacker to gain",
            " access to sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-22954",
        vendor: "VMware",
        product: "Workspace ONE Access and Identity Manager",
        cpe23: concat!(
            "cpe:2.3:a:vmware:workspace_one_access_and_identity_manager:*:*:*:*",
            ":*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware Workspace ONE Access and Identity Manager allow for remote ",
            "code execution due to server-side template injection."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22960",
        vendor: "VMware",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:vmware:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware Workspace ONE Access, Identity Manager and vRealize Automat",
            "ion contain a privilege escalation vulnerability due to improper p",
            "ermissions in support scripts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22963",
        vendor: "VMware Tanzu",
        product: "Spring Cloud",
        cpe23: "cpe:2.3:a:vmware_tanzu:spring_cloud:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "When using routing functionality in VMware Tanzu's Spring Cloud Fu",
            "nction, it is possible for a user to provide a specially crafted S",
            "pEL as a routing-expression that may result in remote code executi",
            "on and access to local resources."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-22965",
        vendor: "vmware",
        product: "spring_framework",
        cpe23: "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 972,
        summary: "Spring Framework (< 5.3.18) Data Binding Security Advisory",
        remediation: concat!(
            "Spring Framework kutubxonasini 5.3.34+ yoki 6.1+ versiyasiga yangi",
            "lang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-2309",
        vendor: "pypi",
        product: "lxml",
        cpe23: "cpe:2.3:a:pypi:lxml:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI lxml vulnerability advisory",
        remediation: "Upgrade lxml to >= 4.9.1",
    },
    KevCveRecord {
        cve_id: "CVE-2022-23131",
        vendor: "Zabbix",
        product: "Frontend",
        cpe23: "cpe:2.3:a:zabbix:frontend:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unsafe client-side session storage leading to authentication bypas",
            "s/instance takeover via Zabbix Frontend with configured SAML."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-23134",
        vendor: "Zabbix",
        product: "Frontend",
        cpe23: "cpe:2.3:a:zabbix:frontend:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Malicious actors can pass step checks and potentially change the c",
            "onfiguration of Zabbix Frontend."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-23176",
        vendor: "WatchGuard",
        product: "Firebox and XTM",
        cpe23: "cpe:2.3:a:watchguard:firebox_and_xtm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WatchGuard Firebox and XTM appliances allow a remote attacker with",
            " unprivileged credentials to access the system with a privileged m",
            "anagement session via exposed management access."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-23227",
        vendor: "NUUO",
        product: "NVRmini2 Devices",
        cpe23: "cpe:2.3:a:nuuo:nvrmini2_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "NUUO NVRmini2 devices contain a missing authentication vulnerabili",
            "ty that allows an unauthenticated attacker to upload an encrypted ",
            "TAR archive, which can be abused to add arbitrary users."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-23529",
        vendor: "npm",
        product: "jsonwebtoken",
        cpe23: "cpe:2.3:a:npm:jsonwebtoken:*:*:*:*:*:*:*:*",
        cvss_x10: 76, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm jsonwebtoken vulnerability advisory",
        remediation: "Upgrade jsonwebtoken to >= 9.0.0",
    },
    KevCveRecord {
        cve_id: "CVE-2022-23748",
        vendor: "Audinate",
        product: "Dante Discovery",
        cpe23: "cpe:2.3:a:audinate:dante_discovery:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dante Discovery contains a process control vulnerability in mDNSRe",
            "sponder.exe that all allows for a DLL sideloading attack. A local ",
            "attacker can leverage this vulnerability in the Dante Application ",
            "Library to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-24086",
        vendor: "Adobe",
        product: "Commerce and Magento Open Source",
        cpe23: "cpe:2.3:a:adobe:commerce_and_magento_open_source:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Commerce and Magento Open Source contain an improper input v",
            "alidation vulnerability which can allow for arbitrary code executi",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-24112",
        vendor: "Apache",
        product: "APISIX",
        cpe23: "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache APISIX contains an authentication bypass vulnerability that",
            " allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-24521",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) Driver contains an",
            " unspecified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-24682",
        vendor: "Synacor",
        product: "Zimbra Collaborate Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaborate_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-79",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting (XSS) vulnerability in the Calendar feature that allows an ",
            "attacker to execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-24706",
        vendor: "Apache",
        product: "CouchDB",
        cpe23: "cpe:2.3:a:apache:couchdb:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache CouchDB contains an insecure default initialization of reso",
            "urce vulnerability which can allow an attacker to escalate to admi",
            "nistrative privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-24816",
        vendor: "OSGeo",
        product: "JAI-EXT",
        cpe23: "cpe:2.3:a:osgeo:jai-ext:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OSGeo GeoServer JAI-EXT contains a code injection vulnerability th",
            "at, when programs use jt-jiffle and allow Jiffle script to be prov",
            "ided via network request, could allow remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-24990",
        vendor: "TerraMaster",
        product: "TerraMaster OS",
        cpe23: "cpe:2.3:a:terramaster:terramaster_os:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "TerraMaster OS contains a remote command execution vulnerability t",
            "hat allows an unauthenticated user to execute commands on the targ",
            "et endpoint."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-25845",
        vendor: "maven",
        product: "com.alibaba:fastjson",
        cpe23: "cpe:2.3:a:maven:com.alibaba_fastjson:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Maven com.alibaba:fastjson vulnerability advisory",
        remediation: "Upgrade com.alibaba:fastjson to >= 1.2.83",
    },
    KevCveRecord {
        cve_id: "CVE-2022-2586",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains a use-after-free vulnerability in the nft_ob",
            "ject, allowing local attackers to escalate privileges."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-25869",
        vendor: "npm",
        product: "angular",
        cpe23: "cpe:2.3:a:npm:angular:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm angular vulnerability advisory",
        remediation: "Upgrade angular to >= 1.8.0",
    },
    KevCveRecord {
        cve_id: "CVE-2022-25883",
        vendor: "npm",
        product: "semver",
        cpe23: "cpe:2.3:a:npm:semver:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm semver vulnerability advisory",
        remediation: "Upgrade semver to >= 7.5.2",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26134",
        vendor: "Atlassian",
        product: "Confluence Server/Data Center",
        cpe23: "cpe:2.3:a:atlassian:confluence_server_data_center:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Atlassian Confluence Server and Data Center contain a remote code ",
            "execution vulnerability that allows for an unauthenticated attacke",
            "r to perform remote code execution."
        ),
        remediation: concat!(
            "Immediately block all internet traffic to and from affected produc",
            "ts AND apply the update per vendor instructions [https://confluenc",
            "e.atlassian.com/doc/confluence-security-advisory-2022-06-02-113037",
            "7146.html] OR remove the affected products by the due date on "
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-26138",
        vendor: "Atlassian",
        product: "Confluence",
        cpe23: "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Atlassian Questions For Confluence App has hard-coded credentials,",
            " exposing the username and password in plaintext. A remote unauthe",
            "nticated attacker can use these credentials to log into Confluence",
            " and access all content accessible to users in the confluence-user",
            "s group."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26143",
        vendor: "Mitel",
        product: "MiCollab, MiVoice Business Express",
        cpe23: "cpe:2.3:a:mitel:micollab_mivoice_business_express:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability has been identified in MiCollab and MiVoice Busine",
            "ss Express that may allow a malicious actor to gain unauthorized a",
            "ccess to sensitive information and services, cause performance deg",
            "radations or a denial of service condition on the affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26258",
        vendor: "D-Link",
        product: "DIR-820L",
        cpe23: "cpe:2.3:a:d-link:dir-820l:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-820L contains an unspecified vulnerability in Device Na",
            "me parameter in /lan.asp which allows for remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-26318",
        vendor: "WatchGuard",
        product: "Firebox and XTM Appliances",
        cpe23: "cpe:2.3:a:watchguard:firebox_and_xtm_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "On WatchGuard Firebox and XTM appliances, an unauthenticated user ",
            "can execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26352",
        vendor: "dotCMS",
        product: "dotCMS",
        cpe23: "cpe:2.3:a:dotcms:dotcms:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "dotCMS ContentResource API contains an unrestricted upload of file",
            " with a dangerous type vulnerability that allows for directory tra",
            "versal, in which the file is saved outside of the intended storage",
            " location. Exploitation allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26485",
        vendor: "Mozilla",
        product: "Firefox",
        cpe23: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox contains a use-after-free vulnerability in XSLT pa",
            "rameter processing which can be exploited to perform arbitrary cod",
            "e execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26486",
        vendor: "Mozilla",
        product: "Firefox",
        cpe23: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox contains a use-after-free vulnerability in WebGPU ",
            "IPC Framework which can be exploited to perform arbitrary code exe",
            "cution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26500",
        vendor: "Veeam",
        product: "Backup & Replication",
        cpe23: "cpe:2.3:a:veeam:backup_replication:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Veeam Distribution Service in the Backup & Replication applica",
            "tion allows unauthenticated users to access internal API functions",
            ". A remote attacker can send input to the internal API which may l",
            "ead to uploading and executing of malicious code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26501",
        vendor: "Veeam",
        product: "Backup & Replication",
        cpe23: "cpe:2.3:a:veeam:backup_replication:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Veeam Distribution Service in the Backup & Replication applica",
            "tion allows unauthenticated users to access internal API functions",
            ". A remote attacker can send input to the internal API which may l",
            "ead to uploading and executing of malicious code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26871",
        vendor: "Trend Micro",
        product: "Apex Central",
        cpe23: "cpe:2.3:a:trend_micro:apex_central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An arbitrary file upload vulnerability in Trend Micro Apex Central",
            " could allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26904",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows User Profile Service contains an unspecified vul",
            "nerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26923",
        vendor: "Microsoft",
        product: "Active Directory",
        cpe23: "cpe:2.3:a:microsoft:active_directory:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An authenticated user could manipulate attributes on computer acco",
            "unts they own or manage, and acquire a certificate from Active Dir",
            "ectory Certificate Services that would allow for privilege escalat",
            "ion to SYSTEM."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-26925",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Local Security Authority (LSA) contains a spoofi",
            "ng vulnerability where an attacker can coerce the domain controlle",
            "r to authenticate to the attacker using NTLM."
        ),
        remediation: concat!(
            "Apply remediation actions outlined in CISA guidance [https://www.c",
            "isa.gov/guidance-applying-june-microsoft-patch]."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-27518",
        vendor: "Citrix",
        product: "Application Delivery Controller (ADC) and Gateway",
        cpe23: concat!(
            "cpe:2.3:a:citrix:application_delivery_controller_adc_and_gateway:*",
            ":*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix Application Delivery Controller (ADC) and Gateway, when con",
            "figured with SAML SP or IdP configuration, contain an authenticati",
            "on bypass vulnerability that allows an attacker to execute code as",
            " administrator."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-27593",
        vendor: "QNAP",
        product: "Photo Station",
        cpe23: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Certain QNAP NAS running Photo Station with internet exposure cont",
            "ain an externally controlled reference to a resource vulnerability",
            " which can allow an attacker to modify system files. This vulnerab",
            "ility was observed being utilized in a Deadbolt ransomware campaig",
            "n."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-27924",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) allows an attacker to inj",
            "ect memcache commands into a targeted instance which causes an ove",
            "rwrite of arbitrary cached entries."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-27925",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains flaw in the mbox",
            "import functionality, allowing an authenticated attacker to upload",
            " arbitrary files to perform remote code execution. This vulnerabil",
            "ity was chained with CVE-2022-37042 which allows for unauthenticat",
            "ed remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-27926",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting vulnerability by allowing an endpoint URL to accept paramet",
            "ers without sanitizing."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-2856",
        vendor: "Google",
        product: "Chromium Intents",
        cpe23: "cpe:2.3:a:google:chromium_intents:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Intents contains an insufficient validation of unt",
            "rusted input vulnerability that allows a remote attacker to browse",
            " to a malicious website via a crafted HTML page. This vulnerabilit",
            "y could affect multiple web browsers that utilize Chromium, includ",
            "ing, but not limited to, Google Chrome, Microsoft Edge, "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-28810",
        vendor: "Zoho",
        product: "ManageEngine",
        cpe23: "cpe:2.3:a:zoho:manageengine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho ManageEngine ADSelfService Plus contains an unspecified vulne",
            "rability allowing for remote code execution when performing a pass",
            "word change or reset."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-29078",
        vendor: "npm",
        product: "ejs",
        cpe23: "cpe:2.3:a:npm:ejs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm ejs vulnerability advisory",
        remediation: "Upgrade ejs to >= 3.1.10",
    },
    KevCveRecord {
        cve_id: "CVE-2022-29181",
        vendor: "rubygems",
        product: "nokogiri",
        cpe23: "cpe:2.3:a:rubygems:nokogiri:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "RubyGems nokogiri vulnerability advisory",
        remediation: "Upgrade nokogiri to >= 1.13.9",
    },
    KevCveRecord {
        cve_id: "CVE-2022-29303",
        vendor: "SolarView",
        product: "Compact",
        cpe23: "cpe:2.3:a:solarview:compact:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarView Compact contains a command injection vulnerability due t",
            "o improper validation of input values on the send test mail consol",
            "e of the product's web server."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-29464",
        vendor: "wso2",
        product: "wso2_apim",
        cpe23: "cpe:2.3:a:wso2:api_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "WSO2 API Manager (< 4.2.0) Endpoint Upload Advisory",
        remediation: "WSO2 API Manager ni 4.2.0+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-29499",
        vendor: "Mitel",
        product: "MiVoice Connect",
        cpe23: "cpe:2.3:a:mitel:mivoice_connect:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Service Appliance component in Mitel MiVoice Connect allows re",
            "mote code execution due to incorrect data validation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-30190",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A remote code execution vulnerability exists when MSDT is called u",
            "sing the URL protocol from a calling application such as Word. An ",
            "attacker who successfully exploits this vulnerability can run code",
            " with the privileges of the calling application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-30333",
        vendor: "RARLAB",
        product: "UnRAR",
        cpe23: "cpe:2.3:a:rarlab:unrar:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "RARLAB UnRAR on Linux and UNIX contains a directory traversal vuln",
            "erability, allowing an attacker to write to files during an extrac",
            "t (unpack) operation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-3038",
        vendor: "Google",
        product: "Chromium Network Service",
        cpe23: "cpe:2.3:a:google:chromium_network_service:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Network Service contains a use-after-free vulnerab",
            "ility that allows a remote attacker to potentially exploit heap co",
            "rruption via a crafted HTML page. This vulnerability could affect ",
            "multiple web browsers that utilize Chromium, including, but not li",
            "mited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-30525",
        vendor: "Zyxel",
        product: "Multiple Firewalls",
        cpe23: "cpe:2.3:a:zyxel:multiple_firewalls:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A command injection vulnerability in the CGI program of some Zyxel",
            " firewall versions could allow an attacker to modify specific file",
            "s and then execute some OS commands on a vulnerable device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-30550",
        vendor: "dovecot",
        product: "dovecot",
        cpe23: "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-269",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Dovecot (< 2.3.21) Privilege Separation Advisory",
        remediation: "Dovecot IMAP/POP3 serverini 2.3.21+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-3075",
        vendor: "Google",
        product: "Chromium Mojo",
        cpe23: "cpe:2.3:a:google:chromium_mojo:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Mojo contains an insufficient data validation vuln",
            "erability that allows a remote attacker, who has compromised the r",
            "enderer process, to potentially perform a sandbox escape via a cra",
            "fted HTML page. This vulnerability could affect multiple web brows",
            "ers that utilize Chromium, including, but not limited to"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-31090",
        vendor: "packagist",
        product: "guzzlehttp/guzzle",
        cpe23: "cpe:2.3:a:packagist:guzzlehttp_guzzle:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Packagist guzzlehttp/guzzle vulnerability advisory",
        remediation: "Upgrade guzzlehttp/guzzle to >= 7.4.5",
    },
    KevCveRecord {
        cve_id: "CVE-2022-31129",
        vendor: "npm",
        product: "moment",
        cpe23: "cpe:2.3:a:npm:moment:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm moment vulnerability advisory",
        remediation: "Upgrade moment to >= 2.29.4",
    },
    KevCveRecord {
        cve_id: "CVE-2022-31199",
        vendor: "Netwrix",
        product: "Auditor",
        cpe23: "cpe:2.3:a:netwrix:auditor:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Netwrix Auditor User Activity Video Recording component contains a",
            "n insecure objection deserialization vulnerability that allows an ",
            "unauthenticated, remote attacker to execute code as the NT AUTHORI",
            "TY\\SYSTEM user. Successful exploitation requires that the attacke",
            "r is able to reach port 9004/TCP, which is commonly block"
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-3236",
        vendor: "Sophos",
        product: "Firewall",
        cpe23: "cpe:2.3:a:sophos:firewall:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A code injection vulnerability in the User Portal and Webadmin of ",
            "Sophos Firewall allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-32893",
        vendor: "Apple",
        product: "iOS and macOS",
        cpe23: "cpe:2.3:a:apple:ios_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and macOS contain an out-of-bounds write vulnerability t",
            "hat could allow for remote code execution when processing maliciou",
            "s crafted web content."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-32894",
        vendor: "Apple",
        product: "iOS and macOS",
        cpe23: "cpe:2.3:a:apple:ios_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and macOS contain an out-of-bounds write vulnerability t",
            "hat could allow an application to execute code with kernel privile",
            "ges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-32917",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple kernel, which is included in iOS, iPadOS, and macOS, contain",
            "s an unspecified vulnerability where an application may be able to",
            " execute code with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-33891",
        vendor: "Apache",
        product: "Spark",
        cpe23: "cpe:2.3:a:apache:spark:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Spark contains a command injection vulnerability via Spark ",
            "User Interface (UI) when Access Control Lists (ACLs) are enabled."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-34713",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists when Microsoft Window",
            "s MSDT is called using the URL protocol from a calling application",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-35405",
        vendor: "Zoho",
        product: "ManageEngine",
        cpe23: "cpe:2.3:a:zoho:manageengine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho ManageEngine PAM360, Password Manager Pro, and Access Manager",
            " Plus contain an unspecified vulnerability that allows for remote ",
            "code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-35914",
        vendor: "Teclib",
        product: "GLPI",
        cpe23: "cpe:2.3:a:teclib:glpi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Teclib GLPI contains a remote code execution vulnerability in the ",
            "third-party library, htmlawed."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-3602",
        vendor: "openssl",
        product: "openssl",
        cpe23: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-120",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "OpenSSL 3.0.0–3.0.6 X.509 Buffer Overflow Advisory",
        remediation: concat!(
            "OpenSSL 3.0 kutubxonasini kamida 3.0.7+ (yoki 3.0.14+) versiyasiga",
            " yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-36537",
        vendor: "ZK Framework",
        product: "AuUploader",
        cpe23: "cpe:2.3:a:zk_framework:auuploader:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "ZK Framework AuUploader servlets contain an unspecified vulnerabil",
            "ity that could allow an attacker to retrieve the content of a file",
            " located in the web context. The ZK Framework is an open-source Ja",
            "va framework. This vulnerability can impact multiple products, inc",
            "luding but not limited to ConnectWise R1Soft Server Back"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-36804",
        vendor: "atlassian",
        product: "bitbucket",
        cpe23: "cpe:2.3:a:atlassian:bitbucket:*:*:*:*:*:*:*:*",
        cvss_x10: 99, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Atlassian Bitbucket Server (< 8.3.1) Git Archive Advisory",
        remediation: "Bitbucket Data Center ni 8.9.10+ LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-37042",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains an authenticatio",
            "n bypass vulnerability in MailboxImportServlet. This vulnerability",
            " was chained with CVE-2022-27925 which allows for unauthenticated ",
            "remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-37055",
        vendor: "D-Link",
        product: "Routers",
        cpe23: "cpe:2.3:a:d-link:routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link Routers contains a buffer overflow vulnerability that has a",
            " high impact on confidentiality, integrity, and availability. The ",
            "impacted products could be end-of-life (EoL) and/or end-of-service",
            " (EoS). Users should discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-3723",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-3786",
        vendor: "openssl",
        product: "openssl",
        cpe23: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-120",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "OpenSSL 3.0.0–3.0.6 X.509 Buffer Overflow Advisory",
        remediation: concat!(
            "OpenSSL 3.0 kutubxonasini kamida 3.0.7+ (yoki 3.0.14+) versiyasiga",
            " yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-37969",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) driver contains an",
            " unspecified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-38028",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Print Spooler service contains a privilege escal",
            "ation vulnerability. An attacker may modify a JavaScript constrain",
            "ts file and execute it with SYSTEM-level permissions."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-38181",
        vendor: "Arm",
        product: "Mali Graphics Processing Unit (GPU)",
        cpe23: "cpe:2.3:a:arm:mali_graphics_processing_unit_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali GPU Kernel Driver contains a use-after-free vulnerability",
            " that may allow a non-privileged user to gain root privilege and/o",
            "r disclose information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-39059",
        vendor: "pkp",
        product: "ojs",
        cpe23: "cpe:2.3:a:pkp:open_journal_systems:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Open Journal Systems (< 3.3.0) Security Advisory",
        remediation: concat!(
            "PKP Open Journal Systems (OJS) ni 3.3.0-16+ yoki 3.4+ versiyasiga ",
            "yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-39197",
        vendor: "Fortra",
        product: "Cobalt Strike",
        cpe23: "cpe:2.3:a:fortra:cobalt_strike:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortra Cobalt Strike contains a cross-site scripting (XSS) vulnera",
            "bility in Teamserver that would allow an attacker to set a malform",
            "ed username in the Beacon configuration, allowing them to execute ",
            "code remotely."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-40139",
        vendor: "Trend Micro",
        product: "Apex One and Apex One as a Service",
        cpe23: concat!(
            "cpe:2.3:a:trend_micro:apex_one_and_apex_one_as_a_service:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One and Apex One as a Service contain an improper",
            " validation of rollback mechanism components that could lead to re",
            "mote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-40684",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS, FortiProxy, and FortiSwitchManager contain an au",
            "thentication bypass vulnerability that could allow an unauthentica",
            "ted attacker to perform operations on the administrative interface",
            " via specially crafted HTTP or HTTPS requests."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-40765",
        vendor: "Mitel",
        product: "MiVoice Connect",
        cpe23: "cpe:2.3:a:mitel:mivoice_connect:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Mitel Edge Gateway component of MiVoice Connect allows an auth",
            "enticated attacker with internal network access to execute command",
            "s within the context of the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-40799",
        vendor: "D-Link",
        product: "DNR-322L",
        cpe23: "cpe:2.3:a:d-link:dnr-322l:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DNR-322L contains a download of code without integrity chec",
            "k vulnerability that could allow an authenticated attacker to exec",
            "ute OS level commands on the device. The impacted products could b",
            "e end-of-life (EoL) and/or end-of-service (EoS). Users should disc",
            "ontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-41033",
        vendor: "Microsoft",
        product: "Windows COM+ Event System Service",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:windows_com_event_system_service:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows COM+ Event System Service contains an unspecifie",
            "d vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41040",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server allows for server-side request forgery. ",
            "Dubbed \"ProxyNotShell,\" this vulnerability is chainable with CVE",
            "-2022-41082 which allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41049",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Mark of the Web (MOTW) contains a security featu",
            "re bypass vulnerability resulting in a limited loss of integrity a",
            "nd availability of security features."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41073",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Print Spooler contains an unspecified vulnerabil",
            "ity that allows an attacker to gain SYSTEM-level privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41080",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for privilege escalation. This vulnerability is chainabl",
            "e with CVE-2022-41082, which allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41082",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for authenticated remote code execution. Dubbed \"ProxyN",
            "otShell,\" this vulnerability is chainable with CVE-2022-41040 whi",
            "ch allows for the remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41091",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Mark of the Web (MOTW) contains a security featu",
            "re bypass vulnerability resulting in a limited loss of integrity a",
            "nd availability of security features."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41125",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Cryptographic Next Generation (CNG) Key Isolatio",
            "n Service contains an unspecified vulnerability that allows an att",
            "acker to gain SYSTEM-level privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41128",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains an unspecified vulnerability in the JSc",
            "ript9 scripting language which allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41223",
        vendor: "Mitel",
        product: "MiVoice Connect",
        cpe23: "cpe:2.3:a:mitel:mivoice_connect:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Director component in Mitel MiVoice Connect allows an authenti",
            "cated attacker with internal network access to execute code within",
            " the context of the application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41267",
        vendor: "packagist",
        product: "monolog/monolog",
        cpe23: "cpe:2.3:a:packagist:monolog_monolog:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Packagist monolog/monolog vulnerability advisory",
        remediation: "Upgrade monolog/monolog to >= 2.8.0",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41328",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiOS contains a path traversal vulnerability that may ",
            "allow a local privileged attacker to read and write files via craf",
            "ted CLI commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-4135",
        vendor: "Google",
        product: "Chromium GPU",
        cpe23: "cpe:2.3:a:google:chromium_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium GPU contains a heap buffer overflow vulnerability ",
            "that allows a remote attacker, who has compromised the renderer pr",
            "ocess, to potentially perform a sandbox escape via a crafted HTML ",
            "page. This vulnerability could affect multiple web browsers that u",
            "tilize Chromium, including, but not limited to, Google C"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-41352",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) allows an attacker to upl",
            "oad arbitrary files using cpio package to gain incorrect access to",
            " any other user accounts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42003",
        vendor: "maven",
        product: "com.fasterxml.jackson.core:jackson-databind",
        cpe23: concat!(
            "cpe:2.3:a:maven:com.fasterxml.jackson.core_jackson-databind:*:*:*:",
            "*:*:*:*:*"
        ),
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: concat!(
            "Maven com.fasterxml.jackson.core:jackson-databind vulnerability ad",
            "visory"
        ),
        remediation: "Upgrade com.fasterxml.jackson.core:jackson-databind to >= 2.13.4",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42475",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Multiple versions of Fortinet FortiOS SSL-VPN contain a heap-based",
            " buffer overflow vulnerability which can allow an unauthenticated,",
            " remote attacker to execute arbitrary code or commands via specifi",
            "cally crafted requests."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-4262",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42827",
        vendor: "Apple",
        product: "iOS and iPadOS",
        cpe23: "cpe:2.3:a:apple:ios_and_ipados:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and iPadOS kernel contain an out-of-bounds write vulnera",
            "bility which can allow an application to perform code execution wi",
            "th kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42856",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS contains a type confusion vulnerability when processing ",
            "maliciously crafted web content leading to code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42889",
        vendor: "maven",
        product: "org.apache.commons:commons-text",
        cpe23: "cpe:2.3:a:maven:org.apache.commons_commons-text:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Maven org.apache.commons:commons-text vulnerability advisory",
        remediation: "Upgrade org.apache.commons:commons-text to >= 1.10.0",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42948",
        vendor: "Fortra",
        product: "Cobalt Strike",
        cpe23: "cpe:2.3:a:fortra:cobalt_strike:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortra Cobalt Strike User Interface contains an unspecified vulner",
            "ability rooted in Java Swing that may allow remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-42969",
        vendor: "hex",
        product: "plug",
        cpe23: "cpe:2.3:a:hex:plug:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Hex plug vulnerability advisory",
        remediation: "Upgrade plug to >= 1.14.1",
    },
    KevCveRecord {
        cve_id: "CVE-2022-43769",
        vendor: "Hitachi Vantara",
        product: "Pentaho Business Analytics (BA) Server",
        cpe23: concat!(
            "cpe:2.3:a:hitachi_vantara:pentaho_business_analytics_ba_server:*:*",
            ":*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Hitachi Vantara Pentaho BA Server contains a special element injec",
            "tion vulnerability that allows an attacker to inject Spring templa",
            "tes into properties files, allowing for arbitrary command executio",
            "n."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-43939",
        vendor: "Hitachi Vantara",
        product: "Pentaho Business Analytics (BA) Server",
        cpe23: concat!(
            "cpe:2.3:a:hitachi_vantara:pentaho_business_analytics_ba_server:*:*",
            ":*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Hitachi Vantara Pentaho BA Server contains a use of non-canonical ",
            "URL paths for authorization decisions vulnerability that enables a",
            "n attacker to bypass authorization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-44698",
        vendor: "Microsoft",
        product: "Defender",
        cpe23: "cpe:2.3:a:microsoft:defender:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Defender SmartScreen contains a security feature bypass ",
            "vulnerability that could allow an attacker to evade Mark of the We",
            "b (MOTW) defenses via a specially crafted malicious file."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-44877",
        vendor: "CWP",
        product: "Control Web Panel",
        cpe23: "cpe:2.3:a:cwp:control_web_panel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "CWP Control Web Panel (formerly CentOS Web Panel) contains an OS c",
            "ommand injection vulnerability that allows remote attackers to exe",
            "cute commands via shell metacharacters in the login parameter."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-46169",
        vendor: "Cacti",
        product: "Cacti",
        cpe23: "cpe:2.3:a:cacti:cacti:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cacti contains a command injection vulnerability that allows an un",
            "authenticated user to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-47966",
        vendor: "Zoho",
        product: "ManageEngine",
        cpe23: "cpe:2.3:a:zoho:manageengine:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Multiple Zoho ManageEngine products contain an unauthenticated rem",
            "ote code execution vulnerability due to the usage of an outdated t",
            "hird-party dependency, Apache Santuario."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-47986",
        vendor: "IBM",
        product: "Aspera Faspex",
        cpe23: "cpe:2.3:a:ibm:aspera_faspex:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "IBM Aspera Faspex could allow a remote attacker to execute code on",
            " the system, caused by a YAML deserialization flaw."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2022-48503",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple macOS, iOS, tvOS, Safari, and watchOS contain an unspecified",
            " vulnerability in JavaScriptCore that when processing web content ",
            "may lead to arbitrary code execution. The impacted product could b",
            "e end-of-life (EoL) and/or end-of-service (EoS). Users should disc",
            "ontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2022-48618",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and watchOS contain a time-of-chec",
            "k/time-of-use (TOCTOU) memory corruption vulnerability that allows",
            " an attacker with read and write capabilities to bypass Pointer Au",
            "thentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-0266",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel contains a use-after-free vulnerability that allows f",
            "or privilege escalation to gain ring0 access from the system user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-0386",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an improper ownership management vulnerabili",
            "ty, where unauthorized access to the execution of the setuid file ",
            "with capabilities was found in the Linux kernel’s OverlayFS subsys",
            "tem in how a user copies a capable file from a nosuid mount into a",
            "nother mount. This uid mapping bug allows a local user t"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-0669",
        vendor: "Fortra",
        product: "GoAnywhere MFT",
        cpe23: "cpe:2.3:a:fortra:goanywhere_mft:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortra (formerly, HelpSystems) GoAnywhere MFT contains a pre-authe",
            "ntication remote code execution vulnerability in the License Respo",
            "nse Servlet due to deserializing an attacker-controlled object."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-0842",
        vendor: "npm",
        product: "xml2js",
        cpe23: "cpe:2.3:a:npm:xml2js:*:*:*:*:*:*:*:*",
        cvss_x10: 53, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm xml2js vulnerability advisory",
        remediation: "Upgrade xml2js to >= 0.5.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-1389",
        vendor: "TP-Link",
        product: "Archer AX21",
        cpe23: "cpe:2.3:a:tp-link:archer_ax21:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TP-Link Archer AX-21 contains a command injection vulnerability th",
            "at allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-1671",
        vendor: "Sophos",
        product: "Web Appliance",
        cpe23: "cpe:2.3:a:sophos:web_appliance:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sophos Web Appliance contains a command injection vulnerability in",
            " the warn-proceed handler that allows for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-1718",
        vendor: "1c-bitrix",
        product: "bitrix",
        cpe23: "cpe:2.3:a:1c-bitrix:site_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated 1C-Bitrix Site Manager (< 23.300.100) Security Advisory",
        remediation: "1C-Bitrix yadrosini eng oxirgi versiyaga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-20109",
        vendor: "Cisco",
        product: "IOS and IOS XE",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS and IOS XE contain an out-of-bounds write vulnerability ",
            "in the Group Encrypted Transport VPN (GET VPN) feature that could ",
            "allow an authenticated, remote attacker who has administrative con",
            "trol of either a group member or a key server to execute malicious",
            " code or cause a device to crash."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-20118",
        vendor: "Cisco",
        product: "Small Business RV Series Routers",
        cpe23: "cpe:2.3:a:cisco:small_business_rv_series_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Cisco Small Business RV Series Routers contains a command",
            " injection vulnerability in the web-based management interface. Su",
            "ccessful exploitation could allow an authenticated, remote attacke",
            "r to gain root-level privileges and access unauthorized data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-20198",
        vendor: "cisco",
        product: "cisco_ios_xe",
        cpe23: "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
        cvss_x10: 100, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Cisco IOS XE Web UI Privilege Escalation Advisory",
        remediation: "`no ip http server` o'rnating va IOS XE ni yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-20269",
        vendor: "Cisco",
        product: "Adaptive Security Appliance and Firepower Threat Defense",
        cpe23: concat!(
            "cpe:2.3:a:cisco:adaptive_security_appliance_and_firepower_threat_d",
            "efense:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco Adaptive Security Appliance and Firepower Threat Defense con",
            "tain an unauthorized access vulnerability that could allow an unau",
            "thenticated, remote attacker to conduct a brute force attack in an",
            " attempt to identify valid username and password combinations or e",
            "stablish a clientless SSL VPN session with an unauthoriz"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions for group-lock and vpn-s",
            "imultaneous-logins or discontinue use of the product for unsupport",
            "ed devices."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-20273",
        vendor: "Cisco",
        product: "Cisco IOS XE Web UI",
        cpe23: "cpe:2.3:a:cisco:cisco_ios_xe_web_ui:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XE contains a command injection vulnerability in the web",
            " user interface. When chained with CVE-2023-20198, the attacker ca",
            "n leverage the new local user to elevate privilege to root and wri",
            "te the implant to the file system. Cisco identified CVE-2023-20273",
            " as the vulnerability exploited to deploy the implant. C"
        ),
        remediation: concat!(
            "Verify that instances of Cisco IOS XE Web UI are in compliance wit",
            "h BOD 23-02 and apply mitigations per vendor instructions. For aff",
            "ected products (Cisco IOS XE Web UI exposed to the internet or to ",
            "untrusted networks), follow vendor instructions to determine i"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-2033",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-20867",
        vendor: "VMware",
        product: "Tools",
        cpe23: "cpe:2.3:a:vmware:tools:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware Tools contains an authentication bypass vulnerability in th",
            "e vgauth module. A fully compromised ESXi host can force VMware To",
            "ols to fail to authenticate host-to-guest operations, impacting th",
            "e confidentiality and integrity of the guest virtual machine. An a",
            "ttacker must have root access over ESXi to exploit this "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-20887",
        vendor: "VMware",
        product: "Aria Operations for Networks",
        cpe23: "cpe:2.3:a:vmware:aria_operations_for_networks:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware Aria Operations for Networks (formerly vRealize Network Ins",
            "ight) contains a command injection vulnerability that allows a mal",
            "icious actor with network access to perform an attack resulting in",
            " remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-20963",
        vendor: "Android",
        product: "Framework",
        cpe23: "cpe:2.3:a:android:framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Framework contains an unspecified vulnerability that allow",
            "s for privilege escalation after updating an app to a higher Targe",
            "t SDK with no additional execution privileges needed."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-21237",
        vendor: "Android",
        product: "Pixel",
        cpe23: "cpe:2.3:a:android:pixel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Pixel contains a vulnerability in the Framework component,",
            " where the UI may be misleading or insufficient, providing a means",
            " to hide a foreground service notification. This could enable a lo",
            "cal attacker to disclose sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-2136",
        vendor: "Google",
        product: "Chromium Skia",
        cpe23: "cpe:2.3:a:google:chromium_skia:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Skia contains an integer overflow vulnerability th",
            "at allows a remote attacker, who has compromised the renderer proc",
            "ess, to potentially perform a sandbox escape via a crafted HTML pa",
            "ge. This vulnerability affects Google Chrome and ChromeOS, Android",
            ", Flutter, and possibly other products."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-21492",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices running Android 11, 12, and 13 contain an i",
            "nsertion of sensitive information into log file vulnerability that",
            " allows a privileged, local attacker to conduct an address space l",
            "ayout randomization (ASLR) bypass."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-21529",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server contains a deserialization of untrusted ",
            "data that allows an authenticated attacker to achieve remote code ",
            "execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-21608",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contains a use-after-free vulnerability t",
            "hat allows for code execution in the context of the current user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-21674",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Advanced Local Procedure Call (ALPC) contains an",
            " unspecified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-21715",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Publisher contains a security feature bypass vuln",
            "erability that allows for a local, authenticated attack on a targe",
            "ted system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-21823",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Graphic Component contains an unspecified vulner",
            "ability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-21839",
        vendor: "oracle",
        product: "weblogic",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Oracle WebLogic (< 14.1.2) IIOP/T3 JNDI Advisory",
        remediation: "Oracle CPU o'rnating va T3/IIOP portni yoping.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-22515",
        vendor: "Atlassian",
        product: "Confluence Data Center and Server",
        cpe23: concat!(
            "cpe:2.3:a:atlassian:confluence_data_center_and_server:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Atlassian Confluence Data Center and Server contains a broken acce",
            "ss control vulnerability that allows an attacker to create unautho",
            "rized Confluence administrator accounts and access Confluence."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable. Check all affected Confl",
            "uence instances for evidence of compromise per vendor instructions",
            " and report any positive findings to CISA."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-22518",
        vendor: "Atlassian",
        product: "Confluence Data Center and Server",
        cpe23: concat!(
            "cpe:2.3:a:atlassian:confluence_data_center_and_server:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Atlassian Confluence Data Center and Server contain an improper au",
            "thorization vulnerability that can result in significant data loss",
            " when exploited by an unauthenticated attacker. There is no impact",
            " on confidentiality since the attacker cannot exfiltrate any data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-22527",
        vendor: "atlassian",
        product: "confluence",
        cpe23: "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
        cvss_x10: 100, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "Atlassian Confluence (< 8.5.4) Template Advisory",
        remediation: concat!(
            "Atlassian Confluence Data Center ni 8.5.5+ LTS yoki 8.9+ versiyasi",
            "ga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-22795",
        vendor: "rubygems",
        product: "rails",
        cpe23: "cpe:2.3:a:rubygems:rails:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "RubyGems rails vulnerability advisory",
        remediation: "Upgrade rails to >= 7.0.4",
    },
    KevCveRecord {
        cve_id: "CVE-2023-22894",
        vendor: "Strapi",
        product: "Strapi",
        cpe23: "cpe:2.3:a:strapi:strapi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Strapi contains a cleartext storage of sensitive information vulne",
            "rability that could allow attackers with access to the admin panel",
            " to discover sensitive user details via the query filter. The impa",
            "cted product(s) could be end-of-life (EoL) and/or end-of-service (",
            "EoS). Users are advised to discontinue use and/or transi"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-22952",
        vendor: "SugarCRM",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:sugarcrm:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple SugarCRM products contain a remote code execution vulnera",
            "bility in the EmailTemplates. Using a specially crafted request, c",
            "ustom PHP code can be injected through the EmailTemplates."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-23376",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) driver contains an",
            " unspecified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-23397",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Outlook contains a privilege escalation vulnerabi",
            "lity that allows for a NTLM Relay attack against another service t",
            "o authenticate as the user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-23529",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, MacOS, Safari and iPadOS WebKit contain a type confusio",
            "n vulnerability that leads to code execution when processing malic",
            "iously crafted web content. This vulnerability could impact HTML p",
            "arsers that use WebKit, including but not limited to Apple Safari ",
            "and non-Apple products which rely on WebKit for HTML pro"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-23752",
        vendor: "joomla",
        product: "joomla",
        cpe23: "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 971,
        summary: "Joomla (< 4.2.8) Unauthenticated REST API Information Disclosure",
        remediation: "Joomla CMS tizimini 4.2.8+ yoki 5.x xavfsizlik reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-24489",
        vendor: "Citrix",
        product: "Content Collaboration",
        cpe23: "cpe:2.3:a:citrix:content_collaboration:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix Content Collaboration contains an improper access control v",
            "ulnerability that could allow an unauthenticated attacker to remot",
            "ely compromise customer-managed ShareFile storage zones controller",
            "s."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-24880",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows SmartScreen contains a security feature bypass v",
            "ulnerability that could allow an attacker to evade Mark of the Web",
            " (MOTW) defenses via a specially crafted malicious file."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-24955",
        vendor: "Microsoft",
        product: "SharePoint Server",
        cpe23: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint Server contains a code injection vulnerabilit",
            "y that allows an authenticated attacker with Site Owner privileges",
            " to execute code remotely."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-25194",
        vendor: "apache",
        product: "druid",
        cpe23: "cpe:2.3:a:apache:druid:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache Druid (< 25.0.0) Kafka Connector Configuration Advisory",
        remediation: "Apache Druid klasterini 28.0+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-25280",
        vendor: "D-Link",
        product: "DIR-820 Router",
        cpe23: "cpe:2.3:a:d-link:dir-820_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-820 routers contain an OS command injection vulnerabili",
            "ty that allows a remote, unauthenticated attacker to escalate priv",
            "ileges to root via a crafted payload with the ping_addr parameter ",
            "to ping.ccp."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-2533",
        vendor: "PaperCut",
        product: "NG/MF",
        cpe23: "cpe:2.3:a:papercut:ng_mf:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PaperCut NG/MF contains a cross-site request forgery (CSRF) vulner",
            "ability, which, under specific conditions, could potentially enabl",
            "e an attacker to alter security settings or execute arbitrary code",
            "."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-25717",
        vendor: "Ruckus Wireless",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:ruckus_wireless:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ruckus Wireless Access Point (AP) software contains an unspecified",
            " vulnerability in the web services component. If the web services ",
            "component is enabled on the AP, an attacker can perform cross-site",
            " request forgery (CSRF) or remote code execution (RCE). This vulne",
            "rability impacts Ruckus ZoneDirector, SmartZone, and Sol"
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or disconnect product if it ",
            "is end-of-life."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-25859",
        vendor: "apereo",
        product: "cas",
        cpe23: "cpe:2.3:a:apereo:central_authentication_service:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apereo CAS (< 6.6.14) SSO Ticket Validation Advisory",
        remediation: "Apereo CAS ni 7.0+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26083",
        vendor: "Arm",
        product: "Mali Graphics Processing Unit (GPU)",
        cpe23: "cpe:2.3:a:arm:mali_graphics_processing_unit_gpu:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali GPU Kernel Driver contains an information disclosure vuln",
            "erability that allows a non-privileged user to make valid GPU proc",
            "essing operations that expose sensitive kernel metadata."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26125",
        vendor: "go",
        product: "github.com/gin-gonic/gin",
        cpe23: "cpe:2.3:a:go:github.com_gin-gonic_gin:*:*:*:*:*:*:*:*",
        cvss_x10: 53, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Go github.com/gin-gonic/gin vulnerability advisory",
        remediation: "Upgrade github.com/gin-gonic/gin to >= 1.9.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26136",
        vendor: "npm",
        product: "tough-cookie",
        cpe23: "cpe:2.3:a:npm:tough-cookie:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm tough-cookie vulnerability advisory",
        remediation: "Upgrade tough-cookie to >= 4.1.3",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26253",
        vendor: "gluster",
        product: "glusterfs",
        cpe23: "cpe:2.3:a:gluster:glusterfs:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-787",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated GlusterFS (< 11.1.0) Buffer Handling Advisory",
        remediation: "GlusterFS ni 11.1+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26268",
        vendor: "apache",
        product: "couchdb",
        cpe23: "cpe:2.3:a:apache:couchdb:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache CouchDB (< 3.3.2) Document Design Isolation Advisory",
        remediation: "Apache CouchDB serverini 3.3.3+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26359",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains a deserialization of untrusted data vuln",
            "erability that could result in code execution in the context of th",
            "e current user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-26360",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains a deserialization of untrusted data vuln",
            "erability that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-26369",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contains an out-of-bounds write vulnerabi",
            "lity that allows for code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-26964",
        vendor: "crates.io",
        product: "hyper",
        cpe23: "cpe:2.3:a:crates.io:hyper:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "crates.io hyper vulnerability advisory",
        remediation: "Upgrade hyper to >= 0.14.25",
    },
    KevCveRecord {
        cve_id: "CVE-2023-27159",
        vendor: "appwrite",
        product: "appwrite",
        cpe23: "cpe:2.3:a:appwrite:appwrite:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-918",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Appwrite (< 1.3.2) Webhook SSRF Advisory",
        remediation: "Appwrite ni 1.5+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-27350",
        vendor: "PaperCut",
        product: "MF/NG",
        cpe23: "cpe:2.3:a:papercut:mf_ng:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "PaperCut MF/NG contains an improper access control vulnerability w",
            "ithin the SetupCompleted class that allows authentication bypass a",
            "nd code execution in the context of system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-27351",
        vendor: "PaperCut",
        product: "NG/MF",
        cpe23: "cpe:2.3:a:papercut:ng_mf:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "PaperCut NG/MF contains an improper authentication vulnerability t",
            "hat could allow remote attackers to bypass authentication on affec",
            "ted installations via the SecurityRequestFilter class."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-27524",
        vendor: "apache",
        product: "superset",
        cpe23: "cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 951,
        summary: concat!(
            "Apache Superset (< 2.1.2) Default SECRET_KEY Session Validation Ad",
            "visory"
        ),
        remediation: concat!(
            "Apache Superset ni 3.1+ versiyasiga yangilang va tasodifiy SECRET_",
            "KEY belgilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-27530",
        vendor: "rubygems",
        product: "rack",
        cpe23: "cpe:2.3:a:rubygems:rack:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "RubyGems rack vulnerability advisory",
        remediation: "Upgrade rack to >= 2.2.6",
    },
    KevCveRecord {
        cve_id: "CVE-2023-27532",
        vendor: "Veeam",
        product: "Backup & Replication",
        cpe23: "cpe:2.3:a:veeam:backup_replication:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Veeam Backup & Replication Cloud Connect component contains a miss",
            "ing authentication for critical function vulnerability that allows",
            " an unauthenticated user operating within the backup infrastructur",
            "e network perimeter to obtain encrypted credentials stored in the ",
            "configuration database. This may lead to an attacker gai"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-27992",
        vendor: "Zyxel",
        product: "Multiple Network-Attached Storage (NAS) Devices",
        cpe23: concat!(
            "cpe:2.3:a:zyxel:multiple_network-attached_storage_nas_devices:*:*:",
            "*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Zyxel network-attached storage (NAS) devices contain a pr",
            "e-authentication command injection vulnerability that could allow ",
            "an unauthenticated attacker to execute commands remotely via a cra",
            "fted HTTP request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-27997",
        vendor: "Fortinet",
        product: "FortiOS and FortiProxy SSL-VPN",
        cpe23: "cpe:2.3:a:fortinet:fortios_and_fortiproxy_ssl-vpn:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS and FortiProxy SSL-VPN contain a heap-based buffe",
            "r overflow vulnerability which can allow an unauthenticated, remot",
            "e attacker to execute code or commands via specifically crafted re",
            "quests."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28204",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain",
            " an out-of-bounds read vulnerability that may disclose sensitive i",
            "nformation when processing maliciously crafted web content. This v",
            "ulnerability could impact HTML parsers that use WebKit, including ",
            "but not limited to Apple Safari and non-Apple products w"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28205",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain a use-after-fr",
            "ee vulnerability that leads to code execution when processing mali",
            "ciously crafted web content. This vulnerability could impact HTML ",
            "parsers that use WebKit, including but not limited to Apple Safari",
            " and non-Apple products which rely on WebKit for HTML pr"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28206",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS IOSurfaceAccelerator contain an out-o",
            "f-bounds write vulnerability that allows an app to execute code wi",
            "th kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28229",
        vendor: "Microsoft",
        product: "Windows CNG Key Isolation Service",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:windows_cng_key_isolation_service:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Cryptographic Next Generation (CNG) Key Isolatio",
            "n Service contains an unspecified vulnerability that allows an att",
            "acker to gain specific limited SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-28252",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) driver contains an",
            " unspecified vulnerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28366",
        vendor: "eclipse",
        product: "mosquitto",
        cpe23: "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-401",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Eclipse Mosquitto (< 2.0.16) QoS Memory Advisory",
        remediation: "Eclipse Mosquitto ni 2.0.18+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28370",
        vendor: "pypi",
        product: "tornado",
        cpe23: "cpe:2.3:a:pypi:tornado:*:*:*:*:*:*:*:*",
        cvss_x10: 53, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI tornado vulnerability advisory",
        remediation: "Upgrade tornado to >= 6.3.3",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28432",
        vendor: "MinIO",
        product: "MinIO",
        cpe23: "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MinIO contains a vulnerability in a cluster deployment where MinIO",
            " returns all environment variables, which allows for information d",
            "isclosure."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28434",
        vendor: "MinIO",
        product: "MinIO",
        cpe23: "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MinIO contains a security feature bypass vulnerability that allows",
            " an attacker to use crafted requests to bypass metadata bucket nam",
            "e checking and put an object into any bucket while processing `Pos",
            "tPolicyBucket` to conduct privilege escalation. To carry out this ",
            "attack, the attacker requires credentials with `arn:aws:"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-28461",
        vendor: "Array Networks",
        product: "AG/vxAG ArrayOS",
        cpe23: "cpe:2.3:a:array_networks:ag_vxag_arrayos:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Array Networks AG and vxAG ArrayOS contain a missing authenticatio",
            "n for critical function vulnerability that allows an attacker to r",
            "ead local files and execute code on the SSL VPN gateway."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-2868",
        vendor: "Barracuda Networks",
        product: "Email Security Gateway (ESG) Appliance",
        cpe23: concat!(
            "cpe:2.3:a:barracuda_networks:email_security_gateway_esg_appliance:",
            "*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Barracuda Email Security Gateway (ESG) appliance contains an impro",
            "per input validation vulnerability of a user-supplied .tar file, l",
            "eading to remote command injection."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-28771",
        vendor: "Zyxel",
        product: "Multiple Firewalls",
        cpe23: "cpe:2.3:a:zyxel:multiple_firewalls:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zyxel ATP, USG FLEX, VPN, and ZyWALL/USG firewalls allow for impro",
            "per error message handling which could allow an unauthenticated at",
            "tacker to execute OS commands remotely by sending crafted packets ",
            "to an affected device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-29298",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains an improper access control vulnerability",
            " that allows for a security feature bypass."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-29300",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe ColdFusion contains a deserialization of untrusted data vuln",
            "erability that allows for code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-29336",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability that allows",
            " for privilege escalation up to SYSTEM privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-29357",
        vendor: "Microsoft",
        product: "SharePoint Server",
        cpe23: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint Server contains an unspecified vulnerability ",
            "that allows an unauthenticated attacker, who has gained access to ",
            "spoofed JWT authentication tokens, to use them for executing a net",
            "work attack. This attack bypasses authentication, enabling the att",
            "acker to gain administrator privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-29360",
        vendor: "Microsoft",
        product: "Streaming Service",
        cpe23: "cpe:2.3:a:microsoft:streaming_service:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Streaming Service contains an untrusted pointer derefere",
            "nce vulnerability that allows for privilege escalation, enabling a",
            " local attacker to gain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-29492",
        vendor: "Novi Survey",
        product: "Novi Survey",
        cpe23: "cpe:2.3:a:novi_survey:novi_survey:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Novi Survey contains an insecure deserialization vulnerability tha",
            "t allows remote attackers to execute code on the server in the con",
            "text of the service account."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-29510",
        vendor: "milvus",
        product: "milvus",
        cpe23: "cpe:2.3:a:milvus:milvus:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-306",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Milvus (< 2.3.3) Proxy Auth Advisory",
        remediation: "Milvus ni 2.4+ ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-29552",
        vendor: "IETF",
        product: "Service Location Protocol (SLP)",
        cpe23: "cpe:2.3:a:ietf:service_location_protocol_slp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Service Location Protocol (SLP) contains a denial-of-service (",
            "DoS) vulnerability that could allow an unauthenticated, remote att",
            "acker to register services and use spoofed UDP traffic to conduct ",
            "a denial-of-service (DoS) attack with a significant amplification ",
            "factor."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or disable SLP service o",
            "r port 427/UDP on all systems running on untrusted networks, inclu",
            "ding those directly connected to the Internet."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-30464",
        vendor: "coredns",
        product: "coredns",
        cpe23: "cpe:2.3:a:coredns:coredns:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated CoreDNS (< 1.10.1) DNS Cache Advisory",
        remediation: "CoreDNS ni 1.11+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-30575",
        vendor: "apache",
        product: "guacamole",
        cpe23: "cpe:2.3:a:apache:guacamole:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-416",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache Guacamole (< 1.5.2) RDP Protocol Handling Advisory",
        remediation: "Apache Guacamole ni 1.5.4+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-3079",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a type confusion vulnerability ",
            "that allows a remote attacker to potentially exploit heap corrupti",
            "on via a crafted HTML page. This vulnerability could affect multip",
            "le web browsers that utilize Chromium, including, but not limited ",
            "to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-30799",
        vendor: "mikrotik",
        product: "routeros",
        cpe23: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*",
        cvss_x10: 82, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "MikroTik RouterOS (< 7.12.1) Management Interface Advisory",
        remediation: concat!(
            "MikroTik RouterOS ni 7.15+ Stable versiyasiga yangilang va Winbox/",
            "WebFig ni ichki tarmoqqa cheklang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-32007",
        vendor: "apache",
        product: "spark",
        cpe23: "cpe:2.3:a:apache:spark:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache Spark (< 3.5.1) UI ACL Command Handling Advisory",
        remediation: "Apache Spark tizimini 3.5.1+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32046",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows MSHTML Platform contains an unspecified vulnerab",
            "ility that allows for privilege escalation."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-32049",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Defender SmartScreen contains a security feature",
            " bypass vulnerability that allows an attacker to bypass the Open F",
            "ile - Security Warning prompt."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-32191",
        vendor: "suse",
        product: "rancher",
        cpe23: "cpe:2.3:a:suse:rancher:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "SUSE Rancher (< 2.8.3) Kubernetes Secret Handling Advisory",
        remediation: "SUSE Rancher boshqaruv serverini 2.8.4+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32315",
        vendor: "Ignite Realtime",
        product: "Openfire",
        cpe23: "cpe:2.3:a:ignite_realtime:openfire:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ignite Realtime Openfire contains a path traversal vulnerability t",
            "hat allows an unauthenticated attacker to access restricted pages ",
            "in the Openfire Admin Console reserved for administrative users."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-32373",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain",
            " a use-after-free vulnerability that leads to code execution when ",
            "processing maliciously crafted web content. This vulnerability cou",
            "ld impact HTML parsers that use WebKit, including but not limited ",
            "to Apple Safari and non-Apple products which rely on Web"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32409",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, watchOS, and Safari WebKit contain",
            " an unspecified vulnerability that can allow a remote attacker to ",
            "break out of the Web Content sandbox. This vulnerability could imp",
            "act HTML parsers that use WebKit, including but not limited to App",
            "le Safari and non-Apple products which rely on WebKit fo"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32434",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS. iPadOS, macOS, and watchOS contain an integer overflow ",
            "vulnerability that could allow an application to execute code with",
            " kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32435",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain a memory corru",
            "ption vulnerability that leads to code execution when processing m",
            "aliciously crafted web content. This vulnerability could impact HT",
            "ML parsers that use WebKit, including but not limited to Apple Saf",
            "ari and non-Apple products which rely on WebKit for HTML"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32439",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain a type confusi",
            "on vulnerability that leads to code execution when processing mali",
            "ciously crafted web content. This vulnerability could impact HTML ",
            "parsers that use WebKit, including but not limited to Apple Safari",
            " and non-Apple products which rely on WebKit for HTML pr"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32681",
        vendor: "pypi",
        product: "requests",
        cpe23: "cpe:2.3:a:pypi:requests:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI requests vulnerability advisory",
        remediation: "Upgrade requests to >= 2.31.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-32695",
        vendor: "npm",
        product: "socket.io-parser",
        cpe23: "cpe:2.3:a:npm:socket.io-parser:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm socket.io-parser vulnerability advisory",
        remediation: "Upgrade socket.io-parser to >= 4.2.3",
    },
    KevCveRecord {
        cve_id: "CVE-2023-33009",
        vendor: "Zyxel",
        product: "Multiple Firewalls",
        cpe23: "cpe:2.3:a:zyxel:multiple_firewalls:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zyxel ATP, USG FLEX, USG FLEX 50(W), USG20(W)-VPN, VPN, and ZyWALL",
            "/USG firewalls contain a buffer overflow vulnerability in the noti",
            "fication function that could allow an unauthenticated attacker to ",
            "cause denial-of-service (DoS) conditions and remote code execution",
            " on an affected device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-33010",
        vendor: "Zyxel",
        product: "Multiple Firewalls",
        cpe23: "cpe:2.3:a:zyxel:multiple_firewalls:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zyxel ATP, USG FLEX, USG FLEX 50(W), USG20(W)-VPN, VPN, and ZyWALL",
            "/USG firewalls contain a buffer overflow vulnerability in the ID p",
            "rocessing function that could allow an unauthenticated attacker to",
            " cause denial-of-service (DoS) conditions and remote code executio",
            "n on an affected device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-33063",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a use-after-free vulnerability ",
            "due to memory corruption in DSP Services during a remote call from",
            " HLOS to DSP."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-33106",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a use of out-of-range pointer o",
            "ffset vulnerability due to memory corruption in Graphics while sub",
            "mitting a large list of sync points in an AUX command to the IOCTL",
            "_KGSL_GPU_AUX_COMMAND."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-33107",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain an integer overflow vulnerabili",
            "ty due to memory corruption in Graphics Linux while assigning shar",
            "ed virtual memory region during IOCTL call."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-33246",
        vendor: "Apache",
        product: "RocketMQ",
        cpe23: "cpe:2.3:a:apache:rocketmq:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Several components of Apache RocketMQ, including NameServer, Broke",
            "r, and Controller, are exposed to the extranet and lack permission",
            " verification. An attacker can exploit this vulnerability by using",
            " the update configuration function to execute commands as the syst",
            "em users that RocketMQ is running as or achieve the same"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-33538",
        vendor: "TP-Link",
        product: "Multiple Routers",
        cpe23: "cpe:2.3:a:tp-link:multiple_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 con",
            "tain a command injection vulnerability via the component /userRpm/",
            "WlanNetworkRpm. The impacted products could be end-of-life (EoL) a",
            "nd/or end-of-service (EoS). Users should discontinue product utili",
            "zation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-33968",
        vendor: "meilisearch",
        product: "meilisearch",
        cpe23: "cpe:2.3:a:meilisearch:meilisearch:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Meilisearch (< 1.2.0) Master Key Posture Advisory",
        remediation: concat!(
            "Meilisearch 1.8+ versiyasiga yangilang va `MEILI_MASTER_KEY` o'rna",
            "ting."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-34048",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware vCenter Server contains an out-of-bounds write vulnerabilit",
            "y in the implementation of the DCERPC protocol that allows an atta",
            "cker to conduct remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-34055",
        vendor: "vmware",
        product: "spring_boot",
        cpe23: "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Spring Boot 3.0/3.1 (< 3.1.6) Security Advisory",
        remediation: "Spring Boot 3.x tarmog'ini 3.2.5+ / 3.3+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-34192",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting (XSS) vulnerability that allows a remote authenticated atta",
            "cker to execute arbitrary code via a crafted script to the /h/auto",
            "SaveDraft function."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-34362",
        vendor: "Progress",
        product: "MOVEit Transfer",
        cpe23: "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Progress MOVEit Transfer contains a SQL injection vulnerability th",
            "at could allow an unauthenticated attacker to gain unauthorized ac",
            "cess to MOVEit Transfer's database. Depending on the database engi",
            "ne being used (MySQL, Microsoft SQL Server, or Azure SQL), an atta",
            "cker may be able to infer information about the structur"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-34468",
        vendor: "apache",
        product: "nifi",
        cpe23: "cpe:2.3:a:apache:nifi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache NiFi (< 1.22.0) DBCP Connection Pool Validation Advisory",
        remediation: "Apache NiFi platformasini 1.25+ / 2.0+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-34843",
        vendor: "dle-news",
        product: "datalife_engine",
        cpe23: "cpe:2.3:a:dle-news:datalife_engine:*:*:*:*:*:*:*:*",
        cvss_x10: 78, severity: "High", cwe: "CWE-89",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated DataLife Engine (< 16.1) CMS Security Advisory",
        remediation: concat!(
            "DataLife Engine (DLE) tizimini 17.x+ xavfsizlik reliziga yangilang",
            "."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-35078",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM, previously branded MobileIro",
            "n Core) contains an authentication bypass vulnerability that allow",
            "s unauthenticated access to specific API paths. An attacker with a",
            "ccess to these API paths can access personally identifiable inform",
            "ation (PII) such as names, phone numbers, and other mobi"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-35081",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) contains a path traversal vu",
            "lnerability that enables an authenticated administrator to perform",
            " malicious file writes to the EPMM server. This vulnerability can ",
            "be used in conjunction with CVE-2023-35078 to bypass authenticatio",
            "n and ACLs restrictions (if applicable)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-35082",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM) and MobileIron Core",
        cpe23: concat!(
            "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm_and_mobileiron_core:",
            "*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core contain ",
            "an authentication bypass vulnerability that allows unauthorized us",
            "ers to access restricted functionality or resources of the applica",
            "tion."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-3519",
        vendor: "Citrix",
        product: "NetScaler ADC and NetScaler Gateway",
        cpe23: concat!(
            "cpe:2.3:a:citrix:netscaler_adc_and_netscaler_gateway:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contains a code injecti",
            "on vulnerability that allows for unauthenticated remote code execu",
            "tion."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-35311",
        vendor: "Microsoft",
        product: "Outlook",
        cpe23: "cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Outlook contains a security feature bypass vulnerability",
            " that allows an attacker to bypass the Microsoft Outlook Security ",
            "Notice prompt."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-35674",
        vendor: "Android",
        product: "Framework",
        cpe23: "cpe:2.3:a:android:framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Framework contains an unspecified vulnerability that allow",
            "s for privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-35848",
        vendor: "emqx",
        product: "emqx",
        cpe23: "cpe:2.3:a:emqx:emqx:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated EMQX (< 5.1.0) MQTT Dashboard API Advisory",
        remediation: "EMQX brokerini 5.5+ LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-36025",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows SmartScreen contains a security feature bypass v",
            "ulnerability that could allow an attacker to bypass Windows Defend",
            "er SmartScreen checks and their associated prompts."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36033",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Desktop Window Manager (DWM) Core Library contai",
            "ns an unspecified vulnerability that allows for privilege escalati",
            "on."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36036",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Cloud Files Mini Filter Driver contains a privil",
            "ege escalation vulnerability that could allow an attacker to gain ",
            "SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36424",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Common Log File System Driver contains an out-of",
            "-bounds read vulnerability that could allow a threat actor for pri",
            "vileges escalation"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36563",
        vendor: "Microsoft",
        product: "WordPad",
        cpe23: "cpe:2.3:a:microsoft:wordpad:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft WordPad contains an unspecified vulnerability that allow",
            "s for information disclosure."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36584",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Mark of the Web (MOTW) contains a security featu",
            "re bypass vulnerability resulting in a limited loss of integrity a",
            "nd availability of security features."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36761",
        vendor: "Microsoft",
        product: "Word",
        cpe23: "cpe:2.3:a:microsoft:word:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Word contains an unspecified vulnerability that allows f",
            "or information disclosure."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36802",
        vendor: "Microsoft",
        product: "Streaming Service Proxy",
        cpe23: "cpe:2.3:a:microsoft:streaming_service_proxy:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Streaming Service Proxy contains an unspecified vulnerab",
            "ility that allows for privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36844",
        vendor: "Juniper",
        product: "Junos OS",
        cpe23: "cpe:2.3:a:juniper:junos_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Juniper Junos OS on EX Series contains a PHP external variable mod",
            "ification vulnerability that allows an unauthenticated, network-ba",
            "sed attacker to control certain, important environment variables. ",
            "Using a crafted request an attacker is able to modify certain PHP ",
            "environment variables, leading to partial loss of integr"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36845",
        vendor: "juniper",
        product: "juniper_junos",
        cpe23: "cpe:2.3:a:juniper:junos:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Juniper Junos OS J-Web Environment Variable Advisory",
        remediation: "Junos OS tizimini yangilang va J-Web interfeysini o'chiring.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-36846",
        vendor: "Juniper",
        product: "Junos OS",
        cpe23: "cpe:2.3:a:juniper:junos_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Juniper Junos OS on SRX Series contains a missing authentication f",
            "or critical function vulnerability that allows an unauthenticated,",
            " network-based attacker to cause limited impact to the file system",
            " integrity. With a specific request to user.php that doesn't requi",
            "re authentication, an attacker is able to upload arbitra"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36847",
        vendor: "Juniper",
        product: "Junos OS",
        cpe23: "cpe:2.3:a:juniper:junos_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Juniper Junos OS on EX Series contains a missing authentication fo",
            "r critical function vulnerability that allows an unauthenticated, ",
            "network-based attacker to cause limited impact to the file system ",
            "integrity. With a specific request to installAppPackage.php that d",
            "oesn't require authentication, an attacker is able to up"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36851",
        vendor: "Juniper",
        product: "Junos OS",
        cpe23: "cpe:2.3:a:juniper:junos_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Juniper Junos OS on SRX Series contains a missing authentication f",
            "or critical function vulnerability that allows an unauthenticated,",
            " network-based attacker to cause limited impact to the file system",
            " integrity. With a specific request to webauth_operation.php that ",
            "doesn't require authentication, an attacker is able to u"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36874",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Error Reporting Service contains an unspecified ",
            "vulnerability that allows for privilege escalation."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-36884",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Search contains an unspecified vulnerability tha",
            "t could allow an attacker to evade Mark of the Web (MOTW) defenses",
            " via a specially crafted malicious file, leading to remote code ex",
            "ecution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-37265",
        vendor: "pub",
        product: "archive",
        cpe23: "cpe:2.3:a:pub:archive:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Pub archive vulnerability advisory",
        remediation: "Upgrade archive to >= 3.3.8",
    },
    KevCveRecord {
        cve_id: "CVE-2023-37450",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain an unspecified",
            " vulnerability that leads to code execution when processing malici",
            "ously crafted web content. This vulnerability could impact HTML pa",
            "rsers that use WebKit, including but not limited to Apple Safari a",
            "nd non-Apple products which rely on WebKit for HTML proc"
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-37466",
        vendor: "npm",
        product: "vm2",
        cpe23: "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm vm2 vulnerability advisory",
        remediation: "Upgrade vm2 to >= 3.9.20",
    },
    KevCveRecord {
        cve_id: "CVE-2023-37580",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting vulnerability impacting the confidentiality and integrity o",
            "f data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38035",
        vendor: "Ivanti",
        product: "Sentry",
        cpe23: "cpe:2.3:a:ivanti:sentry:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Sentry, formerly known as MobileIron Sentry, contains an au",
            "thentication bypass vulnerability that may allow an attacker to by",
            "pass authentication controls on the administrative interface due t",
            "o an insufficiently restrictive Apache HTTPD configuration."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38180",
        vendor: "Microsoft",
        product: ".NET Core and Visual Studio",
        cpe23: "cpe:2.3:a:microsoft:.net_core_and_visual_studio:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft .NET Core and Visual Studio contain an unspecified vulne",
            "rability that allows for denial-of-service (DoS)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38203",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe ColdFusion contains a deserialization of untrusted data vuln",
            "erability that allows for code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38205",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains an improper access control vulnerability",
            " that allows for a security feature bypass."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38443",
        vendor: "cockroachlabs",
        product: "cockroachdb",
        cpe23: "cpe:2.3:a:cockroachlabs:cockroachdb:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated CockroachDB (< 23.1.9) SQL Privilege Evaluation Advisory",
        remediation: "CockroachDB klasterini 23.2+ LTS reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-38500",
        vendor: "seafile",
        product: "seafile",
        cpe23: "cpe:2.3:a:seafile:seafile:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Seafile (< 10.0.2) Share Link Advisory",
        remediation: "Seafile ni 11.0+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-38501",
        vendor: "gravitee",
        product: "gravitee",
        cpe23: "cpe:2.3:a:gravitee:api_management:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Gravitee APIM (< 4.1.2) Expression Language Advisory",
        remediation: "Gravitee APIM ni 4.2+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-38606",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and watchOS contain an unspecified",
            " vulnerability allowing an app to modify a sensitive kernel state."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38646",
        vendor: "metabase",
        product: "metabase",
        cpe23: "cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: false, ransomware: "Unknown", epss_permille: 955,
        summary: "Metabase BI (< 0.46.6.1) Pre-Auth Setup Token Validation Advisory",
        remediation: "Metabase BI tizimini 0.46.6.1+ yoki 0.49+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-38831",
        vendor: "RARLAB",
        product: "WinRAR",
        cpe23: "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "RARLAB WinRAR contains an unspecified vulnerability that allows an",
            " attacker to execute code when a user attempts to view a benign fi",
            "le within a ZIP archive."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-38950",
        vendor: "ZKTeco",
        product: "BioTime",
        cpe23: "cpe:2.3:a:zkteco:biotime:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ZKTeco BioTime contains a path traversal vulnerability in the iclo",
            "ck API that allows an unauthenticated attacker to read arbitrary f",
            "iles via supplying a crafted payload."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-39325",
        vendor: "dexidp",
        product: "dex",
        cpe23: "cpe:2.3:a:dexidp:dex:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Dex OIDC (< 2.37.0) HTTP/2 Resource Advisory",
        remediation: "Dex IdP ni 2.38+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-39780",
        vendor: "ASUS",
        product: "RT-AX55 Routers",
        cpe23: "cpe:2.3:a:asus:rt-ax55_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ASUS RT-AX55 devices contain an OS command injection vulnerability",
            " that could allow a remote, authenticated attacker to execute arbi",
            "trary commands. As represented by CVE-2023-41346."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-40028",
        vendor: "ghost",
        product: "ghost",
        cpe23: "cpe:2.3:a:ghost:ghost:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-59",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Ghost CMS (< 5.59.1) Symlink Import Advisory",
        remediation: "Ghost CMS ni 5.80+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-40044",
        vendor: "Progress",
        product: "WS_FTP Server",
        cpe23: "cpe:2.3:a:progress:ws_ftp_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Progress WS_FTP Server contains a deserialization of untrusted dat",
            "a vulnerability in the Ad Hoc Transfer module that allows an authe",
            "nticated attacker to execute remote commands on the underlying ope",
            "rating system."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-40224",
        vendor: "webmin",
        product: "webmin",
        cpe23: "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Webmin (< 2.105) Administrative Session Advisory",
        remediation: "Webmin boshqaruv paketini 2.111+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-40225",
        vendor: "haproxy",
        product: "haproxy",
        cpe23: "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*",
        cvss_x10: 82, severity: "High", cwe: "CWE-444",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "HAProxy (< 2.8.2) HTTP Request Parsing Advisory",
        remediation: concat!(
            "HAProxy balanslovchisini 2.8.10+ LTS yoki 3.0+ versiyasiga yangila",
            "ng."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4043",
        vendor: "eclipse",
        product: "glassfish",
        cpe23: "cpe:2.3:a:eclipse:glassfish:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Eclipse GlassFish (< 7.0.9) Admin File Advisory",
        remediation: "GlassFish ni 7.0.11+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-41044",
        vendor: "graylog",
        product: "graylog",
        cpe23: "cpe:2.3:a:graylog:graylog:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Graylog (< 5.1.6) Support Bundle Information Exposure Advisory",
        remediation: "Graylog serverini 5.2+ barqaror versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-41061",
        vendor: "Apple",
        product: "iOS, iPadOS, and watchOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_watchos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and watchOS contain an unspecified vulnerabilit",
            "y due to a validation issue affecting Wallet in which a maliciousl",
            "y crafted attachment may result in code execution. This vulnerabil",
            "ity was chained with CVE-2023-41064."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41064",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS contain a buffer overflow vulnerabili",
            "ty in ImageIO when processing a maliciously crafted image, which m",
            "ay lead to code execution. This vulnerability was chained with CVE",
            "-2023-41061."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41179",
        vendor: "Trend Micro",
        product: "Apex One and Worry-Free Business Security",
        cpe23: concat!(
            "cpe:2.3:a:trend_micro:apex_one_and_worry-free_business_security:*:",
            "*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One and Worry-Free Business Security contain an u",
            "nspecified vulnerability in the third-party anti-virus uninstaller",
            " that could allow an attacker to manipulate the module to conduct ",
            "remote code execution. An attacker must first obtain administrativ",
            "e console access on the target system in order to exploi"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41265",
        vendor: "Qlik",
        product: "Sense",
        cpe23: "cpe:2.3:a:qlik:sense:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Qlik Sense contains an HTTP tunneling vulnerability that allows an",
            " attacker to escalate privileges and execute HTTP requests on the ",
            "backend server hosting the software."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41266",
        vendor: "Qlik",
        product: "Sense",
        cpe23: "cpe:2.3:a:qlik:sense:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Qlik Sense contains a path traversal vulnerability that allows a r",
            "emote, unauthenticated attacker to create an anonymous session by ",
            "sending maliciously crafted HTTP requests. This anonymous session ",
            "could allow the attacker to send further requests to unauthorized ",
            "endpoints."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41338",
        vendor: "pocketbase",
        product: "pocketbase",
        cpe23: "cpe:2.3:a:pocketbase:pocketbase:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated PocketBase (< 0.18.0) Filter Advisory",
        remediation: "PocketBase ni 0.22+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-41763",
        vendor: "Microsoft",
        product: "Skype for Business",
        cpe23: "cpe:2.3:a:microsoft:skype_for_business:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Skype for Business contains an unspecified vulnerability",
            " that allows for privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41913",
        vendor: "strongswan",
        product: "strongswan",
        cpe23: "cpe:2.3:a:strongswan:strongswan:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-787",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "strongSwan (< 5.9.12) IKEv2 EAP Buffer Handling Advisory",
        remediation: "strongSwan IPsec xizmatini 5.9.12+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-41974",
        vendor: "Apple",
        product: "iOS and iPadOS",
        cpe23: "cpe:2.3:a:apple:ios_and_ipados:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and iPadOS contain a use-after-free vulnerability. An ap",
            "p may be able to execute arbitrary code with kernel privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41990",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and watchOS contain an unspecified",
            " vulnerability that allows for code execution when processing a fo",
            "nt file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41991",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS contain an improper certific",
            "ate validation vulnerability that can allow a malicious app to byp",
            "ass signature validation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41992",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS contain an unspecified vulne",
            "rability that allows for local privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-41993",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain an unspecified",
            " vulnerability that leads to code execution when processing malici",
            "ously crafted web content. This vulnerability could impact HTML pa",
            "rsers that use WebKit, including but not limited to Apple Safari a",
            "nd non-Apple products which rely on WebKit for HTML proc"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4211",
        vendor: "Arm",
        product: "Mali GPU Kernel Driver",
        cpe23: "cpe:2.3:a:arm:mali_gpu_kernel_driver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Mali GPU Kernel Driver contains a use-after-free vulnerability",
            " that allows a local, non-privileged user to make improper GPU mem",
            "ory processing operations to gain access to already freed memory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-42115",
        vendor: "exim",
        product: "exim",
        cpe23: "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-787",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Exim MTA (< 4.96.2) Memory Safety Advisory",
        remediation: "Exim pochta serverini 4.97+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-42326",
        vendor: "netgate",
        product: "pfsense",
        cpe23: "cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Netgate pfSense (< 2.7.1) WebGUI Input Validation Advisory",
        remediation: "pfSense ni 2.7.2+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-42793",
        vendor: "JetBrains",
        product: "TeamCity",
        cpe23: "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "JetBrains TeamCity contains an authentication bypass vulnerability",
            " that allows for remote code execution on TeamCity Server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-42824",
        vendor: "Apple",
        product: "iOS and iPadOS",
        cpe23: "cpe:2.3:a:apple:ios_and_ipados:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and iPadOS contain an unspecified vulnerability that all",
            "ows for local privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-42916",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain an out-of-boun",
            "ds read vulnerability that may disclose sensitive information when",
            " processing maliciously crafted web content. This vulnerability co",
            "uld impact HTML parsers that use WebKit, including but not limited",
            " to Apple Safari and non-Apple products which rely on We"
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-42917",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and Safari WebKit contain a memory corru",
            "ption vulnerability that leads to code execution when processing m",
            "aliciously crafted web content. This vulnerability could impact HT",
            "ML parsers that use WebKit, including but not limited to Apple Saf",
            "ari and non-Apple products which rely on WebKit for HTML"
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-43000",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple macOS, iOS, iPadOS, and Safari 16.6 contain a use-after-free",
            " vulnerability due to the processing of maliciously crafted web co",
            "ntent that may lead to memory corruption."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-43040",
        vendor: "ceph",
        product: "ceph",
        cpe23: "cpe:2.3:a:ceph:ceph:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Ceph Storage (< 18.2.1) RGW Bucket Policy Advisory",
        remediation: "Ceph Reef 18.2.1+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-43208",
        vendor: "NextGen Healthcare",
        product: "Mirth Connect",
        cpe23: "cpe:2.3:a:nextgen_healthcare:mirth_connect:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "NextGen Healthcare Mirth Connect contains a deserialization of unt",
            "rusted data vulnerability that allows for unauthenticated remote c",
            "ode execution via a specially crafted request."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4346",
        vendor: "KNX Association",
        product: "KNX Protocol Connection Authorization Option 1",
        cpe23: concat!(
            "cpe:2.3:a:knx_association:knx_protocol_connection_authorization_op",
            "tion_1:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "KNX Association KNX Protocol Connection Authorization Option 1 con",
            "tains an overly restrictive account lockout mechanism vulnerabilit",
            "y that could allow an attacker to purge all devices without additi",
            "onal security options enabled and set a BCU key to lock the device",
            "."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-43770",
        vendor: "Roundcube",
        product: "Webmail",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail contains a persistent cross-site scripting (XSS)",
            " vulnerability that can lead to information disclosure via malicio",
            "us link references in plain/text messages."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-44221",
        vendor: "SonicWall",
        product: "SMA100 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma100_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SonicWall SMA100 appliances contain an OS command injection vulner",
            "ability in the SSL-VPN management interface that allows a remote, ",
            "authenticated attacker with administrative privilege to inject arb",
            "itrary commands as a 'nobody' user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-44270",
        vendor: "npm",
        product: "postcss",
        cpe23: "cpe:2.3:a:npm:postcss:*:*:*:*:*:*:*:*",
        cvss_x10: 53, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm postcss vulnerability advisory",
        remediation: "Upgrade postcss to >= 8.4.31",
    },
    KevCveRecord {
        cve_id: "CVE-2023-44487",
        vendor: "nic",
        product: "bird",
        cpe23: "cpe:2.3:a:nic:bird:*:*:*:*:*:*:*:*",
        cvss_x10: 59, severity: "Medium", cwe: "CWE-400",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Outdated BIRD Routing Daemon (< 2.14.0) Advisory",
        remediation: "BIRD daemonini 2.15+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-44981",
        vendor: "apache",
        product: "zookeeper",
        cpe23: "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-285",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache ZooKeeper (< 3.8.3) SASL Quorum Authorization Advisory",
        remediation: "Apache ZooKeeper ni 3.8.3+ / 3.9.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-45136",
        vendor: "openproject",
        product: "openproject",
        cpe23: "cpe:2.3:a:openproject:openproject:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-79",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "OpenProject (< 13.0.6) Attachment Advisory",
        remediation: "OpenProject ni 13.4+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-45249",
        vendor: "Acronis",
        product: "Cyber Infrastructure (ACI)",
        cpe23: "cpe:2.3:a:acronis:cyber_infrastructure_aci:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Acronis Cyber Infrastructure (ACI) allows an unauthenticated user ",
            "to execute commands remotely due to the use of default passwords."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-45288",
        vendor: "go",
        product: "golang.org/x/net",
        cpe23: "cpe:2.3:a:go:golang.org_x_net:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Go golang.org/x/net vulnerability advisory",
        remediation: "Upgrade golang.org/x/net to >= 0.23.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-45727",
        vendor: "North Grid",
        product: "Proself",
        cpe23: "cpe:2.3:a:north_grid:proself:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "North Grid Proself Enterprise/Standard, Gateway, and Mail Sanitize",
            " contain an improper restriction of XML External Entity (XXE) refe",
            "rence vulnerability, which could allow a remote, unauthenticated a",
            "ttacker to conduct an XXE attack."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-45803",
        vendor: "pypi",
        product: "urllib3",
        cpe23: "cpe:2.3:a:pypi:urllib3:*:*:*:*:*:*:*:*",
        cvss_x10: 42, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI urllib3 vulnerability advisory",
        remediation: "Upgrade urllib3 to >= 2.0.7",
    },
    KevCveRecord {
        cve_id: "CVE-2023-45857",
        vendor: "npm",
        product: "axios",
        cpe23: "cpe:2.3:a:npm:axios:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm axios vulnerability advisory",
        remediation: "Upgrade axios to >= 1.6.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-46118",
        vendor: "vmware",
        product: "rabbitmq",
        cpe23: "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated RabbitMQ (< 3.12.6) Management API Advisory",
        remediation: "RabbitMQ brokerini 3.12.14+ yoki 3.13+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-46233",
        vendor: "typesense",
        product: "typesense",
        cpe23: "cpe:2.3:a:typesense:typesense:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Typesense (< 0.25.2) Search Key Advisory",
        remediation: "Typesense ni 26.0+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-46604",
        vendor: "apache",
        product: "activemq",
        cpe23: "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
        cvss_x10: 100, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 970,
        summary: "Apache ActiveMQ (< 5.18.3) OpenWire Class Instantiation Advisory",
        remediation: concat!(
            "Apache ActiveMQ brokerini 5.18.3+ yoki 6.0+ versiyasiga zudlik bil",
            "an yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-46747",
        vendor: "f5",
        product: "f5_bigip",
        cpe23: "cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 968,
        summary: "F5 BIG-IP TMUI Configuration Utility Auth Bypass Advisory",
        remediation: "F5 BIG-IP ni 17.1.1+ ga yangilang va TMUI portini yoping.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-46748",
        vendor: "F5",
        product: "BIG-IP Configuration Utility",
        cpe23: "cpe:2.3:a:f5:big-ip_configuration_utility:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "F5 BIG-IP Configuration utility contains an SQL injection vulnerab",
            "ility that may allow an authenticated attacker with network access",
            " through the BIG-IP management port and/or self IP addresses to ex",
            "ecute system commands. This vulnerability can be used in conjuncti",
            "on with CVE-2023-46747."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-46805",
        vendor: "Ivanti",
        product: "Connect Secure and Policy Secure",
        cpe23: "cpe:2.3:a:ivanti:connect_secure_and_policy_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Connect Secure (ICS, formerly known as Pulse Connect Secure",
            ") and Ivanti Policy Secure gateways contain an authentication bypa",
            "ss vulnerability in the web component that allows an attacker to a",
            "ccess restricted resources by bypassing control checks. This vulne",
            "rability can be leveraged in conjunction with CVE-2024-2"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-46846",
        vendor: "squid-cache",
        product: "squid",
        cpe23: "cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*",
        cvss_x10: 86, severity: "High", cwe: "CWE-444",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Squid Proxy (< 6.6) Chunked Request Parsing Advisory",
        remediation: "Squid kesh-proksi serverini 6.6+ xavfsizlik versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-46852",
        vendor: "memcached",
        product: "memcached",
        cpe23: "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-120",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Memcached (< 1.6.22) Buffer Handling Advisory",
        remediation: concat!(
            "Memcached xizmatini 1.6.22+ versiyasiga yangilang va lokal interfe",
            "ysga bog'lang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-47122",
        vendor: "npm",
        product: "dompurify",
        cpe23: "cpe:2.3:a:npm:dompurify:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm dompurify vulnerability advisory",
        remediation: "Upgrade dompurify to >= 2.4.2",
    },
    KevCveRecord {
        cve_id: "CVE-2023-47235",
        vendor: "frrouting",
        product: "frrouting",
        cpe23: "cpe:2.3:a:frrouting:frrouting:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-476",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "FRRouting (< 9.0.2) BGP Attribute Parsing Advisory",
        remediation: "FRRouting paketini 9.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-47246",
        vendor: "SysAid",
        product: "SysAid Server",
        cpe23: "cpe:2.3:a:sysaid:sysaid_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SysAid Server (on-premises version) contains a path traversal vuln",
            "erability that leads to code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-47565",
        vendor: "QNAP",
        product: "VioStor NVR",
        cpe23: "cpe:2.3:a:qnap:viostor_nvr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "QNAP VioStar NVR contains an OS command injection vulnerability th",
            "at allows authenticated users to execute commands via a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4762",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains a type confusion vulnerability that al",
            "lows a remote attacker to execute code via a crafted HTML page. Th",
            "is vulnerability could affect multiple web browsers that utilize C",
            "hromium, including, but not limited to, Google Chrome, Microsoft E",
            "dge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-47891",
        vendor: "apache",
        product: "flink",
        cpe23: "cpe:2.3:a:apache:flink:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Apache Flink (< 1.18.1) Cluster REST Advisory",
        remediation: "Apache Flink klasterini 1.18.1+ / 1.19+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-48022",
        vendor: "anyscale",
        product: "ray",
        cpe23: "cpe:2.3:a:anyscale:ray:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Anyscale Ray (< 2.8.1) Unauthenticated Jobs Submission API Advisor",
            "y"
        ),
        remediation: "Ray Dashboard `:8265` portini faqat `127.0.0.1` ga bog'lang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-48222",
        vendor: "opnsense",
        product: "opnsense",
        cpe23: "cpe:2.3:a:opnsense:opnsense:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-79",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated OPNsense (< 23.7.8) Firewall UI Advisory",
        remediation: "OPNsense ni 24.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-48365",
        vendor: "Qlik",
        product: "Sense",
        cpe23: "cpe:2.3:a:qlik:sense:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Qlik Sense contains an HTTP tunneling vulnerability that allows an",
            " attacker to escalate privileges and execute HTTP requests on the ",
            "backend server hosting the software."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4863",
        vendor: "Google",
        product: "Chromium WebP",
        cpe23: "cpe:2.3:a:google:chromium_webp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium WebP contains a heap-based buffer overflow vulnera",
            "bility that allows a remote attacker to perform an out-of-bounds m",
            "emory write via a crafted HTML page. This vulnerability can affect",
            " applications that use the WebP Codec."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-48788",
        vendor: "Fortinet",
        product: "FortiClient EMS",
        cpe23: "cpe:2.3:a:fortinet:forticlient_ems:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiClient EMS contains a SQL injection vulnerability th",
            "at allows an unauthenticated attacker to execute commands as SYSTE",
            "M via specifically crafted requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-48795",
        vendor: "vyos",
        product: "vyos",
        cpe23: "cpe:2.3:a:vyos:vyos:*:*:*:*:*:*:*:*",
        cvss_x10: 59, severity: "Medium", cwe: "CWE-354",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated VyOS (< 1.4.0) SSH Transport Advisory",
        remediation: "VyOS marshrutizator tizimini 1.4+ LTS ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-49070",
        vendor: "apache",
        product: "apisix",
        cpe23: "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Apache APISIX (< 3.8.0) Gateway Policy Advisory",
        remediation: "Apache APISIX shlyuzini 3.9+ LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-49103",
        vendor: "owncloud",
        product: "owncloud",
        cpe23: "cpe:2.3:a:owncloud:owncloud:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "ownCloud (< 10.13.4) GraphAPI Environment Configuration Advisory",
        remediation: concat!(
            "ownCloud tizimini 10.13.4+ / 10.14+ reliziga yangilang va graphapi",
            " test fayllarini o'chiring."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-49105",
        vendor: "ownCloud",
        product: "ownCloud",
        cpe23: "cpe:2.3:a:owncloud:owncloud:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ownCloud contains an improper authentication vulnerability that al",
            "lows an attacker to access, modify, or delete any file without aut",
            "hentication if the username of a victim is known, and the victim h",
            "as no signing-key configured."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4911",
        vendor: "GNU",
        product: "GNU C Library",
        cpe23: "cpe:2.3:a:gnu:gnu_c_library:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GNU C Library's dynamic loader ld.so contains a buffer overflow vu",
            "lnerability when processing the GLIBC_TUNABLES environment variabl",
            "e, allowing a local attacker to execute code with elevated privile",
            "ges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-4966",
        vendor: "citrix",
        product: "citrix_adc",
        cpe23: "cpe:2.3:a:citrix:application_delivery_controller:*:*:*:*:*:*:*:*",
        cvss_x10: 94, severity: "Critical", cwe: "CWE-119",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "Citrix NetScaler ADC (< 14.1) Session Memory Disclosure Advisory",
        remediation: concat!(
            "Citrix NetScaler ADC qurilmasini eng so'nggi xavfsizlik buildiga y",
            "angilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-49803",
        vendor: "bookstackapp",
        product: "bookstack",
        cpe23: "cpe:2.3:a:bookstackapp:bookstack:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-918",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "BookStack (< 23.10.4) SSRF Filter Advisory",
        remediation: "BookStack ni 23.12+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-49897",
        vendor: "FXC",
        product: "AE1021, AE1021PE",
        cpe23: "cpe:2.3:a:fxc:ae1021_ae1021pe:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "FXC AE1021 and AE1021PE contain an OS command injection vulnerabil",
            "ity that allows authenticated users to execute commands via a netw",
            "ork."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-50164",
        vendor: "apache",
        product: "struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache Struts (< 6.3.0.2) File Upload Path Traversal Advisory",
        remediation: concat!(
            "Apache Struts ni 6.3.0.2+ yoki 6.4+ versiyasiga zudlik bilan yangi",
            "lang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-50224",
        vendor: "TP-Link",
        product: "TL-WR841N",
        cpe23: "cpe:2.3:a:tp-link:tl-wr841n:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TP-Link TL-WR841N contains an authentication bypass by spoofing vu",
            "lnerability within the httpd service, which listens on TCP port 80",
            " by default, leading to the disclose of stored credentials. The im",
            "pacted products could be end-of-life (EoL) and/or end-of-service (",
            "EoS). Users should discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-50298",
        vendor: "apache",
        product: "solr",
        cpe23: "cpe:2.3:a:apache:solr:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Apache Solr (< 9.4.1) ConfigSet Environment Disclosure Advisory",
        remediation: "Apache Solr tizimini 9.4.1+ / 9.6+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-50387",
        vendor: "nlnetlabs",
        product: "unbound",
        cpe23: "cpe:2.3:a:nlnetlabs:unbound:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "NLnet Labs Unbound (< 1.19.1) DNSSEC KeyTrap Advisory",
        remediation: "Unbound DNS resolverini 1.19.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-50447",
        vendor: "pypi",
        product: "pillow",
        cpe23: "cpe:2.3:a:pypi:pillow:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI pillow vulnerability advisory",
        remediation: "Upgrade pillow to >= 10.2.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-50782",
        vendor: "pypi",
        product: "cryptography",
        cpe23: "cpe:2.3:a:pypi:cryptography:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI cryptography vulnerability advisory",
        remediation: "Upgrade cryptography to >= 42.0.0",
    },
    KevCveRecord {
        cve_id: "CVE-2023-50868",
        vendor: "nic",
        product: "knot_resolver",
        cpe23: "cpe:2.3:a:nic:knot_resolver:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Knot Resolver (< 5.7.1) DNSSEC Advisory",
        remediation: "Knot Resolver ni 5.7.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-5157",
        vendor: "mariadb",
        product: "mariadb",
        cpe23: "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated MariaDB 10.6 (< 10.6.17) Security Advisory",
        remediation: "MariaDB 10.6 LTS tarmog'ini 10.6.18+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-51764",
        vendor: "postfix",
        product: "postfix",
        cpe23: "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-444",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Postfix 3.8 (< 3.8.4) SMTP Smuggling Advisory",
        remediation: "Postfix 3.8 tarmog'ini 3.8.4+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-52163",
        vendor: "Digiever",
        product: "DS-2105 Pro",
        cpe23: "cpe:2.3:a:digiever:ds-2105_pro:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Digiever DS-2105 Pro contains a missing authorization vulnerabilit",
            "y which could allow for command injection via time_tzsetup.cgi."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-5217",
        vendor: "Google",
        product: "Chromium libvpx",
        cpe23: "cpe:2.3:a:google:chromium_libvpx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium libvpx contains a heap buffer overflow vulnerabili",
            "ty in vp8 encoding that allows a remote attacker to potentially ex",
            "ploit heap corruption via a crafted HTML page. This vulnerability ",
            "could impact web browsers using libvpx, including but not limited ",
            "to Google Chrome."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-5631",
        vendor: "Roundcube",
        product: "Webmail",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail contains a persistent cross-site scripting (XSS)",
            " vulnerability that allows a remote attacker to run malicious Java",
            "Script code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-5685",
        vendor: "redhat",
        product: "wildfly",
        cpe23: "cpe:2.3:a:redhat:wildfly:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated WildFly (< 30.0.1) Application Server Advisory",
        remediation: "WildFly ni 31.0+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2023-6345",
        vendor: "Google",
        product: "Chromium Skia",
        cpe23: "cpe:2.3:a:google:chromium_skia:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Skia contains an integer overflow vulnerability th",
            "at allows a remote attacker, who has compromised the renderer proc",
            "ess, to potentially perform a sandbox escape via a malicious file.",
            " This vulnerability affects Google Chrome and ChromeOS, Android, F",
            "lutter, and possibly other products."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-6378",
        vendor: "maven",
        product: "ch.qos.logback:logback-core",
        cpe23: "cpe:2.3:a:maven:ch.qos.logback_logback-core:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Maven ch.qos.logback:logback-core vulnerability advisory",
        remediation: "Upgrade ch.qos.logback:logback-core to >= 1.4.14",
    },
    KevCveRecord {
        cve_id: "CVE-2023-6448",
        vendor: "Unitronics",
        product: "Vision PLC and HMI",
        cpe23: "cpe:2.3:a:unitronics:vision_plc_and_hmi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unitronics Vision Series PLCs and HMIs ship with an insecure defau",
            "lt password, which if left unchanged, can allow attackers to execu",
            "te remote commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-6548",
        vendor: "Citrix",
        product: "NetScaler ADC and NetScaler Gateway",
        cpe23: concat!(
            "cpe:2.3:a:citrix:netscaler_adc_and_netscaler_gateway:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain a code injectio",
            "n vulnerability that allows for authenticated remote code executio",
            "n on the management interface with access to NSIP, CLIP, or SNIP."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-6549",
        vendor: "Citrix",
        product: "NetScaler ADC and NetScaler Gateway",
        cpe23: concat!(
            "cpe:2.3:a:citrix:netscaler_adc_and_netscaler_gateway:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain a buffer overfl",
            "ow vulnerability that allows for a denial-of-service when configur",
            "ed as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) o",
            "r AAA virtual server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-7024",
        vendor: "Google",
        product: "Chromium WebRTC",
        cpe23: "cpe:2.3:a:google:chromium_webrtc:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium WebRTC, an open-source project providing web brows",
            "ers with real-time communication, contains a heap buffer overflow ",
            "vulnerability that allows a remote attacker to potentially exploit",
            " heap corruption via a crafted HTML page. This vulnerability could",
            " impact web browsers using WebRTC, including but not lim"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-7028",
        vendor: "gitlab",
        product: "gitlab",
        cpe23: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
        cvss_x10: 100, severity: "Critical", cwe: "CWE-640",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "GitLab (< 16.7.2) Password Reset Account Takeover Advisory",
        remediation: concat!(
            "GitLab CE/EE instansiyasini 16.11+ yoki 17.x versiyasiga yangilang",
            "."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2023-7101",
        vendor: "Spreadsheet::ParseExcel",
        product: "Spreadsheet::ParseExcel",
        cpe23: concat!(
            "cpe:2.3:a:spreadsheet_parseexcel:spreadsheet_parseexcel:*:*:*:*:*:",
            "*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Spreadsheet::ParseExcel contains a remote code execution vulnerabi",
            "lity due to passing unvalidated input from a file into a string-ty",
            "pe “eval”. Specifically, the issue stems from the evaluation of Nu",
            "mber format strings within the Excel parsing logic."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-0012",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains an authentication bypass vulner",
            "ability in the web-based management interface for several PAN-OS p",
            "roducts, including firewalls and VPN concentrators."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable. Additionally, management",
            " interface for affected devices should not be exposed to untrusted",
            " networks, including the internet."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-0056",
        vendor: "nuget",
        product: "microsoft.data.sqlclient",
        cpe23: "cpe:2.3:a:nuget:microsoft.data.sqlclient:*:*:*:*:*:*:*:*",
        cvss_x10: 87, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "NuGet microsoft.data.sqlclient vulnerability advisory",
        remediation: "Upgrade microsoft.data.sqlclient to >= 5.1.4",
    },
    KevCveRecord {
        cve_id: "CVE-2024-0087",
        vendor: "nvidia",
        product: "triton_server",
        cpe23: "cpe:2.3:a:nvidia:triton_inference_server:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "NVIDIA Triton (< 24.04) Shared Memory Advisory",
        remediation: "Triton Serverni 24.05+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-0519",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an out-of-bounds memory access ",
            "vulnerability that allows a remote attacker to potentially exploit",
            " heap corruption via a crafted HTML page. This vulnerability could",
            " affect multiple web browsers that utilize Chromium, including, bu",
            "t not limited to, Google Chrome, Microsoft Edge, and Ope"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
];
