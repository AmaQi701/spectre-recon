// SPECTRE Rust Static .rodata CVE & KEV Shard (KEV_CVE_PART3)

use crate::rust_kev_cve_part1::KevCveRecord;

pub static KEV_CVE_PART3: &[KevCveRecord] = &[
    KevCveRecord {
        cve_id: "CVE-2024-0769",
        vendor: "D-Link",
        product: "DIR-859 Router",
        cpe23: "cpe:2.3:a:d-link:dir-859_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-859 routers contain a path traversal vulnerability in t",
            "he file /hedwig.cgi of the component HTTP POST Request Handler. Ma",
            "nipulation of the argument service with the input ../../../../htdo",
            "cs/webinc/getcfg/DHCPS6.BRIDGE-1.xml allows for the leakage of ses",
            "sion data potentially enabling privilege escalation and "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-0985",
        vendor: "postgresql",
        product: "postgresql",
        cpe23: "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
        cvss_x10: 80, severity: "High", cwe: "CWE-269",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated PostgreSQL 16 (< 16.2) Security Advisory",
        remediation: "PostgreSQL 16 tarmog'ini 16.2+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-10441",
        vendor: "Synology",
        product: "DiskStation Manager (DSM)",
        cpe23: "cpe:2.3:a:synology:diskstation_manager_dsm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synology DSM contains an improper encoding or escaping of output v",
            "ulnerability in the system plugin daemon in Synology BeeStation OS",
            " (BSM) that could allow a remote attacker to execute arbitrary cod",
            "e via unspecified vectors."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-1086",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Linux kernel contains a use-after-free vulnerability in the netfil",
            "ter: nf_tables component that allows an attacker to achieve local ",
            "privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-11120",
        vendor: "GeoVision",
        product: "Multiple Devices",
        cpe23: "cpe:2.3:a:geovision:multiple_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple GeoVision devices contain an OS command injection vulnera",
            "bility that allows a remote, unauthenticated attacker to inject an",
            "d execute arbitrary system commands. The impacted products could b",
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
        cve_id: "CVE-2024-11182",
        vendor: "MDaemon",
        product: "Email Server",
        cpe23: "cpe:2.3:a:mdaemon:email_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MDaemon Email Server contains a cross-site scripting (XSS) vulnera",
            "bility that allows a remote attacker to load arbitrary JavaScript ",
            "code via an HTML e-mail message."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-1135",
        vendor: "pypi",
        product: "gunicorn",
        cpe23: "cpe:2.3:a:pypi:gunicorn:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI gunicorn vulnerability advisory",
        remediation: "Upgrade gunicorn to >= 22.0.0",
    },
    KevCveRecord {
        cve_id: "CVE-2024-11667",
        vendor: "Zyxel",
        product: "Multiple Firewalls",
        cpe23: "cpe:2.3:a:zyxel:multiple_firewalls:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Multiple Zyxel firewalls contain a path traversal vulnerability in",
            " the web management interface that could allow an attacker to down",
            "load or upload files via a crafted URL."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-11680",
        vendor: "ProjectSend",
        product: "ProjectSend",
        cpe23: "cpe:2.3:a:projectsend:projectsend:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ProjectSend contains an improper authentication vulnerability that",
            " allows a remote, unauthenticated attacker to enable unauthorized ",
            "modification of the application's configuration via crafted HTTP r",
            "equests to options.php. Successful exploitation allows attackers t",
            "o create accounts, upload webshells, and embed malicious"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-1212",
        vendor: "Progress",
        product: "Kemp LoadMaster",
        cpe23: "cpe:2.3:a:progress:kemp_loadmaster:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Progress Kemp LoadMaster contains an OS command injection vulnerab",
            "ility that allows an unauthenticated, remote attacker to access th",
            "e system through the LoadMaster management interface, enabling arb",
            "itrary system command execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-12356",
        vendor: "BeyondTrust",
        product: "Privileged Remote Access (PRA) and Remote Support (RS)",
        cpe23: concat!(
            "cpe:2.3:a:beyondtrust:privileged_remote_access_pra_and_remote_supp",
            "ort_rs:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS)",
            " contain a command injection vulnerability, which can allow an una",
            "uthenticated attacker to inject commands that are run as a site us",
            "er."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-12686",
        vendor: "BeyondTrust",
        product: "Privileged Remote Access (PRA) and Remote Support (RS)",
        cpe23: concat!(
            "cpe:2.3:a:beyondtrust:privileged_remote_access_pra_and_remote_supp",
            "ort_rs:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS)",
            " contain an OS command injection vulnerability that can be exploit",
            "ed by an attacker with existing administrative privileges to uploa",
            "d a malicious file. Successful exploitation of this vulnerability ",
            "can allow a remote attacker to execute underlying operat"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-12987",
        vendor: "DrayTek",
        product: "Vigor Routers",
        cpe23: "cpe:2.3:a:draytek:vigor_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "DrayTek Vigor2960, Vigor300B, and Vigor3900 routers contain an OS ",
            "command injection vulnerability due to an unknown function of the ",
            "file /cgi-bin/mainfunction.cgi/apmcfgupload of the component web m",
            "anagement interface."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-13159",
        vendor: "Ivanti",
        product: "Endpoint Manager (EPM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_epm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager (EPM) contains an absolute path traversal ",
            "vulnerability that allows a remote unauthenticated attacker to lea",
            "k sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-13160",
        vendor: "Ivanti",
        product: "Endpoint Manager (EPM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_epm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager (EPM) contains an absolute path traversal ",
            "vulnerability that allows a remote unauthenticated attacker to lea",
            "k sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-13161",
        vendor: "Ivanti",
        product: "Endpoint Manager (EPM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_epm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager (EPM) contains an absolute path traversal ",
            "vulnerability that allows a remote unauthenticated attacker to lea",
            "k sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-1351",
        vendor: "mongodb",
        product: "mongodb",
        cpe23: "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-295",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated MongoDB 7.0 (< 7.0.6) Certificate Validation Advisory",
        remediation: "MongoDB 7.0 tarmog'ini 7.0.6+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-1561",
        vendor: "gradio_project",
        product: "gradio",
        cpe23: "cpe:2.3:a:gradio_project:gradio:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Gradio (< 4.19.2) Arbitrary File Read via Component API Advisory",
        remediation: "Gradio kutubxonasini 4.36+ xavfsiz reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-1597",
        vendor: "atlassian",
        product: "bamboo",
        cpe23: "cpe:2.3:a:atlassian:bamboo:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Atlassian Bamboo (< 9.6.1) Data Center Dependency Advisory",
        remediation: "Atlassian Bamboo serverini 9.6.1+ LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-1708",
        vendor: "ConnectWise",
        product: "ScreenConnect",
        cpe23: "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "ConnectWise ScreenConnect contains a path traversal vulnerability ",
            "which could allow an attacker to execute remote code or directly i",
            "mpact confidential data and critical systems."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-1709",
        vendor: "ConnectWise",
        product: "ScreenConnect",
        cpe23: "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "ConnectWise ScreenConnect contains an authentication bypass vulner",
            "ability that allows an attacker with network access to the managem",
            "ent interface to create a new, administrator-level account on affe",
            "cted devices."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-1737",
        vendor: "isc",
        product: "bind",
        cpe23: "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "ISC BIND 9 (< 9.18.28) DNS Database Resolver Resource Advisory",
        remediation: "ISC BIND DNS paketini 9.18.28+ yoki 9.20+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-20353",
        vendor: "Cisco",
        product: concat!(
            "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FT",
            "D)"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:adaptive_security_appliance_asa_and_firepower_thre",
            "at_defense_ftd:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defen",
            "se (FTD) contain an infinite loop vulnerability that can lead to r",
            "emote denial of service condition."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-20359",
        vendor: "Cisco",
        product: concat!(
            "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FT",
            "D)"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:adaptive_security_appliance_asa_and_firepower_thre",
            "at_defense_ftd:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defen",
            "se (FTD) contain a privilege escalation vulnerability that can all",
            "ow local privilege escalation from Administrator to root."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-20399",
        vendor: "Cisco",
        product: "NX-OS",
        cpe23: "cpe:2.3:a:cisco:nx-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco NX-OS contains a command injection vulnerability in the comm",
            "and line interface (CLI) that could allow an authenticated, local ",
            "attacker to execute commands as root on the underlying operating s",
            "ystem of an affected device."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-20439",
        vendor: "Cisco",
        product: "Smart Licensing Utility",
        cpe23: "cpe:2.3:a:cisco:smart_licensing_utility:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Smart Licensing Utility contains a static credential vulnera",
            "bility that allows an unauthenticated, remote attacker to log in t",
            "o an affected system and gain administrative credentials."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-20481",
        vendor: "Cisco",
        product: concat!(
            "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FT",
            "D)"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:adaptive_security_appliance_asa_and_firepower_thre",
            "at_defense_ftd:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defen",
            "se (FTD) contain a missing release of resource after effective lif",
            "etime vulnerability that could allow an unauthenticated, remote at",
            "tacker to cause a denial-of-service (DoS) of the RAVPN service."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-20767",
        vendor: "adobe",
        product: "coldfusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Adobe ColdFusion (< 2023.0.7) Access Control Advisory",
        remediation: "ColdFusion serverini yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-20953",
        vendor: "Oracle",
        product: "Agile Product Lifecycle Management (PLM)",
        cpe23: concat!(
            "cpe:2.3:a:oracle:agile_product_lifecycle_management_plm:*:*:*:*:*:",
            "*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Agile Product Lifecycle Management (PLM) contains a deseria",
            "lization vulnerability that allows a low-privileged attacker with ",
            "network access via HTTP to compromise the system."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-20960",
        vendor: "oracle",
        product: "mysql",
        cpe23: "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated MySQL 8.0 (< 8.0.36) Critical Patch Update Advisory",
        remediation: "MySQL 8.0 serverini 8.0.36+ yoki 8.4 LTS reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-21182",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic contains an unspecified vulnerability that could a",
            "llow an unauthenticated attacker with network access via T3, IIOP ",
            "to compromise Oracle WebLogic Server. Successful attacks of this v",
            "ulnerability can result in unauthorized access to critical data or",
            " complete access to all Oracle WebLogic Server accessibl"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21287",
        vendor: "Oracle",
        product: "Agile Product Lifecycle Management (PLM)",
        cpe23: concat!(
            "cpe:2.3:a:oracle:agile_product_lifecycle_management_plm:*:*:*:*:*:",
            "*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Agile Product Lifecycle Management (PLM) contains an incorr",
            "ect authorization vulnerability in the Process Extension component",
            " of the Software Development Kit. Successful exploitation of this ",
            "vulnerability may result in unauthenticated file disclosure."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21338",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Kernel contains an exposed IOCTL with insufficie",
            "nt access control vulnerability within the IOCTL (input and output",
            " control) dispatcher in appid.sys that allows a local attacker to ",
            "achieve privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21351",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows SmartScreen contains a security feature bypass v",
            "ulnerability that allows an attacker to bypass the SmartScreen use",
            "r experience and inject code to potentially gain code execution, w",
            "hich could lead to some data exposure, lack of system availability",
            ", or both."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21410",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Exchange Server contains an unspecified vulnerability th",
            "at allows for privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21412",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Internet Shortcut Files contains an unspecified ",
            "vulnerability that allows for a security feature bypass."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21413",
        vendor: "Microsoft",
        product: "Office Outlook",
        cpe23: "cpe:2.3:a:microsoft:office_outlook:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Outlook contains an improper input validation vulnerabil",
            "ity that allows for remote code execution. Successful exploitation",
            " of this vulnerability would allow an attacker to bypass the Offic",
            "e Protected View and open in editing mode rather than protected mo",
            "de."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21626",
        vendor: "kubernetes",
        product: "cri_o",
        cpe23: "cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*",
        cvss_x10: 86, severity: "High", cwe: "CWE-250",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated CRI-O (< 1.28.4) Container Runtime Advisory",
        remediation: "CRI-O runtime ni 1.29+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-21637",
        vendor: "goauthentik",
        product: "authentik",
        cpe23: "cpe:2.3:a:goauthentik:authentik:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Authentik (< 2024.2.2) Session Token Advisory",
        remediation: "Authentik IdP ni 2024.4+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-21650",
        vendor: "rancher",
        product: "longhorn",
        cpe23: "cpe:2.3:a:rancher:longhorn:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Rancher Longhorn (< 1.5.4) UI Proxy Exposure Advisory",
        remediation: "Longhorn tizimini 1.6+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-21683",
        vendor: "atlassian",
        product: "crucible",
        cpe23: "cpe:2.3:a:atlassian:fisheye:*:*:*:*:*:*:*:*",
        cvss_x10: 83, severity: "High", cwe: "CWE-94",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Atlassian Fisheye / Crucible (< 4.8.14) Template Advisory",
        remediation: "Atlassian Fisheye/Crucible tizimini 4.8.14+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-21762",
        vendor: "fortinet",
        product: "fortios",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-787",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "Fortinet FortiOS (< 7.4.3) SSL-VPN Out-of-Bounds Write Advisory",
        remediation: concat!(
            "FortiOS tizimini 7.4.4+ versiyasiga zudlik bilan yangilang va SSL-",
            "VPN ni cheklang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21887",
        vendor: "ivanti",
        product: "ivanti_connect_secure",
        cpe23: "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "Ivanti Connect Secure Gateway Web Component Advisory",
        remediation: "Ivanti Connect Secure tizimini 22.7R1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-21893",
        vendor: "Ivanti",
        product: "Connect Secure, Policy Secure, and Neurons",
        cpe23: concat!(
            "cpe:2.3:a:ivanti:connect_secure_policy_secure_and_neurons:*:*:*:*:",
            "*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Connect Secure (ICS, formerly known as Pulse Connect Secure",
            "), Ivanti Policy Secure, and Ivanti Neurons contain a server-side ",
            "request forgery (SSRF) vulnerability in the SAML component that al",
            "lows an attacker to access certain restricted resources without au",
            "thentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-21907",
        vendor: "nuget",
        product: "newtonsoft.json",
        cpe23: "cpe:2.3:a:nuget:newtonsoft.json:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "NuGet newtonsoft.json vulnerability advisory",
        remediation: "Upgrade newtonsoft.json to >= 13.0.1",
    },
    KevCveRecord {
        cve_id: "CVE-2024-22120",
        vendor: "zabbix",
        product: "zabbix",
        cpe23: "cpe:2.3:a:zabbix:zabbix:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-89",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Zabbix (< 6.0.31 LTS) Server/Frontend Advisory",
        remediation: "Zabbix monitoring tizimini 6.0.32+ LTS yoki 7.0+ LTS ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-22195",
        vendor: "pypi",
        product: "jinja2",
        cpe23: "cpe:2.3:a:pypi:jinja2:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI jinja2 vulnerability advisory",
        remediation: "Upgrade jinja2 to >= 3.1.3",
    },
    KevCveRecord {
        cve_id: "CVE-2024-22201",
        vendor: "eclipse",
        product: "jetty",
        cpe23: "cpe:2.3:a:eclipse:jetty:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Eclipse Jetty 11 (< 11.0.20) HTTP/2 Advisory",
        remediation: concat!(
            "Eclipse Jetty 11 tarmog'ini 11.0.20+ yoki 12.x versiyasiga yangila",
            "ng."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-22205",
        vendor: "rocket.chat",
        product: "rocketchat",
        cpe23: "cpe:2.3:a:rocket.chat:rocket.chat:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Rocket.Chat (< 6.6.6) Collaboration Server Advisory",
        remediation: "Rocket.Chat serverini 6.7+ LTS xavfsizlik reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-22257",
        vendor: "maven",
        product: "org.springframework.security:spring-security-web",
        cpe23: concat!(
            "cpe:2.3:a:maven:org.springframework.security_spring-security-web:*",
            ":*:*:*:*:*:*:*"
        ),
        cvss_x10: 82, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: concat!(
            "Maven org.springframework.security:spring-security-web vulnerabili",
            "ty advisory"
        ),
        remediation: concat!(
            "Upgrade org.springframework.security:spring-security-web to >= 6.2",
            ".3"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-22278",
        vendor: "linuxfoundation",
        product: "harbor",
        cpe23: "cpe:2.3:a:linuxfoundation:harbor:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Harbor Registry (< 2.10.2) Access Control Advisory",
        remediation: "Harbor Container Registry ni 2.10.3+ yoki 2.11+ ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-22650",
        vendor: "drupal",
        product: "drupal",
        cpe23: "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Drupal 10 (< 10.2.2) Security Advisory",
        remediation: "Drupal 10 tarmog'ini 10.2.2+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-23113",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiOS, FortiPAM, FortiProxy, and FortiWeb contain a for",
            "mat string vulnerability that allows a remote, unauthenticated att",
            "acker to execute arbitrary code or commands via specially crafted ",
            "requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23222",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and Safari WebKit contain a type c",
            "onfusion vulnerability that leads to code execution when processin",
            "g maliciously crafted web content. This vulnerability could impact",
            " HTML parsers that use WebKit, including but not limited to Apple ",
            "Safari and non-Apple products which rely on WebKit for H"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23225",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, watchOS, and visionOS kernel conta",
            "in a memory corruption vulnerability that allows an attacker with ",
            "arbitrary kernel read and write capability to bypass kernel memory",
            " protections."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23296",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and watchOS RTKit contain a memory",
            " corruption vulnerability that allows an attacker with arbitrary k",
            "ernel read and write capability to bypass kernel memory protection",
            "s."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23331",
        vendor: "vmware",
        product: "velero",
        cpe23: "cpe:2.3:a:vmware:velero:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-532",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "VMware Velero (< 1.12.3) Backup Credential Log Advisory",
        remediation: "Velero ni 1.13+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-23334",
        vendor: "pypi",
        product: "aiohttp",
        cpe23: "cpe:2.3:a:pypi:aiohttp:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI aiohttp vulnerability advisory",
        remediation: "Upgrade aiohttp to >= 3.9.2",
    },
    KevCveRecord {
        cve_id: "CVE-2024-23446",
        vendor: "elastic",
        product: "elasticsearch",
        cpe23: "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Elasticsearch 8 (< 8.12.1) Security Advisory",
        remediation: "Elasticsearch 8 tarmog'ini 8.12.2+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-23672",
        vendor: "apache",
        product: "tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Outdated Apache Tomcat (< 9.0.86 / Legacy 7.x–8.5.x) Security Advi",
            "sory"
        ),
        remediation: concat!(
            "Apache Tomcat serverini 9.0.86+, 10.1.19+ yoki 11.x barqaror versi",
            "yasiga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23692",
        vendor: "Rejetto",
        product: "HTTP File Server",
        cpe23: "cpe:2.3:a:rejetto:http_file_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Rejetto HTTP File Server contains an improper neutralization of sp",
            "ecial elements used in a template engine vulnerability. This allow",
            "s a remote, unauthenticated attacker to execute commands on the af",
            "fected system by sending a specially crafted HTTP request."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23832",
        vendor: "joinmastodon",
        product: "mastodon",
        cpe23: "cpe:2.3:a:joinmastodon:mastodon:*:*:*:*:*:*:*:*",
        cvss_x10: 94, severity: "Critical", cwe: "CWE-347",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Mastodon (< 4.2.5) Origin Signature Advisory",
        remediation: "Mastodon ni 4.2.5+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-23897",
        vendor: "jenkins",
        product: "jenkins",
        cpe23: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 958,
        summary: "Jenkins (< 2.442) CLI Argument File Read Advisory",
        remediation: concat!(
            "Jenkins LTS versiyasini 2.452.4+ reliziga yangilang va CLI kirishn",
            "i cheklang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-23952",
        vendor: "litespeedtech",
        product: "litespeed",
        cpe23: "cpe:2.3:a:litespeedtech:litespeed_web_server:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Outdated OpenLiteSpeed / LiteSpeed (< 1.7.19) HTTP Handling Adviso",
            "ry"
        ),
        remediation: "LiteSpeed veb-serverini 1.8.1+ barqaror reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-24497",
        vendor: "wazuh",
        product: "wazuh",
        cpe23: "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Wazuh SIEM (< 4.7.2) Cluster API Validation Advisory",
        remediation: "Wazuh Manager va Dashboard ni 4.8+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-24549",
        vendor: "apache",
        product: "tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Outdated Apache Tomcat 10 (< 10.1.19) HTTP/2 Header Handling Advis",
            "ory"
        ),
        remediation: "Apache Tomcat 10 tarmog'ini 10.1.19+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-24598",
        vendor: "packagist",
        product: "symfony/http-kernel",
        cpe23: "cpe:2.3:a:packagist:symfony_http-kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Packagist symfony/http-kernel vulnerability advisory",
        remediation: "Upgrade symfony/http-kernel to >= 6.4.3",
    },
    KevCveRecord {
        cve_id: "CVE-2024-24762",
        vendor: "pypi",
        product: "fastapi",
        cpe23: "cpe:2.3:a:pypi:fastapi:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI fastapi vulnerability advisory",
        remediation: "Upgrade fastapi to >= 0.109.1",
    },
    KevCveRecord {
        cve_id: "CVE-2024-24919",
        vendor: "checkpoint",
        product: "check_point_gaia",
        cpe23: "cpe:2.3:a:checkpoint:gaia_os:*:*:*:*:*:*:*:*",
        cvss_x10: 86, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "Check Point Security Gateway Information Disclosure Advisory",
        remediation: "Check Point Jumbo Hotfix paketini o'rnating.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-25119",
        vendor: "sensiolabs",
        product: "symfony",
        cpe23: "cpe:2.3:a:sensiolabs:symfony:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Symfony (< 6.4.4 LTS) Security Advisory",
        remediation: "Symfony freymvorkini 6.4.12+ LTS yoki 7.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-25120",
        vendor: "hex",
        product: "phoenix",
        cpe23: "cpe:2.3:a:hex:phoenix:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Hex phoenix vulnerability advisory",
        remediation: "Upgrade phoenix to >= 1.7.11",
    },
    KevCveRecord {
        cve_id: "CVE-2024-26169",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Error Reporting Service contains an improper pri",
            "vilege management vulnerability that allows a local attacker with ",
            "user permissions to gain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-27098",
        vendor: "discourse",
        product: "discourse",
        cpe23: "cpe:2.3:a:discourse:discourse:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Discourse (< 3.2.1) API Input Advisory",
        remediation: "Discourse ni 3.2.2+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27198",
        vendor: "jetbrains",
        product: "teamcity",
        cpe23: "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-288",
        is_kev: true, ransomware: "Known", epss_permille: 966,
        summary: concat!(
            "JetBrains TeamCity (< 2023.11.4) Web Authentication Bypass Advisor",
            "y"
        ),
        remediation: concat!(
            "JetBrains TeamCity CI/CD serverini 2023.11.4+ versiyasiga yangilan",
            "g."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-27199",
        vendor: "JetBrains",
        product: "TeamCity",
        cpe23: "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "JetBrains TeamCity contains a relative path traversal vulnerabilit",
            "y that could allow limited admin actions to be performed."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-27302",
        vendor: "authelia",
        product: "authelia",
        cpe23: "cpe:2.3:a:authelia:authelia:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Authelia (< 4.38.0) OIDC Consent Validation Advisory",
        remediation: "Authelia SSO shlyuzini 4.38+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27316",
        vendor: "apache",
        product: "apache",
        cpe23: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Apache HTTP Server (< 2.4.59) Security Advisory",
        remediation: concat!(
            "Apache HTTP Server ni 2.4.62+ reliziga yoki distribyutor security-",
            "backport paketiga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-27348",
        vendor: "apache",
        product: "hugegraph",
        cpe23: "cpe:2.3:a:apache:hugegraph:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Apache HugeGraph-Server (< 1.3.0) Gremlin Sandbox Advisory",
        remediation: "Apache HugeGraph ni 1.3.0+ ga yangilang va Auth rejimini yoqing.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27351",
        vendor: "pypi",
        product: "django",
        cpe23: "cpe:2.3:a:pypi:django:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI django vulnerability advisory",
        remediation: "Upgrade django to >= 4.2.11",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27443",
        vendor: "synacor",
        product: "zimbra",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 78, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Outdated Zimbra Collaboration Suite (< 10.0.8) Webmail Advisory",
        remediation: concat!(
            "Zimbra Collaboration yamoqlarini eng oxirgi Patch darajasiga yangi",
            "lang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-27459",
        vendor: "openvpn",
        product: "openvpn",
        cpe23: "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*",
        cvss_x10: 78, severity: "High", cwe: "CWE-122",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated OpenVPN (< 2.6.10) Service Handling Advisory",
        remediation: "OpenVPN xizmatini 2.6.10+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27834",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, Safari, tvOS and watchOS 10.5 contain an",
            " improper authentication vulnerability which could allow an attack",
            "er with arbitrary read and write capability to bypass pointer auth",
            "entication."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-27905",
        vendor: "apache",
        product: "airflow",
        cpe23: "cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Apache Airflow (< 2.8.2) DAG Configuration Advisory",
        remediation: "Apache Airflow orkestratorini 2.8.4+ / 2.9+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27918",
        vendor: "victoriametrics",
        product: "victoriametrics",
        cpe23: "cpe:2.3:a:victoriametrics:victoriametrics:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated VictoriaMetrics (< 1.99.0) Metrics UI Advisory",
        remediation: "VictoriaMetrics tizimini 1.101+ LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-27983",
        vendor: "nodejs",
        product: "nodejs",
        cpe23: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Node.js 20 (< 20.12.1) HTTP/2 Frame Handling Advisory",
        remediation: "Node.js 20 LTS tarmog'ini 20.12.2+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-28863",
        vendor: "npm",
        product: "tar",
        cpe23: "cpe:2.3:a:npm:tar:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm tar vulnerability advisory",
        remediation: "Upgrade tar to >= 6.2.1",
    },
    KevCveRecord {
        cve_id: "CVE-2024-28868",
        vendor: "hex",
        product: "jose",
        cpe23: "cpe:2.3:a:hex:jose:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Hex jose vulnerability advisory",
        remediation: "Upgrade jose to >= 1.11.7",
    },
    KevCveRecord {
        cve_id: "CVE-2024-28869",
        vendor: "traefik",
        product: "traefik",
        cpe23: "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Traefik Proxy (< 2.11.2) HTTP/2 Resource Handling Advisory",
        remediation: "Traefik reverse-proxy ni 2.11.6+ yoki 3.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-28986",
        vendor: "SolarWinds",
        product: "Web Help Desk",
        cpe23: "cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Web Help Desk contains a deserialization of untrusted d",
            "ata vulnerability that could allow for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-28987",
        vendor: "SolarWinds",
        product: "Web Help Desk",
        cpe23: "cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Web Help Desk contains a hardcoded credential vulnerabi",
            "lity that could allow a remote, unauthenticated user to access int",
            "ernal functionality and modify data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-28995",
        vendor: "SolarWinds",
        product: "Serv-U",
        cpe23: "cpe:2.3:a:solarwinds:serv-u:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Serv-U contains a path traversal vulnerability that all",
            "ows an attacker access to read sensitive files on the host machine",
            "."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-29028",
        vendor: "trychroma",
        product: "chromadb",
        cpe23: "cpe:2.3:a:trychroma:chroma:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-306",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "ChromaDB (< 0.4.24) Vector Store Authentication Posture Advisory",
        remediation: "ChromaDB ni 0.5+ ga yangilang va token autentifikatsiyani yoqing.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-29041",
        vendor: "npm",
        product: "express",
        cpe23: "cpe:2.3:a:npm:express:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm express vulnerability advisory",
        remediation: "Upgrade express to >= 4.19.2",
    },
    KevCveRecord {
        cve_id: "CVE-2024-29059",
        vendor: "Microsoft",
        product: ".NET Framework",
        cpe23: "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft .NET Framework contains an information disclosure vulner",
            "ability that exposes the ObjRef URI to an attacker, ultimately ena",
            "bling remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-2928",
        vendor: "lfprojects",
        product: "mlflow",
        cpe23: "cpe:2.3:a:lfprojects:mlflow:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "MLflow (< 2.11.3) Artifact URI Traversal Advisory",
        remediation: concat!(
            "MLflow platformasini 2.12.1+ versiyasiga yangilang va autentifikat",
            "siyani yoqing."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-29291",
        vendor: "packagist",
        product: "laravel/framework",
        cpe23: "cpe:2.3:a:packagist:laravel_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Packagist laravel/framework vulnerability advisory",
        remediation: "Upgrade laravel/framework to >= 9.52.16",
    },
    KevCveRecord {
        cve_id: "CVE-2024-29745",
        vendor: "Android",
        product: "Pixel",
        cpe23: "cpe:2.3:a:android:pixel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Pixel contains an information disclosure vulnerability in ",
            "the fastboot firmware used to support unlocking, flashing, and loc",
            "king affected devices."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-29748",
        vendor: "Android",
        product: "Pixel",
        cpe23: "cpe:2.3:a:android:pixel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Pixel contains a privilege escalation vulnerability that a",
            "llows an attacker to interrupt a factory reset triggered by a devi",
            "ce admin app."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-29824",
        vendor: "Ivanti",
        product: "Endpoint Manager (EPM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_epm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager (EPM) contains a SQL injection vulnerabili",
            "ty in Core server that allows an unauthenticated attacker within t",
            "he same network to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-29857",
        vendor: "nuget",
        product: "bouncycastle.cryptography",
        cpe23: "cpe:2.3:a:nuget:bouncycastle.cryptography:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "NuGet bouncycastle.cryptography vulnerability advisory",
        remediation: "Upgrade bouncycastle.cryptography to >= 2.3.1",
    },
    KevCveRecord {
        cve_id: "CVE-2024-29988",
        vendor: "Microsoft",
        product: "SmartScreen Prompt",
        cpe23: "cpe:2.3:a:microsoft:smartscreen_prompt:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SmartScreen Prompt contains a security feature bypass vu",
            "lnerability that allows an attacker to bypass the Mark of the Web ",
            "(MotW) feature. This vulnerability can be chained with CVE-2023-38",
            "831 and CVE-2024-21412 to execute a malicious file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-30040",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows MSHTML Platform contains an unspecified vulnerab",
            "ility that allows for a security feature bypass."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-30051",
        vendor: "Microsoft",
        product: "DWM Core Library",
        cpe23: "cpe:2.3:a:microsoft:dwm_core_library:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft DWM Core Library contains a privilege escalation vulnera",
            "bility that allows an attacker to gain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-30088",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Kernel contains a time-of-check to time-of-use (",
            "TOCTOU) race condition vulnerability that could allow for privileg",
            "e escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-30156",
        vendor: "varnish_cache_project",
        product: "varnish",
        cpe23: "cpe:2.3:a:varnish_cache_project:varnish_cache:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Varnish Cache (< 7.4.3) HTTP/2 Continuation Advisory",
        remediation: "Varnish Cache serverini 7.4.3+ / 7.5+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-30255",
        vendor: "envoyproxy",
        product: "envoy",
        cpe23: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-400",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Envoy Proxy (< 1.29.3) HTTP/2 CONTINUATION Flood Advisory",
        remediation: "Envoy Proxy ni 1.29.7+ yoki 1.31+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-3120",
        vendor: "langflow",
        product: "langflow",
        cpe23: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 78, severity: "High", cwe: "CWE-94",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Langflow (< 1.0.15) Workflow Validation Advisory",
        remediation: concat!(
            "Langflow platformasini 1.1+ reliziga yangilang va `AUTO_LOGIN=Fals",
            "e` o'rnating."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-31207",
        vendor: "npm",
        product: "vite",
        cpe23: "cpe:2.3:a:npm:vite:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm vite vulnerability advisory",
        remediation: "Upgrade vite to >= 5.2.6",
    },
    KevCveRecord {
        cve_id: "CVE-2024-31210",
        vendor: "wordpress",
        product: "wordpress",
        cpe23: "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated WordPress Core (< 6.4.3) Security Advisory",
        remediation: concat!(
            "WordPress yadrosini eng so'nggi 6.5+ / 6.6+ xavfsizlik reliziga ya",
            "ngilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-31989",
        vendor: "argoproj",
        product: "argocd",
        cpe23: "cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Argo CD (< 2.10.10) Redis Cache Advisory",
        remediation: "Argo CD ni 2.10.12+ yoki 2.12+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-32113",
        vendor: "Apache",
        product: "OFBiz",
        cpe23: "cpe:2.3:a:apache:ofbiz:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache OFBiz contains a path traversal vulnerability that could al",
            "low for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-3251",
        vendor: "hashicorp",
        product: "nomad",
        cpe23: "cpe:2.3:a:hashicorp:nomad:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "HashiCorp Nomad (< 1.7.6) ACL Policy Validation Advisory",
        remediation: "HashiCorp Nomad paketini 1.7.6+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-32650",
        vendor: "crates.io",
        product: "h2",
        cpe23: "cpe:2.3:a:crates.io:h2:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "crates.io h2 vulnerability advisory",
        remediation: "Upgrade h2 to >= 0.3.26",
    },
    KevCveRecord {
        cve_id: "CVE-2024-32658",
        vendor: "nextcloud",
        product: "nextcloud",
        cpe23: "cpe:2.3:a:nextcloud:nextcloud_server:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Nextcloud Server (< 28.0.4) Access Control Advisory",
        remediation: concat!(
            "Nextcloud Server platformasini 28.0.6+ yoki 29.x+ versiyasiga yang",
            "ilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-3272",
        vendor: "D-Link",
        product: "Multiple NAS Devices",
        cpe23: "cpe:2.3:a:d-link:multiple_nas_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DNS-320L, DNS-325, DNS-327L, and DNS-340L contains a hard-c",
            "oded credential that allows an attacker to conduct authenticated c",
            "ommand injection, leading to remote, unauthorized code execution."
        ),
        remediation: concat!(
            "This vulnerability affects legacy D-Link products. All associated ",
            "hardware revisions have reached their end-of-life (EOL) or end-of-",
            "service (EOS) life cycle and should be retired and replaced per ve",
            "ndor instructions."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-3273",
        vendor: "D-Link",
        product: "Multiple NAS Devices",
        cpe23: "cpe:2.3:a:d-link:multiple_nas_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DNS-320L, DNS-325, DNS-327L, and DNS-340L contain a command",
            " injection vulnerability. When combined with CVE-2024-3272, this c",
            "an lead to remote, unauthorized code execution."
        ),
        remediation: concat!(
            "This vulnerability affects legacy D-Link products. All associated ",
            "hardware revisions have reached their end-of-life (EOL) or end-of-",
            "service (EOS) life cycle and should be retired and replaced per ve",
            "ndor instructions."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-32872",
        vendor: "monospace",
        product: "directus",
        cpe23: "cpe:2.3:a:monospace:directus:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Directus (< 10.10.5) Access Token Policy Advisory",
        remediation: "Directus platformasini 10.11+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-32896",
        vendor: "Android",
        product: "Pixel",
        cpe23: "cpe:2.3:a:android:pixel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Pixel contains an unspecified vulnerability in the firmwar",
            "e that allows for privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-3393",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains a vulnerability in parsing and ",
            "logging malicious DNS packets in the DNS Security feature that, wh",
            "en exploited, allows an unauthenticated attacker to remotely reboo",
            "t the firewall. Repeated attempts to trigger this condition will c",
            "ause the firewall to enter maintenance mode."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-3400",
        vendor: "paloaltonetworks",
        product: "paloalto_panos",
        cpe23: "cpe:2.3:a:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 100, severity: "Critical", cwe: "CWE-77",
        is_kev: true, ransomware: "Known", epss_permille: 965,
        summary: "Palo Alto PAN-OS GlobalProtect Gateway Telemetry Advisory",
        remediation: "PAN-OS dasturiy ta'minotini xavfsizlik reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-34065",
        vendor: "strapi",
        product: "strapi",
        cpe23: "cpe:2.3:a:strapi:strapi:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-287",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Strapi Headless CMS (< 4.20.2) Session Handling Advisory",
        remediation: "Strapi paketlarini 4.24+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-34069",
        vendor: "pypi",
        product: "werkzeug",
        cpe23: "cpe:2.3:a:pypi:werkzeug:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI werkzeug vulnerability advisory",
        remediation: "Upgrade werkzeug to >= 3.0.3",
    },
    KevCveRecord {
        cve_id: "CVE-2024-34102",
        vendor: "Adobe",
        product: "Commerce and Magento Open Source",
        cpe23: "cpe:2.3:a:adobe:commerce_and_magento_open_source:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Commerce and Magento Open Source contain an improper restric",
            "tion of XML external entity reference (XXE) vulnerability that all",
            "ows for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-34351",
        vendor: "vercel",
        product: "nextjs",
        cpe23: "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-918",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Next.js 14 (< 14.1.1) Server-Side Redirect Handling Advisory",
        remediation: "Next.js 14 tarmog'ini 14.1.1+ yoki 14.2+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-34359",
        vendor: "pypi",
        product: "llama-index",
        cpe23: "cpe:2.3:a:pypi:llama-index:*:*:*:*:*:*:*:*",
        cvss_x10: 93, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI llama-index vulnerability advisory",
        remediation: "Upgrade llama-index to >= 0.10.38",
    },
    KevCveRecord {
        cve_id: "CVE-2024-34502",
        vendor: "mediawiki",
        product: "mediawiki",
        cpe23: "cpe:2.3:a:mediawiki:mediawiki:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-79",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated MediaWiki (< 1.41.1) SpecialPage Rendering Advisory",
        remediation: "MediaWiki tizimini 1.41.2+ yoki 1.39.8+ LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-35250",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Kernel-Mode Driver contains an untrusted pointer",
            " dereference vulnerability that allows a local attacker to escalat",
            "e privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-36401",
        vendor: "OSGeo",
        product: "GeoServer",
        cpe23: "cpe:2.3:a:osgeo:geoserver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OSGeo GeoServer GeoTools contains an improper neutralization of di",
            "rectives in dynamically evaluated code vulnerability due to unsafe",
            "ly evaluating property names as XPath expressions. This allows una",
            "uthenticated attackers to conduct remote code execution via specia",
            "lly crafted input."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-36480",
        vendor: "pypi",
        product: "langchain",
        cpe23: "cpe:2.3:a:pypi:langchain:*:*:*:*:*:*:*:*",
        cvss_x10: 86, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI langchain vulnerability advisory",
        remediation: "Upgrade langchain to >= 0.1.17",
    },
    KevCveRecord {
        cve_id: "CVE-2024-3656",
        vendor: "redhat",
        product: "keycloak",
        cpe23: "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-601",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Keycloak (< 24.0.3) OIDC/Redirect Validation Advisory",
        remediation: "Keycloak IAM serverini 24.0.5+ yoki 25.x+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-36971",
        vendor: "Android",
        product: "Kernel",
        cpe23: "cpe:2.3:a:android:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android contains an unspecified vulnerability in the kernel that a",
            "llows for remote code execution. This vulnerability resides in Lin",
            "ux Kernel and could impact other products, including but not limit",
            "ed to Android OS."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-36991",
        vendor: "splunk",
        product: "splunk",
        cpe23: "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Splunk Enterprise (< 9.2.2) Windows Modules Path Traversal Advisor",
            "y"
        ),
        remediation: "Splunk Enterprise ni 9.2.2+ / 9.1.5+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-37032",
        vendor: "ollama",
        product: "ollama",
        cpe23: "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Ollama (< 0.1.34) Model Path Validation Advisory",
        remediation: concat!(
            "Ollama xizmatini 0.1.34+ / 0.3+ versiyasiga yangilang va loopback ",
            "interfeysga bog'lang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-37059",
        vendor: "pypi",
        product: "mlflow",
        cpe23: "cpe:2.3:a:pypi:mlflow:*:*:*:*:*:*:*:*",
        cvss_x10: 96, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI mlflow vulnerability advisory",
        remediation: "Upgrade mlflow to >= 2.12.2",
    },
    KevCveRecord {
        cve_id: "CVE-2024-37079",
        vendor: "Broadcom",
        product: "VMware vCenter Server",
        cpe23: "cpe:2.3:a:broadcom:vmware_vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Broadcom VMware vCenter Server contains an out-of-bounds write vul",
            "nerability in the implementation of the DCERPC protocol. This coul",
            "d allow a malicious actor with network access to vCenter Server to",
            " send specially crafted network packets, potentially leading to re",
            "mote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-37085",
        vendor: "vmware",
        product: "vmware_esxi",
        cpe23: "cpe:2.3:a:vmware:esxi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "VMware ESXi (< 8.0 U2) AD Integration & Hypervisor Advisory",
        remediation: concat!(
            "VMware ESXi gipervizorini 8.0 U3+ xavfsizlik yamoqlari bilan yangi",
            "lang va boshqaruv interfeysini izolyatsiya qiling."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-37287",
        vendor: "elastic",
        product: "kibana",
        cpe23: "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-1321",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Elastic Kibana (< 8.15.1) Prototype Configuration Advisory",
        remediation: concat!(
            "Elastic Kibana platformasini 8.15.1+ xavfsizlik reliziga yangilang",
            "."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-37383",
        vendor: "Roundcube",
        product: "Webmail",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "RoundCube Webmail contains a cross-site scripting (XSS) vulnerabil",
            "ity in the handling of SVG animate attributes that allows a remote",
            " attacker to run malicious JavaScript code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-37890",
        vendor: "npm",
        product: "ws",
        cpe23: "cpe:2.3:a:npm:ws:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm ws vulnerability advisory",
        remediation: "Upgrade ws to >= 8.17.1",
    },
    KevCveRecord {
        cve_id: "CVE-2024-38014",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Installer contains an improper privilege managem",
            "ent vulnerability that could allow an attacker to gain SYSTEM priv",
            "ileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38080",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Hyper-V contains a privilege escalation vulnerab",
            "ility that allows a local attacker with user permissions to gain S",
            "YSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38094",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint contains a deserialization vulnerability that",
            " allows for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38106",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Kernel contains an unspecified vulnerability tha",
            "t allows for privilege escalation, enabling a local attacker to ga",
            "in SYSTEM privileges. Successful exploitation of this vulnerabilit",
            "y requires an attacker to win a race condition."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38107",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Power Dependency Coordinator contains an unspeci",
            "fied vulnerability that allows for privilege escalation, enabling ",
            "a local attacker to obtain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38112",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows MSHTML Platform contains a spoofing vulnerabilit",
            "y that has a high impact to confidentiality, integrity, and availa",
            "bility."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38178",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Scripting Engine contains a memory corruption vu",
            "lnerability that allows unauthenticated attacker to initiate remot",
            "e code execution via a specially crafted URL."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38189",
        vendor: "Microsoft",
        product: "Project",
        cpe23: "cpe:2.3:a:microsoft:project:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Project contains an unspecified vulnerability that allow",
            "s for remote code execution via a malicious file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38193",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Ancillary Function Driver for WinSock contains a",
            "n unspecified vulnerability that allows for privilege escalation, ",
            "enabling a local attacker to gain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38213",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows SmartScreen contains a security feature bypass v",
            "ulnerability that allows an attacker to bypass the SmartScreen use",
            "r experience via a malicious file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38217",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Mark of the Web (MOTW) contains a protection mec",
            "hanism failure vulnerability that allows an attacker to bypass MOT",
            "W-based defenses. This can result in a limited loss of integrity a",
            "nd availability of security features such as Protected View in Mic",
            "rosoft Office, which rely on MOTW tagging."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38226",
        vendor: "Microsoft",
        product: "Publisher",
        cpe23: "cpe:2.3:a:microsoft:publisher:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Publisher contains a protection mechanism failure vulner",
            "ability that allows attacker to bypass Office macro policies used ",
            "to block untrusted or malicious files."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-3829",
        vendor: "qdrant",
        product: "qdrant",
        cpe23: "cpe:2.3:a:qdrant:qdrant:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-22",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Qdrant Vector DB (< 1.9.0) Snapshot Upload Validation Advisory",
        remediation: concat!(
            "Qdrant serverini 1.9.0+ versiyasiga yangilang va API key o'rnating",
            "."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38475",
        vendor: "Apache",
        product: "HTTP Server",
        cpe23: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache HTTP Server contains an improper escaping of output vulnera",
            "bility in mod_rewrite that allows an attacker to map URLs to files",
            "ystem locations that are permitted to be served by the server but ",
            "are not intentionally/directly reachable by any URL, resulting in ",
            "code execution or source code disclosure."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38812",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware vCenter Server contains a heap-based buffer overflow vulner",
            "ability in the implementation of the DCERPC protocol. This vulnera",
            "bility could allow an attacker with network access to the vCenter ",
            "Server to execute remote code by sending a specially crafted packe",
            "t."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38813",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware vCenter contains an improper check for dropped privileges v",
            "ulnerability. This vulnerability could allow an attacker with netw",
            "ork access to the vCenter Server to escalate privileges to root by",
            " sending a specially crafted packet."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-38856",
        vendor: "apache",
        product: "ofbiz",
        cpe23: "cpe:2.3:a:apache:ofbiz:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Apache OFBiz (< 18.12.15) Controller View Override Advisory",
        remediation: "Apache OFBiz ERP tizimini 18.12.15+ reliziga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-39689",
        vendor: "pypi",
        product: "certifi",
        cpe23: "cpe:2.3:a:pypi:certifi:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI certifi vulnerability advisory",
        remediation: "Upgrade certifi to >= 2024.7.4",
    },
    KevCveRecord {
        cve_id: "CVE-2024-39717",
        vendor: "Versa",
        product: "Director",
        cpe23: "cpe:2.3:a:versa:director:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Versa Director GUI contains an unrestricted upload of file wit",
            "h dangerous type vulnerability that allows administrators with Pro",
            "vider-Data-Center-Admin or Provider-Data-Center-System-Admin privi",
            "leges to customize the user interface. The “Change Favicon” (Favor",
            "ite Icon) enables the upload of a .png file, which can b"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-39848",
        vendor: "langgenius",
        product: "dify",
        cpe23: "cpe:2.3:a:langgenius:dify:*:*:*:*:*:*:*:*",
        cvss_x10: 82, severity: "High", cwe: "CWE-918",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Dify (< 0.6.13) Sandbox SSRF Advisory",
        remediation: "Dify ni 0.6.14+ ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-39891",
        vendor: "Twilio",
        product: "Authy",
        cpe23: "cpe:2.3:a:twilio:authy:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Twilio Authy contains an information disclosure vulnerability in i",
            "ts API that allows an unauthenticated endpoint to accept a request",
            " containing a phone number and respond with information about whet",
            "her the phone number was registered with Authy."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4040",
        vendor: "CrushFTP",
        product: "CrushFTP",
        cpe23: "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "CrushFTP contains an unspecified sandbox escape vulnerability that",
            " allows a remote attacker to escape the CrushFTP virtual file syst",
            "em (VFS)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4067",
        vendor: "npm",
        product: "micromatch",
        cpe23: "cpe:2.3:a:npm:micromatch:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm micromatch vulnerability advisory",
        remediation: "Upgrade micromatch to >= 4.0.8",
    },
    KevCveRecord {
        cve_id: "CVE-2024-4068",
        vendor: "npm",
        product: "braces",
        cpe23: "cpe:2.3:a:npm:braces:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm braces vulnerability advisory",
        remediation: "Upgrade braces to >= 3.0.3",
    },
    KevCveRecord {
        cve_id: "CVE-2024-40711",
        vendor: "Veeam",
        product: "Backup & Replication",
        cpe23: "cpe:2.3:a:veeam:backup_replication:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Veeam Backup and Replication contains a deserialization vulnerabil",
            "ity allowing an unauthenticated user to perform remote code execut",
            "ion."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-40766",
        vendor: "sonicwall",
        product: "sonicwall_sonicos",
        cpe23: "cpe:2.3:a:sonicwall:sonicos:*:*:*:*:*:*:*:*",
        cvss_x10: 93, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: "SonicWall SonicOS Access Control & SSLVPN Advisory",
        remediation: "SonicOS ni 7.1.2-7019+ versiyasiga yangilang va MFA yoqing.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-40890",
        vendor: "Zyxel",
        product: "DSL CPE Devices",
        cpe23: "cpe:2.3:a:zyxel:dsl_cpe_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Zyxel DSL CPE devices contain a post-authentication comma",
            "nd injection vulnerability in the CGI program that could allow an ",
            "authenticated attacker to execute OS commands via a crafted HTTP r",
            "equest."
        ),
        remediation: concat!(
            "The impacted product could be end-of-life (EoL) and/or end-of-serv",
            "ice (EoS). Users should discontinue product utilization if a curre",
            "nt mitigation is unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-40891",
        vendor: "Zyxel",
        product: "DSL CPE Devices",
        cpe23: "cpe:2.3:a:zyxel:dsl_cpe_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Zyxel DSL CPE devices contain a post-authentication comma",
            "nd injection vulnerability in the management commands that could a",
            "llow an authenticated attacker to execute OS commands via Telnet."
        ),
        remediation: concat!(
            "The impacted product could be end-of-life (EoL) and/or end-of-serv",
            "ice (EoS). Users should discontinue product utilization if a curre",
            "nt mitigation is unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-41110",
        vendor: "go",
        product: "github.com/docker/docker",
        cpe23: "cpe:2.3:a:go:github.com_docker_docker:*:*:*:*:*:*:*:*",
        cvss_x10: 99, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Go github.com/docker/docker vulnerability advisory",
        remediation: "Upgrade github.com/docker/docker to >= 25.0.6",
    },
    KevCveRecord {
        cve_id: "CVE-2024-41710",
        vendor: "Mitel",
        product: "SIP Phones",
        cpe23: "cpe:2.3:a:mitel:sip_phones:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mitel 6800 Series, 6900 Series, and 6900w Series SIP Phones, inclu",
            "ding the 6970 Conference Unit, contain an argument injection vulne",
            "rability due to insufficient parameter sanitization during the boo",
            "t process. Successful exploitation may allow an attacker to execut",
            "e arbitrary commands within the context of the system."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-41713",
        vendor: "Mitel",
        product: "MiCollab",
        cpe23: "cpe:2.3:a:mitel:micollab:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Mitel MiCollab contains a path traversal vulnerability that could ",
            "allow an attacker to gain unauthorized and unauthenticated access.",
            " This vulnerability can be chained with CVE-2024-55550, which allo",
            "ws an unauthenticated, remote attacker to read arbitrary files on ",
            "the server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-42005",
        vendor: "djangoproject",
        product: "django",
        cpe23: "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-89",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Django (< 4.2.15 LTS) QuerySet Advisory",
        remediation: concat!(
            "Django freymvorkini 4.2.16+ LTS yoki 5.1+ xavfsizlik reliziga yang",
            "ilang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-42009",
        vendor: "roundcube",
        product: "roundcube",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 82, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Roundcube Webmail (< 1.6.8) Message Sanitization Advisory",
        remediation: concat!(
            "Roundcube Webmail tizimini 1.6.8+ yoki 1.5.8+ LTS reliziga yangila",
            "ng."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43047",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a use-after-free vulnerability ",
            "due to memory corruption in DSP Services while maintaining memory ",
            "maps of HLOS memory."
        ),
        remediation: concat!(
            "Apply remediations or mitigations per vendor instructions or disco",
            "ntinue use of the product if remediation or mitigations are unavai",
            "lable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43093",
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
        cve_id: "CVE-2024-43208",
        vendor: "sonarsource",
        product: "sonarqube",
        cpe23: "cpe:2.3:a:sonarsource:sonarqube:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-200",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated SonarQube (< 9.9.5 LTA) Security Advisory",
        remediation: concat!(
            "SonarQube platformasini 9.9.6+ LTA yoki 10.6+ versiyasiga yangilan",
            "g."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4323",
        vendor: "treasuredata",
        product: "fluent_bit",
        cpe23: "cpe:2.3:a:treasuredata:fluent_bit:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-787",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Fluent Bit (< 3.0.4) Embedded HTTP Server Memory Advisory",
        remediation: concat!(
            "Fluent Bit ni 3.0.4+ versiyasiga yangilang va `:2020` HTTP portni ",
            "yoping."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4325",
        vendor: "pypi",
        product: "gradio",
        cpe23: "cpe:2.3:a:pypi:gradio:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI gradio vulnerability advisory",
        remediation: "Upgrade gradio to >= 4.31.3",
    },
    KevCveRecord {
        cve_id: "CVE-2024-4340",
        vendor: "pypi",
        product: "sqlparse",
        cpe23: "cpe:2.3:a:pypi:sqlparse:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI sqlparse vulnerability advisory",
        remediation: "Upgrade sqlparse to >= 0.5.0",
    },
    KevCveRecord {
        cve_id: "CVE-2024-43425",
        vendor: "moodle",
        product: "moodle",
        cpe23: "cpe:2.3:a:moodle:moodle:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-94",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Moodle LMS (< 4.1.12 LTS) Security Advisory",
        remediation: concat!(
            "Moodle LMS platformasini 4.1.12+ LTS yoki 4.4+ versiyasiga yangila",
            "ng."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43451",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains an NTLMv2 hash spoofing vulnerability t",
            "hat could result in disclosing a user's NTLMv2 hash to an attacker",
            " via a file open operation. The attacker could then leverage this ",
            "hash to impersonate that user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43461",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows MSHTML Platform contains a user interface (UI) m",
            "isrepresentation of critical information vulnerability that allows",
            " an attacker to spoof a web page. This vulnerability was exploited",
            " in conjunction with CVE-2024-38112."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43468",
        vendor: "Microsoft",
        product: "Configuration Manager",
        cpe23: "cpe:2.3:a:microsoft:configuration_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Configuration Manager contains an SQL injection vulnerab",
            "ility. An unauthenticated attacker could exploit this vulnerabilit",
            "y by sending specially crafted requests to the target environment ",
            "which are processed in an unsafe manner enabling the attacker to e",
            "xecute commands on the server and/or underlying database"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43485",
        vendor: "nuget",
        product: "system.text.json",
        cpe23: "cpe:2.3:a:nuget:system.text.json:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "NuGet system.text.json vulnerability advisory",
        remediation: "Upgrade system.text.json to >= 8.0.5",
    },
    KevCveRecord {
        cve_id: "CVE-2024-43572",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Management Console contains unspecified vulnerab",
            "ility that allows for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-43573",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows MSHTML Platform contains an unspecified spoofing",
            " vulnerability which can lead to a loss of confidentiality."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4358",
        vendor: "Progress",
        product: "Telerik Report Server",
        cpe23: "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Progress Telerik Report Server contains an authorization bypass by",
            " spoofing vulnerability that allows an attacker to obtain unauthor",
            "ized access."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-44308",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, and other Apple products contain an unspecified ",
            "vulnerability when processing maliciously crafted web content that",
            " may lead to arbitrary code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-44309",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, and other Apple products contain an unspecified ",
            "vulnerability when processing maliciously crafted web content that",
            " may lead to a cross-site scripting (XSS) attack."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-45195",
        vendor: "Apache",
        product: "OFBiz",
        cpe23: "cpe:2.3:a:apache:ofbiz:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache OFBiz contains a forced browsing vulnerability that allows ",
            "a remote attacker to obtain unauthorized access."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-45296",
        vendor: "npm",
        product: "path-to-regexp",
        cpe23: "cpe:2.3:a:npm:path-to-regexp:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm path-to-regexp vulnerability advisory",
        remediation: "Upgrade path-to-regexp to >= 6.3.0",
    },
    KevCveRecord {
        cve_id: "CVE-2024-45302",
        vendor: "nuget",
        product: "restsharp",
        cpe23: "cpe:2.3:a:nuget:restsharp:*:*:*:*:*:*:*:*",
        cvss_x10: 53, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "NuGet restsharp vulnerability advisory",
        remediation: "Upgrade restsharp to >= 112.0.0",
    },
    KevCveRecord {
        cve_id: "CVE-2024-45519",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains an unspecified v",
            "ulnerability in the postjournal service that may allow an unauthen",
            "ticated user to execute commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4577",
        vendor: "php",
        product: "php",
        cpe23: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 962,
        summary: "Outdated PHP 8.3 (< 8.3.8) Runtime Security Advisory",
        remediation: concat!(
            "PHP 8.3 tarmog'ini 8.3.8+ versiyasiga yangilang va `expose_php = O",
            "ff` o'rnating."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4610",
        vendor: "Arm",
        product: "Mali GPU Kernel Driver",
        cpe23: "cpe:2.3:a:arm:mali_gpu_kernel_driver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arm Bifrost and Valhall GPU kernel drivers contain a use-after-fre",
            "e vulnerability that allows a local, non-privileged user to make i",
            "mproper GPU memory processing operations to gain access to already",
            " freed memory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4671",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Visuals contains a use-after-free vulnerability th",
            "at allows a remote attacker to exploit heap corruption via a craft",
            "ed HTML page. This vulnerability could affect multiple web browser",
            "s that utilize Chromium, including, but not limited to, Google Chr",
            "ome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-47575",
        vendor: "Fortinet",
        product: "FortiManager",
        cpe23: "cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiManager contains a missing authentication vulnerabil",
            "ity in the fgfmd daemon that allows a remote, unauthenticated atta",
            "cker to execute arbitrary code or commands via specially crafted r",
            "equests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4761",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an unspecified out-of-bounds me",
            "mory write vulnerability via a crafted HTML page. This vulnerabili",
            "ty could affect multiple web browsers that utilize Chromium, inclu",
            "ding, but not limited to, Google Chrome, Microsoft Edge, and Opera",
            "."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-48248",
        vendor: "NAKIVO",
        product: "Backup and Replication",
        cpe23: "cpe:2.3:a:nakivo:backup_and_replication:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "NAKIVO Backup and Replication contains an absolute path traversal ",
            "vulnerability that enables an attacker to read arbitrary files."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4879",
        vendor: "ServiceNow",
        product: "Utah, Vancouver, and Washington DC Now Platform",
        cpe23: concat!(
            "cpe:2.3:a:servicenow:utah_vancouver_and_washington_dc_now_platform",
            ":*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ServiceNow Utah, Vancouver, and Washington DC Now Platform release",
            "s contain a jelly template injection vulnerability in UI macros. A",
            "n unauthenticated user could exploit this vulnerability to execute",
            " code remotely."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4885",
        vendor: "Progress",
        product: "WhatsUp Gold",
        cpe23: "cpe:2.3:a:progress:whatsup_gold:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Progress WhatsUp Gold contains a path traversal vulnerability that",
            " allows an unauthenticated attacker to achieve remote code executi",
            "on."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-49035",
        vendor: "Microsoft",
        product: "Partner Center",
        cpe23: "cpe:2.3:a:microsoft:partner_center:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Partner Center contains an improper access control vulne",
            "rability that allows an attacker to escalate privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-49039",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Task Scheduler contains a privilege escalation v",
            "ulnerability that can allow an attacker-provided, local applicatio",
            "n to escalate privileges outside of its AppContainer, and access p",
            "rivileged RPC functions."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-49138",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) driver contains a ",
            "heap-based buffer overflow vulnerability that allows a local attac",
            "ker to escalate privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4947",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains a type confusion vulnerability that al",
            "lows a remote attacker to execute code via a crafted HTML page."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4956",
        vendor: "sonatype",
        product: "nexus",
        cpe23: "cpe:2.3:a:sonatype:nexus_repository_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 250,
        summary: "Sonatype Nexus Repository 3 (< 3.68.1) Path Traversal Advisory",
        remediation: concat!(
            "Sonatype Nexus Repository Manager ni 3.68.1+ versiyasiga yangilang",
            "."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-4978",
        vendor: "Justice AV Solutions",
        product: "Viewer",
        cpe23: "cpe:2.3:a:justice_av_solutions:viewer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Justice AV Solutions (JAVS) Viewer installer contains a malicious ",
            "version of ffmpeg.exe, named fffmpeg.exe (SHA256: 421a4ad2615941b1",
            "77b6ec4ab5e239c14e62af2ab07c6df1741e2a62223223c4). When run, this ",
            "creates a backdoor connection to a malicious C2 server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-50302",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Linux kernel contains a use of uninitialized resource vulnerab",
            "ility that allows an attacker to leak kernel memory via a speciall",
            "y crafted HID report."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-50603",
        vendor: "Aviatrix",
        product: "Controllers",
        cpe23: "cpe:2.3:a:aviatrix:controllers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Aviatrix Controllers contain an OS command injection vulnerability",
            " that could allow an unauthenticated attacker to execute arbitrary",
            " code. Shell metacharacters can be sent to /v1/api in cloud_type f",
            "or list_flightpath_destination_instances, or src_cloud_type for fl",
            "ightpath_connection_test."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-50623",
        vendor: "Cleo",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:cleo:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cleo Harmony, VLTrader, and LexiCom, which are managed file transf",
            "er products, contain an unrestricted file upload and download vuln",
            "erability that can lead to remote code execution with elevated pri",
            "vileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-51378",
        vendor: "CyberPersons",
        product: "CyberPanel",
        cpe23: "cpe:2.3:a:cyberpersons:cyberpanel:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "CyberPanel contains an incorrect default permissions vulnerability",
            " that allows for authentication bypass and the execution of arbitr",
            "ary commands using shell metacharacters in the statusfile property",
            "."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-5146",
        vendor: "mattermost",
        product: "mattermost",
        cpe23: "cpe:2.3:a:mattermost:mattermost_server:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: concat!(
            "Outdated Mattermost Server (< 9.5.6) Channel Authorization Advisor",
            "y"
        ),
        remediation: "Mattermost Server ni 9.5.6+ ESR yoki 9.9+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-51567",
        vendor: "CyberPersons",
        product: "CyberPanel",
        cpe23: "cpe:2.3:a:cyberpersons:cyberpanel:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "CyberPanel contains an incorrect default permissions vulnerability",
            " that allows a remote, unauthenticated attacker to execute command",
            "s as root."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-5217",
        vendor: "ServiceNow",
        product: "Utah, Vancouver, and Washington DC Now Platform",
        cpe23: concat!(
            "cpe:2.3:a:servicenow:utah_vancouver_and_washington_dc_now_platform",
            ":*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ServiceNow Washington DC, Vancouver, and earlier Now Platform rele",
            "ases contain an incomplete list of disallowed inputs vulnerability",
            " in the GlideExpression script. An unauthenticated user could expl",
            "oit this vulnerability to execute code remotely."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-5225",
        vendor: "berriai",
        product: "litellm",
        cpe23: "cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*",
        cvss_x10: 86, severity: "High", cwe: "CWE-284",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "LiteLLM (< 1.40.0) Admin Key Validation Advisory",
        remediation: "LiteLLM ni 1.44+ ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-5274",
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
        cve_id: "CVE-2024-53104",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel contains an out-of-bounds write vulnerability in the ",
            "uvc_parse_streaming component of the USB Video Class (UVC) driver ",
            "that could allow for physical escalation of privilege."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-53150",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an out-of-bounds read vulnerability in the U",
            "SB-audio driver that allows a local, privileged attacker to obtain",
            " potentially sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-53197",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an out-of-bounds access vulnerability in the",
            " USB-audio driver that allows an attacker with physical access to ",
            "the system to use a malicious USB device to potentially manipulate",
            " system memory, escalate privileges, or execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-53704",
        vendor: "SonicWall",
        product: "SonicOS",
        cpe23: "cpe:2.3:a:sonicwall:sonicos:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SonicOS contains an improper authentication vulnerabilit",
            "y in the SSLVPN authentication mechanism that allows a remote atta",
            "cker to bypass authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-54085",
        vendor: "AMI",
        product: "MegaRAC SPx",
        cpe23: "cpe:2.3:a:ami:megarac_spx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "AMI MegaRAC SPx contains an authentication bypass by spoofing vuln",
            "erability in the Redfish Host Interface. A successful exploitation",
            " of this vulnerability may lead to a loss of confidentiality, inte",
            "grity, and/or availability."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-55550",
        vendor: "Mitel",
        product: "MiCollab",
        cpe23: "cpe:2.3:a:mitel:micollab:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Mitel MiCollab contains a path traversal vulnerability that could ",
            "allow an authenticated attacker with administrative privileges to ",
            "read local files within the system due to insufficient input sanit",
            "ization. This vulnerability can be chained with CVE-2024-41713, wh",
            "ich allows an unauthenticated, remote attacker to read a"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-55591",
        vendor: "Fortinet",
        product: "FortiOS and FortiProxy",
        cpe23: "cpe:2.3:a:fortinet:fortios_and_fortiproxy:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS and FortiProxy contain an authentication bypass v",
            "ulnerability that may allow an unauthenticated, remote attacker to",
            " gain super-admin privileges via crafted requests to Node.js webso",
            "cket module."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-5565",
        vendor: "pypi",
        product: "langchain-core",
        cpe23: "cpe:2.3:a:pypi:langchain-core:*:*:*:*:*:*:*:*",
        cvss_x10: 91, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI langchain-core vulnerability advisory",
        remediation: "Upgrade langchain-core to >= 0.1.53",
    },
    KevCveRecord {
        cve_id: "CVE-2024-55956",
        vendor: "Cleo",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:cleo:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cleo Harmony, VLTrader, and LexiCom, which are managed file transf",
            "er products, contain an unrestricted file upload vulnerability tha",
            "t could allow an unauthenticated user to import and execute arbitr",
            "ary bash or PowerShell commands on the host system by leveraging t",
            "he default settings of the Autorun directory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-56145",
        vendor: "Craft CMS",
        product: "Craft CMS",
        cpe23: "cpe:2.3:a:craft_cms:craft_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Craft CMS contains a code injection vulnerability. Users with affe",
            "cted versions are vulnerable to remote code execution if their php",
            ".ini configuration has `register_argc_argv` enabled."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-57726",
        vendor: "SimpleHelp",
        product: "SimpleHelp",
        cpe23: "cpe:2.3:a:simplehelp:simplehelp:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SimpleHelp contains a missing authorization vulnerability that cou",
            "ld allow low-privileged technicians to create API keys with excess",
            "ive permissions. These API keys can be used to escalate privileges",
            " to the server admin role."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-57727",
        vendor: "SimpleHelp",
        product: "SimpleHelp",
        cpe23: "cpe:2.3:a:simplehelp:simplehelp:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SimpleHelp remote support software contains multiple path traversa",
            "l vulnerabilities that allow unauthenticated remote attackers to d",
            "ownload arbitrary files from the SimpleHelp host via crafted HTTP ",
            "requests. These files may include server configuration files and h",
            "ashed user passwords."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-57728",
        vendor: "SimpleHelp",
        product: "SimpleHelp",
        cpe23: "cpe:2.3:a:simplehelp:simplehelp:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SimpleHelp contains a path traversal vulnerability that allows adm",
            "in users to upload arbitrary files anywhere on the file system by ",
            "uploading a crafted zip file (i.e. zip slip). This can be exploite",
            "d to execute arbitrary code on the host in the context of the Simp",
            "leHelp server user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-57968",
        vendor: "Advantive",
        product: "VeraCore",
        cpe23: "cpe:2.3:a:advantive:veracore:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Advantive VeraCore contains an unrestricted file upload vulnerabil",
            "ity that allows a remote unauthenticated attacker to upload files ",
            "to unintended folders via upload.apsx."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-58136",
        vendor: "Yiiframework",
        product: "Yii",
        cpe23: "cpe:2.3:a:yiiframework:yii:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Yii Framework contains an improper protection of alternate path vu",
            "lnerability that may allow a remote attacker to execute arbitrary ",
            "code. This vulnerability could affect other products that implemen",
            "t Yii, including—but not limited to—Craft CMS, as represented by C",
            "VE-2025-32432."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-5910",
        vendor: "Palo Alto Networks",
        product: "Expedition",
        cpe23: "cpe:2.3:a:palo_alto_networks:expedition:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks Expedition contains a missing authentication vu",
            "lnerability that allows an attacker with network access to takeove",
            "r an Expedition admin account and potentially access configuration",
            " secrets, credentials, and other data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-6047",
        vendor: "GeoVision",
        product: "Multiple Devices",
        cpe23: "cpe:2.3:a:geovision:multiple_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple GeoVision devices contain an OS command injection vulnera",
            "bility that allows a remote, unauthenticated attacker to inject an",
            "d execute arbitrary system commands. The impacted products could b",
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
        cve_id: "CVE-2024-6387",
        vendor: "openbsd",
        product: "openssh",
        cpe23: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-362",
        is_kev: true, ransomware: "Unknown", epss_permille: 892,
        summary: concat!(
            "OpenSSH (8.5–9.7p1) Signal Handler Race Condition Advisory (regreS",
            "SHion)"
        ),
        remediation: concat!(
            "OpenSSH paketini 9.8p1+ (yoki OS security-patch versiyasiga) yangi",
            "lang."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-6670",
        vendor: "Progress",
        product: "WhatsUp Gold",
        cpe23: "cpe:2.3:a:progress:whatsup_gold:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Progress WhatsUp Gold contains a SQL injection vulnerability that ",
            "allows an unauthenticated attacker to retrieve the user's encrypte",
            "d password if the application is configured with only a single use",
            "r."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-6886",
        vendor: "gitea",
        product: "gitea",
        cpe23: "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-79",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Gitea (< 1.21.11) Repository Permission Advisory",
        remediation: "Gitea Git xizmatini 1.22.1+ barqaror versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-7262",
        vendor: "Kingsoft",
        product: "WPS Office",
        cpe23: "cpe:2.3:a:kingsoft:wps_office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kingsoft WPS Office contains a path traversal vulnerability in pro",
            "mecefpluginhost.exe on Windows that allows an attacker to load an ",
            "arbitrary Windows library."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-7399",
        vendor: "Samsung",
        product: "MagicINFO 9 Server",
        cpe23: "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung MagicINFO 9 Server contains a path traversal vulnerability",
            " that could allow an attacker to write arbitrary files as system a",
            "uthority."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-7593",
        vendor: "Ivanti",
        product: "Virtual Traffic Manager",
        cpe23: "cpe:2.3:a:ivanti:virtual_traffic_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Virtual Traffic Manager contains an authentication bypass v",
            "ulnerability that allows a remote, unauthenticated attacker to cre",
            "ate a chosen administrator account."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-7694",
        vendor: "TeamT5",
        product: "ThreatSonar Anti-Ransomware",
        cpe23: "cpe:2.3:a:teamt5:threatsonar_anti-ransomware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TeamT5 ThreatSonar Anti-Ransomware contains an unrestricted upload",
            " of file with dangerous type vulnerability. ThreatSonar Anti-Ranso",
            "mware does not properly validate the content of uploaded files. Re",
            "mote attackers with administrator privileges on the product platfo",
            "rm can upload malicious files, which can be used to exec"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-7965",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains an inappropriate implementation vulner",
            "ability that allows a remote attacker to potentially exploit heap ",
            "corruption via a crafted HTML page. This vulnerability could affec",
            "t multiple web browsers that utilize Chromium, including, but not ",
            "limited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-7971",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains a type confusion vulnerability that al",
            "lows a remote attacker to exploit heap corruption via a crafted HT",
            "ML page. This vulnerability could affect multiple web browsers tha",
            "t utilize Chromium, including, but not limited to, Google Chrome, ",
            "Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-8068",
        vendor: "Citrix",
        product: "Session Recording",
        cpe23: "cpe:2.3:a:citrix:session_recording:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix Session Recording contains an improper privilege management",
            " vulnerability that could allow for privilege escalation to Networ",
            "kService Account access. An attacker must be an authenticated user",
            " in the same Windows Active Directory domain as the session record",
            "ing server domain."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-8069",
        vendor: "Citrix",
        product: "Session Recording",
        cpe23: "cpe:2.3:a:citrix:session_recording:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix Session Recording contains a deserialization of untrusted d",
            "ata vulnerability that allows limited remote code execution with p",
            "rivilege of a NetworkService Account access. Attacker must be an a",
            "uthenticated user on the same intranet as the session recording se",
            "rver."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-8190",
        vendor: "Ivanti",
        product: "Cloud Services Appliance",
        cpe23: "cpe:2.3:a:ivanti:cloud_services_appliance:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Cloud Services Appliance (CSA) contains an OS command injec",
            "tion vulnerability in the administrative console which can allow a",
            "n authenticated attacker with application admin privileges to pass",
            " commands to the underlying OS."
        ),
        remediation: concat!(
            "As Ivanti CSA has reached End-of-Life status, users are urged to r",
            "emove CSA 4.6.x from service or upgrade to the 5.0.x line of suppo",
            "rted solutions, as future vulnerabilities on the 4.6.x version of ",
            "CSA are unlikely to receive future security updates."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-8956",
        vendor: "PTZOptics",
        product: "PT30X-SDI/NDI Cameras",
        cpe23: "cpe:2.3:a:ptzoptics:pt30x-sdi_ndi_cameras:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PTZOptics PT30X-SDI/NDI cameras contain an insecure direct object ",
            "reference (IDOR) vulnerability that allows a remote, attacker to b",
            "ypass authentication for the /cgi-bin/param.cgi CGI script. If com",
            "bined with CVE-2024-8957, this can lead to remote code execution a",
            "s root."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-8957",
        vendor: "PTZOptics",
        product: "PT30X-SDI/NDI Cameras",
        cpe23: "cpe:2.3:a:ptzoptics:pt30x-sdi_ndi_cameras:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PTZOptics PT30X-SDI/NDI cameras contain an OS command injection vu",
            "lnerability that allows a remote, authenticated attacker to escala",
            "te privileges to root via a crafted payload with the ntp_addr para",
            "meter of the /cgi-bin/param.cgi CGI script."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-8963",
        vendor: "Ivanti",
        product: "Cloud Services Appliance (CSA)",
        cpe23: "cpe:2.3:a:ivanti:cloud_services_appliance_csa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Cloud Services Appliance (CSA) contains a path traversal vu",
            "lnerability that could allow a remote, unauthenticated attacker to",
            " access restricted functionality. If CVE-2024-8963 is used in conj",
            "unction with CVE-2024-8190, an attacker could bypass admin authent",
            "ication and execute arbitrary commands on the appliance."
        ),
        remediation: concat!(
            "As Ivanti CSA has reached End-of-Life status, users are urged to r",
            "emove CSA 4.6.x from service or upgrade to the 5.0.x line of suppo",
            "rted solutions, as future vulnerabilities on the 4.6.x version of ",
            "CSA are unlikely to receive security updates."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9052",
        vendor: "vllm_project",
        product: "vllm",
        cpe23: "cpe:2.3:a:vllm_project:vllm:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "vLLM (< 0.6.2) Distributed RPC Deserialization Advisory",
        remediation: "vLLM ni 0.6.3+ ga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2024-9264",
        vendor: "grafana",
        product: "grafana",
        cpe23: "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
        cvss_x10: 81, severity: "High", cwe: "CWE-94",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated Grafana (< 10.4.2) Expression & Auth Advisory",
        remediation: concat!(
            "Grafana xizmatini 10.4.10+ yoki 11.2+ xavfsizlik reliziga yangilan",
            "g."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9379",
        vendor: "Ivanti",
        product: "Cloud Services Appliance (CSA)",
        cpe23: "cpe:2.3:a:ivanti:cloud_services_appliance_csa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Cloud Services Appliance (CSA) contains a SQL injection vul",
            "nerability in the admin web console in versions prior to 5.0.2, wh",
            "ich can allow a remote attacker authenticated as administrator to ",
            "run arbitrary SQL statements."
        ),
        remediation: concat!(
            "As Ivanti CSA 4.6.x has reached End-of-Life status, users are urge",
            "d to remove CSA 4.6.x from service or upgrade to the 5.0.x line, o",
            "r later, of supported solution."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9380",
        vendor: "Ivanti",
        product: "Cloud Services Appliance (CSA)",
        cpe23: "cpe:2.3:a:ivanti:cloud_services_appliance_csa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Cloud Services Appliance (CSA) contains an OS command injec",
            "tion vulnerability in the administrative console which can allow a",
            "n authenticated attacker with application admin privileges to pass",
            " commands to the underlying OS."
        ),
        remediation: concat!(
            "As Ivanti CSA 4.6.x has reached End-of-Life status, users are urge",
            "d to remove CSA 4.6.x from service or upgrade to the 5.0.x line, o",
            "r later, of supported solution."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9463",
        vendor: "Palo Alto Networks",
        product: "Expedition",
        cpe23: "cpe:2.3:a:palo_alto_networks:expedition:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks Expedition contains an OS command injection vul",
            "nerability that allows an unauthenticated attacker to run arbitrar",
            "y OS commands as root in Expedition, resulting in disclosure of us",
            "ernames, cleartext passwords, device configurations, and device AP",
            "I keys of PAN-OS firewalls."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9465",
        vendor: "Palo Alto Networks",
        product: "Expedition",
        cpe23: "cpe:2.3:a:palo_alto_networks:expedition:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks Expedition contains a SQL injection vulnerabili",
            "ty that allows an unauthenticated attacker to reveal Expedition da",
            "tabase contents, such as password hashes, usernames, device config",
            "urations, and device API keys. With this, attackers can also creat",
            "e and read arbitrary files on the Expedition system."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9474",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains an OS command injection vulnera",
            "bility that allows for privilege escalation through the web-based ",
            "management interface for several PAN products, including firewalls",
            " and VPN concentrators."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable. Additionally, the manage",
            "ment interfaces for affected devices should not be exposed to untr",
            "usted networks, including the internet."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9537",
        vendor: "ScienceLogic",
        product: "SL1",
        cpe23: "cpe:2.3:a:sciencelogic:sl1:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ScienceLogic SL1 (formerly EM7) is affected by an unspecified vuln",
            "erability involving an unspecified third-party component."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2024-9680",
        vendor: "Mozilla",
        product: "Firefox",
        cpe23: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Mozilla Firefox and Firefox ESR contain a use-after-free vulnerabi",
            "lity in Animation timelines that allows for code execution in the ",
            "content process."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-0108",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains an authentication bypass vulner",
            "ability in its management web interface. This vulnerability allows",
            " an unauthenticated attacker with network access to the management",
            " web interface to bypass the authentication normally required and ",
            "invoke certain PHP scripts."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-0111",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains an external control of file nam",
            "e or path vulnerability. Successful exploitation enables an authen",
            "ticated attacker with network access to the management web interfa",
            "ce to read files on the PAN-OS filesystem that are readable by the",
            " “nobody” user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-0282",
        vendor: "Ivanti",
        product: "Connect Secure, Policy Secure, and ZTA Gateways",
        cpe23: concat!(
            "cpe:2.3:a:ivanti:connect_secure_policy_secure_and_zta_gateways:*:*",
            ":*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Connect Secure, Policy Secure, and ZTA Gateways contain a s",
            "tack-based buffer overflow which can lead to unauthenticated remot",
            "e code execution."
        ),
        remediation: concat!(
            "Apply mitigations as set forth in the CISA instructions linked bel",
            "ow to include conducting hunt activities, taking remediation actio",
            "ns if applicable, and applying updates prior to returning a device",
            " to service."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-0411",
        vendor: "7-Zip",
        product: "7-Zip",
        cpe23: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "7-Zip contains a protection mechanism failure vulnerability that a",
            "llows remote attackers to bypass the Mark-of-the-Web security feat",
            "ure to execute arbitrary code in the context of the current user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-0994",
        vendor: "Trimble",
        product: "Cityworks",
        cpe23: "cpe:2.3:a:trimble:cityworks:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trimble Cityworks contains a deserialization vulnerability. This c",
            "ould allow an authenticated user to perform a remote code executio",
            "n attack against a customer's Microsoft Internet Information Servi",
            "ces (IIS) web server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-10035",
        vendor: "Fortra",
        product: "GoAnywhere MFT",
        cpe23: "cpe:2.3:a:fortra:goanywhere_mft:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortra GoAnywhere MFT contains a deserialization of untrusted data",
            " vulnerability allows an actor with a validly forged license respo",
            "nse signature to deserialize an arbitrary actor-controlled object,",
            " possibly leading to command injection."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-10585",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium contains a type confusion vulnerability in the V8 ",
            "JavaScript and WebAssembly engine."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-11371",
        vendor: "Gladinet",
        product: "CentreStack and Triofox",
        cpe23: "cpe:2.3:a:gladinet:centrestack_and_triofox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Gladinet CentreStack and Triofox contains a files or directories a",
            "ccessible to external parties vulnerability that allows unintended",
            " disclosure of system files."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-11953",
        vendor: "React Native Community",
        product: "CLI",
        cpe23: "cpe:2.3:a:react_native_community:cli:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "React Native Community CLI contains an OS command injection vulner",
            "ability which could allow unauthenticated network attackers to sen",
            "d POST requests to the Metro Development Server and run arbitrary ",
            "executables via a vulnerable endpoint exposed by the server. On Wi",
            "ndows, attackers can also execute arbitrary shell comman"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-12480",
        vendor: "Gladinet",
        product: "Triofox",
        cpe23: "cpe:2.3:a:gladinet:triofox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Gladinet Triofox contains an improper access control vulnerability",
            " that allows access to initial setup pages even after setup is com",
            "plete."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-1316",
        vendor: "Edimax",
        product: "IC-7100 IP Camera",
        cpe23: "cpe:2.3:a:edimax:ic-7100_ip_camera:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Edimax IC-7100 IP camera contains an OS command injection vulnerab",
            "ility due to improper input sanitization that allows an attacker t",
            "o achieve remote code execution via specially crafted requests. Th",
            "e impacted product could be end-of-life (EoL) and/or end-of-servic",
            "e (EoS). Users should discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-13223",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains a type confusion vulnerability that al",
            "lows for heap corruption."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-14174",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium contains an out of bounds memory access vulnerabil",
            "ity in ANGLE that could allow a remote attacker to perform out of ",
            "bounds memory access via a crafted HTML page. This vulnerability c",
            "ould affect multiple web browsers that utilize Chromium, including",
            ", but not limited to, Google Chrome, Microsoft Edge, and"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-14611",
        vendor: "Gladinet",
        product: "CentreStack and Triofox",
        cpe23: "cpe:2.3:a:gladinet:centrestack_and_triofox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Gladinet CentreStack and TrioFox contain a hardcoded cryptographic",
            " keys vulnerability for their implementation of the AES cryptosche",
            "me. This vulnerability degrades security for public exposed endpoi",
            "nts that may make use of it and may offer arbitrary local file inc",
            "lusion when provided a specially crafted request without"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-14733",
        vendor: "WatchGuard",
        product: "Firebox",
        cpe23: "cpe:2.3:a:watchguard:firebox:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "WatchGuard Fireware OS iked process contains an out of bounds writ",
            "e vulnerability in the OS iked process. This vulnerability may all",
            "ow a remote unauthenticated attacker to execute arbitrary code and",
            " affects both the mobile user VPN with IKEv2 and the branch office",
            " VPN using IKEv2 when configured with a dynamic gateway "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-14847",
        vendor: "MongoDB",
        product: "MongoDB and MongoDB Server",
        cpe23: "cpe:2.3:a:mongodb:mongodb_and_mongodb_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MongoDB Server contains an improper handling of length parameter i",
            "nconsistency vulnerability in Zlib compressed protocol headers. Th",
            "is vulnerability may allow a read of uninitialized heap memory by ",
            "an unauthenticated client."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-15556",
        vendor: "Notepad++",
        product: "Notepad++",
        cpe23: "cpe:2.3:a:notepad:notepad:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Notepad++ when using the WinGUp updater, contains a download of co",
            "de without integrity check vulnerability that could allow an attac",
            "ker to intercept or redirect update traffic to download and execut",
            "e an attacker-controlled installer. This could lead to arbitrary c",
            "ode execution with the privileges of the user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-1976",
        vendor: "Broadcom",
        product: "Brocade Fabric OS",
        cpe23: "cpe:2.3:a:broadcom:brocade_fabric_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Broadcom Brocade Fabric OS contains a code injection vulnerability",
            " that allows a local user with administrative privileges to execut",
            "e arbitrary code with full root privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-20281",
        vendor: "Cisco",
        product: "Identity Services Engine",
        cpe23: "cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Identity Services Engine contains an injection vulnerability",
            " in a specific API of Cisco ISE and Cisco ISE-PIC due to insuffici",
            "ent validation of user-supplied input allowing an attacker to expl",
            "oit this vulnerability by submitting a crafted API request. Succes",
            "sful exploitation could allow an attacker to perform rem"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-20333",
        vendor: "Cisco",
        product: concat!(
            "Secure Firewall Adaptive Security Appliance and Secure Firewall Th",
            "reat Defense"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_adaptive_security_appliance_and_se",
            "cure_firewall_threat_defense:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Firewall Adaptive Security (ASA) Appliance and Secure",
            " Firewall Threat Defense (FTD) Software VPN Web Server contain a b",
            "uffer overflow vulnerability that allows for remote code execution",
            ". This vulnerability could be chained with CVE-2025-20362."
        ),
        remediation: concat!(
            "The KEV due date refers to the deadline by which FCEB agencies are",
            " expected to review and begin implementing the guidance outlined i",
            "n Emergency Directive (ED) 25-03 (URL listed below in Notes). Agen",
            "cies must follow the mitigation steps provided by CISA (URL li"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-20337",
        vendor: "Cisco",
        product: "Identity Services Engine",
        cpe23: "cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Identity Services Engine contains an injection vulnerability",
            " in a specific API of Cisco ISE and Cisco ISE-PIC due to insuffici",
            "ent validation of user-supplied input allowing an attacker to expl",
            "oit this vulnerability by submitting a crafted API request. Succes",
            "sful exploitation could allow an attacker to perform rem"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-20352",
        vendor: "Cisco",
        product: "IOS and IOS XE",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS and IOS XE contains a stack-based buffer overflow vulner",
            "ability in the Simple Network Management Protocol (SNMP) subsystem",
            " that could allow for denial of service or remote code execution. ",
            "A successful exploit could allow a low-privileged attacker to caus",
            "e the affected system to reload, resulting in a DoS cond"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-20362",
        vendor: "Cisco",
        product: concat!(
            "Secure Firewall Adaptive Security Appliance and Secure Firewall Th",
            "reat Defense"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_adaptive_security_appliance_and_se",
            "cure_firewall_threat_defense:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Firewall Adaptive Security (ASA) Appliance and Secure",
            " Firewall Threat Defense (FTD) Software VPN Web Server contain a m",
            "issing authorization vulnerability. This vulnerability could be ch",
            "ained with CVE-2025-20333."
        ),
        remediation: concat!(
            "The KEV due date refers to the deadline by which FCEB agencies are",
            " expected to review and begin implementing the guidance outlined i",
            "n Emergency Directive (ED) 25-03 (URL listed below in Notes). Agen",
            "cies must follow the mitigation steps provided by CISA (URL li"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-20393",
        vendor: "Cisco",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:cisco:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Email Gateway, Secure Email, AsyncOS Software, and We",
            "b Manager appliances contains an improper input validation vulnera",
            "bility that allows threat actors to execute arbitrary commands wit",
            "h root privileges on the underlying operating system of an affecte",
            "d appliance."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21042",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an out-of-bounds write vulnerabilit",
            "y in libimagecodec.quram.so. This vulnerability could allow remote",
            " attackers to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21043",
        vendor: "Samsung",
        product: "Mobile Devices",
        cpe23: "cpe:2.3:a:samsung:mobile_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung mobile devices contain an out-of-bounds write vulnerabilit",
            "y in libimagecodec.quram.so which allows remote attackers to execu",
            "te arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21333",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Hyper-V NT Kernel Integration VSP contains a hea",
            "p-based buffer overflow vulnerability that allows a local attacker",
            " to gain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21334",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Hyper-V NT Kernel Integration VSP contains a use",
            "-after-free vulnerability that allows a local attacker to gain SYS",
            "TEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21335",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Hyper-V NT Kernel Integration VSP contains a use",
            "-after-free vulnerability that allows a local attacker to gain SYS",
            "TEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21391",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Storage contains a link following vulnerability ",
            "that could allow for privilege escalation. This vulnerability coul",
            "d allow an attacker to delete data including data that results in ",
            "the service being unavailable."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21418",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Ancillary Function Driver for WinSock contains a",
            " heap-based buffer overflow vulnerability that allows for privileg",
            "e escalation, enabling a local attacker to gain SYSTEM privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21479",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain an incorrect authorization vuln",
            "erability. This vulnerability allows for memory corruption due to ",
            "unauthorized command execution in GPU micronode while executing sp",
            "ecific sequence of commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21480",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain an incorrect authorization vuln",
            "erability. This vulnerability allows for memory corruption due to ",
            "unauthorized command execution in GPU micronode while executing sp",
            "ecific sequence of commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-21590",
        vendor: "Juniper",
        product: "Junos OS",
        cpe23: "cpe:2.3:a:juniper:junos_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Juniper Junos OS contains an improper isolation or compartmentaliz",
            "ation vulnerability. This vulnerability could allows a local attac",
            "ker with high privileges to inject arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-22224",
        vendor: "VMware",
        product: "ESXi and Workstation",
        cpe23: "cpe:2.3:a:vmware:esxi_and_workstation:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware ESXi and Workstation contain a time-of-check time-of-use (T",
            "OCTOU) race condition vulnerability that leads to an out-of-bounds",
            " write. Successful exploitation enables an attacker with local adm",
            "inistrative privileges on a virtual machine to execute code as the",
            " virtual machine's VMX process running on the host."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-22225",
        vendor: "VMware",
        product: "ESXi",
        cpe23: "cpe:2.3:a:vmware:esxi:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware ESXi contains an arbitrary write vulnerability. Successful ",
            "exploitation allows an attacker with privileges within the VMX pro",
            "cess to trigger an arbitrary kernel write leading to an escape of ",
            "the sandbox."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-22226",
        vendor: "VMware",
        product: "ESXi, Workstation, and Fusion",
        cpe23: "cpe:2.3:a:vmware:esxi_workstation_and_fusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware ESXi, Workstation, and Fusion contain an information disclo",
            "sure vulnerability due to an out-of-bounds read in HGFS. Successfu",
            "l exploitation allows an attacker with administrative privileges t",
            "o a virtual machine to leak memory from the vmx process."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-22457",
        vendor: "Ivanti",
        product: "Connect Secure, Policy Secure, and ZTA Gateways",
        cpe23: concat!(
            "cpe:2.3:a:ivanti:connect_secure_policy_secure_and_zta_gateways:*:*",
            ":*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Connect Secure, Policy Secure, and ZTA Gateways contains a ",
            "stack-based buffer overflow vulnerability that allows a remote una",
            "uthenticated attacker to achieve remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations as set forth in the CISA instructions linked bel",
            "ow."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-23006",
        vendor: "SonicWall",
        product: "SMA1000 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma1000_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SMA1000 Appliance Management Console (AMC) and Central M",
            "anagement Console (CMC) contain a deserialization of untrusted dat",
            "a vulnerability, which can enable a remote, unauthenticated attack",
            "er to execute arbitrary OS commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-23209",
        vendor: "Craft CMS",
        product: "Craft CMS",
        cpe23: "cpe:2.3:a:craft_cms:craft_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Craft CMS contains a code injection vulnerability caused by improp",
            "er validation of the database backup path, ultimately enabling rem",
            "ote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24016",
        vendor: "Wazuh",
        product: "Wazuh Server",
        cpe23: "cpe:2.3:a:wazuh:wazuh_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Wazuh contains a deserialization of untrusted data vulnerability t",
            "hat allows for remote code execution on Wazuh servers."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24054",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows NTLM contains an external control of file name o",
            "r path vulnerability that allows an unauthorized attacker to perfo",
            "rm spoofing over a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24085",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, and other Apple products contain a user-after-fr",
            "ee vulnerability that could allow a malicious application to eleva",
            "te privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24200",
        vendor: "Apple",
        product: "iOS and iPadOS",
        cpe23: "cpe:2.3:a:apple:ios_and_ipados:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and iPadOS contains an incorrect authorization vulnerabi",
            "lity that allows a physical attacker to disable USB Restricted Mod",
            "e on a locked device."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24201",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and other Apple products contain an out-",
            "of-bounds write vulnerability in WebKit that may allow maliciously",
            " crafted web content to break out of Web Content sandbox. This vul",
            "nerability could impact HTML parsers that use WebKit, including bu",
            "t not limited to Apple Safari and non-Apple products whi"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24472",
        vendor: "Fortinet",
        product: "FortiOS and FortiProxy",
        cpe23: "cpe:2.3:a:fortinet:fortios_and_fortiproxy:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS and FortiProxy contain an authentication bypass v",
            "ulnerability that allows a remote attacker to gain super-admin pri",
            "vileges via crafted CSF proxy requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24813",
        vendor: "Apache",
        product: "Tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Tomcat contains a path equivalence vulnerability that allow",
            "s a remote attacker to execute code, disclose information, or inje",
            "ct malicious content via a partial PUT request. This vulnerability",
            " can be chained with CVE‑2026‑34486."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24893",
        vendor: "XWiki",
        product: "Platform",
        cpe23: "cpe:2.3:a:xwiki:platform:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "XWiki Platform contains an eval injection vulnerability that could",
            " allow any guest to perform arbitrary remote code execution throug",
            "h a request to SolrSearch."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24983",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Win32 Kernel Subsystem contains a use-after-free",
            " vulnerability that allows an authorized attacker to elevate privi",
            "leges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24984",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows New Technology File System (NTFS) contains an in",
            "sertion of sensitive Information into log file vulnerability that ",
            "allows an unauthorized attacker to disclose information with a phy",
            "sical attack. An attacker who successfully exploited this vulnerab",
            "ility could potentially read portions of heap memory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24985",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Fast FAT File System Driver contains an integer ",
            "overflow or wraparound vulnerability that allows an unauthorized a",
            "ttacker to execute code locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24989",
        vendor: "Microsoft",
        product: "Power Pages",
        cpe23: "cpe:2.3:a:microsoft:power_pages:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Power Pages contains an improper access control vulnerab",
            "ility that allows an unauthorized attacker to elevate privileges o",
            "ver a network potentially bypassing the user registration control."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow BOD 22-01 guidan",
            "ce for cloud services, or discontinue use of the product if mitiga",
            "tions are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24990",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Agere Modem Driver contains an untrusted pointer",
            " dereference vulnerability that allows for privilege escalation. A",
            "n attacker who successfully exploited this vulnerability could gai",
            "n administrator privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24991",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows New Technology File System (NTFS) contains an ou",
            "t-of-bounds read vulnerability that allows an authorized attacker ",
            "to disclose information locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-24993",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows New Technology File System (NTFS) contains a hea",
            "p-based buffer overflow vulnerability that allows an unauthorized ",
            "attacker to execute code locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-25181",
        vendor: "Advantive",
        product: "VeraCore",
        cpe23: "cpe:2.3:a:advantive:veracore:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Advantive VeraCore contains a SQL injection vulnerability in timeo",
            "utWarning.asp that allows a remote attacker to execute arbitrary S",
            "QL commands via the PmSess1 parameter."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-25249",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiOS, FortiSwitchManager, and FortiSASE contain a heap",
            "-based buffer overflow vulnerability that allows an attacker to ex",
            "ecute unauthorized code or commands via specially crafted packets."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-25257",
        vendor: "Fortinet",
        product: "FortiWeb",
        cpe23: "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiWeb contains a SQL injection vulnerability that may ",
            "allow an unauthenticated attacker to execute unauthorized SQL code",
            " or commands via crafted HTTP or HTTPs requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-26399",
        vendor: "SolarWinds",
        product: "Web Help Desk",
        cpe23: "cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SolarWinds Web Help Desk contain a deserialization of untrusted da",
            "ta vulnerability in AjaxProxy that could allow an attacker to run ",
            "commands on the host machine."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-26633",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Management Console (MMC) contains an improper ne",
            "utralization vulnerability that allows an unauthorized attacker to",
            " bypass a security feature locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-27038",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a use-after-free vulnerability.",
            " This vulnerability allows for memory corruption while rendering g",
            "raphics using Adreno GPU drivers in Chrome."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-27363",
        vendor: "FreeType",
        product: "FreeType",
        cpe23: "cpe:2.3:a:freetype:freetype:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "FreeType contains an out-of-bounds write vulnerability when attemp",
            "ting to parse font subglyph structures related to TrueType GX and ",
            "variable font files that may allow for arbitrary code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-2746",
        vendor: "Kentico",
        product: "Xperience CMS",
        cpe23: "cpe:2.3:a:kentico:xperience_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kentico Xperience CMS contains an authentication bypass using an a",
            "lternate path or channel vulnerability that could allow an attacke",
            "r to control administrative objects."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-2747",
        vendor: "Kentico",
        product: "Xperience CMS",
        cpe23: "cpe:2.3:a:kentico:xperience_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kentico Xperience CMS contains an authentication bypass using an a",
            "lternate path or channel vulnerability that could allow an attacke",
            "r to control administrative objects."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-2749",
        vendor: "Kentico",
        product: "Kentico Xperience",
        cpe23: "cpe:2.3:a:kentico:kentico_xperience:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kentico Xperience contains a path traversal vulnerability that cou",
            "ld allow an authenticated user's Staging Sync Server to upload arb",
            "itrary data to path relative locations."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-2775",
        vendor: "SysAid",
        product: "SysAid On-Prem",
        cpe23: "cpe:2.3:a:sysaid:sysaid_on-prem:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SysAid On-Prem contains an improper restriction of XML external en",
            "tity reference vulnerability in the Checkin processing functionali",
            "ty, allowing for administrator account takeover and file read prim",
            "itives."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-2776",
        vendor: "SysAid",
        product: "SysAid On-Prem",
        cpe23: "cpe:2.3:a:sysaid:sysaid_on-prem:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SysAid On-Prem contains an improper restriction of XML external en",
            "tity reference vulnerability in the Server URL processing function",
            "ality, allowing for administrator account takeover and file read p",
            "rimitives."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-2783",
        vendor: "Google",
        product: "Chromium Mojo",
        cpe23: "cpe:2.3:a:google:chromium_mojo:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium Mojo on Windows contains a sandbox escape vulnerab",
            "ility caused by a logic error, which results from an incorrect han",
            "dle being provided in unspecified circumstances. This vulnerabilit",
            "y could affect multiple web browsers that utilize Chromium, includ",
            "ing, but not limited to, Google Chrome, Microsoft Edge, "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-27915",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting vulnerability that exists in the Classic Web Client due to ",
            "insufficient sanitization of HTML content in ICS files. When a use",
            "r views an e-mail message containing a malicious ICS entry, its em",
            "bedded JavaScript executes via an ontoggle event inside "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-27920",
        vendor: "Srimax",
        product: "Output Messenger",
        cpe23: "cpe:2.3:a:srimax:output_messenger:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Srimax Output Messenger contains a directory traversal vulnerabili",
            "ty that allows an attacker to access sensitive files outside the i",
            "ntended directory, potentially leading to configuration leakage or",
            " arbitrary file access."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-29635",
        vendor: "D-Link",
        product: "DIR-823X",
        cpe23: "cpe:2.3:a:d-link:dir-823x:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-823X contains a command injection vulnerability that al",
            "lows an authorized attacker to execute arbitrary commands on remot",
            "e devices by sending a POST request to /goform/set_prohibiting via",
            " the corresponding function. The impacted product could be end-of-",
            "life (EoL) and/or end-of-service (EoS). Users should dis"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-29824",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) Driver contains a ",
            "use-after-free vulnerability that allows an authorized attacker to",
            " elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-30066",
        vendor: "tj-actions",
        product: "changed-files GitHub Action",
        cpe23: "cpe:2.3:a:tj-actions:changed-files_github_action:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "tj-actions/changed-files GitHub Action contains an embedded malici",
            "ous code vulnerability that allows a remote attacker to discover s",
            "ecrets by reading Github Actions Workflow Logs. These secrets may ",
            "include, but are not limited to, valid AWS access keys, GitHub per",
            "sonal access tokens (PATs), npm tokens, and private RSA "
        ),
        remediation: concat!(
            "Apply mitigations as set forth in the CISA instructions linked bel",
            "ow. Apply mitigations per vendor instructions, follow applicable B",
            "OD 22-01 guidance for cloud services, or discontinue use of the pr",
            "oduct if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-30154",
        vendor: "reviewdog",
        product: "action-setup GitHub Action",
        cpe23: "cpe:2.3:a:reviewdog:action-setup_github_action:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "reviewdog action-setup GitHub Action contains an embedded maliciou",
            "s code vulnerability that dumps exposed secrets to Github Actions ",
            "Workflow Logs."
        ),
        remediation: concat!(
            "Apply mitigations as set forth in the CISA instructions linked bel",
            "ow. Apply mitigations per vendor instructions, follow applicable B",
            "OD 22-01 guidance for cloud services, or discontinue use of the pr",
            "oduct if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-30397",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Scripting Engine contains a type confusion vulne",
            "rability that allows an unauthorized attacker to execute code over",
            " a network via a specially crafted URL."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-30400",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows DWM Core Library contains a use-after-free vulne",
            "rability that allows an authorized attacker to elevate privileges ",
            "locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-30406",
        vendor: "Gladinet",
        product: "CentreStack",
        cpe23: "cpe:2.3:a:gladinet:centrestack:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Gladinet CentreStack and Triofox contains a use of hard-coded cryp",
            "tographic key vulnerability in the way that the application manage",
            "s keys used for ViewState integrity verification. Successful explo",
            "itation allows an attacker to forge ViewState payloads for server-",
            "side deserialization, allowing for remote code execution"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-31125",
        vendor: "Vite",
        product: "Vitejs",
        cpe23: "cpe:2.3:a:vite:vitejs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Vite Vitejs contains an improper access control vulnerability that",
            " exposes content of non-allowed files using ?inline&import or ?raw",
            "?import. Only apps explicitly exposing the Vite dev server to the ",
            "network (using --host or server.host config option) are affected."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-31161",
        vendor: "CrushFTP",
        product: "CrushFTP",
        cpe23: "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "CrushFTP contains an authentication bypass vulnerability in the HT",
            "TP authorization header that allows a remote unauthenticated attac",
            "ker to authenticate to any known or guessable user account (e.g., ",
            "crushadmin), potentially leading to a full compromise."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-31200",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and other Apple products contain a memor",
            "y corruption vulnerability that allows for code execution when pro",
            "cessing an audio stream in a maliciously crafted media file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-31201",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and other Apple products contain an arbi",
            "trary read and write vulnerability that allows an attacker to bypa",
            "ss Pointer Authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-31277",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple Safari, iOS, watchOS, visionOS, iPadOS, macOS, and tvOS cont",
            "ain a buffer overflow vulnerability that could allow the processin",
            "g of maliciously crafted web content which may lead to memory corr",
            "uption."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-31324",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SAP NetWeaver Visual Composer Metadata Uploader contains an unrest",
            "ricted file upload vulnerability that allows an unauthenticated ag",
            "ent to upload potentially malicious executable binaries."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32432",
        vendor: "Craft CMS",
        product: "Craft CMS",
        cpe23: "cpe:2.3:a:craft_cms:craft_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Craft CMS contains a code injection vulnerability that allows a re",
            "mote attacker to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32433",
        vendor: "Erlang",
        product: "Erlang/OTP",
        cpe23: "cpe:2.3:a:erlang:erlang_otp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Erlang Erlang/OTP SSH server contains a missing authentication for",
            " critical function vulnerability. This could allow an attacker to ",
            "execute arbitrary commands without valid credentials, potentially ",
            "leading to unauthenticated remote code execution (RCE). By exploit",
            "ing a flaw in how SSH protocol messages are handled, a m"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32463",
        vendor: "Sudo",
        product: "Sudo",
        cpe23: "cpe:2.3:a:sudo:sudo:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sudo contains an inclusion of functionality from untrusted control",
            " sphere vulnerability. This vulnerability could allow local attack",
            "er to leverage sudo’s -R (--chroot) option to run arbitrary comman",
            "ds as root, even if they are not listed in the sudoers file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-3248",
        vendor: "Langflow",
        product: "Langflow",
        cpe23: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Langflow contains a missing authentication vulnerability in the /a",
            "pi/v1/validate/code endpoint that allows a remote, unauthenticated",
            " attacker to execute arbitrary code via crafted HTTP requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32701",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) Driver contains a ",
            "use-after-free vulnerability that allows an authorized attacker to",
            " elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32706",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) Driver contains a ",
            "heap-based buffer overflow vulnerability that allows an authorized",
            " attacker to elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32709",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Ancillary Function Driver for WinSock contains a",
            " use-after-free vulnerability that allows an authorized attacker t",
            "o escalate privileges to administrator."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32756",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiFone, FortiVoice, FortiNDR and FortiMail contain a s",
            "tack-based overflow vulnerability that may allow a remote unauthen",
            "ticated attacker to execute arbitrary code or commands via crafted",
            " HTTP requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-32975",
        vendor: "Quest",
        product: "KACE Systems Management Appliance (SMA)",
        cpe23: concat!(
            "cpe:2.3:a:quest:kace_systems_management_appliance_sma:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Quest KACE Systems Management Appliance (SMA) contains an improper",
            " authentication vulnerability that could allow attackers to impers",
            "onate legitimate users without valid credentials."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-33053",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains an external control of file name or pat",
            "h vulnerability that could allow an attacker to execute code from ",
            "a remote WebDAV location specified by the WorkingDirectory attribu",
            "te of Internet Shortcut files."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-33073",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows SMB Client contains an improper access control v",
            "ulnerability that could allow for privilege escalation. An attacke",
            "r could execute a specially crafted malicious script to coerce the",
            " victim machine to connect back to the attack system using SMB and",
            " authenticate."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-34026",
        vendor: "Versa",
        product: "Concerto",
        cpe23: "cpe:2.3:a:versa:concerto:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Versa Concerto SD-WAN orchestration platform contains an improper ",
            "authentication vulnerability in the Traefik reverse proxy configur",
            "ation, allowing at attacker to access administrative endpoints. Th",
            "e internal Actuator endpoint can be leveraged for access to heap d",
            "umps and trace logs."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-34028",
        vendor: "Commvault",
        product: "Command Center",
        cpe23: "cpe:2.3:a:commvault:command_center:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Commvault Command Center contains a path traversal vulnerability t",
            "hat allows a remote, unauthenticated attacker to execute arbitrary",
            " code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-34291",
        vendor: "Langflow",
        product: "Langflow",
        cpe23: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Langflow contains an origin validation error vulnerability in whic",
            "h an overly permissive CORS configuration combined with a refresh ",
            "token cookie configured as SameSite=None allows a malicious webpag",
            "e to perform cross-origin requests that include credentials and su",
            "ccessfully call the refresh endpoint. This could allow t"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-35939",
        vendor: "Craft CMS",
        product: "Craft CMS",
        cpe23: "cpe:2.3:a:craft_cms:craft_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Craft CMS contains an external control of assumed-immutable web pa",
            "rameter vulnerability. This vulnerability could allow an unauthent",
            "icated client to introduce arbitrary values, such as PHP code, to ",
            "a known local file location on the server. This vulnerability coul",
            "d be chained with CVE-2024-58136 as represented by CVE-2"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-37164",
        vendor: "Hewlett Packard Enterprise (HPE)",
        product: "OneView",
        cpe23: "cpe:2.3:a:hewlett_packard_enterprise_hpe:oneview:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Hewlett Packard Enterprise (HPE) OneView contains a code injection",
            " vulnerability that allows a remote unauthenticated user to perfor",
            "m remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-38352",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel contains a time-of-check time-of-use (TOCTOU) race co",
            "ndition vulnerability that has a high impact on confidentiality, i",
            "ntegrity, and availability."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-3928",
        vendor: "Commvault",
        product: "Web Server",
        cpe23: "cpe:2.3:a:commvault:web_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Commvault Web Server contains an unspecified vulnerability that al",
            "lows a remote, authenticated attacker to create and execute webshe",
            "lls."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-3935",
        vendor: "ConnectWise",
        product: "ScreenConnect",
        cpe23: "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ConnectWise ScreenConnect contains an improper authentication vuln",
            "erability. This vulnerability could allow a ViewState code injecti",
            "on attack, which could allow remote code execution if machine keys",
            " are compromised."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-39682",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an improper check for unusual or exceptional",
            " conditions vulnerability in the TLS receive path which allows a z",
            "ero-length record retrieved from the rx_list to bypass the intende",
            "d recvmsg() record-type handling, potentially causing subsequent T",
            "LS records to be processed using incorrect zero-copy and"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-39964",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains a race condition vulnerability which allows ",
            "concurrent writes to the same AF_ALG socket causing data to be unp",
            "redictably interleaved and creating inconsistencies in the socket'",
            "s internal state."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-4008",
        vendor: "Smartbedded",
        product: "Meteobridge",
        cpe23: "cpe:2.3:a:smartbedded:meteobridge:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Smartbedded Meteobridge contains a command injection vulnerability",
            " that could allow remote unauthenticated attackers to gain arbitra",
            "ry command execution with elevated privileges (root) on affected d",
            "evices."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-40536",
        vendor: "SolarWinds",
        product: "Web Help Desk",
        cpe23: "cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Web Help Desk contains a security control bypass vulner",
            "ability that could allow an unauthenticated attacker to gain acces",
            "s to certain restricted functionality."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-40551",
        vendor: "SolarWinds",
        product: "Web Help Desk",
        cpe23: "cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Web Help Desk contains a deserialization of untrusted d",
            "ata vulnerability that could lead to remote code execution, which ",
            "would allow an attacker to run commands on the host machine. This ",
            "could be exploited without authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-40602",
        vendor: "SonicWall",
        product: "SMA1000 appliance",
        cpe23: "cpe:2.3:a:sonicwall:sma1000_appliance:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SonicWall SMA1000 contains a missing authorization vulnerability t",
            "hat could allow for privilege escalation appliance management cons",
            "ole (AMC) of affected devices."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-41244",
        vendor: "Broadcom",
        product: "VMware Aria Operations and VMware Tools",
        cpe23: concat!(
            "cpe:2.3:a:broadcom:vmware_aria_operations_and_vmware_tools:*:*:*:*",
            ":*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Broadcom VMware Aria Operations and VMware Tools contain a privile",
            "ge defined with unsafe actions vulnerability. A malicious local ac",
            "tor with non-administrative privileges having access to a VM with ",
            "VMware Tools installed and managed by Aria Operations with SDMP en",
            "abled may exploit this vulnerability to escalate privile"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-42599",
        vendor: "Qualitia",
        product: "Active! Mail",
        cpe23: "cpe:2.3:a:qualitia:active_mail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Qualitia Active! Mail contains a stack-based buffer overflow vulne",
            "rability that allows a remote, unauthenticated attacker to execute",
            " arbitrary or trigger a denial-of-service via a specially crafted ",
            "request."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-42999",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SAP NetWeaver Visual Composer Metadata Uploader contains a deseria",
            "lization vulnerability that allows a privileged attacker to compro",
            "mise the confidentiality, integrity, and availability of the host ",
            "system by deserializing untrusted or malicious content."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-43200",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, watchOS, and visionOS, contain an unspec",
            "ified vulnerability when processing a maliciously crafted photo or",
            " video shared via an iCloud Link."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-43300",
        vendor: "Apple",
        product: "iOS, iPadOS, and macOS",
        cpe23: "cpe:2.3:a:apple:ios_ipados_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, and macOS contain an out-of-bounds write vulner",
            "ability in the Image I/O framework."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-43510",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple watchOS, iOS, iPadOS, macOS, visionOS, and tvOS contain an i",
            "mproper locking vulnerability that could allow a malicious applica",
            "tion to cause unexpected changes in memory shared between processe",
            "s."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-43520",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple watchOS, iOS, iPadOS, macOS, visionOS, and tvOS contain a cl",
            "assic buffer overflow vulnerability which could allow a malicious ",
            "application to cause unexpected system termination or write kernel",
            " memory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-43529",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and other Apple products contain a use-a",
            "fter-free vulnerability in WebKit. Processing maliciously crafted ",
            "web content may lead to memory corruption. This vulnerability coul",
            "d impact HTML parsers that use WebKit, including but not limited t",
            "o Apple Safari and non-Apple products which rely on WebK"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-4427",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) contains an authentication b",
            "ypass vulnerability in the API component that allows an attacker t",
            "o access protected resources without proper credentials via crafte",
            "d API requests. This vulnerability results from an insecure implem",
            "entation of the Spring Framework open-source library."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-4428",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vu",
            "lnerability in the API component that allows an authenticated atta",
            "cker to remotely execute arbitrary code via crafted API requests. ",
            "This vulnerability results from an insecure implementation of the ",
            "Hibernate Validator open-source library, as represented "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-4632",
        vendor: "Samsung",
        product: "MagicINFO 9 Server",
        cpe23: "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Samsung MagicINFO 9 Server contains a path traversal vulnerability",
            " that allows an attacker to write arbitrary file as system authori",
            "ty."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-47729",
        vendor: "TeleMessage",
        product: "TM SGNL",
        cpe23: "cpe:2.3:a:telemessage:tm_sgnl:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TeleMessage TM SGNL contains a hidden functionality vulnerability ",
            "in which the archiving backend holds cleartext copies of messages ",
            "from TM SGNL application users."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-47812",
        vendor: "Wing FTP Server",
        product: "Wing FTP Server",
        cpe23: "cpe:2.3:a:wing_ftp_server:wing_ftp_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Wing FTP Server contains an improper neutralization of null byte o",
            "r NUL character vulnerability that can allow injection of arbitrar",
            "y Lua code into user session files. This can be used to execute ar",
            "bitrary system commands with the privileges of the FTP service (ro",
            "ot or SYSTEM by default)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-47813",
        vendor: "Wing FTP Server",
        product: "Wing FTP Server",
        cpe23: "cpe:2.3:a:wing_ftp_server:wing_ftp_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Wing FTP Server contains a generation of error message containing ",
            "sensitive information vulnerability when using a long value in the",
            " UID cookie."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-47827",
        vendor: "IGEL",
        product: "IGEL OS",
        cpe23: "cpe:2.3:a:igel:igel_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "IGEL OS contains a use of a key past its expiration date vulnerabi",
            "lity that allows for Secure Boot bypass. The igel-flash-driver mod",
            "ule improperly verifies a cryptographic signature. Ultimately, a c",
            "rafted root filesystem can be mounted from an unverified SquashFS ",
            "image."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48384",
        vendor: "Git",
        product: "Git",
        cpe23: "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Git contains a link following vulnerability that stems from Git’s ",
            "inconsistent handling of carriage return characters in configurati",
            "on files."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48543",
        vendor: "Android",
        product: "Runtime",
        cpe23: "cpe:2.3:a:android:runtime:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Runtime contains a use-after-free vulnerability potentiall",
            "y allowing a chrome sandbox escape leading to local privilege esca",
            "lation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48572",
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
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48595",
        vendor: "Android",
        product: "Framework",
        cpe23: "cpe:2.3:a:android:framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Framework contains an integer overflow vulnerability that ",
            "allows for code execution that could allow for local privilege esc",
            "alation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48633",
        vendor: "Android",
        product: "Framework",
        cpe23: "cpe:2.3:a:android:framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Framework contains an unspecified vulnerability that allow",
            "s for information disclosure."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48700",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting vulnerability that could allow attackers to execute arbitra",
            "ry JavaScript within the user's session, potentially leading to un",
            "authorized access to sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48703",
        vendor: "CWP",
        product: "Control Web Panel",
        cpe23: "cpe:2.3:a:cwp:control_web_panel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "CWP Control Web Panel (formerly CentOS Web Panel) contains an OS c",
            "ommand Injection vulnerability that allows unauthenticated remote ",
            "code execution via shell metacharacters in the t_total parameter i",
            "n a filemanager changePerm request. A valid non-root username must",
            " be known."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48927",
        vendor: "TeleMessage",
        product: "TM SGNL",
        cpe23: "cpe:2.3:a:telemessage:tm_sgnl:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TeleMessage TM SGNL contains an initialization of a resource with ",
            "an insecure default vulnerability. This vulnerability relies on ho",
            "w the Spring Boot Actuator is configured with an exposed heap dump",
            " endpoint at a /heapdump URI."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-48928",
        vendor: "TeleMessage",
        product: "TM SGNL",
        cpe23: "cpe:2.3:a:telemessage:tm_sgnl:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TeleMessage TM SGNL contains an exposure of core dump file to an u",
            "nauthorized control sphere Vulnerability. This vulnerability is ba",
            "sed on a JSP application in which the heap content is roughly equi",
            "valent to a \"core dump\" in which a password previously sent over",
            " HTTP would be included in this dump."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-49113",
        vendor: "Roundcube",
        product: "Webmail",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "RoundCube Webmail contains a deserialization of untrusted data vul",
            "nerability that allows remote code execution by authenticated user",
            "s because the _from parameter in a URL is not validated in program",
            "/actions/settings/upload.php."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-49704",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint contains a code injection vulnerability that ",
            "could allow an authorized attacker to execute code over a network.",
            " This vulnerability could be chained with CVE-2025-49706. CVE-2025",
            "-53770 is a patch bypass for CVE-2025-49704, and the updates for C",
            "VE-2025-53770 include more robust protection than those "
        ),
        remediation: concat!(
            "Disconnect public-facing versions of SharePoint Server that have r",
            "eached their end-of-life (EOL) or end-of-service (EOS) to include ",
            "SharePoint Server 2013 and earlier versions. For supported version",
            "s, please follow the mitigations according to CISA (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-49706",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint contains an improper authentication vulnerabi",
            "lity that allows an authorized attacker to perform spoofing over a",
            " network. Successfully exploitation could allow an attacker to vie",
            "w sensitive information and make some changes to disclosed informa",
            "tion. This vulnerability could be chained with CVE-2025-"
        ),
        remediation: concat!(
            "Disconnect public-facing versions of SharePoint Server that have r",
            "eached their end-of-life (EOL) or end-of-service (EOS) to include ",
            "SharePoint Server 2013 and earlier versions. For supported version",
            "s, please follow the mitigations according to CISA (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-5086",
        vendor: "Dassault Systèmes",
        product: "DELMIA Apriso",
        cpe23: "cpe:2.3:a:dassault_syst_mes:delmia_apriso:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dassault Systèmes DELMIA Apriso contains a deserialization of untr",
            "usted data vulnerability that could lead to a remote code executio",
            "n."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-52691",
        vendor: "SmarterTools",
        product: "SmarterMail",
        cpe23: "cpe:2.3:a:smartertools:smartermail:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SmarterTools SmarterMail contains an unrestricted upload of file w",
            "ith dangerous type vulnerability that could allow an unauthenticat",
            "ed attacker to upload arbitrary files to any location on the mail ",
            "server, potentially enabling remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-53521",
        vendor: "F5",
        product: "BIG-IP",
        cpe23: "cpe:2.3:a:f5:big-ip:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "F5 BIG-IP APM contains a stack-based buffer overflow vulnerability",
            " that could allow a threat actor to achieve remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-53690",
        vendor: "Sitecore",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:sitecore:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sitecore Experience Manager (XM), Experience Platform (XP), Experi",
            "ence Commerce (XC), and Managed Cloud contain a deserialization of",
            " untrusted data vulnerability involving the use of default machine",
            " keys. This flaw allows attackers to exploit exposed ASP.NET machi",
            "ne keys to achieve remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-53770",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint Server on-premises contains a deserialization",
            " of untrusted data vulnerability that could allow an unauthorized ",
            "attacker to execute code over a network. This vulnerability could ",
            "be chained with CVE-2025-53771. CVE-2025-53770 is a patch bypass f",
            "or CVE-2025-49704, and the updates for CVE-2025-53770 in"
        ),
        remediation: concat!(
            "Disconnect public-facing versions of SharePoint Server that have r",
            "eached their end-of-life (EOL) or end-of-service (EOS) to include ",
            "SharePoint Server 2013 and earlier versions. For supported version",
            "s, please follow the mitigations according to CISA (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-54068",
        vendor: "Laravel",
        product: "Livewire",
        cpe23: "cpe:2.3:a:laravel:livewire:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Laravel Livewire contain a code injection vulnerability that could",
            " allow unauthenticated attackers to achieve remote command executi",
            "on in specific scenarios."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-5419",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains an out-of-bounds read and write vulner",
            "ability that could allow a remote attacker to potentially exploit ",
            "heap corruption via a crafted HTML page. This vulnerability could ",
            "affect multiple web browsers that utilize Chromium, including, but",
            " not limited to, Google Chrome, Microsoft Edge, and Oper"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-54236",
        vendor: "Adobe",
        product: "Commerce and Magento",
        cpe23: "cpe:2.3:a:adobe:commerce_and_magento:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Commerce and Magento Open Source contain an improper input v",
            "alidation vulnerability that could allow an attacker to take over ",
            "customer accounts through the Commerce REST API."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-54253",
        vendor: "Adobe",
        product: "Experience Manager (AEM) Forms",
        cpe23: "cpe:2.3:a:adobe:experience_manager_aem_forms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Experience Manager Forms in JEE contains an unspecified vuln",
            "erability that allows for arbitrary code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-54309",
        vendor: "CrushFTP",
        product: "CrushFTP",
        cpe23: "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "CrushFTP contains an unprotected alternate channel vulnerability. ",
            "When the DMZ proxy feature is not used, mishandles AS2 validation ",
            "and consequently allows remote attackers to obtain admin access vi",
            "a HTTPS."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-54313",
        vendor: "Prettier",
        product: "eslint-config-prettier",
        cpe23: "cpe:2.3:a:prettier:eslint-config-prettier:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Prettier eslint-config-prettier contains an embedded malicious cod",
            "e vulnerability. Installing an affected package executes an instal",
            "l.js file that launches the node-gyp.dll malware on Windows."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-54948",
        vendor: "Trend Micro",
        product: "Apex One",
        cpe23: "cpe:2.3:a:trend_micro:apex_one:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One Management Console (on-premise) contains an O",
            "S command injection vulnerability that could allow a pre-authentic",
            "ated remote attacker to upload malicious code and execute commands",
            " on affected installations."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-55177",
        vendor: "Meta Platforms",
        product: "WhatsApp",
        cpe23: "cpe:2.3:a:meta_platforms:whatsapp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Meta Platforms WhatsApp contains an incorrect authorization vulner",
            "ability due to an incomplete authorization of linked device synchr",
            "onization messages. This vulnerability could allow an unrelated us",
            "er to trigger processing of content from an arbitrary URL on a tar",
            "get’s device."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-55182",
        vendor: "Meta",
        product: "React Server Components",
        cpe23: "cpe:2.3:a:meta:react_server_components:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Meta React Server Components contains a remote code execution vuln",
            "erability that could allow unauthenticated remote code execution b",
            "y exploiting a flaw in how React decodes payloads sent to React Se",
            "rver Function endpoints. Please note CVE-2025-66478 has been rejec",
            "ted, but it is associated with CVE-2025- 55182."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-5777",
        vendor: "Citrix",
        product: "NetScaler ADC and Gateway",
        cpe23: "cpe:2.3:a:citrix:netscaler_adc_and_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Citrix NetScaler ADC and Gateway contain an out-of-bounds read vul",
            "nerability due to insufficient input validation. This vulnerabilit",
            "y can lead to memory overread when the NetScaler is configured as ",
            "a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA ",
            "virtual server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-57819",
        vendor: "Sangoma",
        product: "FreePBX",
        cpe23: "cpe:2.3:a:sangoma:freepbx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sangoma FreePBX contains an authentication bypass vulnerability du",
            "e to insufficiently sanitized user-supplied data allows unauthenti",
            "cated access to FreePBX Administrator leading to arbitrary databas",
            "e manipulation and remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-58034",
        vendor: "Fortinet",
        product: "FortiWeb",
        cpe23: "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiWeb contains an OS command Injection vulnerability t",
            "hat may allow an authenticated attacker to execute unauthorized co",
            "de on the underlying system via crafted HTTP requests or CLI comma",
            "nds."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-58360",
        vendor: "OSGeo",
        product: "GeoServer",
        cpe23: "cpe:2.3:a:osgeo:geoserver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OSGeo GeoServer contains an improper restriction of XML external e",
            "ntity reference vulnerability that occurs when the application acc",
            "epts XML input through a specific endpoint /geoserver/wms operatio",
            "n GetMap and could allow an attacker to define external entities w",
            "ithin the XML request."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-59230",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains an improper access control vulnerabilit",
            "y in Windows Remote Access Connection Manager which could allow an",
            " authorized attacker to elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-59287",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Server Update Service (WSUS) contains a deserial",
            "ization of untrusted data vulnerability that allows for remote cod",
            "e execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-59374",
        vendor: "ASUS",
        product: "Live Update",
        cpe23: "cpe:2.3:a:asus:live_update:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ASUS Live Update contains an embedded malicious code vulnerability",
            " client were distributed with unauthorized modifications introduce",
            "d through a supply chain compromise. The modified builds could cau",
            "se devices meeting specific targeting conditions to perform uninte",
            "nded actions. The impacted product could be end-of-life "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-59689",
        vendor: "Libraesva",
        product: "Email Security Gateway",
        cpe23: "cpe:2.3:a:libraesva:email_security_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Libraesva Email Security Gateway (ESG) contains a command injectio",
            "n vulnerability which allows command injection via a compressed e-",
            "mail attachment."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-59718",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiOS, FortiSwitchMaster, FortiProxy, and FortiWeb cont",
            "ain an improper verification of cryptographic signature vulnerabil",
            "ity that may allow an unauthenticated attacker to bypass the Forti",
            "Cloud SSO login authentication via a crafted SAML message. Please ",
            "be aware that CVE-2025-59719 pertains to the same proble"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-60710",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows contains a link following vulnerability that all",
            "ows for privilege escalation"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-61624",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "FortiOS, FortiPAM, FortiProxy, and FortiSwitchManager contain a pa",
            "th traversal vulnerability that may allow an authenticated attacke",
            "r with admin profile and at least read-write permissions to write ",
            "or delete arbitrary files via specific CLI commands."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-61757",
        vendor: "Oracle",
        product: "Fusion Middleware",
        cpe23: "cpe:2.3:a:oracle:fusion_middleware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Fusion Middleware contains a missing authentication for cri",
            "tical function vulnerability, allowing unauthenticated remote atta",
            "ckers to take over Identity Manager."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-61882",
        vendor: "Oracle",
        product: "E-Business Suite",
        cpe23: "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Oracle E-Business Suite contains an unspecified vulnerability in t",
            "he BI Publisher Integration component. The vulnerability allows un",
            "authenticated attacker with network access via HTTP to compromise ",
            "Oracle Concurrent Processing. Successful attacks can result in tak",
            "eover of Oracle Concurrent Processing."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-61884",
        vendor: "Oracle",
        product: "E-Business Suite",
        cpe23: "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Oracle E-Business Suite contains a server-side request forgery (SS",
            "RF) vulnerability in the Runtime component of Oracle Configurator.",
            " This vulnerability is remotely exploitable without authentication",
            "."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-61932",
        vendor: "Motex",
        product: "LANSCOPE Endpoint Manager",
        cpe23: "cpe:2.3:a:motex:lanscope_endpoint_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Motex LANSCOPE Endpoint Manager contains an improper verification ",
            "of source of a communication channel vulnerability allowing an att",
            "acker to execute arbitrary code by sending specially crafted packe",
            "ts."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-6204",
        vendor: "Dassault Systèmes",
        product: "DELMIA Apriso",
        cpe23: "cpe:2.3:a:dassault_syst_mes:delmia_apriso:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dassault Systèmes DELMIA Apriso contains a code injection vulnerab",
            "ility that could allow an attacker to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-6205",
        vendor: "Dassault Systèmes",
        product: "DELMIA Apriso",
        cpe23: "cpe:2.3:a:dassault_syst_mes:delmia_apriso:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dassault Systèmes DELMIA Apriso contains a missing authorization v",
            "ulnerability that could allow an attacker to gain privileged acces",
            "s to the application."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-6218",
        vendor: "RARLAB",
        product: "WinRAR",
        cpe23: "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "RARLAB WinRAR contains a path traversal vulnerability allowing an ",
            "attacker to execute code in the context of the current user."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-62215",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Kernel contains a race condition vulnerability t",
            "hat allows a local attacker with low-level privileges to escalate ",
            "privileges. Successful exploitation of this vulnerability could en",
            "able the attacker to gain SYSTEM-level access."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-62221",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Cloud Files Mini Filter Driver contains a use af",
            "ter free vulnerability that can allow an authorized attacker to el",
            "evate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-62593",
        vendor: "Ray-Project",
        product: "Ray",
        cpe23: "cpe:2.3:a:ray-project:ray:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ray-Project Ray contains a code injection vulnerability that could",
            " allow remote code execution. Developers using Ray as a developmen",
            "t tool may be exposed to this vulnerability exploitable through Fi",
            "refox and Safari."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-64328",
        vendor: "Sangoma",
        product: "FreePBX",
        cpe23: "cpe:2.3:a:sangoma:freepbx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sangoma FreePBX Endpoint Manager contains an OS command injection ",
            "vulnerability that could allow for a post-authentication command i",
            "njection by an authenticated known user via the testconnection -> ",
            "check_ssh_connect() function. An attacker can leverage this vulner",
            "ability to potentially obtain remote access to the syste"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-64446",
        vendor: "Fortinet",
        product: "FortiWeb",
        cpe23: "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiWeb contains a relative path traversal vulnerability",
            " that may allow an unauthenticated attacker to execute administrat",
            "ive commands on the system via crafted HTTP or HTTPS requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-6543",
        vendor: "Citrix",
        product: "NetScaler ADC and Gateway",
        cpe23: "cpe:2.3:a:citrix:netscaler_adc_and_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and Gateway contain a buffer overflow vulnera",
            "bility leading to unintended control flow and Denial of Service. N",
            "etScaler must be configured as Gateway (VPN virtual server, ICA Pr",
            "oxy, CVPN, RDP Proxy) OR AAA virtual server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-6554",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains a type confusion vulnerability that co",
            "uld allow a remote attacker to perform arbitrary read/write via a ",
            "crafted HTML page. This vulnerability could affect multiple web br",
            "owsers that utilize Chromium, including, but not limited to, Googl",
            "e Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-6558",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium contains an improper input validation vulnerabilit",
            "y in ANGLE and GPU. This vulnerability could allow a remote attack",
            "er to potentially perform a sandbox escape via a crafted HTML page",
            ". This vulnerability could affect multiple web browsers that utili",
            "ze Chromium, including, but not limited to, Google Chrom"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-66376",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting vulnerability in the Classic UI where attackers could abuse",
            " Cascading Style Sheets (CSS) @import directives in email HTML."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-66644",
        vendor: "Array Networks",
        product: "ArrayOS AG",
        cpe23: "cpe:2.3:a:array_networks:arrayos_ag:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Array Networks ArrayOS AG contains an OS command injection vulnera",
            "bility that could allow an attacker to execute arbitrary commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-67038",
        vendor: "Lantronix",
        product: "EDS5000",
        cpe23: "cpe:2.3:a:lantronix:eds5000:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Lantronix EDS5000 contains a code injection vulnerability that cou",
            "ld allow attackers to inject arbitrary OS commands into the userna",
            "me parameter. Injected commands are executed with root privileges."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-68461",
        vendor: "Roundcube",
        product: "Webmail",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "RoundCube Webmail contains a cross-site scripting vulnerability vi",
            "a the animate tag in an SVG document."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-68613",
        vendor: "n8n",
        product: "n8n",
        cpe23: "cpe:2.3:a:n8n:n8n:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "n8n contains an improper control of dynamically managed code resou",
            "rces vulnerability in its workflow expression evaluation system th",
            "at allows for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-68645",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a PHP remote fil",
            "e inclusion vulnerability that could allow for remote attackers to",
            " craft requests to the /h/rest endpoint to influence internal requ",
            "est dispatching, allowing inclusion of arbitrary files from the We",
            "bRoot directory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-68686",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiOS contains an exposure of sensitive information to ",
            "an unauthorized actor vulnerability. This may allow a remote unaut",
            "henticated attacker to bypass the patch developed for the symbolic",
            " link persistency mechanism observed in some post-exploit cases, v",
            "ia crafted HTTP requests. An attacker would need first t"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-7775",
        vendor: "Citrix",
        product: "NetScaler",
        cpe23: "cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain a memory overfl",
            "ow vulnerability that could allow for remote code execution and/or",
            " denial of service."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-8088",
        vendor: "RARLAB",
        product: "WinRAR",
        cpe23: "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "RARLAB WinRAR contains a path traversal vulnerability affecting th",
            "e Windows version of WinRAR. This vulnerability could allow an att",
            "acker to execute arbitrary code by crafting malicious archive file",
            "s."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-8110",
        vendor: "Gogs",
        product: "Gogs",
        cpe23: "cpe:2.3:a:gogs:gogs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Gogs contains a path traversal vulnerability affecting improper Sy",
            "mbolic link handling in the PutContents API that could allow for c",
            "ode execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-8875",
        vendor: "N-able",
        product: "N-Central",
        cpe23: "cpe:2.3:a:n-able:n-central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "N-able N-Central contains an insecure deserialization vulnerabilit",
            "y that could lead to command execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-8876",
        vendor: "N-able",
        product: "N-Central",
        cpe23: "cpe:2.3:a:n-able:n-central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "N-able N-Central contains a command injection vulnerability via im",
            "proper sanitization of user input."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-9242",
        vendor: "WatchGuard",
        product: "Firebox",
        cpe23: "cpe:2.3:a:watchguard:firebox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WatchGuard Firebox contains an out-of-bounds write vulnerability i",
            "n the OS iked process that may allow a remote unauthenticated atta",
            "cker to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2025-9377",
        vendor: "TP-Link",
        product: "Multiple Routers",
        cpe23: "cpe:2.3:a:tp-link:multiple_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TP-Link Archer C7(EU) and TL-WR841N/ND(MS) contain an OS command i",
            "njection vulnerability that exists in the Parental Control page. T",
            "he impacted products could be end-of-life (EoL) and/or end-of-serv",
            "ice (EoS). Users should discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-0257",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains an authentication bypass vulner",
            "ability that allows attackers to bypass security restrictions and ",
            "establish an unauthorized VPN connection."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-0300",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains an out-of-bounds write vulnerab",
            "ility in the User-ID Authentication Portal (aka Captive Portal) se",
            "rvice that can allow an unauthenticated attacker to execute arbitr",
            "ary code with root privileges on the PA-Series and VM-Series firew",
            "alls by sending specially crafted packets."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable. Until the vendor releases an off",
            "icial fix, the following workaround should be implemented:  - "
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-0322",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains a code injection vulnerability ",
            "that could allow an authenticated attacker with network access to ",
            "execute arbitrary code with root privileges on the firewall."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-0770",
        vendor: "Langflow",
        product: "Langflow",
        cpe23: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Langflow contains an inclusion of functionality from untrusted con",
            "trol sphere vulnerability that allows remote attackers to execute ",
            "arbitrary code on affected installations."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-102489",
        vendor: "Zammad GmbH",
        product: "Zammad",
        cpe23: "cpe:2.3:a:zammad_gmbh:zammad:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zammad GmbH Zammad contains a session fixation vulnerability that ",
            "can lead to remote code execution as the zammad user. This vulnera",
            "bility can be chained with CVE-2026-102490."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-102490",
        vendor: "Zammad GmbH",
        product: "Zammad",
        cpe23: "cpe:2.3:a:zammad_gmbh:zammad:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zammad GmbH Zammad contains an improper privilege management vulne",
            "rability that can allow the local zammad user to escalate privileg",
            "es to root. This vulnerability can be chained with CVE-2026-102489",
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
        cve_id: "CVE-2026-102764",
        vendor: "BeyondTrust",
        product: "Remote Support",
        cpe23: "cpe:2.3:a:beyondtrust:remote_support:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BeyondTrust Remote Support contains an authentication bypass by sp",
            "oofing vulnerability that could allow a remote attacker to perform",
            " file operations on the appliance."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-102895",
        vendor: "GPUStack",
        product: "GPUStack",
        cpe23: "cpe:2.3:a:gpustack:gpustack:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GPUStack contains an improper authentication vulnerability which c",
            "ould allow unauthenticated administrative access, including user a",
            "nd model changes, persistent administrator API-key creation, discl",
            "osure of worker and cloud-provider secrets, and code execution thr",
            "ough POST /v2/inference-backends/from-yaml."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-104286",
        vendor: "Fortinet",
        product: "FortiMail",
        cpe23: "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiMail contains a path traversal and an improper neutr",
            "alization of NULL byte or NULL character vulnerability that may al",
            "low an unauthenticated attacker to write arbitrary files on the un",
            "derlying system via crafted HTTP or HTTPS requests."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-104935",
        vendor: "Ivanti",
        product: "Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Connect Secure contains an authentication bypass by spoofin",
            "g vulnerability that allows a remote unauthenticated attacker to e",
            "xecute arbitrary commands."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-105133",
        vendor: "Ahsay",
        product: "AhsayCBS",
        cpe23: "cpe:2.3:a:ahsay:ahsaycbs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ahsay AhsayCBS contains an improper authentication vulnerability t",
            "hat could allow a remote attacker to bypass authentication via man",
            "ipulation of the random parameter in the API component’s checkSysP",
            "wd function. This vulnerability can be chained with CVE-2026-10513",
            "4."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-105134",
        vendor: "Ahsay",
        product: "AhsayCBS",
        cpe23: "cpe:2.3:a:ahsay:ahsaycbs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ahsay AhsayCBS contains a command injection vulnerability that cou",
            "ld allow a remote attacker to execute operating system commands vi",
            "a manipulation of the random parameter in the Replication Receiver",
            " component’s /rps/api/json/UpdateReceivers.do endpoint. This vulne",
            "rability can be chained with CVE-2026-105133."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-10520",
        vendor: "Ivanti",
        product: "Sentry",
        cpe23: "cpe:2.3:a:ivanti:sentry:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Sentry (formerly known as MobileIron Sentry) contains an OS",
            " command injection vulnerability which could allow a remote unauth",
            "enticated user to achieve root-level remote code execution. This v",
            "ulnerability can be successfully exploited in cases where the Sent",
            "ry appliance is in an unmanaged state with its endpoints"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-106931",
        vendor: "EG Secure Solutions",
        product: "SiteGuard Server Edition",
        cpe23: concat!(
            "cpe:2.3:a:eg_secure_solutions:siteguard_server_edition:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "EG Secure Solutions SiteGuard Server Edition contains an OS comman",
            "d injection vulnerability which may allow an attacker to execute a",
            "rbitrary OS commands with root or SYSTEM privileges on the system ",
            "running the affected product."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-109618",
        vendor: "PHP Group",
        product: "PHP",
        cpe23: "cpe:2.3:a:php_group:php:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PHP contains an out-of-memory corruption vulnerability that allows",
            " for unauthenticated remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-109619",
        vendor: "PHP Group",
        product: "PHP",
        cpe23: "cpe:2.3:a:php_group:php:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PHP contains a stale internal request-state vulnerability that all",
            "ows for unauthenticated remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-110447",
        vendor: "Collabora",
        product: "Collabora Online – Built-in CODE Server",
        cpe23: concat!(
            "cpe:2.3:a:collabora:collabora_online_built-in_code_server:*:*:*:*:",
            "*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Collabora Collabora Online – Built-in CODE Server when used within",
            " the NextCloud platform contains an OS command injection vulnerabi",
            "lity that allows for remote code execution when the CODE server is",
            "n't running."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-110936",
        vendor: "Siemens",
        product: "Software Center",
        cpe23: "cpe:2.3:a:siemens:software_center:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Siemens Software Center contains an uncontrolled search path eleme",
            "nt vulnerability that could allow an authenticated local attacker ",
            "to place a specially crafted DLL in a directory that the applicati",
            "on searches, leading to arbitrary code execution with the privileg",
            "es of the affected application."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-111357",
        vendor: "Ivanti",
        product: "Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Connect Secure contains a missing authentication for critic",
            "al function vulnerability that could allow a local authenticated a",
            "ttacker to escalate their privileges. This vulnerability can be ch",
            "ained with CVE-2026-104935 and CVE-2026-118527."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-111497",
        vendor: "Google",
        product: "Brotli",
        cpe23: "cpe:2.3:a:google:brotli:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Brotli contains an unchecked return value vulnerability tha",
            "t allows a remote unauthenticated attacker to corrupt adjacent dec",
            "oder state memory, disclose sensitive memory contents, cause a den",
            "ial of service, or potentially execute arbitrary code using a craf",
            "ted Brotli-compressed stream."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-111560",
        vendor: "Barracuda Networks",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:barracuda_networks:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Barracuda Networks Email Security Gateway (ESG), Load Balancer, Ap",
            "plication Delivery Controller (ADC), Message Archiver (BMA), WAF C",
            "ontrol Center (WCC), Web Application Firewall (WAF), and Web Secur",
            "ity Gateway (WSG) contain an OS command injection vulnerability. T",
            "his vulnerability could allow an authenticated administr"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-111793",
        vendor: "Openwave Messaging Limited",
        product: "Webtop Media Transcoder",
        cpe23: concat!(
            "cpe:2.3:a:openwave_messaging_limited:webtop_media_transcoder:*:*:*",
            ":*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Openwave Messaging Limited Webtop Media Transcoder contains an inc",
            "orrect resource transfer between spheres vulnerability that may al",
            "low an authenticated user to process and convert unintended docume",
            "nt types if bypassing the Webmail experience."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-114625",
        vendor: "Arista",
        product: "VeloCloud Orchestrator",
        cpe23: "cpe:2.3:a:arista:velocloud_orchestrator:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arista VeloCloud Orchestrator on-prem contains a SQL injection vul",
            "nerability that may allow a remote attacker to access privileged i",
            "nternal functionality and impact the VCO host. Successful exploita",
            "tion may compromise the confidentiality, integrity, and availabili",
            "ty of the orchestrator and data managed by the orchestra"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-114713",
        vendor: "UnrealIRCd",
        product: "UnrealIRCd",
        cpe23: "cpe:2.3:a:unrealircd:unrealircd:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "UnrealIRCd UnrealIRCd contains an improper neutralization of delim",
            "iters vulnerability that allows any user on a network with two or ",
            "more linked servers to inject server-to-server commands that are e",
            "xecuted with server authority."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-115731",
        vendor: "Perforce",
        product: "Puppet Enterprise",
        cpe23: "cpe:2.3:a:perforce:puppet_enterprise:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Perforce Puppet Enterprise contains a deserialization of untrusted",
            " data vulnerability in Puppet’s report-processing code that allows",
            " a client with any CA-signed agent certificate to execute arbitrar",
            "y code on the Puppet Server as the service user by submitting a re",
            "port containing a crafted rich-data type through a PUT r"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-11645",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 out-of-bounds read and write vulnerability that",
            " could allow a remote attacker to execute arbitrary code inside a ",
            "sandbox via a crafted HTML page. This vulnerability could affect m",
            "ultiple web browsers that utilize Chromium, including, but not lim",
            "ited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-116606",
        vendor: "Barracuda Networks",
        product: "Barracuda Email Security Gateway (ESG)",
        cpe23: concat!(
            "cpe:2.3:a:barracuda_networks:barracuda_email_security_gateway_esg:",
            "*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Barracuda Networks Email Security Gateway (ESG) contains an authen",
            "tication bypass using an alternate path or channel that could allo",
            "w an unauthenticated remote attacker to invoke a configuration-imp",
            "ort function and restore a crafted, compatible backup archive, res",
            "ulting in unauthorized modification of the appliance’s g"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-116779",
        vendor: "SignalWire",
        product: "FreeSwitch",
        cpe23: "cpe:2.3:a:signalwire:freeswitch:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SignalWire FreeSwitch contains a code injection vulnerability that",
            " permits configuration and credential disclosure, arbitrary call c",
            "ontrol, and command execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-118527",
        vendor: "Ivanti",
        product: "Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Connect Secure contains a generation of predictable numbers",
            " or identifiers vulnerability that allows a remote authenticated a",
            "ttacker to upload files with attacker-controlled content to a know",
            "n location on disk. This vulnerability can be chained with CVE-202",
            "6-104935 and CVE-2026-111357."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-119977",
        vendor: "WordPress",
        product: "WordPress Core",
        cpe23: "cpe:2.3:a:wordpress:wordpress_core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress WordPress Core contains a time-of-check time-of-use (TOC",
            "TOU) race condition vulnerability that could allow unauthenticated",
            " attackers to execute code on the server during the upgrade window",
            ". This is due to predictable, web-accessible staging paths used du",
            "ring full-package core upgrades."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-123039",
        vendor: "Check Point",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:check_point:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Check Point Firewall, Multi-Domain Security Management Server, Sca",
            "lable Platforms, Security Gateway, and Security Management Server ",
            "contain an incorrect permissions assignment for critical resources",
            " vulnerability when the Gaia OS DynamicCLI daemon runs as root and",
            " listens on a world-writable local socket without authen"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-123158",
        vendor: "OpenBSD",
        product: "OpenSSH",
        cpe23: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OpenBSD OpenSSH on Linux contains an unexpected status code or ret",
            "urn value vulnerability that could allow for authentication bypass",
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
        cve_id: "CVE-2026-123218",
        vendor: "IBM",
        product: "Aspera Faspex",
        cpe23: "cpe:2.3:a:ibm:aspera_faspex:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "IBM Aspera Faspex contains an incorrect authorization vulnerabilit",
            "y that could allow an authenticated user to craft a specific messa",
            "ge to bypass authorization, causing privilege escalations."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-124194",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Outlook contains a missing user interaction for p",
            "otentially unsafe action vulnerability that allows an unauthorized",
            " attacker to perform spoofing over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-125350",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium contains a use-after-free vulnerability in the XML",
            " component that could allow a remote attacker to execute arbitrary",
            " code inside the sandbox via a specially crafted webpage. This vul",
            "nerability could affect multiple web browsers that utilize Chromiu",
            "m, including, but not limited to, Google Chrome, Microso"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-12569",
        vendor: "PTC",
        product: "Windchill and FlexPLM",
        cpe23: "cpe:2.3:a:ptc:windchill_and_flexplm:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "PTC Windchill and FlexPLM contains an improper input validation vu",
            "lnerability allowing an unauthenticated, remote attacker to execut",
            "e arbitrary code by sending a malicious request to the network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-1281",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vu",
            "lnerability that could allow attackers to achieve unauthenticated ",
            "remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-1340",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vu",
            "lnerability that could allow attackers to achieve unauthenticated ",
            "remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-15409",
        vendor: "SonicWall",
        product: "SMA1000 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma1000_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-918",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SMA1000 Appliances contain a server-side request forgery",
            " vulnerability that could allow a remote unauthenticated attacker ",
            "to potentially cause the appliance to make requests to unintended ",
            "location."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-15410",
        vendor: "SonicWall",
        product: "SMA1000 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma1000_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SMA1000 Appliances contain a code injection vulnerabilit",
            "y which in specific conditions could potentially enable a remote a",
            "uthenticated attacker as administrator to execute arbitrary OS com",
            "mands."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-1603",
        vendor: "Ivanti",
        product: "Endpoint Manager (EPM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_epm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager (EPM) contains an authentication bypass us",
            "ing an alternate path or channel vulnerability that could allow a ",
            "remote unauthenticated attacker to leak specific stored credential",
            " data."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-16232",
        vendor: "Check Point",
        product: "SmartConsole",
        cpe23: "cpe:2.3:a:check_point:smartconsole:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Check Point SmartConsole contains an improper authentication vulne",
            "rability which could allow an unauthenticated remote attacker to o",
            "btain an application login token and use it to authenticate with f",
            "ull administrative privileges."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-16812",
        vendor: "Arista",
        product: "VeloCloud Orchestrator",
        cpe23: "cpe:2.3:a:arista:velocloud_orchestrator:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arista VeloCloud Orchestrator On-Prem contains an OS command injec",
            "tion vulnerability that may allow a remote attacker to access priv",
            "ileged internal functionality and impact the VCO host. Successful ",
            "exploitation may compromise the confidentiality, integrity, and av",
            "ailability of the orchestrator and data managed by the o"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-1731",
        vendor: "BeyondTrust",
        product: "Remote Support (RS) and Privileged Remote Access (PRA)",
        cpe23: concat!(
            "cpe:2.3:a:beyondtrust:remote_support_rs_and_privileged_remote_acce",
            "ss_pra:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA)",
            "contain an OS command injection vulnerability. Successful exploita",
            "tion could allow an unauthenticated remote attacker to execute ope",
            "rating system commands in the context of the site user. Successful",
            " exploitation requires no authentication or user interac"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-18556",
        vendor: "N-able",
        product: "N-central",
        cpe23: "cpe:2.3:a:n-able:n-central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "N-able N-central contains an authentication bypass using an altern",
            "ate path or channel that allows for authentication bypass."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-18577",
        vendor: "N-able",
        product: "N-central",
        cpe23: "cpe:2.3:a:n-able:n-central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "N-able N-central contains an authentication bypass using an altern",
            "ate path or channel allows for authentication bypass and account t",
            "akeover in N-central. This vulnerability is the result of an incom",
            "plete patch for CVE-2026-18556."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-19490",
        vendor: "Citrix",
        product: "NetScaler",
        cpe23: "cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain an authenticati",
            "on-bypass vulnerability involving an alternate path or channel. Wh",
            "en the NetScaler appliance is configured as an AAA virtual server ",
            "or as a Gateway (SSL VPN, ICA Proxy, CVPN, or RDP Proxy), an unaut",
            "henticated remote threat actor may be able to bypass aut"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-19868",
        vendor: "SonicWall",
        product: "SonicOS SSLVPN",
        cpe23: "cpe:2.3:a:sonicwall:sonicos_sslvpn:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SonicWall SonicOS SSLVPN contains a use of single-factor authentic",
            "ation vulnerability that may allow a user with valid credentials f",
            "or an alternate authentication method to bypass SAML authenticatio",
            "n controls. Successful exploitation may also bypass SAML-enforced ",
            "multi-factor authentication (MFA)."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20045",
        vendor: "Cisco",
        product: "Unified Communications Manager",
        cpe23: "cpe:2.3:a:cisco:unified_communications_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Unified Communications Manager (Unified CM), Cisco Unified C",
            "ommunications Manager Session Management Edition (Unified CM SME),",
            " Cisco Unified Communications Manager IM & Presence Service (Unifi",
            "ed CM IM&P), Cisco Unity Connection, and Cisco Webex Calling Dedic",
            "ated Instance contain a code injection vulnerability tha"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20079",
        vendor: "Cisco",
        product: concat!(
            "Secure Firewall Management Center (FMC) and Security Cloud Control",
            " (SCC) Firewall Management"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_management_center_fmc_and_security",
            "_cloud_control_scc_firewall_management:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Firewall Management Center (FMC) Software and Cisco S",
            "ecurity Cloud Control (SCC) Firewall Management contain an authent",
            "ication Bypass using an alternate path or channel vulnerability th",
            "at could allow an unauthenticated, remote attacker to bypass authe",
            "ntication and execute script files on an affected device"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20122",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Manger",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan_manger:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Manager contains an incorrect use of privile",
            "ged APIs vulnerability due to improper file handling on the API in",
            "terface of an affected system. An attacker could exploit this vuln",
            "erability by uploading a malicious file on the local file system. ",
            "A successful exploit could allow the attacker to overwri"
        ),
        remediation: concat!(
            "Please adhere to CISA’s guidelines to assess exposure and mitigate",
            " risks associated with Cisco SD-WAN devices as outlines in CISA’s ",
            "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s “",
            "Hunt & Hardening Guidance for Cisco SD-WAN Devices (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20127",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Controller and Manager",
        cpe23: concat!(
            "cpe:2.3:a:cisco:catalyst_sd-wan_controller_and_manager:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Controller, formerly SD-WAN vSmart, and Cisc",
            "o Catalyst SD-WAN Manager, formerly SD-WAN vManage, contain an aut",
            "hentication bypass vulnerability could allow an unauthenticated, r",
            "emote attacker to bypass authentication and obtain administrative ",
            "privileges on an affected system. This vulnerability exi"
        ),
        remediation: concat!(
            "Please adhere to CISA’s guidelines to assess exposure and mitigate",
            " risks associated with Cisco SD-WAN devices as outlines in CISA’s ",
            "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s “",
            "Hunt & Hardening Guidance for Cisco SD-WAN Devices (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20128",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Manager",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Manager contains a storing passwords in a re",
            "coverable format vulnerability that allows an authenticated, local",
            " attacker to gain DCA user privileges by accessing a credential fi",
            "le for the DCA user on the filesystem as a low-privileged user."
        ),
        remediation: concat!(
            "Please adhere to CISA’s guidelines to assess exposure and mitigate",
            " risks associated with Cisco SD-WAN devices as outlines in CISA’s ",
            "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s “",
            "Hunt & Hardening Guidance for Cisco SD-WAN Devices (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20131",
        vendor: "Cisco",
        product: "Secure Firewall Management Center (FMC)",
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_management_center_fmc:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco Secure Firewall Management Center (FMC) Software and Cisco S",
            "ecurity Cloud Control (SCC) Firewall Management contain a deserial",
            "ization of untrusted data vulnerability in the web-based managemen",
            "t interface that could allow an unauthenticated, remote attacker t",
            "o execute arbitrary Java code as root on an affected dev"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20133",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Manager",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Manager contains an exposure of sensitive in",
            "formation to an unauthorized actor vulnerability that could allow ",
            "remote attackers to view sensitive information on affected systems",
            "."
        ),
        remediation: concat!(
            "Please adhere to CISA’s guidelines to assess exposure and mitigate",
            " risks associated with Cisco SD-WAN devices as outlines in CISA’s ",
            "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s “",
            "Hunt & Hardening Guidance for Cisco SD-WAN Devices (URL listed"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20182",
        vendor: "Cisco",
        product: "Catalyst SD-WAN",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Controller & Manager contain an authenticati",
            "on bypass vulnerability that allows an unauthenticated, remote att",
            "acker to bypass authentication and obtain administrative privilege",
            "s on an affected system."
        ),
        remediation: concat!(
            "Please adhere to CISA’s guidelines to assess exposure and mitigate",
            " risks associated with Cisco SD-WAN devices as outlined in CISA’s ",
            "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s H",
            "unt & Hardening Guidance for Cisco SD-WAN Devices (URL listed "
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20230",
        vendor: "Cisco",
        product: "Unified Communications Manager",
        cpe23: "cpe:2.3:a:cisco:unified_communications_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Unified Communications Manager (Unified CM) and Cisco Unifie",
            "d Communications Manager Session Management Edition (Unified CM SM",
            "E) contain a server-side request forgery (SSRF) Vulnerability that",
            " could allow an unauthenticated, remote attacker to write files to",
            " the underlying operating system that could be used late"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20245",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Manager",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Manager formerly SD-WAN vManage contains an ",
            "improper encoding or escaping of output vulnerability. This vulner",
            "ability could allow an authenticated, local attacker to execute ar",
            "bitrary commands as root by supplying a crafted file to the affect",
            "ed system."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20253",
        vendor: "Splunk",
        product: "Enterprise",
        cpe23: "cpe:2.3:a:splunk:enterprise:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Splunk Enterprise contains a missing authentication for critical f",
            "unction vulnerability which could allow an unauthenticated user to",
            " create or truncate arbitrary files through a PostgreSQL sidecar s",
            "ervice endpoint."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20262",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Manager",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Manager contains a directory or path travers",
            "al vulnerability that could allow an authenticated, remote attacke",
            "r to create a file or overwrite any file on the filesystem of an a",
            "ffected system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20316",
        vendor: "Cisco",
        product: "Secure Firewall Management Center (FMC)",
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_management_center_fmc:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco Secure Firewall Management Center (FMC) formerly known as Fi",
            "repower Management Center contains a use of hard-coded password vu",
            "lnerability that could allow an unauthenticated, remote attacker t",
            "o log in to an affected device using a low-privileged account to a",
            "ccess sensitive data within the impacted systems."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20320",
        vendor: "Cisco",
        product: "BroadWorks",
        cpe23: "cpe:2.3:a:cisco:broadworks:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco BroadWorks contains an improper restriction of XML external ",
            "entity reference vulnerability that could allow an unauthenticated",
            ", remote attacker to read sensitive configuration information on a",
            "n affected system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20349",
        vendor: "Cisco",
        product: concat!(
            "Secure Firewall Adaptive Security Appliance (ASA) and Secure Firew",
            "all Threat Defense (FTD)"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_adaptive_security_appliance_asa_an",
            "d_secure_firewall_threat_defense_ftd:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure",
            " Firewall Threat Defense (FTD) contain a heap inspection vulnerabi",
            "lity that could allow an unauthenticated, remote attacker to cause",
            " the device to reload unexpectedly, resulting in a denial of servi",
            "ce (DoS) condition."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20700",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, tvOS, watchOS, and visionOS contain an improper ",
            "restriction of operations within the bounds of a memory buffer vul",
            "nerability that could allow an attacker with memory write the capa",
            "bility to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20805",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Desktop Windows Manager contains an information ",
            "disclosure vulnerability that allows an authorized attacker to dis",
            "close information locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-20963",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint contains a deserialization of untrusted data ",
            "vulnerability that allows an unauthorized attacker to execute code",
            " over a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21385",
        vendor: "Qualcomm",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:qualcomm:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Qualcomm chipsets contain a memory corruption vulnerabili",
            "ty while using alignments for memory allocation."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21509",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a security feature bypass vulnerability ",
            "in which reliance on untrusted inputs in a security decision in Mi",
            "crosoft Office could allow an unauthorized attacker to bypass a se",
            "curity feature locally. Some of the impacted product(s) could be e",
            "nd-of-life (EoL) and/or end-of-service (EoS). Users are "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21510",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Shell contains a protection mechanism failure vu",
            "lnerability that could allow an unauthorized attacker to bypass a ",
            "security feature over a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21513",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft MSHTML Framework contains a protection mechanism failure",
            " vulnerability that could allow an unauthorized attacker to bypass",
            " a security feature over a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21514",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Word contains a reliance on untrusted inputs in a",
            " security decision vulnerability that could allow an authorized at",
            "tacker to elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21519",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Desktop Windows Manager contains a type confusion vulner",
            "ability that could allow an authorized attacker to elevate privile",
            "ges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21525",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Remote Access Connection Manager contains a NULL",
            " pointer dereference that could allow an unauthorized attacker to ",
            "deny service locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21533",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Remote Desktop Services contains an improper pri",
            "vilege management vulnerability that could allow an authorized att",
            "acker to elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21589",
        vendor: "Atlassian",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:atlassian:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Atlassian products (Bitbucket Data Center ,Confluence Dat",
            "a Center, Jira Service Management Data Center, Jira Software Data ",
            "Center, Bamboo Data Center, Crowd Data Center, Crucible and Fishey",
            "e) contain a files or directories accessible to external parties v",
            "ulnerability which could allow an unauthenticated attack"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21643",
        vendor: "Fortinet",
        product: "FortiClient EMS",
        cpe23: "cpe:2.3:a:fortinet:forticlient_ems:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiClient EMS contains a SQL injection vulnerability th",
            "at may allow an unauthenticated attacker to execute unauthorized c",
            "ode or commands via specifically crafted HTTP requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-21962",
        vendor: "Oracle",
        product: "HTTP Server and Oracle Weblogic Server Proxy Plug-in",
        cpe23: concat!(
            "cpe:2.3:a:oracle:http_server_and_oracle_weblogic_server_proxy_plug",
            "-in:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in contai",
            "n an improper access control vulnerability that can result in unau",
            "thorized creation, deletion or modification access to critical dat",
            "a as well as unauthorized access to critical data or complete acce",
            "ss to all Oracle HTTP Server and Oracle Weblogic Server "
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-22719",
        vendor: "Broadcom",
        product: "VMware Aria Operations",
        cpe23: "cpe:2.3:a:broadcom:vmware_aria_operations:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Broadcom VMware Aria Operations formerly known as vRealize Operati",
            "ons (vROps) contains a command injection vulnerability that allows",
            " an unauthenticated attacker to execute arbitrary commands, potent",
            "ially leading to remote code execution during support‑assisted pro",
            "duct migration."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-22769",
        vendor: "Dell",
        product: "RecoverPoint for Virtual Machines (RP4VMs)",
        cpe23: concat!(
            "cpe:2.3:a:dell:recoverpoint_for_virtual_machines_rp4vms:*:*:*:*:*:",
            "*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-798",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dell RecoverPoint for Virtual Machines (RP4VMs) contains an use of",
            " hard-coded credentials vulnerability that could allow an unauthen",
            "ticated remote attacker to gain unauthorized access to the underly",
            "ing operating system and root-level persistence."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-23760",
        vendor: "SmarterTools",
        product: "SmarterMail",
        cpe23: "cpe:2.3:a:smartertools:smartermail:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SmarterTools SmarterMail contains an authentication bypass using a",
            "n alternate path or channel vulnerability in the password reset AP",
            "I. The force-reset-password endpoint permits anonymous requests an",
            "d fails to verify the existing password or a reset token when rese",
            "tting system administrator accounts. This could allow an"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-24061",
        vendor: "GNU",
        product: "InetUtils",
        cpe23: "cpe:2.3:a:gnu:inetutils:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GNU InetUtils contains an argument injection vulnerability in teln",
            "etd that could allow for remote authentication bypass via a \"-f r",
            "oot\" value for the USER environment variable."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-2441",
        vendor: "Google",
        product: "Chromium",
        cpe23: "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium CSS contains a use-after-free vulnerability that c",
            "ould allow a remote attacker to potentially exploit heap corruptio",
            "n via a crafted HTML page. This vulnerability could affect multipl",
            "e web browsers that utilize Chromium, including, but not limited t",
            "o, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-24423",
        vendor: "SmarterTools",
        product: "SmarterMail",
        cpe23: "cpe:2.3:a:smartertools:smartermail:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SmarterTools SmarterMail contains a missing authentication for cri",
            "tical function vulnerability in the ConnectToHub API method. This ",
            "could allow the attacker to point the SmarterMail instance to a ma",
            "licious HTTP server which serves the malicious OS command and coul",
            "d lead to command execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-24858",
        vendor: "Fortinet",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:fortinet:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiAnalyzer, FortiManager, FortiOS, and FortiProxy cont",
            "ain an authentication bypass using an alternate path or channel th",
            "at could allow an attacker with a FortiCloud account and a registe",
            "red device to log into other devices registered to other accounts,",
            " if FortiCloud SSO authentication is enabled on those de"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-25089",
        vendor: "Fortinet",
        product: "FortiSandbox",
        cpe23: "cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiSandbox, FortiSandbox Cloud, and FortiSandbox PaaS c",
            "ontain an OS command injection vulnerability that allows an unauth",
            "enticated attacker to execute unauthorized commands via specifical",
            "ly crafted HTTP requests."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-25108",
        vendor: "Soliton Systems K.K",
        product: "FileZen",
        cpe23: "cpe:2.3:a:soliton_systems_k.k:filezen:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Soliton Systems K.K FileZen contains an OS command injection vulne",
            "rability when an user logs-in to the affected product and sends a ",
            "specially crafted HTTP request."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-28318",
        vendor: "SolarWinds",
        product: "Serv-U",
        cpe23: "cpe:2.3:a:solarwinds:serv-u:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Serv-U contains an uncontrolled resource consumption vu",
            "lnerability that allows specially crafted POST requests using the ",
            "Content-Encoding: deflate header to crash the Serv-U service witho",
            "ut authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-3055",
        vendor: "Citrix",
        product: "NetScaler",
        cpe23: "cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC (formerly Citrix ADC), NetScaler Gateway (for",
            "merly Citrix Gateway) and NetScaler ADC FIPS and NDcPP contain an ",
            "out-of-bounds reads vulnerability when configured as a SAML IDP le",
            "ading to memory overread."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-31431",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an incorrect resource transfer between spher",
            "es vulnerability that could allow for privilege escalation."
        ),
        remediation: concat!(
            "\"Apply mitigations per vendor instructions, follow applicable BOD",
            " 22-01 guidance for cloud services, or discontinue use of the prod",
            "uct if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-32201",
        vendor: "Microsoft",
        product: "SharePoint Server",
        cpe23: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint Server contains an improper input validation ",
            "vulnerability that allows an unauthorized attacker to perform spoo",
            "fing over a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-32202",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Shell contains a protection mechanism failure vu",
            "lnerability that allows an unauthorized attacker to perform spoofi",
            "ng over a network."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-33017",
        vendor: "Langflow",
        product: "Langflow",
        cpe23: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Langflow contains a code injection vulnerability that could allow ",
            "building public flows without requiring authentication."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-33634",
        vendor: "Aquasecurity",
        product: "Trivy",
        cpe23: "cpe:2.3:a:aquasecurity:trivy:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Aquasecurity Trivy contains an embedded malicious code vulnerabili",
            "ty that could allow an attacker to gain access to everything in th",
            "e CI/CD environment, including all tokens, SSH keys, cloud credent",
            "ials, database passwords, and any sensitive configuration in memor",
            "y."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-33824",
        vendor: "Microsoft",
        product: "Internet Key Exchange (IKE) Service Extensions",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:internet_key_exchange_ike_service_extensions:*",
            ":*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Key Exchange (IKE) Service Extensions contains ",
            "a double free vulnerability that could enable remote code executio",
            "n."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-33825",
        vendor: "Microsoft",
        product: "Defender",
        cpe23: "cpe:2.3:a:microsoft:defender:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Defender contains an insufficient granularity of access ",
            "control vulnerability that could allow an authorized attacker to e",
            "scalate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34197",
        vendor: "Apache",
        product: "ActiveMQ",
        cpe23: "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache ActiveMQ contains an improper input validation vulnerabilit",
            "y that allows for code injection."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34486",
        vendor: "Apache",
        product: "Tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Tomcat contains a missing encryption of sensitive data vuln",
            "erability that allows the bypass of the EncryptInterceptor. This v",
            "ulnerability can be chained with CVE‑2025‑24813."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34621",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contain a prototype pollution vulnerabili",
            "ty that allows for arbitrary code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34908",
        vendor: "Ubiquiti",
        product: "UniFi OS",
        cpe23: "cpe:2.3:a:ubiquiti:unifi_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ubiquiti UniFi OS contains an improper access control vulnerabilit",
            "y which could allow a malicious actor with access to the network t",
            "o make unauthorized changes to the system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34909",
        vendor: "Ubiquiti",
        product: "UniFi OS",
        cpe23: "cpe:2.3:a:ubiquiti:unifi_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ubiquiti UniFi OS contains a path traversal vulnerability which co",
            "uld allow a malicious actor with access to the network to access f",
            "iles on the underlying system that could be manipulated to access ",
            "an underlying account."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34910",
        vendor: "Ubiquiti",
        product: "UniFi OS",
        cpe23: "cpe:2.3:a:ubiquiti:unifi_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ubiquiti UniFi OS contains an improper input validation vulnerabil",
            "ity which could allow a malicious actor with access to the network",
            " to conduct command injection."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-34926",
        vendor: "Trend Micro",
        product: "Apex One",
        cpe23: "cpe:2.3:a:trend_micro:apex_one:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One (on-premise) contains a directory traversal v",
            "ulnerability that could allow a pre-authenticated local attacker t",
            "o modify a key table on the server to inject malicious code to dep",
            "loy to agents on affected installations."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-3502",
        vendor: "TrueConf",
        product: "Client",
        cpe23: "cpe:2.3:a:trueconf:client:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TrueConf Client contains a download of code without integrity chec",
            "k vulnerability. An attacker who is able to influence the update d",
            "elivery path can substitute a tampered update payload. If the payl",
            "oad is executed or installed by the updater, this may result in ar",
            "bitrary code execution in the context of the updating pr"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-35273",
        vendor: "Oracle",
        product: "PeopleSoft Enterprise PeopleTools",
        cpe23: "cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Oracle PeopleSoft Enterprise PeopleTools contains a missing authen",
            "tication for critical function vulnerability which could allow an ",
            "unauthenticated attacker to obtain takeover of PeopleSoft Enterpri",
            "se PeopleTools."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-35616",
        vendor: "Fortinet",
        product: "FortiClient EMS",
        cpe23: "cpe:2.3:a:fortinet:forticlient_ems:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiClient EMS contains an improper access control vulne",
            "rability that may allow an unauthenticated attacker to execute una",
            "uthorized code or commands via crafted requests."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-3909",
        vendor: "Google",
        product: "Skia",
        cpe23: "cpe:2.3:a:google:skia:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Skia contains an out-of-bounds write vulnerability that cou",
            "ld allow a remote attacker to perform out of bounds memory access ",
            "via a crafted HTML page. This vulnerability affects Google Chrome ",
            "and ChromeOS, Android, Flutter, and possibly other products."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-3910",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains an improper restriction of operations ",
            "within the bounds of a memory buffer vulnerability that could allo",
            "w a remote attacker to execute arbitrary code inside a sandbox via",
            " a crafted HTML page. This vulnerability could affect multiple web",
            " browsers that utilize Chromium, including, but not limi"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-39808",
        vendor: "Fortinet",
        product: "FortiSandbox",
        cpe23: "cpe:2.3:a:fortinet:fortisandbox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Fortinet FortiSandbox contains an OS command injection vulnerabili",
            "ty that could allow an unauthenticated attacker to execute unautho",
            "rized code or commands via crafted HTTP requests."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-39987",
        vendor: "Marimo",
        product: "Marimo",
        cpe23: "cpe:2.3:a:marimo:marimo:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Marimo contains an pre-authorization remote code execution vulnera",
            "bility, allowing an unauthenticated attacked to shell access and e",
            "xecute arbitrary system commands."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-40217",
        vendor: "BerriAI",
        product: "LiteLLM",
        cpe23: "cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BerriAI LiteLLM contains an unprotected alternate channel vulnerab",
            "ility that could allow remote attackers to execute arbitrary code ",
            "via bytecode rewriting at the /guardrails/test_custom_code URI."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-41091",
        vendor: "Microsoft",
        product: "Defender",
        cpe23: "cpe:2.3:a:microsoft:defender:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Defender contains a link following vulnerability that al",
            "lows an authorized attacker to elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-41709",
        vendor: "Broadcom",
        product: "VMware ESX",
        cpe23: "cpe:2.3:a:broadcom:vmware_esx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Broadcom VMWare ESX contains an insufficient logging vulnerability",
            " that could allow a malicious actor with admin access to perform c",
            "ertain operations without being logged."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-41940",
        vendor: "WebPros",
        product: "cPanel & WHM and WP2 (WordPress Squared)",
        cpe23: concat!(
            "cpe:2.3:a:webpros:cpanel_whm_and_wp2_wordpress_squared:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "WebPros cPanel & WHM (WebHost Manager) and WP2 (WordPress Squared)",
            " contain an authentication bypass vulnerability in the login flow ",
            "that allows unauthenticated remote attackers to gain unauthorized ",
            "access to the control panel."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-42016",
        vendor: "JFrog",
        product: "Artifactory",
        cpe23: "cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JFrog Artifactory contains an incorrect authorization vulnerabilit",
            "y that leads to a privilege escalation attack due to a validation ",
            "check of the token signature/issuer and not the token’s scope."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-42018",
        vendor: "JFrog",
        product: "Artifactory",
        cpe23: "cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JFrog Artifactory contains an improper authentication vulnerabilit",
            "y that could return an internal anonymous-user token to an unauthe",
            "nticated caller when anonymous access is disabled, potentially exp",
            "osing sensitive resources."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-42208",
        vendor: "BerriAI",
        product: "LiteLLM",
        cpe23: "cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BerriAI LiteLLM contains a SQL injection vulnerability that allows",
            " an attacker to read data from the proxy's database and potentiall",
            "y modify it, leading to unauthorized access to the proxy and the c",
            "redentials it manages."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-42271",
        vendor: "BerriAI",
        product: "LiteLLM",
        cpe23: "cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BerriAI LiteLLM contains a command injection vulnerability that co",
            "uld allow any authenticated user, including holders of low-privile",
            "ge internal-user keys, to run arbitrary commands on the host."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-42897",
        vendor: "Microsoft",
        product: "Microsoft",
        cpe23: "cpe:2.3:a:microsoft:microsoft:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Exchange Server contains a cross-site scripting vulnerab",
            "ility during web page generation in Outlook Web Access and when ce",
            "rtain interaction conditions are met, arbitrary JavaScript can be ",
            "executed in the browser context."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-45247",
        vendor: "Mirasvit",
        product: "Mirasvit Full Page Cache Warmer",
        cpe23: "cpe:2.3:a:mirasvit:mirasvit_full_page_cache_warmer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mirasvit Full Page Cache Warmer contains a deserialization of untr",
            "usted data vulnerability that could allow unauthenticated attacker",
            "s to achieve remote code execution by supplying a crafted serializ",
            "ed PHP object in the CacheWarmer cookie."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-45321",
        vendor: "TanStack",
        product: "TanStack",
        cpe23: "cpe:2.3:a:tanstack:tanstack:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "TanStack contains an unspecified vulnerability that allowed malici",
            "ous versions of the product to be published to the npm registry to",
            " publish credential-stealing malware under a trusted identity."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-45498",
        vendor: "Microsoft",
        product: "Defender",
        cpe23: "cpe:2.3:a:microsoft:defender:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Defender contains an unspecified vulnerability that allo",
            "ws for denial of service."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-45659",
        vendor: "Microsoft",
        product: "SharePoint Server",
        cpe23: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint Server contains a deserialization of untruste",
            "d data vulnerability which allows an authorized attacker to execut",
            "e code over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-46300",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains a missing initialization of a variable vulne",
            "rability that could allow for unintended modification of page-cach",
            "e-backed data via failure to preserve the shared-fragment marker d",
            "uring socket buffer coalescing, causing ESP input processing to de",
            "crypt shared fragments in place. This vulnerability can "
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-46817",
        vendor: "Oracle",
        product: "E-Business Suite",
        cpe23: "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle E-Business Suite contains an improper privilege management ",
            "vulnerability that allows an unauthenticated attacker with network",
            " access via HTTP to compromise Oracle Payments. Successful attacks",
            " of this vulnerability can result in takeover of Oracle Payments."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48027",
        vendor: "Nx",
        product: "Nx Console",
        cpe23: "cpe:2.3:a:nx:nx_console:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Nx Console contains an embedded malicious code vulnerability that ",
            "allowed a malicious version of Nx Console to be published. The com",
            "promised extension fetched an obfuscated payload that could harves",
            "ted credentials from multiple sources on disk and in memory."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48172",
        vendor: "LiteSpeed",
        product: "cPanel Plugin",
        cpe23: "cpe:2.3:a:litespeed:cpanel_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "LiteSpeed cPanel Plugin contains privilege escalation vulnerabilit",
            "y that is exposed via the user-end cPanel plugin, which can be abu",
            "sed by any cPanel user account to execute arbitrary scripts with r",
            "oot privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48282",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains a path traversal vulnerability that coul",
            "d lead to arbitrary code execution in the context of the current u",
            "ser."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48356",
        vendor: "Adobe",
        product: "Commerce and Magento",
        cpe23: "cpe:2.3:a:adobe:commerce_and_magento:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Commerce and Magento contain an unrestricted upload of file ",
            "with dangerous type vulnerability that could result in arbitrary c",
            "ode execution in the context of the current user, potentially gain",
            "ing elevated access or control over the victim's account or sessio",
            "n."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48558",
        vendor: "SimpleHelp",
        product: "SimpleHelp",
        cpe23: "cpe:2.3:a:simplehelp:simplehelp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SimpleHelp contains an authentication bypass vulnerability in the ",
            "OIDC authentication flow. When OIDC authentication is configured, ",
            "identity tokens submitted during login are accepted without verify",
            "ing their cryptographic signature. In a vulnerable configuration, ",
            "a remote, unauthenticated attacker can submit a forged t"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48710",
        vendor: "Kludex",
        product: "Starlette",
        cpe23: "cpe:2.3:a:kludex:starlette:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kludex Starlette contains a HTTP request/response smuggling vulner",
            "ability that could allow attackers to inject paths into the host p",
            "art, prepending the actual path leading to issues such as authenti",
            "cation bypass when the authentication depends on the reconstructed",
            " URL’s path. This vulnerability could be chaned with CVE"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48907",
        vendor: "Widget Factory",
        product: "Joomla Content Editor",
        cpe23: "cpe:2.3:a:widget_factory:joomla_content_editor:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Widget Factory Joomla Content Editor contains an improper access c",
            "ontrol vulnerability which could allow for upload and execution of",
            " PHP code via the creation of new editor profiles for unauthentica",
            "ted users."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48908",
        vendor: "JoomShaper",
        product: "SP Page Builder",
        cpe23: "cpe:2.3:a:joomshaper:sp_page_builder:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JoomShaper SP Page Builder contains an unrestricted upload of file",
            " with dangerous type vulnerability that allows unauthenticated use",
            "rs to upload arbitrary files, ultimately resulting in the upload a",
            "nd execution of PHP code."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-48939",
        vendor: "iCagenda",
        product: "iCagenda",
        cpe23: "cpe:2.3:a:icagenda:icagenda:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "iCagenda contains an unrestricted upload of file with dangerous ty",
            "pe vulnerability that allows the upload of arbitrary files in the ",
            "file attachment feature, ultimately resulting in PHP code upload a",
            "nd execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-49869",
        vendor: "Kestra",
        product: "Kestra OSS",
        cpe23: "cpe:2.3:a:kestra:kestra_oss:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kestra OSS contains an OS command injection vulnerability that cou",
            "ld allow an unauthenticated remote attacker to create and execute ",
            "arbitrary workflows without credentials."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-50522",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint contains a deserialization of untrusted data ",
            "vulnerability which could allow an unauthorized attacker to execut",
            "e code over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-50751",
        vendor: "Check Point",
        product: "Security Gateway",
        cpe23: "cpe:2.3:a:check_point:security_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Check Point Security Gateway contains an improper authentication v",
            "ulnerability in IKEv1 key exchange that could allow an unauthentic",
            "ated remote attacker to bypass user authentication and establish a",
            " remote access VPN connection without a valid user password."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-5281",
        vendor: "Google",
        product: "Dawn",
        cpe23: "cpe:2.3:a:google:dawn:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Dawn contains an use-after-free vulnerability that could al",
            "low a remote attacker who had compromised the renderer process to ",
            "execute arbitrary code via a crafted HTML page. This vulnerability",
            " could affect multiple Chromium-based products including, but not ",
            "limited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-53266",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an out-of-bounds write vulnerability in the ",
            "ebtables SNAT target which allows an ARP sender hardware address r",
            "ewrite to write directly into a nonlinear socket-buffer fragment b",
            "acked by a splice-imported file page. The impacted product(s) coul",
            "d be end-of-life (EoL) and/or end-of-service (EoS). User"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-53362",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an unspecified vulnerability that can allow ",
            "for privilege escalation via IPv6 networking subsystem. This vulne",
            "rability can impact multiple products, including but not limited t",
            "o Suse, Red Hat, and other products using Linux."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-5430",
        vendor: "WSO2",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:wso2:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WSO2 API Control Plane, API Manager, Traffic Manager & Universal G",
            "ateway contain a path traversal vulnerability that could allow for",
            " unrestricted file upload and lead to remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-54420",
        vendor: "LiteSpeed",
        product: "cPanel Plugin",
        cpe23: "cpe:2.3:a:litespeed:cpanel_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "LiteSpeed cPanel plugin contains a UNIX symbolic link (Symlink) fo",
            "llowing vulnerability that could allow a user with FTP or web shel",
            "l access on a shared hosting server running CloudLinux/CageFS."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-55040",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint contains a weak authentication vulnerability ",
            "which allows an unauthorized attacker to bypass a security feature",
            " over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-55255",
        vendor: "Langflow",
        product: "Langflow",
        cpe23: "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Langflow contains an authorization bypass through user-controlled ",
            "key vulnerability which allows an authenticated attacker to execut",
            "e any flow belonging to another user by specifying the victim's fl",
            "ow ID in the request."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-56155",
        vendor: "Microsoft",
        product: "Active Directory Federation Services",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:active_directory_federation_services:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Active Directory Federation Services contains an insuffi",
            "cient granularity of access control vulnerability that allows an a",
            "uthorized attacker to elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-56164",
        vendor: "Microsoft",
        product: "SharePoint Server",
        cpe23: "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint contains a missing authentication for critica",
            "l function vulnerability that allows an unauthorized attacker to e",
            "levate privileges over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-56290",
        vendor: "Joomlack",
        product: "Page Builder",
        cpe23: "cpe:2.3:a:joomlack:page_builder:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Joomlack Page Builder contains an improper access control vulnerab",
            "ility that could allow for remote code execution via unauthenticat",
            "ed arbitrary file upload."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-56291",
        vendor: "Balbooa",
        product: "Forms",
        cpe23: "cpe:2.3:a:balbooa:forms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Balbooa Forms contains an unrestricted upload of file with dangero",
            "us type vulnerability that allows an unauthenticated arbitrary fil",
            "e upload which could allow uploading of executable files leading t",
            "o full RCE."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-58644",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint contains a deserialization of untrusted data ",
            "vulnerability that allows an unauthorized attacker to execute code",
            " over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-58704",
        vendor: "Google",
        product: "Pixel",
        cpe23: "cpe:2.3:a:google:pixel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Pixel devices contain an improper authorization vulnerabili",
            "ty in the cellular modem. A logic error may allow an attacker to b",
            "ypass permission checks and escalate privileges."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-59310",
        vendor: "Broadcom",
        product: "VMware vCenter",
        cpe23: "cpe:2.3:a:broadcom:vmware_vcenter:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Broadcom VMware vCenter contains a path traversal vulnerability wh",
            "ich could allow a threat actor with network access to vCenter to e",
            "xecute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-59822",
        vendor: "BerriAI",
        product: "LiteLLM",
        cpe23: "cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "BerriAI LiteLLM contains an improper authentication vulnerability ",
            "in the MCP Streamable HTTP endpoint that could allow an unauthenti",
            "cated attacker to establish an authenticated MCP session using an ",
            "arbitrary Bearer token."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-60004",
        vendor: "Gitea",
        product: "Gitea",
        cpe23: "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Gitea contains a code injection vulnerability that allows an attac",
            "ker with repository write access to send a malicious patch to the ",
            "diffpatch API endpoint to plant an executable Git hook and run she",
            "ll commands as the Gitea service account."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-60137",
        vendor: "WordPress",
        product: "Core",
        cpe23: "cpe:2.3:a:wordpress:core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress Core contains a SQL injection vulnerability when a plugi",
            "n or theme passes untrusted input to the parameter. This vulnerabi",
            "lity can be chained with CVE-2026-63030 to allow an unauthenticate",
            "d attacker to gain remote code execution on default WordPress inst",
            "allations."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-63030",
        vendor: "WordPress",
        product: "Core",
        cpe23: "cpe:2.3:a:wordpress:core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress Core contains an interpretation conflict vulnerability t",
            "hat could allow an attacker to perform SQL Injection and achieve R",
            "emote Code Execution. This vulnerability can be chained with CVE-2",
            "026-60137."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-63077",
        vendor: "JetBrains",
        product: "TeamCity",
        cpe23: "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "JetBrains TeamCity contains a deserialization of untrusted data vu",
            "lnerability that could allow unauthenticated remote code execution",
            " via the agent polling protocol."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-64849",
        vendor: "MLflow",
        product: "MLflow",
        cpe23: "cpe:2.3:a:mlflow:mlflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MLflow contains a server-side request forgery vulnerability that c",
            "an allow attackers to reach internal or cloud metadata services an",
            "d receive response_status and response_body."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-65400",
        vendor: "Apple",
        product: "macOS",
        cpe23: "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple macOS contains an improper authentication vulnerability that",
            " could allow an attacker on the network to authenticate to Screen ",
            "Sharing without valid credentials."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-65660",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SharePoint contains a code injection vulnerability which",
            " could allow an authorized attacker to execute code over a network",
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
        cve_id: "CVE-2026-66384",
        vendor: "JFrog",
        product: "Artifactory",
        cpe23: "cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JFrog Artifactory contains an improper limitation of a pathname to",
            " a restricted directory vulnerability. This can allow an authentic",
            "ated user to write data outside the intended Docker cache path und",
            "er specific remote-repository conditions."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-67277",
        vendor: "MikroTik",
        product: "RouterOS",
        cpe23: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MikroTik RouterOS contains a missing authentication for critical f",
            "unction vulnerability which allows kernel memory disclosure and de",
            "nial of service in the btest service."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-67279",
        vendor: "MikroTik",
        product: "RouterOS",
        cpe23: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mikrotik RouterOS contains an improper enforcement of behavioral w",
            "orkflow vulnerability that could allow an unauthenticated client t",
            "o open a session channel and send an exec request. This vulnerabil",
            "ity can be chained to achieve unauthenticated exploitation of CVE-",
            "2026-86060."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-68820",
        vendor: "Microsoft",
        product: "Windows Ancillary Function Driver for WinSock",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:windows_ancillary_function_driver_for_winsock:",
            "*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Ancillary Function Driver for WinSock contains a",
            " use-after-free vulnerability that allows an authorized attacker t",
            "o elevate privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-6973",
        vendor: "Ivanti",
        product: "Endpoint Manager Mobile (EPMM)",
        cpe23: "cpe:2.3:a:ivanti:endpoint_manager_mobile_epmm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti Endpoint Manager Mobile (EPMM) contains an improper input v",
            "alidation vulnerability that allows a remotely authenticated user ",
            "with administrative access to achieve remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-71362",
        vendor: "Adobe",
        product: "Commerce and Magento",
        cpe23: "cpe:2.3:a:adobe:commerce_and_magento:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Commerce and Magento contains an incorrect authorization vul",
            "nerability that could allow an attacker to leverage this vulnerabi",
            "lity to gain elevated access to sensitive resources without any us",
            "er interaction."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-72529",
        vendor: "TrueConf",
        product: "Server",
        cpe23: "cpe:2.3:a:trueconf:server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TrueConf Server contains a missing authentication for critical fun",
            "ction vulnerability which could allow a remote unauthorized attack",
            "er with network access via port 4307/TCP to execute an arbitrary s",
            "cript."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-72530",
        vendor: "TrueConf",
        product: "Server",
        cpe23: "cpe:2.3:a:trueconf:server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TrueConf Server contains a code injection vulnerability that could",
            " allow an unauthorized remote attacker with network access via por",
            "t 4307/TCP to use a specially crafted script to break out of the i",
            "solated environment and execute arbitrary code on the host system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-7273",
        vendor: "Zyxel",
        product: "GS1900 Series Switches",
        cpe23: "cpe:2.3:a:zyxel:gs1900_series_switches:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zyxel GS1900 series switches contain a stack-based buffer overflow",
            " vulnerability in the CGI program which could allow a LAN-based, u",
            "nauthenticated attacker to exploit the flaw and potentially execut",
            "e OS commands via a crafted HTTP request."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-72898",
        vendor: "Metabase",
        product: "Metabase",
        cpe23: "cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Metabase contains a SQL Injection vulnerability that allows an una",
            "uthenticated remote attacker to inject arbitrary SQL into the Meta",
            "base application database, which can give them administrator acces",
            "s to the instance. From there, the attacker could change the appli",
            "cation configuration, steal stored credentials for the c"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-73570",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zimbra Collaboration Suite (ZCS) contains an OS command injection ",
            "vulnerability which could allow an unauthenticated attacker to sen",
            "d specially crafted SMTP requests that may result in execution of ",
            "arbitrary operating system commands as the Zimbra user."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-7473",
        vendor: "Arista",
        product: "Extensible Operating System",
        cpe23: "cpe:2.3:a:arista:extensible_operating_system:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arista Extensible Operating System (EOS) contains an incomplete co",
            "mparison with missing factors vulnerability when the switch incorr",
            "ectly decapsulate and forwards other unexpected tunneled packet wi",
            "th a destination IP matching its configured decapsulation IP."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-75650",
        vendor: "Adobe",
        product: "Commerce and Magento",
        cpe23: "cpe:2.3:a:adobe:commerce_and_magento:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Commerce and Magento Open Source contain an improper neutral",
            "ization of special elements used in a template engine vulnerabilit",
            "y that could allow an attacker to execute arbitrary code."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-76418",
        vendor: "Cisco",
        product: "Secure Firewall ASA Software and Cisco Secure FTD Software",
        cpe23: concat!(
            "cpe:2.3:a:cisco:secure_firewall_asa_software_and_cisco_secure_ftd_",
            "software:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Firewall ASA Software and Cisco Secure FTD Software c",
            "ontains an unchecked return value to NULL pointer dereference vuln",
            "erability that could allow an unauthenticated, remote attacker to ",
            "cause the device to reload unexpectedly, resulting in a denial of ",
            "service (DoS) condition."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-76460",
        vendor: "Cisco",
        product: "Identity Services Engine",
        cpe23: "cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identit",
            "y Connector (ISE-PIC) contain an incorrect use of privileged APIs ",
            "vulnerability that could allow an unauthenticated, remote attacker",
            " to gain unauthorized access to the affected device by bypassing t",
            "he web-based management interface."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-76461",
        vendor: "Cisco",
        product: "Secure Email Gateway",
        cpe23: "cpe:2.3:a:cisco:secure_email_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco AsyncOS software for Cisco Secure Email Gateway (SEG) contai",
            "ns a SQL injection vulnerability that could allow an unauthenticat",
            "ed, remote attacker to execute arbitrary commands with root privil",
            "eges on the underlying operating system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-76504",
        vendor: "Cisco",
        product: "Catalyst SD-WAN Manager",
        cpe23: "cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Catalyst SD-WAN Manager contains a hex encoding vulnerabilit",
            "y that could allow an unauthenticated, remote attacker to access a",
            "n affected system with privileges of the admin user due to imprope",
            "r handling of URI encoding in an HTTP request."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-76519",
        vendor: "Cisco",
        product: "Secure Email Gateway",
        cpe23: "cpe:2.3:a:cisco:secure_email_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Secure Email Gateway contains a relative path traversal vuln",
            "erability that could allow an unauthenticated, remote attacker to ",
            "write arbitrary files on the underlying operating system."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-8037",
        vendor: "Progress",
        product: "LoadMaster",
        cpe23: "cpe:2.3:a:progress:loadmaster:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Progress LoadMaster contains a command injection vulnerability tha",
            "t allows an un-authenticated attacker to execute arbitrary command",
            "s on the LoadMaster appliance by exploiting unsanitized input in m",
            "ultiple command endpoints."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-81578",
        vendor: "PaperCut",
        product: "NG/MF",
        cpe23: "cpe:2.3:a:papercut:ng_mf:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PaperCut NG/MF contains a missing authentication for critical func",
            "tion vulnerability which allows an unauthenticated remote attacker",
            " to modify certain system configurations. This vulnerability can b",
            "e chained with CVE-2026-82078."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-81963",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Update Stack contains a link following vulnerabi",
            "lity that allows a local attacker to escalate privileges locally u",
            "p to SYSTEM."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-82078",
        vendor: "PaperCut",
        product: "NG/MF",
        cpe23: "cpe:2.3:a:papercut:ng_mf:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PaperCut NG/MF contains an unsafe reflection vulnerability that al",
            "lows an attacker to manipulate system configuration parameters and",
            " execute arbitrary Java bytecode residing on the application class",
            "path under the security context of the PaperCut server process. Th",
            "is vulnerability can be chained with CVE-2026-81578."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-82329",
        vendor: "JFrog",
        product: "Artifactory",
        cpe23: "cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JFrog Artifactory contains an improper authentication vulnerabilit",
            "y that under default configuration can allow an unauthenticated at",
            "tacker with network access to obtain administrative privileges."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-83548",
        vendor: "SonicWall",
        product: "SMA1000 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma1000_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SonicWall SMA1000 Appliances contains a server-side request forger",
            "y vulnerability that could allow a remote unauthenticated attacker",
            " to gain unauthorized access to sensitive functionality and perfor",
            "m unauthorized operations."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-83549",
        vendor: "SonicWall",
        product: "SMA1000 Appliances",
        cpe23: "cpe:2.3:a:sonicwall:sma1000_appliances:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SonicWall SMA1000 Appliances contains an OS command injection vuln",
            "erability that could enable a remote authenticated attacker as adm",
            "inistrator to execute arbitrary OS commands, resulting in remote c",
            "ode execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-8398",
        vendor: "Daemon",
        product: "Daemon Tools Lite",
        cpe23: "cpe:2.3:a:daemon:daemon_tools_lite:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Daemon Tools contains an unspecified vulnerability that has a high",
            " impact on confidentiality, integrity, and availability."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-8452",
        vendor: "Citrix",
        product: "NetScaler ADC and NetScaler Gateway",
        cpe23: concat!(
            "cpe:2.3:a:citrix:netscaler_adc_and_netscaler_gateway:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain an improper res",
            "triction of operations within the bounds of a memory buffer vulner",
            "ability which could lead to denial of service."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-84869",
        vendor: "ConnectWise",
        product: "ScreenConnect",
        cpe23: "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ConnectWise ScreenConnect contains both an improper privilege mana",
            "gement and missing authorization vulnerability that may allow an a",
            "ttacker to transfer and execute files through an active remote ses",
            "sion without authorization or host confirmation."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-85046",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains a type confusion vulnerability that al",
            "lows a remote attacker to execute arbitrary code inside the sandbo",
            "x via a crafted HTML page. This vulnerability could affect multipl",
            "e web browsers that utilize Chromium, including, but not limited t",
            "o, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-85102",
        vendor: "Check Point",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:check_point:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Check Point Security Gateway and Check Point Spark Firewall using ",
            "Site to Site VPN or Remote Access VPN contain an improper certific",
            "ate validation vulnerability which could allow an unauthenticated ",
            "remote attacker to execute arbitrary code on the Gateway."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-85706",
        vendor: "GitLab",
        product: "Community Edition and Enterprise Edition",
        cpe23: concat!(
            "cpe:2.3:a:gitlab:community_edition_and_enterprise_edition:*:*:*:*:",
            "*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GitLab Community Edition and Enterprise Edition contains a path tr",
            "aversal vulnerability that allows an unauthenticated user to read ",
            "arbitrary files due to an improper path confinement and missing au",
            "thentication enforcement in the repository commits API."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-85880",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Advanced Local Procedure Call contains a heap-ba",
            "sed buffer overflow vulnerability that allows an attacker to eleva",
            "te privileges locally."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-86060",
        vendor: "MikroTik",
        product: "RouterOS",
        cpe23: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MikroTik RouterOS contains an improper neutralization of argument ",
            "delimiters in a command vulnerability which allows an attacker to ",
            "change the trusted RouterOS policy mask, leading to privilege esca",
            "lation."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-86218",
        vendor: "N-able",
        product: "N-central",
        cpe23: "cpe:2.3:a:n-able:n-central:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "N-able N-central contains a static code injection vulnerability th",
            "at could allow for pre-authentication remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-86950",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, and iPadOS contain an out-of-bounds write vulner",
            "ability in CoreGraphics that may lead to arbitrary code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-87491",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 contains an out of bounds write vulnerability t",
            "hat allows a remote attacker to execute arbitrary code inside the ",
            "sandbox via a crafted HTML page. This vulnerability could affect m",
            "ultiple web browsers that utilize Chromium, including, but not lim",
            "ited to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-87886",
        vendor: "Acronis",
        product: "Backup",
        cpe23: "cpe:2.3:a:acronis:backup:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Acronis Backup plugin for cPanel & WHM and extension for Plesk con",
            "tains an incorrect default permissions vulnerability that could al",
            "low for privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-87902",
        vendor: "WordPress",
        product: "Core",
        cpe23: "cpe:2.3:a:wordpress:core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress Core contains a remote file inclusion vulnerability whic",
            "h could allow an unauthenticated attacker to make page-template re",
            "solution include a chosen readable local `.php` file outside the a",
            "ctive theme directories, leading to remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-88771",
        vendor: "Citrix",
        product: "NetScaler",
        cpe23: "cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain an improper inp",
            "ut validation vulnerability that could allow an unauthenticated at",
            "tacker to execute arbitrary commands."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-88772",
        vendor: "Citrix",
        product: "NetScaler",
        cpe23: "cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC and NetScaler Gateway contain an improper res",
            "triction of operations within the bounds of a memory buffer vulner",
            "ability that could allow for remote code execution or denial of se",
            "rvice"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-88779",
        vendor: "Citrix",
        product: "NetScaler",
        cpe23: "cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Citrix NetScaler ADC (formerly Citrix ADC) and Citrix NetScaler Ga",
            "teway (formerly Citrix Gateway) contain an improper restriction of",
            " operations within the bounds of a memory buffer vulnerability tha",
            "t could allow for a denial of service."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-90436",
        vendor: "Apache",
        product: "Axis",
        cpe23: "cpe:2.3:a:apache:axis:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Axis contains an unsafe reflection vulnerability that could",
            " allow an unauthenticated remote attacker to execute arbitrary cod",
            "e via a crafted SOAP fault message that causes Axis to load and in",
            "stantiate an attacker-specified class when a suitable class is ava",
            "ilable on the application classpath. The impacted produc"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-90817",
        vendor: "Vanderbilt University",
        product: "Research Electronic Data Capture (REDCap)",
        cpe23: concat!(
            "cpe:2.3:a:vanderbilt_university:research_electronic_data_capture_r",
            "edcap:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Vanderbilt University Research Electronic Data Capture (REDCap) co",
            "ntains a code injection vulnerability which could allow an unauthe",
            "nticated attacker to execute arbitrary code on the server. An atta",
            "cker could exploit this via crafted HTTP requests that access an u",
            "nintended controller route from a public survey context "
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-9082",
        vendor: "Drupal",
        product: "Core",
        cpe23: "cpe:2.3:a:drupal:core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Drupal Core contains a SQL injection vulnerability that could allo",
            "w for privilege escalation and remote code execution via specially",
            " crafted requests sent with the database abstraction API."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-9198",
        vendor: "IBM",
        product: "Langflow",
        cpe23: "cpe:2.3:a:ibm:langflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Langflow contains a code injection vulnerability that allows unaut",
            "henticated attackers to achieve full remote code execution on defa",
            "ult Langflow deployments."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-93616",
        vendor: "Check Point",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:check_point:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Check Point Security Management Server, Multi-Domain Security Mana",
            "gement Server, Log Server, Multi-Domain Log Server, and SmartEvent",
            " contain a path traversal vulnerability that allows an unauthentic",
            "ated attacker to upload and execute arbitrary scripts."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-93952",
        vendor: "Arista",
        product: "VeloCloud Orchestrator",
        cpe23: "cpe:2.3:a:arista:velocloud_orchestrator:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Arista VeloCloud Orchestrator (VCO) on-prem contains an improper i",
            "nput validation vulnerability that may allow a remote attacker to ",
            "access privileged internal functionality and impact the VCO host. ",
            "Successful exploitation may compromise the confidentiality, integr",
            "ity, and availability of the orchestrator and data manag"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-94127",
        vendor: "F5",
        product: "BIG-IP APM",
        cpe23: "cpe:2.3:a:f5:big-ip_apm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "F5 BIG-IP APM contains a heap-based buffer overflow vulnerability ",
            "when access policy and an OAuth profile are configured on a virtua",
            "l server. This vulnerability could allow an unauthenticated attack",
            "er to perform remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-9586",
        vendor: "Sangoma",
        product: "Switchvox",
        cpe23: "cpe:2.3:a:sangoma:switchvox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sangoma Switchvox contains a SQL injection vulnerability which all",
            "ows an unauthenticated remote attacker to execute arbitrary SQL st",
            "atements against the backend PostgreSQL database using a single cr",
            "afted request, including database operations and remote code execu",
            "tion."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-96652",
        vendor: "Plex",
        product: "Media Server",
        cpe23: "cpe:2.3:a:plex:media_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Plex Media Server contains a server-side request forgery (SSRF) vu",
            "lnerability which could allow an attacker using any X-Plex-Token v",
            "alue to include a full URL in the 'protocol' parameter and force t",
            "he Plex server to POST to the attacker's chosen destination. This ",
            "vulnerability can be chained with CVE-2026-96654, CVE-20"
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-96654",
        vendor: "Plex",
        product: "Media Server",
        cpe23: "cpe:2.3:a:plex:media_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Plex Media Server contains an improper neutralization of encoded U",
            "RI schemes in a web page vulnerability that could allow an attacke",
            "r to call other plugins' functions and supply their own parameters",
            ". This vulnerability can be chained with CVE-2026-96652, CVE-2026-",
            "96655, and CVE-2026-96656."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-96655",
        vendor: "Plex",
        product: "Media Server",
        cpe23: "cpe:2.3:a:plex:media_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Plex Media Server contains a server-side request forgery (SSRF) vu",
            "lnerability that could allow an authenticated user to request arbi",
            "trary internal or external addresses via the '/video/:/transcode/u",
            "niversal' path parameter. This vulnerability can be chained with C",
            "VE-2026-96652, CVE-2026-96654, and CVE-2026-96656."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-96656",
        vendor: "Plex",
        product: "Media Server",
        cpe23: "cpe:2.3:a:plex:media_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Plex Media Server contains an external control of file name or pat",
            "h vulnerability which can allow an admin user to write arbitrary f",
            "iles that may be executed on load. This vulnerability can be chain",
            "ed with CVE-2026-96652, CVE-2026-96654, and CVE-2026-96655."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-96951",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Shell contains a command injection vulnerability",
            " that allows an unauthorized attacker to bypass a security feature",
            " over a network."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2026-97229",
        vendor: "GitLab",
        product: "Community Edition and Enterprise Edition",
        cpe23: concat!(
            "cpe:2.3:a:gitlab:community_edition_and_enterprise_edition:*:*:*:*:",
            "*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GitLab Community Edition and Enterprise Edition contain a integer ",
            "overflow or wraparound vulnerability that could allow an unauthent",
            "icated user to execute arbitrary code on the GitLab server via a s",
            "pecially crafted regular expression in a CI/CD configuration, due ",
            "to insufficient regular expression validation."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "EOL-APACHE-2.2",
        vendor: "apache",
        product: "apache",
        cpe23: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life Apache HTTP Server 2.2.x Unsupported Branch",
        remediation: concat!(
            "Qo'llab-quvvatlash to'xtatilgan Apache 2.2 tarmog'idan zamonaviy A",
            "pache 2.4 LTS reliziga o'ting."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-DRUPAL-LEGACY",
        vendor: "drupal",
        product: "drupal",
        cpe23: "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life Drupal (6.x–9.x) Unsupported CMS Branch",
        remediation: concat!(
            "Qo'llab-quvvatlash tugagan Drupal versiyasini Drupal 10.2.2+ yoki ",
            "11.x ga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-IIS-LEGACY",
        vendor: "microsoft",
        product: "iis",
        cpe23: "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
        cvss_x10: 65, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Legacy Microsoft-IIS (6.0–8.5) End-of-Support Server Branch",
        remediation: concat!(
            "IIS platformasini qo'llab-quvvatlanadigan IIS 10.0+ versiyasiga mi",
            "gratsiya qiling."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-LARAVEL-LEGACY",
        vendor: "laravel",
        product: "laravel",
        cpe23: "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
        cvss_x10: 59, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life Laravel Framework (< 10.x) Unsupported Release",
        remediation: concat!(
            "Laravel freymvorkini qo'llab-quvvatlanadigan 10.x LTS yoki 11.x ve",
            "rsiyasiga ko'taring."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-MONGODB-LEGACY",
        vendor: "mongodb",
        product: "mongodb",
        cpe23: "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life MongoDB (2.x–4.x) Unsupported Database Branch",
        remediation: concat!(
            "MongoDB serverini qo'llab-quvvatlanadigan 6.0.14+ yoki 7.0.6+ LTS ",
            "versiyasiga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-MYSQL-5.X",
        vendor: "oracle",
        product: "mysql",
        cpe23: "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life MySQL 5.x Unsupported Database Branch",
        remediation: concat!(
            "Qo'llab-quvvatlash to'xtatilgan MySQL 5.x tarmog'ini MySQL 8.0.36+",
            " yoki 8.4 LTS ga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-NODEJS-LEGACY",
        vendor: "nodejs",
        product: "nodejs",
        cpe23: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life Node.js (< 18.0.0) Unsupported Runtime Branch",
        remediation: concat!(
            "Node.js muhitini qo'llab-quvvatlanadigan Node.js 20 LTS yoki 22 LT",
            "S ga yangilang."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-OPENSSL-1.0",
        vendor: "openssl",
        product: "openssl",
        cpe23: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        cvss_x10: 74, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life OpenSSL 1.0.x Cryptographic Library",
        remediation: "OpenSSL kutubxonasini OpenSSL 3.x LTS versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "EOL-OPENSSL-1.1.1",
        vendor: "openssl",
        product: "openssl",
        cpe23: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        cvss_x10: 59, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life OpenSSL 1.1.1 Cryptographic Library Branch",
        remediation: concat!(
            "Qo'llab-quvvatlash muddati tugagan OpenSSL 1.1.1 o'rniga OpenSSL 3",
            ".x LTS ga o'ting."
        ),
    },
    KevCveRecord {
        cve_id: "EOL-PHP-LEGACY",
        vendor: "php",
        product: "php",
        cpe23: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "End-of-Life PHP Runtime (5.x / 7.x / 8.0 Unsupported Branch)",
        remediation: concat!(
            "Xavfsizlik yangilanishlari to'xtatilgan PHP versiyasini PHP 8.2 / ",
            "8.3 LTS reliziga yangilang."
        ),
    },
];

use crate::rust_kev_cve_part1::KEV_CVE_PART1;
use crate::rust_kev_cve_part2::KEV_CVE_PART2;

pub fn total_kev_cve_count() -> u32 {
    (KEV_CVE_PART1.len() + KEV_CVE_PART2.len() + KEV_CVE_PART3.len()) as u32
}

fn json_esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' | '\r' | '\t' => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

fn find_sh(sh: &'static [KevCveRecord], k: &str) -> Option<&'static KevCveRecord> {
    let i = sh.binary_search_by(|e| e.cve_id.cmp(k)).ok()?;
    Some(&sh[i])
}

pub fn lookup_cve_json(cve_id: &str) -> Option<String> {
    let k = cve_id.trim().to_ascii_uppercase();
    let r = find_sh(KEV_CVE_PART1, &k)
        .or_else(|| find_sh(KEV_CVE_PART2, &k))
        .or_else(|| find_sh(KEV_CVE_PART3, &k))?;
    let p1 = format!(
        "{{\"cve_id\":\"{}\",\"vendor\":\"{}\",\"product\":\"{}\",\"cpe23\":\"{}\",",
        json_esc(r.cve_id), json_esc(r.vendor), json_esc(r.product), json_esc(r.cpe23)
    );
    let p2 = format!(
        "\"cvss\":{}.{},\"severity\":\"{}\",\"cwe\":\"{}\",\"is_kev\":{},\"ransomware_use\":\"{}\",",
        r.cvss_x10 / 10, r.cvss_x10 % 10, json_esc(r.severity), json_esc(r.cwe),
        if r.is_kev { "true" } else { "false" }, json_esc(r.ransomware)
    );
    let p3 = format!(
        "\"epss\":{:.3},\"summary\":\"{}\",\"remediation\":\"{}\",\"spdx_license\":\"US-Gov-Public-Domain\"}}",
        (r.epss_permille as f64) / 1000.0, json_esc(r.summary), json_esc(r.remediation)
    );
    Some(p1 + &p2 + &p3)
}
