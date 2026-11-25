// SPECTRE Rust Static .rodata CVE & KEV Shard (KEV_CVE_PART1)

#[derive(Copy, Clone)]
pub struct KevCveRecord {
    pub cve_id: &'static str, pub vendor: &'static str,
    pub product: &'static str, pub cpe23: &'static str,
    pub cvss_x10: u16, pub severity: &'static str, pub cwe: &'static str,
    pub is_kev: bool, pub ransomware: &'static str, pub epss_permille: u16,
    pub summary: &'static str, pub remediation: &'static str,
}

pub static KEV_CVE_PART1: &[KevCveRecord] = &[
    KevCveRecord {
        cve_id: "CVE-2002-0367",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "smss.exe debugging subsystem in Microsoft Windows does not properl",
            "y authenticate programs that connect to other programs, which allo",
            "ws local users to gain administrator or SYSTEM privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2004-0210",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A privilege elevation vulnerability exists in the POSIX subsystem.",
            " This vulnerability could allow a logged on user to take complete ",
            "control of the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2004-1464",
        vendor: "Cisco",
        product: "IOS",
        cpe23: "cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS contains an unspecified vulnerability that may block fur",
            "ther telnet, reverse telnet, Remote Shell (RSH), Secure Shell (SSH",
            "), and in some cases, Hypertext Transport Protocol (HTTP) access t",
            "o the Cisco device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2005-2773",
        vendor: "Hewlett Packard (HP)",
        product: "OpenView Network Node Manager",
        cpe23: concat!(
            "cpe:2.3:a:hewlett_packard_hp:openview_network_node_manager:*:*:*:*",
            ":*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "HP OpenView Network Node Manager could allow a remote attacker to ",
            "execute arbitrary commands on the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2006-1547",
        vendor: "Apache",
        product: "Struts 1",
        cpe23: "cpe:2.3:a:apache:struts_1:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ActionForm in Apache Struts versions before 1.2.9 with BeanUtils 1",
            ".7 contains a vulnerability that allows for denial-of-service (DoS",
            ")."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2006-2492",
        vendor: "Microsoft",
        product: "Word",
        cpe23: "cpe:2.3:a:microsoft:word:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Word and Microsoft Works Suites contain a malformed obje",
            "ct pointer which allows attackers to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2007-0671",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Excel contains a remote code execution vulnerabil",
            "ity that can be exploited when a specially crafted Excel file is o",
            "pened. This malicious file could be delivered as an email attachme",
            "nt or hosted on a malicious website. An attacker could leverage th",
            "is vulnerability by creating a specially crafted Excel f"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2007-3010",
        vendor: "Alcatel",
        product: "OmniPCX Enterprise",
        cpe23: "cpe:2.3:a:alcatel:omnipcx_enterprise:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "masterCGI in the Unified Maintenance Tool in Alcatel OmniPCX Enter",
            "prise Communication Server allows remote attackers to execute arbi",
            "trary commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2007-5659",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contain a buffer overflow vulnerability t",
            "hat allows remote attackers to execute code via a PDF file with lo",
            "ng arguments to unspecified JavaScript methods."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2008-0015",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Video ActiveX Control contains a remote code exe",
            "cution vulnerability. An attacker could exploit the vulnerability ",
            "by constructing a specially crafted Web page. When a user views th",
            "e Web page, the vulnerability could allow remote code execution. A",
            "n attacker who successfully exploited this vulnerability"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2008-0655",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contains an unespecified vulnerability de",
            "scribed as a design flaw which could allow a specially crafted fil",
            "e to be printed silently an arbitrary number of times."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2008-2992",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe Acrobat and Reader contain an input validation issue in a Ja",
            "vaScript method that could potentially lead to remote code executi",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2008-3431",
        vendor: "Oracle",
        product: "VirtualBox",
        cpe23: "cpe:2.3:a:oracle:virtualbox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An input validation vulnerability exists in the VBoxDrv.sys driver",
            " of Sun xVM VirtualBox which allows attackers to locally execute a",
            "rbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2008-4128",
        vendor: "Cisco",
        product: "IOS",
        cpe23: "cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS 12.4 contains multiple cross-site forgery vulnerabilitie",
            "s that allows remote attackers to execute arbitrary commands via (",
            "1) a certain \"show privilege\" command to the /level/15/exec/- UR",
            "I, and (2) a certain \"alias exec\" command to the /level/15/exec/",
            "-/configure/http URI."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2008-4250",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains a buffer overflow vulnerability in the ",
            "Windows Server Service that allows remote attackers to execute arb",
            "itrary code via a crafted RPC request that triggers an overflow du",
            "ring path canonicalization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2009-0238",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Excel contains a remote code execution vulnerabil",
            "ity that could allow an attacker to take complete control of an af",
            "fected system if a user opens a specially crafted Excel file that ",
            "includes a malformed object."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2009-0556",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office PowerPoint contains a code injection vulnerabilit",
            "y that allows remote attackers to execute arbitrary code via a Pow",
            "erPoint file with an OutlineTextRefAtom containing an invalid inde",
            "x value that triggers memory corruption."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2009-0557",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains an object record corruption vulnerabilit",
            "y that allows remote attackers to execute code via a crafted Excel",
            " file with a malformed record object."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-0563",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a buffer overflow vulnerability that all",
            "ows remote attackers to execute code via a Word document with a cr",
            "afted tag containing an invalid length field."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-0927",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Stack-based buffer overflow in Adobe Reader and Adobe Acrobat allo",
            "ws remote attackers to execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-1123",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The kernel in Microsoft Windows does not properly validate changes",
            " to unspecified kernel objects, which allows local users to gain p",
            "rivileges via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-1151",
        vendor: "phpMyAdmin",
        product: "phpMyAdmin",
        cpe23: "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Setup script used to generate configuration can be fooled using a ",
            "crafted POST request to include arbitrary PHP code in generated co",
            "nfiguration file."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-1537",
        vendor: "Microsoft",
        product: "DirectX",
        cpe23: "cpe:2.3:a:microsoft:directx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft DirectX contains a NULL byte overwrite vulnerability in ",
            "the QuickTime Movie Parser Filter in quartz.dll in DirectShow whic",
            "h could allow remote attackers to execute arbitrary code via a cra",
            "fted QuickTime media file."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2009-1862",
        vendor: "Adobe",
        product: "Acrobat and Reader, Flash Player",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader_flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader and Adobe Flash Player allows remote atta",
            "ckers to execute code or cause denial-of-service (DoS)."
        ),
        remediation: concat!(
            "For Adobe Acrobat and Reader, apply updates per vendor instruction",
            "s. For Adobe Flash Player, the impacted product is end-of-life and",
            " should be disconnected if still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2009-2055",
        vendor: "Cisco",
        product: "IOS XR",
        cpe23: "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XR,when BGP is the configured routing feature, allows re",
            "mote attackers to cause a denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-3129",
        vendor: "Microsoft",
        product: "Excel",
        cpe23: "cpe:2.3:a:microsoft:excel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Excel allows remote attackers to execute arbitrar",
            "y code via a spreadsheet with a FEATHEADER record containing an in",
            "valid cbHdrData size element that affects a pointer offset."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-3459",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contain a heap-based buffer overflow vuln",
            "erability which could allow remote attackers to execute arbitrary ",
            "code via a crafted PDF file that triggers memory corruption."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2009-3953",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contains an array boundary issue in Unive",
            "rsal 3D (U3D) support that could lead to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-3960",
        vendor: "Adobe",
        product: "BlazeDS",
        cpe23: "cpe:2.3:a:adobe:blazeds:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe BlazeDS, which is utilized in LifeCycle and Coldfusion, cont",
            "ains a vulnerability that allows for information disclosure."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2009-4324",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in Adobe Acrobat and Reader allows re",
            "mote attackers to execute code via a crafted PDF file."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-0188",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unspecified vulnerability in Adobe Reader and Acrobat allows attac",
            "kers to cause a denial of service or possibly execute arbitrary co",
            "de."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-0232",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The kernel in Microsoft Windows, when access to 16-bit application",
            "s is enabled on a 32-bit x86 platform, does not properly validate ",
            "certain BIOS calls, which allows local users to gain privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-0249",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains an use-after-free vulnerabili",
            "ty that could allow remote attackers to execute arbitrary code by ",
            "accessing a pointer associated with a deleted object. The impacted",
            " product could be end-of-life (EoL) and/or end-of-service (EoS). U",
            "sers should discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2010-0738",
        vendor: "Red Hat",
        product: "JBoss",
        cpe23: "cpe:2.3:a:red_hat:jboss:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The JMX-Console web application in JBossAs in Red Hat JBoss Enterp",
            "rise Application Platform performs access control only for the GET",
            " and POST methods, which allows remote attackers to send requests ",
            "to this application's GET handler by using a different method."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-0806",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains an use-after-free vulnerabili",
            "ty that could allow remote attackers to execute arbitrary code via",
            " vectors involving access to an invalid pointer after the deletion",
            " of an object. The impacted product could be end-of-life (EoL) and",
            "/or end-of-service (EoS). Users should discontinue produ"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2010-0840",
        vendor: "Oracle",
        product: "Java Runtime Environment (JRE)",
        cpe23: "cpe:2.3:a:oracle:java_runtime_environment_jre:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in the Java Runtime Environment (JRE) in",
            " Java SE component allows remote attackers to affect confidentiali",
            "ty, integrity, and availability via Unknown vectors."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-1297",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a memory corruption vulnerability that",
            " allows remote attackers to execute code or cause denial-of-servic",
            "e (DoS)."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2010-1428",
        vendor: "Red Hat",
        product: "JBoss",
        cpe23: "cpe:2.3:a:red_hat:jboss:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unauthenticated access to the JBoss Application Server Web Console",
            " (/web-console) is blocked by default. However, it was found that ",
            "this block was incomplete, and only blocked GET and POST HTTP verb",
            "s. A remote attacker could use this flaw to gain access to sensiti",
            "ve information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-1871",
        vendor: "Red Hat",
        product: "JBoss Seam 2",
        cpe23: "cpe:2.3:a:red_hat:jboss_seam_2:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JBoss Seam 2 (jboss-seam2), as used in JBoss Enterprise Applicatio",
            "n Platform 4.3.0 for Red Hat Linux, allows attackers to perform re",
            "mote code execution. This vulnerability can only be exploited when",
            " the Java Security Manager is not properly configured."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-2568",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows incorrectly parses shortcuts in such a way that ",
            "malicious code may be executed when the operating system displays ",
            "the icon of a malicious shortcut file. An attacker who successfull",
            "y exploited this vulnerability could execute code as the logged-on",
            " user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-2572",
        vendor: "Microsoft",
        product: "PowerPoint",
        cpe23: "cpe:2.3:a:microsoft:powerpoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft PowerPoint contains a buffer overflow vulnerability that",
            " alllows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-2861",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A directory traversal vulnerability exists in the administrator co",
            "nsole in Adobe ColdFusion which allows remote attackers to read ar",
            "bitrary files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-2883",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader contain a stack-based buffer overflow vul",
            "nerability that allows remote attackers to execute code or cause d",
            "enial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-3035",
        vendor: "Cisco",
        product: "IOS XR",
        cpe23: "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XR, when BGP is the configured routing feature, allows r",
            "emote attackers to cause a denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-3333",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A stack-based buffer overflow vulnerability exists in the parsing ",
            "of RTF data in Microsoft Office and earlier allows an attacker to ",
            "perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-3765",
        vendor: "Mozilla",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:mozilla:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox, SeaMonkey, and Thunderbird contain an unspecified",
            " vulnerability when JavaScript is enabled. This allows remote atta",
            "ckers to execute arbitrary code via vectors related to nsCSSFrameC",
            "onstructor::ContentAppended, the appendChild method, incorrect ind",
            "ex tracking, and the creation of multiple frames, which "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2010-3904",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an improper input validation vulnerability i",
            "n the Reliable Datagram Sockets (RDS) protocol implementation that",
            " allows local users to gain privileges via crafted use of the send",
            "msg and recvmsg system calls."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2010-3962",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains an uninitialized memory corru",
            "ption vulnerability that could allow for remote code execution. Th",
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
        cve_id: "CVE-2010-4344",
        vendor: "Exim",
        product: "Exim",
        cpe23: "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Heap-based buffer overflow in the string_vformat function in strin",
            "g.c in Exim before 4.70 allows remote attackers to execute arbitra",
            "ry code via an SMTP session."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-4345",
        vendor: "Exim",
        product: "Exim",
        cpe23: "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Exim allows local users to gain privileges by leveraging the abili",
            "ty of the exim user account to specify an alternate configuration ",
            "file with a directive that contains arbitrary commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-4398",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Stack-based buffer overflow in the RtlQueryRegistryValues function",
            " in win32k.sys in Microsoft Windows allows local users to gain pri",
            "vileges, and bypass the User Account Control (UAC) feature."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-5326",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver Application Server Java Platforms Invoker Servlet do",
            "es not require authentication, allowing for remote code execution ",
            "via a HTTP or HTTPS request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2010-5330",
        vendor: "Ubiquiti",
        product: "AirOS",
        cpe23: "cpe:2.3:a:ubiquiti:airos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Certain Ubiquiti devices contain a command injection vulnerability",
            " via a GET request to stainfo.cgi."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2011-0609",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains an unspecified vulnerability that allo",
            "ws remote attackers to execute code or cause denial-of-service (Do",
            "S)."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2011-0611",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a vulnerability that allows remote att",
            "ackers to execute arbitrary code or cause a denial of service (app",
            "lication crash) via crafted Flash content."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2011-1823",
        vendor: "Android",
        product: "Android OS",
        cpe23: "cpe:2.3:a:android:android_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The vold volume manager daemon in Android kernel trusts messages f",
            "rom a PF_NETLINK socket, which allows an attacker to execute code ",
            "and gain root privileges. This vulnerability is associated with Gi",
            "ngerBreak and Exploit.AndroidOS.Lotoor."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2011-1889",
        vendor: "Microsoft",
        product: "Forefront Threat Management Gateway (TMG)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:forefront_threat_management_gateway_tmg:*:*:*:",
            "*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in the Forefront Thre",
            "at Management Gateway (TMG) Firewall Client Winsock provider that ",
            "could allow code execution in the security context of the client a",
            "pplication."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2011-2005",
        vendor: "Microsoft",
        product: "Ancillary Function Driver (afd.sys)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:ancillary_function_driver_afd.sys:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "afd.sys in the Ancillary Function Driver in Microsoft Windows does",
            " not properly validate user-mode input passed to kernel mode, whic",
            "h allows local users to gain privileges via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2011-2462",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Universal 3D (U3D) component in Adobe Reader and Acrobat conta",
            "ins a memory corruption vulnerability which could allow remote att",
            "ackers to execute code or cause denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2011-2523",
        vendor: "vsftpd_project",
        product: "vsftpd",
        cpe23: "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-506",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Legacy vsFTPd 2.3.4 Compromised Release Advisory",
        remediation: concat!(
            "vsFTPd 2.3.4 paketini darhol rasmiy 3.0.5+ versiyasiga yoki OpenSS",
            "H SFTP ga almashtiring."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2011-3402",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Kernel contains an unspecified vulnerability in ",
            "the TrueType font parsing engine in win32k.sys in the kernel-mode ",
            "drivers that allows remote attackers to execute arbitrary code via",
            " crafted font data in a Word document or web page."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2011-3544",
        vendor: "Oracle",
        product: "Java SE JDK and JRE",
        cpe23: "cpe:2.3:a:oracle:java_se_jdk_and_jre:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An access control vulnerability exists in the Applet Rhino Script ",
            "Engine component of Oracle's Java Runtime Environment allows an at",
            "tacker to remotely execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2011-4723",
        vendor: "D-Link",
        product: "DIR-300 Router",
        cpe23: "cpe:2.3:a:d-link:dir-300_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The D-Link DIR-300 router stores cleartext passwords, which allows",
            " context-dependent attackers to obtain sensitive information."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-0151",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Authenticode Signature Verification function in Microsoft Wind",
            "ows (WinVerifyTrust) does not properly validate the digest of a si",
            "gned portable executable (PE) file, which allows user-assisted rem",
            "ote attackers to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-0158",
        vendor: "Microsoft",
        product: "MSCOMCTL.OCX",
        cpe23: "cpe:2.3:a:microsoft:mscomctl.ocx:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft MSCOMCTL.OCX contains an unspecified vulnerability that ",
            "allows for remote code execution, allowing an attacker to take com",
            "plete control of an affected system under the context of the curre",
            "nt user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-0391",
        vendor: "Apache",
        product: "Struts 2",
        cpe23: "cpe:2.3:a:apache:struts_2:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The ExceptionDelegator component in Apache Struts 2 before 2.2.3.1",
            " contains an improper input validation vulnerability that allows f",
            "or remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-0507",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An incorrect type vulnerability exists in the Concurrency componen",
            "t of Oracle's Java Runtime Environment allows an attacker to remot",
            "ely execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-0518",
        vendor: "Oracle",
        product: "Fusion Middleware",
        cpe23: "cpe:2.3:a:oracle:fusion_middleware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in the Oracle Application Server Single ",
            "Sign-On component in Oracle Fusion Middleware allows remote attack",
            "ers to affect integrity via Unknown vectors"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-0754",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a memory corruption vulnerability that",
            " allows remote attackers to execute code or cause denial-of-servic",
            "e (DoS)."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-0767",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a XSS vulnerability that allows remote",
            " attackers to inject web script or HTML."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-1535",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in Adobe Flash Player allows remote atta",
            "ckers to execute arbitrary code or cause a denial of service via c",
            "rafted SWF content."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-1710",
        vendor: "Oracle",
        product: "Fusion Middleware",
        cpe23: "cpe:2.3:a:oracle:fusion_middleware:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unspecified vulnerability in the Oracle WebCenter Forms Recognitio",
            "n component in Oracle Fusion Middleware allows remote attackers to",
            " affect confidentiality, integrity, and availability via Unknown v",
            "ectors related to Designer."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-1723",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unspecified vulnerability in the Java Runtime Environment (JRE) co",
            "mponent in Oracle Java SE allows remote attackers to affect confid",
            "entiality, integrity, and availability via Unknown vectors related",
            " to Hotspot."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-1823",
        vendor: "PHP",
        product: "PHP",
        cpe23: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "sapi/cgi/cgi_main.c in PHP, when configured as a CGI script, does ",
            "not properly handle query strings, which allows remote attackers t",
            "o execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-1854",
        vendor: "Microsoft",
        product: "Visual Basic for Applications (VBA)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:visual_basic_for_applications_vba:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Visual Basic for Applications (VBA) contains an insecure",
            " library loading vulnerability that could allow for remote code ex",
            "ecution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-1856",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The TabStrip ActiveX control in the Common Controls in MSCOMCTL.OC",
            "X in Microsoft Office allows remote attackers to execute arbitrary",
            " code via a crafted (1) document or (2) web page that triggers sys",
            "tem-state corruption."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-1889",
        vendor: "Microsoft",
        product: "XML Core Services",
        cpe23: "cpe:2.3:a:microsoft:xml_core_services:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft XML Core Services contains a memory corruption vulnerabi",
            "lity which could allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-2034",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a memory corruption vulnerability that",
            " allows for remote code execution or denial-of-service (DoS)."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-2539",
        vendor: "Microsoft",
        product: "Word",
        cpe23: "cpe:2.3:a:microsoft:word:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Word allows attackers to execute remote code or cause a ",
            "denial-of-service (DoS) via crafted RTF data."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-3152",
        vendor: "Oracle",
        product: "Fusion Middleware",
        cpe23: "cpe:2.3:a:oracle:fusion_middleware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Fusion Middleware Reports Developer contains an unspecified",
            " vulnerability that allows remote attackers to affect confidential",
            "ity and integrity of affected systems."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-4681",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Java Runtime Environment (JRE) component in Oracle Java SE all",
            "ow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-4792",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a use-after-free vulnerabilit",
            "y that allows a remote attacker to execute arbitrary code via a cr",
            "afted web site that triggers access to an object that (1) was not ",
            "properly allocated or (2) is deleted, as demonstrated by a CDwnBin",
            "dInfo object."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-4969",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a use-after-free vulnerabilit",
            "y that allows remote attackers to execute code via a crafted web s",
            "ite."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2012-5054",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains an integer overflow vulnerability that",
            " allows remote attackers to execute code via malformed arguments."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2012-5076",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The default Java security properties configuration did not restric",
            "t access to the com.sun.org.glassfish.external and com.sun.org.gla",
            "ssfish.gmbal packages. An untrusted Java application or applet cou",
            "ld use these flaws to bypass Java sandbox restrictions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0074",
        vendor: "Microsoft",
        product: "Silverlight",
        cpe23: "cpe:2.3:a:microsoft:silverlight:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Silverlight does not properly validate pointers during H",
            "TML object rendering, which allows remote attackers to execute cod",
            "e via a crafted Silverlight application."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-0422",
        vendor: "Oracle",
        product: "Java Runtime Environment (JRE)",
        cpe23: "cpe:2.3:a:oracle:java_runtime_environment_jre:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A vulnerability in the way Java restricts the permissions of Java ",
            "applets could allow an attacker to execute commands on a vulnerabl",
            "e system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0431",
        vendor: "Oracle",
        product: "Java Runtime Environment (JRE)",
        cpe23: "cpe:2.3:a:oracle:java_runtime_environment_jre:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unspecified vulnerability in the Java Runtime Environment (JRE) co",
            "mponent in Oracle allows remote attackers to bypass the Java secur",
            "ity sandbox."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0625",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Coldfusion contains an authentication bypass vulnerability, ",
            "which could result in an unauthorized user gaining administrative ",
            "access."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0629",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Coldfusion contains a directory traversal vulnerability, whi",
            "ch could permit an unauthorized user access to restricted director",
            "ies."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0631",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Coldfusion contains an unspecified vulnerability, which coul",
            "d result in information disclosure from a compromised server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0632",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An authentication bypass vulnerability exists in Adobe ColdFusion ",
            "which could result in an unauthorized user gaining administrative ",
            "access."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0640",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An memory corruption vulnerability exists in the acroform.dll in A",
            "dobe Reader that allows an attacker to perform remote code executi",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0641",
        vendor: "Adobe",
        product: "Reader",
        cpe23: "cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A buffer overflow vulnerability exists in Adobe Reader which allow",
            "s an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-0643",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains an incorrect default permissions vulne",
            "rability in the Firefox sandbox that allows a remote attacker to e",
            "xecute arbitrary code via crafted SWF content."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-0648",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains an unspecified vulnerability in the Ex",
            "ternalInterface ActionScript functionality that allows a remote at",
            "tacker to execute arbitrary code via crafted SWF content."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-1331",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a buffer overflow vulnerability that all",
            "ows remote attackers to execute code via crafted PNG data in an Of",
            "fice document."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-1347",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "This vulnerability may corrupt memory in a way that could allow an",
            " attacker to execute arbitrary code in the context of the current ",
            "user within Internet Explorer."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-1675",
        vendor: "Mozilla",
        product: "Firefox",
        cpe23: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox does not properly initialize data structures for t",
            "he nsDOMSVGZoomEvent::mPreviousScale and nsDOMSVGZoomEvent::mNewSc",
            "ale functions, which allows remote attackers to obtain sensitive i",
            "nformation from process memory via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-1690",
        vendor: "Mozilla",
        product: "Firefox and Thunderbird",
        cpe23: "cpe:2.3:a:mozilla:firefox_and_thunderbird:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox and Thunderbird do not properly handle onreadystat",
            "echange events in conjunction with page reloading, which allows re",
            "mote attackers to cause a denial-of-service (DoS) or possibly exec",
            "ute malicious code via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2094",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel fails to check all 64 bits of attr.config passed by u",
            "ser space, resulting to out-of-bounds access of the perf_swevent_e",
            "nabled array in sw_perf_event_destroy(). Explotation allows for pr",
            "ivilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2251",
        vendor: "Apache",
        product: "Struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Struts allows remote attackers to execute arbitrary Object-",
            "Graph Navigation Language (OGNL) expressions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2423",
        vendor: "Oracle",
        product: "Java Runtime Environment (JRE)",
        cpe23: "cpe:2.3:a:oracle:java_runtime_environment_jre:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in hotspot for Java Runtime Environment ",
            "(JRE) allows remote attackers to affect integrity."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2465",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Unspecified vulnerability in the Java Runtime Environment (JRE) co",
            "mponent in Oracle Java SE allows remote attackers to affect confid",
            "entiality, integrity, and availability via Unknown vectors related",
            " to 2D"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2551",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Use-after-free vulnerability in Microsoft Internet Explorer allows",
            " remote attackers to execute remote code via a crafted web site th",
            "at triggers access to a deleted object."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2596",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux kernel fb_mmap function in drivers/video/fbmem.c contains an",
            " integer overflow vulnerability that allows for privilege escalati",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2597",
        vendor: "Code Aurora",
        product: "ACDB Audio Driver",
        cpe23: "cpe:2.3:a:code_aurora:acdb_audio_driver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Code Aurora audio calibration database (acdb) audio driver con",
            "tains a stack-based buffer overflow vulnerability that allows for ",
            "privilege escalation. Code Aurora is used in third-party products ",
            "such as Qualcomm and Android."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-2729",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Integer overflow vulnerability in Adobe Reader and Acrobat allows ",
            "attackers to execute remote code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-3163",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity that allows remote attackers to execute code or cause a denia",
            "l of service via a crafted website."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-3346",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Reader and Acrobat contain a memory corruption vulnerability",
            " which can allow attackers to execute arbitrary code or cause a de",
            "nial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-3660",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The EPATHOBJ::pprFlattenRec function in win32k.sys in the kernel-m",
            "ode drivers in Microsoft does not properly initialize a pointer fo",
            "r the next object in a certain list, which allows local users to g",
            "ain privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-3893",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity that allows for remote code execution. The impacted products ",
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
        cve_id: "CVE-2013-3896",
        vendor: "Microsoft",
        product: "Silverlight",
        cpe23: "cpe:2.3:a:microsoft:silverlight:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Silverlight does not properly validate pointers during a",
            "ccess to Silverlight elements, which allows remote attackers to ob",
            "tain sensitive information via a crafted Silverlight application."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-3897",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A use-after-free vulnerability exists within CDisplayPointer in Mi",
            "crosoft Internet Explorer that allows an attacker to remotely exec",
            "ute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-3900",
        vendor: "Microsoft",
        product: "WinVerifyTrust function",
        cpe23: "cpe:2.3:a:microsoft:winverifytrust_function:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in the way that the W",
            "inVerifyTrust function handles Windows Authenticode signature veri",
            "fication for PE files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-3906",
        vendor: "Microsoft",
        product: "Graphics Component",
        cpe23: "cpe:2.3:a:microsoft:graphics_component:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Graphics Component contains a memory corruption vulnerab",
            "ility which can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-3918",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains an out-of-bounds write vulnerability in",
            " the InformationCardSigninHelper Class ActiveX control, icardie.dl",
            "l. An attacker could exploit the vulnerability by constructing a s",
            "pecially crafted webpage. When a user views the webpage, the vulne",
            "rability could allow remote code execution. An attacker "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-3993",
        vendor: "IBM",
        product: "InfoSphere BigInsights",
        cpe23: "cpe:2.3:a:ibm:infosphere_biginsights:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Certain APIs within BigInsights can take invalid input that might ",
            "allow attackers unauthorized access to read, write, modify, or del",
            "ete data."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2013-4810",
        vendor: "Hewlett Packard (HP)",
        product: concat!(
            "ProCurve Manager (PCM), PCM+, Identity Driven Manager (IDM), and A",
            "pplication Lifecycle Management"
        ),
        cpe23: concat!(
            "cpe:2.3:a:hewlett_packard_hp:procurve_manager_pcm_pcm_identity_dri",
            "ven_manager_idm_and_application_lifecycle_management:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "HP ProCurve Manager (PCM), PCM+, Identity Driven Manager (IDM), an",
            "d Application Lifecycle Management allow remote attackers to execu",
            "te arbitrary code via a marshalled object to (1) EJBInvokerServlet",
            " or (2) JMXInvokerServlet."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-5065",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows NDProxy.sys in the kernel contains an improper i",
            "nput validation vulnerability which can allow a local attacker to ",
            "escalate privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-5223",
        vendor: "D-Link",
        product: "DSL-2760U",
        cpe23: "cpe:2.3:a:d-link:dsl-2760u:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A cross-site scripting (XSS) vulnerability exists in the D-Link DS",
            "L-2760U gateway, allowing remote authenticated users to inject arb",
            "itrary web script or HTML."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-6282",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The get_user and put_user API functions of the Linux kernel fail t",
            "o validate the target address when being used on ARM v6k/v7 platfo",
            "rms. This allows an application to read and write kernel memory wh",
            "ich could lead to privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2013-7331",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An information disclosure vulnerability exists in Internet Explore",
            "r which allows resources loaded into memory to be queried. This vu",
            "lnerability could allow an attacker to detect anti-malware applica",
            "tions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-0130",
        vendor: "Rails",
        product: "Ruby on Rails",
        cpe23: "cpe:2.3:a:rails:ruby_on_rails:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Directory traversal vulnerability in actionpack/lib/abstract_contr",
            "oller/base.rb in the implicit-render implementation in Ruby on Rai",
            "ls allows remote attackers to read arbitrary files via a crafted r",
            "equest."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-0160",
        vendor: "OpenSSL",
        product: "OpenSSL",
        cpe23: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The TLS and DTLS implementations in OpenSSL do not properly handle",
            " Heartbeat Extension packets, which allows remote attackers to obt",
            "ain sensitive information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-0196",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains a race condition vulnerability within the n_",
            "tty_write function that allows local users to cause a denial-of-se",
            "rvice (DoS) or gain privileges via read and write operations with ",
            "long strings."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-0322",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in Microsoft Internet Explorer allows",
            " remote attackers to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-0496",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Reader and Acrobat contain a use-after-free vulnerability wh",
            "ich can allow for code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-0497",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains an integer underflow vulnerability tha",
            "t allows a remote attacker to execute arbitrary code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-0502",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a double free vulnerability that allow",
            "s a remote attacker to execute arbitrary code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-0546",
        vendor: "Adobe",
        product: "Reader and Acrobat",
        cpe23: "cpe:2.3:a:adobe:reader_and_acrobat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Reader and Acrobat on Windows allow attackers to bypass a sa",
            "ndbox protection mechanism, and consequently execute native code i",
            "n a privileged context."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-0780",
        vendor: "InduSoft",
        product: "Web Studio",
        cpe23: "cpe:2.3:a:indusoft:web_studio:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "InduSoft Web Studio NTWebServer contains a directory traversal vul",
            "nerability that allows remote attackers to read administrative pas",
            "swords in APP files, allowing for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-100005",
        vendor: "D-Link",
        product: "DIR-600 Router",
        cpe23: "cpe:2.3:a:d-link:dir-600_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-600 routers contain a cross-site request forgery (CSRF)",
            " vulnerability that allows an attacker to change router configurat",
            "ions by hijacking an existing administrator session."
        ),
        remediation: concat!(
            "This vulnerability affects legacy D-Link products. All associated ",
            "hardware revisions have reached their end-of-life (EOL) or end-of-",
            "service (EOS) life cycle and should be retired and replaced per ve",
            "ndor instructions."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-1761",
        vendor: "Microsoft",
        product: "Word",
        cpe23: "cpe:2.3:a:microsoft:word:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Word contains a memory corruption vulnerability which wh",
            "en exploited could allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-1776",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity that allows remote attackers to execute code in the context o",
            "f the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-1812",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Active Directory contains a privilege escalation",
            " vulnerability due to the way it distributes passwords that are co",
            "nfigured using Group Policy preferences. An authenticated attacker",
            " who successfully exploits the vulnerability could decrypt the pas",
            "swords and use them to elevate privileges on the domain."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-2120",
        vendor: "Cisco",
        product: "Adaptive Security Appliance (ASA)",
        cpe23: "cpe:2.3:a:cisco:adaptive_security_appliance_asa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) contains a cross-site scri",
            "pting (XSS) vulnerability in the WebVPN login page. This vulnerabi",
            "lity allows remote attackers to inject arbitrary web script or HTM",
            "L via an unspecified parameter."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-2817",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer cotains an unspecified vulnerability t",
            "hat allows remote attackers to gain privileges via a crafted web s",
            "ite."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-3120",
        vendor: "Elastic",
        product: "Elasticsearch",
        cpe23: "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Elasticsearch enables dynamic scripting, which allows remote attac",
            "kers to execute arbitrary MVEL expressions and Java code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-3153",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The futex_requeue function in kernel/futex.c in Linux kernel does ",
            "not ensure that calls have two different futex addresses, which al",
            "lows local users to gain privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-3931",
        vendor: "Looking Glass",
        product: "Multi-Router Looking Glass (MRLG)",
        cpe23: concat!(
            "cpe:2.3:a:looking_glass:multi-router_looking_glass_mrlg:*:*:*:*:*:",
            "*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multi-Router Looking Glass (MRLG) contains a buffer overflow vulne",
            "rability that could allow remote attackers to cause an arbitrary m",
            "emory write and memory corruption."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-4077",
        vendor: "Microsoft",
        product: "Input Method Editor (IME) Japanese",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:input_method_editor_ime_japanese:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Input Method Editor (IME) Japanese is a keyboard with Ja",
            "panese characters that can be enabled on Windows systems as it is ",
            "included by default (with the default set as disabled). IME Japane",
            "se contains an unspecified vulnerability when IMJPDCT.EXE (IME for",
            " Japanese) is installed which allows attackers to bypass"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-4113",
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
        cve_id: "CVE-2014-4114",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability exists in Windows Object Linking & Embedding (OLE)",
            " that could allow remote code execution if a user opens a file tha",
            "t contains a specially crafted OLE object."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-4123",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains an unspecified vulnerability ",
            "that allows remote attackers to gain privileges via a crafted web ",
            "site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-4148",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists when the Windows kern",
            "el-mode driver improperly handles TrueType fonts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-4404",
        vendor: "Apple",
        product: "OS X",
        cpe23: "cpe:2.3:a:apple:os_x:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Heap-based buffer overflow in IOHIDFamily in Apple OS X, which aff",
            "ects, iOS before 8 and Apple TV before 7, allows attackers to exec",
            "ute arbitrary code in a privileged context."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-6271",
        vendor: "GNU",
        product: "Bourne-Again Shell (Bash)",
        cpe23: "cpe:2.3:a:gnu:bourne-again_shell_bash:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GNU Bash through 4.3 processes trailing strings after function def",
            "initions in the values of environment variables, which allows remo",
            "te attackers to execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-6278",
        vendor: "GNU",
        product: "GNU Bash",
        cpe23: "cpe:2.3:a:gnu:gnu_bash:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GNU Bash contains an OS command injection vulnerability which allo",
            "ws remote attackers to execute arbitrary commands via a crafted en",
            "vironment."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-6287",
        vendor: "Rejetto",
        product: "HTTP File Server (HFS)",
        cpe23: "cpe:2.3:a:rejetto:http_file_server_hfs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The findMacroMarker function in parserLib.pas in Rejetto HTTP File",
            " Server (HFS or HttpFileServer) allows remote attackers to execute",
            " arbitrary programs."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-6324",
        vendor: "Microsoft",
        product: "Kerberos Key Distribution Center (KDC)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:kerberos_key_distribution_center_kdc:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Kerberos Key Distribution Center (KDC) in Microsoft allows rem",
            "ote authenticated domain users to obtain domain administrator priv",
            "ileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-6332",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "OleAut32.dll in OLE in Microsoft Windows allows remote attackers t",
            "o remotely execute code via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-6352",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows allow remote attackers to execute arbitrary code",
            " via a crafted OLE object."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-7169",
        vendor: "GNU",
        product: "Bourne-Again Shell (Bash)",
        cpe23: "cpe:2.3:a:gnu:bourne-again_shell_bash:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "GNU Bash through 4.3 processes trailing strings after function def",
            "initions in the values of environment variables, which allows remo",
            "te attackers to execute code. This CVE correctly remediates the vu",
            "lnerability in CVE-2014-6271."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2014-8361",
        vendor: "Realtek",
        product: "SDK",
        cpe23: "cpe:2.3:a:realtek:sdk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Realtek SDK contains an improper input validation vulnerability in",
            " the miniigd SOAP service that allows remote attackers to execute ",
            "malicious code via a crafted NewInternalClient request."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-8439",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player has a vulnerability in the way it handles a der",
            "eferenced memory pointer which could lead to code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2014-9163",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Stack-based buffer overflow in Adobe Flash Player allows attackers",
            " to execute code remotely."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-0016",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Directory traversal vulnerability in the TS WebProxy (TSWbPrxy) co",
            "mponent in Microsoft Windows allows remote attackers to escalate p",
            "rivileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-0071",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer allows remote attackers to bypass the ",
            "address space layout randomization (ASLR) protection mechanism via",
            " a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-0310",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player does not properly restrict discovery of memory ",
            "addresses, which allows attackers to bypass the address space layo",
            "ut randomization (ASLR) protection mechanism."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-0311",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in Adobe Flash Player allows remote atta",
            "ckers to execute code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-0313",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in Adobe Flash Player allows remote a",
            "ttackers to execute code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-0666",
        vendor: "Cisco",
        product: "Prime Data Center Network Manager (DCNM)",
        cpe23: concat!(
            "cpe:2.3:a:cisco:prime_data_center_network_manager_dcnm:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Directory traversal vulnerability in the fmserver servlet in Cisco",
            " Prime Data Center Network Manager (DCNM) allows remote attackers ",
            "to read arbitrary files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1130",
        vendor: "Apple",
        product: "OS X",
        cpe23: "cpe:2.3:a:apple:os_x:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The XPC implementation in Admin Framework in Apple OS X before 10.",
            "10.3 allows local users to bypass authentication and obtain admin ",
            "privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1187",
        vendor: "D-Link and TRENDnet",
        product: "Multiple Devices",
        cpe23: "cpe:2.3:a:d-link_and_trendnet:multiple_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The ping tool in multiple D-Link and TRENDnet devices allow remote",
            " attackers to perform remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-1427",
        vendor: "Elastic",
        product: "Elasticsearch",
        cpe23: "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Groovy scripting engine in Elasticsearch allows remote attacke",
            "rs to bypass the sandbox protection mechanism and execute arbitrar",
            "y shell commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1635",
        vendor: "Microsoft",
        product: "HTTP.sys",
        cpe23: "cpe:2.3:a:microsoft:http.sys:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft HTTP protocol stack (HTTP.sys) contains a vulnerability ",
            "that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1641",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a memory corruption vulnerability due to",
            " failure to properly handle rich text format files in memory. Succ",
            "essful exploitation allows for remote code execution in the contex",
            "t of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1642",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a memory corruption vulnerability that a",
            "llows remote attackers to execute arbitrary code via a crafted doc",
            "ument."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1671",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists when components of Wi",
            "ndows, .NET Framework, Office, Lync, and Silverlight fail to prope",
            "rly handle TrueType fonts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1701",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An unspecified vulnerability exists in the Win32k.sys kernel-mode ",
            "driver in Microsoft Windows Server that allows a local attacker to",
            " execute arbitrary code with elevated privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1769",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows Mount",
            " Manager component improperly processes symbolic links."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-1770",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office allows remote attackers to execute arbitrary code",
            " via a crafted Office document."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2051",
        vendor: "D-Link",
        product: "DIR-645 Router",
        cpe23: "cpe:2.3:a:d-link:dir-645_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-645 Wired/Wireless Router allows remote attackers to ex",
            "ecute arbitrary commands via a GetDeviceSettings action to the HNA",
            "P interface."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-2291",
        vendor: "Intel",
        product: "Ethernet Diagnostics Driver for Windows",
        cpe23: concat!(
            "cpe:2.3:a:intel:ethernet_diagnostics_driver_for_windows:*:*:*:*:*:",
            "*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Intel ethernet diagnostics driver for Windows IQVW32.sys and IQVW6",
            "4.sys contain an unspecified vulnerability that allows for a denia",
            "l-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2360",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Win32k.sys in the kernel-mode drivers in Microsoft Windows allows ",
            "local users to gain privileges or cause denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2387",
        vendor: "Microsoft",
        product: "ATM Font Driver",
        cpe23: "cpe:2.3:a:microsoft:atm_font_driver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ATMFD.DLL in the Adobe Type Manager Font Driver in Microsoft Windo",
            "ws Server allows local users to gain privileges via a crafted appl",
            "ication."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2419",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "JScript in Microsoft Internet Explorer allows remote attackers to ",
            "execute remote code or cause a denial of service (memory corruptio",
            "n) via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2424",
        vendor: "Microsoft",
        product: "PowerPoint",
        cpe23: "cpe:2.3:a:microsoft:powerpoint:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft PowerPoint allows remote attackers to execute arbitrary ",
            "code or cause a denial of service (memory corruption) via a crafte",
            "d Office document."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2425",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity that allows remote attackers to execute code or cause denial-",
            "of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2426",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in Microsoft Windows ",
            "when the Windows Adobe Type Manager Library improperly handles spe",
            "cially crafted OpenType fonts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2502",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity that allows an attacker to execute code or cause a denial-of-",
            "service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2545",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office allows remote attackers to execute arbitrary code",
            " via a crafted EPS image."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2546",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The kernel-mode driver in Microsoft Windows OS and Server allows l",
            "ocal users to gain privileges via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-2590",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An unspecified vulnerability exists within Oracle Java Runtime Env",
            "ironment that allows an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-3035",
        vendor: "TP-Link",
        product: "Multiple Archer Devices",
        cpe23: "cpe:2.3:a:tp-link:multiple_archer_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Directory traversal vulnerability in multiple TP-Link Archer devic",
            "es allows remote attackers to read arbitrary files via a .. (dot d",
            "ot) in the PATH_INFO to login/."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-3043",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A memory corruption vulnerability exists in Adobe Flash Player tha",
            "t allows an attacker to perform remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-3113",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Heap-based buffer overflow vulnerability in Adobe Flash Player all",
            "ows remote attackers to execute code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-3246",
        vendor: "Red Hat",
        product: "Libuser",
        cpe23: "cpe:2.3:a:red_hat:libuser:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Red Hat libuser contains a race condition vulnerability that allow",
            "s authenticated local users to corrupt the /etc/passwd file to cau",
            "se a denial of service or privilege escalation."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-3306",
        vendor: "ProFTPD",
        product: "ProFTPD",
        cpe23: "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ProFTPD contains an improper access control vulnerability that cou",
            "ld allow remote attackers to read and write to arbitrary files via",
            " the site cpfr and site cpto commands."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-4068",
        vendor: "Arcserve",
        product: "Unified Data Protection (UDP)",
        cpe23: "cpe:2.3:a:arcserve:unified_data_protection_udp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Directory traversal vulnerability in Arcserve UDP allows remote at",
            "tackers to obtain sensitive information or cause a denial of servi",
            "ce."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-4495",
        vendor: "Mozilla",
        product: "Firefox",
        cpe23: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Moxilla Firefox allows remote attackers to bypass the Same Origin ",
            "Policy to read arbitrary files or gain privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-4852",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server contains a deserialization of untrusted dat",
            "a vulnerability within Apache Commons, which can allow for for rem",
            "ote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-4902",
        vendor: "Oracle",
        product: "Java SE",
        cpe23: "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in Oracle Java SE allows remote attacker",
            "s to affect integrity via Unknown vectors related to deployment."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-5119",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A use-after-free vulnerability exists within the ActionScript 3 By",
            "teArray class in Adobe Flash Player that allows an attacker to per",
            "form remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-5122",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in the DisplayObject class in the Act",
            "ionScript 3 (AS3) implementation in Adobe Flash Player allows remo",
            "te attackers to execute code or cause a denial-of-service (DoS)."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-5123",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in the BitmapData class in the Action",
            "Script 3 (AS3) implementation in Adobe Flash Player allows remote ",
            "attackers to execute code or cause a denial-of-service (DoS)."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-5287",
        vendor: "Red Hat",
        product: "Automatic Bug Reporting Tool",
        cpe23: "cpe:2.3:a:red_hat:automatic_bug_reporting_tool:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Red Hat Automatic Bug Reporting Tool (ABRT) contains a privilege e",
            "scalation vulnerability that could allow local users with certain ",
            "permissions to gain privileges via a symlink attack on a file with",
            " a predictable name. The impacted product(s) could be end-of-life ",
            "(EoL) and/or end-of-service (EoS). Users are advised to "
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-5317",
        vendor: "Jenkins",
        product: "Jenkins User Interface (UI)",
        cpe23: "cpe:2.3:a:jenkins:jenkins_user_interface_ui:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Jenkins User Interface (UI) contains an information disclosure vul",
            "nerability that allows users to see the names of jobs and builds o",
            "therwise inaccessible to them on the \"Fingerprints\" pages."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-5477",
        vendor: "ISC",
        product: "BIND",
        cpe23: "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ISC BIND contains a data processing errors vulnerability that coul",
            "d allow remote attackers to cause a denial of service via TKEY que",
            "ries."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-6175",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The kernel in Microsoft Windows contains a vulnerability that allo",
            "ws local users to gain privileges via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-7450",
        vendor: "IBM",
        product: "WebSphere Application Server and Server Hypervisor Edition",
        cpe23: concat!(
            "cpe:2.3:a:ibm:websphere_application_server_and_server_hypervisor_e",
            "dition:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Serialized-object interfaces in certain IBM analytics, business so",
            "lutions, cognitive, IT infrastructure, and mobile and social produ",
            "cts allow remote attackers to execute arbitrary commands"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2015-7645",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe Flash Player allows remote attackers to execute arbitrary co",
            "de via a crafted SWF file."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-7755",
        vendor: "Juniper",
        product: "ScreenOS",
        cpe23: "cpe:2.3:a:juniper:screenos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Juniper ScreenOS contains an improper authentication vulnerability",
            " that could allow unauthorized remote administrative access to the",
            " device."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2015-8651",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Integer overflow in Adobe Flash Player allows attackers to execute",
            " code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-0034",
        vendor: "Microsoft",
        product: "Silverlight",
        cpe23: "cpe:2.3:a:microsoft:silverlight:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Silverlight mishandles negative offsets during decoding,",
            " which allows attackers to execute remote code or cause a denial-o",
            "f-service (DoS)."
        ),
        remediation: concat!(
            "The impacted products are end-of-life and should be disconnected i",
            "f still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-0040",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The kernel in Microsoft Windows allows local users to gain privile",
            "ges via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0099",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists in Microsoft Windows i",
            "f the Windows Secondary Logon Service fails to properly manage req",
            "uest handles in memory. An attacker who successfully exploited thi",
            "s vulnerability could run arbitrary code as an administrator."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0151",
        vendor: "Microsoft",
        product: "Client-Server Run-time Subsystem (CSRSS)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:client-server_run-time_subsystem_csrss:*:*:*:*",
            ":*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Client-Server Run-time Subsystem (CSRSS) in Microsoft mismanag",
            "es process tokens, which allows local users to gain privileges via",
            " a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0162",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An information disclosure vulnerability exists when Internet Explo",
            "rer does not properly handle JavaScript. The vulnerability could a",
            "llow an attacker to detect specific files on the user's computer."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0165",
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
        cve_id: "CVE-2016-0167",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability that allows",
            " for privilege escalation via a crafted application"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0185",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Media Center contains a remote code execution vu",
            "lnerability when Windows Media Center opens a specially crafted Me",
            "dia Center link (.mcl) file that references malicious code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0189",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The Microsoft JScript nd VBScript engines, as used in Internet Exp",
            "lorer and other products, allow attackers to execute remote code o",
            "r cause a denial of service (memory corruption) via a crafted web ",
            "site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0752",
        vendor: "Rails",
        product: "Ruby on Rails",
        cpe23: "cpe:2.3:a:rails:ruby_on_rails:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Directory traversal vulnerability in Action View in Ruby on Rails ",
            "allows remote attackers to read arbitrary files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-0984",
        vendor: "Adobe",
        product: "Flash Player and AIR",
        cpe23: "cpe:2.3:a:adobe:flash_player_and_air:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in Adobe Flash Player and Adobe AIR a",
            "llows attackers to execute code."
        ),
        remediation: concat!(
            "The impacted products are end-of-life and should be disconnected i",
            "f still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-10033",
        vendor: "PHP",
        product: "PHPMailer",
        cpe23: "cpe:2.3:a:php:phpmailer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PHPMailer contains a command injection vulnerability because it fa",
            "ils to sanitize user-supplied input. Specifically, this issue affe",
            "cts the 'mail()' function of 'class.phpmailer.php' script. An atta",
            "cker can exploit this issue to execute arbitrary code within the c",
            "ontext of the application. Failed exploit attempts will "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-1010",
        vendor: "Adobe",
        product: "Flash Player and AIR",
        cpe23: "cpe:2.3:a:adobe:flash_player_and_air:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Integer overflow vulnerability in Adobe Flash Player and AIR allow",
            "s attackers to execute code."
        ),
        remediation: concat!(
            "The impacted products are end-of-life and should be disconnected i",
            "f still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-10174",
        vendor: "NETGEAR",
        product: "WNR2000v5 Router",
        cpe23: "cpe:2.3:a:netgear:wnr2000v5_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The NETGEAR WNR2000v5 router contains a buffer overflow which can ",
            "be exploited to achieve remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-1019",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe Flash Player allows remote attackers to cause a denial of se",
            "rvice or possibly execute arbitrary code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-11021",
        vendor: "D-Link",
        product: "DCS-930L Devices",
        cpe23: "cpe:2.3:a:d-link:dcs-930l_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "setSystemCommand on D-Link DCS-930L devices allows a remote attack",
            "er to execute code via an OS command."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-1555",
        vendor: "NETGEAR",
        product: "Wireless Access Point (WAP) Devices",
        cpe23: concat!(
            "cpe:2.3:a:netgear:wireless_access_point_wap_devices:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple NETGEAR Wireless Access Point devices allows unauthentica",
            "ted web pages to pass form input directly to the command-line inte",
            "rface. Exploitation allows for arbitrary code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-1646",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an out-of-bounds read vulnerabi",
            "lity that allows a remote attacker to cause a denial of service or",
            " possibly have another unspecified impact via crafted JavaScript c",
            "ode. This vulnerability could affect multiple web browsers that ut",
            "ilize Chromium, including, but not limited to, Google Ch"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-20017",
        vendor: "D-Link",
        product: "DSL-2750B Devices",
        cpe23: "cpe:2.3:a:d-link:dsl-2750b_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DSL-2750B devices contain a command injection vulnerability",
            " that allows remote, unauthenticated command injection via the log",
            "in.cgi cli parameter."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-2386",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SQL injection vulnerability in the UDDI server in SAP NetWeaver J2",
            "EE Engine 7.40 allows remote attackers to execute arbitrary SQL co",
            "mmands via unspecified vectors."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-2388",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Universal Worklist Configuration in SAP NetWeaver AS JAVA 7.4 ",
            "allows remote attackers to obtain sensitive user information via a",
            " crafted HTTP request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3081",
        vendor: "Apache",
        product: "Struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Struts contains a command injection vulnerability that coul",
            "d allow remote attackers to execute arbitrary code via method:pref",
            "ix when Dynamic Method Invocation is enabled."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-3088",
        vendor: "Apache",
        product: "ActiveMQ",
        cpe23: "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Fileserver web application in Apache ActiveMQ allows remote at",
            "tackers to upload and execute arbitrary files via an HTTP PUT foll",
            "owed by an HTTP MOVE request"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3235",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Object Linking & Embedding (OLE) dynamic link lib",
            "rary (DLL) contains a side loading vulnerability due to it imprope",
            "rly validating input before loading libraries. Successful exploita",
            "tion allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3298",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An information disclosure vulnerability exists when the Microsoft ",
            "Internet Messaging API improperly handles objects in memory. An at",
            "tacker who successfully exploited this vulnerability could allow t",
            "he attacker to test for the presence of files on disk."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3309",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows kerne",
            "l fails to properly handle objects in memory. An attacker who succ",
            "essfully exploited this vulnerability could run arbitrary code in ",
            "kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3351",
        vendor: "Microsoft",
        product: "Internet Explorer and Edge",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer_and_edge:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-200",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An information disclosure vulnerability exists in the way that cer",
            "tain functions in Internet Explorer and Edge handle objects in mem",
            "ory. The vulnerability could allow an attacker to detect specific ",
            "files on the user's computer."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3393",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists due to the way the Wi",
            "ndows GDI component handles objects in the memory. An attacker who",
            " successfully exploits this vulnerability could take control of th",
            "e affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3427",
        vendor: "Oracle",
        product: "Java SE and JRockit",
        cpe23: "cpe:2.3:a:oracle:java_se_and_jrockit:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Java SE and JRockit contains an unspecified vulnerability t",
            "hat allows remote attackers to affect confidentiality, integrity, ",
            "and availability via vectors related to Java Management Extensions",
            " (JMX). This vulnerability can be exploited through sandboxed Java",
            " Web Start applications and sandboxed Java applets. It c"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3643",
        vendor: "SolarWinds",
        product: "Virtualization Manager",
        cpe23: "cpe:2.3:a:solarwinds:virtualization_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Virtualization Manager allows for privilege escalation ",
            "through leveraging a misconfiguration of sudo."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3714",
        vendor: "ImageMagick",
        product: "ImageMagick",
        cpe23: "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ImageMagick contains an improper input validation vulnerability th",
            "at affects the EPHEMERAL, HTTPS, MVG, MSL, TEXT, SHOW, WIN, and PL",
            "T coders. This allows a remote attacker to execute arbitrary code ",
            "via shell metacharacters in a crafted image."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-3715",
        vendor: "ImageMagick",
        product: "ImageMagick",
        cpe23: "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ImageMagick contains an unspecified vulnerability that could allow",
            " users to delete files by using ImageMagick's 'ephemeral' pseudo p",
            "rotocol, which deletes files after reading."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3718",
        vendor: "ImageMagick",
        product: "ImageMagick",
        cpe23: "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ImageMagick contains an unspecified vulnerability that allows atta",
            "ckers to perform server-side request forgery (SSRF) via a crafted ",
            "image."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-3976",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver Application Server Java Platforms contains a directo",
            "ry traversal vulnerability via a ..\\ (dot dot backslash) in the f",
            "ileName parameter to CrashFileDownloadServlet. This allows remote ",
            "attackers to read files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-4117",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An access of resource using incompatible type vulnerability exists",
            " within Adobe Flash Player that allows an attacker to perform remo",
            "te code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-4171",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Unspecified vulnerability in Adobe Flash Player allows for remote ",
            "code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-4437",
        vendor: "Apache",
        product: "Shiro",
        cpe23: "cpe:2.3:a:apache:shiro:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Shiro contains a vulnerability which may allow remote attac",
            "kers to execute code or bypass intended access restrictions via an",
            " unspecified request parameter when a cipher key has not been conf",
            "igured for the \"remember me\" feature."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-4523",
        vendor: "Trihedral",
        product: "VTScada (formerly VTS)",
        cpe23: "cpe:2.3:a:trihedral:vtscada_formerly_vts:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The WAP interface in Trihedral VTScada (formerly VTS) allows remot",
            "e attackers to cause a denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-4655",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Apple iOS kernel allows attackers to obtain sensitive informat",
            "ion from memory via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-4656",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A memory corruption vulnerability in Apple iOS kernel allows attac",
            "kers to execute code in a privileged context or cause a denial-of-",
            "service (DoS) via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-4657",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS WebKit contains a memory corruption vulnerability that a",
            "llows attackers to execute remote code or cause a denial-of-servic",
            "e (DoS) via a crafted web site. This vulnerability could impact HT",
            "ML parsers that use WebKit, including but not limited to Apple Saf",
            "ari and non-Apple products which rely on WebKit for HTML"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-5195",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Race condition in mm/gup.c in the Linux kernel allows local users ",
            "to escalate privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-5198",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an out-of-bounds memory access ",
            "vulnerability that allows a remote attacker to perform read/write ",
            "operations, leading to code execution, via a crafted HTML page. Th",
            "is vulnerability could affect multiple web browsers that utilize C",
            "hromium, including, but not limited to, Google Chrome, M"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-6277",
        vendor: "NETGEAR",
        product: "Multiple Routers",
        cpe23: "cpe:2.3:a:netgear:multiple_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "NETGEAR confirmed multiple routers allow unauthenticated web pages",
            " to pass form input directly to the command-line interface, permit",
            "ting remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-6366",
        vendor: "Cisco",
        product: "Adaptive Security Appliance (ASA)",
        cpe23: "cpe:2.3:a:cisco:adaptive_security_appliance_asa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A buffer overflow vulnerability in the Simple Network Management P",
            "rotocol (SNMP) code of Cisco ASA software could allow an attacker ",
            "to cause a reload of the affected system or to remotely execute co",
            "de."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-6367",
        vendor: "Cisco",
        product: "Adaptive Security Appliance (ASA)",
        cpe23: "cpe:2.3:a:cisco:adaptive_security_appliance_asa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the command-line interface (CLI) parser of Cisc",
            "o ASA software could allow an authenticated, local attacker to cre",
            "ate a denial-of-service (DoS) condition or potentially execute cod",
            "e."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-6415",
        vendor: "Cisco",
        product: "IOS, IOS XR, and IOS XE",
        cpe23: "cpe:2.3:a:cisco:ios_ios_xr_and_ios_xe:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS, IOS XR, and IOS XE contain insufficient condition check",
            "s in the part of the code that handles Internet Key Exchange versi",
            "on 1 (IKEv1) security negotiation requests. contains an informatio",
            "n disclosure vulnerability in the Internet Key Exchange version 1 ",
            "(IKEv1) that could allow an attacker to retrieve memory "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7193",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a memory corruption vulnerability which ",
            "can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7200",
        vendor: "Microsoft",
        product: "Edge",
        cpe23: "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Chakra JavaScript scripting engine in Microsoft Edge allows re",
            "mote attackers to execute remote code or cause a denial of service",
            " (memory corruption) via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7201",
        vendor: "Microsoft",
        product: "Edge",
        cpe23: "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Chakra JavaScript scripting engine in Microsoft Edge allows re",
            "mote attackers to execute remote code or cause a denial of service",
            " (memory corruption) via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7255",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Win32k kernel-mode driver fails to properly handle objec",
            "ts in memory which allows for privilege escalation. Successful exp",
            "loitation allows an attacker to run code in kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7256",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists when the Windows font",
            " library improperly handles specially crafted embedded fonts. An a",
            "ttacker who successfully exploits this vulnerability could take co",
            "ntrol of the affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7262",
        vendor: "Microsoft",
        product: "Excel",
        cpe23: "cpe:2.3:a:microsoft:excel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A security feature bypass vulnerability exists when Microsoft Offi",
            "ce improperly handles input. An attacker who successfully exploite",
            "d the vulnerability could execute arbitrary commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-7836",
        vendor: "SKYSEA",
        product: "Client View",
        cpe23: "cpe:2.3:a:skysea:client_view:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SKYSEA Client View contains an improper authentication vulnerabili",
            "ty that allows remote code execution via a flaw in processing auth",
            "entication on the TCP connection with the management console progr",
            "am."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-7855",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Use-after-free vulnerability in Adobe Flash Player Windows and OS ",
            "and Linux allows remote attackers to execute arbitrary code."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-7892",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player has an exploitable use-after-free vulnerability",
            " in the TextField class."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2016-8562",
        vendor: "Siemens",
        product: "SIMATIC CP",
        cpe23: "cpe:2.3:a:siemens:simatic_cp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An improper privilege management vulnerability exists within the S",
            "iemens SIMATIC Communication Processor (CP) that allows a privileg",
            "ed attacker to remotely cause a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-8735",
        vendor: "Apache",
        product: "Tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Tomcat contains an unspecified vulnerability that allows fo",
            "r remote code execution if JmxRemoteLifecycleListener is used and ",
            "an attacker can reach Java Management Extension (JMX) ports. This ",
            "CVE exists because this listener wasn't updated for consistency wi",
            "th the Oracle patched issues for CVE-2016-3427 which aff"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-9079",
        vendor: "Mozilla",
        product: "Firefox, Firefox ESR, and Thunderbird",
        cpe23: concat!(
            "cpe:2.3:a:mozilla:firefox_firefox_esr_and_thunderbird:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox, Firefox ESR, and Thunderbird contain a use-after-",
            "free vulnerability in SVG Animation, targeting Firefox and Tor bro",
            "wser users on Windows."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2016-9563",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver Application Server Java Platforms contains an unspec",
            "ified vulnerability in BC-BMT-BPM-DSK which allows remote, authent",
            "icated users to conduct XML External Entity (XXE) attacks."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0001",
        vendor: "Microsoft",
        product: "Graphics Device Interface (GDI)",
        cpe23: "cpe:2.3:a:microsoft:graphics_device_interface_gdi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Graphics Device Interface (GDI) in Microsoft Windows Vista SP2",
            "; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; ",
            "Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Go",
            "ld, 1511, and 1607 allows local users to gain privileges"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0005",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Graphics Device Interface (GDI) in Microsoft Windows allows lo",
            "cal users to gain privileges via a crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0022",
        vendor: "Microsoft",
        product: "XML Core Services",
        cpe23: "cpe:2.3:a:microsoft:xml_core_services:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft XML Core Services (MSXML) improperly handles objects in ",
            "memory, allowing attackers to test for files on disk via a crafted",
            " web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0037",
        vendor: "Microsoft",
        product: "Edge and Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:edge_and_internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Edge and Internet Explorer have a type confusion vulnera",
            "bility in mshtml.dll, which allows remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0059",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer allow remote attackers to obtain sensi",
            "tive information from process memory via a crafted web site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0101",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows Trans",
            "action Manager improperly handles objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0143",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Server Message Block 1.0 (SMBv1) contains an uns",
            "pecified vulnerability that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0144",
        vendor: "Microsoft",
        product: "SMBv1",
        cpe23: "cpe:2.3:a:microsoft:smbv1:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The SMBv1 server in multiple Microsoft Windows versions allows rem",
            "ote attackers to execute arbitrary code via crafted packets."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0145",
        vendor: "Microsoft",
        product: "SMBv1",
        cpe23: "cpe:2.3:a:microsoft:smbv1:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The SMBv1 server in multiple Microsoft Windows versions allows rem",
            "ote attackers to execute arbitrary code via crafted packets."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0146",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The SMBv1 server in Microsoft Windows allows remote attackers to p",
            "erform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0147",
        vendor: "Microsoft",
        product: "SMBv1 server",
        cpe23: "cpe:2.3:a:microsoft:smbv1_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-200",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The SMBv1 server in Microsoft Windows allows remote attackers to o",
            "btain sensitive information from process memory via a crafted pack",
            "et."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0148",
        vendor: "Microsoft",
        product: "SMBv1 server",
        cpe23: "cpe:2.3:a:microsoft:smbv1_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The SMBv1 server in Microsoft allows remote attackers to execute a",
            "rbitrary code via crafted packets."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0149",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity that allows remote attackers to execute code or cause a denia",
            "l-of-service (DoS) via a crafted website."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0199",
        vendor: "Microsoft",
        product: "Office and WordPad",
        cpe23: "cpe:2.3:a:microsoft:office_and_wordpad:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Office and WordPad contain an unspecified vulnerability ",
            "due to the way the applications parse specially crafted files. Suc",
            "cessful exploitation allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0210",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A privilege escalation vulnerability exists when Internet Explorer",
            " does not properly enforce cross-domain policies, which could allo",
            "w an attacker to access information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0213",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows COM Aggregate Marshaler allows for privilege esc",
            "alation when an attacker runs a specially crafted application."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0222",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists when Internet Explore",
            "r improperly accesses objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0261",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a use-after-free vulnerability which can",
            " allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0262",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "A remote code execution vulnerability exists in Microsoft Office.",
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-0263",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains a privilege escalation vulnerability due",
            " to the Windows kernel-mode driver failing to properly handle obje",
            "cts in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-1000253",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Linux kernel contains a position-independent executable (PIE) stac",
            "k buffer corruption vulnerability in load_elf_ binary() that allow",
            "s a local attacker to escalate privileges."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-1000353",
        vendor: "Jenkins",
        product: "Jenkins",
        cpe23: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Jenkins contains a remote code execution vulnerability. This vulne",
            "rability that could allowed attackers to transfer a serialized Jav",
            "a SignedObject object to the remoting-based Jenkins CLI, that woul",
            "d be deserialized using a new ObjectInputStream, bypassing the exi",
            "sting blocklist-based protection mechanism."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-1000486",
        vendor: "Primetek",
        product: "Primefaces Application",
        cpe23: "cpe:2.3:a:primetek:primefaces_application:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Primetek Primefaces is vulnerable to a weak encryption flaw result",
            "ing in remote code execution"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-10271",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Oracle Corporation WebLogic Server contains a vulnerability that a",
            "llows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-11292",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player contains a type confusion vulnerability which c",
            "an allow for remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-11317",
        vendor: "Telerik",
        product: "User Interface (UI) for ASP.NET AJAX",
        cpe23: concat!(
            "cpe:2.3:a:telerik:user_interface_ui_for_asp.net_ajax:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX allows remo",
            "te attackers to perform arbitrary file uploads or execute arbitrar",
            "y code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-11357",
        vendor: "Telerik",
        product: "User Interface (UI) for ASP.NET AJAX",
        cpe23: concat!(
            "cpe:2.3:a:telerik:user_interface_ui_for_asp.net_ajax:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Telerik UI for ASP.NET AJAX contains an insecure direct object ref",
            "erence vulnerability in RadAsyncUpload that can result in file upl",
            "oads in a limited location and/or remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-11774",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office Outlook contains a security feature bypass vulner",
            "ability due to improperly handling objects in memory. Successful e",
            "xploitation allows an attacker to execute commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-11826",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in Microsoft Office s",
            "oftware when the software fails to properly handle objects in memo",
            "ry. An attacker who successfully exploited the vulnerability could",
            " run arbitrary code in the context of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-11882",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Office contains a memory corruption vulnerability that a",
            "llows remote code execution in the context of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12149",
        vendor: "Red Hat",
        product: "JBoss Application Server",
        cpe23: "cpe:2.3:a:red_hat:jboss_application_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The JBoss Application Server, shipped with Red Hat Enterprise Appl",
            "ication Platform 5.2, allows an attacker to execute arbitrary code",
            " via crafted serialized data."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12231",
        vendor: "Cisco",
        product: "IOS software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the implementation of Network Address Translati",
            "on (NAT) functionality in Cisco IOS could allow an unauthenticated",
            ", remote attacker to cause a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12232",
        vendor: "Cisco",
        product: "IOS software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the implementation of a protocol in Cisco Integ",
            "rated Services Routers Generation 2 (ISR G2) Routers running Cisco",
            " IOS could allow an unauthenticated, adjacent attacker to cause an",
            " affected device to reload, resulting in a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12233",
        vendor: "Cisco",
        product: "IOS software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "There is a vulnerability in the implementation of the Common Indus",
            "trial Protocol (CIP) feature in Cisco IOS could allow an unauthent",
            "icated, remote attacker to cause an affected device to reload, res",
            "ulting in a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12234",
        vendor: "Cisco",
        product: "IOS software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "There is a vulnerability in the implementation of the Common Indus",
            "trial Protocol (CIP) feature in Cisco IOS could allow an unauthent",
            "icated, remote attacker to cause an affected device to reload, res",
            "ulting in a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12235",
        vendor: "Cisco",
        product: "IOS software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the implementation of the PROFINET Discovery an",
            "d Configuration Protocol (PN-DCP) for Cisco IOS could allow an una",
            "uthenticated, remote attacker to cause an affected device to reloa",
            "d, resulting in a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12237",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Internet Key Exchange Version 2 (IKEv2) mod",
            "ule of Cisco IOS and Cisco IOS XE could allow an unauthenticated, ",
            "remote attacker to cause high CPU utilization, traceback messages,",
            " or a reload of an affected device that leads to a denial of servi",
            "ce."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12238",
        vendor: "Cisco",
        product: "Catalyst 6800 Series Switches",
        cpe23: "cpe:2.3:a:cisco:catalyst_6800_series_switches:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Virtual Private LAN Service (VPLS) code of ",
            "Cisco IOS for Cisco Catalyst 6800 Series Switches could allow an u",
            "nauthenticated, adjacent attacker to cause a denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12240",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Dynamic Host Configuration Protocol (DHCP) relay subsystem of ",
            "Cisco IOS and Cisco IOS XE Software contains a vulnerability that ",
            "could allow an unauthenticated, remote attacker to execute arbitra",
            "ry code and gain full control of an affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12319",
        vendor: "Cisco",
        product: "IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Border Gateway Protocol (BGP) over an Ether",
            "net Virtual Private Network (EVPN) for Cisco IOS XE Software could",
            " allow an unauthenticated, remote attacker to cause the device to ",
            "reload, resulting in a denial of service (DoS) condition, or poten",
            "tially corrupt the BGP routing table, which could result"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12615",
        vendor: "Apache",
        product: "Tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "When running Apache Tomcat on Windows with HTTP PUTs enabled, it i",
            "s possible to upload a JSP file to the server via a specially craf",
            "ted request. This JSP could then be requested and any code it cont",
            "ained would be executed by the server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12617",
        vendor: "Apache",
        product: "Tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "When running Apache Tomcat, it is possible to upload a JSP file to",
            " the server via a specially crafted request. This JSP could then b",
            "e requested and any code it contained would be executed by the ser",
            "ver."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-12637",
        vendor: "SAP",
        product: "NetWeaver",
        cpe23: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP NetWeaver Application Server (AS) Java contains a directory tr",
            "aversal vulnerability in scheduler/ui/js/ffffffffbca41eb4/UIUtilJa",
            "vaScriptJS that allows a remote attacker to read arbitrary files v",
            "ia a .. (dot dot) in the query string."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-15944",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains multiple, unspecified vulnerabi",
            "lities which can allow for remote code execution when chained."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-16651",
        vendor: "Roundcube",
        product: "Roundcube Webmail",
        cpe23: "cpe:2.3:a:roundcube:roundcube_webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail contains a file disclosure vulnerability caused ",
            "by insufficient input validation in conjunction with file-based at",
            "tachment plugins, which are used by default."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-17562",
        vendor: "Embedthis",
        product: "GoAhead",
        cpe23: "cpe:2.3:a:embedthis:goahead:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Embedthis GoAhead before 3.6.5 allows remote code execution if CGI",
            " is enabled and a CGI program is dynamically linked."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-18362",
        vendor: "Kaseya",
        product: "Virtual System/Server Administrator (VSA)",
        cpe23: concat!(
            "cpe:2.3:a:kaseya:virtual_system_server_administrator_vsa:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "ConnectWise ManagedITSync integration for Kaseya VSA is vulnerable",
            " to unauthenticated remote commands that allow full direct access ",
            "to the Kaseya VSA database."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-18368",
        vendor: "Zyxel",
        product: "P660HN-T1A Routers",
        cpe23: "cpe:2.3:a:zyxel:p660hn-t1a_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zyxel P660HN-T1A routers contain a command injection vulnerability",
            " in the Remote System Log forwarding function, which is accessible",
            " by an unauthenticated user and exploited via the remote_host para",
            "meter of the ViewLog.asp page."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-3066",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains a deserialization vulnerability in the A",
            "pache BlazeDS library that allows for arbitrary code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-3506",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server, a product within the Fusion Middleware sui",
            "te, contains an OS command injection vulnerability that allows an ",
            "attacker to execute arbitrary code via a specially crafted HTTP re",
            "quest that includes a malicious XML document."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-3881",
        vendor: "Cisco",
        product: "IOS and IOS XE",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Cisco Cluster Management Protocol (CMP) pro",
            "cessing code in Cisco IOS and Cisco IOS XE Software could allow an",
            " unauthenticated, remote attacker to cause a reload of an affected",
            " device or remotely execute code with elevated privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-5030",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains a memory corruption vulnerabili",
            "ty that allows a remote attacker to execute code via a crafted HTM",
            "L page. This vulnerability could affect multiple web browsers that",
            " utilize Chromium, including, but not limited to, Google Chrome, M",
            "icrosoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-5070",
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
        cve_id: "CVE-2017-5521",
        vendor: "NETGEAR",
        product: "Multiple Devices",
        cpe23: "cpe:2.3:a:netgear:multiple_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-200",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple NETGEAR devices are prone to admin password disclosure vi",
            "a simple crafted requests to the web management server."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions. If the affected device has ",
            "since entered end-of-life, it should be disconnected if still in u",
            "se."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-5638",
        vendor: "Apache",
        product: "Struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Apache Struts Jakarta Multipart parser allows for malicious file u",
            "pload using the Content-Type value, leading to remote code executi",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-5689",
        vendor: "Intel",
        product: concat!(
            "Active Management Technology (AMT), Small Business Technology (SBT",
            "), and Standard Manageability"
        ),
        cpe23: concat!(
            "cpe:2.3:a:intel:active_management_technology_amt_small_business_te",
            "chnology_sbt_and_standard_manageability:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Intel products contain a vulnerability which can allow attackers t",
            "o perform privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6077",
        vendor: "NETGEAR",
        product: "Wireless Router DGN2200",
        cpe23: "cpe:2.3:a:netgear:wireless_router_dgn2200:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "NETGEAR DGN2200 wireless routers contain a vulnerability that allo",
            "ws for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6316",
        vendor: "Citrix",
        product: concat!(
            "NetScaler SD-WAN Enterprise, CloudBridge Virtual WAN, and XenMobil",
            "e Server"
        ),
        cpe23: concat!(
            "cpe:2.3:a:citrix:netscaler_sd-wan_enterprise_cloudbridge_virtual_w",
            "an_and_xenmobile_server:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability has been identified in the management interface of",
            " Citrix NetScaler SD-WAN Enterprise and Standard Edition and Citri",
            "x CloudBridge Virtual WAN Edition that could result in an unauthen",
            "ticated, remote attacker being able to execute arbitrary code as a",
            " root user. This vulnerability also affects XenMobile Se"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6327",
        vendor: "Symantec",
        product: "Symantec Messaging Gateway",
        cpe23: "cpe:2.3:a:symantec:symantec_messaging_gateway:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Symantec Messaging Gateway contains an unspecified vulnerability w",
            "hich can allow for remote code execution. With the ability to perf",
            "orm remote code execution, an attacker may also desire to perform ",
            "privilege escalating actions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6334",
        vendor: "NETGEAR",
        product: "DGN2200 Devices",
        cpe23: "cpe:2.3:a:netgear:dgn2200_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "dnslookup.cgi on NETGEAR DGN2200 devices with firmware through 10.",
            "0.0.50 allows remote authenticated users to execute arbitrary OS c",
            "ommands"
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-6627",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the UDP processing code of Cisco IOS and IOS XE",
            " could allow an unauthenticated, remote attacker to cause the inpu",
            "t queue of an affected system to hold UDP packets, causing an inte",
            "rface queue wedge and denial of service."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6663",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Autonomic Networking feature of Cisco IOS S",
            "oftware and Cisco IOS XE Software could allow an unauthenticated, ",
            "adjacent attacker to cause autonomic nodes of an affected system t",
            "o reload, resulting in denial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6736",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6737",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6738",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6739",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code on an affected sy",
            "stem or cause an affected system to reload."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6740",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code on an affected sy",
            "stem or cause an affected system to reload."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6742",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code on an affected sy",
            "stem or cause an affected system to reload."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6743",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS and IOS XE contains a vulnerability that could allow an authent",
            "icated, remote attacker to remotely execute code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6744",
        vendor: "Cisco",
        product: "IOS software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Simple Network Management Protocol (SNMP) subsystem of Cisco I",
            "OS 1 contains a vulnerability that could allow an authenticated, r",
            "emote attacker to remotely execute code on an affected system or c",
            "ause an affected system to reload. An attacker could exploit these",
            " vulnerabilities by sending a crafted SNMP packet to an "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6862",
        vendor: "NETGEAR",
        product: "Multiple Devices",
        cpe23: "cpe:2.3:a:netgear:multiple_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple NETGEAR devices contain a buffer overflow vulnerability t",
            "hat allows for authentication bypass and remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-6884",
        vendor: "Zyxel",
        product: "EMG2926 Routers",
        cpe23: "cpe:2.3:a:zyxel:emg2926_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Zyxel EMG2926 routers contain a command injection vulnerability lo",
            "cated in the diagnostic tools, specifically the nslookup function.",
            " A malicious user may exploit numerous vectors to execute maliciou",
            "s commands on the router, such as the ping_ip parameter to the exp",
            "ert/maintenance/diagnostic/nslookup URI."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-7269",
        vendor: "Microsoft",
        product: "Internet Information Services (IIS)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:internet_information_services_iis:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Server 2003 R2 contains a buffer overflow vulner",
            "ability in Internet Information Services (IIS) 6.0 which allows re",
            "mote attackers to execute code via a long header beginning with \"",
            "If: <http://\" in a PROPFIND request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-7494",
        vendor: "Samba",
        product: "Samba",
        cpe23: "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Samba contains a remote code execution vulnerability, allowing a m",
            "alicious client to upload a shared library to a writable share and",
            " then cause the server to load and execute it."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-7921",
        vendor: "Hikvision",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:hikvision:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Hikvision products contain an improper authentication vul",
            "nerability that could allow a malicious user to escalate privilege",
            "s on the system and gain access to sensitive information."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2017-8291",
        vendor: "Artifex",
        product: "Ghostscript",
        cpe23: "cpe:2.3:a:artifex:ghostscript:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Artifex Ghostscript allows -dSAFER bypass and remote command execu",
            "tion via .rsdparams type confusion with a \"/OutputFile."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-8464",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Windows Shell in multiple versions of Microsoft Windows allows loc",
            "al users or remote attackers to execute arbitrary code via a craft",
            "ed .LNK file"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-8540",
        vendor: "Microsoft",
        product: "Malware Protection Engine",
        cpe23: "cpe:2.3:a:microsoft:malware_protection_engine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Microsoft Malware Protection Engine running on Microsoft Foref",
            "ront and Microsoft Defender on Microsoft Windows Server 2008 SP2 a",
            "nd R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold an",
            "d R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and W",
            "indows Server 2016, Microsoft Exchange Server 2013 and 2"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-8543",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows allows an attacker to take control of the affect",
            "ed system when Windows Search fails to handle objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-8570",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in Microsoft Office s",
            "oftware when it fails to properly handle objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-8759",
        vendor: "Microsoft",
        product: ".NET Framework",
        cpe23: "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft .NET Framework contains a remote code execution vulnerab",
            "ility when processing untrusted input that could allow an attacker",
            " to take control of an affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-9248",
        vendor: "Progress",
        product: "ASP.NET AJAX and Sitefinity",
        cpe23: "cpe:2.3:a:progress:asp.net_ajax_and_sitefinity:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Progress Telerik UI for ASP.NET AJAX and Sitefinity have a cryptog",
            "raphic weakness in Telerik.Web.UI.dll that can be exploited to dis",
            "close encryption keys (Telerik.Web.UI.DialogParametersEncryptionKe",
            "y and/or the MachineKey), perform cross-site-scripting (XSS) attac",
            "ks, compromise the ASP.NET ViewState, and/or upload and "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-9791",
        vendor: "Apache",
        product: "Struts 1",
        cpe23: "cpe:2.3:a:apache:struts_1:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Struts 1 plugin in Apache Struts might allow remote code execu",
            "tion via a malicious field value passed in a raw message to the Ac",
            "tionMessage."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-9805",
        vendor: "Apache",
        product: "Struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Struts REST Plugin uses an XStreamHandler with an instance ",
            "of XStream for deserialization without any type filtering, which c",
            "an lead to remote code execution when deserializing XML payloads."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-9822",
        vendor: "DotNetNuke (DNN)",
        product: "DotNetNuke (DNN)",
        cpe23: "cpe:2.3:a:dotnetnuke_dnn:dotnetnuke_dnn:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "DotNetNuke (DNN) contains a vulnerability that may allow for remot",
            "e code execution via cookie deserialization."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2017-9841",
        vendor: "PHPUnit",
        product: "PHPUnit",
        cpe23: "cpe:2.3:a:phpunit:phpunit:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PHPUnit allows remote attackers to execute arbitrary PHP code via ",
            "HTTP POST data beginning with a \"<?php \" substring, as demonstra",
            "ted by an attack on a site with an exposed /vendor folder, i.e., e",
            "xternal access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-st",
            "din.php URI."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0125",
        vendor: "Cisco",
        product: "VPN Routers",
        cpe23: "cpe:2.3:a:cisco:vpn_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the web interface of the Cisco VPN Routers coul",
            "d allow an unauthenticated, remote attacker to execute arbitrary c",
            "ode as root and gain full control of an affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0147",
        vendor: "Cisco",
        product: "Secure Access Control System (ACS)",
        cpe23: "cpe:2.3:a:cisco:secure_access_control_system_acs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in Java deserialization used by Cisco Secure Acces",
            "s Control System (ACS) could allow an unauthenticated, remote atta",
            "cker to execute arbitrary commands on an affected device. The vuln",
            "erability is due to insecure deserialization of user-supplied cont",
            "ent by the affected software."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0151",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the quality of service (QoS) subsystem of Cisco",
            " IOS Software and Cisco IOS XE Software could allow an unauthentic",
            "ated, remote attacker to cause a denial of service (DoS) condition",
            " or execute arbitrary code with elevated privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0154",
        vendor: "Cisco",
        product: "IOS Software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the crypto engine of the Cisco Integrated Servi",
            "ces Module for VPN (ISM-VPN) running Cisco IOS Software could allo",
            "w an unauthenticated, remote attacker to cause a denial-of-service",
            " (DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0155",
        vendor: "Cisco",
        product: concat!(
            "Catalyst 4500 Series Switches and Cisco Catalyst 4500-X Series Swi",
            "tches"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:catalyst_4500_series_switches_and_cisco_catalyst_4",
            "500-x_series_switches:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Bidirectional Forwarding Detection (BFD) of",
            "fload implementation of Cisco Catalyst 4500 Series Switches and Ci",
            "sco Catalyst 4500-X Series Switches could allow an unauthenticated",
            ", remote attacker to cause a crash of the iosd process, causing a ",
            "denial-of-service (DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0156",
        vendor: "Cisco",
        product: "IOS Software and Cisco IOS XE Software",
        cpe23: concat!(
            "cpe:2.3:a:cisco:ios_software_and_cisco_ios_xe_software:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Smart Install feature of Cisco IOS Software",
            " and Cisco IOS XE Software could allow an unauthenticated, remote ",
            "attacker to trigger a reload of an affected device, resulting in a",
            " denial-of-service (DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0158",
        vendor: "Cisco",
        product: "IOS Software and Cisco IOS XE Software",
        cpe23: concat!(
            "cpe:2.3:a:cisco:ios_software_and_cisco_ios_xe_software:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the implementation of Internet Key Exchange Ver",
            "sion 1 (IKEv1) functionality in Cisco IOS Software and Cisco IOS X",
            "E Software could allow an unauthenticated, remote attacker to caus",
            "e an affected device to reload, resulting in a denial-of-service (",
            "DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0159",
        vendor: "Cisco",
        product: "IOS Software and Cisco IOS XE Software",
        cpe23: concat!(
            "cpe:2.3:a:cisco:ios_software_and_cisco_ios_xe_software:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the implementation of Internet Key Exchange Ver",
            "sion 1 (IKEv1) functionality in Cisco IOS Software and Cisco IOS X",
            "E Software could allow an unauthenticated, remote attacker to caus",
            "e an affected device to reload, resulting in a denial-of-service (",
            "DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0161",
        vendor: "Cisco",
        product: "IOS Software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Simple Network Management Protocol (SNMP) s",
            "ubsystem of Cisco IOS Software running on certain models of Cisco ",
            "Catalyst Switches could allow an authenticated, remote attacker to",
            " cause a denial-of-service (DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0167",
        vendor: "Cisco",
        product: "IOS, XR, and XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_xr_and_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "There is a buffer overflow vulnerability in the Link Layer Discove",
            "ry Protocol (LLDP) subsystem of Cisco IOS Software, Cisco IOS XE S",
            "oftware, and Cisco IOS XR Software which could allow an unauthenti",
            "cated, adjacent attacker to cause a denial of service (DoS) condit",
            "ion or execute arbitrary code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0171",
        vendor: "Cisco",
        product: "IOS and IOS XE",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS and IOS XE Software improperly validates packet data, al",
            "lowing an unauthenticated, remote attacker to trigger a reload of ",
            "an affected device, cause a denial-of-service (DoS) condition, or ",
            "perform code execution on the affected device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0172",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the DHCP option 82 encapsulation functionality ",
            "of Cisco IOS Software and Cisco IOS XE Software could allow for de",
            "nial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0173",
        vendor: "Cisco",
        product: "IOS and IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_and_ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Cisco IOS Software and Cisco IOS XE Softwar",
            "e function that restores encapsulated option 82 information in DHC",
            "P Version 4 (DHCPv4) packets can allow for denial-of-service (DoS)",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0174",
        vendor: "Cisco",
        product: "IOS XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the DHCP option 82 encapsulation functionality ",
            "of Cisco IOS Software and Cisco IOS XE Software could allow for de",
            "nial-of-service (DoS)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0175",
        vendor: "Cisco",
        product: "IOS, XR, and XE Software",
        cpe23: "cpe:2.3:a:cisco:ios_xr_and_xe_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Format string vulnerability in the Link Layer Discovery Protocol (",
            "LLDP) subsystem of Cisco IOS Software, Cisco IOS XE Software, and ",
            "Cisco IOS XR Software could allow an unauthenticated, adjacent att",
            "acker to cause a denial of service (DoS) condition or execute arbi",
            "trary code with elevated privileges on an affected devic"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0179",
        vendor: "Cisco",
        product: "IOS Software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Login Enhancements (Login Block) feature of",
            " Cisco IOS Software could allow an unauthenticated, remote attacke",
            "r to trigger a reload of an affected system, resulting in a denial",
            " of service (DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0180",
        vendor: "Cisco",
        product: "IOS Software",
        cpe23: "cpe:2.3:a:cisco:ios_software:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the Login Enhancements (Login Block) feature of",
            " Cisco IOS Software could allow an unauthenticated, remote attacke",
            "r to trigger a reload of an affected system, resulting in a denial",
            " of service (DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0296",
        vendor: "Cisco",
        product: "Adaptive Security Appliance (ASA)",
        cpe23: "cpe:2.3:a:cisco:adaptive_security_appliance_asa:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) contains an improper input",
            " validation vulnerability with HTTP URLs. Exploitation could allow",
            " an attacker to cause a denial-of-service (DoS) condition or infor",
            "mation disclosure."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0798",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Office contains a memory corruption vulnerability due to",
            " the way objects are handled in memory. Successful exploitation al",
            "lows for remote code execution in the context of the current user.",
            " This vulnerability is known to be chained with CVE-2018-0802."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0802",
        vendor: "Microsoft",
        product: "Office",
        cpe23: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Office contains a memory corruption vulnerability due to",
            " the way objects are handled in memory. Successful exploitation al",
            "lows for remote code execution in the context of the current user.",
            " This vulnerability is known to be chained with CVE-2018-0798."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-0824",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft COM for Windows contains a deserialization of untrusted ",
            "data vulnerability that allows for privilege escalation and remote",
            " code execution via a specially crafted file or script."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-1000861",
        vendor: "Jenkins",
        product: "Jenkins Stapler Web Framework",
        cpe23: "cpe:2.3:a:jenkins:jenkins_stapler_web_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A code execution vulnerability exists in the Stapler web framework",
            " used by Jenkins"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-10561",
        vendor: "Dasan",
        product: "Gigabit Passive Optical Network (GPON) Routers",
        cpe23: concat!(
            "cpe:2.3:a:dasan:gigabit_passive_optical_network_gpon_routers:*:*:*",
            ":*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Dasan GPON Routers contain an authentication bypass vulnerability.",
            " When combined with CVE-2018-10562, exploitation can allow an atta",
            "cker to perform remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-10562",
        vendor: "Dasan",
        product: "Gigabit Passive Optical Network (GPON) Routers",
        cpe23: concat!(
            "cpe:2.3:a:dasan:gigabit_passive_optical_network_gpon_routers:*:*:*",
            ":*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Dasan GPON Routers contain an authentication bypass vulnerability.",
            " When combined with CVE-2018-10561, exploitation can allow an atta",
            "cker to perform remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-11138",
        vendor: "Quest",
        product: "KACE System Management Appliance",
        cpe23: "cpe:2.3:a:quest:kace_system_management_appliance:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The '/common/download_agent_installer.php' script in the Quest KAC",
            "E System Management Appliance is accessible by anonymous users and",
            " can be abused to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-11776",
        vendor: "Apache",
        product: "Struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Struts contains a vulnerability that allows for remote code",
            " execution under two circumstances. One, where the alwaysSelectFul",
            "lNamespace option is true and the value isn't set for a result def",
            "ined in underlying configurations and in same time, its upper pack",
            "age configuration have no or wildcard namespace.  Or, us"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-1273",
        vendor: "VMware Tanzu",
        product: "Spring Data Commons",
        cpe23: "cpe:2.3:a:vmware_tanzu:spring_data_commons:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-94",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Spring Data Commons contains a property binder vulnerability which",
            " can allow an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-13374",
        vendor: "Fortinet",
        product: "FortiOS and FortiADC",
        cpe23: "cpe:2.3:a:fortinet:fortios_and_fortiadc:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS and FortiADC contain an improper access control v",
            "ulnerability that allows attackers to obtain the LDAP server login",
            " credentials configured in FortiGate by pointing a LDAP server con",
            "nectivity test request to a rogue LDAP server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-13379",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS SSL VPN web portal contains a path traversal vuln",
            "erability that may allow an unauthenticated attacker to download F",
            "ortiOS system files through specially crafted HTTP resource reques",
            "ts."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-13382",
        vendor: "Fortinet",
        product: "FortiOS and FortiProxy",
        cpe23: "cpe:2.3:a:fortinet:fortios_and_fortiproxy:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An Improper Authorization vulnerability in Fortinet FortiOS and Fo",
            "rtiProxy under SSL VPN web portal allows an unauthenticated attack",
            "er to modify the password."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-13383",
        vendor: "Fortinet",
        product: "FortiOS and FortiProxy",
        cpe23: "cpe:2.3:a:fortinet:fortios_and_fortiproxy:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A heap buffer overflow in Fortinet FortiOS and FortiProxy may caus",
            "e the SSL VPN web service termination for logged in users."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-14558",
        vendor: "Tenda",
        product: "AC7, AC9, and AC10 Routers",
        cpe23: "cpe:2.3:a:tenda:ac7_ac9_and_ac10_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Tenda AC7, AC9, and AC10 devices contain a command injection vulne",
            "rability due to  the \"formsetUsbUnload\" function executes a dosy",
            "stemCmd function with untrusted input. Successful exploitation all",
            "ows an attacker to execute OS commands via a crafted goform/setUsb",
            "Unload request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-14634",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Linux Kernel contains an integer overflow vulnerability in the cre",
            "ate_elf_tables() function which could allow an unprivileged local ",
            "user with access to SUID (or otherwise privileged) binary to escal",
            "ate their privileges on the system."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-14667",
        vendor: "Red Hat",
        product: "JBoss RichFaces Framework",
        cpe23: "cpe:2.3:a:red_hat:jboss_richfaces_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Red Hat JBoss RichFaces Framework contains an expression language ",
            "injection vulnerability via the UserResource resource. A remote, u",
            "nauthenticated attacker could exploit this vulnerability to execut",
            "e malicious code using a chain of Java serialized objects via org.",
            "ajax4jsf.resource.UserResource$UriData."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-14839",
        vendor: "LG",
        product: "N1A1 NAS",
        cpe23: "cpe:2.3:a:lg:n1a1_nas:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "LG N1A1 NAS 3718.510 is affected by a remote code execution vulner",
            "ability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-14847",
        vendor: "MikroTik",
        product: "RouterOS",
        cpe23: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "MikroTik RouterOS through 6.42 allows unauthenticated remote attac",
            "kers to read arbitrary files and remote authenticated attackers to",
            " write arbitrary files due to a directory traversal vulnerability ",
            "in the WinBox interface."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-14933",
        vendor: "NUUO",
        product: "NVRmini Devices",
        cpe23: "cpe:2.3:a:nuuo:nvrmini_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "NUUO NVRmini devices contain an OS command injection vulnerability",
            ". This vulnerability allows remote command execution via shell met",
            "acharacters in the uploaddir parameter for a writeuploaddir comman",
            "d."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-15133",
        vendor: "Laravel",
        product: "Laravel Framework",
        cpe23: "cpe:2.3:a:laravel:laravel_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Laravel Framework contains a deserialization of untrusted data vul",
            "nerability, allowing for remote command execution. This vulnerabil",
            "ity may only be exploited if a malicious user has accessed the app",
            "lication encryption key (APP_KEY environment variable)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-15811",
        vendor: "DotNetNuke (DNN)",
        product: "DotNetNuke (DNN)",
        cpe23: "cpe:2.3:a:dotnetnuke_dnn:dotnetnuke_dnn:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "DotNetNuke (DNN) contains an inadequate encryption strength vulner",
            "ability resulting from the use of a weak encryption algorithm to p",
            "rotect input parameters."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-15961",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains an unrestricted file upload vulnerabilit",
            "y that could allow for code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-15982",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe Flash Player com.adobe.tvsdk.mediacore.metadata Use After Fr",
            "ee Vulnerability"
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-17463",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an unspecified vulnerability th",
            "at allows a remote attacker to execute code inside a sandbox via a",
            " crafted HTML page. This vulnerability could affect multiple web b",
            "rowsers that utilize Chromium, including, but not limited to, Goog",
            "le Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-17480",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains out-of-bounds write vulnerabili",
            "ty that allows a remote attacker to execute code inside a sandbox ",
            "via a crafted HTML page. This vulnerability could affect multiple ",
            "web browsers that utilize Chromium, including, but not limited to,",
            " Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-18325",
        vendor: "DotNetNuke (DNN)",
        product: "DotNetNuke (DNN)",
        cpe23: "cpe:2.3:a:dotnetnuke_dnn:dotnetnuke_dnn:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "DotNetNuke (DNN) contains an inadequate encryption strength vulner",
            "ability resulting from the use of a weak encryption algorithm to p",
            "rotect input parameters. This CVE ID resolves an incomplete patch ",
            "for CVE-2018-15811."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-18809",
        vendor: "TIBCO",
        product: "JasperReports",
        cpe23: "cpe:2.3:a:tibco:jasperreports:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TIBCO JasperReports Library contains a directory-traversal vulnera",
            "bility that may allow web server users to access contents of the h",
            "ost system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19320",
        vendor: "GIGABYTE",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:gigabyte:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The GDrv low-level driver in GIGABYTE App Center, AORUS Graphics E",
            "ngine, XTREME Gaming Engine, and OC GURU II exposes ring0 memcpy-l",
            "ike functionality that could allow a local attacker to take comple",
            "te control of the affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19321",
        vendor: "GIGABYTE",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:gigabyte:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The GPCIDrv and GDrv low-level drivers in GIGABYTE App Center, AOR",
            "US Graphics Engine, XTREME Gaming Engine, and OC GURU II expose fu",
            "nctionality to read and write arbitrary physical memory. This coul",
            "d be leveraged by a local attacker to elevate privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19322",
        vendor: "GIGABYTE",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:gigabyte:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The GPCIDrv and GDrv low-level drivers in GIGABYTE App Center, AOR",
            "US Graphics Engine, XTREME Gaming Engine, and OC GURU II expose fu",
            "nctionality to read/write data from/to IO ports. This could be lev",
            "eraged in a number of ways to ultimately run code with elevated pr",
            "ivileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19323",
        vendor: "GIGABYTE",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:gigabyte:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The GPCIDrv and GDrv low-level drivers in GIGABYTE App Center, AOR",
            "US Graphics Engine, XTREME Gaming Engine, and OC GURU expose funct",
            "ionality to read and write arbitrary physical memory. This could b",
            "e leveraged by a local attacker to elevate privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19410",
        vendor: "Paessler",
        product: "PRTG Network Monitor",
        cpe23: "cpe:2.3:a:paessler:prtg_network_monitor:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Paessler PRTG Network Monitor contains a local file inclusion vuln",
            "erability that allows a remote, unauthenticated attacker to create",
            " users with read-write privileges (including administrator)."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-19943",
        vendor: "QNAP",
        product: "Network Attached Storage (NAS)",
        cpe23: "cpe:2.3:a:qnap:network_attached_storage_nas:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-79",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A cross-site scripting vulnerability affecting QNAP NAS File Stati",
            "on could allow remote attackers to inject malicious code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19949",
        vendor: "QNAP",
        product: "Network Attached Storage (NAS)",
        cpe23: "cpe:2.3:a:qnap:network_attached_storage_nas:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A command injection vulnerability affecting QNAP NAS File Station ",
            "could allow remote attackers to run commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-19953",
        vendor: "QNAP",
        product: "Network Attached Storage (NAS)",
        cpe23: "cpe:2.3:a:qnap:network_attached_storage_nas:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-79",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A cross-site scripting vulnerability affecting QNAP NAS File Stati",
            "on could allow remote attackers to inject malicious code."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-20062",
        vendor: "ThinkPHP",
        product: "noneCms",
        cpe23: "cpe:2.3:a:thinkphp:nonecms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ThinkPHP \"noneCms\" contains an unspecified vulnerability that al",
            "lows for remote code execution through crafted use of the filter p",
            "arameter."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-20250",
        vendor: "RARLAB",
        product: "WinRAR",
        cpe23: "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "WinRAR Absolute Path Traversal vulnerability leads to Remote Code ",
            "Execution"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-20753",
        vendor: "Kaseya",
        product: "Virtual System/Server Administrator (VSA)",
        cpe23: concat!(
            "cpe:2.3:a:kaseya:virtual_system_server_administrator_vsa:*:*:*:*:*",
            ":*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Kaseya VSA RMM allows unprivileged remote attackers to execute Pow",
            "erShell payloads on all managed devices."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-2380",
        vendor: "SAP",
        product: "Customer Relationship Management (CRM)",
        cpe23: "cpe:2.3:a:sap:customer_relationship_management_crm:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SAP Customer Relationship Management (CRM) contains a path travers",
            "al vulnerability that allows an attacker to exploit insufficient v",
            "alidation of path information provided by users."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-2628",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server contains an unspecified vulnerability which",
            " can allow an unauthenticated attacker with T3 network access to c",
            "ompromise the server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-4063",
        vendor: "Sierra Wireless",
        product: "AirLink ALEOS",
        cpe23: "cpe:2.3:a:sierra_wireless:airlink_aleos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sierra Wireless AirLink ALEOS contains an unrestricted upload of f",
            "ile with dangerous type vulnerability. A specially crafted HTTP re",
            "quest can upload a file, resulting in executable code being upload",
            "ed, and routable, to the webserver. An attacker can make an authen",
            "ticated HTTP request to trigger this vulnerability. The "
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-4344",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, tvOS, and watchOS contain a memory corruption vu",
            "lnerability which can allow for code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-4878",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Adobe Flash Player contains a use-after-free vulnerability that co",
            "uld allow for code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-4939",
        vendor: "Adobe",
        product: "ColdFusion",
        cpe23: "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe ColdFusion contains a deserialization of untrusted data vuln",
            "erability that could allow for code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-4990",
        vendor: "Adobe",
        product: "Acrobat and Reader",
        cpe23: "cpe:2.3:a:adobe:acrobat_and_reader:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Acrobat and Reader have a double free vulnerability that cou",
            "ld lead to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-5002",
        vendor: "Adobe",
        product: "Flash Player",
        cpe23: "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Adobe Flash Player have a stack-based buffer overflow vulnerabilit",
            "y that could lead to remote code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-5430",
        vendor: "TIBCO",
        product: "JasperReports",
        cpe23: "cpe:2.3:a:tibco:jasperreports:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TIBCO JasperReports Server contain a vulnerability which may allow",
            " any authenticated user read-only access to the contents of the we",
            "b application, including key configuration files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-6065",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an integer overflow vulnerabili",
            "ty that allows a remote attacker to potentially exploit heap corru",
            "ption via a crafted HTML page. This vulnerability could affect mul",
            "tiple web browsers that utilize Chromium, including, but not limit",
            "ed to, Google Chrome, Microsoft Edge, and Opera."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-6530",
        vendor: "D-Link",
        product: "Multiple Routers",
        cpe23: "cpe:2.3:a:d-link:multiple_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Multiple D-Link routers contain an unspecified vulnerability that ",
            "allows for execution of OS commands."
        ),
        remediation: concat!(
            "The vendor D-Link published an advisory stating the fix under CVE-",
            "2018-20114 properly patches KEV entry CVE-2018-6530. If the device",
            " is still supported, apply updates per vendor instructions. If the",
            " affected device has since entered its end-of-life, it should "
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-6789",
        vendor: "Exim",
        product: "Exim",
        cpe23: "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Exim contains a buffer overflow vulnerability in the base64d funct",
            "ion part of the SMTP listener that may allow for remote code execu",
            "tion."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-6882",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-79",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scr",
            "ipting vulnerability that might allow remote attackers to inject a",
            "rbitrary web script or HTML."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-6961",
        vendor: "VMware",
        product: "SD-WAN Edge",
        cpe23: "cpe:2.3:a:vmware:sd-wan_edge:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware SD-WAN Edge by VeloCloud contains a command injection vulne",
            "rability in the local web UI component. Successful exploitation of",
            " this issue could result in remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-7445",
        vendor: "MikroTik",
        product: "RouterOS",
        cpe23: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "In MikroTik RouterOS, a stack-based buffer overflow occurs when pr",
            "ocessing NetBIOS session request messages. Remote attackers with a",
            "ccess to the service can exploit this vulnerability and gain code ",
            "execution on the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-7600",
        vendor: "Drupal",
        product: "Drupal Core",
        cpe23: "cpe:2.3:a:drupal:drupal_core:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Drupal Core contains a remote code execution vulnerability that co",
            "uld allow an attacker to exploit multiple attack vectors on a Drup",
            "al site, resulting in complete site compromise."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-7602",
        vendor: "Drupal",
        product: "Core",
        cpe23: "cpe:2.3:a:drupal:core:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A remote code execution vulnerability exists within multiple subsy",
            "stems of Drupal that can allow attackers to exploit multiple attac",
            "k vectors on a Drupal site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-7841",
        vendor: "Schneider Electric",
        product: "U.motion Builder",
        cpe23: "cpe:2.3:a:schneider_electric:u.motion_builder:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A SQL Injection vulnerability exists in U.motion Builder software ",
            "which could cause unwanted code execution when an improper set of ",
            "characters is entered."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-8120",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists in Windows when the Wi",
            "n32k component fails to properly handle objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8174",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A remote code execution vulnerability exists in the way that the V",
            "BScript engine handles objects in memory, aka \"Windows VBScript E",
            "ngine Remote Code Execution\""
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8298",
        vendor: "ChakraCore",
        product: "ChakraCore scripting engine",
        cpe23: "cpe:2.3:a:chakracore:chakracore_scripting_engine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The ChakraCore scripting engine contains a type confusion vulnerab",
            "ility which can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8373",
        vendor: "Microsoft",
        product: "Internet Explorer Scripting Engine",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:internet_explorer_scripting_engine:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in the way that the s",
            "cripting engine handles objects in memory in Internet Explorer."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8405",
        vendor: "Microsoft",
        product: "DirectX Graphics Kernel (DXGKRNL)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:directx_graphics_kernel_dxgkrnl:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An elevation of privilege vulnerability exists when the DirectX Gr",
            "aphics Kernel (DXGKRNL) driver improperly handles objects in memor",
            "y."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8406",
        vendor: "Microsoft",
        product: "DirectX Graphics Kernel (DXGKRNL)",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:directx_graphics_kernel_dxgkrnl:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An elevation of privilege vulnerability exists when the DirectX Gr",
            "aphics Kernel (DXGKRNL) driver improperly handles objects in memor",
            "y."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8414",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists when the Windows Shel",
            "l does not properly validate file paths."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8440",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An elevation of privilege vulnerability exists when Windows improp",
            "erly handles calls to Advanced Local Procedure Call (ALPC)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8453",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Win32k contains a vulnerability that allows an a",
            "ttacker to escalate privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8581",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists in Microsoft Exchange ",
            "Server. An attacker who successfully exploited this vulnerability ",
            "could attempt to impersonate any other user of the Exchange server",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8589",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows improperl",
            "y handles calls to Win32k.sys. An attacker who successfully exploi",
            "ted this vulnerability could run remote code in the security conte",
            "xt of the local system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8611",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows kerne",
            "l fails to properly handle objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-8639",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Win32k contains an improper resource shutdown or",
            " release vulnerability that allows for local, authenticated privil",
            "ege escalation. An attacker who successfully exploited this vulner",
            "ability could run arbitrary code in kernel mode."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2018-8653",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity due to how the Scripting Engine handles objects in memory, le",
            "ading to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2018-9276",
        vendor: "Paessler",
        product: "PRTG Network Monitor",
        cpe23: "cpe:2.3:a:paessler:prtg_network_monitor:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Paessler PRTG Network Monitor contains an OS command injection vul",
            "nerability that allows an attacker with administrative privileges ",
            "to execute commands via the PRTG System Administrator web console."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-0193",
        vendor: "Apache",
        product: "Solr",
        cpe23: "cpe:2.3:a:apache:solr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The optional Apache Solr module DataImportHandler contains a code ",
            "injection vulnerability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0211",
        vendor: "Apache",
        product: "HTTP Server",
        cpe23: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache HTTP Server, with MPM event, worker or prefork, code execut",
            "ing in less-privileged child processes or threads (including scrip",
            "ts executed by an in-process scripting interpreter) could execute ",
            "code with the privileges of the parent process (usually root) by m",
            "anipulating the scoreboard."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0344",
        vendor: "SAP",
        product: "Commerce Cloud",
        cpe23: "cpe:2.3:a:sap:commerce_cloud:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SAP Commerce Cloud (formerly known as Hybris) contains a deseriali",
            "zation of untrusted data vulnerability within the mediaconversion ",
            "and virtualjdbc extension that allows for code injection."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-0541",
        vendor: "Microsoft",
        product: "MSHTML",
        cpe23: "cpe:2.3:a:microsoft:mshtml:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft MSHTML engine contains an improper input validation vuln",
            "erability that allows for remote code execution vulnerability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0543",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows improperl",
            "y handles authentication requests. An attacker who successfully ex",
            "ploited this vulnerability could run processes in an elevated cont",
            "ext."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0604",
        vendor: "Microsoft",
        product: "SharePoint",
        cpe23: "cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SharePoint fails to check the source markup of an applic",
            "ation package. An attacker who successfully exploits the vulnerabi",
            "lity could run remote code in the context of the SharePoint applic",
            "ation pool and the SharePoint server farm account."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0676",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An information disclosure vulnerability exists when Internet Explo",
            "rer improperly handles objects in memory. An attacker who successf",
            "ully exploited this vulnerability could test for the presence of f",
            "iles on disk."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0703",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An information disclosure vulnerability exists in the way that the",
            " Windows SMB Server handles certain requests, which could lead to ",
            "information disclosure from the server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0708",
        vendor: "Microsoft",
        product: "Remote Desktop Services",
        cpe23: "cpe:2.3:a:microsoft:remote_desktop_services:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Remote Desktop Services, formerly known as Terminal Serv",
            "ice, contains an unspecified vulnerability that allows an unauthen",
            "ticated attacker to connect to the target system using RDP and sen",
            "d specially crafted requests. Successful exploitation allows for r",
            "emote code execution. The vulnerability is also known un"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0752",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A remote code execution vulnerability exists in the way that the s",
            "cripting engine handles objects in memory in Internet Explorer"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0797",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains a privilege escalation vulnerability whe",
            "n the Win32k component fails to properly handle objects in memory.",
            " Successful exploitation allows an attacker to execute code in ker",
            "nel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0803",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Win32k contains an unspecified vulnerability due to it f",
            "ailing to properly handle objects in memory causing privilege esca",
            "lation. Successful exploitation allows an attacker to run code in ",
            "kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0808",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains a privilege escalation vulnerability due",
            " to the component failing to properly handle objects in memory. Su",
            "ccessful exploitation allows an attacker to run code in kernel mod",
            "e."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0841",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows AppXSVC i",
            "mproperly handles hard links. An attacker who successfully exploit",
            "ed this vulnerability could run processes in an elevated context."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0859",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Win32k fails to properly handle objects in memory causin",
            "g privilege escalation. Successful exploitation allows an attacker",
            " to run code in kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0863",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Error Reporting (WER) contains a privilege escal",
            "ation vulnerability due to the way it handles files, allowing for ",
            "code execution in kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0880",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A local elevation of privilege vulnerability exists in how splwow6",
            "4.exe handles certain calls. An attacker who successfully exploite",
            "d the vulnerability could elevate privileges on an affected system",
            " from low-integrity to medium-integrity."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-0903",
        vendor: "Microsoft",
        product: "Graphics Device Interface (GDI)",
        cpe23: "cpe:2.3:a:microsoft:graphics_device_interface_gdi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in the way that the W",
            "indows Graphics Device Interface (GDI) handles objects in the memo",
            "ry. An attacker who successfully exploited this vulnerability coul",
            "d take control of the affected system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1003029",
        vendor: "Jenkins",
        product: "Script Security Plugin",
        cpe23: "cpe:2.3:a:jenkins:script_security_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Jenkins Script Security Plugin contains a protection mechanism fai",
            "lure, allowing an attacker to bypass the sandbox."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1003030",
        vendor: "Jenkins",
        product: "Matrix Project Plugin",
        cpe23: "cpe:2.3:a:jenkins:matrix_project_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Jenkins Matrix Project plugin contains a vulnerability which can a",
            "llow users to escape the sandbox, opening opportunity to perform r",
            "emote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-10068",
        vendor: "Kentico",
        product: "Xperience",
        cpe23: "cpe:2.3:a:kentico:xperience:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kentico contains a failure to validate security headers. This dese",
            "rialization can led to unauthenticated remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-10149",
        vendor: "Exim",
        product: "Mail Transfer Agent (MTA)",
        cpe23: "cpe:2.3:a:exim:mail_transfer_agent_mta:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Improper validation of recipient address in deliver_message() func",
            "tion in /src/deliver.c may lead to remote command execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1064",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows AppXSVC i",
            "mproperly handles hard links. An attacker who successfully exploit",
            "ed this vulnerability could run processes in an elevated context."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1068",
        vendor: "Microsoft",
        product: "SQL Server",
        cpe23: "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft SQL Server contains a remote code execution vulnerabilit",
            "y that could allow an attacker to execute code in the context of t",
            "he SQL Server Database Engine service account."
        ),
        remediation: concat!(
            "Apply mitigations in accordance with vendor instructions, ensuring",
            " compliance with CISA’s BOD 26-04 Prioritizing Security Updates Ba",
            "sed on Risk (see URL in Notes) guidance and CISA’s “Forensics Tria",
            "ge Requirements” (see URL in Notes). Follow applicable BOD 26-"
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-1069",
        vendor: "Microsoft",
        product: "Task Scheduler",
        cpe23: "cpe:2.3:a:microsoft:task_scheduler:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists in the way the Task Sc",
            "heduler Service validates certain file operations."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-10758",
        vendor: "MongoDB",
        product: "mongo-express",
        cpe23: "cpe:2.3:a:mongodb:mongo-express:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "mongo-express before 0.54.0 is vulnerable to Remote Code Execution",
            " via endpoints that uses the `toBSON` method."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11001",
        vendor: "Reolink",
        product: "Multiple IP Cameras",
        cpe23: "cpe:2.3:a:reolink:multiple_ip_cameras:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Reolink RLC-410W, C1 Pro, C2 Pro, RLC-422W, and RLC-511W IP camera",
            "s contain an authenticated OS command injection vulnerability. Thi",
            "s vulnerability allows an authenticated admin to use the \"TestEma",
            "il\" functionality to inject and run OS commands as root."
        ),
        remediation: concat!(
            "The impacted product could be end-of-life (EoL) and/or end-of-serv",
            "ice (EoS). Users should discontinue product utilization if a curre",
            "nt mitigation is unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-11043",
        vendor: "PHP",
        product: "FastCGI Process Manager (FPM)",
        cpe23: "cpe:2.3:a:php:fastcgi_process_manager_fpm:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "In some versions of PHP in certain configurations of FPM setup, it",
            " is possible to cause FPM module to write past allocated buffers a",
            "llowing the possibility of remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1129",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows AppXSVC i",
            "mproperly handles hard links. An attacker who successfully exploit",
            "ed this vulnerability could run processes in an elevated context."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1130",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows AppX Depl",
            "oyment Service (AppXSVC) improperly handles hard links."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1132",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A privilege escalation vulnerability exists in Windows when the Wi",
            "n32k component fails to properly handle objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11510",
        vendor: "Ivanti",
        product: "Pulse Connect Secure",
        cpe23: "cpe:2.3:a:ivanti:pulse_connect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Pulse Connect Secure contains an arbitrary file read vulner",
            "ability that allows an unauthenticated remote attacker with networ",
            "k access via HTTPS to send a specially crafted URI."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11539",
        vendor: "Ivanti",
        product: "Pulse Connect Secure and Pulse Policy Secure",
        cpe23: concat!(
            "cpe:2.3:a:ivanti:pulse_connect_secure_and_pulse_policy_secure:*:*:",
            "*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Ivanti Pulse Connect Secure and Policy Secure allows an authentica",
            "ted attacker from the admin web interface to inject and execute co",
            "mmands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11580",
        vendor: "Atlassian",
        product: "Crowd and Crowd Data Center",
        cpe23: "cpe:2.3:a:atlassian:crowd_and_crowd_data_center:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Atlassian Crowd and Crowd Data Center contain a remote code execut",
            "ion vulnerability resulting from a pdkinstall development plugin b",
            "eing incorrectly enabled in release builds."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11581",
        vendor: "Atlassian",
        product: "Jira Server and Data Center",
        cpe23: "cpe:2.3:a:atlassian:jira_server_and_data_center:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Atlassian Jira Server and Data Center contain a server-side templa",
            "te injection vulnerability which can allow for remote code executi",
            "on."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11634",
        vendor: "Citrix",
        product: "Workspace Application and Receiver for Windows",
        cpe23: concat!(
            "cpe:2.3:a:citrix:workspace_application_and_receiver_for_windows:*:",
            "*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Citrix Workspace Application and Receiver for Windows contains rem",
            "ote code execution vulnerability resulting from local drive access",
            " preferences not being enforced into the clients' local drives."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11707",
        vendor: "Mozilla",
        product: "Firefox and Thunderbird",
        cpe23: "cpe:2.3:a:mozilla:firefox_and_thunderbird:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox and Thunderbird contain a type confusion vulnerabi",
            "lity that can occur when manipulating JavaScript objects due to is",
            "sues in Array.pop, allowing for an exploitable crash."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-11708",
        vendor: "Mozilla",
        product: "Firefox and Thunderbird",
        cpe23: "cpe:2.3:a:mozilla:firefox_and_thunderbird:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox and Thunderbird contain a sandbox escape vulnerabi",
            "lity that could result in remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1214",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Common Log File System (CLFS) driver improperly ",
            "handles objects in memory which can allow for privilege escalation",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1215",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows contains an unspecified vulnerability due to the",
            " way ws2ifsl.sys (Winsock) handles objects in memory, allowing for",
            " privilege escalation. Successful exploitation allows an attacker ",
            "to execute code with elevated privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1253",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows AppX ",
            "Deployment Server improperly handles junctions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1297",
        vendor: "Microsoft",
        product: "Excel",
        cpe23: "cpe:2.3:a:microsoft:excel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in Microsoft Excel wh",
            "en the software fails to properly handle objects in memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-12989",
        vendor: "Citrix",
        product: "SD-WAN and NetScaler",
        cpe23: "cpe:2.3:a:citrix:sd-wan_and_netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Citrix SD-WAN and NetScaler SD-WAN allow SQL Injection.",
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-12991",
        vendor: "Citrix",
        product: "SD-WAN and NetScaler",
        cpe23: "cpe:2.3:a:citrix:sd-wan_and_netscaler:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Authenticated Command Injection in Citrix SD-WAN Appliance and Net",
            "Scaler SD-WAN Appliance."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1315",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows Error Rep",
            "orting manager improperly handles hard links. An attacker who succ",
            "essfully exploited this vulnerability could overwrite a targeted f",
            "ile leading to an elevated status."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1322",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when Windows improperl",
            "y handles authentication requests. An attacker who successfully ex",
            "ploited this vulnerability could run processes in an elevated cont",
            "ext."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-13272",
        vendor: "Linux",
        product: "Kernel",
        cpe23: "cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kernel/ptrace.c in Linux kernel mishandles contains an improper pr",
            "ivilege management vulnerability that allows local users to obtain",
            " root access."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-13608",
        vendor: "Citrix",
        product: "StoreFront Server",
        cpe23: "cpe:2.3:a:citrix:storefront_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Citrix StoreFront Server contains an XML External Entity (XXE) pro",
            "cessing vulnerability that may allow an unauthenticated attacker t",
            "o retrieve potentially sensitive information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1367",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity in how the scripting engine handles objects in memory. Succes",
            "sful exploitation allows for remote code execution in the context ",
            "of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-13720",
        vendor: "Google",
        product: "Chrome WebAudio",
        cpe23: "cpe:2.3:a:google:chrome_webaudio:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chrome WebAudio contains a use-after-free vulnerability tha",
            "t allows a remote attacker to potentially exploit heap corruption ",
            "via a crafted HTML page."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1385",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows AppX ",
            "Deployment Extensions improperly performs privilege management, re",
            "sulting in access to system files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1388",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows Certificate Dialog contains a privilege escalati",
            "on vulnerability, allowing attackers to run processes in an elevat",
            "ed context."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1405",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists when the Windows UPnP ",
            "service improperly allows COM object creation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1429",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity which can allow for remote code execution in the context of t",
            "he current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1458",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A privilege escalation vulnerability exists in Windows when the Wi",
            "n32k component fails to properly handle objects in memory, aka 'Wi",
            "n32k EoP."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-15107",
        vendor: "Webmin",
        product: "Webmin",
        cpe23: "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "An issue was discovered in Webmin. The parameter old in password_c",
            "hange.cgi contains a command injection vulnerability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-15271",
        vendor: "Cisco",
        product: "RV Series Routers",
        cpe23: "cpe:2.3:a:cisco:rv_series_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A deserialization of untrusted data vulnerability in the web-based",
            " management interface of certain Cisco Small Business RV Series Ro",
            "uters could allow an attacker to execute code with root privileges",
            "."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-15752",
        vendor: "Docker",
        product: "Desktop Community Edition",
        cpe23: "cpe:2.3:a:docker:desktop_community_edition:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Docker Desktop Community Edition contains a vulnerability that may",
            " allow local users to escalate privileges by placing a trojan hors",
            "e docker-credential-wincred.exe file in %PROGRAMDATA%\\DockerDeskt",
            "op\\version-bin\\."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1579",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Remote Code Execution in PAN-OS with GlobalProtect Portal or Globa",
            "lProtect Gateway Interface enabled."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-15949",
        vendor: "Nagios",
        product: "Nagios XI",
        cpe23: "cpe:2.3:a:nagios:nagios_xi:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Nagios XI contains a remote code execution vulnerability in which ",
            "a user can modify the check_plugin executable and insert malicious",
            " commands to execute as root."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-16057",
        vendor: "D-Link",
        product: "DNS-320 Storage Device",
        cpe23: "cpe:2.3:a:d-link:dns-320_storage_device:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-78",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "The login_mgr.cgi script in D-Link DNS-320 is vulnerable to remote",
            " code execution."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-16256",
        vendor: "SIMalliance",
        product: "Toolbox Browser",
        cpe23: "cpe:2.3:a:simalliance:toolbox_browser:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SIMalliance Toolbox Browser contains an command injection vulnerab",
            "ility that could allow remote attackers to retrieve location and I",
            "MEI information or execute a range of other attacks by modifying t",
            "he attack message."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-16278",
        vendor: "Nostromo",
        product: "nhttpd",
        cpe23: "cpe:2.3:a:nostromo:nhttpd:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Nostromo nhttpd contains a directory traversal vulnerability in th",
            "e http_verify() function in a non-chrooted nhttpd server allowing ",
            "for remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-1652",
        vendor: "Cisco",
        product: "Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv320_and_rv325_dual_gigabit_wan_vp",
            "n_routers:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in the web-based management interface of Cisco Sma",
            "ll Business RV320 and RV325 Dual Gigabit WAN VPN Routers could all",
            "ow an authenticated, remote attacker with administrative privilege",
            "s on an affected device to execute arbitrary commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-1653",
        vendor: "Cisco",
        product: "Small Business RV320 and RV325 Routers",
        cpe23: concat!(
            "cpe:2.3:a:cisco:small_business_rv320_and_rv325_routers:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers ",
            "contain improper access controls for URLs. Exploitation could allo",
            "w an attacker to download the router configuration or detailed dia",
            "gnostic information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-16759",
        vendor: "vBulletin",
        product: "vBulletin",
        cpe23: "cpe:2.3:a:vbulletin:vbulletin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The PHP module within vBulletin contains an unspecified vulnerabil",
            "ity that allows for remote code execution via the widgetConfig[cod",
            "e] parameter in an ajax/render/widget_php routestring request."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-16920",
        vendor: "D-Link",
        product: "Multiple Routers",
        cpe23: "cpe:2.3:a:d-link:multiple_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple D-Link routers contain a command injection vulnerability ",
            "which can allow attackers to achieve full system compromise."
        ),
        remediation: concat!(
            "The impacted product is end-of-life and should be disconnected if ",
            "still in use."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-16928",
        vendor: "Exim",
        product: "Exim Internet Mailer",
        cpe23: "cpe:2.3:a:exim:exim_internet_mailer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Exim contains an out-of-bounds write vulnerability which can allow",
            " for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-17026",
        vendor: "Mozilla",
        product: "Firefox and Thunderbird",
        cpe23: "cpe:2.3:a:mozilla:firefox_and_thunderbird:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Mozilla Firefox and Thunderbird contain a type confusion vulnerabi",
            "lity due to incorrect alias information in the IonMonkey JIT compi",
            "ler when setting array elements."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-17558",
        vendor: "Apache",
        product: "Solr",
        cpe23: "cpe:2.3:a:apache:solr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Apache Solr VelocityResponseWriter plug-in contains an unspeci",
            "fied vulnerability which can allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-17621",
        vendor: "D-Link",
        product: "DIR-859 Router",
        cpe23: "cpe:2.3:a:d-link:dir-859_router:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-859 router contains a command execution vulnerability i",
            "n the UPnP endpoint URL, /gena.cgi. Exploitation allows an unauthe",
            "nticated remote attacker to execute system commands as root by sen",
            "ding a specially crafted HTTP SUBSCRIBE request to the UPnP servic",
            "e when connecting to the local network."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-18187",
        vendor: "Trend Micro",
        product: "OfficeScan",
        cpe23: "cpe:2.3:a:trend_micro:officescan:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro OfficeScan contains a directory traversal vulnerabilit",
            "y by extracting files from a zip file to a specific folder on the ",
            "OfficeScan server, leading to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-18426",
        vendor: "Meta Platforms",
        product: "WhatsApp",
        cpe23: "cpe:2.3:a:meta_platforms:whatsapp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A vulnerability in WhatsApp Desktop when paired with WhatsApp for ",
            "iPhone allows cross-site scripting and local file reading."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-18935",
        vendor: "Progress",
        product: "Telerik UI for ASP.NET AJAX",
        cpe23: "cpe:2.3:a:progress:telerik_ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Progress Telerik UI for ASP.NET AJAX contains a deserialization of",
            " untrusted data vulnerability through RadAsyncUpload which leads t",
            "o code execution on the server in the context of the w3wp.exe proc",
            "ess."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-18988",
        vendor: "TeamViewer",
        product: "Desktop",
        cpe23: "cpe:2.3:a:teamviewer:desktop:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TeamViewer Desktop allows for bypass of remote-login access contro",
            "l because the same AES key is used for different customers' instal",
            "lations. If an attacker were to know this key, they could decrypt ",
            "protected information stored in registry or configuration files or",
            " decryption of the Unattended Access password to the sys"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-19006",
        vendor: "Sangoma",
        product: "FreePBX",
        cpe23: "cpe:2.3:a:sangoma:freepbx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sangoma FreePBX contains an improper authentication vulnerability ",
            "that potentially allows unauthorized users to bypass password auth",
            "entication and access services provided by the FreePBX admin."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-19356",
        vendor: "Netis",
        product: "WF2419 Devices",
        cpe23: "cpe:2.3:a:netis:wf2419_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Netis WF2419 devices contains an unspecified vulnerability that al",
            "lows an attacker to perform remote code execution as root through ",
            "the router's web management page."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-19781",
        vendor: "Citrix",
        product: concat!(
            "Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP A",
            "ppliance"
        ),
        cpe23: concat!(
            "cpe:2.3:a:citrix:application_delivery_controller_adc_gateway_and_s",
            "d-wan_wanop_appliance:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Citrix ADC, Citrix Gateway, and multiple Citrix SD-WAN WANOP appli",
            "ance models contain an unspecified vulnerability that could allow ",
            "an unauthenticated attacker to perform code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-20085",
        vendor: "TVT",
        product: "NVMS-1000",
        cpe23: "cpe:2.3:a:tvt:nvms-1000:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TVT devices utilizing NVMS-1000 software contain a directory trave",
            "rsal vulnerability via GET /.. requests."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-20500",
        vendor: "D-Link",
        product: "DWL-2600AP Access Point",
        cpe23: "cpe:2.3:a:d-link:dwl-2600ap_access_point:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DWL-2600AP access point contains an authenticated command i",
            "njection vulnerability via the Save Configuration functionality in",
            " the Web interface, using shell metacharacters in the admin.cgi?ac",
            "tion=config_save configBackup or downloadServerip parameter."
        ),
        remediation: concat!(
            "Apply updates per vendor instructions or discontinue use of the pr",
            "oduct if updates are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-2215",
        vendor: "Android",
        product: "Android Kernel",
        cpe23: "cpe:2.3:a:android:android_kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Kernel contains a use-after-free vulnerability in binder.c",
            " that allows for privilege escalation from an application to the L",
            "inux Kernel. This vulnerability was observed chained with CVE-2020",
            "-0041 and CVE-2020-0069 under exploit chain \"AbstractEmu.\""
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-2616",
        vendor: "Oracle",
        product: "BI Publisher (Formerly XML Publisher)",
        cpe23: concat!(
            "cpe:2.3:a:oracle:bi_publisher_formerly_xml_publisher:*:*:*:*:*:*:*",
            ":*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle BI Publisher, formerly XML Publisher, contains an unspecifi",
            "ed vulnerability that allows for various unauthorized actions. Ope",
            "n-source reporting attributes this vulnerability to allowing for a",
            "uthentication bypass."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-2725",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Injection vulnerability in the Oracle WebLogic Server component of",
            " Oracle Fusion Middleware (subcomponent: Web Services)."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-3010",
        vendor: "Oracle",
        product: "Solaris",
        cpe23: "cpe:2.3:a:oracle:solaris:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Solaris component: XScreenSaver contains an unspecified vul",
            "nerability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-3396",
        vendor: "Atlassian",
        product: "Confluence Server and Data Server",
        cpe23: concat!(
            "cpe:2.3:a:atlassian:confluence_server_and_data_server:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Atlassian Confluence Server and Data Center contain a server-side ",
            "template injection vulnerability that may allow an attacker to ach",
            "ieve path traversal and remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-3398",
        vendor: "Atlassian",
        product: "Confluence Server and Data Center",
        cpe23: concat!(
            "cpe:2.3:a:atlassian:confluence_server_and_data_center:*:*:*:*:*:*:",
            "*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Atlassian Confluence Server and Data Center contain a path travers",
            "al vulnerability in the downloadallattachments resource that may a",
            "llow a privileged, remote attacker to write files. Exploitation ca",
            "n lead to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-3568",
        vendor: "Meta Platforms",
        product: "WhatsApp",
        cpe23: "cpe:2.3:a:meta_platforms:whatsapp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A buffer overflow vulnerability in WhatsApp VOIP stack allowed rem",
            "ote code execution via specially crafted series of RTCP packets se",
            "nt to a target phone number."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-3929",
        vendor: "Crestron",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:crestron:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Crestron products are vulnerable to command injection via",
            " the file_transfer.cgi HTTP endpoint. A remote, unauthenticated at",
            "tacker can use this vulnerability to execute operating system comm",
            "ands as root."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-4716",
        vendor: "IBM",
        product: "Planning Analytics",
        cpe23: "cpe:2.3:a:ibm:planning_analytics:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "IBM Planning Analytics is vulnerable to a configuration overwrite ",
            "that allows an unauthenticated user to login as \"admin\", and the",
            "n execute code as root or SYSTEM via TM1 scripting."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-5418",
        vendor: "Rails",
        product: "Ruby on Rails",
        cpe23: "cpe:2.3:a:rails:ruby_on_rails:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Rails Ruby on Rails contains a path traversal vulnerability in Act",
            "ion View. Specially crafted accept headers in combination with cal",
            "ls to `render file:` can cause arbitrary files on the target serve",
            "r to be rendered, disclosing the file contents."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-5544",
        vendor: "VMware",
        product: "VMware ESXi and Horizon DaaS",
        cpe23: "cpe:2.3:a:vmware:vmware_esxi_and_horizon_daas:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "VMware ESXi and Horizon Desktop as a Service (DaaS) OpenSLP contai",
            "ns a heap-based buffer overflow vulnerability that allows an attac",
            "ker with network access to port 427 to overwrite the heap of the O",
            "penSLP service to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-5591",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-306",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS contains a default configuration vulnerability th",
            "at may allow an unauthenticated attacker on the same subnet to int",
            "ercept sensitive information by impersonating the Lightweight Dire",
            "ctory Access Protocol (LDAP) server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-5786",
        vendor: "Google",
        product: "Chrome Blink",
        cpe23: "cpe:2.3:a:google:chrome_blink:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chrome Blink contains a heap use-after-free vulnerability t",
            "hat allows an attacker to potentially perform out of bounds memory",
            " access via a crafted HTML page."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-5825",
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
        cve_id: "CVE-2019-6223",
        vendor: "Apple",
        product: "iOS and macOS",
        cpe23: "cpe:2.3:a:apple:ios_and_macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS and macOS Group FaceTime contains an unspecified vulnera",
            "bility where the call initiator can cause the recipient's Apple de",
            "vice to answer unknowingly or without user interaction."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-6340",
        vendor: "Drupal",
        product: "Core",
        cpe23: "cpe:2.3:a:drupal:core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "In Drupal Core, some field types do not properly sanitize data fro",
            "m non-form sources. This can lead to arbitrary PHP code execution ",
            "in some cases."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-6693",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-798",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS contains a use of hard-coded credentials vulnerab",
            "ility that could allow an attacker to cipher sensitive data in For",
            "tiOS configuration backup file via knowledge of the hard-coded key",
            "."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-7192",
        vendor: "QNAP",
        product: "Photo Station",
        cpe23: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "QNAP NAS devices running Photo Station contain an improper access ",
            "control vulnerability allowing remote attackers to gain unauthoriz",
            "ed access to the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7193",
        vendor: "QNAP",
        product: "QTS",
        cpe23: "cpe:2.3:a:qnap:qts:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "QNAP QTS contains an improper input validation vulnerability allow",
            "ing remote attackers to inject code on the system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7194",
        vendor: "QNAP",
        product: "Photo Station",
        cpe23: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "QNAP devices running Photo Station contain an external control of ",
            "file name or path vulnerability allowing remote attackers to acces",
            "s or modify system files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7195",
        vendor: "QNAP",
        product: "Photo Station",
        cpe23: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-22",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "QNAP devices running Photo Station contain an external control of ",
            "file name or path vulnerability allowing remote attackers to acces",
            "s or modify system files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7238",
        vendor: "Sonatype",
        product: "Nexus Repository Manager",
        cpe23: "cpe:2.3:a:sonatype:nexus_repository_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sonatype Nexus Repository Manager before 3.15.0 has an incorrect a",
            "ccess control vulnerability. Exploitation allows for remote code e",
            "xecution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7256",
        vendor: "Nice",
        product: "Linear eMerge E3-Series",
        cpe23: "cpe:2.3:a:nice:linear_emerge_e3-series:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Nice Linear eMerge E3-Series contains an OS command injection vuln",
            "erability that allows an attacker to conduct remote code execution",
            "."
        ),
        remediation: concat!(
            "Contact the vendor for guidance on remediating firmware, per their",
            " advisory."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-7286",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, macOS, watchOS, and tvOS contain a memory corruption vu",
            "lnerability that could allow for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7287",
        vendor: "Apple",
        product: "iOS",
        cpe23: "cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS contains a memory corruption vulnerability which could a",
            "llow an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7481",
        vendor: "SonicWall",
        product: "SMA100",
        cpe23: "cpe:2.3:a:sonicwall:sma100:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "SonicWall SMA100 contains a SQL injection vulnerability allowing a",
            "n unauthenticated user to gain read-only access to unauthorized re",
            "sources."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7483",
        vendor: "SonicWall",
        product: "SMA100",
        cpe23: "cpe:2.3:a:sonicwall:sma100:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "In SonicWall SMA100, an unauthenticated Directory Traversal vulner",
            "ability in the handleWAFRedirect CGI allows the user to test for t",
            "he presence of a file on the server."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-7609",
        vendor: "Elastic",
        product: "Kibana",
        cpe23: "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-94",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Kibana contain an arbitrary code execution flaw in the Timelion vi",
            "sualizer."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-8331",
        vendor: "npm",
        product: "bootstrap",
        cpe23: "cpe:2.3:a:npm:bootstrap:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "npm bootstrap vulnerability advisory",
        remediation: "Upgrade bootstrap to >= 4.3.1",
    },
    KevCveRecord {
        cve_id: "CVE-2019-8394",
        vendor: "Zoho",
        product: "ManageEngine",
        cpe23: "cpe:2.3:a:zoho:manageengine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho ManageEngine ServiceDesk Plus (SDP) contains an unspecified v",
            "ulnerability that allows remote users to upload files via login pa",
            "ge customization."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-8506",
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
        cve_id: "CVE-2019-8526",
        vendor: "Apple",
        product: "macOS",
        cpe23: "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple macOS contains a use-after-free vulnerability that could all",
            "ow for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-8605",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A use-after-free vulnerability in Apple iOS, macOS, tvOS, and watc",
            "hOS could allow a malicious application to execute code with syste",
            "m privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-8720",
        vendor: "WebKitGTK",
        product: "WebKitGTK",
        cpe23: "cpe:2.3:a:webkitgtk:webkitgtk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WebKitGTK contains a memory corruption vulnerability which can all",
            "ow an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-9082",
        vendor: "ThinkPHP",
        product: "ThinkPHP",
        cpe23: "cpe:2.3:a:thinkphp:thinkphp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "ThinkPHP contains an unspecified vulnerability that allows for rem",
            "ote code execution via public//?s=index/\\think\\app/invokefunctio",
            "n&function=call_user_func_array&vars[0]=system&vars[1][]= followed",
            " by the command."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-9621",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-918",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains a server-side re",
            "quest forgery (SSRF) vulnerability via the ProxyServlet component."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-9670",
        vendor: "Synacor",
        product: "Zimbra Collaboration Suite (ZCS)",
        cpe23: "cpe:2.3:a:synacor:zimbra_collaboration_suite_zcs:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Synacor Zimbra Collaboration Suite (ZCS) contains an improper rest",
            "riction of XML external entity (XXE) vulnerability in the mailboxd",
            " component."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2019-9874",
        vendor: "Sitecore",
        product: "CMS and Experience Platform (XP)",
        cpe23: "cpe:2.3:a:sitecore:cms_and_experience_platform_xp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sitecore CMS and Experience Platform (XP) contain a deserializatio",
            "n vulnerability in the Sitecore.Security.AntiCSRF module that allo",
            "ws an unauthenticated attacker to execute arbitrary code by sendin",
            "g a serialized .NET object in the HTTP POST parameter __CSRFTOKEN."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-9875",
        vendor: "Sitecore",
        product: "CMS and Experience Platform (XP)",
        cpe23: "cpe:2.3:a:sitecore:cms_and_experience_platform_xp:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sitecore CMS and Experience Platform (XP) contain a deserializatio",
            "n vulnerability in the Sitecore.Security.AntiCSRF module that allo",
            "ws an authenticated attacker to execute arbitrary code by sending ",
            "a serialized .NET object in the HTTP POST parameter __CSRFTOKEN."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2019-9978",
        vendor: "WordPress",
        product: "Social Warfare Plugin",
        cpe23: "cpe:2.3:a:wordpress:social_warfare_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress Social Warfare plugin contains a cross-site scripting (X",
            "SS) vulnerability that allows for remote code execution. This vuln",
            "erability affects Social Warfare and Social Warfare Pro."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0041",
        vendor: "Android",
        product: "Android Kernel",
        cpe23: "cpe:2.3:a:android:android_kernel:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Android Kernel binder_transaction of binder.c contains an out-of-b",
            "ounds write vulnerability due to an incorrect bounds check that co",
            "uld allow for local privilege escalation. This vulnerability was o",
            "bserved chained with CVE-2019-2215 and CVE-2020-0069 under exploit",
            " chain \"AbstractEmu.\""
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0069",
        vendor: "MediaTek",
        product: "Multiple Chipsets",
        cpe23: "cpe:2.3:a:mediatek:multiple_chipsets:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple MediaTek chipsets contain an insufficient input validatio",
            "n vulnerability and have missing SELinux restrictions in the Comma",
            "nd Queue drivers ioctl handlers. This causes an out-of-bounds writ",
            "e leading to privilege escalation. This vulnerability was observed",
            " chained with CVE-2019-2215 and CVE-2020-0041 under expl"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0601",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows CryptoAPI (Crypt32.dll) contains a spoofing vuln",
            "erability in the way it validates Elliptic Curve Cryptography (ECC",
            ") certificates. An attacker could exploit the vulnerability by usi",
            "ng a spoofed code-signing certificate to sign a malicious executab",
            "le, making it appear the file was from a trusted, legiti"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0618",
        vendor: "Microsoft",
        product: "SQL Server",
        cpe23: "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-502",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft SQL Server Reporting Services contains a deserialization",
            " vulnerability when handling page requests incorrectly. An authent",
            "icated attacker can exploit this vulnerability to execute code in ",
            "the context of the Report Server service account."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-0638",
        vendor: "Microsoft",
        product: "Update Notification Manager",
        cpe23: "cpe:2.3:a:microsoft:update_notification_manager:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Update Notification Manager contains an unspecified vuln",
            "erability that allows for privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0646",
        vendor: "Microsoft",
        product: ".NET Framework",
        cpe23: "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft .NET Framework contains an improper input validation vul",
            "nerability that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0674",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity due to the way the Scripting Engine handles objects in memory",
            ". Successful exploitation could allow remote code execution in the",
            " context of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0683",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Installer contains a privilege escalation vulner",
            "ability when MSI packages process symbolic links, which allows att",
            "ackers to bypass access restrictions to add or remove files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0688",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Exchange Server Validation Key fails to properly create ",
            "unique keys at install time, allowing for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0787",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-284",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Windows BITS is vulnerable to to a privilege elevation v",
            "ulnerability if it improperly handles symbolic links. An actor can",
            " exploit this vulnerability to execute arbitrary code with system-",
            "level privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0796",
        vendor: "Microsoft",
        product: "SMBv3",
        cpe23: "cpe:2.3:a:microsoft:smbv3:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "A remote code execution vulnerability exists in the way that the M",
            "icrosoft Server Message Block 3.1.1 (SMBv3) protocol handles certa",
            "in requests. An attacker who successfully exploited the vulnerabil",
            "ity could gain the ability to execute code on the target server or",
            " client."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0878",
        vendor: "Microsoft",
        product: "Edge and Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:edge_and_internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Edge and Internet Explorer contain a memory corruption v",
            "ulnerability that allows attackers to execute code in the context ",
            "of the current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0938",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Adobe Font Manager Library contains an unspecifi",
            "ed vulnerability when handling specially crafted multi-master font",
            "s (Adobe Type 1 PostScript format) that allows for remote code exe",
            "cution for all systems except Windows 10. For systems running Wind",
            "ows 10, an attacker who successfully exploited the vulne"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0968",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity due to how the Scripting Engine handles objects in memory, le",
            "ading to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-0986",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows kernel contains an unspecified vulnerability whe",
            "n handling objects in memory that allows attackers to escalate pri",
            "vileges and execute code in kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-10148",
        vendor: "SolarWinds",
        product: "Orion",
        cpe23: "cpe:2.3:a:solarwinds:orion:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-287",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SolarWinds Orion API contains an authentication bypass vulnerabili",
            "ty that could allow a remote attacker to execute API commands."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-10181",
        vendor: "Sumavision",
        product: "Enhanced Multimedia Router (EMR)",
        cpe23: concat!(
            "cpe:2.3:a:sumavision:enhanced_multimedia_router_emr:*:*:*:*:*:*:*:",
            "*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sumavision Enhanced Multimedia Router (EMR) contains a cross-site ",
            "request forgery (CSRF) vulnerability allowing the creation of user",
            "s with elevated privileges as administrator on a device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-10189",
        vendor: "Zoho",
        product: "ManageEngine",
        cpe23: "cpe:2.3:a:zoho:manageengine:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zoho ManageEngine Desktop Central contains a file upload vulnerabi",
            "lity that allows for unauthenticated remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-10199",
        vendor: "Sonatype",
        product: "Nexus Repository",
        cpe23: "cpe:2.3:a:sonatype:nexus_repository:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sonatype Nexus Repository contains an unspecified vulnerability th",
            "at allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1020",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows Adobe Font Manager Library contains an unspecifi",
            "ed vulnerability when handling specially crafted multi-master font",
            "s (Adobe Type 1 PostScript format) that allows for remote code exe",
            "cution for all systems except Windows 10. For systems running Wind",
            "ows 10, an attacker who successfully exploited the vulne"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-10221",
        vendor: "rConfig",
        product: "rConfig",
        cpe23: "cpe:2.3:a:rconfig:rconfig:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "rConfig lib/ajaxHandlers/ajaxAddTemplate.php contains an OS comman",
            "d injection vulnerability that allows remote attackers to execute ",
            "OS commands via shell metacharacters in the fileName POST paramete",
            "r."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1027",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "An elevation of privilege vulnerability exists in the way that the",
            " Windows Kernel handles objects in memory. An attacker who success",
            "fully exploited the vulnerability could execute code with elevated",
            " permissions."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1040",
        vendor: "Microsoft",
        product: "Hyper-V RemoteFX",
        cpe23: "cpe:2.3:a:microsoft:hyper-v_remotefx:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Hyper-V RemoteFX vGPU contains an improper input validat",
            "ion vulnerability due to the host server failing to properly valid",
            "ate input from an authenticated user on a guest operating system. ",
            "Successful exploitation allows for remote code execution on the ho",
            "st operating system."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1054",
        vendor: "Microsoft",
        product: "Win32k",
        cpe23: "cpe:2.3:a:microsoft:win32k:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Win32k contains a privilege escalation vulnerability whe",
            "n the Windows kernel-mode driver fails to properly handle objects ",
            "in memory. Successful exploitation allows an attacker to execute c",
            "ode in kernel mode."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-10987",
        vendor: "Tenda",
        product: "AC1900 Router AC15 Model",
        cpe23: "cpe:2.3:a:tenda:ac1900_router_ac15_model:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Tenda AC1900 Router AC15 Model contains an unspecified vulnerabili",
            "ty that allows remote attackers to execute system commands via the",
            " deviceName POST parameter."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11022",
        vendor: "jquery",
        product: "jquery",
        cpe23: "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-79",
        is_kev: false, ransomware: "Unknown", epss_permille: 250,
        summary: "Outdated jQuery (< 3.5.0) DOM HTML Prefilter Advisory",
        remediation: "Frontend jQuery kutubxonasini 3.7.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11023",
        vendor: "jquery",
        product: "jquery",
        cpe23: "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
        cvss_x10: 61, severity: "Medium", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: "Outdated jQuery (< 3.5.0) DOM HTML Prefilter Advisory",
        remediation: "Frontend jQuery kutubxonasini 3.7.1+ versiyasiga yangilang.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11261",
        vendor: "Qualcomm",
        product: concat!(
            "Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snap",
            "dragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile,",
            " Snapdragon Voice & Music, Snapdragon Wearables"
        ),
        cpe23: concat!(
            "cpe:2.3:a:qualcomm:snapdragon_auto_snapdragon_compute_snapdragon_c",
            "onnectivity_snapdragon_consumer_iot_snapdragon_industrial_iot_snap",
            "dragon_mobile_snapdragon_voice_music_snapdragon_wearables:*:*:*:*:",
            "*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Memory corruption due to improper check to return error when user ",
            "application requests memory allocation of a huge size in Snapdrago",
            "n Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Co",
            "nsumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdrag",
            "on Voice & Music, Snapdragon Wearables"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1147",
        vendor: "Microsoft",
        product: ".NET Framework, SharePoint, Visual Studio",
        cpe23: concat!(
            "cpe:2.3:a:microsoft:.net_framework_sharepoint_visual_studio:*:*:*:",
            "*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft .NET Framework, Microsoft SharePoint, and Visual Studio ",
            "contain a remote code execution vulnerability when the software fa",
            "ils to check the source markup of XML file input. Successful explo",
            "itation allows an attacker to execute code in the context of the p",
            "rocess responsible for deserialization of the XML conten"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11651",
        vendor: "SaltStack",
        product: "Salt",
        cpe23: "cpe:2.3:a:saltstack:salt:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SaltStack Salt contains an authentication bypass vulnerability in ",
            "the salt-master process ClearFuncs due to improperly validating me",
            "thod calls. The vulnerability allows a remote user to access some ",
            "methods without authentication, which can be used to retrieve user",
            " tokens from the salt master and/or run commands on salt"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11652",
        vendor: "SaltStack",
        product: "Salt",
        cpe23: "cpe:2.3:a:saltstack:salt:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SaltStack Salt contains a path traversal vulnerability in the salt",
            "-master process ClearFuncs which allows directory access to authen",
            "ticated users. Salt users who follow fundamental internet security",
            " guidelines and best practices are not affected by this vulnerabil",
            "ity."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11738",
        vendor: "WordPress",
        product: "Snap Creek Duplicator Plugin",
        cpe23: "cpe:2.3:a:wordpress:snap_creek_duplicator_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress Snap Creek Duplicator plugin contains a file download vu",
            "lnerability when an administrator creates a new copy of their site",
            " that allows an attacker to download the generated files from thei",
            "r Wordpress dashboard. This vulnerability affects Duplicator and D",
            "ulplicator Pro."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11899",
        vendor: "Treck TCP/IP stack",
        product: "IPv6",
        cpe23: "cpe:2.3:a:treck_tcp_ip_stack:ipv6:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The Treck TCP/IP stack contains an IPv6 out-of-bounds read vulnera",
            "bility."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-11978",
        vendor: "Apache",
        product: "Airflow",
        cpe23: "cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code/command injection vulnerability was discovered in on",
            "e of the example DAGs shipped with Airflow."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-12271",
        vendor: "Sophos",
        product: "SFOS",
        cpe23: "cpe:2.3:a:sophos:sfos:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Sophos Firewall operating system (SFOS) firmware contains a SQL in",
            "jection vulnerability when configured with either the administrati",
            "on (HTTPS) service or the User Portal is exposed on the WAN zone. ",
            "Successful exploitation may cause remote code execution to exfiltr",
            "ate usernames and hashed passwords for the local device "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-12641",
        vendor: "Roundcube",
        product: "Roundcube Webmail",
        cpe23: "cpe:2.3:a:roundcube:roundcube_webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail contains an remote code execution vulnerability ",
            "that allows attackers to execute code via shell metacharacters in ",
            "a configuration setting for im_convert_path or im_identify_path."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-12812",
        vendor: "Fortinet",
        product: "FortiOS",
        cpe23: "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-287",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Fortinet FortiOS SSL VPN contains an improper authentication vulne",
            "rability that may allow a user to login successfully without being",
            " prompted for the second factor of authentication (FortiToken) if ",
            "they change the case in their username."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1350",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows DNS Servers fail to properly handle requests, al",
            "lowing an attacker to perform remote code execution in the context",
            " of the Local System Account. The vulnerability is also known unde",
            "r the moniker of SIGRed."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-13671",
        vendor: "Drupal",
        product: "Drupal core",
        cpe23: "cpe:2.3:a:drupal:drupal_core:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Improper sanitization in the extension file names is present in Dr",
            "upal core."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1380",
        vendor: "Microsoft",
        product: "Internet Explorer",
        cpe23: "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Internet Explorer contains a memory corruption vulnerabi",
            "lity which can allow for remote code execution in the context of t",
            "he current user."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-13927",
        vendor: "Apache",
        product: "Airflow's Experimental API",
        cpe23: "cpe:2.3:a:apache:airflow_s_experimental_api:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The previous default setting for Airflow's Experimental API was to",
            " allow all API requests without authentication."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-13965",
        vendor: "Roundcube",
        product: "Webmail",
        cpe23: "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail contains a cross-site scripting (XSS) vulnerabil",
            "ity that allows a remote attacker to manipulate data via a malicio",
            "us XML attachment."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-14145",
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
        cve_id: "CVE-2020-14343",
        vendor: "pypi",
        product: "pyyaml",
        cpe23: "cpe:2.3:a:pypi:pyyaml:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "PyPI pyyaml vulnerability advisory",
        remediation: "Upgrade pyyaml to >= 5.4.0",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1464",
        vendor: "Microsoft",
        product: "Windows",
        cpe23: "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Windows contains a spoofing vulnerability when Windows i",
            "ncorrectly validates file signatures, allowing an attacker to bypa",
            "ss security features and load improperly signed files."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-14644",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server, a product within the Fusion Middleware sui",
            "te, contains a deserialization vulnerability. Unauthenticated atta",
            "ckers with network access via T3 or IIOP can exploit this vulnerab",
            "ility to achieve remote code execution."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-1472",
        vendor: "Microsoft",
        product: "Netlogon",
        cpe23: "cpe:2.3:a:microsoft:netlogon:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Microsoft's Netlogon Remote Protocol (MS-NRPC) contains a privileg",
            "e escalation vulnerability when an attacker establishes a vulnerab",
            "le Netlogon secure channel connection to a domain controller. An a",
            "ttacker who successfully exploits the vulnerability could run a sp",
            "ecially crafted application on a device on the network. "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-14750",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server contains an unspecified vulnerability allow",
            "ing an unauthenticated attacker to perform remote code execution. ",
            "This vulnerability is related to CVE-2020-14882."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-14864",
        vendor: "Oracle",
        product: "Intelligence Enterprise Edition",
        cpe23: "cpe:2.3:a:oracle:intelligence_enterprise_edition:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Path traversal vulnerability, where an attacker can target the pre",
            "view FilePath parameter of the getPreviewImage function to get acc",
            "ess to arbitrary system file."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-14871",
        vendor: "Oracle",
        product: "Solaris and Zettabyte File System (ZFS)",
        cpe23: concat!(
            "cpe:2.3:a:oracle:solaris_and_zettabyte_file_system_zfs:*:*:*:*:*:*",
            ":*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Solaris and Oracle ZFS Storage Appliance Kit contain an uns",
            "pecified vulnerability causing high impacts to confidentiality, in",
            "tegrity, and availability of affected systems."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-14882",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server contains an unspecified vulnerability, whic",
            "h is assessed to allow for remote code execution, based on this vu",
            "lnerability being related to CVE-2020-14750."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-14883",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server contains an unspecified vulnerability in th",
            "e Console component with high impacts to confidentilaity, integrit",
            "y, and availability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-15069",
        vendor: "Sophos",
        product: "XG Firewall",
        cpe23: "cpe:2.3:a:sophos:xg_firewall:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Sophos XG Firewall contains a buffer overflow vulnerability that a",
            "llows for remote code execution via the \"HTTP/S bookmark\" featur",
            "e."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-15415",
        vendor: "DrayTek",
        product: "Multiple Vigor Routers",
        cpe23: "cpe:2.3:a:draytek:multiple_vigor_routers:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "DrayTek Vigor3900, Vigor2960, and Vigor300B devices contain an OS ",
            "command injection vulnerability in cgi-bin/mainfunction.cgi/cvmcfg",
            "upload that allows for remote code execution via shell metacharact",
            "ers in a filename when the text/x-python-script content type is us",
            "ed."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-15505",
        vendor: "Ivanti",
        product: "MobileIron Multiple Products",
        cpe23: "cpe:2.3:a:ivanti:mobileiron_multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Ivanti MobileIron's Core & Connector, Sentry, and Monitor and Repo",
            "rting Database (RDB) products contain an unspecified vulnerability",
            " that allows for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-15999",
        vendor: "Google",
        product: "Chrome FreeType",
        cpe23: "cpe:2.3:a:google:chrome_freetype:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chrome uses FreeType, an open-source software library to re",
            "nder fonts, which contains a heap buffer overflow vulnerability in",
            " the function Load_SBit_Png when processing PNG images embedded in",
            "to fonts. This vulnerability is part of an exploit chain with CVE-",
            "2020-17087 on Windows and CVE-2020-16010 on Android."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-16009",
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
        cve_id: "CVE-2020-16010",
        vendor: "Google",
        product: "Chrome for Android UI",
        cpe23: "cpe:2.3:a:google:chrome_for_android_ui:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chrome for Android UI contains a heap buffer overflow vulne",
            "rability that allows a remote attacker, who has compromised the re",
            "nderer process, to potentially perform a sandbox escape via a craf",
            "ted HTML page."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-16013",
        vendor: "Google",
        product: "Chromium V8",
        cpe23: "cpe:2.3:a:google:chromium_v8:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chromium V8 Engine contains an inappropriate implementation",
            " vulnerability that allows a remote attacker to potentially exploi",
            "t heap corruption via a crafted HTML page. This vulnerability coul",
            "d affect multiple web browsers that utilize Chromium, including, b",
            "ut not limited to, Google Chrome, Microsoft Edge, and Op"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-16017",
        vendor: "Google",
        product: "Chrome",
        cpe23: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Google Chrome contains a use-after-free vulnerability that allows ",
            "a remote attacker, who has compromised the renderer process, to po",
            "tentially perform a sandbox escape via a crafted HTML page."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1631",
        vendor: "Juniper",
        product: "Junos OS",
        cpe23: "cpe:2.3:a:juniper:junos_os:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A path traversal vulnerability in the HTTP/HTTPS service used by J",
            "-Web, Web Authentication, Dynamic-VPN (DVPN), Firewall Authenticat",
            "ion Pass-Through with Web-Redirect, and Zero Touch Provisioning (Z",
            "TP) allows an unauthenticated attacker to perform remote code exec",
            "ution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-16846",
        vendor: "SaltStack",
        product: "Salt",
        cpe23: "cpe:2.3:a:saltstack:salt:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "SaltStack Salt allows an unauthenticated user with network access ",
            "to the Salt API to use shell injections to run code on the Salt AP",
            "I using the SSH client. This vulnerability affects any users runni",
            "ng the Salt API."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-17087",
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
        cve_id: "CVE-2020-17144",
        vendor: "Microsoft",
        product: "Exchange Server",
        cpe23: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Microsoft Exchange Server improperly validates cmdlet arguments wh",
            "ich allow an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-17463",
        vendor: "Fuel CMS",
        product: "Fuel CMS",
        cpe23: "cpe:2.3:a:fuel_cms:fuel_cms:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-89",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "FUEL CMS 1.4.7 allows SQL Injection via the col parameter to /page",
            "s/items, /permissions/items, or /navigation/items."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-17496",
        vendor: "vBulletin",
        product: "vBulletin",
        cpe23: "cpe:2.3:a:vbulletin:vbulletin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "The PHP module within vBulletin contains an unspecified vulnerabil",
            "ity that allows for remote code execution via crafted subWidgets d",
            "ata in an ajax/render/widget_tabbedcontainer_tab_panel request. Th",
            "is CVE ID resolves an incomplete patch for CVE-2019-16759."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-17519",
        vendor: "Apache",
        product: "Flink",
        cpe23: "cpe:2.3:a:apache:flink:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Flink contains an improper access control vulnerability tha",
            "t allows an attacker to read any file on the local filesystem of t",
            "he JobManager through its REST interface."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-17530",
        vendor: "Apache",
        product: "Struts",
        cpe23: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Forced Object-Graph Navigation Language (OGNL) evaluation in Apach",
            "e Struts, when evaluated on raw user input in tag attributes, can ",
            "lead to remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1938",
        vendor: "Apache",
        product: "Tomcat",
        cpe23: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Tomcat treats Apache JServ Protocol (AJP) connections as ha",
            "ving higher trust than, for example, a similar HTTP connection. If",
            " such connections are available to an attacker, they can be exploi",
            "ted."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1956",
        vendor: "Apache",
        product: "Kylin",
        cpe23: "cpe:2.3:a:apache:kylin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apache Kylin contains an OS command injection vulnerability which ",
            "could permit an attacker to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-1957",
        vendor: "maven",
        product: "org.apache.shiro:shiro-core",
        cpe23: "cpe:2.3:a:maven:org.apache.shiro_shiro-core:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Maven org.apache.shiro:shiro-core vulnerability advisory",
        remediation: "Upgrade org.apache.shiro:shiro-core to >= 1.6.0",
    },
    KevCveRecord {
        cve_id: "CVE-2020-2021",
        vendor: "Palo Alto Networks",
        product: "PAN-OS",
        cpe23: "cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Palo Alto Networks PAN-OS contains a vulnerability in SAML which a",
            "llows an attacker to bypass authentication."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-24363",
        vendor: "TP-Link",
        product: "TL-WA855RE",
        cpe23: "cpe:2.3:a:tp-link:tl-wa855re:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "TP-link TL-WA855RE contains a missing authentication for critical ",
            "function vulnerability. This vulnerability could allow an unauthen",
            "ticated attacker (on the same network) to submit a TDDP_RESET POST",
            " request for a factory reset and reboot. The attacker can then obt",
            "ain incorrect access control by setting a new administra"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-24557",
        vendor: "Trend Micro",
        product: "Apex One, OfficeScan, and Worry-Free Business Security",
        cpe23: concat!(
            "cpe:2.3:a:trend_micro:apex_one_officescan_and_worry-free_business_",
            "security:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Trend Micro Apex One, OfficeScan, and Worry-Free Business Security",
            " on Microsoft Windows contain an improper access control vulnerabi",
            "lity that may allow an attacker to manipulate a particular product",
            " folder to disable the security temporarily, abuse a specific Wind",
            "ows function, and attain privilege escalation."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-2506",
        vendor: "QNAP Systems",
        product: "Helpdesk",
        cpe23: "cpe:2.3:a:qnap_systems:helpdesk:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "QNAP Helpdesk contains an improper access control vulnerability wh",
            "ich could allow an attacker to gain privileges or to read sensitiv",
            "e information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-25078",
        vendor: "D-Link",
        product: "DCS-2530L and DCS-2670L Devices",
        cpe23: "cpe:2.3:a:d-link:dcs-2530l_and_dcs-2670l_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DCS-2530L and DCS-2670L devices contains an unspecified vul",
            "nerability that could allow for remote administrator password disc",
            "losure. The impacted products could be end-of-life (EoL) and/or en",
            "d-of-service (EoS). Users should discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-25079",
        vendor: "D-Link",
        product: "DCS-2530L and DCS-2670L Devices",
        cpe23: "cpe:2.3:a:d-link:dcs-2530l_and_dcs-2670l_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DCS-2530L and DCS-2670L devices contains a command injectio",
            "n vulnerability in the cgi-bin/ddns_enc.cgi. The impacted products",
            " could be end-of-life (EoL) and/or end-of-service (EoS). Users sho",
            "uld discontinue product utilization."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions, follow applicable BOD 2",
            "2-01 guidance for cloud services, or discontinue use of the produc",
            "t if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-2509",
        vendor: "QNAP",
        product: "QNAP Network-Attached Storage (NAS)",
        cpe23: "cpe:2.3:a:qnap:qnap_network-attached_storage_nas:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "QNAP NAS devices contain a command injection vulnerability which c",
            "ould allow attackers to perform remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-25213",
        vendor: "WordPress",
        product: "File Manager Plugin",
        cpe23: "cpe:2.3:a:wordpress:file_manager_plugin:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "WordPress File Manager plugin contains a remote code execution vul",
            "nerability that allows unauthenticated users to execute PHP code a",
            "nd upload malicious files on a target site."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-25223",
        vendor: "Sophos",
        product: "SG UTM",
        cpe23: "cpe:2.3:a:sophos:sg_utm:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "A remote code execution vulnerability exists in the WebAdmin of So",
            "phos SG UTM."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-25506",
        vendor: "D-Link",
        product: "DNS-320 Device",
        cpe23: "cpe:2.3:a:d-link:dns-320_device:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-78",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DNS-320 device contains a command injection vulnerability i",
            "n the sytem_mgr.cgi component that may allow for remote code execu",
            "tion."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-2551",
        vendor: "Oracle",
        product: "Fusion Middleware",
        cpe23: "cpe:2.3:a:oracle:fusion_middleware:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle Fusion Middleware contains an unspecified vulnerability in ",
            "the WLS Core Components that allows an unauthenticated attacker wi",
            "th network access via IIOP to compromise the WebLogic Server."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-2555",
        vendor: "Oracle",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:oracle:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-502",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Multiple Oracle products contain a remote code execution vulnerabi",
            "lity that allows an unauthenticated attacker with network access v",
            "ia T3 or HTTP to takeover the affected system. Impacted Oracle pro",
            "ducts: Oracle Coherence in Fusion Middleware, Oracle Utilities Fra",
            "mework, Oracle Retail Assortment Planning, Oracle Commer"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-26160",
        vendor: "go",
        product: "github.com/golang-jwt/jwt",
        cpe23: "cpe:2.3:a:go:github.com_golang-jwt_jwt:*:*:*:*:*:*:*:*",
        cvss_x10: 75, severity: "High", cwe: "CWE-1104",
        is_kev: false, ransomware: "Unknown", epss_permille: 200,
        summary: "Go github.com/golang-jwt/jwt vulnerability advisory",
        remediation: "Upgrade github.com/golang-jwt/jwt to >= 3.2.2",
    },
    KevCveRecord {
        cve_id: "CVE-2020-26919",
        vendor: "NETGEAR",
        product: "JGS516PE Devices",
        cpe23: "cpe:2.3:a:netgear:jgs516pe_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Netgear JGS516PE devices contain a missing function level access c",
            "ontrol vulnerability."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-27930",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS FontParser contain a memory ",
            "corruption vulnerability which may allow for code execution when p",
            "rocessing maliciously crafted front."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-27932",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS contain a type confusion vul",
            "nerability that may allow a malicious application to execute code ",
            "with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-27950",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, and watchOS contain a memory initializat",
            "ion vulnerability that may allow a malicious application to disclo",
            "se kernel memory."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-2883",
        vendor: "Oracle",
        product: "WebLogic Server",
        cpe23: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Oracle WebLogic Server, a product within the Fusion Middleware sui",
            "te, contains an unspecified vulnerability exploitable by an unauth",
            "enticated attacker with network access via IIOP or T3."
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-28949",
        vendor: "PEAR",
        product: "Archive_Tar",
        cpe23: "cpe:2.3:a:pear:archive_tar:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PEAR Archive_Tar allows an unserialization attack because phar: is",
            " blocked but PHAR: is not blocked. PEAR stands for PHP Extension a",
            "nd Application Repository and it is an open-source framework and d",
            "istribution system for reusable PHP components with known usage in",
            " third-party products such as Drupal Core and Red Hat Li"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-29557",
        vendor: "D-Link",
        product: "DIR-825 R1 Devices",
        cpe23: "cpe:2.3:a:d-link:dir-825_r1_devices:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "D-Link DIR-825 R1 devices contain a buffer overflow vulnerability ",
            "in the web interface that may allow for remote code execution."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-29574",
        vendor: "Sophos",
        product: "CyberoamOS",
        cpe23: "cpe:2.3:a:sophos:cyberoamos:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-89",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "CyberoamOS (CROS) contains a SQL injection vulnerability in the We",
            "bAdmin that allows an unauthenticated attacker to execute arbitrar",
            "y SQL statements remotely."
        ),
        remediation: concat!(
            "The impacted product is end-of-life (EoL) and/or end-of-service (E",
            "oS). Users should discontinue utilization of the product."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-29583",
        vendor: "Zyxel",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:zyxel:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Zyxel firewalls (ATP, USG, VM) and AP Controllers (NXC2500 and NXC",
            "5500) contain a use of hard-coded credentials vulnerability in an ",
            "undocumented account (\"zyfwp\") with an unchangeable password."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3118",
        vendor: "Cisco",
        product: "IOS XR",
        cpe23: "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XR improperly validates string input from certain fields",
            " in Cisco Discovery Protocol messages. Exploitation could allow an",
            " unauthenticated, adjacent attacker to execute code with administr",
            "ative privileges or cause a reload on an affected device."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3153",
        vendor: "Cisco",
        product: "AnyConnect Secure",
        cpe23: "cpe:2.3:a:cisco:anyconnect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco AnyConnect Secure Mobility Client for Windows allows for inc",
            "orrect handling of directory paths. An attacker with valid credent",
            "ials on Windows would be able to copy malicious files to arbitrary",
            " locations with system level privileges. This could include DLL pr",
            "e-loading, DLL hijacking, and other related attacks."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3161",
        vendor: "Cisco",
        product: "Cisco IP Phones",
        cpe23: "cpe:2.3:a:cisco:cisco_ip_phones:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IP Phones contain an improper input validation vulnerability",
            " for HTTP requests. Exploitation could allow an attacker to execut",
            "e code remotely with root privileges or cause a denial-of-service ",
            "(DoS) condition."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3259",
        vendor: "Cisco",
        product: concat!(
            "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FT",
            "D)"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:adaptive_security_appliance_asa_and_firepower_thre",
            "at_defense_ftd:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-200",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defen",
            "se (FTD) contain an information disclosure vulnerability. An attac",
            "ker could retrieve memory contents on an affected device, which co",
            "uld lead to the disclosure of confidential information due to a bu",
            "ffer tracking issue when the software parses invalid URL"
        ),
        remediation: concat!(
            "Apply mitigations per vendor instructions or discontinue use of th",
            "e product if mitigations are unavailable."
        ),
    },
    KevCveRecord {
        cve_id: "CVE-2020-3433",
        vendor: "Cisco",
        product: "AnyConnect Secure",
        cpe23: "cpe:2.3:a:cisco:anyconnect_secure:*:*:*:*:*:*:*:*",
        cvss_x10: 98, severity: "Critical", cwe: "CWE-1104",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco AnyConnect Secure Mobility Client for Windows interprocess c",
            "ommunication (IPC) channel allows for insufficient validation of r",
            "esources that are loaded by the application at run time. An attack",
            "er with valid credentials on Windows could execute code on the aff",
            "ected machine with SYSTEM privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3452",
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
            "se (FTD) contain an improper input validation vulnerability when H",
            "TTP requests process URLs.  An attacker could exploit this vulnera",
            "bility by sending a crafted HTTP request containing directory trav",
            "ersal character sequences to an affected device. A succe"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3566",
        vendor: "Cisco",
        product: "IOS XR",
        cpe23: "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XR Distance Vector Multicast Routing Protocol (DVMRP) in",
            "correctly handles Internet Group Management Protocol (IGMP) packet",
            "s. Exploitation could allow an unauthenticated, remote attacker to",
            " immediately crash the IGMP process or make it consume available m",
            "emory and eventually crash."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3569",
        vendor: "Cisco",
        product: "IOS XR",
        cpe23: "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Cisco IOS XR Distance Vector Multicast Routing Protocol (DVMRP) in",
            "correctly handles Internet Group Management Protocol (IGMP) packet",
            "s. Exploitation could allow an unauthenticated, remote attacker to",
            " immediately crash the IGMP process or make it consume available m",
            "emory and eventually crash."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-35730",
        vendor: "Roundcube",
        product: "Roundcube Webmail",
        cpe23: "cpe:2.3:a:roundcube:roundcube_webmail:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-79",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Roundcube Webmail contains a cross-site scripting (XSS) vulnerabil",
            "ity that allows an attacker to send a plain text e-mail message wi",
            "th Javascript in a link reference element that is mishandled by li",
            "nkref_addinindex in rcube_string_replacer.php."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3580",
        vendor: "Cisco",
        product: concat!(
            "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FT",
            "D)"
        ),
        cpe23: concat!(
            "cpe:2.3:a:cisco:adaptive_security_appliance_asa_and_firepower_thre",
            "at_defense_ftd:*:*:*:*:*:*:*:*"
        ),
        cvss_x10: 98, severity: "Critical", cwe: "CWE-79",
        is_kev: true, ransomware: "Known", epss_permille: 850,
        summary: concat!(
            "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defen",
            "se (FTD) contain an insufficient input validation vulnerability fo",
            "r user-supplied input by the web services interface.  Successful e",
            "xploitation could allow an attacker to perform cross-site scriptin",
            "g (XSS) in the context of the interface or access sensit"
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-36193",
        vendor: "PEAR",
        product: "Archive_Tar",
        cpe23: "cpe:2.3:a:pear:archive_tar:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-22",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "PEAR Archive_Tar Tar.php allows write operations with directory tr",
            "aversal due to inadequate checking of symbolic links. PEAR stands ",
            "for PHP Extension and Application Repository and it is an open-sou",
            "rce framework and distribution system for reusable PHP components ",
            "with known usage in third-party products such as Drupal "
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3837",
        vendor: "Apple",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:apple:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-1104",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "Apple iOS, iPadOS, macOS, tvOS, and watchOS contain a memory corru",
            "ption vulnerability that could allow an application to execute cod",
            "e with kernel privileges."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3950",
        vendor: "VMware",
        product: "Multiple Products",
        cpe23: "cpe:2.3:a:vmware:multiple_products:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-284",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware Fusion, Remote Console (VMRC) for Mac, and Horizon Client f",
            "or Mac contain a privilege escalation vulnerability due to imprope",
            "r use of setuid binaries that allows attackers to escalate privile",
            "ges to root."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
    KevCveRecord {
        cve_id: "CVE-2020-3952",
        vendor: "VMware",
        product: "vCenter Server",
        cpe23: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
        cvss_x10: 88, severity: "High", cwe: "CWE-306",
        is_kev: true, ransomware: "Unknown", epss_permille: 650,
        summary: concat!(
            "VMware vCenter Server contains an information disclosure vulnerabi",
            "lity in the VMware Directory Service (vmdir) when the Platform Ser",
            "vices Controller (PSC) does not correctly implement access control",
            "s. Successful exploitation allows an attacker with network access ",
            "to port 389 to extract sensitive information."
        ),
        remediation: "Apply updates per vendor instructions.",
    },
];
