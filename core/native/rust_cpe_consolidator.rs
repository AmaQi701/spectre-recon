// SPECTRE Rust Zero-Request CPE 2.3 Consolidator & Trail of Bits 7-Brocards Verifier
// Normalizes passive/active HTTP headers, socket banners, and tech hints into NIST CPE 2.3
// URIs and evaluates version boundaries against Clean-Room NVD/OSV ranges with 0 extra packets.

use crate::cmp_deb_rpm_part;
use crate::rust_cleanroom_nvd_cpe_pack::CLEANROOM_RANGE_RULES;
use crate::rust_cpe_advisory_engine::{lookup_cpe_vendor_slug, CPE_PRODUCTS, SEMVER_ADVISORIES};

struct BannerSig {
    token_lower: &'static str,
    vendor: &'static str,
    product: &'static str,
    part: char,
}

static BANNER_SIGS: &[BannerSig] = &[
    BannerSig { token_lower: "openssh_", vendor: "openbsd", product: "openssh", part: 'a' },
    BannerSig { token_lower: "openssh/", vendor: "openbsd", product: "openssh", part: 'a' },
    BannerSig { token_lower: "nginx/", vendor: "f5", product: "nginx", part: 'a' },
    BannerSig { token_lower: "apache/", vendor: "apache", product: "http_server", part: 'a' },
    BannerSig { token_lower: "tomcat/", vendor: "apache", product: "tomcat", part: 'a' },
    BannerSig { token_lower: "php/", vendor: "php", product: "php", part: 'a' },
    BannerSig { token_lower: "redis_version:", vendor: "redis", product: "redis", part: 'a' },
    BannerSig { token_lower: "redis/", vendor: "redis", product: "redis", part: 'a' },
    BannerSig { token_lower: "postgresql ", vendor: "postgresql", product: "postgresql", part: 'a' },
    BannerSig { token_lower: "jenkins/", vendor: "jenkins", product: "jenkins", part: 'a' },
    BannerSig { token_lower: "x-jenkins:", vendor: "jenkins", product: "jenkins", part: 'a' },
    BannerSig { token_lower: "grafana/", vendor: "grafana", product: "grafana", part: 'a' },
    BannerSig { token_lower: "gitlab/", vendor: "gitlab", product: "gitlab", part: 'a' },
    BannerSig { token_lower: "next.js/", vendor: "vercel", product: "next.js", part: 'a' },
    BannerSig { token_lower: "activemq/", vendor: "apache", product: "activemq", part: 'a' },
    BannerSig { token_lower: "activemq ", vendor: "apache", product: "activemq", part: 'a' },
    BannerSig { token_lower: "teamcity/", vendor: "jetbrains", product: "teamcity", part: 'a' },
    BannerSig { token_lower: "keycloak/", vendor: "redhat", product: "keycloak", part: 'a' },
    BannerSig { token_lower: "zabbix ", vendor: "zabbix", product: "zabbix", part: 'a' },
];

fn extract_version_after(raw: &str, start_idx: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = start_idx;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'v' || bytes[i] == b'V') {
        i += 1;
    }
    if i >= bytes.len() || !bytes[i].is_ascii_digit() {
        return None;
    }
    let v_start = i;
    while i < bytes.len() {
        let c = bytes[i];
        let ok = c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'+' || c == b'~';
        if !ok {
            break;
        }
        i += 1;
    }
    let cand = raw[v_start..i].trim_end_matches(|c: char| c == '.' || c == '-');
    if cand.contains('.') {
        Some(cand.to_string())
    } else {
        None
    }
}

pub fn json_escape_rs(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

fn has_distro_backport_marker(obs_lower: &str, ver: &str) -> bool {
    let vl = ver.to_ascii_lowercase();
    if vl.contains("ubuntu") || vl.contains("deb") || vl.contains(".el8") || vl.contains(".el9") {
        return true;
    }
    if obs_lower.contains("ubuntu") || obs_lower.contains("debian") || obs_lower.contains("red hat") {
        return true;
    }
    matches!(ver, "8.9p1" | "9.2p1" | "9.6p1")
}

fn normalize_upstream_for_cmp(ver: &str) -> String {
    if let Some((base, rest)) = ver.split_once('-') {
        let rl = rest.to_ascii_lowercase();
        if rl.starts_with("rc") || rl.starts_with("alpha") || rl.starts_with("beta") || rl.starts_with("pre") || rl.starts_with("dev") {
            return format!("{}~{}", base, rl);
        }
        return base.to_string();
    }
    ver.to_string()
}

pub fn consolidate_cpe_and_audit_json(observations: &str) -> String {
    let obs_low = observations.to_ascii_lowercase();
    let mut seen_prod: Vec<(char, &str, &str, String)> = Vec::new();

    for sig in BANNER_SIGS {
        let mut search_from = 0usize;
        while let Some(rel) = obs_low[search_from..].find(sig.token_lower) {
            let hit_end = search_from + rel + sig.token_lower.len();
            if let Some(ver) = extract_version_after(observations, hit_end) {
                if !seen_prod.iter().any(|(_, _, p, v)| *p == sig.product && *v == ver) {
                    seen_prod.push((sig.part, sig.vendor, sig.product, ver));
                }
            }
            search_from = hit_end;
            if search_from >= obs_low.len() {
                break;
            }
        }
    }
    for cp in CPE_PRODUCTS {
        for sep in ["/", " ", ":"] {
            let tok = format!("{}{}", cp.key, sep);
            let mut search_from = 0usize;
            while let Some(rel) = obs_low[search_from..].find(&tok) {
                let hit_end = search_from + rel + tok.len();
                if let Some(ver) = extract_version_after(observations, hit_end) {
                    let (vend, slug) = lookup_cpe_vendor_slug(cp.key).unwrap_or((cp.vendor, cp.slug));
                    if !seen_prod.iter().any(|(_, _, p, v)| *p == slug && *v == ver) {
                        seen_prod.push(('a', vend, slug, ver));
                    }
                }
                search_from = hit_end;
                if search_from >= obs_low.len() {
                    break;
                }
            }
        }
    }

    let mut items_json: Vec<String> = Vec::new();
    for (part_ch, vendor, prod, ver) in &seen_prod {
        let cmp_ver = normalize_upstream_for_cmp(ver);
        let cpe_ver = ver.split('+').next().unwrap_or(ver.as_str());
        let cpe23 = format!("cpe:2.3:{}:{}:{}:{}:*:*:*:*:*:*:*", part_ch, vendor, prod, cpe_ver);
        let backport = has_distro_backport_marker(&obs_low, ver);
        let qod = if backport { 60 } else { 88 };

        let mut matched_cves: Vec<String> = Vec::new();
        let mut seen_cve_ids: Vec<&str> = Vec::new();
        for rule in CLEANROOM_RANGE_RULES {
            if rule.product != *prod || seen_cve_ids.contains(&rule.cve_id) {
                continue;
            }
            let ge_min = cmp_deb_rpm_part(cmp_ver.as_bytes(), rule.min_ver.as_bytes()) >= 0;
            let lt_max = cmp_deb_rpm_part(cmp_ver.as_bytes(), rule.max_ver_excl.as_bytes()) < 0;
            if ge_min && lt_max {
                seen_cve_ids.push(rule.cve_id);
                matched_cves.push(format!(
                    "{{\"cve\":\"{}\",\"severity\":\"{}\",\"cvss\":{:.1},\"cwe\":\"{}\",\"is_kev\":{},\"qod\":{},\"backport_possible\":{},\"summary\":\"{}\",\"fix\":\"{}\"}}",
                    json_escape_rs(rule.cve_id),
                    rule.severity,
                    (rule.cvss_x10 as f64) / 10.0,
                    rule.cwe,
                    if rule.is_kev { "true" } else { "false" },
                    qod,
                    if backport { "true" } else { "false" },
                    json_escape_rs(rule.summary),
                    json_escape_rs(rule.fix),
                ));
            }
        }
        for srule in SEMVER_ADVISORIES {
            if srule.product != *prod || seen_cve_ids.contains(&srule.cve) {
                continue;
            }
            let ge_min = cmp_deb_rpm_part(cmp_ver.as_bytes(), srule.min_v.as_bytes()) >= 0;
            let lt_max = cmp_deb_rpm_part(cmp_ver.as_bytes(), srule.max_v.as_bytes()) < 0;
            if ge_min && lt_max {
                seen_cve_ids.push(srule.cve);
                matched_cves.push(format!(
                    "{{\"cve\":\"{}\",\"severity\":\"{}\",\"cvss\":{:.1},\"cwe\":\"{}\",\"is_kev\":false,\"qod\":{},\"backport_possible\":{},\"summary\":\"{}\",\"fix\":\"Upgrade {} to >= {}\"}}",
                    json_escape_rs(srule.cve),
                    srule.severity,
                    (srule.cvss_x10 as f64) / 10.0,
                    srule.cwe,
                    qod,
                    if backport { "true" } else { "false" },
                    json_escape_rs(srule.title),
                    json_escape_rs(prod),
                    json_escape_rs(srule.max_v),
                ));
            }
        }
        items_json.push(format!(
            "{{\"vendor\":\"{}\",\"product\":\"{}\",\"version\":\"{}\",\"cpe23\":\"{}\",\"backport_possible\":{},\"qod\":{},\"advisories\":[{}]}}",
            vendor,
            prod,
            json_escape_rs(ver),
            json_escape_rs(&cpe23),
            if backport { "true" } else { "false" },
            qod,
            matched_cves.join(",")
        ));
    }
    format!("[{}]", items_json.join(","))
}

pub fn evaluate_seven_triage_brocards(
    severity: &str,
    cwe: &str,
    asset: &str,
    evidence: &str,
    remediation: &str,
    qod: i32,
) -> i32 {
    let sev_l = severity.trim().to_ascii_lowercase();
    if sev_l == "info" || sev_l == "informational" || sev_l.is_empty() {
        return 0;
    }
    let ev_l = evidence.to_ascii_lowercase();
    if ev_l.contains("welcome to nginx!") || ev_l.contains("attention required!") || ev_l.contains("telegram web") {
        return 10;
    }
    let mut score = 0i32;
    let a_trim = asset.trim();
    if a_trim.starts_with("http://") || a_trim.starts_with("https://") || a_trim.contains(':') || a_trim.contains('/') {
        score += 15;
    }
    if matches!(sev_l.as_str(), "critical" | "high" | "medium" | "low") {
        score += 15;
    }
    if cwe.trim().to_ascii_uppercase().starts_with("CWE-") {
        score += 15;
    }
    if evidence.trim().len() >= 12 {
        score += 20;
    }
    if remediation.trim().len() >= 10 {
        score += 15;
    }
    if qod >= 80 {
        score += 20;
    } else if qod >= 60 {
        score += 10;
    }
    score.min(100)
}

