// SPECTRE v10.0 Rust Attack Graph Scorer, 7-Gate Refuting Triage & Taint v2 Kernel (ABI v1000)
// SPDX-License-Identifier: Apache-2.0
// Clean-room zero-dependency Rust security verification engine providing:
//   1. Probabilistic Multi-Hop Attack Graph Scorer with MITRE ATT&CK v15 chain synthesis
//   2. 7-Gate Refuting Triage Pipeline (eliminating stub, decoy, mock, sanitizer & backport FPs)
//   3. 6-Language Intra-Procedural Multi-Hop Source-to-Sink Taint Engine v2

use std::collections::{HashMap, HashSet};
use crate::rust_sast_lexer_engine::{strip_comments_for_lang, SourceLang};

fn json_escape_rs(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
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

pub fn score_attack_graph_json(tsv_nodes: &str) -> String {
    // Format per line:
    // host \t max_cvss \t kev \t epss_pct \t bola \t cors_cookie \t xss \t cloud_iam \t k8s_priv \t sast_taint \t db_ports
    let mut items: Vec<(i32, String)> = Vec::new();
    for raw_line in tsv_nodes.lines() {
        let ln = raw_line.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = ln.split('\t').collect();
        if cols.len() < 11 {
            continue;
        }
        let host = cols[0].trim();
        if host.is_empty() {
            continue;
        }
        let max_cvss: f64 = cols[1].trim().parse().unwrap_or(0.0);
        let is_kev = cols[2].trim() == "1";
        let epss_pct: f64 = cols[3].trim().parse().unwrap_or(0.0);
        let has_bola = cols[4].trim() == "1";
        let has_cors_ck = cols[5].trim() == "1";
        let has_xss = cols[6].trim() == "1";
        let has_cloud = cols[7].trim() == "1";
        let has_k8s = cols[8].trim() == "1";
        let has_sast = cols[9].trim() == "1";
        let has_db = cols[10].trim() == "1";

        let mut p_not = 1.0f64;
        let mut hops: Vec<&str> = Vec::new();
        let mut mitre: Vec<&str> = Vec::new();

        if max_cvss >= 7.0 {
            let p_cve = (max_cvss / 10.0) * if is_kev { 0.96 } else { 0.72 };
            p_not *= 1.0 - p_cve.clamp(0.1, 0.96);
            hops.push(if is_kev { "KEV-Exploited-Surface" } else { "High-CVSS-Surface" });
            mitre.push("T1190");
        }
        if has_bola {
            p_not *= 1.0 - 0.82;
            hops.push("Cross-Role-BOLA");
            mitre.push("T1078");
        }
        if has_cors_ck || has_xss {
            p_not *= 1.0 - if has_cors_ck && has_xss { 0.86 } else { 0.58 };
            hops.push(if has_xss { "Client-DOM-Session-Pivot" } else { "Credentialed-CORS-Session" });
            mitre.push("T1539");
        }
        if has_sast {
            p_not *= 1.0 - 0.78;
            hops.push("WhiteBox-Sink-Reachability");
            mitre.push("T1059");
        }
        if has_cloud {
            p_not *= 1.0 - 0.84;
            hops.push("Cloud-IAM-Privilege-Pivot");
            mitre.push("T1098");
        }
        if has_k8s {
            p_not *= 1.0 - 0.85;
            hops.push("K8s-Pod-Node-Breakout");
            mitre.push("T1611");
        }
        if has_db {
            p_not *= 1.0 - 0.76;
            hops.push("Exposed-Data-Store");
            mitre.push("T1213");
        }

        if hops.is_empty() {
            continue;
        }
        let compound_prob = 1.0 - p_not;
        let epss_boost = (epss_pct / 100.0).clamp(0.0, 1.0) * 8.0;
        let hop_bonus = if hops.len() >= 3 { 9.0 } else if hops.len() == 2 { 5.0 } else { 0.0 };
        let raw_score = (compound_prob * 85.0 + epss_boost + hop_bonus).round() as i32;
        let final_score = raw_score.clamp(15, 100);
        let sev = if final_score >= 88 {
            "Critical"
        } else if final_score >= 70 {
            "High"
        } else {
            "Medium"
        };
        let chain_str = hops.join(" -> ");
        let mitre_str = mitre.join(",");
        let entry = format!(
            "{{\"host\":\"{}\",\"score\":{},\"severity\":\"{}\",\"hop_count\":{},\"chain\":\"{}\",\"mitre\":\"{}\"}}",
            json_escape_rs(host),
            final_score,
            sev,
            hops.len(),
            json_escape_rs(&chain_str),
            json_escape_rs(&mitre_str),
        );
        items.push((final_score, entry));
    }
    items.sort_by(|a, b| b.0.cmp(&a.0));
    let joined: Vec<String> = items.into_iter().map(|(_, s)| s).collect();
    format!("[{}]", joined.join(","))
}


pub fn refute_triage_seven_gates_json(tsv_finding: &str) -> String {
    // Format: severity \t cwe \t asset \t evidence \t remediation \t qod \t distro_hint
    let mut parts = tsv_finding.splitn(7, '\t');
    let sev = parts.next().unwrap_or("").trim();
    let cwe = parts.next().unwrap_or("").trim();
    let asset = parts.next().unwrap_or("").trim();
    let evidence = parts.next().unwrap_or("").trim();
    let remediation = parts.next().unwrap_or("").trim();
    let qod_raw: i32 = parts.next().unwrap_or("80").trim().parse().unwrap_or(80);
    let distro_hint = parts.next().unwrap_or("").trim().to_ascii_lowercase();

    let sev_l = sev.to_ascii_lowercase();
    let asset_l = asset.to_ascii_lowercase();
    let ev_l = evidence.to_ascii_lowercase();

    // Gate 1: Non-Info & Reachable Non-Stub Asset
    if sev_l == "info" || sev_l == "informational" || asset.is_empty() || ev_l.contains("content-length: 0") {
        return "{\"verdict\":\"REFUTED_FALSE_POSITIVE\",\"adjusted_qod\":0,\"gates_passed\":0,\"reason\":\"G1_STUB_OR_INFO_NOISE\"}".to_string();
    }
    // Gate 2: Non-Decoy / Non-Default Stub Origin (Law 5)
    for decoy in &[
        "welcome to nginx!",
        "apache2 ubuntu default page",
        "telegram web",
        "attention required! | cloudflare",
        "accessdenied</code",
    ] {
        if ev_l.contains(decoy) {
            return "{\"verdict\":\"REFUTED_FALSE_POSITIVE\",\"adjusted_qod\":0,\"gates_passed\":1,\"reason\":\"G2_DECOY_OR_DEFAULT_STUB\"}".to_string();
        }
    }
    // Gate 3: Non-Test / Non-Fixture Context
    for tdir in &["/tests/", "/__tests__/", "/fixtures/", "/testdata/", "_test.go", ".spec.ts", ".test.js"] {
        if asset_l.contains(tdir) {
            return "{\"verdict\":\"REFUTED_FALSE_POSITIVE\",\"adjusted_qod\":0,\"gates_passed\":2,\"reason\":\"G3_TEST_FIXTURE_PATH\"}".to_string();
        }
    }
    // Gate 4: Explicit Sanitizer / Parameterized Kill-Set Absence
    for san in &[
        "dompurify.sanitize(",
        "preparedstatement",
        "shlex.quote(",
        "hmac.compare_digest(",
        "crypto.timingsafeequal(",
        "subtle.constanttimecompare(",
    ] {
        if ev_l.contains(san) {
            return "{\"verdict\":\"REFUTED_FALSE_POSITIVE\",\"adjusted_qod\":0,\"gates_passed\":3,\"reason\":\"G4_SANITIZER_PRESENT\"}".to_string();
        }
    }
    // Gate 5: Valid CWE/CVE Identifier & Remediation Presence
    let cwe_up = cwe.to_ascii_uppercase();
    if (!cwe_up.starts_with("CWE-") && !cwe_up.starts_with("CVE-")) || remediation.len() < 8 {
        return "{\"verdict\":\"REFUTED_FALSE_POSITIVE\",\"adjusted_qod\":30,\"gates_passed\":4,\"reason\":\"G5_MISSING_CWE_OR_REMEDIATION\"}".to_string();
    }
    // Gate 6: Distro Backport Guard (Law 10)
    let is_banner_cve = ev_l.contains("banner") && !ev_l.contains("confirmed") && !ev_l.contains("lockfile");
    let has_backport_os = distro_hint.contains("debian")
        || distro_hint.contains("ubuntu")
        || distro_hint.contains("rhel")
        || ev_l.contains("openssh_8.9p1")
        || ev_l.contains("openssh_9.2p1")
        || ev_l.contains("openssh_9.6p1");
    if is_banner_cve && has_backport_os {
        return "{\"verdict\":\"DOWNGRADED_BACKPORT\",\"adjusted_qod\":60,\"gates_passed\":6,\"reason\":\"G6_DISTRO_BACKPORT_POSSIBLE\"}".to_string();
    }
    // Gate 7: Empirical Evidence & Minimum QoD Threshold
    if evidence.len() < 6 || qod_raw < 60 {
        return format!(
            "{{\"verdict\":\"REFUTED_FALSE_POSITIVE\",\"adjusted_qod\":{},\"gates_passed\":6,\"reason\":\"G7_INSUFFICIENT_EMPIRICAL_QOD\"}}",
            qod_raw.clamp(0, 59)
        );
    }
    let adj_qod = qod_raw.clamp(70, 99);
    format!(
        "{{\"verdict\":\"VERIFIED\",\"adjusted_qod\":{},\"gates_passed\":7,\"reason\":\"ALL_7_GATES_PASSED\"}}",
        adj_qod
    )
}


fn is_ident_char_rs(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn contains_ident_word(expr: &str, var_name: &str) -> bool {
    if var_name.is_empty() || expr.len() < var_name.len() {
        return false;
    }
    let eb = expr.as_bytes();
    let vb = var_name.as_bytes();
    let mut pos = 0usize;
    while pos + vb.len() <= eb.len() {
        if let Some(rel) = expr[pos..].find(var_name) {
            let idx = pos + rel;
            let left_ok = idx == 0 || !is_ident_char_rs(eb[idx - 1]);
            let right_idx = idx + vb.len();
            let right_ok = right_idx >= eb.len() || !is_ident_char_rs(eb[right_idx]);
            if left_ok && right_ok {
                return true;
            }
            pos = idx + 1;
        } else {
            break;
        }
    }
    false
}

fn extract_lhs_rhs(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'=' {
            let prev = if i > 0 { bytes[i - 1] } else { 0 };
            let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            if next == b'=' || next == b'>' || prev == b'!' || prev == b'<' || prev == b'>' || prev == b'=' {
                continue;
            }
            let lhs_raw = if prev == b':' && i >= 2 { &line[..i - 1] } else { &line[..i] };
            let rhs = line[i + 1..].trim();
            let mut lhs = lhs_raw.trim();
            for kw in &["const ", "let ", "var ", "final ", "String ", "string ", "auto "] {
                if let Some(rest) = lhs.strip_prefix(kw) {
                    lhs = rest.trim();
                }
            }
            let var_tok = lhs.split_whitespace().last().unwrap_or("").trim();
            if !var_tok.is_empty() && var_tok.bytes().all(is_ident_char_rs) {
                return Some((var_tok, rhs));
            }
            return None;
        }
    }
    None
}
pub fn analyze_taint_flow_v2_json(raw_src: &[u8], lang_tag: &[u8]) -> String {
    let lang = SourceLang::from_tag_or_sniff(lang_tag, raw_src);
    let stripped = strip_comments_for_lang(raw_src, lang);
    let Ok(code) = std::str::from_utf8(&stripped) else {
        return "[]".to_string();
    };

    let sources = [
        "request.args", "request.form", "request.json", "request.GET", "request.POST",
        "req.query", "req.body", "req.params", "location.search", "location.hash",
        "r.URL.Query()", "r.FormValue(", "request.getParameter(", "$_GET[", "$_POST[",
        "$_REQUEST[", "Request.Query[", "HttpContext.Request",
    ];
    let sanitizers = [
        "shlex.quote(", "DOMPurify.sanitize(", "html.escape(", "htmlspecialchars(",
        "escapeshellarg(", "filepath.Clean(", "PreparedStatement", "SqlParameter(",
        "parseInt(", "Number(", "int(", "strconv.Atoi(", "UUID.fromString(",
    ];
    let sinks: &[(&str, &str, &str)] = &[
        ("cursor.execute(", "CWE-89", "SQL_SINK"),
        ("db.Query(", "CWE-89", "SQL_SINK"),
        ("Statement.executeQuery(", "CWE-89", "SQL_SINK"),
        ("mysqli_query(", "CWE-89", "SQL_SINK"),
        ("subprocess.Popen(", "CWE-78", "CMD_SINK"),
        ("os.system(", "CWE-78", "CMD_SINK"),
        ("child_process.exec(", "CWE-78", "CMD_SINK"),
        ("exec.Command(", "CWE-78", "CMD_SINK"),
        ("Runtime.getRuntime().exec(", "CWE-78", "CMD_SINK"),
        ("shell_exec(", "CWE-78", "CMD_SINK"),
        (".innerHTML", "CWE-79", "DOM_SINK"),
        ("requests.get(", "CWE-918", "SSRF_SINK"),
        ("http.Get(", "CWE-918", "SSRF_SINK"),
    ];

    let mut tainted: HashMap<String, String> = HashMap::new();
    let mut emitted: HashSet<(usize, &str)> = HashSet::new();
    let mut out: Vec<String> = Vec::new();

    for (idx, raw_ln) in code.lines().enumerate() {
        let lno = idx + 1;
        let ln = raw_ln.trim();
        if ln.is_empty() {
            continue;
        }
        let has_sanitizer = sanitizers.iter().any(|s| ln.contains(s));
        if let Some((lhs, rhs)) = extract_lhs_rhs(ln) {
            if has_sanitizer {
                tainted.remove(lhs);
            } else if sources.iter().any(|src| rhs.contains(src)) {
                tainted.insert(lhs.to_string(), lhs.to_string());
            } else {
                let mut inherited: Option<String> = None;
                for (tvar, root_src) in &tainted {
                    if contains_ident_word(rhs, tvar) {
                        inherited = Some(root_src.clone());
                        break;
                    }
                }
                if let Some(origin) = inherited {
                    tainted.insert(lhs.to_string(), origin);
                } else if rhs.starts_with('"') && !rhs.contains('+') && !rhs.contains('{') && !rhs.contains('$') {
                    tainted.remove(lhs);
                }
            }
        }
        if has_sanitizer {
            continue;
        }
        let is_param_sql = (ln.contains("?,") || ln.contains("$1") || ln.contains("%s\", (") || ln.contains("%s', ("))
            && !ln.contains('+')
            && !ln.contains("f\"")
            && !ln.contains("fmt.Sprintf");
        if is_param_sql {
            continue;
        }
        for &(sink_pat, cwe, kind) in sinks {
            if ln.contains(sink_pat) {
                for (tvar, root_src) in &tainted {
                    if contains_ident_word(ln, tvar) && !emitted.contains(&(lno, cwe)) {
                        emitted.insert((lno, cwe));
                        out.push(format!(
                            "{{\"line\":{},\"cwe\":\"{}\",\"sink\":\"{}\",\"source_var\":\"{}\",\"taint_var\":\"{}\"}}",
                            lno, cwe, kind, json_escape_rs(root_src), json_escape_rs(tvar)
                        ));
                        break;
                    }
                }
            }
        }
    }
    format!("[{}]", out.join(","))
}


