// SPECTRE Native Rust Kernel Self-Test & Differential Invariant Verifier (ABI v950)
// Validates multi-branch SemVer/CVE range boundaries, Debian/RPM epoch-backport ordering,
// 6-language SAST lexer keyword-regex/CRLF preservation, strict FIRST.org CVSS v3.1 vector
// validation, cross-role access differential verification, and Trail of Bits 7-Brocards scoring.

use crate::rust_cpe_consolidator::{consolidate_cpe_and_audit_json, evaluate_seven_triage_brocards};
use crate::rust_sast_lexer_engine::{lexical_scope_metrics, strip_comments_for_lang, SourceLang};
use crate::{
    spectre_rust_compare_distro_versions, spectre_rust_cvss31_score, spectre_rust_is_valid_dns_label,
    spectre_rust_sast_prefilter_mask, spectre_rust_topological_waves, spectre_rust_verify_access_diff,
};

fn verify_multibranch_cve_invariants() -> bool {
    let patched_obs = concat!(
        "Server: PHP/8.1.29\n",
        "X-Powered-By: PHP/8.2.20\n",
        "Banner: PostgreSQL 15.8\n",
        "Framework: Next.js/14.2.25\n",
        "Server: Apache Tomcat/10.1.34\n",
        "Banner: redis_version:7.2.6\n",
    );
    let patched_json = consolidate_cpe_and_audit_json(patched_obs);
    if patched_json.contains("CVE-2024-4577")
        || patched_json.contains("CVE-2024-7348")
        || patched_json.contains("CVE-2025-29927")
        || patched_json.contains("CVE-2024-50379")
        || patched_json.contains("CVE-2024-31449")
    {
        return false;
    }

    let vuln_obs = concat!(
        "Server: PHP/8.1.28\n",
        "Banner: PostgreSQL 15.7\n",
        "Framework: Next.js/14.2.24\n",
        "Server: Apache Tomcat/10.1.33\n",
        "Banner: redis_version:7.2.5\n",
        "Service: nginx/1.25.3-rc1\n",
    );
    let vuln_json = consolidate_cpe_and_audit_json(vuln_obs);
    vuln_json.contains("CVE-2024-4577")
        && vuln_json.contains("CVE-2024-7348")
        && vuln_json.contains("CVE-2025-29927")
        && vuln_json.contains("CVE-2024-50379")
        && vuln_json.contains("CVE-2024-31449")
}

fn verify_distro_lsc_comparators() -> bool {
    let cases: &[(&[u8], &[u8], i32)] = &[
        (b"1.0~rc1", b"1.0", -1),
        (b"1.0~alpha2", b"1.0~beta1", -1),
        (b"0:2.4.58-01", b"2.4.58-1", 0),
        (b"1:8.9p1-3ubuntu0.10", b"1:8.9p1-3ubuntu0.6", 1),
        (b"8.7p1-38.el9_4", b"8.7p1-38.el9_4.1", -1),
        (b"1:9.2p1-2+deb12u3", b"1:9.2p1-2+deb12u2", 1),
        (b"2:1.20.1-1", b"1:1.99.9-9", 1),
    ];
    for &(v1, v2, expected) in cases {
        let got = spectre_rust_compare_distro_versions(v1.as_ptr(), v1.len(), v2.as_ptr(), v2.len());
        if got != expected {
            return false;
        }
    }
    true
}

fn verify_cvss31_strict_vectors() -> bool {
    let valid_crit = b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
    let valid_med = b"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N";
    let valid_zero = b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    let invalid_v2 = b"CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let invalid_v4 = b"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N";
    let invalid_tok = b"CVSS:3.1/AV:NetworkGarbage/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let invalid_key = b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y";

    let s_crit = spectre_rust_cvss31_score(valid_crit.as_ptr(), valid_crit.len());
    let s_med = spectre_rust_cvss31_score(valid_med.as_ptr(), valid_med.len());
    let s_zero = spectre_rust_cvss31_score(valid_zero.as_ptr(), valid_zero.len());
    let s_v2 = spectre_rust_cvss31_score(invalid_v2.as_ptr(), invalid_v2.len());
    let s_v4 = spectre_rust_cvss31_score(invalid_v4.as_ptr(), invalid_v4.len());
    let s_tok = spectre_rust_cvss31_score(invalid_tok.as_ptr(), invalid_tok.len());
    let s_key = spectre_rust_cvss31_score(invalid_key.as_ptr(), invalid_key.len());

    (s_crit - 10.0).abs() < 1e-6
        && (s_med - 7.4).abs() < 1e-6
        && s_zero == 0.0
        && s_v2 == 0.0
        && s_v4 == 0.0
        && s_tok == 0.0
        && s_key == 0.0
}

fn verify_polyglot_sast_lexer_invariants() -> bool {
    let js_regex_src = concat!(
        "function checkInput(x) {\n",
        "  // single-line comment removed\n",
        "  if (typeof /[/*]/.test(x) === 'boolean') {\n",
        "    return /[/*]/.test(x) && eval(x);\n",
        "  }\n",
        "}\n",
    );
    let cleaned_js = strip_comments_for_lang(js_regex_src.as_bytes(), SourceLang::JsTs);
    let Ok(cleaned_js_str) = std::str::from_utf8(&cleaned_js) else {
        return false;
    };
    if !cleaned_js_str.contains("eval(x)") || cleaned_js_str.contains("single-line comment") {
        return false;
    }

    let crlf_str_src = b"const msg = \"line1\\\r\n/* not a comment */\\\r\nline3\";\r\nconst q = eval(userIn);\r\n";
    let cleaned_crlf = strip_comments_for_lang(crlf_str_src, SourceLang::JsTs);
    let Ok(cleaned_crlf_str) = std::str::from_utf8(&cleaned_crlf) else {
        return false;
    };
    if !cleaned_crlf_str.contains("eval(userIn)") {
        return false;
    }

    let py_doc_src = concat!(
        "def safe_helper():\n",
        "    \"\"\"Docstring mentioning subprocess.Popen(cmd, shell=True)\"\"\"\n",
        "    # Comment with pickle.loads(x)\n",
        "    return 42\n",
    );
    let cleaned_py = strip_comments_for_lang(py_doc_src.as_bytes(), SourceLang::Python);
    let Ok(cleaned_py_str) = std::str::from_utf8(&cleaned_py) else {
        return false;
    };
    if cleaned_py_str.contains("pickle.loads") {
        return false;
    }

    let go_raw_src = "package main\nfunc run() {\n\ts := `/* raw literal stays */`\n\t/* block comment stripped */\n\t_ = s\n}\n";
    let cleaned_go = strip_comments_for_lang(go_raw_src.as_bytes(), SourceLang::Go);
    let Ok(cleaned_go_str) = std::str::from_utf8(&cleaned_go) else {
        return false;
    };
    if !cleaned_go_str.contains("raw literal stays") || cleaned_go_str.contains("block comment stripped") {
        return false;
    }

    let php_hash_src = "<?php\n# shell comment with unserialize($x)\n$clean = 1;\n";
    let cleaned_php = strip_comments_for_lang(php_hash_src.as_bytes(), SourceLang::Php);
    let Ok(cleaned_php_str) = std::str::from_utf8(&cleaned_php) else {
        return false;
    };
    if cleaned_php_str.contains("unserialize") || !cleaned_php_str.contains("$clean = 1;") {
        return false;
    }

    let (_, _, lex_fp) = lexical_scope_metrics(js_regex_src.as_bytes());
    let mask_clean = spectre_rust_sast_prefilter_mask(b"fn add(a: i32, b: i32) -> i32 { a + b }".as_ptr(), 39);
    let sharp_sample = b"cipher = AES.new(key, AES.MODE_ECB)";
    let mask_sharp = spectre_rust_sast_prefilter_mask(sharp_sample.as_ptr(), sharp_sample.len());
    lex_fp != 0 && mask_clean == 0 && mask_sharp != 0
}

fn verify_access_matrix_and_brocards() -> bool {
    let p_ver = b"/api/v1/profile";
    let p_obj = b"/api/v1/orders/1042";
    let p_uuid = b"/api/v2/accounts/550e8400-e29b-41d4-a716-446655440000";

    let role_a_prof = br#"{"id":101,"email":"alice@corp.example","role":"member"}"#;
    let role_b_prof = br#"{"id":202,"email":"bob@corp.example","role":"member"}"#;
    let role_a_ord = br#"{"order_id":1042,"owner_id":101,"total":9500,"currency":"USD"}"#;
    let role_b_same_ord = br#"{"order_id":1042,"owner_id":101,"total":9500,"currency":"USD"}"#;
    let role_b_diff_ord = br#"{"order_id":2088,"owner_id":202,"total":1200,"currency":"USD"}"#;

    let fp_versioned = spectre_rust_verify_access_diff(
        p_ver.as_ptr(), p_ver.len(),
        role_a_prof.as_ptr(), role_a_prof.len(),
        role_a_prof.as_ptr(), role_a_prof.len(),
    );
    let fp_diff_owner = spectre_rust_verify_access_diff(
        p_obj.as_ptr(), p_obj.len(),
        role_a_ord.as_ptr(), role_a_ord.len(),
        role_b_diff_ord.as_ptr(), role_b_diff_ord.len(),
    );
    let tp_same_id = spectre_rust_verify_access_diff(
        p_obj.as_ptr(), p_obj.len(),
        role_a_ord.as_ptr(), role_a_ord.len(),
        role_b_same_ord.as_ptr(), role_b_same_ord.len(),
    );
    let tp_uuid = spectre_rust_verify_access_diff(
        p_uuid.as_ptr(), p_uuid.len(),
        br#"{"uuid":"550e8400-e29b-41d4-a716-446655440000","balance":500}"#.as_ptr(), 61,
        br#"{"uuid":"550e8400-e29b-41d4-a716-446655440000","balance":500}"#.as_ptr(), 61,
    );
    let fp_diff_prof_on_obj = spectre_rust_verify_access_diff(
        p_obj.as_ptr(), p_obj.len(),
        role_a_prof.as_ptr(), role_a_prof.len(),
        role_b_prof.as_ptr(), role_b_prof.len(),
    );

    if fp_versioned != 0 || fp_diff_owner != 0 || fp_diff_prof_on_obj != 0 || tp_same_id != 1 || tp_uuid != 1 {
        return false;
    }

    let score_info = evaluate_seven_triage_brocards("Info", "CWE-200", "https://example.org", "banner", "fix", 90);
    let score_verified = evaluate_seven_triage_brocards(
        "High",
        "CWE-639",
        "https://api.example.org/api/v1/orders/1042",
        "Guest=401 | Role-A=200 (order_id=1042) | Role-B=200 (order_id=1042)",
        "Enforce object owner check in order controller.",
        95,
    );
    score_info == 0 && score_verified >= 75
}

fn verify_wave_dag_and_dns_validators() -> bool {
    let dag_ok = b"c\tb\na\t\nb\ta,external_dep\n";
    let mut out = [0u8; 256];
    let rc_ok = spectre_rust_topological_waves(dag_ok.as_ptr(), dag_ok.len(), out.as_mut_ptr(), out.len());
    let dag_cyc = b"p1\tp2\np2\tp1\n";
    let rc_cyc = spectre_rust_topological_waves(dag_cyc.as_ptr(), dag_cyc.len(), out.as_mut_ptr(), out.len());

    let dns_good = b"api-gateway-01";
    let dns_bad1 = b"-leading-hyphen";
    let dns_bad2 = b"under_score";

    rc_ok == 3
        && rc_cyc == -1
        && spectre_rust_is_valid_dns_label(dns_good.as_ptr(), dns_good.len()) == 1
        && spectre_rust_is_valid_dns_label(dns_bad1.as_ptr(), dns_bad1.len()) == 0
        && spectre_rust_is_valid_dns_label(dns_bad2.as_ptr(), dns_bad2.len()) == 0
}

pub fn run_all_rust_kernel_selftests() -> i32 {
    let mut passed = 0i32;
    if verify_multibranch_cve_invariants() {
        passed += 1;
    }
    if verify_distro_lsc_comparators() {
        passed += 1;
    }
    if verify_cvss31_strict_vectors() {
        passed += 1;
    }
    if verify_polyglot_sast_lexer_invariants() {
        passed += 1;
    }
    if verify_access_matrix_and_brocards() {
        passed += 1;
    }
    if verify_wave_dag_and_dns_validators() {
        passed += 1;
    }
    if passed == 6 { 6 } else { -passed }
}


