// SPECTRE Polyglot Rust Security Kernel (`libspectre_rust_core.so` — ABI v850)
// Compiled with: rustc -O --crate-type cdylib spectre_rust_core.rs -o libspectre_rust_core.so
// Memory-safe, zero-dependency Rust FFI kernel accelerating:
//   1. Debian Policy 5.6.12 & RPM Epoch-Upstream-Revision Distro LSC Comparator
//   2. Kahn Topological Wave DAG Planner with Deterministic Tie-Breaking & Cycle Detection
//   3. Single-Pass 6-Language SAST Byte Automaton Pre-Filter (Sharp-Edges / Entry-Point / TOCTOU)
//   4. Official FIRST.org CVSS v3.1 Vector Base Score Engine
//   5. HTTP/Cookie/DOM Clean-Room Technology Fingerprint Automaton & RFC-1123 DNS Validator

use std::collections::{HashMap, HashSet};
use std::slice;

#[no_mangle]
pub extern "C" fn spectre_rust_abi_version() -> u32 {
    850
}

#[inline]
fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let Some(&first) = s.first() {
        if first.is_ascii_whitespace() {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = s.last() {
        if last.is_ascii_whitespace() {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

#[inline]
fn char_order_deb(ch: Option<u8>) -> i32 {
    match ch {
        Some(b'~') => -2,
        None => -1,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => (c as i32) + 256,
    }
}

fn cmp_deb_rpm_part(part_a: &[u8], part_b: &[u8]) -> i32 {
    let (mut i, mut j) = (0usize, 0usize);
    let (la, lb) = (part_a.len(), part_b.len());
    while i < la || j < lb {
        while (i < la && !part_a[i].is_ascii_digit()) || (j < lb && !part_b[j].is_ascii_digit()) {
            let ca = if i < la && !part_a[i].is_ascii_digit() { Some(part_a[i]) } else { None };
            let cb = if j < lb && !part_b[j].is_ascii_digit() { Some(part_b[j]) } else { None };
            let (oa, ob) = (char_order_deb(ca), char_order_deb(cb));
            if oa != ob {
                return if oa < ob { -1 } else { 1 };
            }
            if ca.is_some() { i += 1; }
            if cb.is_some() { j += 1; }
        }
        let mut sa = i;
        while i < la && part_a[i].is_ascii_digit() { i += 1; }
        let mut sb = j;
        while j < lb && part_b[j].is_ascii_digit() { j += 1; }
        while sa < i && part_a[sa] == b'0' { sa += 1; }
        while sb < j && part_b[sb] == b'0' { sb += 1; }
        let da = &part_a[sa..i];
        let db = &part_b[sb..j];
        if da.len() != db.len() {
            return if da.len() < db.len() { -1 } else { 1 };
        }
        if da != db {
            return if da < db { -1 } else { 1 };
        }
    }
    0
}

fn parse_distro_bytes(raw: &[u8]) -> (u64, &[u8], &[u8]) {
    let mut s = trim_ascii(raw);
    let mut epoch = 0u64;
    if let Some(colon) = s.iter().position(|&b| b == b':') {
        let ep_part = &s[..colon];
        if !ep_part.is_empty() && ep_part.iter().all(|b| b.is_ascii_digit()) {
            for &d in ep_part {
                epoch = epoch.saturating_mul(10).saturating_add((d - b'0') as u64);
            }
            s = &s[colon + 1..];
        }
    }
    if let Some(dash) = s.iter().rposition(|&b| b == b'-') {
        return (epoch, &s[..dash], &s[dash + 1..]);
    }
    (epoch, s, b"")
}

#[no_mangle]
pub extern "C" fn spectre_rust_compare_distro_versions(
    v1_ptr: *const u8,
    v1_len: usize,
    v2_ptr: *const u8,
    v2_len: usize,
) -> i32 {
    let b1 = if v1_ptr.is_null() || v1_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(v1_ptr, v1_len) } };
    let b2 = if v2_ptr.is_null() || v2_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(v2_ptr, v2_len) } };
    let (ep1, up1, rev1) = parse_distro_bytes(b1);
    let (ep2, up2, rev2) = parse_distro_bytes(b2);
    if ep1 != ep2 {
        return if ep1 < ep2 { -1 } else { 1 };
    }
    let c_up = cmp_deb_rpm_part(up1, up2);
    if c_up != 0 {
        return c_up;
    }
    cmp_deb_rpm_part(rev1, rev2)
}

fn write_c_buf(src: &[u8], out_ptr: *mut u8, out_cap: usize) -> bool {
    if out_ptr.is_null() || out_cap == 0 || src.len() + 1 > out_cap {
        return false;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), out_ptr, src.len());
        *out_ptr.add(src.len()) = 0;
    }
    true
}

#[no_mangle]
pub extern "C" fn spectre_rust_topological_waves(
    spec_ptr: *const u8,
    spec_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    if out_ptr.is_null() || out_cap < 2 {
        return -2;
    }
    unsafe { *out_ptr = 0; }
    if spec_ptr.is_null() || spec_len == 0 {
        return 0;
    }
    let raw_bytes = unsafe { slice::from_raw_parts(spec_ptr, spec_len) };
    let spec_str = match std::str::from_utf8(raw_bytes) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut ordered_names: Vec<&str> = Vec::new();
    let mut raw_deps: HashMap<&str, Vec<&str>> = HashMap::new();

    for line in spec_str.lines() {
        if line.is_empty() {
            continue;
        }
        let (t_name, dep_blob) = match line.split_once('\t') {
            Some((n, d)) => (n, d),
            None => (line, ""),
        };
        if t_name.is_empty() {
            continue;
        }
        let entry = raw_deps.entry(t_name).or_insert_with(|| {
            ordered_names.push(t_name);
            Vec::new()
        });
        if !dep_blob.is_empty() {
            for dep in dep_blob.split(',') {
                if !dep.is_empty() && !entry.contains(&dep) {
                    entry.push(dep);
                }
            }
        }
    }

    if ordered_names.is_empty() {
        return 0;
    }

    let known: HashSet<&str> = ordered_names.iter().copied().collect();
    let mut in_deg: HashMap<&str, usize> = HashMap::with_capacity(ordered_names.len());
    let mut dependents: HashMap<&str, Vec<&str>> = ordered_names.iter().map(|&n| (n, Vec::new())).collect();
    let rank: HashMap<&str, usize> = ordered_names.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    for &n in &ordered_names {
        let mut deg = 0usize;
        if let Some(deps) = raw_deps.get(n) {
            for &d in deps {
                if known.contains(d) {
                    deg += 1;
                    if let Some(children) = dependents.get_mut(d) {
                        children.push(n);
                    }
                }
            }
        }
        in_deg.insert(n, deg);
    }

    let mut ready: Vec<&str> = ordered_names
        .iter()
        .copied()
        .filter(|n| *in_deg.get(n).unwrap_or(&0) == 0)
        .collect();
    ready.sort_by_key(|n| *rank.get(n).unwrap_or(&0));

    let mut waves: Vec<String> = Vec::new();
    let mut visited = 0usize;

    while !ready.is_empty() {
        let current_wave = ready.clone();
        visited += current_wave.len();
        waves.push(current_wave.join("\t"));
        let mut next_ready: Vec<&str> = Vec::new();
        for done_node in current_wave {
            if let Some(children) = dependents.get(done_node) {
                for &child in children {
                    if let Some(deg) = in_deg.get_mut(child) {
                        *deg -= 1;
                        if *deg == 0 {
                            next_ready.push(child);
                        }
                    }
                }
            }
        }
        next_ready.sort_by_key(|n| *rank.get(n).unwrap_or(&0));
        ready = next_ready;
    }

    if visited != ordered_names.len() {
        let cyclic: Vec<&str> = ordered_names
            .into_iter()
            .filter(|n| *in_deg.get(n).unwrap_or(&0) > 0)
            .collect();
        let cyc_msg = cyclic.join(", ");
        let _ = write_c_buf(cyc_msg.as_bytes(), out_ptr, out_cap);
        return -1;
    }

    let encoded = waves.join("\n");
    if !write_c_buf(encoded.as_bytes(), out_ptr, out_cap) {
        return -2;
    }
    waves.len() as i32
}

#[inline]
fn match_ci_rs(slice: &[u8], lit_lower: &[u8]) -> bool {
    if slice.len() < lit_lower.len() {
        return false;
    }
    for (i, &lc) in lit_lower.iter().enumerate() {
        if slice[i].to_ascii_lowercase() != lc {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn spectre_rust_sast_prefilter_mask(data_ptr: *const u8, data_len: usize) -> u32 {
    if data_ptr.is_null() || data_len < 2 {
        return 0;
    }
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let mut mask = 0u32;
    for i in 0..data_len {
        let rem = &data[i..];
        match rem[0].to_ascii_lowercase() {
            b'=' => {
                if (mask & 1) == 0 && rem.len() >= 2 && rem[1] == b'=' { mask |= 1; }
            }
            b'!' => {
                if (mask & 1) == 0 && rem.len() >= 2 && rem[1] == b'=' { mask |= 1; }
            }
            b'e' => {
                if (mask & 1) == 0 && (match_ci_rs(rem, b"equals") || match_ci_rs(rem, b"ecb") || match_ci_rs(rem, b"extractall")) { mask |= 1; }
                if (mask & 8) == 0 && match_ci_rs(rem, b"environ") { mask |= 8; }
            }
            b'v' => {
                if (mask & 9) != 9 && match_ci_rs(rem, b"verify") { mask |= 1 | 8; }
            }
            b'a' => {
                if (mask & 1) == 0 && match_ci_rs(rem, b"algorithms") { mask |= 1; }
                if (mask & 8) == 0 && match_ci_rs(rem, b"allow_all") { mask |= 8; }
            }
            b'p' => {
                if (mask & 1) == 0 && match_ci_rs(rem, b"parseclaimsjwt") { mask |= 1; }
                if (mask & 2) == 0 && (match_ci_rs(rem, b"postmapping") || match_ci_rs(rem, b"putmapping") || match_ci_rs(rem, b"patchmapping")) { mask |= 2; }
                if (mask & 8) == 0 && match_ci_rs(rem, b"process.env") { mask |= 8; }
            }
            b'i' => {
                if (mask & 1) == 0 && match_ci_rs(rem, b"insecureignoresignature") { mask |= 1; }
            }
            b'.' => {
                if (mask & 2) == 0 && (match_ci_rs(rem, b".post(") || match_ci_rs(rem, b".put(") || match_ci_rs(rem, b".delete(") || match_ci_rs(rem, b".patch(")) { mask |= 2; }
            }
            b'd' => {
                if (mask & 2) == 0 && match_ci_rs(rem, b"deletemapping") { mask |= 2; }
                if (mask & 8) == 0 && match_ci_rs(rem, b"debug") { mask |= 8; }
            }
            b'r' => {
                if (mask & 2) == 0 && match_ci_rs(rem, b"route::") { mask |= 2; }
            }
            b'[' => {
                if (mask & 2) == 0 && match_ci_rs(rem, b"[http") { mask |= 2; }
            }
            b'b' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"balance") { mask |= 4; }
            }
            b'w' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"wallet") { mask |= 4; }
            }
            b'c' => {
                if (mask & 4) == 0 && (match_ci_rs(rem, b"credit") || match_ci_rs(rem, b"coupon_count")) { mask |= 4; }
                if (mask & 8) == 0 && (match_ci_rs(rem, b"config") || match_ci_rs(rem, b"cors")) { mask |= 8; }
            }
            b'q' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"quota") { mask |= 4; }
            }
            b's' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"stock") { mask |= 4; }
                if (mask & 8) == 0 && match_ci_rs(rem, b"ssl") { mask |= 8; }
            }
            b'g' => {
                if (mask & 8) == 0 && match_ci_rs(rem, b"getenv") { mask |= 8; }
            }
            b't' => {
                if (mask & 8) == 0 && match_ci_rs(rem, b"tls") { mask |= 8; }
            }
            _ => {}
        }
        if mask == 0x0F { break; }
    }
    mask
}

#[no_mangle]
pub extern "C" fn spectre_rust_cvss31_score(vec_ptr: *const u8, vec_len: usize) -> f64 {
    if vec_ptr.is_null() || vec_len == 0 {
        return 0.0;
    }
    let raw_bytes = unsafe { slice::from_raw_parts(vec_ptr, vec_len) };
    let vec_str = match std::str::from_utf8(raw_bytes) {
        Ok(s) => s.trim(),
        Err(_) => return 0.0,
    };

    let (mut av, mut ac, mut ui, mut c_w, mut i_w, mut a_w): (f64, f64, f64, f64, f64, f64) =
        (-1.0, -1.0, -1.0, -1.0, -1.0, -1.0);
    let (mut pr_tok, mut scope_tok) = (0u8, 0u8);

    for tok in vec_str.split('/') {
        if let Some((k_raw, v_raw)) = tok.split_once(':') {
            if k_raw.eq_ignore_ascii_case("CVSS") {
                continue;
            }
            let v_up = v_raw.trim().as_bytes().first().map(|b| b.to_ascii_uppercase()).unwrap_or(0);
            if k_raw.eq_ignore_ascii_case("AV") {
                av = match v_up { b'N' => 0.85, b'A' => 0.62, b'L' => 0.55, b'P' => 0.20, _ => return 0.0 };
            } else if k_raw.eq_ignore_ascii_case("AC") {
                ac = match v_up { b'L' => 0.77, b'H' => 0.44, _ => return 0.0 };
            } else if k_raw.eq_ignore_ascii_case("PR") {
                if matches!(v_up, b'N' | b'L' | b'H') { pr_tok = v_up; } else { return 0.0; }
            } else if k_raw.eq_ignore_ascii_case("UI") {
                ui = match v_up { b'N' => 0.85, b'R' => 0.62, _ => return 0.0 };
            } else if k_raw.eq_ignore_ascii_case("S") {
                if matches!(v_up, b'U' | b'C') { scope_tok = v_up; } else { return 0.0; }
            } else if k_raw.eq_ignore_ascii_case("C") {
                c_w = match v_up { b'H' => 0.56, b'L' => 0.22, b'N' => 0.0, _ => return 0.0 };
            } else if k_raw.eq_ignore_ascii_case("I") {
                i_w = match v_up { b'H' => 0.56, b'L' => 0.22, b'N' => 0.0, _ => return 0.0 };
            } else if k_raw.eq_ignore_ascii_case("A") {
                a_w = match v_up { b'H' => 0.56, b'L' => 0.22, b'N' => 0.0, _ => return 0.0 };
            }
        }
    }

    if av < 0.0 || ac < 0.0 || ui < 0.0 || c_w < 0.0 || i_w < 0.0 || a_w < 0.0 || pr_tok == 0 || scope_tok == 0 {
        return 0.0;
    }
    let scope_changed = scope_tok == b'C';
    let pr = match pr_tok {
        b'N' => 0.85,
        b'L' => if scope_changed { 0.68 } else { 0.62 },
        b'H' => if scope_changed { 0.50 } else { 0.27 },
        _ => return 0.0,
    };

    let iss = 1.0 - ((1.0 - c_w) * (1.0 - i_w) * (1.0 - a_w));
    if iss <= 0.0 {
        return 0.0;
    }
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw: f64 = if scope_changed {
        (1.08_f64 * (impact + exploitability)).min(10.0_f64)
    } else {
        (impact + exploitability).min(10.0_f64)
    };
    (((raw * 100_000.0_f64).round()) / 10_000.0_f64).ceil() / 10.0_f64
}

#[no_mangle]
pub extern "C" fn spectre_rust_is_valid_dns_label(ptr: *const u8, len: usize) -> i32 {
    if ptr.is_null() || len == 0 || len > 63 {
        return 0;
    }
    let s = unsafe { slice::from_raw_parts(ptr, len) };
    if s[0] == b'-' || s[len - 1] == b'-' {
        return 0;
    }
    for &b in s {
        let low = b.to_ascii_lowercase();
        if !(low.is_ascii_lowercase() || low.is_ascii_digit() || low == b'-') {
            return 0;
        }
    }
    1
}

#[no_mangle]
pub extern "C" fn spectre_rust_tech_fingerprint_mask(data_ptr: *const u8, data_len: usize) -> u32 {
    if data_ptr.is_null() || data_len < 4 {
        return 0;
    }
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let mut mask = 0u32;
    for i in 0..data_len {
        let rem = &data[i..];
        match rem[0].to_ascii_lowercase() {
            b'c' => {
                if (mask & 1) == 0 && (match_ci_rs(rem, b"cf-ray") || match_ci_rs(rem, b"cloudflare") || match_ci_rs(rem, b"cloudfront")) { mask |= 1; }
                if (mask & 4) == 0 && match_ci_rs(rem, b"csrftoken") { mask |= 4; }
            }
            b'x' => {
                if (mask & 1) == 0 && (match_ci_rs(rem, b"x-amz-cf-id") || match_ci_rs(rem, b"x-fastly") || match_ci_rs(rem, b"x-akamai")) { mask |= 1; }
                if (mask & 64) == 0 && (match_ci_rs(rem, b"x-kong-") || match_ci_rs(rem, b"x-envoy-")) { mask |= 64; }
                if (mask & 256) == 0 && match_ci_rs(rem, b"x-litellm-") { mask |= 256; }
            }
            b'_' => {
                if (mask & 2) == 0 && (match_ci_rs(rem, b"__next_data__") || match_ci_rs(rem, b"__nuxt__")) { mask |= 2; }
                if (mask & 128) == 0 && match_ci_rs(rem, b"_gitlab_session") { mask |= 128; }
            }
            b'/' => {
                if (mask & 2) == 0 && (match_ci_rs(rem, b"/_next/static/") || match_ci_rs(rem, b"/_nuxt/")) { mask |= 2; }
                if (mask & 8) == 0 && (match_ci_rs(rem, b"/wp-content/") || match_ci_rs(rem, b"/wp-includes/") || match_ci_rs(rem, b"/bitrix/")) { mask |= 8; }
            }
            b'l' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"laravel_session") { mask |= 4; }
            }
            b'j' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"jsessionid") { mask |= 4; }
                if (mask & 8) == 0 && match_ci_rs(rem, b"joomla!") { mask |= 8; }
            }
            b'k' => {
                if (mask & 16) == 0 && match_ci_rs(rem, b"keycloak") { mask |= 16; }
            }
            b's' => {
                if (mask & 32) == 0 && match_ci_rs(rem, b"supabase.co") { mask |= 32; }
            }
            b'g' => {
                if (mask & 128) == 0 && match_ci_rs(rem, b"grafanabootdata") { mask |= 128; }
            }
            b'a' => {
                if (mask & 4) == 0 && match_ci_rs(rem, b"asp.net_sessionid") { mask |= 4; }
                if (mask & 16) == 0 && match_ci_rs(rem, b"auth_session_id") { mask |= 16; }
                if (mask & 64) == 0 && match_ci_rs(rem, b"apisix") { mask |= 64; }
                if (mask & 128) == 0 && match_ci_rs(rem, b"atlassian.xsrf") { mask |= 128; }
            }
            _ => {}
        }
        if mask == 0x1FF {
            break;
        }
    }
    mask
}


