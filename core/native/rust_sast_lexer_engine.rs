// SPECTRE 6-Language State-Machine SAST Lexer & Scope Analyzer (ABI v950)
// SPDX-License-Identifier: Apache-2.0
// Grammar-aware comment stripper and scope depth analyzer across Python,
// JavaScript, TypeScript, Go, Java, and PHP while preserving exact line numbers.

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SourceLang {
    Python,
    JsTs,
    Go,
    Java,
    Php,
}

impl SourceLang {
    pub fn from_tag_or_sniff(tag: &[u8], src: &[u8]) -> Self {
        if !tag.is_empty() {
            if tag.eq_ignore_ascii_case(b"py") || tag.eq_ignore_ascii_case(b"python") {
                return Self::Python;
            }
            if tag.eq_ignore_ascii_case(b"js")
                || tag.eq_ignore_ascii_case(b"ts")
                || tag.eq_ignore_ascii_case(b"javascript")
                || tag.eq_ignore_ascii_case(b"typescript")
            {
                return Self::JsTs;
            }
            if tag.eq_ignore_ascii_case(b"go") || tag.eq_ignore_ascii_case(b"golang") {
                return Self::Go;
            }
            if tag.eq_ignore_ascii_case(b"java") {
                return Self::Java;
            }
            if tag.eq_ignore_ascii_case(b"php") {
                return Self::Php;
            }
        }
        sniff_language(src)
    }
}

fn sniff_language(src: &[u8]) -> SourceLang {
    let win = if src.len() > 4096 { &src[..4096] } else { src };
    if contains_subslice(win, b"<?php") || contains_subslice(win, b"$_GET") || contains_subslice(win, b"$_POST") {
        return SourceLang::Php;
    }
    if contains_subslice(win, b"package ") && contains_subslice(win, b"func ") {
        return SourceLang::Go;
    }
    if contains_subslice(win, b"public class ") || contains_subslice(win, b"import java.") {
        return SourceLang::Java;
    }
    if contains_subslice(win, b"def ") || contains_subslice(win, b"import ") && contains_subslice(win, b":\n") {
        return SourceLang::Python;
    }
    if !win.is_empty() && win[0] == b'#' && !win.starts_with(b"#!") {
        return SourceLang::Python;
    }
    SourceLang::JsTs
}

#[inline]
fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[inline]
pub fn fnv1a64_ascii_lower(tok: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in tok {
        let c = if b.is_ascii_uppercase() { b + 32 } else { b };
        h ^= c as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[inline]
fn can_start_js_regex(prev_non_ws: u8) -> bool {
    matches!(
        prev_non_ws,
        0 | b'(' | b',' | b'=' | b':' | b'[' | b'!' | b'&' | b'|' | b'?' | b'{' | b'}' | b';' | b'\n'
    )
}

fn strip_python(src: &[u8]) -> Vec<u8> {
    let n = src.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        let b = src[i];
        if (b == b'\'' || b == b'"') && i + 2 < n && src[i + 1] == b && src[i + 2] == b {
            let q = b;
            out.extend_from_slice(&src[i..i + 3]);
            i += 3;
            while i < n {
                if src[i] == b'\\' && i + 1 < n {
                    out.push(src[i]);
                    out.push(src[i + 1]);
                    i += 2;
                    continue;
                }
                if i + 2 < n && src[i] == q && src[i + 1] == q && src[i + 2] == q {
                    out.extend_from_slice(&src[i..i + 3]);
                    i += 3;
                    break;
                }
                out.push(src[i]);
                i += 1;
            }
            continue;
        }
        if b == b'\'' || b == b'"' {
            let q = b;
            out.push(q);
            i += 1;
            while i < n && src[i] != b'\n' {
                if src[i] == b'\\' && i + 1 < n {
                    out.push(src[i]);
                    out.push(src[i + 1]);
                    i += 2;
                    continue;
                }
                out.push(src[i]);
                if src[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b == b'#' {
            while i < n && src[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

fn strip_c_like(src: &[u8], lang: SourceLang) -> Vec<u8> {
    let n = src.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;
    let mut prev_non_ws: u8 = 0;
    let mut tpl_brace_stack: Vec<u32> = Vec::new();

    if i + 1 < n && src[0] == b'#' && src[1] == b'!' {
        while i < n && src[i] != b'\n' {
            out.push(b' ');
            i += 1;
        }
    }

    while i < n {
        let b = src[i];

        if lang == SourceLang::Java && b == b'"' && i + 2 < n && src[i + 1] == b'"' && src[i + 2] == b'"' {
            out.extend_from_slice(b"\"\"\"");
            i += 3;
            while i < n {
                if src[i] == b'\\' && i + 1 < n {
                    out.push(src[i]);
                    out.push(src[i + 1]);
                    i += 2;
                    continue;
                }
                if i + 2 < n && src[i] == b'"' && src[i + 1] == b'"' && src[i + 2] == b'"' {
                    out.extend_from_slice(b"\"\"\"");
                    i += 3;
                    break;
                }
                out.push(src[i]);
                i += 1;
            }
            prev_non_ws = b'"';
            continue;
        }

        if b == b'/' && i + 1 < n && src[i + 1] == b'/' {
            while i < n && src[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }

        if b == b'/' && i + 1 < n && src[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < n {
                if i + 1 < n && src[i] == b'*' && src[i + 1] == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    break;
                }
                out.push(if src[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            continue;
        }

        if lang == SourceLang::Php && b == b'#' && !(i + 1 < n && src[i + 1] == b'[') {
            while i < n && src[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }

        if b == b'\'' || b == b'"' {
            let q = b;
            out.push(q);
            i += 1;
            while i < n {
                if src[i] == b'\\' && i + 1 < n {
                    out.push(src[i]);
                    out.push(src[i + 1]);
                    i += 2;
                    continue;
                }
                if src[i] == b'\n' && lang != SourceLang::Php {
                    break;
                }
                out.push(src[i]);
                if src[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            prev_non_ws = q;
            continue;
        }

        if lang == SourceLang::Go && b == b'`' {
            out.push(b'`');
            i += 1;
            while i < n {
                out.push(src[i]);
                if src[i] == b'`' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            prev_non_ws = b'`';
            continue;
        }

        if lang == SourceLang::JsTs && b == b'`' {
            out.push(b'`');
            i += 1;
            i = consume_js_template_segment(src, i, &mut out, &mut tpl_brace_stack);
            prev_non_ws = b'`';
            continue;
        }

        if lang == SourceLang::JsTs && b == b'{' && !tpl_brace_stack.is_empty() {
            if let Some(top) = tpl_brace_stack.last_mut() {
                *top = top.saturating_add(1);
            }
        } else if lang == SourceLang::JsTs && b == b'}' && !tpl_brace_stack.is_empty() {
            let resume_tpl = match tpl_brace_stack.last_mut() {
                Some(top) if *top == 0 => true,
                Some(top) => {
                    *top -= 1;
                    false
                }
                None => false,
            };
            if resume_tpl {
                let _ = tpl_brace_stack.pop();
                out.push(b'}');
                i += 1;
                i = consume_js_template_segment(src, i, &mut out, &mut tpl_brace_stack);
                prev_non_ws = b'`';
                continue;
            }
        }

        if lang == SourceLang::JsTs && b == b'/' && can_start_js_regex(prev_non_ws) {
            out.push(b'/');
            i += 1;
            let mut in_class = false;
            while i < n && src[i] != b'\n' {
                if src[i] == b'\\' && i + 1 < n {
                    out.push(src[i]);
                    out.push(src[i + 1]);
                    i += 2;
                    continue;
                }
                if src[i] == b'[' {
                    in_class = true;
                } else if src[i] == b']' {
                    in_class = false;
                } else if src[i] == b'/' && !in_class {
                    out.push(b'/');
                    i += 1;
                    break;
                }
                out.push(src[i]);
                i += 1;
            }
            prev_non_ws = b'/';
            continue;
        }

        out.push(b);
        if !b.is_ascii_whitespace() {
            prev_non_ws = b;
        }
        i += 1;
    }
    out
}

fn consume_js_template_segment(
    src: &[u8],
    mut i: usize,
    out: &mut Vec<u8>,
    tpl_brace_stack: &mut Vec<u32>,
) -> usize {
    let n = src.len();
    while i < n {
        if src[i] == b'\\' && i + 1 < n {
            out.push(src[i]);
            out.push(src[i + 1]);
            i += 2;
            continue;
        }
        if src[i] == b'$' && i + 1 < n && src[i + 1] == b'{' {
            out.push(b'$');
            out.push(b'{');
            tpl_brace_stack.push(0);
            return i + 2;
        }
        out.push(src[i]);
        if src[i] == b'`' {
            return i + 1;
        }
        i += 1;
    }
    i
}

pub fn strip_comments_for_lang(src: &[u8], lang: SourceLang) -> Vec<u8> {
    match lang {
        SourceLang::Python => strip_python(src),
        other => strip_c_like(src, other),
    }
}

pub fn strip_comments_preserve_lines(src: &[u8]) -> Vec<u8> {
    let lang = sniff_language(src);
    strip_comments_for_lang(src, lang)
}

fn python_indent_max_depth(cleaned: &[u8]) -> u32 {
    let mut stack: Vec<usize> = vec![0];
    let mut max_depth: u32 = 0;
    let mut bracket_lvl: u32 = 0;

    for line in cleaned.split(|&b| b == b'\n') {
        let mut spaces = 0usize;
        let mut idx = 0usize;
        while idx < line.len() {
            match line[idx] {
                b' ' => spaces += 1,
                b'\t' => spaces += 4,
                b'\r' => {}
                _ => break,
            }
            idx += 1;
        }
        let rest = &line[idx..];
        if rest.is_empty() {
            continue;
        }
        if bracket_lvl == 0 {
            let cur = stack.last().copied().unwrap_or(0);
            if spaces > cur {
                stack.push(spaces);
                let d = (stack.len().saturating_sub(1)) as u32;
                if d > max_depth {
                    max_depth = d;
                }
            } else if spaces < cur {
                while stack.len() > 1 && stack.last().copied().unwrap_or(0) > spaces {
                    let _ = stack.pop();
                }
            }
        }
        for &ch in rest {
            match ch {
                b'(' | b'[' | b'{' => bracket_lvl = bracket_lvl.saturating_add(1),
                b')' | b']' | b'}' => bracket_lvl = bracket_lvl.saturating_sub(1),
                _ => {}
            }
        }
    }
    max_depth
}

pub fn lexical_scope_metrics_for_lang(src: &[u8], lang: SourceLang) -> (u32, u32, u64) {
    let cleaned = strip_comments_for_lang(src, lang);
    let mut token_count: u32 = 0;
    let mut cur_depth: u32 = 0;
    let mut max_depth: u32 = if lang == SourceLang::Python {
        python_indent_max_depth(&cleaned)
    } else {
        0
    };
    let mut rolling_sig: u64 = 0xcbf29ce484222325;
    let mut i = 0usize;
    let n = cleaned.len();

    while i < n {
        let b = cleaned[i];
        if lang != SourceLang::Python && b == b'{' {
            cur_depth = cur_depth.saturating_add(1);
            if cur_depth > max_depth {
                max_depth = cur_depth;
            }
            i += 1;
            continue;
        }
        if lang != SourceLang::Python && b == b'}' {
            cur_depth = cur_depth.saturating_sub(1);
            i += 1;
            continue;
        }
        if b.is_ascii_alphabetic() || b == b'_' || b == b'$' {
            let start = i;
            i += 1;
            while i < n && (cleaned[i].is_ascii_alphanumeric() || cleaned[i] == b'_' || cleaned[i] == b'.') {
                i += 1;
            }
            token_count = token_count.saturating_add(1);
            let h = fnv1a64_ascii_lower(&cleaned[start..i]);
            rolling_sig ^= h.rotate_left((cur_depth & 31) as u32);
            continue;
        }
        i += 1;
    }
    (token_count, max_depth, rolling_sig)
}

pub fn lexical_scope_metrics(src: &[u8]) -> (u32, u32, u64) {
    let lang = sniff_language(src);
    lexical_scope_metrics_for_lang(src, lang)
}
