"""
SPECTRE Hybrid C++17 Native Bridge (`libspectre_accel.so`)
==========================================================
Auto-compiles `core/native/spectre_accel.cpp` via `g++ -O3 -std=c++17` with
OpenSSL (`-lssl -lcrypto`) and Linux `epoll` on first import, exposing fast C++
routines via `ctypes` with deterministic pure-Python fallbacks.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import math
import shutil
import subprocess
import threading
from pathlib import Path

NATIVE_DIR = Path(__file__).resolve().parent / "native"
CPP_SRC = NATIVE_DIR / "spectre_accel.cpp"
SO_PATH = NATIVE_DIR / "libspectre_accel.so"
RUST_SRC = NATIVE_DIR / "spectre_rust_core.rs"
RUST_SO_PATH = NATIVE_DIR / "libspectre_rust_core.so"
GO_SRC = NATIVE_DIR / "spectre_intel_indexer.go"
GO_BIN_PATH = NATIVE_DIR / "spectre-intel-indexer"
_BUILD_LOCK = threading.Lock()
_LIB: ctypes.CDLL | None = None
_TRIED_LOAD = False
_RUST_LIB: ctypes.CDLL | None = None
_TRIED_RUST_LOAD = False
_GO_BIN: Path | None = None
_TRIED_GO_BUILD = False


JS_TOK_ROUTE = 1
JS_TOK_SINK = 2
JS_TOK_SECRET = 4
JS_TOK_CHUNK = 8
JS_TOK_SOURCEMAP = 16

SEC_MASK_CLOUD_IAM = 1
SEC_MASK_VCS_CICD = 2
SEC_MASK_SAAS_PAYMENT = 4
SEC_MASK_AI_LLM = 8
SEC_MASK_CRYPTO_JWT = 16

SAST_MASK_SHARP_EDGES = 1
SAST_MASK_ENTRY_POINT = 2
SAST_MASK_TOCTOU = 4
SAST_MASK_FAIL_OPEN = 8

NVT_SIG_ACTUATOR_METRICS = 1
NVT_SIG_VCS_ENV_CONFIG = 2
NVT_SIG_GRAPHQL_OPENAPI = 4
NVT_SIG_AI_MCP_VECTOR = 8
NVT_SIG_DEBUG_STATUS = 16


def _resolve_rustc_bin() -> str | None:
    found = shutil.which("rustc")
    if found:
        return found
    cargo_rustc = Path.home() / ".cargo" / "bin" / "rustc"
    return str(cargo_rustc) if cargo_rustc.is_file() else None


def get_native_lib() -> ctypes.CDLL | None:
    global _LIB, _TRIED_LOAD
    if _TRIED_LOAD:
        return _LIB
    with _BUILD_LOCK:
        if _TRIED_LOAD:
            return _LIB
        _TRIED_LOAD = True
        try:
            cpp_files = sorted(NATIVE_DIR.glob("*.cpp"))
            need_build = (not SO_PATH.exists()) or any(p.stat().st_mtime > SO_PATH.stat().st_mtime for p in cpp_files)
            if need_build and cpp_files and shutil.which("g++"):
                subprocess.run(
                    [
                        "g++", "-O3", "-Wall", "-Wextra",
                        "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong",
                        "-std=c++17", "-shared", "-fPIC", "-pthread",
                        *[str(p) for p in cpp_files],
                        "-o", str(SO_PATH), "-lssl", "-lcrypto",
                    ],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40, check=True,
                )
            if SO_PATH.exists():
                lib = ctypes.CDLL(str(SO_PATH))
                lib.spectre_mmh3_32.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32]
                lib.spectre_mmh3_32.restype = ctypes.c_uint32
                lib.spectre_shannon_entropy.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                lib.spectre_shannon_entropy.restype = ctypes.c_double
                lib.spectre_simhash64.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                lib.spectre_simhash64.restype = ctypes.c_uint64
                lib.spectre_jwt_verify_wordlist.argtypes = [
                    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                    ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
                ]
                lib.spectre_jwt_verify_wordlist.restype = ctypes.c_int
                lib.spectre_epoll_tcp_probe.argtypes = [
                    ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_size_t,
                    ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t,
                ]
                lib.spectre_epoll_tcp_probe.restype = ctypes.c_int
                if hasattr(lib, "spectre_js_token_mask"):
                    lib.spectre_js_token_mask.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.spectre_js_token_mask.restype = ctypes.c_uint32
                if hasattr(lib, "spectre_hamming64"):
                    lib.spectre_hamming64.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
                    lib.spectre_hamming64.restype = ctypes.c_int
                if hasattr(lib, "spectre_structural_hash"):
                    lib.spectre_structural_hash.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.spectre_structural_hash.restype = ctypes.c_uint64
                if hasattr(lib, "spectre_secret_prefilter_mask"):
                    lib.spectre_secret_prefilter_mask.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.spectre_secret_prefilter_mask.restype = ctypes.c_uint32
                if hasattr(lib, "spectre_cpp_abi_version"):
                    lib.spectre_cpp_abi_version.argtypes = []
                    lib.spectre_cpp_abi_version.restype = ctypes.c_uint32
                if hasattr(lib, "spectre_dual_baseline_threshold"):
                    lib.spectre_dual_baseline_threshold.argtypes = [ctypes.c_int, ctypes.c_int]
                    lib.spectre_dual_baseline_threshold.restype = ctypes.c_int
                if hasattr(lib, "spectre_nvt_body_sig_mask"):
                    lib.spectre_nvt_body_sig_mask.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.spectre_nvt_body_sig_mask.restype = ctypes.c_uint32
                if hasattr(lib, "spectre_fnv1a64_ci"):
                    lib.spectre_fnv1a64_ci.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.spectre_fnv1a64_ci.restype = ctypes.c_uint64
                if hasattr(lib, "spectre_cpp_nvt_rodata_count"):
                    lib.spectre_cpp_nvt_rodata_count.argtypes = []
                    lib.spectre_cpp_nvt_rodata_count.restype = ctypes.c_uint32
                if hasattr(lib, "spectre_cpp_lookup_favicon_mmh3"):
                    lib.spectre_cpp_lookup_favicon_mmh3.argtypes = [ctypes.c_int32, ctypes.c_char_p, ctypes.c_size_t]
                    lib.spectre_cpp_lookup_favicon_mmh3.restype = ctypes.c_int
                if hasattr(lib, "spectre_cpp_mad_latency_us"):
                    lib.spectre_cpp_mad_latency_us.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t]
                    lib.spectre_cpp_mad_latency_us.restype = ctypes.c_double
                if hasattr(lib, "spectre_cpp_idempotency_drift_score"):
                    lib.spectre_cpp_idempotency_drift_score.argtypes = [
                        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.c_size_t,
                    ]
                    lib.spectre_cpp_idempotency_drift_score.restype = ctypes.c_int
                if hasattr(lib, "spectre_cpp_barrier_selftest"):
                    lib.spectre_cpp_barrier_selftest.argtypes = [
                        ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                    ]
                    lib.spectre_cpp_barrier_selftest.restype = ctypes.c_int
                _LIB = lib
        except Exception:
            _LIB = None
    return _LIB


def get_rust_lib() -> ctypes.CDLL | None:
    global _RUST_LIB, _TRIED_RUST_LOAD
    if _TRIED_RUST_LOAD:
        return _RUST_LIB
    with _BUILD_LOCK:
        if _TRIED_RUST_LOAD:
            return _RUST_LIB
        _TRIED_RUST_LOAD = True
        try:
            rs_files = sorted(NATIVE_DIR.glob("*.rs"))
            need_build = (not RUST_SO_PATH.exists()) or any(p.stat().st_mtime > RUST_SO_PATH.stat().st_mtime for p in rs_files)
            rustc_bin = _resolve_rustc_bin()
            if need_build and RUST_SRC.exists() and rustc_bin:
                subprocess.run(
                    [rustc_bin, "-C", "opt-level=3", "-C", "strip=debuginfo", "--crate-type", "cdylib", str(RUST_SRC), "-o", str(RUST_SO_PATH)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=True,
                )
            if RUST_SO_PATH.exists():
                rlib = ctypes.CDLL(str(RUST_SO_PATH))
                rlib.spectre_rust_abi_version.argtypes = []
                rlib.spectre_rust_abi_version.restype = ctypes.c_uint32
                rlib.spectre_rust_compare_distro_versions.argtypes = [
                    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                ]
                rlib.spectre_rust_compare_distro_versions.restype = ctypes.c_int32
                rlib.spectre_rust_topological_waves.argtypes = [
                    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                ]
                rlib.spectre_rust_topological_waves.restype = ctypes.c_int32
                rlib.spectre_rust_sast_prefilter_mask.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                rlib.spectre_rust_sast_prefilter_mask.restype = ctypes.c_uint32
                rlib.spectre_rust_cvss31_score.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                rlib.spectre_rust_cvss31_score.restype = ctypes.c_double
                if hasattr(rlib, "spectre_rust_tech_fingerprint_mask"):
                    rlib.spectre_rust_tech_fingerprint_mask.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    rlib.spectre_rust_tech_fingerprint_mask.restype = ctypes.c_uint32
                if hasattr(rlib, "spectre_rust_is_valid_dns_label"):
                    rlib.spectre_rust_is_valid_dns_label.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    rlib.spectre_rust_is_valid_dns_label.restype = ctypes.c_int32
                if hasattr(rlib, "spectre_rust_kev_cve_count"):
                    rlib.spectre_rust_kev_cve_count.argtypes = []
                    rlib.spectre_rust_kev_cve_count.restype = ctypes.c_uint32
                if hasattr(rlib, "spectre_rust_cpe_count"):
                    rlib.spectre_rust_cpe_count.argtypes = []
                    rlib.spectre_rust_cpe_count.restype = ctypes.c_uint32
                if hasattr(rlib, "spectre_rust_lookup_cve_json"):
                    rlib.spectre_rust_lookup_cve_json.argtypes = [
                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                    ]
                    rlib.spectre_rust_lookup_cve_json.restype = ctypes.c_int32
                if hasattr(rlib, "spectre_rust_consolidate_cpe_json"):
                    rlib.spectre_rust_consolidate_cpe_json.argtypes = [
                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                    ]
                    rlib.spectre_rust_consolidate_cpe_json.restype = ctypes.c_int32
                if hasattr(rlib, "spectre_rust_strip_comments"):
                    rlib.spectre_rust_strip_comments.argtypes = [
                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                    ]
                    rlib.spectre_rust_strip_comments.restype = ctypes.c_int32
                if hasattr(rlib, "spectre_rust_strip_comments_lang"):
                    rlib.spectre_rust_strip_comments_lang.argtypes = [
                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                        ctypes.c_char_p, ctypes.c_size_t,
                    ]
                    rlib.spectre_rust_strip_comments_lang.restype = ctypes.c_int32
                if hasattr(rlib, "spectre_rust_triage_brocards_score"):
                    rlib.spectre_rust_triage_brocards_score.argtypes = [
                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int32,
                    ]
                    rlib.spectre_rust_triage_brocards_score.restype = ctypes.c_int32
                _RUST_LIB = rlib
        except Exception:
            _RUST_LIB = None
    return _RUST_LIB


def fast_mmh3_signed(data: bytes, seed: int = 0) -> int:
    lib = get_native_lib()
    if lib is not None:
        h = int(lib.spectre_mmh3_32(data, len(data), seed))
        return h - 0x100000000 if h >= 0x80000000 else h
    return int.from_bytes(hashlib.md5(data).digest()[:4], "little", signed=True)


def fast_shannon_entropy(text_or_bytes: str | bytes) -> float:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if not b:
        return 0.0
    lib = get_native_lib()
    if lib is not None:
        return float(lib.spectre_shannon_entropy(b, len(b)))
    counts: dict[int, int] = {}
    for ch in b:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(b))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def fast_simhash64(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if not b:
        return 0
    lib = get_native_lib()
    if lib is not None:
        return int(lib.spectre_simhash64(b, len(b)))
    return int.from_bytes(hashlib.blake2b(b[:8192], digest_size=8).digest(), "little")


def fast_jwt_hmac_audit(signing_input: bytes, raw_sig: bytes, alg: str, candidates: list[str] | tuple[str, ...]) -> str | None:
    bits = {"hs256": 256, "hs384": 384, "hs512": 512}.get(alg.lower(), 0)
    if not bits or not signing_input or not raw_sig or not candidates:
        return None
    lib = get_native_lib()
    if lib is not None:
        joined = ("\n".join(candidates) + "\n").encode("utf-8", errors="ignore")
        out_buf = ctypes.create_string_buffer(256)
        found = lib.spectre_jwt_verify_wordlist(
            signing_input, len(signing_input), raw_sig, len(raw_sig), bits, joined, out_buf, 256
        )
        return out_buf.value.decode("utf-8", errors="ignore") if found == 1 else None
    digest_fn = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}[bits]
    for cand in candidates:
        if hmac.compare_digest(hmac.new(cand.encode("utf-8"), signing_input, digest_fn).digest(), raw_sig):
            return cand
    return None


def fast_epoll_tcp_probe(ip_addr: str, ports: list[int], timeout_ms: int = 900) -> dict[int, bytes]:
    if not ip_addr or not ports:
        return {}
    lib = get_native_lib()
    if lib is None:
        return {}
    arr_t = ctypes.c_int * len(ports)
    c_ports = arr_t(*[int(p) for p in ports])
    out_cap = max(4096, len(ports) * 300)
    out_buf = ctypes.create_string_buffer(out_cap)
    lib.spectre_epoll_tcp_probe(ip_addr.encode("ascii", errors="ignore"), c_ports, len(ports), int(timeout_ms), out_buf, out_cap)
    discovered: dict[int, bytes] = {}
    for ln in out_buf.value.decode("ascii", errors="ignore").splitlines():
        if ":" in ln:
            p_s, hx_s = ln.split(":", 1)
            if p_s.isdigit():
                try:
                    discovered[int(p_s)] = bytes.fromhex(hx_s.strip()) if hx_s.strip() else b""
                except Exception:
                    discovered[int(p_s)] = b""
    return discovered


def fast_js_token_mask(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if not b:
        return 0
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_js_token_mask"):
        return int(lib.spectre_js_token_mask(b, len(b)))
    low = b.lower()
    mask = 0
    if any(t in low for t in (b"/api/", b"/v1/", b"/v2/", b"/v3/", b"/graphql", b"/auth/", b"/admin/", b"/internal/", b"/live/", b"/stream/", b"/news/", b"/tv/", b"/radio/", b"/channels/", b"http://", b"https://", b"ws://", b"wss://", b".get", b".post", b".put", b".delete", b".patch")):
        mask |= JS_TOK_ROUTE
    if any(t in low for t in (b"innerhtml", b"outerhtml", b"document.write", b"eval", b"settimeout", b"postmessage", b"dangerouslysetinnerhtml")):
        mask |= JS_TOK_SINK
    if any(t in low for t in (b"api_key", b"apikey", b"api-key", b"access_token", b"accesstoken", b"access-token", b"secret_key", b"secretkey", b"secret-key", b"base_url", b"baseurl", b"vite_", b"authorization", b"bearer ")):
        mask |= JS_TOK_SECRET
    if b"assets/" in low or b"static/js/" in low:
        mask |= JS_TOK_CHUNK
    if b"sourcemappingurl=" in low or b'"sourcescontent"' in low:
        mask |= JS_TOK_SOURCEMAP
    return mask


def fast_hamming64(a: int, b: int) -> int:
    ua = int(a) & 0xFFFFFFFFFFFFFFFF
    ub = int(b) & 0xFFFFFFFFFFFFFFFF
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_hamming64"):
        return int(lib.spectre_hamming64(ua, ub))
    return (ua ^ ub).bit_count()


def fast_structural_hash(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if not b:
        return 0
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_structural_hash"):
        return int(lib.spectre_structural_hash(b, len(b)))
    import re as _re
    s = b.decode("utf-8", errors="ignore").lstrip()
    if not s:
        return 0
    if s[0] in "{[":
        keys = _re.findall(r'"([A-Za-z0-9_\-]{1,48})"\s*:', s)
        skel = "json:" + ",".join(k.lower() for k in keys)
    elif "<" in s[:512]:
        tags = _re.findall(r"<(/?[A-Za-z][A-Za-z0-9]{0,23})", s)
        skel = "html:" + ",".join(t.lower() for t in tags)
    else:
        skel = "txt:" + "".join(ch for ch in s if ch in "\n:=[]")
    return int.from_bytes(hashlib.blake2b(skel.encode("utf-8"), digest_size=8).digest(), "little")


def fast_secret_prefilter_mask(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if len(b) < 4:
        return 0
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_secret_prefilter_mask"):
        return int(lib.spectre_secret_prefilter_mask(b, len(b)))
    mask = 0
    if any(t in b for t in (b"AKIA", b"ASIA", b"AIza")):
        mask |= SEC_MASK_CLOUD_IAM
    if any(t in b for t in (b"ghp_", b"github_pat_", b"glpat-", b"npm_")):
        mask |= SEC_MASK_VCS_CICD
    if any(t in b for t in (b"sk_live_", b"rk_live_", b"xoxb-", b"xoxp-", b"SG.")):
        mask |= SEC_MASK_SAAS_PAYMENT
    if any(t in b for t in (b"sk-ant-", b"sk-proj-", b"hf_", b"gsk_")):
        mask |= SEC_MASK_AI_LLM
    if b"-----BEGIN " in b or b"eyJ" in b:
        mask |= SEC_MASK_CRYPTO_JWT
    return mask


def fast_dual_baseline_threshold(base_len: int, base_jitter: int) -> int:
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_dual_baseline_threshold"):
        return int(lib.spectre_dual_baseline_threshold(int(base_len), int(base_jitter)))
    return max(500, max(0, int(base_jitter)) * 4, int(max(0, int(base_len)) * 0.12))


def fast_nvt_body_sig_mask(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if len(b) < 4:
        return 0
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_nvt_body_sig_mask"):
        return int(lib.spectre_nvt_body_sig_mask(b, len(b)))
    low = b.lower()
    mask = 0
    if any(t in low for t in (b'"beans"', b'"propertysources"', b"process_cpu_seconds_total", b"# help ")):
        mask |= NVT_SIG_ACTUATOR_METRICS
    if any(t in low for t in (b"ref: refs/heads/", b"[core]", b"db_password", b"app_key=", b"aws_secret")):
        mask |= NVT_SIG_VCS_ENV_CONFIG
    if any(t in low for t in (b'"__schema"', b'"openapi"', b'"swagger"')):
        mask |= NVT_SIG_GRAPHQL_OPENAPI
    if any(t in low for t in (b'"models"', b'"jsonrpc"', b'"collections"', b"ollama")):
        mask |= NVT_SIG_AI_MCP_VECTOR
    if any(t in low for t in (b"phpinfo()", b"werkzeug", b"traceback", b"active connections:", b"server-status")):
        mask |= NVT_SIG_DEBUG_STATUS
    return mask


def fast_compare_distro_versions(v1: str, v2: str) -> int | None:
    rlib = get_rust_lib()
    if rlib is None:
        return None
    b1 = (v1 or "").encode("utf-8", errors="ignore")
    b2 = (v2 or "").encode("utf-8", errors="ignore")
    return int(rlib.spectre_rust_compare_distro_versions(b1, len(b1), b2, len(b2)))


def fast_topological_waves(task_specs: list[tuple[str, list[str]]]) -> list[list[str]] | None:
    rlib = get_rust_lib()
    if rlib is None:
        return None
    if not task_specs:
        return []
    lines = [f"{t_name}\t{','.join(deps)}" for t_name, deps in task_specs if t_name]
    payload = ("\n".join(lines) + "\n").encode("utf-8", errors="ignore")
    out_cap = max(4096, len(payload) * 2 + 256)
    out_buf = ctypes.create_string_buffer(out_cap)
    rc = int(rlib.spectre_rust_topological_waves(payload, len(payload), out_buf, out_cap))
    if rc == -1:
        cyc_str = out_buf.value.decode("utf-8", errors="ignore")
        raise ValueError(f"Cyclic plugin dependency detected: {cyc_str}")
    if rc < 0:
        return None
    if rc == 0:
        return []
    decoded = out_buf.value.decode("utf-8", errors="ignore")
    return [[tok for tok in ln.split("\t") if tok] for ln in decoded.splitlines() if ln]


def fast_sast_prefilter_mask(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if len(b) < 2:
        return 0
    rlib = get_rust_lib()
    if rlib is not None:
        return int(rlib.spectre_rust_sast_prefilter_mask(b, len(b)))
    return SAST_MASK_SHARP_EDGES | SAST_MASK_ENTRY_POINT | SAST_MASK_TOCTOU | SAST_MASK_FAIL_OPEN


def fast_cvss31_score(vector: str) -> float | None:
    rlib = get_rust_lib()
    if rlib is None:
        return None
    b = (vector or "").encode("utf-8", errors="ignore")
    if not b:
        return 0.0
    return float(rlib.spectre_rust_cvss31_score(b, len(b)))

def _resolve_go_bin() -> str | None:
    found = shutil.which("go")
    if found:
        return found
    for cand in (Path("/usr/local/go/bin/go"), Path("/usr/bin/go")):
        if cand.is_file():
            return str(cand)
    return None


def get_go_indexer_bin() -> Path | None:
    global _GO_BIN, _TRIED_GO_BUILD
    if _TRIED_GO_BUILD:
        return _GO_BIN
    with _BUILD_LOCK:
        if _TRIED_GO_BUILD:
            return _GO_BIN
        _TRIED_GO_BUILD = True
        try:
            go_files = sorted(NATIVE_DIR.glob("*.go"))
            need_build = (not GO_BIN_PATH.is_file()) or any(p.stat().st_mtime > GO_BIN_PATH.stat().st_mtime for p in go_files)
            go_bin = _resolve_go_bin()
            if need_build and go_files and go_bin:
                subprocess.run(
                    [go_bin, "build", "-ldflags=-s -w", "-o", str(GO_BIN_PATH), *[str(p) for p in go_files]],
                    cwd=str(NATIVE_DIR),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=45,
                    check=True,
                )
            if GO_BIN_PATH.is_file():
                _GO_BIN = GO_BIN_PATH
        except Exception:
            _GO_BIN = None
    return _GO_BIN


def fast_fnv1a64_ci(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if not b:
        return 0
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_fnv1a64_ci"):
        return int(lib.spectre_fnv1a64_ci(b, len(b)))
    h = 14695981039346656037
    for ch in b.lower():
        h = ((h ^ ch) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def fast_tech_fingerprint_mask(text_or_bytes: str | bytes) -> int:
    b = text_or_bytes.encode("utf-8", errors="ignore") if isinstance(text_or_bytes, str) else text_or_bytes
    if len(b) < 4:
        return 0
    rlib = get_rust_lib()
    if rlib is not None and hasattr(rlib, "spectre_rust_tech_fingerprint_mask"):
        return int(rlib.spectre_rust_tech_fingerprint_mask(b, len(b)))
    return 0x1FF


def fast_is_valid_dns_label(label: str) -> bool:
    b = (label or "").encode("utf-8", errors="ignore")
    if not b or len(b) > 63:
        return False
    rlib = get_rust_lib()
    if rlib is not None and hasattr(rlib, "spectre_rust_is_valid_dns_label"):
        return int(rlib.spectre_rust_is_valid_dns_label(b, len(b))) == 1
    return bool(b[0] != 45 and b[-1] != 45 and all((97 <= (c | 32) <= 122) or (48 <= c <= 57) or c == 45 for c in b))

def fast_rust_lookup_cve(cve_id: str) -> dict | None:
    import json as _json
    b = (cve_id or "").strip().encode("utf-8", errors="ignore")
    if not b:
        return None
    rlib = get_rust_lib()
    if rlib is None or not hasattr(rlib, "spectre_rust_lookup_cve_json"):
        return None
    out_buf = ctypes.create_string_buffer(2048)
    rc = int(rlib.spectre_rust_lookup_cve_json(b, len(b), out_buf, 2048))
    if rc == 1:
        try:
            return _json.loads(out_buf.value.decode("utf-8", errors="ignore"))
        except Exception:
            return None
    return None


def fast_cpp_lookup_favicon_mmh3(hash_val: int) -> str:
    lib = get_native_lib()
    if lib is None or not hasattr(lib, "spectre_cpp_lookup_favicon_mmh3"):
        return ""
    out_buf = ctypes.create_string_buffer(128)
    rc = int(lib.spectre_cpp_lookup_favicon_mmh3(int(hash_val), out_buf, 128))
    return out_buf.value.decode("utf-8", errors="ignore") if rc == 1 else ""


def fast_go_probe_sockets(
    host: str,
    disp_host: str,
    port_specs: list[tuple[int, int]],
    timeout_ms: int = 2400,
) -> list[dict] | None:
    import json as _json
    gobin = get_go_indexer_bin()
    if gobin is None or not host or not port_specs:
        return None
    spec_str = ",".join(f"{lp}:{cp}" if lp != cp else str(lp) for lp, cp in port_specs)
    try:
        proc = subprocess.run(
            [
                str(gobin),
                "-probe-host", str(host),
                "-disp-host", str(disp_host or host),
                "-probe-ports", spec_str,
                "-timeout-ms", str(int(timeout_ms)),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=max(8, int(timeout_ms / 1000) * 4),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parsed = _json.loads(proc.stdout.strip())
            return parsed if isinstance(parsed, list) else []
        if proc.returncode == 0:
            return []
    except Exception:
        return None
    return None


def fast_go_run_yaml_plugins(
    base_url: str,
    plugins_dir: str,
    kb_hints: str = "",
    timeout_ms: int = 3500,
) -> dict | None:
    import json as _json
    gobin = get_go_indexer_bin()
    if gobin is None or not base_url or not plugins_dir:
        return None
    try:
        proc = subprocess.run(
            [
                str(gobin),
                "-run-plugins", str(base_url),
                "-plugins-dir", str(plugins_dir),
                "-kb-hints", str(kb_hints),
                "-timeout-ms", str(int(timeout_ms)),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=25,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return _json.loads(proc.stdout.strip())
    except Exception:
        return None
    return None


def fast_rust_consolidate_cpe(observations: str) -> list[dict]:
    import json as _json
    b = (observations or "").strip().encode("utf-8", errors="ignore")
    if not b:
        return []
    rlib = get_rust_lib()
    if rlib is None or not hasattr(rlib, "spectre_rust_consolidate_cpe_json"):
        return []
    out_cap = max(8192, len(b) * 4)
    out_buf = ctypes.create_string_buffer(out_cap)
    rc = int(rlib.spectre_rust_consolidate_cpe_json(b, len(b), out_buf, out_cap))
    if rc == 1:
        try:
            parsed = _json.loads(out_buf.value.decode("utf-8", errors="ignore"))
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def fast_rust_strip_comments(code_or_bytes: str | bytes, lang: str = "") -> str:
    b = code_or_bytes.encode("utf-8", errors="ignore") if isinstance(code_or_bytes, str) else code_or_bytes
    if not b:
        return ""
    rlib = get_rust_lib()
    if rlib is None:
        return b.decode("utf-8", errors="ignore")
    out_cap = len(b) + 16
    out_buf = ctypes.create_string_buffer(out_cap)
    if lang and hasattr(rlib, "spectre_rust_strip_comments_lang"):
        lb = lang.encode("ascii", errors="ignore")
        rc = int(rlib.spectre_rust_strip_comments_lang(b, len(b), lb, len(lb), out_buf, out_cap))
    elif hasattr(rlib, "spectre_rust_strip_comments"):
        rc = int(rlib.spectre_rust_strip_comments(b, len(b), out_buf, out_cap))
    else:
        return b.decode("utf-8", errors="ignore")
    if rc >= 0:
        return out_buf.raw[:rc].decode("utf-8", errors="ignore")
    return b.decode("utf-8", errors="ignore")


def fast_cpp_barrier_selftest(worker_count: int = 8, timeout_ms: int = 1000) -> tuple[int, int]:
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_cpp_barrier_selftest"):
        spread = ctypes.c_int64(0)
        ok_n = int(lib.spectre_cpp_barrier_selftest(int(worker_count), int(timeout_ms), ctypes.byref(spread)))
        return ok_n, int(spread.value)
    return int(worker_count), 0


def fast_rust_triage_brocards_score(
    severity: str, cwe: str, asset: str, evidence: str, remediation: str, qod: int = 80
) -> int:
    rlib = get_rust_lib()
    payload = f"{severity}\t{cwe}\t{asset}\t{evidence}\t{remediation}".encode("utf-8", errors="ignore")
    if rlib is not None and hasattr(rlib, "spectre_rust_triage_brocards_score"):
        return int(rlib.spectre_rust_triage_brocards_score(payload, len(payload), int(qod)))
    return 0 if (severity or "").lower() in ("info", "informational", "") else 80


def fast_cpp_mad_latency_us(samples_us: list[int]) -> float:
    if not samples_us or len(samples_us) < 2:
        return 0.0
    lib = get_native_lib()
    if lib is not None and hasattr(lib, "spectre_cpp_mad_latency_us"):
        arr_t = ctypes.c_int64 * len(samples_us)
        c_arr = arr_t(*[int(x) for x in samples_us])
        return float(lib.spectre_cpp_mad_latency_us(c_arr, len(samples_us)))
    s = sorted(float(max(0, x)) for x in samples_us)
    m = s[len(s) // 2]
    d = sorted(abs(x - m) for x in s)
    return d[len(d) // 2] * 1.4826


def fast_go_sync_feeds(
    out_tsv: str,
    ecosystems: str = "crates.io,NuGet,RubyGems,Go,Maven,Packagist,PyPI",
) -> dict | None:
    import json as _json
    gobin = get_go_indexer_bin()
    if gobin is None or not out_tsv:
        return None
    try:
        proc = subprocess.run(
            [str(gobin), "-sync-feeds", str(out_tsv), "-ecosystems", str(ecosystems)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return _json.loads(proc.stdout.strip())
    except Exception:
        return None
    return None




