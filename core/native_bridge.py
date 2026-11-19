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
_BUILD_LOCK = threading.Lock()
_LIB: ctypes.CDLL | None = None
_TRIED_LOAD = False


JS_TOK_ROUTE = 1
JS_TOK_SINK = 2
JS_TOK_SECRET = 4
JS_TOK_CHUNK = 8
JS_TOK_SOURCEMAP = 16


def get_native_lib() -> ctypes.CDLL | None:
    global _LIB, _TRIED_LOAD
    if _TRIED_LOAD:
        return _LIB
    with _BUILD_LOCK:
        if _TRIED_LOAD:
            return _LIB
        _TRIED_LOAD = True
        try:
            need_build = (not SO_PATH.exists()) or (CPP_SRC.exists() and CPP_SRC.stat().st_mtime > SO_PATH.stat().st_mtime)
            if need_build and CPP_SRC.exists() and shutil.which("g++"):
                subprocess.run(
                    ["g++", "-O3", "-std=c++17", "-shared", "-fPIC", str(CPP_SRC), "-o", str(SO_PATH), "-lssl", "-lcrypto"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=True,
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
                _LIB = lib
        except Exception:
            _LIB = None
    return _LIB


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


