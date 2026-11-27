"""
SPECTRE — Rate-Limited & Circuit-Protected Concurrent HTTP Engine
=================================================================
Provides per-host token-bucket pacing, fast circuit-breaking on unreachable
or firewall-tarpitted origins, and non-blocking parallel batch fetching.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import os
from pathlib import Path
import tempfile
import threading
import time
import urllib.parse
from typing import Any

import requests

from core.scope_guard import ScopeGuard

_SENSITIVE_AUTH_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie",
    "x-api-key", "x-auth-token", "x-access-token", "api-key",
})


def is_unsafe_redirect_target(url: str, scope: ScopeGuard | None = None) -> bool:
    host = ScopeGuard.extract_host(url)
    if not host:
        return True
    if scope is not None and not scope.is_in_scope(url)[0]:
        return True
    try:
        ip_obj = ipaddress.ip_address(host)
        if (ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified):
            if scope is None or not scope.is_in_scope(host)[0]:
                return True
    except ValueError:
        pass
    return False


def get_project_js_cache_dir(project_id: int) -> Path:
    uid = os.geteuid() if hasattr(os, "geteuid") else 0
    cdir = Path(tempfile.gettempdir()) / f"spectre_js_cache_{uid}_{int(project_id)}"
    if project_id > 0 and not cdir.exists():
        cdir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(cdir, 0o700)
        except OSError:
            pass
    return cdir


def fetch_cached_text(
    session: Any,
    project_id: int,
    url: str,
    timeout: float = 5.5,
    max_chars: int = 350000,
) -> str:
    """Fetches a JS/HTML asset once per project using disk + session LRU cache."""
    if not url or not ScopeGuard.extract_host(url):
        return ""
    url_hash = hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:20]
    clean_p = url.split("?", 1)[0].split("#", 1)[0].lower()
    ext = ".js" if clean_p.endswith((".js", ".mjs")) else ".cache"
    cache_dir = get_project_js_cache_dir(project_id)
    cache_file = cache_dir / f"u_{url_hash}{ext}"
    if project_id > 0 and cache_file.is_file() and not cache_file.is_symlink():
        try:
            return cache_file.read_text(encoding="utf-8", errors="ignore")[:max_chars]
        except Exception:
            pass
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        if getattr(resp, "status_code", 0) != 200:
            return ""
        txt = (resp.text or "")[:max_chars]
        if project_id > 0 and txt and not cache_file.is_symlink():
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(txt, encoding="utf-8", errors="ignore")
            except Exception:
                pass
        return txt
    except Exception:
        return ""


class RateLimitedHttpEngine:
    """Thread-safe HTTP client pool with per-host RPS pacing and circuit-breaker."""

    def __init__(
        self,
        session: requests.Session | None = None,
        max_rps_per_host: float = 12.0,
        fail_threshold: int = 4,
        max_response_bytes: int = 524288,
        scope: ScopeGuard | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.scope: ScopeGuard | None = scope
        adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.max_rps_per_host = max(1.0, float(max_rps_per_host))
        self.min_interval = 1.0 / self.max_rps_per_host
        self.fail_threshold = max(2, int(fail_threshold))
        self.max_response_bytes = max(32768, int(max_response_bytes))
        self._lock = threading.Lock()
        self._last_req_ts: dict[str, float] = {}
        self._backoff_until: dict[str, float] = {}
        self._fail_counts: dict[str, int] = {}
        self._dead_origins: set[str] = set()
        self._dead_hosts: set[str] = set()

    def reset(self) -> None:
        with self._lock:
            self._last_req_ts.clear()
            self._backoff_until.clear()
            self._fail_counts.clear()
            self._dead_origins.clear()
            self._dead_hosts.clear()

    @staticmethod
    def _parse_keys(url_or_host: str) -> tuple[str, str]:
        s = str(url_or_host or "").strip()
        if "://" not in s:
            h = s.lower().split("/")[0].split(":")[0]
            return h, h
        p = urllib.parse.urlparse(s)
        h = (p.hostname or "").lower()
        orig = f"{p.scheme}://{p.netloc}".lower() if p.netloc else h
        return h, orig

    def is_host_dead(self, url_or_host: str) -> bool:
        h, orig = self._parse_keys(url_or_host)
        with self._lock:
            return h in self._dead_hosts or orig in self._dead_origins

    def _pace_origin(self, host: str, orig: str) -> None:
        if not orig:
            return
        sleep_needed = 0.0
        with self._lock:
            if host in self._dead_hosts or orig in self._dead_origins:
                raise requests.exceptions.ConnectTimeout(f"Circuit-Breaker: {orig} unreachable")
            now = time.monotonic()
            base_start = max(now, self._backoff_until.get(orig, 0.0))
            nxt = max(base_start, self._last_req_ts.get(orig, 0.0) + self.min_interval)
            if nxt > now:
                sleep_needed = nxt - now
                self._last_req_ts[orig] = nxt
            else:
                self._last_req_ts[orig] = now
        if sleep_needed > 0:
            time.sleep(min(sleep_needed, 2.5))

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        want_redirects = bool(kwargs.pop("allow_redirects", False))
        cur_url = str(url)
        cur_method = method.upper()
        init_host, init_orig = self._parse_keys(cur_url)
        if self.scope is not None and not self.scope.is_in_scope(cur_url)[0]:
            raise requests.exceptions.InvalidURL(f"ScopeGuard blocked request: {cur_url}")

        max_hops = 4 if want_redirects else 0
        for hop in range(max_hops + 1):
            host, orig = self._parse_keys(cur_url)
            self._pace_origin(host, orig)
            hop_kw = dict(kwargs)
            max_bytes = int(hop_kw.pop("max_bytes", self.max_response_bytes))
            caller_stream = bool(hop_kw.get("stream", False))
            hop_kw.setdefault("timeout", (3.0, 4.5))
            hop_kw.setdefault("verify", False)
            hop_kw["allow_redirects"] = False
            if hop > 0 and orig != init_orig:
                merged_h = dict(self.session.headers)
                if isinstance(hop_kw.get("headers"), dict):
                    merged_h.update(hop_kw["headers"])
                for hk in list(merged_h.keys()):
                    if hk.lower() in _SENSITIVE_AUTH_HEADERS:
                        merged_h[hk] = None
                hop_kw["headers"] = merged_h
            if not caller_stream:
                hop_kw["stream"] = True
            try:
                resp = self.session.request(cur_method, cur_url, **hop_kw)
                is_redir = resp.status_code in (301, 302, 303, 307, 308) and bool(resp.headers.get("Location"))
                if not caller_stream:
                    if resp.status_code in (204, 301, 302, 303, 304, 307, 308):
                        resp.close()
                        resp._content = b""
                    else:
                        buf = bytearray()
                        t0 = time.monotonic()
                        try:
                            for chunk in resp.iter_content(chunk_size=16384):
                                if not chunk:
                                    break
                                buf.extend(chunk)
                                if len(buf) >= max_bytes or (time.monotonic() - t0) > 7.5:
                                    break
                        finally:
                            resp.close()
                        resp._content = bytes(buf[:max_bytes])
                    if not resp.encoding or resp.encoding.lower() == "iso-8859-1":
                        resp.encoding = "utf-8"
                if orig:
                    with self._lock:
                        self._fail_counts[orig] = 0
                        if resp.status_code in (429, 503):
                            ra = resp.headers.get("Retry-After", "")
                            self._backoff_until[orig] = time.monotonic() + min(float(ra) if ra.isdigit() else 1.5, 4.0)
                if want_redirects and is_redir and hop < max_hops:
                    nxt_url = urllib.parse.urljoin(cur_url, resp.headers["Location"])
                    if is_unsafe_redirect_target(nxt_url, self.scope):
                        return resp
                    if resp.status_code in (301, 302, 303) and cur_method not in ("GET", "HEAD"):
                        cur_method = "GET"
                        kwargs.pop("data", None)
                        kwargs.pop("json", None)
                    cur_url = nxt_url
                    continue
                return resp
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as exc:
                if orig:
                    err_s = str(exc)
                    dns_dead = any(k in err_s for k in ("NameResolutionError", "Failed to resolve", "Errno -2", "Errno -3", "Errno -5"))
                    with self._lock:
                        if dns_dead and host:
                            self._dead_hosts.add(host)
                        cnt = self.fail_threshold if dns_dead else (self._fail_counts.get(orig, 0) + 1)
                        self._fail_counts[orig] = cnt
                        if cnt >= self.fail_threshold:
                            self._dead_origins.add(orig)
                raise
        raise requests.exceptions.TooManyRedirects(f"Redirect limit exceeded: {url}")

    def fetch_many(
        self,
        urls: list[str],
        method: str = "GET",
        headers: dict[str, str] | None = None,
        allow_redirects: bool = False,
        max_workers: int = 8,
        overall_timeout: float = 16.0,
    ) -> dict[str, requests.Response]:
        results: dict[str, requests.Response] = {}
        res_lock = threading.Lock()

        def _one(u: str) -> None:
            try:
                r = self.request(method, u, headers=headers, allow_redirects=allow_redirects)
                with res_lock:
                    results[u] = r
            except Exception:
                pass

        if not urls:
            return results
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(urls))))
        futs = [ex.submit(_one, u) for u in urls]
        concurrent.futures.wait(futs, timeout=overall_timeout)
        ex.shutdown(wait=False, cancel_futures=True)
        return results
